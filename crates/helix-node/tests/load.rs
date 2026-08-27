//! What the chain does when transactions arrive faster than it can put them in blocks.
//!
//! **Nothing in this workspace tested that before 2026-08-27.** Every other test submits a
//! handful of transactions, and a handful is precisely the case where the interesting limits do
//! not bind: `MAX_BLOCK_BYTES` (2 MB), `MAX_TXS_PER_BLOCK` (1000), `MAX_BLOCK_FUEL`, the
//! mempool's 10,000-slot ceiling and its fee-priority eviction. Each of those has a failure mode
//! that is invisible until it is reached, and one of them — a block too large for gossipsub to
//! carry — is a *permanent* stall rather than a lost block (#163): it can never be broadcast,
//! never collects a vote, and is rebuilt identically by the next proposer.
//!
//! These are the numbers an operator actually asks for ("how many transactions per second?"), so
//! the test prints them rather than only asserting. Run:
//! `cargo test --release -p helix-node --test load -- --ignored --nocapture`

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Hash, KeyFile, KeyPair};

const RPC_PORT: u16 = 19_401;
const P2P_PORT: u16 = 19_402;

struct NodeGuard {
    child: Child,
    _work_dir: tempdir::TempDir,
}

impl Drop for NodeGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One validator on its own fresh chain, holding the genesis liquid allocation — which is what
/// makes it able to fund a flood of transfers out of its own balance.
fn spawn_loaded_node(kp: &KeyPair, block_time_ms: &str) -> NodeGuard {
    let work_dir = tempdir::TempDir::new().expect("temp work dir");
    KeyFile::from_keypair_plain(kp)
        .save(&work_dir.path().join("validator-key.json"))
        .expect("write validator key");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_helix"));
    cmd.arg("start")
        .current_dir(work_dir.path())
        .env("HELIX_RPC_BIND", format!("127.0.0.1:{RPC_PORT}"))
        .env("HELIX_P2P_LISTEN", format!("127.0.0.1:{P2P_PORT}"))
        // Peer only with itself: a production node reachable over mDNS would gossip its own
        // chain into this one. Same reason `multi_node.rs` sets it.
        .env("HELIX_P2P_DISABLE_MDNS", "1")
        .env("HELIX_NEW_CHAIN", "1")
        .env("HELIX_BLOCK_TIME_MS", block_time_ms)
        // Without this the test measures the RPC's token bucket and nothing else. The default is
        // a burst of 30 and 10 requests/second per IP, so a 2000-transaction flood is admitted at
        // 45 — which is exactly what the first run of this test reported, and exactly the kind of
        // number that looks like a chain problem and is not one. Raised here so what is measured
        // is the mempool, the packer and the block limits.
        .env("HELIX_RPC_RATE_LIMIT", "50000,20000")
        .env("RUST_LOG", std::env::var("HELIX_TEST_LOG").unwrap_or_else(|_| "error".into()))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn().expect("spawn helix node");
    NodeGuard { child, _work_dir: work_dir }
}

async fn get_json(url: &str) -> Option<serde_json::Value> {
    reqwest::get(url).await.ok()?.json().await.ok()
}

async fn status() -> Option<serde_json::Value> {
    get_json(&format!("http://127.0.0.1:{RPC_PORT}/status")).await
}

async fn wait_until_reachable(timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if status().await.is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("node never answered on port {RPC_PORT}");
}

/// The chain's own id — its genesis hash. Signing with anything else produces transactions this
/// chain refuses at the mempool (#174), which would make a load test measure nothing at all.
async fn chain_id() -> Hash {
    let genesis = get_json(&format!("http://127.0.0.1:{RPC_PORT}/blocks/height/0"))
        .await
        .expect("genesis block");
    Hash::from_hex(genesis["hash"].as_str().expect("genesis hash")).expect("parse genesis hash")
}

/// Build and sign one transfer, priced exactly as the wallet prices it: sign once at fee 0 to get
/// a correctly-sized signature, measure, then sign for real. The fee is a fixed-width field, so
/// the size does not move between the two.
fn signed_transfer(
    kp: &KeyPair,
    from: &Address,
    to: &Address,
    amount: u64,
    nonce: u64,
    chain_id: Hash,
    base_fee_per_byte: u64,
    headroom_multiple: u64,
) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        from: from.clone(),
        to: Some(to.clone()),
        amount,
        fee: 0,
        nonce,
        data: Vec::new(),
        crypto_version: kp.scheme,
        chain_id,
        signature: helix_crypto::Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    tx.signature = kp.sign(tx.signing_hash().as_bytes()).expect("sign at fee 0");
    let size = tx.size_bytes();
    let required = base_fee_per_byte.saturating_mul(size);
    tx.fee = (required * headroom_multiple).max(10_000);
    tx.signature = kp.sign(tx.signing_hash().as_bytes()).expect("sign priced");
    tx
}

/// Headroom over the base fee as it stands *before* the flood.
///
/// The wallet uses 25 %, which is right for one transaction into a normal block and wrong for a
/// batch signed all at once. Measured on the first honest run of this test: 2000 transactions
/// priced at +25 % went in, 501 were admitted, and the other 1499 came back with "Fee below the
/// block base fee: got 7802, need at least 10884 (5442 bytes × 2 nano-HLX/byte)" — the base fee
/// had climbed from 1 to 2 to 3 while the batch was being submitted.
///
/// **That is the fee market working, not a fault**, and the flood test now asserts the climb
/// rather than tripping over it. But a load test priced so that the chain rejects most of the load
/// measures the pricing, not the load, so these transactions pay well over the odds — 20× covers
/// roughly twenty-four blocks of 12.5 % growth from a base fee of 1.
const FEE_HEADROOM_MULTIPLE: u64 = 20;

/// Submit, and on refusal say *why*.
///
/// Returning a bare bool was the first version and it cost a whole run: 2000 transactions went in,
/// 45 were admitted, and the failure said only "45 != 2000" — which is consistent with a rate
/// limiter, a full pool, a nonce rule, a fee rule and a broken test, and distinguishes none of
/// them. A load test whose failure does not name the limit it hit is a load test you have to run
/// again to learn anything.
async fn submit(client: &reqwest::Client, tx: &Transaction) -> Result<(), String> {
    let resp = client
        .post(format!("http://127.0.0.1:{RPC_PORT}/transactions"))
        .json(tx)
        .send()
        .await
        .map_err(|e| format!("transport: {e}"))?;
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    // Collapse the varying parts so a histogram of reasons is readable.
    let reason = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or(body);
    let reason: String = reason.chars().take(90).collect();
    Err(format!("{status}: {reason}"))
}

/// **The load run.** A single sender floods the chain with transfers and every one of them is
/// accounted for afterwards — not "most arrived", but the exact balance, the exact nonce, and no
/// block over the size the network can carry.
///
/// A single sender is the harder case, not the easier one: nonces from one account must execute
/// in order, so this exercises `Mempool::pending_for_block`'s per-sender ordering as well as its
/// fee priority. If ordering broke, transfers would be dropped for "nonce mismatch" and the
/// balance check below would catch it rather than a timeout.
#[tokio::test]
#[ignore = "spawns a real node and floods it with 2000 signed transactions (~1-2 min wall-clock) — run with --ignored --nocapture"]
async fn a_flood_of_transactions_is_fully_accounted_for_and_never_overfills_a_block() {
    const FLOOD: u64 = 2_000;
    const AMOUNT: u64 = 1_000_000; // 0.001 HLX each — small enough that 2000 of them fit easily

    let kp = KeyPair::generate();
    let sender = Address::from_public_key(&kp.public);
    let recipient = Address::from_public_key(&KeyPair::generate().public);
    let _node = spawn_loaded_node(&kp, "2000");
    wait_until_reachable(Duration::from_secs(30)).await;

    let chain_id = chain_id().await;
    let base_fee = status().await.expect("status")["base_fee_per_byte"].as_u64().unwrap_or(1);
    let start = status().await.expect("status")["height"].as_u64().unwrap_or(0);

    // Signing 2000 ML-DSA transactions is itself measurable work — do it before the clock starts,
    // so the number reported is the chain's throughput and not this test's signing speed.
    let signing_started = Instant::now();
    let txs: Vec<Transaction> = (0..FLOOD)
        .map(|n| signed_transfer(&kp, &sender, &recipient, AMOUNT, n, chain_id, base_fee, FEE_HEADROOM_MULTIPLE))
        .collect();
    let tx_bytes = txs[0].size_bytes();
    println!(
        "signed {FLOOD} transactions in {:.1}s ({} bytes each, {} per 2 MB block at most)",
        signing_started.elapsed().as_secs_f64(),
        tx_bytes,
        helix_core::fee::MAX_BLOCK_BYTES / tx_bytes,
    );

    let client = reqwest::Client::new();
    let submit_started = Instant::now();
    let mut accepted = 0u64;
    let mut refusals: std::collections::HashMap<String, u64> = Default::default();
    for tx in &txs {
        match submit(&client, tx).await {
            Ok(()) => accepted += 1,
            Err(reason) => *refusals.entry(reason).or_default() += 1,
        }
    }
    println!(
        "submitted {accepted}/{FLOOD} into the mempool in {:.1}s",
        submit_started.elapsed().as_secs_f64()
    );
    for (reason, n) in &refusals {
        println!("  refused {n}× — {reason}");
    }
    assert_eq!(
        accepted, FLOOD,
        "every transaction was validly signed, correctly priced and nonce-ordered — a rejection \
         here is the pool refusing work it should take (reasons above)"
    );

    // Wait for the chain to drain the pool.
    let drain_started = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut final_status = None;
    while Instant::now() < deadline {
        if let Some(s) = status().await {
            if s["mempool_size"].as_u64() == Some(0) {
                final_status = Some(s);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let drained = drain_started.elapsed();
    let s = final_status.expect("the mempool never drained — the chain could not keep up at all");
    let end = s["height"].as_u64().unwrap_or(0);
    let base_fee_after = s["base_fee_per_byte"].as_u64().unwrap_or(0);

    // The fee market has to engage under load, or the anti-spam design is decorative. Blocks well
    // past `TARGET_BLOCK_BYTES` must raise the base fee for the next one — and this is not a
    // theoretical assertion: the first run of this test failed *because* the base fee tripled
    // mid-flood and priced out transactions signed before it moved.
    assert!(
        base_fee_after > base_fee,
        "a flood that fills blocks past the {} MB target must raise the base fee — it went \
         {base_fee} → {base_fee_after}",
        helix_core::fee::TARGET_BLOCK_BYTES / 1_000_000,
    );

    // Every transaction landed, exactly once. This is the assertion that matters: a flood that
    // silently loses transactions, or applies one twice, would still drain the pool.
    let account = get_json(&format!("http://127.0.0.1:{RPC_PORT}/accounts/{recipient}"))
        .await
        .expect("recipient account");
    let received = (account["balance_hlx"].as_f64().unwrap_or(0.0) * 1e9).round() as u64;
    assert_eq!(
        received,
        FLOOD * AMOUNT,
        "the recipient must hold exactly what was sent — every transfer applied once and only once"
    );
    let sender_account = get_json(&format!("http://127.0.0.1:{RPC_PORT}/accounts/{sender}"))
        .await
        .expect("sender account");
    assert_eq!(
        sender_account["nonce"].as_u64(),
        Some(FLOOD),
        "the sender's nonce must have advanced by exactly one per transaction"
    );

    // No block may exceed what the network can carry. A block over `MAX_BLOCK_BYTES` cannot be
    // gossiped, so it is not a lost block — it is a chain that stops (#163).
    let mut largest = 0u64;
    let mut fullest = 0u64;
    for h in start + 1..=end {
        let block = get_json(&format!("http://127.0.0.1:{RPC_PORT}/blocks/height/{h}"))
            .await
            .expect("block");
        let count = block["tx_count"].as_u64().unwrap_or(0);
        let bytes = count * tx_bytes;
        largest = largest.max(bytes);
        fullest = fullest.max(count);
        assert!(
            bytes <= helix_core::fee::MAX_BLOCK_BYTES,
            "block {h} carries {bytes} transaction bytes, over the {} the network will \
             transmit — such a block can never be broadcast and stops the chain",
            helix_core::fee::MAX_BLOCK_BYTES
        );
        assert!(
            count <= 1_000,
            "block {h} carries {count} transactions, over the MAX_TXS_PER_BLOCK cap"
        );
    }

    let blocks = end - start;
    println!(
        "drained {FLOOD} transactions in {:.1}s over {blocks} blocks — {:.0} tx/s, fullest block \
         {fullest} tx ({:.2} MB of a {:.0} MB cap)",
        drained.as_secs_f64(),
        FLOOD as f64 / drained.as_secs_f64(),
        largest as f64 / 1e6,
        helix_core::fee::MAX_BLOCK_BYTES as f64 / 1e6,
    );
    assert!(fullest > 1, "premise: the flood really did put more than one transaction in a block");
}

/// The pool's ceiling, and what it does at it.
///
/// `DEFAULT_MAX_SIZE` is 10,000. Past that the pool evicts its lowest-tipping entry to make room
/// for a higher one and refuses anything that does not outbid — the anti-spam rule. What must not
/// happen is the pool accepting past its own limit (unbounded memory on a public endpoint) or a
/// node falling over. Deliberately submits far more than the chain can include in the time given:
/// the point is the refusal, not the drain.
#[tokio::test]
#[ignore = "spawns a real node and submits 12,000 transactions to overflow the mempool (~2-4 min wall-clock) — run with --ignored --nocapture"]
async fn the_mempool_refuses_work_past_its_ceiling_instead_of_growing_without_bound() {
    const OVERFLOW: u64 = 12_000;
    const AMOUNT: u64 = 1_000;
    /// `helix_mempool`'s `DEFAULT_MAX_SIZE`, which the node does not override.
    const POOL_CEILING: u64 = 10_000;

    let kp = KeyPair::generate();
    let sender = Address::from_public_key(&kp.public);
    let recipient = Address::from_public_key(&KeyPair::generate().public);
    // A slow block time so the pool fills faster than it drains — otherwise this measures block
    // production, not the ceiling.
    let _node = spawn_loaded_node(&kp, "60000");
    wait_until_reachable(Duration::from_secs(30)).await;

    let chain_id = chain_id().await;
    let base_fee = status().await.expect("status")["base_fee_per_byte"].as_u64().unwrap_or(1);
    let client = reqwest::Client::new();

    let mut accepted = 0u64;
    let mut refused = 0u64;
    let mut peak_pool = 0u64;
    let mut reasons: std::collections::HashMap<String, u64> = Default::default();
    for n in 0..OVERFLOW {
        let tx = signed_transfer(&kp, &sender, &recipient, AMOUNT, n, chain_id, base_fee, FEE_HEADROOM_MULTIPLE);
        match submit(&client, &tx).await {
            Ok(()) => accepted += 1,
            Err(reason) => {
                refused += 1;
                *reasons.entry(reason).or_default() += 1;
            }
        }
        if n % 500 == 0 {
            if let Some(s) = status().await {
                peak_pool = peak_pool.max(s["mempool_size"].as_u64().unwrap_or(0));
            }
        }
    }
    let s = status().await.expect("status");
    peak_pool = peak_pool.max(s["mempool_size"].as_u64().unwrap_or(0));

    println!("submitted {OVERFLOW}: {accepted} accepted, {refused} refused, peak pool {peak_pool}");
    for (reason, n) in &reasons {
        println!("  refused {n}× — {reason}");
    }
    assert!(
        peak_pool <= POOL_CEILING,
        "the pool held {peak_pool} entries, past its own {POOL_CEILING} ceiling — on a public \
         endpoint that is unbounded memory for anyone who can sign"
    );
    assert!(refused > 0, "premise: the flood really did exceed the ceiling");
    // **The premise this test lived without on its first run.** Priced at +25 % it never reached
    // the ceiling at all: 5181 went in, the pool peaked at 5001, and every later refusal was the
    // fee market rather than the cap — a test that passed while measuring something else
    // entirely. Assert that the pool actually filled, so the ceiling is what is being exercised.
    assert!(
        peak_pool >= POOL_CEILING - 50,
        "the pool only reached {peak_pool} of its {POOL_CEILING} ceiling, so this run never \
         tested the ceiling — it tested whatever refused the rest (see the reasons above)"
    );
    assert!(
        reasons.keys().any(|r| r.contains("Mempool full")),
        "and the refusals past the ceiling must be the ceiling itself: {:?}",
        reasons.keys().collect::<Vec<_>>()
    );
    // And the node is still answering after all of it.
    assert!(status().await.is_some(), "the node must survive its pool being flooded");
}

/// Local scratch directory, as in `multi_node.rs`.
///
/// Duplicated rather than shared: Rust builds each file in `tests/` as its own binary, so the two
/// cannot see each other's items without a `tests/common/` module, and twenty lines of `mkdir` is
/// not worth restructuring both files for. There is no invariant here to drift — if it ever grows
/// one, it belongs in `tests/common/`.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> std::io::Result<Self> {
            // A counter, not a wall-clock nanosecond: parallel test threads read the same
            // nanosecond often enough to collide — measured a few hundred times in 360k samples
            // when `helix-rpc`'s fixture did it that way.
            static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "helix-load-test-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path)?;
            Ok(TempDir(path))
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
