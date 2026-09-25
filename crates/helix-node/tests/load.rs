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

impl NodeGuard {
    /// Size of the chain database on disk, in bytes.
    ///
    /// `len()` rather than blocks-on-disk: redb grows the file in chunks and reuses freed pages,
    /// so the *file* is what an operator's `df` shows and what a 128 GB budget is spent from. The
    /// difference cost a measurement on 2026-09-09, in the other direction — `metadata().len()`
    /// read a sparse file as bigger than it was. Here the question is the file, so the file is
    /// what is asked.
    fn chain_db_bytes(&self) -> u64 {
        std::fs::metadata(self._work_dir.path().join("helix-data.redb"))
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// What the database has actually written, in 4 KB pages — not the file's length, which redb
    /// grows in doubling steps and which therefore stands still across most writes. The length is
    /// the right number for a promise about the file (the disk budget); for "what does one
    /// transaction cost on disk" it is a staircase, and a flood that stays on one step reads as
    /// costing nothing.
    fn chain_db_allocated_bytes(&self) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(self._work_dir.path().join("helix-data.redb"))
            .map(|m| m.blocks() * 512)
            .unwrap_or(0)
    }
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
        // This file exists to push the *protocol* limits, so the proposer's own restraint has to
        // be lifted out of the way — `HELIX_MAX_PROPOSAL_BYTES` defaults to 256 KB, which is a
        // policy for a network whose gossip crosses one slow relay and would otherwise cap every
        // block here at a fraction of what `MAX_BLOCK_BYTES` allows. A test of the ceiling must
        // not measure the floor somebody sensibly put below it.
        .env("HELIX_MAX_PROPOSAL_BYTES", helix_core::fee::MAX_BLOCK_BYTES.to_string())
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
        public_key: Some(kp.public.clone()),
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
    //
    // Measured on the blocks themselves, not as `tx_count × tx_bytes`: since #243 a transaction
    // from a sender the chain already knows is stored without its key, so the flood's later
    // transactions are ~1.9 KB smaller than the first. Counting them all at full size reported
    // 371 transactions as 2.02 MB — a block that really was under the cap.
    let mut largest = 0u64;
    let mut fullest = 0u64;
    let mut without_key = 0u64;
    for h in start + 1..=end {
        let fetched: Vec<helix_core::Block> = reqwest::get(format!(
            "http://127.0.0.1:{RPC_PORT}/sync/blocks?from={h}&count=1"
        ))
        .await
        .expect("block request")
        .json()
        .await
        .expect("block");
        let block = fetched.into_iter().next().expect("the block at this height");
        let count = block.transactions.len() as u64;
        let bytes = block.transaction_bytes();
        without_key += block.transactions.iter().filter(|t| t.public_key.is_none()).count() as u64;
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
         {fullest} tx ({:.2} MB of a {:.0} MB cap), {without_key} carried without their key",
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

/// **What does a block actually cost on disk, and does that cost scale with what is in it?**
///
/// The question a disk budget turns on, and it had no answer. `/diagnostics` reports
/// `chain_db_bytes_per_block` as the database divided by the height — an average over a chain
/// whose blocks are nearly empty, which says nothing about what a *full* one costs. The pruning
/// window compounds that: `HELIX_KEEP_BLOCKS` counts blocks, not bytes, so the plateau it promises
/// is `keep_blocks × whatever a block happens to weigh`. On 2026-09-18 production reported a 15.7
/// GB plateau at 34 KB per block; the same 500 000-block window over full 2 MB blocks is a
/// terabyte, on a 367 GB disk.
///
/// So this measures the two numbers a budget needs: the fixed cost of an empty block, and the
/// marginal cost of a transaction. Everything else — window size, block size, how long history
/// survives — follows from those two and a target.
///
/// Reported, not just asserted: the assertion guards against a regression, but the *numbers* are
/// what the sizing decision is made from, and they belong in the test output where they can be
/// re-read rather than in a comment that goes stale.
#[tokio::test]
#[ignore = "spawns a node and measures disk growth under a flood (~2-3 min) — run with --ignored --nocapture"]
async fn disk_cost_of_a_block_is_measured_empty_and_full() {
    const FLOOD: u64 = 1_500;
    let kp = KeyPair::generate();
    let sender = Address::from_public_key(&kp.public);
    let recipient = Address::from_public_key(&KeyPair::generate().public);
    let node = spawn_loaded_node(&kp, "1000");
    wait_until_reachable(Duration::from_secs(30)).await;

    // Idle stretch first: the chain produces empty blocks and nothing else, so the growth over
    // this window is the per-block floor — header, commit certificate, and whatever redb writes
    // to index them.
    let h0 = status().await.expect("status")["height"].as_u64().unwrap_or(0);
    let d0 = node.chain_db_allocated_bytes();
    while status().await.and_then(|s| s["height"].as_u64()).unwrap_or(0) < h0 + 30 {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let h1 = status().await.expect("status")["height"].as_u64().unwrap_or(0);
    let d1 = node.chain_db_allocated_bytes();
    let empty_per_block = (d1.saturating_sub(d0)) as f64 / (h1 - h0).max(1) as f64;

    // Then the same measurement with the blocks full.
    let chain_id = chain_id().await;
    let base_fee = status().await.expect("status")["base_fee_per_byte"].as_u64().unwrap_or(1);
    let txs: Vec<Transaction> = (0..FLOOD)
        .map(|n| signed_transfer(&kp, &sender, &recipient, 1_000, n, chain_id, base_fee, FEE_HEADROOM_MULTIPLE))
        .collect();
    let tx_bytes = txs[0].size_bytes();
    let client = reqwest::Client::new();
    let mut accepted = 0u64;
    for tx in &txs {
        if submit(&client, tx).await.is_ok() {
            accepted += 1;
        }
    }
    assert!(accepted > FLOOD / 2, "only {accepted}/{FLOOD} accepted — the flood never happened");

    let h2 = status().await.expect("status")["height"].as_u64().unwrap_or(0);
    let d2 = node.chain_db_allocated_bytes();
    // Drain: wait until the mempool is empty, so every accepted transaction is on disk.
    for _ in 0..240 {
        if status().await.and_then(|s| s["mempool_size"].as_u64()).unwrap_or(1) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // redb defers some of its writing; let it settle so the file reflects the data.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let h3 = status().await.expect("status")["height"].as_u64().unwrap_or(0);
    let d3 = node.chain_db_allocated_bytes();

    let loaded_blocks = (h3 - h2).max(1);
    let loaded_growth = d3.saturating_sub(d2);
    // The premise, checked before a number is drawn from it. Measured on the file's length this
    // read 0 B for 1500 transactions once #243 made them smaller: the flood stayed within one of
    // redb's doubling steps, "0 B per transaction" passed the upper bound below, and the test
    // said nothing while looking green.
    assert!(
        loaded_growth > 0,
        "the database wrote nothing measurable for {accepted} transactions — the instrument saw no \
         growth, so no cost per transaction can be read from it"
    );
    let per_tx = loaded_growth.saturating_sub((empty_per_block * loaded_blocks as f64) as u64) as f64
        / accepted.max(1) as f64;

    println!(
        "empty block: {empty_per_block:.0} B on disk · {accepted} tx of {tx_bytes} B wire drained over \
         {loaded_blocks} blocks costing {loaded_growth} B → {per_tx:.0} B/tx on disk ({:.2}x wire)",
        per_tx / tx_bytes as f64
    );
    println!(
        "  ⇒ a full 2 MB block ({} tx) costs about {:.1} MB on disk",
        2 * 1024 * 1024 / tx_bytes,
        (empty_per_block + per_tx * (2.0 * 1024.0 * 1024.0 / tx_bytes as f64)) / 1024.0 / 1024.0
    );

    // The guard, deliberately loose: what must not happen is a transaction costing several times
    // its own size on disk, because every disk projection in this repo assumes otherwise.
    assert!(
        per_tx < tx_bytes as f64 * 3.0,
        "a transaction costs {per_tx:.0} B on disk against {tx_bytes} B on the wire — disk \
         projections based on wire size would be wrong by that factor"
    );
}

/// **Does a pruned database actually stop growing, or only grow more slowly?**
///
/// A 128 GB budget is a promise about the *file*, and redb never returns space to the filesystem —
/// pruning frees pages for reuse inside the file, nothing more. So "plateau" is a claim that freed
/// pages are reused fast enough that the file stops extending, and that claim has never been
/// tested over more than one prune. The one measurement on record (2026-09-09) saw 46 MB of writes
/// after a prune cost 11 MB of file growth against 75 MB without — better, but not zero, and a
/// 24 % residue compounding over a year is not a plateau.
///
/// This runs a node with a deliberately tiny window and floods it, so it prunes continuously, then
/// asks whether the file is still growing once the window is full. Because the file only ever goes
/// up, a budget has to hold against the *high-water mark* — which is exactly what makes the answer
/// here load-bearing rather than academic.
#[tokio::test]
#[ignore = "runs a node through many prune cycles under load (~3-4 min) — run with --ignored --nocapture"]
async fn a_pruned_database_stops_extending_its_file() {
    const WINDOW: u64 = 1_000; // MIN_KEEP_BLOCKS — the smallest window the node accepts
    let kp = KeyPair::generate();
    let sender = Address::from_public_key(&kp.public);
    let recipient = Address::from_public_key(&KeyPair::generate().public);

    let work_dir = tempdir::TempDir::new().expect("temp work dir");
    KeyFile::from_keypair_plain(&kp)
        .save(&work_dir.path().join("validator-key.json"))
        .expect("write validator key");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_helix"));
    cmd.arg("start")
        .current_dir(work_dir.path())
        .env("HELIX_RPC_BIND", format!("127.0.0.1:{RPC_PORT}"))
        .env("HELIX_P2P_LISTEN", format!("127.0.0.1:{P2P_PORT}"))
        .env("HELIX_P2P_DISABLE_MDNS", "1")
        .env("HELIX_NEW_CHAIN", "1")
        .env("HELIX_BLOCK_TIME_MS", "200")
        .env("HELIX_KEEP_BLOCKS", WINDOW.to_string())
        .env("HELIX_RPC_RATE_LIMIT", "50000,20000")
        .env("HELIX_MAX_PROPOSAL_BYTES", helix_core::fee::MAX_BLOCK_BYTES.to_string())
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let node = NodeGuard { child: cmd.spawn().expect("spawn helix node"), _work_dir: work_dir };
    wait_until_reachable(Duration::from_secs(30)).await;

    let chain_id = chain_id().await;
    let base_fee = status().await.expect("status")["base_fee_per_byte"].as_u64().unwrap_or(1);
    let client = reqwest::Client::new();
    let mut nonce = 0u64;
    let mut samples: Vec<(u64, u64)> = Vec::new();

    // The window has to be *full* before any of this measures pruning — the first attempt at this
    // test floods six times, reached height 179 against a window of 1000, and would have reported
    // an archive node's growth as a plateau had the precondition below not caught it.
    for _ in 0..600 {
        if status().await.and_then(|s| s["height"].as_u64()).unwrap_or(0) > WINDOW + 50 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Eight rounds of "flood, let it drain, measure", all of them past the window, so every block
    // written is also a block pruned.
    for round in 0..8u64 {
        let txs: Vec<Transaction> = (0..400)
            .map(|i| signed_transfer(&kp, &sender, &recipient, 1_000, nonce + i, chain_id, base_fee, FEE_HEADROOM_MULTIPLE))
            .collect();
        nonce += 400;
        for tx in &txs {
            let _ = submit(&client, tx).await;
        }
        for _ in 0..200 {
            if status().await.and_then(|s| s["mempool_size"].as_u64()).unwrap_or(1) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        tokio::time::sleep(Duration::from_secs(4)).await;
        let h = status().await.and_then(|s| s["height"].as_u64()).unwrap_or(0);
        let bytes = node.chain_db_bytes();
        samples.push((h, bytes));
        println!("  round {round}: height {h}, file {:.1} MB", bytes as f64 / 1048576.0);
    }

    let earliest = get_json(&format!("http://127.0.0.1:{RPC_PORT}/diagnostics"))
        .await
        .and_then(|d| d["earliest_block"].as_u64());
    println!("earliest retained block: {earliest:?} (window {WINDOW})");
    assert!(
        earliest.is_some_and(|e| e > 0),
        "the node never pruned anything, so this measured an archive node: earliest={earliest:?}"
    );

    // **Not** measured as bytes-per-block over a window, which is what the first version of this
    // test did and why it failed against perfectly healthy behaviour: redb extends the file in
    // *doubling steps*, measured here as four rounds flat at 32.6 MB, one jump, four flat at 64.8.
    // Any average across that staircase is an artefact of where the window happens to fall.
    //
    // The claim worth testing is the one a disk budget rests on: the file holds a bounded window,
    // not the whole chain. So it is compared against what the same chain would have cost unpruned.
    let steps: Vec<String> = samples.iter().map(|(h, b)| format!("{h}:{:.0}MB", *b as f64 / 1048576.0)).collect();
    println!("file over time: {}", steps.join(" "));

    let (height, file_bytes) = *samples.last().expect("samples");
    let retained = height - earliest.unwrap_or(0);
    let unpruned_estimate = file_bytes as f64 * height as f64 / retained.max(1) as f64;
    println!(
        "height {height}, retaining {retained} blocks in {:.1} MB — the same chain unpruned would \
         be about {:.1} MB",
        file_bytes as f64 / 1048576.0,
        unpruned_estimate / 1048576.0
    );
    assert!(
        retained < height,
        "nothing was dropped: retaining {retained} of {height} blocks is an archive node"
    );
    // The window is what bounds the file. A node retaining a quarter of the chain whose file is
    // the size of the whole chain would mean freed pages are never reused — and then no block
    // window, however small, keeps a promise about disk.
    assert!(
        (file_bytes as f64) < unpruned_estimate * 0.9,
        "the file ({:.1} MB) is as large as the unpruned chain would be ({:.1} MB) — freed pages \
         are not being reused, so HELIX_KEEP_BLOCKS bounds nothing an operator can see with df",
        file_bytes as f64 / 1048576.0,
        unpruned_estimate / 1048576.0
    );
}

/// **The byte budget, against a real node rather than against arithmetic.**
///
/// `keep_blocks_for_budget` has unit tests, and they would all pass if nothing ever called it —
/// that is the failure mode this repo has paid for twice (#147's teardown half, #151's tick
/// counter). So this starts a node with a deliberately small `HELIX_KEEP_BYTES`, floods it well
/// past that budget, and asks the only question that matters: did the file stop growing.
///
/// The budget is a *target*, not a hard ceiling, and the test is written to say so. redb extends
/// its file in doubling steps — measured 32.6 → 64.8 MB — so a database whose content sits just
/// under a step lands on the step above it. The assertion therefore allows the overshoot a
/// doubling can produce and refuses anything beyond, because the failure being guarded against is
/// unbounded growth, not a few megabytes of allocator granularity.
#[tokio::test]
#[ignore = "floods a node past a small disk budget and watches the file (~3-4 min) — run with --ignored --nocapture"]
async fn a_disk_budget_stops_the_database_from_growing() {
    // Chosen against `MIN_KEEP_BLOCKS`, not for roundness. The floor outranks the budget, so a
    // budget below `1000 × bytes-per-block` can never bind and the test would measure the floor
    // while believing it measured the budget — which is exactly what the first run did: height
    // 271 against a floor of 1000, nothing pruned, `earliest_block: None`.
    //
    // On production the same arithmetic is harmless: 1000 blocks at the 1.9 MB a *full* block
    // costs is 1.9 GB, well inside a 120 GB budget. It only bites at test scale.
    const BUDGET_MB: u64 = 80;
    let kp = KeyPair::generate();
    let sender = Address::from_public_key(&kp.public);
    let recipient = Address::from_public_key(&KeyPair::generate().public);

    let work_dir = tempdir::TempDir::new().expect("temp work dir");
    KeyFile::from_keypair_plain(&kp)
        .save(&work_dir.path().join("validator-key.json"))
        .expect("write validator key");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_helix"));
    cmd.arg("start")
        .current_dir(work_dir.path())
        .env("HELIX_RPC_BIND", format!("127.0.0.1:{RPC_PORT}"))
        .env("HELIX_P2P_LISTEN", format!("127.0.0.1:{P2P_PORT}"))
        .env("HELIX_P2P_DISABLE_MDNS", "1")
        .env("HELIX_NEW_CHAIN", "1")
        .env("HELIX_BLOCK_TIME_MS", "200")
        .env("HELIX_KEEP_BYTES", format!("{BUDGET_MB}M"))
        .env("HELIX_RPC_RATE_LIMIT", "50000,20000")
        .env("HELIX_MAX_PROPOSAL_BYTES", helix_core::fee::MAX_BLOCK_BYTES.to_string())
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let node = NodeGuard { child: cmd.spawn().expect("spawn helix node"), _work_dir: work_dir };
    wait_until_reachable(Duration::from_secs(30)).await;

    let chain_id = chain_id().await;
    let base_fee = status().await.expect("status")["base_fee_per_byte"].as_u64().unwrap_or(1);
    let client = reqwest::Client::new();
    let mut nonce = 0u64;
    let mut peak = 0u64;

    // Past the floor before anything is measured, for the reason given on BUDGET_MB.
    for _ in 0..900 {
        if status().await.and_then(|s| s["height"].as_u64()).unwrap_or(0) > 1_500 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Ten rounds, each writing a slice of the budget. Without pruning the file would run well past
    // it; with it, the window has to tighten and the file settle.
    //
    // 750 per round, not the 500 this started with: since #243 every transaction after the
    // sender's first is stored without its key, ~3.5 KB instead of ~5.4 KB, and 5000 of them no
    // longer carried the file past the budget — it stopped at 64.8 MB of 80, so there was nothing
    // to prune, and the test blamed the prune loop.
    const PER_ROUND: u64 = 750;
    for round in 0..10u64 {
        let txs: Vec<Transaction> = (0..PER_ROUND)
            .map(|i| signed_transfer(&kp, &sender, &recipient, 1_000, nonce + i, chain_id, base_fee, FEE_HEADROOM_MULTIPLE))
            .collect();
        nonce += PER_ROUND;
        for tx in &txs {
            let _ = submit(&client, tx).await;
        }
        for _ in 0..200 {
            if status().await.and_then(|s| s["mempool_size"].as_u64()).unwrap_or(1) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        let bytes = node.chain_db_bytes();
        peak = peak.max(bytes);
        let h = status().await.and_then(|s| s["height"].as_u64()).unwrap_or(0);
        println!("  round {round}: height {h}, file {:.1} MB (budget {BUDGET_MB} MB)", bytes as f64 / 1048576.0);
    }

    // **Wait for the sweep, do not assume it already ran.** The budget cannot tighten the window
    // until the file has actually grown — it derives bytes-per-block from the file on disk — so
    // the first prune necessarily happens *after* a doubling step, and the prune loop runs on its
    // own timer rather than with the last transaction of the last round.
    //
    // Under load that ordering became a coin flip. Measured in `build-all.sh` on 2026-09-22: the
    // chain crawled from 1529 to 1774 across the ten rounds instead of racing ahead, so the window
    // only fell below the height at the very last one — and this assertion fired a moment before
    // the sweep it was asking about. Run alone it passes; run beside twelve other crates it does
    // not, which makes it a load artefact of the kind R7 lists, not a regression.
    //
    // Polling instead keeps the property the test is named for (the budget *does* prune) and drops
    // the one it never meant to assert (it prunes within three seconds of the last round).
    let mut earliest = None;
    for _ in 0..40 {
        let diag = get_json(&format!("http://127.0.0.1:{RPC_PORT}/diagnostics")).await;
        earliest = diag.as_ref().and_then(|d| d["earliest_block"].as_u64());
        peak = peak.max(node.chain_db_bytes());
        if earliest.is_some_and(|e| e > 0) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let height = status().await.and_then(|s| s["height"].as_u64()).unwrap_or(0);
    println!("peak file {:.1} MB · height {height} · earliest retained {earliest:?}", peak as f64 / 1048576.0);

    // The premise, measured before anything is concluded from it: the budget only tightens the
    // window once the file is past it, so a file that never got there shows nothing about pruning
    // either way. Without this, a flood too small to matter reads as "the budget is not wired".
    assert!(
        peak > BUDGET_MB * 1024 * 1024,
        "precondition: the file never passed the {BUDGET_MB} MB budget (peak {:.1} MB), so there was \
         nothing to prune — the flood is too small to test the budget, which says nothing about it",
        peak as f64 / 1048576.0
    );
    assert!(
        earliest.is_some_and(|e| e > 0),
        "the file passed the budget and nothing was pruned after two minutes of waiting — the \
         budget is not wired to the prune loop (earliest={earliest:?}, height={height})"
    );
    let ceiling = BUDGET_MB * 1024 * 1024 * 2;
    assert!(
        peak <= ceiling,
        "the file reached {:.1} MB against a {BUDGET_MB} MB budget — more than one doubling step \
         over, so this is unbounded growth rather than allocator granularity",
        peak as f64 / 1048576.0
    );
}
