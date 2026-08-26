//! Automated multi-node integration test — CTO Backlog item 48.
//!
//! Everything else in this workspace is tested against a single, in-process `ChainState`/
//! `HelixDb`/`BftEngine` — real `cargo test --workspace` never spawns more than one node
//! talking to another over real P2P. That gap is not theoretical: five of the seven bugs in
//! the "Multi-Node-Testnetz + Security-Audit" session (CLAUDE.md backlog item 47) — a
//! non-deterministic proposer order, an engine/store height desync on externally-finalized
//! blocks, dropped-instead-of-buffered precommits, a missing P2P tx broadcast, and an
//! `idle_connection_timeout` race — were structurally invisible to a single-validator devnet
//! and were only found because a human ran three real node processes by hand. Two more (a
//! missing genesis-adoption path for `sync_peer`, and a prev_hash-continuity gap in the
//! self-produced/voted block-ingestion path — see backlog item 50) were found the same way.
//!
//! This test automates the simplest version of that manual workflow: start one node fresh
//! (self-generates genesis, produces blocks alone — exactly like the current production
//! devnet), then start two more nodes pointed at it via `HELIX_SYNC_PEER`, and assert that
//! all three converge on identical height, block hash, *and* `state_hash` (execution result,
//! not just which blocks were agreed on — see `ChainState::state_hash`'s doc comment for why
//! that second check matters on its own). This exercises real P2P gossip, sync-peer genesis
//! adoption, `NewCommittedBlock` handling, and prev_hash continuity — exactly the bug classes
//! found by hand above.
//!
//! A second test below (`three_validators_rotate_proposer_and_finalize_blocks_together`,
//! CTO backlog item 56) goes further and exercises real multi-validator BFT — proposer
//! rotation and live voting across independent processes under real network latency, not
//! just gossip/sync agreement with a single active validator. It grows the set the only way a
//! Helix network can — funding two more validators from the genesis validator's liquid reserve
//! and staking them at runtime — then waits out their activation epochs. That path is slow at
//! the production 2 s/block (a fixed 200-block activation is ~7 minutes), so the test runs at an
//! accelerated `HELIX_BLOCK_TIME_MS` (which enters no hash and not the proposer schedule, so it
//! changes only wall-clock). There is deliberately no genesis pre-staking shortcut: a real
//! network never gains validators that way, and the test exercises the path that ships.
//!
//! That second test is marked `#[ignore]`: it spawns three real validator processes and waits
//! out two activation epochs plus a window of finalized blocks (~2 min wall-clock even
//! accelerated), which is slower than the rest of the suite is meant to be on every CI push. Run it
//! explicitly with `cargo test -p helix-node --test multi_node -- --ignored` (e.g. before a
//! release, or after touching consensus/BFT code — it's the regression guard for the
//! multi-validator round-synchronization and vote-buffering that make cold start converge).

use std::collections::HashSet;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use helix_crypto::{Address, KeyFile, KeyPair};

/// Distinct, uncommon port range so this doesn't collide with anything else that might be
/// running on a dev machine or CI runner. Nothing else in this workspace uses these.
const NODE_A_RPC: u16 = 29_545;
const NODE_A_P2P: u16 = 29_546;
const NODE_B_RPC: u16 = 29_555;
const NODE_B_P2P: u16 = 29_556;
const NODE_C_RPC: u16 = 29_565;
const NODE_C_P2P: u16 = 29_566;

/// Serializes the tests in this file that spawn real node processes.
///
/// Each of them brings up three or four complete BFT nodes with real sockets, real gossip and
/// wall-clock round timeouts. `cargo test` runs tests within a binary concurrently, so all of them
/// at once is fifteen-odd nodes competing for the same cores — and a consensus timeout that fires
/// because the machine was busy looks exactly like a consensus timeout that fires because the code
/// is wrong. Measured 2026-08-05: run in parallel, one or two fail; run with `--test-threads=1`,
/// all four pass; run individually, each passes.
///
/// Enforced here rather than by documenting `--test-threads=1`, because a test whose correctness
/// depends on a flag not present in the file is a test that will eventually be run without it —
/// and its failure will be read as a bug in the chain. Distinct port ranges (below) keep the tests
/// from colliding; this keeps them from starving each other.
static NODE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Separate port range for the multi-validator test below — it runs as a distinct
/// `#[tokio::test]` in the same test binary, and `cargo test` runs tests within a binary
/// concurrently by default, so it can't share ports with the test above.
const VAL_A_RPC: u16 = 29_575;
const VAL_A_P2P: u16 = 29_576;
const VAL_B_RPC: u16 = 29_585;
const VAL_B_P2P: u16 = 29_586;
const VAL_C_RPC: u16 = 29_595;
const VAL_C_P2P: u16 = 29_596;

/// Third port range, for the fault-tolerance test (4 validators, one killed mid-run). Same
/// concurrency reason as the range above — all three `#[tokio::test]`s share this binary.
const FT_A_RPC: u16 = 29_605;
const FT_A_P2P: u16 = 29_606;
const FT_B_RPC: u16 = 29_615;
const FT_B_P2P: u16 = 29_616;
const FT_C_RPC: u16 = 29_625;
const FT_C_P2P: u16 = 29_626;
const FT_D_RPC: u16 = 29_635;
const FT_D_P2P: u16 = 29_636;

/// Fourth port range, for the WebSocket-transport test. `WS_A_WS` is the extra
/// `HELIX_P2P_WS_LISTEN` port A listens on for P2P-inside-a-WebSocket, on top of its raw-TCP
/// `WS_A_P2P`.
const WS_A_RPC: u16 = 29_645;
const WS_A_P2P: u16 = 29_646;
const WS_A_WS: u16 = 29_647;
const WS_B_RPC: u16 = 29_655;
const WS_B_P2P: u16 = 29_656;

/// Fifth port range, for the runtime-join test — a validator funded, staked and activated *at
/// runtime* rather than pre-staked in genesis. Same shared-binary concurrency reason as above.
const JOIN_A_RPC: u16 = 29_665;
const JOIN_A_P2P: u16 = 29_666;
const JOIN_B_RPC: u16 = 29_675;
const JOIN_B_P2P: u16 = 29_676;

/// Block cadence for the runtime-join test only (`HELIX_BLOCK_TIME_MS`). The two activation
/// epochs a runtime joiner must cross are a fixed 200 blocks (`EPOCH_LENGTH` is a protocol
/// constant, deliberately not tunable), so at the production 2 s/block that alone is ~7 minutes.
/// Block time enters no hash and not the proposer schedule, so shrinking it changes only wall-clock.
const JOIN_BLOCK_TIME_MS: &str = "300";

/// How long `assert_states_converge` may spend *collecting* comparable samples before it gives up.
///
/// Not a "wait and see whether they agree" window: that helper compares `state_hash` at equal
/// `state_height`, and a committed height's hash never changes, so a mismatch fails on the spot
/// and no amount of waiting can rescue it. This bounds only how long the nodes are given to report
/// enough heights *in common* — a couple of blocks in the normal case, so exceeding it means the
/// nodes stopped advancing or stopped answering, not that they diverged.
const CONVERGENCE_GRACE: Duration = Duration::from_secs(60);

/// Owns a spawned node's child process and its temp working directory. Killing the process
/// on drop (even if the test panics or an assertion fails partway through) is the whole point
/// — without it, a failing run leaks `helix` processes still bound to these ports, and every
/// subsequent run on the same machine fails to bind and gives a confusing, unrelated error.
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

fn spawn_node(rpc_port: u16, p2p_port: u16, sync_peer_rpc_port: Option<u16>) -> NodeGuard {
    spawn_node_with(rpc_port, p2p_port, sync_peer_rpc_port, &[], None)
}

/// `extra_env` — additional env vars beyond the standard bind/listen/sync-peer ones (e.g.
/// `HELIX_BLOCK_TIME_MS` to accelerate activation epochs). `keypair` — if set, pre-writes
/// `validator-key.json` into the node's work dir so it starts with this exact validator
/// identity instead of generating a random one, so the test can address funding transfers to a
/// follower and that follower still ends up controlling the stake it later stakes.
/// Panics with a diagnosis if `port` is taken, instead of letting the test start a node that
/// cannot bind and then time out on a symptom far from the cause.
fn assert_port_free(port: u16, label: &str) {
    // The listener is dropped immediately; this only asks whether the port is claimable right
    // now. A race against something else grabbing it in between is irrelevant here — the case
    // being caught is a process that has been holding it since a previous run.
    if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
        panic!(
            "{label} port {port} is already in use — most likely a helix node left over from an \
             aborted test run is still listening, and this test would talk to it instead of the \
             node it starts (a different chain, so it fails later for a reason that looks like a \
             consensus bug). Find it with `ss -tlnp | grep {port}` and kill it by PID.\n\
             Note: `pkill -f \"target/debug/helix start\"` matches its own shell command line and \
             kills the pkill itself before it gets to them — use the PID."
        );
    }
}

fn spawn_node_with(
    rpc_port: u16,
    p2p_port: u16,
    sync_peer_rpc_port: Option<u16>,
    extra_env: &[(&str, &str)],
    keypair: Option<&KeyPair>,
) -> NodeGuard {
    // Fail here, with the actual reason, rather than 240 seconds later with "did not reach
    // height N". These ports are fixed (they have to be — the tests build multiaddrs from
    // them), so a node surviving an aborted run keeps listening and the next run silently talks
    // to a leftover process carrying a foreign chain. That happened twice on 2026-07-21 and was
    // misread both times as a consensus regression; the test itself had been green throughout.
    // `ss -tlnp` eventually showed the zombies. One bind attempt turns an hour of misdiagnosis
    // into a sentence.
    assert_port_free(rpc_port, "RPC");
    assert_port_free(p2p_port, "P2P");

    let work_dir = tempdir::TempDir::new().expect("create temp work dir for node");
    if let Some(kp) = keypair {
        KeyFile::from_keypair_plain(kp)
            .save(&work_dir.path().join("validator-key.json"))
            .expect("pre-write validator key file");
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_helix"));
    cmd.arg("start");
    cmd.current_dir(work_dir.path())
        .env("HELIX_RPC_BIND", format!("127.0.0.1:{rpc_port}"))
        .env("HELIX_P2P_LISTEN", format!("127.0.0.1:{p2p_port}"))
        // Disable mDNS: these test nodes must peer ONLY with each other (via sync_peer +
        // peer exchange), never with any other Helix node that happens to share the
        // machine's LAN. A live production node discovered via mDNS would gossip its
        // height-36000+ proposals/votes/committed-blocks into this fresh testnet, which
        // then burns every round rejecting them and firing futile catch-up-sync attempts —
        // observed to stall the testnet near height 1-2 and make this test flaky. See
        // helix_p2p::P2PConfig::enable_mdns.
        .env("HELIX_P2P_DISABLE_MDNS", "1")
        // Standalone test chain: without this, a node with no explicit HELIX_SYNC_PEER (the
        // genesis node A) would default to seeding from the public production endpoint instead
        // of self-signing its own genesis. Followers set HELIX_SYNC_PEER explicitly, which
        // overrides this anyway — but setting it on every node keeps the intent unambiguous.
        .env("HELIX_NEW_CHAIN", "1")
        .env("RUST_LOG", std::env::var("HELIX_TEST_LOG").unwrap_or_else(|_| "error".into()));

    // Quiet by default — a green run should not litter the disk. Set `HELIX_TEST_LOG_DIR` (plus
    // `HELIX_TEST_LOG=info` for anything to actually be written) to keep each node's output in
    // `<dir>/node-<rpc_port>.log`. Without this, diagnosing a failure that only reproduces across
    // three real processes means re-running blind: the panic message is all there is, and the node
    // that misbehaved has already been killed by `NodeGuard::drop`.
    match std::env::var("HELIX_TEST_LOG_DIR") {
        Ok(dir) if !dir.is_empty() => {
            let path = std::path::Path::new(&dir).join(format!("node-{rpc_port}.log"));
            let _ = std::fs::create_dir_all(&dir);
            let file = std::fs::File::create(&path).expect("create node log file");
            let dup = file.try_clone().expect("clone node log handle");
            cmd.stdout(Stdio::from(file)).stderr(Stdio::from(dup));
        }
        _ => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    if let Some(peer_port) = sync_peer_rpc_port {
        cmd.env("HELIX_SYNC_PEER", format!("http://127.0.0.1:{peer_port}"));
    }
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let child = cmd.spawn().expect("spawn helix node binary");
    NodeGuard { child, _work_dir: work_dir }
}

async fn block_header(rpc_port: u16, height: u64) -> Option<serde_json::Value> {
    reqwest::get(format!("http://127.0.0.1:{rpc_port}/blocks/height/{height}/header"))
        .await
        .ok()?
        .json()
        .await
        .ok()
}

async fn status(rpc_port: u16) -> Option<serde_json::Value> {
    reqwest::get(format!("http://127.0.0.1:{rpc_port}/status"))
        .await
        .ok()?
        .json()
        .await
        .ok()
}

async fn validators(rpc_port: u16) -> Option<serde_json::Value> {
    reqwest::get(format!("http://127.0.0.1:{rpc_port}/validators"))
        .await
        .ok()?
        .json()
        .await
        .ok()
}

/// Assert that all three nodes computed the same state and the same chain.
///
/// **Compared per height, never per sampling instant.** The earlier version of this helper waited
/// for one pass in which all three nodes reported the same `height` *and* the same `state_hash`,
/// and treated a failure to find one as a divergence. That comparison cannot work, for two
/// independent reasons:
///
/// 1. `height`/`best_hash` come from the block store while `state_hash` comes from the in-memory
///    `ChainState`, and `apply_finalized_block` advances them at different moments. A response
///    sampled in between carries height N−1 next to the state of N. `/status` exposes
///    **`state_height`** precisely so this pair can be matched correctly — see its doc comment in
///    `helix-rpc`, which has said "compare it against `state_height`, not `height`" since
///    2026-07-22. This test never adopted it.
/// 2. Even with a correct pair, requiring three independent processes to be sampled at the same
///    height over three sequential HTTP round trips is a coincidence, and at a 300 ms cadence a
///    rare one. Failing to observe the coincidence says nothing about the chain.
///
/// So: sample all three continuously, keep `state_height → state_hash` and `height → best_hash`
/// per node, and compare **at heights all three have reported**. A hash for a given height is
/// immutable once committed, so no grace window or "did it heal?" reasoning is needed — agreement
/// at a common height is proof of agreement, and disagreement at a common height is proof of
/// divergence and fails immediately. `grace` now bounds only how long we wait to *accumulate*
/// enough common heights, which normally takes a couple of blocks.
///
/// Divergence is the case worth catching: `ChainState::active_validators` is deliberately excluded
/// from `state_hash` (see its doc comment), and the argument for that exclusion is that a
/// disagreement surfaces one step later in `missed_blocks`/`jailed_until`, which *are* hashed —
/// hence the `/validators` dump on failure, where such a split is visible.
async fn assert_states_converge(rpc_ports: [u16; 3], grace: Duration) {
    /// How many distinct heights must be observed on all three nodes before the agreement counts.
    /// More than one, so a single lucky sample can't carry the assertion.
    const REQUIRED_COMMON_HEIGHTS: usize = 3;

    let deadline = std::time::Instant::now() + grace;
    let mut states: [std::collections::HashMap<u64, String>; 3] = Default::default();
    let mut blocks: [std::collections::HashMap<u64, String>; 3] = Default::default();

    loop {
        for (i, port) in rpc_ports.iter().enumerate() {
            let Some(s) = status(*port).await else { continue };
            if let (Some(h), Some(hash)) = (s["state_height"].as_u64(), s["state_hash"].as_str()) {
                states[i].insert(h, hash.to_string());
            }
            if let (Some(h), Some(hash)) = (s["height"].as_u64(), s["best_hash"].as_str()) {
                blocks[i].insert(h, hash.to_string());
            }
        }

        // Genesis is height 0 on every node by construction and would count as free agreement.
        let common = |maps: &[std::collections::HashMap<u64, String>; 3]| -> Vec<u64> {
            let mut hs: Vec<u64> = maps[0]
                .keys()
                .filter(|h| **h > 0 && maps[1].contains_key(h) && maps[2].contains_key(h))
                .copied()
                .collect();
            hs.sort_unstable();
            hs
        };
        let common_states = common(&states);
        let common_blocks = common(&blocks);

        // Disagreement at a shared height is final — a committed height's hash never changes, so
        // there is nothing to wait for.
        for h in &common_states {
            let seen = [&states[0][h], &states[1][h], &states[2][h]];
            if seen[0] != seen[1] || seen[0] != seen[2] {
                let mut report = String::new();
                for (label, port) in ["A", "B", "C"].iter().zip(rpc_ports) {
                    // The three aggregates that separate "the accounts differ" (rewards, fees,
                    // a replayed or dropped transaction) from "the validator bookkeeping differs"
                    // (missed_blocks/jailed_until/the pending/probation tiers) — worth having in
                    // the failure itself, because the processes are killed the moment it panics.
                    let s = status(port).await.unwrap_or(serde_json::Value::Null);
                    let v = validators(port).await.unwrap_or(serde_json::Value::Null);
                    report.push_str(&format!(
                        "\n  node {label} (:{port}) accounts={} supply={} burned={}\n    validators = {v}",
                        s["total_accounts"], s["circulating_supply_hlx"], s["total_burned_hlx"],
                    ));
                }
                panic!(
                    "the three nodes executed height {h} to different state — a real divergence, \
                     not a /status read-skew (this compares state_hash at equal state_height).\
                     \n  state_hash = {seen:?}\
                     \n\nactive_validators is not covered by state_hash, so a split there surfaces \
                     as missed_blocks/jailed_until — compare those:{report}"
                );
            }
        }
        for h in &common_blocks {
            let seen = [&blocks[0][h], &blocks[1][h], &blocks[2][h]];
            assert!(
                seen[0] == seen[1] && seen[0] == seen[2],
                "the three nodes disagree on the block hash at height {h} — a fork.\n  best_hash = {seen:?}"
            );
        }

        if common_states.len() >= REQUIRED_COMMON_HEIGHTS && common_blocks.len() >= REQUIRED_COMMON_HEIGHTS {
            return;
        }

        assert!(
            std::time::Instant::now() < deadline,
            "the three nodes never reported {REQUIRED_COMMON_HEIGHTS} heights in common within \
             {grace:?} — they agreed on every height that could be compared ({} state, {} block), \
             so this is a liveness or reachability problem, not a divergence",
            common_states.len(),
            common_blocks.len(),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Polls `/status` until the node responds at all (its RPC server is up) — startup involves
/// genesis creation/adoption and, for a `sync_peer` node, a full historical sync, so this can
/// take a few seconds longer than a bare process spawn.
async fn wait_until_reachable(rpc_port: u16, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if status(rpc_port).await.is_some() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "node on RPC port {rpc_port} never became reachable within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Polls until `rpc_port` reports a height >= `min_height`, returning its final `/status`.
async fn wait_for_height(rpc_port: u16, min_height: u64, timeout: Duration) -> serde_json::Value {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(s) = status(rpc_port).await {
            if s["height"].as_u64().unwrap_or(0) >= min_height {
                return s;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "node on RPC port {rpc_port} did not reach height {min_height} within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn account(rpc_port: u16, address: &str) -> Option<serde_json::Value> {
    reqwest::get(format!("http://127.0.0.1:{rpc_port}/accounts/{address}"))
        .await
        .ok()?
        .json()
        .await
        .ok()
}

/// Write a keypair to a throwaway plaintext key file the `helix` CLI can sign transactions with
/// (`--key`). The returned `TempDir` must stay alive for the file to exist.
fn temp_keyfile(kp: &KeyPair) -> (tempdir::TempDir, std::path::PathBuf) {
    let dir = tempdir::TempDir::new().expect("temp dir for key file");
    let path = dir.path().join("signer-key.json");
    KeyFile::from_keypair_plain(kp).save(&path).expect("save plaintext key file");
    (dir, path)
}

/// Run the real `helix` CLI binary against `node_url` (via `HELIX_NODE`), returning the exit
/// status. This is the same binary an operator runs — `helix tx send` / `helix tx stake` — so the
/// test exercises transaction building, signing, nonce fetch and submission end to end, not a
/// test-only shortcut.
fn run_cli(node_url: &str, args: &[&str]) -> bool {
    Command::new(env!("CARGO_BIN_EXE_helix"))
        .env("HELIX_NODE", node_url)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run helix CLI")
        .success()
}

/// The focused, minimal runtime join, over the **real `helix` binary**: an operator funds a second
/// account, that account stakes with a real `helix tx stake`, waits out its activation, and must
/// then actually co-sign. The 3- and 4-validator tests grow their sets the same way, but this one
/// isolates a single 1→2 crossing so the co-sign proof needs no signature inspection at all (see
/// below). This is the path every real operator takes, and the one that kept stalling.
///
/// The decisive assertion needs no signature inspection: node A starts as the *sole* validator, so
/// once B is active the set is 2-of-2, whose quorum needs **both** votes — A alone mathematically
/// cannot finalize another block. So if the height keeps climbing *after* B activates, B is
/// provably co-signing. A stall (B bonded-but-silent) would freeze the height instead, exactly the
/// live symptom.
///
/// Honest scope: with both nodes healthy, B crosses its activation *live* (connected, voting), so
/// this exercises the runtime stake→activate→co-sign path of the real binary rather than the
/// sync-path activation race of #130 — that race is covered deterministically by
/// `a_third_validator_joining_over_sync_matches_the_incumbents_set_and_schedule` in the node crate,
/// which can force the crossing to happen over `sync_blocks_from_peer` without a flaky process race.
#[tokio::test]
#[ignore = "spawns 2 real node processes, funds+stakes a validator via the real CLI, and waits out its ~200-block activation at an accelerated block time (~1-2 min wall-clock) — run explicitly with --ignored"]
async fn a_validator_funded_and_staked_at_runtime_activates_and_co_signs() {
    let _serialized = NODE_TEST_LOCK.lock().await;
    let kp_a = KeyPair::generate();
    let kp_b = KeyPair::generate();
    let addr_b = Address::from_public_key(&kp_b.public).to_string();

    let ma = |port: u16| format!("/ip4/127.0.0.1/tcp/{port}");
    let fast = ("HELIX_BLOCK_TIME_MS", JOIN_BLOCK_TIME_MS);

    // A: fresh single-validator genesis (its 500k liquid reserve is what funds B), known key so the
    // test can sign transfers from it. Seeds toward B so the two form a mesh once B is up.
    let seeds_a = ma(JOIN_B_P2P);
    let _node_a = spawn_node_with(
        JOIN_A_RPC,
        JOIN_A_P2P,
        None,
        &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_a)],
        Some(&kp_a),
    );
    wait_until_reachable(JOIN_A_RPC, Duration::from_secs(15)).await;
    wait_for_height(JOIN_A_RPC, 2, Duration::from_secs(30)).await;

    // B: fresh node, no local chain, joins by syncing A's genesis + history — the real join path.
    let seeds_b = ma(JOIN_A_P2P);
    let _node_b = spawn_node_with(JOIN_B_RPC, JOIN_B_P2P, Some(JOIN_A_RPC), &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_b)], Some(&kp_b));
    wait_until_reachable(JOIN_B_RPC, Duration::from_secs(15)).await;

    // Fund B from A's liquid reserve — `helix tx send`, signed by A's key. 110k HLX: 100k to stake
    // plus a margin for fees, mirroring how the live validators were funded.
    let (_kd_a, key_a) = temp_keyfile(&kp_a);
    let a_url = format!("http://127.0.0.1:{JOIN_A_RPC}");
    assert!(
        run_cli(&a_url, &["tx", "send", &addr_b, "110000", "--key", key_a.to_str().unwrap()]),
        "helix tx send (fund B) exited non-zero"
    );
    let funded = wait_for_account(JOIN_A_RPC, &addr_b, |a| a["balance_hlx"].as_f64().unwrap_or(0.0) >= 110_000.0, Duration::from_secs(30)).await;
    assert!(funded, "B was never credited the 110k funding transfer");

    // B stakes 100k — `helix tx stake`, signed by B's key. This is the transaction that makes B a
    // validator; it takes effect at the next epoch boundary and B activates one epoch after that.
    let (_kd_b, key_b) = temp_keyfile(&kp_b);
    assert!(
        run_cli(&a_url, &["tx", "stake", "100000", "--key", key_b.to_str().unwrap()]),
        "helix tx stake exited non-zero"
    );
    let staked = wait_for_account(JOIN_A_RPC, &addr_b, |a| a["staked_hlx"].as_f64().unwrap_or(0.0) >= 100_000.0, Duration::from_secs(30)).await;
    assert!(staked, "B's stake never took effect on chain");

    // B must cross **three** rotations before it is active: a new staker waits one epoch in
    // `pending_validators`, one in `probationary_validators`, and is promoted at the rotation
    // after that (`ChainState::rotate_active_validators`). `EPOCH_LENGTH` is 100, so the wait is
    // ~300 blocks, not the ~200 this comment used to claim.
    //
    // The window is generous because the cadence is not ours to set: `JOIN_BLOCK_TIME_MS` is the
    // *sleep* between ticks, and a debug build on a loaded machine spends far longer than that
    // building and signing each block — measured 2026-08-26 at 0.91 s per block against a
    // configured 300 ms. At 180 s this timed out mid-activation and reported "the activation
    // stalled", which sent a whole session looking for a bug in probation that was not there.
    let active = wait_for_validator_active(JOIN_A_RPC, &addr_b, Duration::from_secs(420)).await;
    assert!(active, "B staked but never entered the active validator set — the activation stalled");

    // THE anti-stall assertion: A alone cannot finalize in a 2-of-2 set, so height advancing past
    // B's activation proves B is co-signing, not sitting bonded-but-silent.
    let height_at_activation = status(JOIN_A_RPC).await.unwrap()["height"].as_u64().unwrap();
    // 180 s rather than 60: the assertion is about the chain *advancing*, not about how fast. The
    // moment a set grows from one validator to two is also the moment the two have to find the
    // same round for the first time, and on a loaded machine that reconciliation can cost a round
    // or two before the cadence settles. Sixty seconds made a green run depend on the machine
    // being idle — measured 2026-08-26, this test passing alone and failing in the same serial run
    // as the other four.
    wait_for_height(JOIN_A_RPC, height_at_activation + 10, Duration::from_secs(180)).await;

    // And both nodes agree on the result — no fork or execution divergence across the join.
    // Third port is A again: this is a 2-node test, so "all three agree" is just "A and B agree".
    let target = status(JOIN_A_RPC).await.unwrap()["height"].as_u64().unwrap();
    wait_for_matching_snapshot([JOIN_A_RPC, JOIN_B_RPC, JOIN_A_RPC], target, Duration::from_secs(60)).await;
    assert_states_converge([JOIN_A_RPC, JOIN_B_RPC, JOIN_A_RPC], CONVERGENCE_GRACE).await;
}

/// Poll `/accounts/:address` on `rpc_port` until `pred` holds or `timeout` elapses.
async fn wait_for_account<F: Fn(&serde_json::Value) -> bool>(
    rpc_port: u16,
    address: &str,
    pred: F,
    timeout: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(a) = account(rpc_port, address).await {
            if pred(&a) {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Poll `/validators` on `rpc_port` until `address` shows `active == true` or `timeout` elapses.
/// The endpoint returns an object `{"validators": [...], ...}`, not a bare array — reaching in for
/// the `validators` field is the difference between measuring activation and measuring nothing.
async fn wait_for_validator_active(rpc_port: u16, address: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let active = validators(rpc_port)
            .await
            .as_ref()
            .and_then(|v| v.get("validators"))
            .and_then(|v| v.as_array())
            .is_some_and(|list| {
                list.iter().any(|v| {
                    v["address"].as_str() == Some(address) && v["active"].as_bool() == Some(true)
                })
            });
        if active {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Fund `joiner` from the genesis validator's liquid reserve and stake it — the two transactions
/// that turn a plain account into a validator over the real production path (there is deliberately
/// no genesis shortcut for pre-staking extra validators; a network grows from one validator by
/// funding and staking more at runtime). Does NOT wait for activation: callers that stake several
/// joiners want them to cross their activation epochs *together*, so staking is separated from the
/// wait. `funder_key` signs the transfer (from the genesis validator's 500k reserve); `joiner_key`
/// signs the stake. Both submit through `funder_rpc`, and each step waits for its on-chain effect
/// before returning, so A's nonce has advanced before the next funding transfer is signed (back to
/// back transfers sharing a committed nonce would collide).
async fn fund_and_stake(
    funder_rpc: u16,
    funder_key: &std::path::Path,
    joiner_kp: &KeyPair,
    joiner_key: &std::path::Path,
) {
    let addr = Address::from_public_key(&joiner_kp.public).to_string();
    let url = format!("http://127.0.0.1:{funder_rpc}");
    // 110k HLX: 100k to stake plus a fee margin, mirroring how the live validators were funded.
    assert!(
        run_cli(&url, &["tx", "send", &addr, "110000", "--key", funder_key.to_str().unwrap()]),
        "helix tx send (fund {addr}) exited non-zero"
    );
    let funded = wait_for_account(funder_rpc, &addr, |a| a["balance_hlx"].as_f64().unwrap_or(0.0) >= 110_000.0, Duration::from_secs(30)).await;
    assert!(funded, "{addr} was never credited its 110k funding transfer");

    assert!(
        run_cli(&url, &["tx", "stake", "100000", "--key", joiner_key.to_str().unwrap()]),
        "helix tx stake ({addr}) exited non-zero"
    );
    let staked = wait_for_account(funder_rpc, &addr, |a| a["staked_hlx"].as_f64().unwrap_or(0.0) >= 100_000.0, Duration::from_secs(30)).await;
    assert!(staked, "{addr}'s stake never took effect on chain");
}

#[tokio::test]
async fn three_nodes_converge_on_identical_height_hash_and_state() {
    let _serialized = NODE_TEST_LOCK.lock().await;
    // Node A: fresh devnet genesis, produces blocks alone — exactly today's production setup.
    let _node_a = spawn_node(NODE_A_RPC, NODE_A_P2P, None);
    wait_until_reachable(NODE_A_RPC, Duration::from_secs(15)).await;
    // Let A get a small head start before anyone tries to sync from it, so there's real
    // history (not just genesis) to actually exercise the sync path.
    wait_for_height(NODE_A_RPC, 2, Duration::from_secs(15)).await;

    // Nodes B and C: fresh processes with no local chain, pointed at A via HELIX_SYNC_PEER —
    // this is exactly the genesis-adoption + historical-sync path added in this same session
    // (see the module doc comment).
    let _node_b = spawn_node(NODE_B_RPC, NODE_B_P2P, Some(NODE_A_RPC));
    let _node_c = spawn_node(NODE_C_RPC, NODE_C_P2P, Some(NODE_A_RPC));
    wait_until_reachable(NODE_B_RPC, Duration::from_secs(15)).await;
    wait_until_reachable(NODE_C_RPC, Duration::from_secs(15)).await;

    // Give the whole fleet time to mesh over gossipsub (empirically 10-40+ seconds for a
    // newly joined peer — see CLAUDE.md backlog item 49's note on this) and for B/C's
    // catch-up sync to actually complete, then require a real, non-trivial height so this
    // isn't just asserting genesis-only agreement.
    //
    // `/status` always reports each node's *current* tip — there's no height-pinned
    // state_hash endpoint (only /blocks/height/:n/header, which has no state_hash at all).
    // Since all three nodes keep independently advancing the whole time this test runs,
    // querying them one after another and comparing would compare three different heights,
    // not the same one — not a race-free check at all. Instead, poll all three nodes
    // together and only accept a round where all three report the *identical* height in
    // that same round: block production is ~2s apart, so there's a real window where all
    // three sit at the same height before the next block moves any of them, and this loop
    // just keeps retrying until it catches one — it can never falsely report agreement.
    let target_height = 6;
    let (a, b, c) = wait_for_matching_snapshot([NODE_A_RPC, NODE_B_RPC, NODE_C_RPC], target_height, Duration::from_secs(90)).await;

    assert_eq!(a["best_hash"], b["best_hash"], "node A and B disagree on the block hash at height {}", a["height"]);
    assert_eq!(a["best_hash"], c["best_hash"], "node A and C disagree on the block hash at height {}", a["height"]);

    // The state comparison deliberately does *not* reuse these three snapshots: `state_hash`
    // belongs to `state_height`, not to `height`, so comparing it across nodes that merely share a
    // `height` compares two different heights' state whenever one of them is mid-commit. See
    // `assert_states_converge`, which matches on `state_height` instead.
    assert_states_converge([NODE_A_RPC, NODE_B_RPC, NODE_C_RPC], CONVERGENCE_GRACE).await;
}

/// CTO backlog item 56. Boots a real 3-validator BFT set — grown from one genesis validator by
/// funding and staking two more at runtime, the only way a Helix network gains validators (there
/// is no genesis pre-staking shortcut) — and asserts two things a single-active-validator setup
/// structurally cannot exercise: (1) more than one of the three distinct validator addresses
/// actually proposes a block — real round-robin rotation, not just one validator winning every
/// round — and (2) all three nodes still converge on identical height, hash, and state despite
/// that rotation happening across independent processes over real network latency, the same bug
/// class (backlog item 47) that a non-deterministic proposer order or an engine height desync
/// would reproduce under exactly these conditions.
#[tokio::test]
#[ignore = "spawns 3 real validator processes and grows the set by funding+staking two at runtime, waiting out their activation epochs at an accelerated block time (~2 min wall-clock) — run explicitly with --ignored, not on every CI push"]
async fn three_validators_rotate_proposer_and_finalize_blocks_together() {
    let _serialized = NODE_TEST_LOCK.lock().await;
    // B and C's validator identities are generated up front so their processes can start with a
    // matching `validator-key.json` (so they control the stake staked to their addresses) and so
    // the test can address the funding transfers.
    let kp_a = KeyPair::generate();
    let kp_b = KeyPair::generate();
    let kp_c = KeyPair::generate();
    let addr_b = Address::from_public_key(&kp_b.public);
    let addr_c = Address::from_public_key(&kp_c.public);

    // Wire all three validators into a full P2P mesh via explicit seed peers (each dials the
    // other two directly), rather than hub-and-spoke through A. In a validator set every node
    // must peer with every other: BFT relays prevotes/precommits between all of them, and a
    // star that relays only through one hub both drops votes and can't survive that hub. These
    // are libp2p multiaddrs for the loopback P2P ports.
    let ma = |port: u16| format!("/ip4/127.0.0.1/tcp/{port}");
    let seeds_a = format!("{},{}", ma(VAL_B_P2P), ma(VAL_C_P2P));
    let seeds_b = format!("{},{}", ma(VAL_A_P2P), ma(VAL_C_P2P));
    let seeds_c = format!("{},{}", ma(VAL_A_P2P), ma(VAL_B_P2P));

    // Accelerated block time so the two 100-block activation epochs the joiners cross pass in ~1
    // minute rather than ~7 (see JOIN_BLOCK_TIME_MS); it enters no hash and not the proposer
    // schedule. A is spawned with a known key so the test can sign the funding transfers from its
    // 500k liquid reserve.
    let fast = ("HELIX_BLOCK_TIME_MS", JOIN_BLOCK_TIME_MS);
    let _node_a = spawn_node_with(VAL_A_RPC, VAL_A_P2P, None, &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_a)], Some(&kp_a));
    wait_until_reachable(VAL_A_RPC, Duration::from_secs(15)).await;
    wait_for_height(VAL_A_RPC, 2, Duration::from_secs(30)).await;

    // B and C join by syncing A's genesis + history (the real join path) with the same full-mesh
    // seed peers, then stake at runtime. With `ValidatorSet::new`'s 1%-of-total-stake cap making
    // every validator's voting power identical once active, quorum genuinely needs all three
    // voting — a real multi-validator BFT round, proposal + two-phase commit, not a single-proposer
    // shortcut.
    let _node_b = spawn_node_with(VAL_B_RPC, VAL_B_P2P, Some(VAL_A_RPC), &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_b)], Some(&kp_b));
    let _node_c = spawn_node_with(VAL_C_RPC, VAL_C_P2P, Some(VAL_A_RPC), &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_c)], Some(&kp_c));
    wait_until_reachable(VAL_B_RPC, Duration::from_secs(15)).await;
    wait_until_reachable(VAL_C_RPC, Duration::from_secs(15)).await;

    // Fund and stake both joiners (from A's reserve) before waiting on either activation, so they
    // cross their activation epochs together and the set grows 1→3 rather than one at a time.
    let (_kd_a, key_a) = temp_keyfile(&kp_a);
    let (_kd_b, key_b) = temp_keyfile(&kp_b);
    let (_kd_c, key_c) = temp_keyfile(&kp_c);
    fund_and_stake(VAL_A_RPC, &key_a, &kp_b, &key_b).await;
    fund_and_stake(VAL_A_RPC, &key_a, &kp_c, &key_c).await;
    // 420 s, for the same measured reason as the runtime-join test above: activation is a fixed
    // ~300 blocks (pending → probation → active), and the *cadence* is not ours to set —
    // `VAL_BLOCK_TIME_MS` is the sleep between ticks, while a debug build on a loaded machine
    // spends far longer than that building and signing each block (0.91 s against a configured
    // 300 ms, measured 2026-08-26). Too short a window here does not report "slow", it reports
    // "activation stalled", which reads as a bug in probation and cost a session finding out it
    // was not one.
    assert!(
        wait_for_validator_active(VAL_A_RPC, &addr_b.to_string(), Duration::from_secs(420)).await,
        "B staked but never entered the active validator set — activation stalled"
    );
    assert!(
        wait_for_validator_active(VAL_A_RPC, &addr_c.to_string(), Duration::from_secs(420)).await,
        "C staked but never entered the active validator set — activation stalled"
    );

    // With all three active and co-signing, finalization continues with proposer rotation across
    // all three. The window starts from here so every sampled height is a genuine 3-validator
    // round. The timeout is deliberately far larger than needed, to stay green on a slow/loaded CI
    // machine without masking a genuine stall.
    let start = status(VAL_A_RPC).await.unwrap()["height"].as_u64().unwrap();
    let target_height = start + 10;
    wait_for_height(VAL_A_RPC, target_height, Duration::from_secs(180)).await;

    let mut distinct_proposers = HashSet::new();
    for height in (start + 1)..=target_height {
        let header = block_header(VAL_A_RPC, height)
            .await
            .unwrap_or_else(|| panic!("node A has no header for height {height} despite reporting that height"));
        distinct_proposers.insert(header["validator"].as_str().unwrap().to_string());
    }
    assert!(
        distinct_proposers.len() > 1,
        "only one validator ({:?}) ever proposed across the {} blocks after all three activated — \
         proposer rotation isn't actually happening despite 3 active validators",
        distinct_proposers, target_height - start
    );

    // Same convergence check as the single-validator test above — rotation happening across
    // independent processes must not cost agreement on the result. Given a grace window rather
    // than sampled once: see `assert_states_converge` for why a single sample cannot tell a
    // `/status` read-skew from a real state divergence, and why that distinction is the whole
    // point of this assertion.
    wait_for_matching_snapshot([VAL_A_RPC, VAL_B_RPC, VAL_C_RPC], target_height, Duration::from_secs(120)).await;
    assert_states_converge([VAL_A_RPC, VAL_B_RPC, VAL_C_RPC], CONVERGENCE_GRACE).await;
}

/// Fault tolerance: a 4-validator BFT set must survive one validator going offline, because
/// `2/3 + 1` of four equal-capped voters is three — a quorum the remaining three still meet.
/// This is the whole reason to run ≥4 validators (`3f + 1` tolerates `f` down), and the case a
/// 3-validator set (where 2 of 3 fall one short of quorum) structurally cannot pass. It also
/// pins the dead-proposer-recovery fix: before it, killing one validator halted the chain
/// forever, because the round-timeout clock only ran on the node holding an active round (the
/// proposer), so a dead proposer left every other validator waiting on a proposal that never
/// came, with nothing advancing them to the next round's live proposer.
#[tokio::test]
#[ignore = "spawns 4 real validator processes (grown by funding+staking three at runtime), kills one, and waits out several round timeouts at an accelerated block time (~2-3 min wall-clock) — run explicitly with --ignored, not on every CI push"]
async fn four_validators_survive_one_going_offline() {
    let _serialized = NODE_TEST_LOCK.lock().await;
    let kp_a = KeyPair::generate();
    let kp_b = KeyPair::generate();
    let kp_c = KeyPair::generate();
    let kp_d = KeyPair::generate();
    let addr_b = Address::from_public_key(&kp_b.public);
    let addr_c = Address::from_public_key(&kp_c.public);
    let addr_d = Address::from_public_key(&kp_d.public);

    let ma = |port: u16| format!("/ip4/127.0.0.1/tcp/{port}");
    let seeds_a = format!("{},{},{}", ma(FT_B_P2P), ma(FT_C_P2P), ma(FT_D_P2P));
    let seeds_b = format!("{},{},{}", ma(FT_A_P2P), ma(FT_C_P2P), ma(FT_D_P2P));
    let seeds_c = format!("{},{},{}", ma(FT_A_P2P), ma(FT_B_P2P), ma(FT_D_P2P));
    let seeds_d = format!("{},{},{}", ma(FT_A_P2P), ma(FT_B_P2P), ma(FT_C_P2P));

    // Accelerated block time (see JOIN_BLOCK_TIME_MS) so the joiners' activation epochs pass in
    // ~1 minute; A carries a known key so the test can fund the other three from its 500k reserve.
    let fast = ("HELIX_BLOCK_TIME_MS", JOIN_BLOCK_TIME_MS);
    let _node_a = spawn_node_with(FT_A_RPC, FT_A_P2P, None, &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_a)], Some(&kp_a));
    wait_until_reachable(FT_A_RPC, Duration::from_secs(15)).await;
    wait_for_height(FT_A_RPC, 2, Duration::from_secs(30)).await;
    let _node_b = spawn_node_with(FT_B_RPC, FT_B_P2P, Some(FT_A_RPC), &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_b)], Some(&kp_b));
    let _node_c = spawn_node_with(FT_C_RPC, FT_C_P2P, Some(FT_A_RPC), &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_c)], Some(&kp_c));
    let node_d = spawn_node_with(FT_D_RPC, FT_D_P2P, Some(FT_A_RPC), &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_d)], Some(&kp_d));
    wait_until_reachable(FT_B_RPC, Duration::from_secs(15)).await;
    wait_until_reachable(FT_C_RPC, Duration::from_secs(15)).await;
    wait_until_reachable(FT_D_RPC, Duration::from_secs(15)).await;

    // Grow the set from 1 to 4 by funding and staking B, C, D at runtime. Staked together so they
    // cross their activation epochs in one boundary and the full 4-validator set forms at once.
    let (_kd_a, key_a) = temp_keyfile(&kp_a);
    let (_kd_b, key_b) = temp_keyfile(&kp_b);
    let (_kd_c, key_c) = temp_keyfile(&kp_c);
    let (_kd_d, key_d) = temp_keyfile(&kp_d);
    fund_and_stake(FT_A_RPC, &key_a, &kp_b, &key_b).await;
    fund_and_stake(FT_A_RPC, &key_a, &kp_c, &key_c).await;
    fund_and_stake(FT_A_RPC, &key_a, &kp_d, &key_d).await;
    // 420 s each — see the comment on the three-validator test above; all three cross their
    // activation epochs together, so this is one wait, not three consecutive ones.
    for (addr, label) in [(&addr_b, "B"), (&addr_c, "C"), (&addr_d, "D")] {
        assert!(
            wait_for_validator_active(FT_A_RPC, &addr.to_string(), Duration::from_secs(420)).await,
            "{label} staked but never entered the active validator set — activation stalled"
        );
    }

    // All four finalize an initial run of blocks together.
    let before = wait_for_height(FT_A_RPC, status(FT_A_RPC).await.unwrap()["height"].as_u64().unwrap() + 4, Duration::from_secs(120)).await;
    let height_at_kill = before["height"].as_u64().unwrap();

    // Take D offline (Drop kills its process). The remaining three are still a quorum, so
    // finalization must continue — just slower, since each round D would have proposed now
    // times out before the next proposer steps up.
    drop(node_d);

    // Progress past the kill is the core assertion: before the dead-proposer fix this hung
    // here forever. Timeout is generous for several ~round-timeout-long dead-proposer slots
    // on a loaded machine.
    let target = height_at_kill + 6;
    wait_for_height(FT_A_RPC, target, Duration::from_secs(240)).await;

    // The three survivors must also stay in agreement — identical height, block hash, AND
    // state hash — i.e. the outage caused no fork or execution divergence. Same grace-window
    // treatment as the 3-validator test: a single sample of `/status` cannot distinguish a
    // read-skew between the block store and the in-memory ChainState from a genuine split, and
    // this assertion failed that way roughly one run in three on 2026-07-22.
    wait_for_matching_snapshot([FT_A_RPC, FT_B_RPC, FT_C_RPC], target, Duration::from_secs(90)).await;
    assert_states_converge([FT_A_RPC, FT_B_RPC, FT_C_RPC], CONVERGENCE_GRACE).await;
}

/// A follower reaches a node and follows its chain over a **WebSocket** P2P transport
/// (`/ip4/.../tcp/<port>/ws`), not raw TCP. This is the connectivity path that lets a node
/// behind an HTTPS reverse proxy or a Cloudflare tunnel be dialed at all: such a proxy forwards
/// WebSockets but not raw libp2p TCP, so without this a tunnelled node can only ever follow the
/// chain over RPC — enough to observe, never to validate (BFT needs gossip for proposals and
/// votes). See `helix_p2p::P2PConfig::ws_listen_addr`.
///
/// A listens on both raw TCP (`WS_A_P2P`) and WebSocket (`WS_A_WS`); B is given only A's
/// WebSocket multiaddr as its seed peer. What this pins is that the WebSocket transport is
/// wired end-to-end: A's `/ws` listener starts, B parses and dials a `/ws` multiaddr, the Noise
/// handshake completes inside the WebSocket, and gossip flows well enough for B to converge on
/// A's exact `state_hash`. It does not, on its own, prove B used *only* the WebSocket: B also
/// learns A's raw-TCP port from `/status` (for the sync-peer dial) and could reach it on
/// loopback. The raw pure-WebSocket case — no TCP path available at all, dialed through a real
/// Cloudflare tunnel — was verified live and is recorded in the CTO backlog (#103); a tunnel is
/// not reproducible in CI, which is why this test asserts the transport works rather than that
/// TCP was excluded.
#[tokio::test]
#[ignore = "spawns two real node processes and runs a WebSocket-transport sync (~20-30s wall-clock) — run explicitly with --ignored, not on every CI push"]
async fn a_follower_syncs_over_a_websocket_transport() {
    let _serialized = NODE_TEST_LOCK.lock().await;
    // A is the genesis node, listening on BOTH raw TCP and WebSocket for P2P.
    let _node_a = spawn_node_with(
        WS_A_RPC,
        WS_A_P2P,
        None,
        &[("HELIX_P2P_WS_LISTEN", &format!("127.0.0.1:{WS_A_WS}"))],
        None,
    );
    wait_until_reachable(WS_A_RPC, Duration::from_secs(15)).await;

    // B seeds from A over RPC (genesis + history) and is handed ONLY A's WebSocket multiaddr as
    // its P2P seed peer — so the live-gossip link it is told to build is the `/ws` one.
    let ws_seed = format!("/ip4/127.0.0.1/tcp/{WS_A_WS}/ws");
    let _node_b = spawn_node_with(
        WS_B_RPC,
        WS_B_P2P,
        Some(WS_A_RPC),
        &[("HELIX_P2P_SEED_PEERS", &ws_seed)],
        None,
    );
    wait_until_reachable(WS_B_RPC, Duration::from_secs(15)).await;

    // Both must climb together and agree on the execution result, not just the block hash —
    // if the WebSocket transport failed to load or dial, B would never receive A's gossip and
    // the snapshot would never match. Poll both together for one round where they report the
    // identical height at once (a naive one-after-another read would race two independently
    // advancing nodes), then compare hashes.
    let min_height = wait_for_height(WS_A_RPC, 8, Duration::from_secs(120)).await["height"]
        .as_u64()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    let (a, b) = loop {
        if let (Some(a), Some(b)) = (status(WS_A_RPC).await, status(WS_B_RPC).await) {
            let (ha, hb) = (a["height"].as_u64().unwrap_or(0), b["height"].as_u64().unwrap_or(1));
            if ha >= min_height && ha == hb {
                break (a, b);
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the WebSocket follower never reached the genesis node's height >= {min_height} within 90s"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    };
    assert_eq!(a["best_hash"], b["best_hash"], "A and the WebSocket follower disagree on the block hash at height {}", a["height"]);

    // Same reason as in the three-node test: `state_hash` belongs to `state_height`, so it must be
    // compared at equal `state_height`, never at equal `height`. Passing A's port twice makes the
    // three-node helper serve a two-node comparison — A trivially agrees with itself, and the
    // A-vs-B comparison is the one under test.
    assert_states_converge([WS_A_RPC, WS_B_RPC, WS_A_RPC], CONVERGENCE_GRACE).await;
}

/// Polls all three nodes together until one round observes the *identical* height on all
/// three at once — see the call site for why a naive one-after-another comparison would be
/// racy against three independently, continuously advancing nodes.
async fn wait_for_matching_snapshot(
    rpc_ports: [u16; 3],
    min_height: u64,
    timeout: Duration,
) -> (serde_json::Value, serde_json::Value, serde_json::Value) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let snapshots = (status(rpc_ports[0]).await, status(rpc_ports[1]).await, status(rpc_ports[2]).await);
        if let (Some(a), Some(b), Some(c)) = snapshots {
            let (ha, hb, hc) = (a["height"].as_u64().unwrap_or(0), b["height"].as_u64().unwrap_or(0), c["height"].as_u64().unwrap_or(0));
            if ha >= min_height && ha == hb && hb == hc {
                return (a, b, c);
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the three nodes never simultaneously agreed on a height >= {min_height} within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

// Minimal local stand-in for the `tempdir` crate (not already a workspace dependency) —
// avoids adding a new external dependency for one test file's worth of "unique scratch
// directory that cleans itself up" need.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> std::io::Result<Self> {
            // Counter rather than a wall-clock nanosecond: parallel test threads can read the same
            // nanosecond and land on one directory. The same scheme in `helix-rpc`'s fixture did
            // exactly that and broke CI; measured, it ties a few hundred times in 360k samples.
            static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let mut path = std::env::temp_dir();
            let unique = format!(
                "helix-multi-node-test-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            path.push(unique);
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
