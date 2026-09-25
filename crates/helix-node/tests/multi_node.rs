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
const GAP_A_RPC: u16 = 29_685;
const GAP_A_P2P: u16 = 29_686;
const GAP_B_RPC: u16 = 29_695;
const GAP_B_P2P: u16 = 29_696;

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
    /// `None` only after `stop` has handed it back.
    work_dir: Option<tempdir::TempDir>,
}

impl Drop for NodeGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl NodeGuard {
    /// Stop the node the way pm2 and systemd do — SIGTERM, then SIGKILL if it has not exited
    /// within ten seconds — and hand back its working directory, so it can be started again
    /// (`start_node_in`) on its own chain database, key and peer file.
    ///
    /// Async on purpose: the test's relays run on the same single-threaded runtime, and a blocking
    /// wait here would freeze every link in the test while one node shuts down.
    async fn stop(mut self) -> tempdir::TempDir {
        signal_node(self.child.id(), "TERM");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.work_dir.take().expect("a running node owns its work dir")
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
    // A fresh node starts a fresh log; `start_node_in` appends, so a restarted node's second run
    // lands after its first instead of over it.
    if let Some(path) = node_log_path(rpc_port) {
        let _ = std::fs::File::create(path);
    }
    start_node_in(work_dir, rpc_port, p2p_port, sync_peer_rpc_port, extra_env)
}

/// Where a node's output goes when `HELIX_TEST_LOG_DIR` is set: `<dir>/node-<rpc_port>.log`.
fn node_log_path(rpc_port: u16) -> Option<std::path::PathBuf> {
    match std::env::var("HELIX_TEST_LOG_DIR") {
        Ok(dir) if !dir.is_empty() => {
            let _ = std::fs::create_dir_all(&dir);
            Some(std::path::Path::new(&dir).join(format!("node-{rpc_port}.log")))
        }
        _ => None,
    }
}

/// Start a node in `work_dir` — a new one from `spawn_node_with`, or one a previous run left behind
/// (`NodeGuard::stop`), with its chain database, key and peer file.
fn start_node_in(
    work_dir: tempdir::TempDir,
    rpc_port: u16,
    p2p_port: u16,
    sync_peer_rpc_port: Option<u16>,
    extra_env: &[(&str, &str)],
) -> NodeGuard {
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
    match node_log_path(rpc_port) {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("open node log file");
            let dup = file.try_clone().expect("clone node log handle");
            cmd.stdout(Stdio::from(file)).stderr(Stdio::from(dup));
        }
        None => {
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
    NodeGuard { child, work_dir: Some(work_dir) }
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

/// A disk limit the node cannot read stops the start, before anything is created.
///
/// `HELIX_KEEP_BYTES=120 gigs` used to read as "no byte budget" — the operator's explicit limit
/// switched off, found out when the disk ran full. Checked at the process, because the rule is
/// tested in the binary's own unit tests and only this shows it is applied at all.
#[tokio::test]
async fn a_node_will_not_start_on_a_disk_limit_it_cannot_read() {
    const RPC: u16 = 29_753;
    const P2P: u16 = 29_754;
    let _serialized = NODE_TEST_LOCK.lock().await;
    assert_port_free(RPC, "disk-limit RPC");
    assert_port_free(P2P, "disk-limit P2P");
    let dir = tempdir::TempDir::new().expect("temp dir");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_helix"));
    cmd.arg("start")
        .current_dir(dir.path())
        .env("HELIX_RPC_BIND", format!("127.0.0.1:{RPC}"))
        .env("HELIX_P2P_LISTEN", format!("127.0.0.1:{P2P}"))
        .env("HELIX_P2P_DISABLE_MDNS", "1")
        .env("HELIX_NEW_CHAIN", "1")
        .env("HELIX_KEEP_BYTES", "120 gigs")
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut guard = NodeGuard { child: cmd.spawn().expect("spawn helix"), work_dir: None };
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let exit = loop {
        if let Some(exit) = guard.child.try_wait().expect("wait on the node") {
            break exit;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a node with HELIX_KEEP_BYTES=\"120 gigs\" is still running — it took an unreadable \
             disk limit for no limit"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(guard.child.stderr.as_mut().expect("piped"), &mut stderr)
        .expect("read stderr");
    drop(guard);
    assert!(!exit.success(), "the refusal has to be an error exit, got {exit}: {stderr}");
    assert!(stderr.contains("HELIX_KEEP_BYTES=\"120 gigs\""), "must name the setting: {stderr}");
    let created: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read work dir")
        .map(|e| e.expect("dir entry").file_name())
        .collect();
    assert!(created.is_empty(), "refused before anything was created, found {created:?}");
}

/// A database from another chain stops the node at startup instead of being run.
///
/// After a reset every operator is asked to rename their data directory. One who forgot used to
/// get a node that loaded the old chain and ran on it — its sync failing on the first block that
/// does not chain, its peers on another chain — with nothing saying so. A node that knows which
/// chain it is meant to be on (here `HELIX_GENESIS_HASH`; on the public network the compiled-in
/// hash) now refuses and names the rename. The control restarts the same directory with its own
/// hash: what stops the node is the mismatch, not the restart, and the refusal left the chain as
/// it was.
#[tokio::test]
async fn a_node_refuses_to_run_on_a_database_from_another_chain() {
    const RPC: u16 = 29_751;
    const P2P: u16 = 29_752;
    let _serialized = NODE_TEST_LOCK.lock().await;
    assert_port_free(RPC, "other-chain RPC");
    assert_port_free(P2P, "other-chain P2P");
    let fast = [("HELIX_BLOCK_TIME_MS", "300")];

    let dir = tempdir::TempDir::new().expect("temp dir");
    let node = start_node_in(dir, RPC, P2P, None, &fast);
    wait_until_reachable(RPC, Duration::from_secs(30)).await;
    wait_for_height(RPC, 2, Duration::from_secs(60)).await;
    let own_genesis = block_header(RPC, 0).await.expect("genesis header")["hash"]
        .as_str()
        .expect("genesis hash")
        .to_string();
    // Read before the stop, so at most lower than what the directory holds: the control below
    // has to find at least this much again.
    let stopped_at = status(RPC).await.expect("status")["height"].as_u64().expect("height");
    let dir = node.stop().await;

    // Another chain's hash — any value but this directory's own genesis.
    let other = "00".repeat(32);
    let mut refused = Command::new(env!("CARGO_BIN_EXE_helix"));
    refused
        .arg("start")
        .current_dir(dir.path())
        .env("HELIX_RPC_BIND", format!("127.0.0.1:{RPC}"))
        .env("HELIX_P2P_LISTEN", format!("127.0.0.1:{P2P}"))
        .env("HELIX_P2P_DISABLE_MDNS", "1")
        .env("HELIX_NEW_CHAIN", "1")
        .env("HELIX_GENESIS_HASH", &other)
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut guard = NodeGuard { child: refused.spawn().expect("spawn helix"), work_dir: None };
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let exit = loop {
        if let Some(exit) = guard.child.try_wait().expect("wait on the node") {
            break exit;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a node configured for chain {other} is still running a minute after it was started \
             on a database of chain {own_genesis} — it runs the other chain instead of refusing"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(guard.child.stderr.as_mut().expect("piped"), &mut stderr)
        .expect("read stderr");
    drop(guard);
    assert!(!exit.success(), "the refusal has to be an error exit, got {exit}: {stderr}");
    assert!(
        stderr.contains(&format!("holds the chain whose genesis is {own_genesis}")),
        "the refusal must name the chain on disk: {stderr}"
    );
    assert!(stderr.contains("has not been touched"), "{stderr}");

    // Control: the same directory with its own hash — and in another casing, as operators copy
    // it — starts, and the chain is where it was.
    let own_upper = own_genesis.to_uppercase();
    let control = start_node_in(dir, RPC, P2P, None, &[("HELIX_GENESIS_HASH", &own_upper)]);
    wait_until_reachable(RPC, Duration::from_secs(30)).await;
    let height = status(RPC).await.expect("status")["height"].as_u64().expect("height");
    assert!(
        height >= stopped_at,
        "the refusal must not have cost a block: {height} < {stopped_at}"
    );
    let genesis = block_header(RPC, 0).await.expect("genesis header")["hash"]
        .as_str()
        .expect("genesis hash")
        .to_string();
    assert_eq!(genesis, own_genesis, "and the chain is still the one it was");
    drop(control);
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


/// A node that fell behind while its peers kept going must catch back up, without a restart and
/// without anyone noticing.
///
/// **This is #188, and it was the most expensive open defect this project had.** On 2026-09-04 the
/// production validator sat exactly one block under the tip for 6 h 20 min with four peers
/// connected. A validator below the tip cannot vote on the next height, so it was absent from the
/// quorum and the chain stopped — the chain that looked like it was waiting for other validators
/// was waiting for it. It came back 33 seconds after a restart, which proves the block was
/// available the whole time and nothing fetched it.
///
/// The consensus engine provably cannot close a height gap on its own — `fault_injection.rs`
/// measures that, and the reason is structural: committed-block gossip applies only at `tip + 1`
/// and the missing block is by definition already past, while the round-sync pull is answered only
/// for the *server's* `current_height + 1`. Block-sync is therefore not a backstop but the only
/// path, and it had no test at all.
///
/// **SIGSTOP rather than a kill, deliberately.** A killed node restarts and runs the startup-sync
/// path, which is a different mechanism with its own tests; the failure being reproduced here is a
/// *running* node that fell behind and has to notice by itself. SIGSTOP freezes it mid-flight,
/// leaves its TCP connections and its peers' view of it intact, and on SIGCONT it wakes up exactly
/// where production was: behind, connected, and nobody is going to resend what it missed.
///
/// **Both gap sizes, because one of them is the production case.** Ten blocks is the comfortable
/// version and the one a reader expects. One block is what actually happened, and it is the harder
/// case to be confident about by reading: it is the smallest gap that exists, the one most easily
/// mistaken for ordinary lag, and — since the missing block is the one that was dropped — the one
/// where no later committed block can ever chain onto the tip that is held.
///
/// A follower rather than a validator, because the driver under test is identical either way and
/// this needs neither funding, staking, nor an activation epoch — the same reproduction for two
/// processes instead of five, and half a minute instead of a quarter of an hour. What it does not
/// cover is a node that is behind *while the chain is stalled*, which is the full production
/// shape; that needs five validators with one already silent and is recorded in the backlog rather
/// than pretended at here.
#[tokio::test]
#[ignore = "spawns two real node processes and freezes one with SIGSTOP, twice (~60s wall-clock) — run explicitly with --ignored"]
async fn a_node_frozen_until_it_falls_behind_catches_up_again_on_its_own() {
    let _serialized = NODE_TEST_LOCK.lock().await;
    // **Two, not one, and that is a property of SIGSTOP rather than a preference.**
    //
    // SIGSTOP halts the process, not its socket: the kernel keeps accepting and buffering what the
    // chain gossips at it. With a one-block lead, B has that block waiting when it is resumed and
    // applies it before the test can read a height — it wakes level with A, the precondition is
    // gone, and the run fails without anything being wrong with catch-up.
    //
    // Measured on 2026-09-09, and measured on the commit *before* that day's work too, so this is
    // not a regression that arrived with it: at gap 1 B woke on 4 against A's 4, repeatably. At
    // gap 2 it wakes on 3 and climbs to 5, three runs, identical numbers. The backlog note for
    // #189 claims "3 → 4" for a one-block gap; that was true when it was written and is not now.
    //
    // Two blocks is still the production shape this exists for — a node a hair behind, not one
    // that missed an epoch. Making it *exactly* one is not achievable with this instrument, and
    // pretending otherwise would leave a test that fails for a reason unrelated to what it checks.
    for gap in [10u64, 2u64] {
        catches_up_after_falling_behind(gap).await;
    }
}

async fn catches_up_after_falling_behind(gap: u64) {
    let _node_a = spawn_node(GAP_A_RPC, GAP_A_P2P, None);
    wait_until_reachable(GAP_A_RPC, Duration::from_secs(15)).await;
    wait_for_height(GAP_A_RPC, 2, Duration::from_secs(30)).await;

    let node_b = spawn_node_with(
        GAP_B_RPC,
        GAP_B_P2P,
        Some(GAP_A_RPC),
        &[("HELIX_P2P_SEED_PEERS", &format!("/ip4/127.0.0.1/tcp/{GAP_A_P2P}"))],
        None,
    );
    wait_until_reachable(GAP_B_RPC, Duration::from_secs(15)).await;
    wait_for_height(GAP_B_RPC, 3, Duration::from_secs(60)).await;

    // Read B's height *before* freezing it, and not only because that is the honest value.
    // A SIGSTOPped process keeps its listen socket: the kernel completes the handshake and
    // nothing ever answers, so an HTTP GET against it does not fail — it hangs, forever, and
    // `reqwest::get` here carries no timeout. The first version of this test asked B how far it
    // had got *after* stopping it and never reached its next line. R2, in the plainest form: the
    // instrument has to survive the condition it is measuring.
    let frozen_at = status(GAP_B_RPC).await.and_then(|s| s["height"].as_u64()).unwrap_or(0);
    assert!(frozen_at > 0, "B has to be following the chain before it is frozen");

    // Freeze B. Its process stays, its sockets stay, and A keeps producing — so the gap opens
    // exactly the way it opened in production, rather than by restarting into a different path.
    let pid = node_b.child.id();
    signal_node(pid, "STOP");
    wait_for_height(GAP_A_RPC, frozen_at + gap, Duration::from_secs(120)).await;
    let ahead = status(GAP_A_RPC).await.unwrap()["height"].as_u64().unwrap();
    println!("gap {gap}: froze B on {frozen_at}, A advanced to {ahead}");

    signal_node(pid, "CONT");

    // Positive control, asserted before the recovery: if B were never actually behind, everything
    // below would pass for the wrong reason. A test of catching up that never fell behind measures
    // the healthy path and calls it a fix.
    let woke_at = wait_for_status(GAP_B_RPC, Duration::from_secs(60))
        .await
        .expect("B must answer again once resumed");
    let b_height = woke_at["height"].as_u64().unwrap_or(0);
    println!("gap {gap}: B woke on {b_height}");
    assert!(
        b_height < ahead,
        "B was frozen while A advanced, so it has to wake up behind — it woke on {b_height} \
         against A's {ahead}. Nothing after this line would be measuring a recovery."
    );

    // The assertion. Block-sync is the only mechanism that can do this, so if it fails, it failed.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let a = status_within(GAP_A_RPC, Duration::from_secs(3)).await.and_then(|s| s["height"].as_u64()).unwrap_or(0);
        let b = status_within(GAP_B_RPC, Duration::from_secs(3)).await.and_then(|s| s["height"].as_u64()).unwrap_or(0);
        if b + 1 >= a && b > b_height {
            println!("gap {gap}: B caught up: {b_height} -> {b}, A on {a}");
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "gap {gap}: B woke on {b_height} and is on {b} while A is on {a} — it never caught \
                 up. A node below the tip is a node missing from the quorum, which is how a single \
                 lost block became a 6 h 20 min stall on 2026-09-04 (#188). Block-sync is the only \
                 path back and it did not run, or ran and achieved nothing."
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Send a signal to a spawned node by PID.
///
/// `kill -STOP`/`-CONT` by pid, never by pattern: `pkill -f` matches its own command line and
/// kills itself before reaching the target, which this repo has walked into four times (R4).
fn signal_node(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status()
        .expect("send signal to node process");
    assert!(status.success(), "kill -{signal} {pid} failed");
}

/// `status`, but waiting for the node to answer at all — a process that has just been resumed
/// from SIGSTOP needs a moment before its RPC responds.
async fn wait_for_status(rpc_port: u16, timeout: Duration) -> Option<serde_json::Value> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(s) = status_within(rpc_port, Duration::from_secs(3)).await {
            return Some(s);
        }
        if std::time::Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}


/// `status`, but it gives up. The plain one has no timeout, which is fine against a node that is
/// either answering or refusing the connection — and useless against one that has been stopped,
/// where the socket accepts and nothing replies.
async fn status_within(rpc_port: u16, timeout: Duration) -> Option<serde_json::Value> {
    let client = reqwest::Client::builder().timeout(timeout).build().ok()?;
    client
        .get(format!("http://127.0.0.1:{rpc_port}/status"))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Throughput under a slow link (2026-09-18)
//
// Everything above runs three nodes over loopback, where a 2 MB block crosses between processes
// in about a millisecond. Production does not: every validator reaches every other through one
// Cloudflare tunnel, measured at ~890 KB/s on 2026-09-18 against 172 MB/s on loopback — a factor
// of 193. That single number is why `HELIX_MAX_PROPOSAL_BYTES` defaults to 256 KB, and why the
// question "what is the block time at 367 transactions?" had no measured answer: `load.rs` is a
// single node, so it exercises the mempool, the packer and the block limits, and never once
// distributes a block to anyone.
//
// This closes that gap. The link is a userspace relay rather than `tc`/`netem` because this
// machine also runs production: a qdisc on loopback would throttle the production node and the
// tunnel along with the test. A relay throttles exactly the sockets handed to it and nothing else,
// needs no privileges, and runs unchanged in CI.
// ─────────────────────────────────────────────────────────────────────────────────────────────

const TL_A_RPC: u16 = 29_575;
const TL_A_P2P: u16 = 29_576;
const TL_A_LINK: u16 = 29_577;
const TL_B_RPC: u16 = 29_585;
const TL_B_P2P: u16 = 29_586;
const TL_B_LINK: u16 = 29_587;
const TL_C_RPC: u16 = 29_595;
const TL_C_P2P: u16 = 29_596;
const TL_C_LINK: u16 = 29_597;

/// The measured production tunnel, in bytes per second (2026-09-18, five runs of 1.76 MB through
/// `node.silvra.net`: 600–1090 KB/s, median 890).
const LINK_BYTES_PER_SEC: u64 = 890 * 1024;

/// Forward TCP between two loopback ports at a fixed byte rate, in both directions.
///
/// One relay stands for one node's link, so its rate is that node's bandwidth — **shared by every
/// connection through it**, one budget per direction, which is what a single uplink actually is.
/// It used to pace each connection on its own: every extra connection to the same node brought its
/// own full rate with it, so a build that opened more connections (#197 redials at "too few peers",
/// and gossipsub spills onto a second connection when the first one's queue is full) was handed
/// more bandwidth by the test and measured as faster. That is not a property of the node.
///
/// A chunk goes out as soon as its direction of the link is free — at once on an idle link, so a
/// small urgent message (a prevote is ~3.3 KB) is never charged for bandwidth it does not use —
/// and otherwise after the chunks already booked ahead of it, whichever connection they belong to.
fn spawn_link(listen: u16, target: u16, bytes_per_sec: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", listen)).await {
            Ok(l) => l,
            Err(e) => panic!("throttled link cannot bind {listen}: {e}"),
        };
        let toward_node = Pacer::new(bytes_per_sec);
        let from_node = Pacer::new(bytes_per_sec);
        loop {
            let Ok((inbound, _)) = listener.accept().await else { continue };
            let (toward_node, from_node) = (toward_node.clone(), from_node.clone());
            tokio::spawn(async move {
                let Ok(outbound) = tokio::net::TcpStream::connect(("127.0.0.1", target)).await else {
                    return;
                };
                // Nagle off on both halves: the relay already paces by rate, and letting the
                // kernel additionally hold small writes back would add a second, invisible delay
                // on top of the one this test is trying to measure.
                let _ = inbound.set_nodelay(true);
                let _ = outbound.set_nodelay(true);
                let (ri, wi) = inbound.into_split();
                let (ro, wo) = outbound.into_split();
                tokio::join!(pump(ri, wo, toward_node), pump(ro, wi, from_node));
            });
        }
    })
}

/// One direction of one node's link, shared by every connection through its relay.
struct Pacer {
    next_free: tokio::sync::Mutex<tokio::time::Instant>,
    bytes_per_sec: u64,
}

impl Pacer {
    fn new(bytes_per_sec: u64) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Pacer {
            next_free: tokio::sync::Mutex::new(tokio::time::Instant::now()),
            bytes_per_sec,
        })
    }

    /// When `n` bytes may start: now on an idle link, otherwise once the bytes booked before them
    /// have gone out. Books the link for their duration.
    async fn book(&self, n: usize) -> tokio::time::Instant {
        let mut next = self.next_free.lock().await;
        let start = (*next).max(tokio::time::Instant::now());
        *next = start + Duration::from_secs_f64(n as f64 / self.bytes_per_sec as f64);
        start
    }
}

async fn pump<R, W>(mut r: R, mut w: W, link: std::sync::Arc<Pacer>)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        tokio::time::sleep_until(link.book(n).await).await;
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = w.shutdown().await;
}

/// Sign `count` transfers from `kp` at nonces 0.., priced well over the base fee.
///
/// Duplicated from `load.rs` rather than shared: the two test binaries cannot see each other's
/// private helpers without a `tests/common` module, and what is common here is twenty lines of
/// struct literal — while what differs is everything that carries judgement (the headroom, the
/// amount, who the sender is).
fn sign_flood(
    kp: &KeyPair,
    to: &Address,
    count: u64,
    chain_id: helix_crypto::Hash,
    base_fee_per_byte: u64,
) -> Vec<helix_core::Transaction> {
    use helix_core::{Transaction, TxType};
    let from = Address::from_public_key(&kp.public);
    (0..count)
        .map(|nonce| {
            let mut tx = Transaction {
                version: 1,
                tx_type: TxType::Transfer,
                from: from.clone(),
                to: Some(to.clone()),
                amount: 1_000_000,
                fee: 0,
                nonce,
                data: Vec::new(),
                crypto_version: kp.scheme,
                chain_id,
                signature: helix_crypto::Signature::from_bytes(vec![]),
                public_key: kp.public.clone(),
            };
            tx.signature = kp.sign(tx.signing_hash().as_bytes()).expect("sign at fee 0");
            // 20× the base fee, for the reason `load.rs` documents: a batch signed up front is
            // priced before the flood moves the market, and a load test whose transactions get
            // outbid measures the fee market rather than the chain.
            tx.fee = (base_fee_per_byte.saturating_mul(tx.size_bytes()) * 20).max(10_000);
            tx.signature = kp.sign(tx.signing_hash().as_bytes()).expect("sign priced");
            tx
        })
        .collect()
}

/// **What is the block time when blocks are full and the network is as slow as production?**
///
/// Everything that made that question unanswerable is in this test's setup rather than its
/// assertions: three real validator processes, every one of them reachable only through a relay
/// pinned to the measured production tunnel rate, announcing that relay as its public address
/// exactly as the production node announces its tunnel. Then two thousand transactions at once.
///
/// Reading block times from header timestamps is legitimate *here* and nowhere else in this
/// repo: a header carries its proposer's clock, and on 2026-08-28 comparing them across four
/// machines measured clock skew instead of block time (R2). All three proposers here are
/// processes on one machine reading one clock, so the skew is zero by construction.
///
/// Run it against the protocol ceiling instead of the shipped policy with
/// `HELIX_MAX_PROPOSAL_BYTES=2097152` — that is the comparison the 256 KB default exists for,
/// and this test is how it stops being an argument and becomes a number.
#[tokio::test]
#[ignore = "three validator processes behind throttled links, two activation epochs, then a 2000-tx flood (~8-12 min) — run with --ignored --nocapture"]
async fn blocks_stay_on_cadence_under_a_flood_when_every_link_is_as_slow_as_production() {
    let _serialized = NODE_TEST_LOCK.lock().await;
    for (port, label) in [
        (TL_A_RPC, "A rpc"), (TL_A_P2P, "A p2p"), (TL_A_LINK, "A link"),
        (TL_B_RPC, "B rpc"), (TL_B_P2P, "B p2p"), (TL_B_LINK, "B link"),
        (TL_C_RPC, "C rpc"), (TL_C_P2P, "C p2p"), (TL_C_LINK, "C link"),
    ] {
        assert_port_free(port, label);
    }

    // The links come up first: a node that dials a relay which is not listening yet simply fails
    // that dial and waits for the next redial tick, which costs 30 s of the test's budget for no
    // reason.
    let _link_a = spawn_link(TL_A_LINK, TL_A_P2P, LINK_BYTES_PER_SEC);
    let _link_b = spawn_link(TL_B_LINK, TL_B_P2P, LINK_BYTES_PER_SEC);
    let _link_c = spawn_link(TL_C_LINK, TL_C_P2P, LINK_BYTES_PER_SEC);

    let kp_a = KeyPair::generate();
    let kp_b = KeyPair::generate();
    let kp_c = KeyPair::generate();
    let addr_b = Address::from_public_key(&kp_b.public);
    let addr_c = Address::from_public_key(&kp_c.public);

    // Every seed is a *relay* port, and every node announces its own relay as its public address.
    // Both halves are needed: the seeds route the dials this test sets up, and the announcement
    // routes everything peer exchange arranges afterwards — without it two nodes that learn about
    // each other through gossip would connect directly and quietly measure loopback.
    let ma = |port: u16| format!("/ip4/127.0.0.1/tcp/{port}");
    let fast = ("HELIX_BLOCK_TIME_MS", JOIN_BLOCK_TIME_MS);
    let seeds_a = format!("{},{}", ma(TL_B_LINK), ma(TL_C_LINK));
    let seeds_b = format!("{},{}", ma(TL_A_LINK), ma(TL_C_LINK));
    let seeds_c = format!("{},{}", ma(TL_A_LINK), ma(TL_B_LINK));
    let pub_a = ma(TL_A_LINK);
    let pub_b = ma(TL_B_LINK);
    let pub_c = ma(TL_C_LINK);

    let _node_a = spawn_node_with(TL_A_RPC, TL_A_P2P, None,
        &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_a), ("HELIX_P2P_PUBLIC_ADDR", &pub_a),
          ("HELIX_RPC_RATE_LIMIT", "50000,20000")], Some(&kp_a));
    wait_until_reachable(TL_A_RPC, Duration::from_secs(15)).await;
    wait_for_height(TL_A_RPC, 2, Duration::from_secs(30)).await;

    let _node_b = spawn_node_with(TL_B_RPC, TL_B_P2P, Some(TL_A_RPC),
        &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_b), ("HELIX_P2P_PUBLIC_ADDR", &pub_b)], Some(&kp_b));
    let _node_c = spawn_node_with(TL_C_RPC, TL_C_P2P, Some(TL_A_RPC),
        &[fast, ("HELIX_P2P_SEED_PEERS", &seeds_c), ("HELIX_P2P_PUBLIC_ADDR", &pub_c)], Some(&kp_c));
    wait_until_reachable(TL_B_RPC, Duration::from_secs(15)).await;
    wait_until_reachable(TL_C_RPC, Duration::from_secs(15)).await;

    let (_kd_a, key_a) = temp_keyfile(&kp_a);
    let (_kd_b, key_b) = temp_keyfile(&kp_b);
    let (_kd_c, key_c) = temp_keyfile(&kp_c);
    fund_and_stake(TL_A_RPC, &key_a, &kp_b, &key_b).await;
    fund_and_stake(TL_A_RPC, &key_a, &kp_c, &key_c).await;
    assert!(
        wait_for_validator_active(TL_A_RPC, &addr_b.to_string(), Duration::from_secs(600)).await,
        "B staked but never activated — activation stalled"
    );
    assert!(
        wait_for_validator_active(TL_A_RPC, &addr_c.to_string(), Duration::from_secs(600)).await,
        "C staked but never activated — activation stalled"
    );

    // Baseline first, on the same three validators and the same links, with nothing in the
    // mempool. Without it a slow flood cannot be told from a slow test machine — and a debug
    // build on a loaded host has been measured at 0.91 s per block against a configured 300 ms
    // (2026-08-26), which is three times the difference this test is looking for.
    let idle = measure_cadence(TL_A_RPC, 12, Duration::from_secs(180)).await;

    let status = status(TL_A_RPC).await.expect("A status");
    let base_fee = status["base_fee_per_byte"].as_u64().unwrap_or(1);
    // The chain id *is* the genesis hash (#174), read from the chain rather than assumed — a
    // wrong one here would make every signature invalid for a reason that reads like a pool bug.
    let genesis = block_header(TL_A_RPC, 0).await.expect("genesis header");
    let chain_id = helix_crypto::Hash::from_hex(genesis["hash"].as_str().expect("genesis hash"))
        .expect("genesis hash parses");

    let recipient = Address::from_public_key(&KeyPair::generate().public);
    let flood_sender = Address::from_public_key(&kp_a.public).to_string();
    let (flood_from_height, nonce_before) = height_and_nonce(TL_A_RPC, &flood_sender).await;
    let txs = sign_flood(&kp_a, &recipient, 2_000, chain_id, base_fee);
    let client = reqwest::Client::new();
    let mut accepted = 0u64;
    for tx in &txs {
        let ok = client
            .post(format!("http://127.0.0.1:{TL_A_RPC}/transactions"))
            .json(tx)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if ok {
            accepted += 1;
        }
    }
    assert!(accepted > 1_500, "only {accepted}/2000 transactions were accepted — the flood never happened");

    let loaded = measure_cadence(TL_A_RPC, 12, Duration::from_secs(300)).await;

    // What the blocks carried of the flood against what the chain applied (#231). Every flood
    // transaction a block carries must apply: a block that packs one it cannot apply wastes its
    // space, and the transaction is then dropped from every pool as committed — lost, with every
    // later nonce of its sender stuck behind the hole. Until #231 this test measured only block
    // times and passed while whole blocks of the flood failed, 48 of 48, block after block.
    let (flood_to_height, nonce_after) = height_and_nonce(TL_A_RPC, &flood_sender).await;
    let mut carried = 0u64;
    for h in (flood_from_height + 1)..=flood_to_height {
        // The block at the state's height can reach the store a moment after the state: wait for
        // it rather than count it as empty.
        let mut body = None;
        for _ in 0..50 {
            body = block_body(TL_A_RPC, h).await.filter(|b| b["transactions"].is_array());
            if body.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let body = body.unwrap_or_else(|| panic!("block {h} never became readable"));
        carried += body["transactions"]
            .as_array()
            .map_or(0, |txs| txs.iter().filter(|t| t["from"] == flood_sender.as_str()).count() as u64);
    }
    let applied = nonce_after - nonce_before;
    eprintln!(
        "link {} KB/s per node · idle: median {:.2}s p90 {:.2}s · under {accepted} tx: median {:.2}s p90 {:.2}s, fullest block {} tx · flood carried {carried}, applied {applied}",
        LINK_BYTES_PER_SEC / 1024, idle.median, idle.p90, loaded.median, loaded.p90, loaded.fullest
    );
    assert!(carried > 0, "no block carried any of the flood — the comparison below would be empty");
    assert_eq!(
        applied, carried,
        "the blocks carried {carried} of the flood's transactions and only {applied} applied: a \
         proposer packed transactions it could not apply (a nonce gap), and each one a block \
         carried was then dropped from every pool (#231)"
    );

    // The chain has to still be finalizing — that is the failure this exists to catch, and it is
    // not hypothetical: a proposal that cannot cross the link inside the round window splits the
    // prevotes, the round dies, and the backlog that caused it is still there for the next one.
    assert!(
        loaded.blocks >= 10,
        "the chain stopped finalizing under load: only {} blocks in the window",
        loaded.blocks
    );
    // Four times the idle cadence, floored so a fast idle run cannot make this stricter than the
    // round window it is really testing. Deliberately loose: this is a guard against the
    // *feedback loop* (#195), where a block too big for the link loses its round, accumulates
    // more transactions and gets bigger — not a bound on how long a full block may take.
    let ceiling = (idle.median * 4.0).max(8.0);
    assert!(
        loaded.p90 < ceiling,
        "block time collapsed under load: p90 {:.2}s against an idle median of {:.2}s (ceiling {:.2}s). \
         Fullest block {} tx. Two causes look exactly like this, and a message naming one of them \
         sent the first diagnosis the wrong way (#224): a proposal that cannot cross the link inside \
         the round window, or nodes that are not processing consensus messages at all. Re-run with \
         `HELIX_TEST_LOG_DIR` set — `heard=none` on every node is the second — and with the link \
         unthrottled: if it still fails, bandwidth is not the cause.",
        loaded.p90, idle.median, ceiling, loaded.fullest
    );
}

struct Cadence {
    median: f64,
    p90: f64,
    blocks: usize,
    fullest: u64,
}

/// Block-to-block times over the next `want` blocks, from header timestamps.
async fn measure_cadence(rpc_port: u16, want: u64, timeout: Duration) -> Cadence {
    let start = status(rpc_port).await.expect("status")["height"].as_u64().unwrap_or(0);
    wait_for_height(rpc_port, start + want, timeout).await;
    let mut stamps = Vec::new();
    let mut fullest = 0u64;
    for h in start..=(start + want) {
        if let Some(header) = block_header(rpc_port, h).await {
            if let Some(ts) = header["timestamp"].as_u64() {
                stamps.push(ts);
            }
        }
        if let Some(b) = block_body(rpc_port, h).await {
            let n = b["transactions"].as_array().map(|a| a.len() as u64).unwrap_or(0);
            fullest = fullest.max(n);
        }
    }
    let mut gaps: Vec<f64> = stamps.windows(2).map(|w| (w[1].saturating_sub(w[0])) as f64 / 1000.0).collect();
    gaps.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = gaps.len().max(1);
    Cadence {
        median: gaps.get(n / 2).copied().unwrap_or(0.0),
        p90: gaps.get((n * 9) / 10).copied().unwrap_or(0.0),
        blocks: gaps.len(),
        fullest,
    }
}

/// `address`'s nonce and the height of the state it was read from, so that no block can commit
/// between the two: state height, nonce, state height again, until both agree. `state_height`,
/// not `height` — the node writes the state before the block, so the store's height can trail the
/// state a nonce is read from by one block.
async fn height_and_nonce(rpc_port: u16, address: &str) -> (u64, u64) {
    for _ in 0..50 {
        let before = status(rpc_port).await.and_then(|s| s["state_height"].as_u64());
        let nonce = account(rpc_port, address).await.and_then(|a| a["nonce"].as_u64());
        let after = status(rpc_port).await.and_then(|s| s["state_height"].as_u64());
        if let (Some(before), Some(nonce), Some(after)) = (before, nonce, after) {
            if before == after {
                return (before, nonce);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("could not read a height and a nonce from the same block on :{rpc_port}");
}

async fn block_body(rpc_port: u16, height: u64) -> Option<serde_json::Value> {
    reqwest::get(format!("http://127.0.0.1:{rpc_port}/blocks/height/{height}"))
        .await
        .ok()?
        .json()
        .await
        .ok()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The production topology (2026-09-25)
//
// Every test above lets each node reach every other one directly. Production never has: one node
// sits behind a tunnel (`p2p.silvra.net`), the others dial it and cannot be dialed themselves, so
// the network is a star around it (#177) — and the two faults that cost the chain most in
// September lived in exactly that shape. A link that died on one side only left the hub unable to
// hear anyone for an hour (#232), and a validator that restarted with one direct peer sat out its
// own turns for two minutes, because by count it could not reach a quorum it plainly reached
// through the hub (#234). Both fixes have unit tests and transport tests; neither had been run
// through whole nodes in the shape that produced them, at the production ping settings.
// ─────────────────────────────────────────────────────────────────────────────────────────────

const STAR_HUB_RPC: u16 = 29_705;
const STAR_HUB_P2P: u16 = 29_706;
/// The hub's tunnel: every link into the hub runs through this relay, as every link into the
/// production node runs through `p2p.silvra.net`.
const STAR_HUB_LINK: u16 = 29_707;
const STAR_P1_RPC: u16 = 29_715;
const STAR_P1_P2P: u16 = 29_716;
/// What P1 announces as its address — a port nothing listens on, so a peer that learns it cannot
/// dial P1, as nobody can dial an operator behind NAT. Announcing *something* is deliberate: left
/// unset, P1 would ask the hub's `/whoami`, be found reachable on loopback, and announce its real
/// port — and the star would quietly become a triangle.
const STAR_P1_CLOSED: u16 = 29_717;
const STAR_P2_RPC: u16 = 29_725;
const STAR_P2_P2P: u16 = 29_726;
const STAR_P2_CLOSED: u16 = 29_727;
const STAR_P3_RPC: u16 = 29_735;
const STAR_P3_P2P: u16 = 29_736;
const STAR_P3_CLOSED: u16 = 29_737;

/// Hub plus three operators: quorum is three of four, so the chain runs on while one operator
/// restarts — the case the restart below is about.
const STAR_VALIDATORS: u64 = 4;

/// How long the chain may take to recover from a one-sided cut. At the production ping settings
/// (15 s interval, 60 s timeout, the second failure closes) the hub gives up its dead half of a
/// link about 135–150 s after the cut; the operator's watchdog (20 s) and redial (30 s) come on top.
const STAR_HEAL_BUDGET: Duration = Duration::from_secs(360);

/// A healed chain: this many blocks inside `STAR_HEALED_WINDOW`. Deliberately far below the idle
/// cadence (about one block a second here) and far above what a chain carried only by pulled votes
/// manages — a crawl is not a recovery.
const STAR_HEALED_BLOCKS: u64 = 10;
const STAR_HEALED_WINDOW: Duration = Duration::from_secs(20);

/// A TCP relay whose links can be cut the way a tunnel or a NAT drops them (#232): `cut()` closes
/// every link it carries at that moment on the *dialing* side — which sees the connection end —
/// and leaves the target's side open and silent. Nothing is read from it or written to it again,
/// so the target keeps believing in a connection that leads nowhere. Links opened after a cut are
/// relayed normally.
///
/// A copy of the relay in `helix-p2p/tests/half_open_transport.rs`: test binaries cannot share
/// helpers without a common module, and forty lines are cheaper than one.
struct CuttableLink {
    generation: tokio::sync::watch::Sender<u64>,
    accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl CuttableLink {
    async fn spawn(listen: u16, target: u16) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", listen))
            .await
            .unwrap_or_else(|e| panic!("cuttable link cannot bind {listen}: {e}"));
        let (generation, _) = tokio::sync::watch::channel(0u64);
        let generations = generation.clone();
        let accepted: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let accepted_here = accepted.clone();
        // The target-side sockets of cut links. Held and never touched: dropping one would close
        // it, and a closed socket is exactly what the target must *not* see.
        let silent: std::sync::Arc<tokio::sync::Mutex<Vec<tokio::net::TcpStream>>> = Default::default();
        tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else { return };
                accepted_here.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Ok(upstream) = tokio::net::TcpStream::connect(("127.0.0.1", target)).await else {
                    continue;
                };
                let mut cut = generations.subscribe();
                let born = *cut.borrow_and_update();
                let silent = silent.clone();
                tokio::spawn(async move {
                    let (mut client, mut upstream) = (client, upstream);
                    let (mut up_buf, mut down_buf) = (vec![0u8; 16 * 1024], vec![0u8; 16 * 1024]);
                    loop {
                        tokio::select! {
                            n = client.read(&mut up_buf) => match n {
                                Ok(0) | Err(_) => return,
                                Ok(n) => if upstream.write_all(&up_buf[..n]).await.is_err() { return },
                            },
                            n = upstream.read(&mut down_buf) => match n {
                                Ok(0) | Err(_) => return,
                                Ok(n) => if client.write_all(&down_buf[..n]).await.is_err() { return },
                            },
                            changed = cut.changed() => {
                                if changed.is_err() { return }
                                if *cut.borrow() > born {
                                    drop(client);
                                    silent.lock().await.push(upstream);
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        CuttableLink { generation, accepted }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn cut(&self) {
        self.generation.send_modify(|g| *g += 1);
    }
}

async fn height_of(rpc_port: u16) -> Option<u64> {
    status(rpc_port).await.and_then(|s| s["height"].as_u64())
}

/// Who proposed block `height`.
async fn proposer_of(rpc_port: u16, height: u64) -> Option<String> {
    block_header(rpc_port, height)
        .await?
        .get("validator")?
        .as_str()
        .map(str::to_string)
}

/// **A hub and three validators that can only reach it — the shape of the production network.**
///
/// Four validators of equal power, quorum three of four (the production set of 2026-09-22). The
/// hub is reachable only through `CuttableLink`, its tunnel; the other three announce addresses
/// nobody can dial, so each holds exactly one connection, to the hub — one short of the two other
/// validators its share of a quorum needs. Production ping settings throughout — the node does not
/// expose them.
///
/// 1. **The tunnel drops its links on one side only (#232).** The three validators see their links
///    end and redial; the hub keeps its halves of the old links, open and silent. Before #232 that
///    was the end of it: to the hub a redial is a *second* connection, gossipsub sends its
///    subscriptions only on the first, and a validator that knows of no subscriber publishes its
///    votes to nobody. On the production node it took an hour to wear off. Here the chain has
///    `STAR_HEAL_BUDGET` to run at a healthy cadence again, by itself.
/// 2. **A validator restarts while the chain runs on without it (#234).** It comes back with one
///    direct peer against the two the count asks for, so by count it cannot reach quorum and held
///    its own proposer turns for the full grace period — each one a round lost while the chain ran
///    on around it (five of them after one restart on 2026-09-24). Counted here the same way:
///    which of its own turns after it caught up did it take? Every one but possibly the first —
///    `ChainPulse` starts out not moving on purpose (blocks a startup sync applied prove only that
///    history exists, not that the chain is moving now), so a turn that falls before the first
///    block applied after the restart is held, as a node with enough direct peers holds it for
///    `MESH_SETTLE_TICKS`. Measured: the turn right after catching up, lost by a tick.
///
/// Four and not three for the second part: with three of three the chain stands while any one of
/// them is down and only moves again once the restarted node votes, which here took up to 13 s of
/// the 18 s grace period (60 ticks at the test's 300 ms). Left one turn to lose — a test that tells
/// the fix from its absence by one turn is a coin toss.
#[tokio::test]
#[ignore = "four validator processes in a star around a relayed hub, two activation epochs, a one-sided cut healed at production ping settings and a restart (~5-8 min) — run with --ignored --nocapture"]
async fn a_star_around_one_hub_heals_a_one_sided_cut_and_a_restart_by_itself() {
    let _serialized = NODE_TEST_LOCK.lock().await;
    for (port, label) in [
        (STAR_HUB_RPC, "hub rpc"), (STAR_HUB_P2P, "hub p2p"), (STAR_HUB_LINK, "hub link"),
        (STAR_P1_RPC, "P1 rpc"), (STAR_P1_P2P, "P1 p2p"), (STAR_P1_CLOSED, "P1 announced"),
        (STAR_P2_RPC, "P2 rpc"), (STAR_P2_P2P, "P2 p2p"), (STAR_P2_CLOSED, "P2 announced"),
        (STAR_P3_RPC, "P3 rpc"), (STAR_P3_P2P, "P3 p2p"), (STAR_P3_CLOSED, "P3 announced"),
    ] {
        assert_port_free(port, label);
    }

    let link = CuttableLink::spawn(STAR_HUB_LINK, STAR_HUB_P2P).await;

    let kp_hub = KeyPair::generate();
    let kp_1 = KeyPair::generate();
    let kp_2 = KeyPair::generate();
    let kp_3 = KeyPair::generate();
    let addr_1 = Address::from_public_key(&kp_1.public).to_string();
    let addr_2 = Address::from_public_key(&kp_2.public).to_string();
    let addr_3 = Address::from_public_key(&kp_3.public).to_string();

    let ma = |port: u16| format!("/ip4/127.0.0.1/tcp/{port}");
    let fast = ("HELIX_BLOCK_TIME_MS", JOIN_BLOCK_TIME_MS);
    // The hub announces its tunnel, so the other two — which derive their seed from the hub's
    // `/status` — dial the tunnel and not the hub's port.
    let hub_addr = ma(STAR_HUB_LINK);
    let closed_1 = ma(STAR_P1_CLOSED);
    let closed_2 = ma(STAR_P2_CLOSED);
    let closed_3 = ma(STAR_P3_CLOSED);
    let env_1 = [fast, ("HELIX_P2P_PUBLIC_ADDR", closed_1.as_str())];
    let env_2 = [fast, ("HELIX_P2P_PUBLIC_ADDR", closed_2.as_str())];
    let env_3 = [fast, ("HELIX_P2P_PUBLIC_ADDR", closed_3.as_str())];

    let _hub = spawn_node_with(STAR_HUB_RPC, STAR_HUB_P2P, None,
        &[fast, ("HELIX_P2P_PUBLIC_ADDR", &hub_addr)], Some(&kp_hub));
    wait_until_reachable(STAR_HUB_RPC, Duration::from_secs(15)).await;
    wait_for_height(STAR_HUB_RPC, 2, Duration::from_secs(30)).await;

    let p1 = spawn_node_with(STAR_P1_RPC, STAR_P1_P2P, Some(STAR_HUB_RPC), &env_1, Some(&kp_1));
    let _p2 = spawn_node_with(STAR_P2_RPC, STAR_P2_P2P, Some(STAR_HUB_RPC), &env_2, Some(&kp_2));
    let _p3 = spawn_node_with(STAR_P3_RPC, STAR_P3_P2P, Some(STAR_HUB_RPC), &env_3, Some(&kp_3));
    wait_until_reachable(STAR_P1_RPC, Duration::from_secs(30)).await;
    wait_until_reachable(STAR_P2_RPC, Duration::from_secs(30)).await;
    wait_until_reachable(STAR_P3_RPC, Duration::from_secs(30)).await;

    let (_kd_hub, key_hub) = temp_keyfile(&kp_hub);
    let (_kd_1, key_1) = temp_keyfile(&kp_1);
    let (_kd_2, key_2) = temp_keyfile(&kp_2);
    let (_kd_3, key_3) = temp_keyfile(&kp_3);
    fund_and_stake(STAR_HUB_RPC, &key_hub, &kp_1, &key_1).await;
    fund_and_stake(STAR_HUB_RPC, &key_hub, &kp_2, &key_2).await;
    fund_and_stake(STAR_HUB_RPC, &key_hub, &kp_3, &key_3).await;
    assert!(
        wait_for_validator_active(STAR_HUB_RPC, &addr_1, Duration::from_secs(600)).await,
        "P1 staked but never activated — activation stalled"
    );
    assert!(
        wait_for_validator_active(STAR_HUB_RPC, &addr_2, Duration::from_secs(600)).await,
        "P2 staked but never activated — activation stalled"
    );
    assert!(
        wait_for_validator_active(STAR_HUB_RPC, &addr_3, Duration::from_secs(600)).await,
        "P3 staked but never activated — activation stalled"
    );

    // Positive control on the topology: without it, a pass below could come from two validators
    // that found each other directly and never needed the hub's links at all.
    let star_by = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let peers = |s: Option<serde_json::Value>| s.and_then(|s| s["peer_count"].as_u64());
        let got = [
            peers(status(STAR_HUB_RPC).await),
            peers(status(STAR_P1_RPC).await),
            peers(status(STAR_P2_RPC).await),
            peers(status(STAR_P3_RPC).await),
        ];
        if got == [Some(3), Some(1), Some(1), Some(1)] {
            break;
        }
        assert!(
            std::time::Instant::now() < star_by,
            "not a star: peers hub, P1, P2, P3 = {got:?} (want 3, 1, 1, 1)"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(link.accepted() >= 3, "the validators never reached the hub through its tunnel");

    let idle = measure_cadence(STAR_HUB_RPC, 12, Duration::from_secs(120)).await;
    // Every validator takes its turns in the star — P1, P2 and P3 hold one direct peer each, one
    // short of what the count says quorum needs (#234).
    //
    // The same blocks also say whose turn each height is. The round-`r` proposer of height `h` is
    // `full[(h + r) % n]` (`ValidatorSet::proposer_for_round`), so on a healthy chain every
    // validator proposes at one fixed residue of `h mod n` — read here rather than assumed from
    // the set's order. The RPC does not carry the round a block was finalized in (`last_commit`
    // comes back as addresses only), and the residue is how the restart below tells a turn taken
    // from a turn lost.
    let tip = height_of(STAR_HUB_RPC).await.expect("hub height");
    let n = STAR_VALIDATORS;
    let mut seen: std::collections::HashMap<String, [u32; STAR_VALIDATORS as usize]> = Default::default();
    for h in tip.saturating_sub(39)..=tip {
        if let Some(v) = proposer_of(STAR_HUB_RPC, h).await {
            seen.entry(v).or_default()[(h % n) as usize] += 1;
        }
    }
    let residue: std::collections::HashMap<String, u64> = seen
        .iter()
        .map(|(v, counts)| {
            let r = (0..n).max_by_key(|r| counts[*r as usize]).unwrap_or(0);
            (v.clone(), r)
        })
        .collect();
    let distinct: HashSet<u64> = residue.values().copied().collect();
    assert!(
        [&addr_1, &addr_2, &addr_3].iter().all(|a| residue.contains_key(*a))
            && residue.len() == n as usize
            && distinct.len() == n as usize,
        "not every validator took its own turns in the last 40 blocks (proposals by residue of \
         h mod {n}: {seen:?})"
    );

    // ── 1. The tunnel drops its links on one side only. ──
    let accepted_before_cut = link.accepted();
    let h_cut = height_of(STAR_HUB_RPC).await.expect("hub height");
    let cut_at = std::time::Instant::now();
    link.cut();
    let mut samples: Vec<(std::time::Instant, u64)> = vec![(cut_at, h_cut)];
    let healed_after = loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = std::time::Instant::now();
        let Some(h) = height_of(STAR_HUB_RPC).await else { continue };
        samples.push((now, h));
        let window_start = samples
            .iter()
            .find(|(t, _)| now.duration_since(*t) <= STAR_HEALED_WINDOW)
            .map(|(_, h)| *h)
            .unwrap_or(h);
        if now.duration_since(cut_at) >= STAR_HEALED_WINDOW && h >= window_start + STAR_HEALED_BLOCKS {
            break now.duration_since(cut_at);
        }
        assert!(
            now.duration_since(cut_at) < STAR_HEAL_BUDGET,
            "the chain did not recover within {STAR_HEAL_BUDGET:?} of the tunnel dropping its links \
             on one side only: height {h_cut} at the cut, {h} now, the validators redialed {} times. \
             The hub keeps its dead halves; to it every redial is a second connection, over which \
             gossipsub never sends its subscriptions, so the validators publish their votes to \
             nobody (#232)",
            link.accepted() - accepted_before_cut
        );
    };
    // The longest stretch without a block after the cut. Positive control: a cut that did not
    // stop the chain proves nothing about how it recovers.
    let mut longest_stall = Duration::ZERO;
    let (mut last_block_at, mut last_height) = (cut_at, h_cut);
    for &(at, h) in &samples {
        if h > last_height {
            longest_stall = longest_stall.max(at.duration_since(last_block_at));
            (last_block_at, last_height) = (at, h);
        }
    }
    eprintln!(
        "idle median {:.2}s p90 {:.2}s · cut at {h_cut}: longest stall {:.1}s, healthy again {:.1}s after the cut, {} redials through the tunnel",
        idle.median,
        idle.p90,
        longest_stall.as_secs_f64(),
        healed_after.as_secs_f64(),
        link.accepted() - accepted_before_cut
    );
    assert!(
        longest_stall >= Duration::from_secs(10),
        "the chain barely noticed the cut (longest stall {:.1}s) — the validators must have had \
         another path to the hub, and this measured nothing",
        longest_stall.as_secs_f64()
    );

    // ── 2. A validator restarts while the chain runs on without it. ──
    let settled = height_of(STAR_HUB_RPC).await.expect("hub height") + 10;
    wait_for_height(STAR_HUB_RPC, settled, Duration::from_secs(60)).await;
    let work_dir = p1.stop().await;
    let h_stopped = height_of(STAR_HUB_RPC).await.expect("hub height");
    tokio::time::sleep(Duration::from_secs(5)).await;
    let h_restart = height_of(STAR_HUB_RPC).await.expect("hub height");
    // Positive control: the others finalized without P1, so P1 comes back into a chain that is
    // moving — the only case in which the blocks it applies can tell it anything.
    assert!(
        h_restart >= h_stopped + 3,
        "the chain did not move while P1 was down ({h_stopped} → {h_restart}): three of four \
         should carry it, and without that there is nothing for P1 to come back to"
    );
    let _p1 = start_node_in(work_dir, STAR_P1_RPC, STAR_P1_P2P, Some(STAR_HUB_RPC), &env_1);
    // Counted from the moment P1 has caught up: before that it could not have proposed on the
    // current height whatever the gate said.
    let caught_up_by = std::time::Instant::now() + Duration::from_secs(60);
    let h0 = loop {
        let (hub, p1) = (height_of(STAR_HUB_RPC).await, height_of(STAR_P1_RPC).await);
        if let (Some(hub), Some(p1)) = (hub, p1) {
            if p1 >= hub {
                break hub;
            }
        }
        assert!(
            std::time::Instant::now() < caught_up_by,
            "P1 did not catch up within 60 s of its restart"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let first = h0 + 1;
    let last = h0 + 16;
    wait_for_height(STAR_HUB_RPC, last, Duration::from_secs(180)).await;
    let (mut turns, mut kept, mut lost, mut rows) = (0u64, 0u64, 0u64, Vec::new());
    let mut missed_after_first = Vec::new();
    for h in first..=last {
        let proposer = proposer_of(STAR_HUB_RPC, h).await.expect("header of a committed block");
        // Rounds this height took, modulo the set size — enough here, where a height losing four
        // rounds in a row would take every validator missing its turn.
        let round = (residue[&proposer] + n - h % n) % n;
        lost += round;
        if h % n == residue[&addr_1] {
            turns += 1;
            if proposer == addr_1 {
                kept += 1;
            } else if turns > 1 {
                missed_after_first.push(h);
            }
        }
        let who = [(&addr_1, "P1"), (&addr_2, "P2"), (&addr_3, "P3")]
            .iter()
            .find(|(a, _)| **a == proposer)
            .map_or("hub", |(_, w)| *w);
        rows.push(format!("{h}:{who}/r{round}"));
    }
    eprintln!(
        "P1 stopped at {h_stopped}, back at {h_restart}, caught up at {h0}: it took {kept} of its \
         {turns} turns in blocks {first}..={last}, {lost} rounds lost — {}",
        rows.join(" ")
    );
    assert!(turns >= 3, "only {turns} of P1's turns in the window — too few to tell anything");
    assert!(
        missed_after_first.is_empty(),
        "after its restart P1 took {kept} of its {turns} turns in blocks {first}..={last} \
         ({lost} rounds lost), missing {missed_after_first:?} after its first: it sat out its own \
         turns. It has one direct peer against the two the count asks for, and it reaches quorum \
         through the hub — the blocks it applies say so (#234)"
    );
}
