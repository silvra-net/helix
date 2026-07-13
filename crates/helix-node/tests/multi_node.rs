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
//! Deliberately does *not* yet exercise multi-validator BFT (proposer rotation, live voting)
//! — that needs a staking dance (fund + `Stake` each follower up to `MIN_VALIDATOR_STAKE`)
//! that's a meaningful next increment, not a blocker for this first, always-on baseline.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Distinct, uncommon port range so this doesn't collide with anything else that might be
/// running on a dev machine or CI runner. Nothing else in this workspace uses these.
const NODE_A_RPC: u16 = 29_545;
const NODE_A_P2P: u16 = 29_546;
const NODE_B_RPC: u16 = 29_555;
const NODE_B_P2P: u16 = 29_556;
const NODE_C_RPC: u16 = 29_565;
const NODE_C_P2P: u16 = 29_566;

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
    let work_dir = tempdir::TempDir::new().expect("create temp work dir for node");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_helix"));
    cmd.current_dir(work_dir.path())
        .env("HELIX_RPC_BIND", format!("127.0.0.1:{rpc_port}"))
        .env("HELIX_P2P_LISTEN", format!("127.0.0.1:{p2p_port}"))
        // Quiet by default; uncomment locally when debugging a failure.
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(peer_port) = sync_peer_rpc_port {
        cmd.env("HELIX_SYNC_PEER", format!("http://127.0.0.1:{peer_port}"));
    }
    let child = cmd.spawn().expect("spawn helix node binary");
    NodeGuard { child, _work_dir: work_dir }
}

async fn status(rpc_port: u16) -> Option<serde_json::Value> {
    reqwest::get(format!("http://127.0.0.1:{rpc_port}/status"))
        .await
        .ok()?
        .json()
        .await
        .ok()
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

#[tokio::test]
async fn three_nodes_converge_on_identical_height_hash_and_state() {
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
    assert_eq!(
        a["state_hash"], b["state_hash"],
        "node A and B agree on the block hash at height {} but computed different state from \
         it — an execution divergence, not a consensus/sync one (see ChainState::state_hash's \
         doc comment)", a["height"]
    );
    assert_eq!(
        a["state_hash"], c["state_hash"],
        "node A and C agree on the block hash at height {} but computed different state from \
         it — an execution divergence, not a consensus/sync one", a["height"]
    );
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
            let mut path = std::env::temp_dir();
            let unique = format!(
                "helix-multi-node-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
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
