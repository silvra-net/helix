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
//! just gossip/sync agreement with a single active validator. Organically growing from one
//! validator to three would mean each follower accumulating `MIN_VALIDATOR_STAKE` (100k HLX)
//! via block rewards (1 HLX/block) or transfers — economically real, but far too slow for an
//! automated test (literally weeks). Instead it uses `HELIX_GENESIS_EXTRA_VALIDATORS` (see
//! `GenesisConfig::extra_validators`'s doc comment) to pre-stake two more validators — with
//! known keypairs, so the spawned follower processes can be given matching `validator-key.json`
//! files — directly at genesis, so all three are active BFT participants from block 0.
//!
//! That second test is marked `#[ignore]`: it spawns three real validator processes and waits
//! out a one-time gossip-mesh settle plus a window of finalized blocks (~30s wall-clock),
//! which is slower than the rest of the suite is meant to be on every CI push. Run it
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

/// Separate port range for the multi-validator test below — it runs as a distinct
/// `#[tokio::test]` in the same test binary, and `cargo test` runs tests within a binary
/// concurrently by default, so it can't share ports with the test above.
const VAL_A_RPC: u16 = 29_575;
const VAL_A_P2P: u16 = 29_576;
const VAL_B_RPC: u16 = 29_585;
const VAL_B_P2P: u16 = 29_586;
const VAL_C_RPC: u16 = 29_595;
const VAL_C_P2P: u16 = 29_596;

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
/// `HELIX_GENESIS_EXTRA_VALIDATORS` on the genesis node). `keypair` — if set, pre-writes
/// `validator-key.json` into the node's work dir so it starts with this exact validator
/// identity instead of generating a random one, so a follower's address can be pre-staked in
/// another node's genesis ahead of time and the follower still ends up controlling it.
fn spawn_node_with(
    rpc_port: u16,
    p2p_port: u16,
    sync_peer_rpc_port: Option<u16>,
    extra_env: &[(&str, &str)],
    keypair: Option<&KeyPair>,
) -> NodeGuard {
    let work_dir = tempdir::TempDir::new().expect("create temp work dir for node");
    if let Some(kp) = keypair {
        KeyFile::from_keypair_plain(kp)
            .save(&work_dir.path().join("validator-key.json"))
            .expect("pre-write validator key file");
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_helix"));
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
        // Quiet by default; uncomment locally when debugging a failure.
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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

/// CTO backlog item 56 — see the module doc comment for the design (genesis pre-staking
/// instead of an organic, too-slow-to-automate staking dance). Boots a real 3-validator BFT
/// set from block 0 and asserts two things a single-active-validator setup structurally
/// cannot exercise: (1) more than one of the three distinct validator addresses actually
/// proposes a block — real round-robin rotation, not just one validator winning every round
/// — and (2) all three nodes still converge on identical height, hash, and state despite that
/// rotation happening across independent processes over real network latency, the same
/// bug class (backlog item 47) that a non-deterministic proposer order or an engine height
/// desync would reproduce under exactly these conditions.
#[tokio::test]
#[ignore = "spawns 3 real validator processes and waits out a mesh-settle + a window of blocks (~30s wall-clock) — run explicitly with --ignored, not on every CI push"]
async fn three_validators_rotate_proposer_and_finalize_blocks_together() {
    // B and C's validator identities are generated up front so their addresses can be
    // pre-staked in A's genesis, and their own processes can later be started with a
    // matching `validator-key.json` so they actually control the stake genesis gave them.
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

    // Exactly MIN_VALIDATOR_STAKE (100k HLX) each — enough to qualify, nothing more.
    let extra_validators = format!("{addr_b}:100000,{addr_c}:100000");
    let _node_a = spawn_node_with(
        VAL_A_RPC,
        VAL_A_P2P,
        None,
        &[("HELIX_GENESIS_EXTRA_VALIDATORS", &extra_validators), ("HELIX_P2P_SEED_PEERS", &seeds_a)],
        None,
    );
    wait_until_reachable(VAL_A_RPC, Duration::from_secs(15)).await;

    // B and C join via HELIX_SYNC_PEER (adopts A's genesis block byte-for-byte *and*, via GET
    // /genesis's extra_validators field, rebuilds the same pre-staked state, so all three
    // independently arrive at an identical 3-validator ValidatorSet from height 0) and the
    // same full-mesh seed peers. With `ValidatorSet::new`'s 1%-of-total-stake cap making every
    // validator's voting power identical, quorum genuinely needs all three voting — a real
    // multi-validator BFT round, proposal + two-phase commit, not a single-proposer shortcut.
    let _node_b = spawn_node_with(VAL_B_RPC, VAL_B_P2P, Some(VAL_A_RPC), &[("HELIX_P2P_SEED_PEERS", &seeds_b)], Some(&kp_b));
    let _node_c = spawn_node_with(VAL_C_RPC, VAL_C_P2P, Some(VAL_A_RPC), &[("HELIX_P2P_SEED_PEERS", &seeds_c)], Some(&kp_c));
    wait_until_reachable(VAL_B_RPC, Duration::from_secs(15)).await;
    wait_until_reachable(VAL_C_RPC, Duration::from_secs(15)).await;

    // Block production waits out a one-time mesh-settle (so the first round's votes aren't lost
    // to a half-formed gossip mesh — see block_production_loop) and then finalizes a steady
    // ~1-2s/block with proposer rotation across all three. The timeout is deliberately far
    // larger than the ~30s this needs, to stay green on a slow/loaded CI machine without
    // masking a genuine stall.
    let target_height = 10;
    wait_for_height(VAL_A_RPC, target_height, Duration::from_secs(180)).await;

    let mut distinct_proposers = HashSet::new();
    for height in 1..=target_height {
        let header = block_header(VAL_A_RPC, height)
            .await
            .unwrap_or_else(|| panic!("node A has no header for height {height} despite reporting that height"));
        distinct_proposers.insert(header["validator"].as_str().unwrap().to_string());
    }
    assert!(
        distinct_proposers.len() > 1,
        "only one validator ({:?}) ever proposed across the first {target_height} blocks — \
         proposer rotation isn't actually happening despite 3 active validators",
        distinct_proposers
    );

    // Same convergence check as the single-validator test above — rotation happening across
    // independent processes must not cost agreement on the result.
    let (a, b, c) = wait_for_matching_snapshot([VAL_A_RPC, VAL_B_RPC, VAL_C_RPC], target_height, Duration::from_secs(120)).await;
    assert_eq!(a["best_hash"], b["best_hash"], "node A and B disagree on the block hash at height {}", a["height"]);
    assert_eq!(a["best_hash"], c["best_hash"], "node A and C disagree on the block hash at height {}", a["height"]);
    assert_eq!(
        a["state_hash"], b["state_hash"],
        "node A and B agree on the block hash at height {} but computed different state from it",
        a["height"]
    );
    assert_eq!(
        a["state_hash"], c["state_hash"],
        "node A and C agree on the block hash at height {} but computed different state from it",
        a["height"]
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
