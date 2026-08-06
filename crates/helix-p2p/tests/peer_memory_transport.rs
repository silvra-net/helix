//! End-to-end proof that a node finds its way back to the network after a restart, without a seed.
//!
//! Why this cannot be a unit test: `peer_store`'s own tests show that what is written can be read
//! back, and they pass just as happily if nothing ever calls `save` — or if the loaded addresses
//! are put in `known_addrs` for gossip but never actually dialed. Both of those are the whole
//! mechanism. The same gap was found the expensive way twice already (#147's teardown half,
//! #151's tick counter): a pure function stays green whether or not it is wired to anything.
//!
//! So: two real `P2PService` instances on loopback TCP, mDNS off so nothing but an address on disk
//! can bring the second pair together.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use helix_p2p::blocksync::{BlockProvider, BlockSyncResponse};
use helix_p2p::{P2PConfig, P2PEvent, P2PService};

struct NoBlocks;

impl BlockProvider for NoBlocks {
    fn blocks<'a>(
        &'a self,
        _from_height: u64,
        _count: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = BlockSyncResponse> + Send + 'a>> {
        Box::pin(async { BlockSyncResponse::empty() })
    }
}

fn config(port: u16, seeds: Vec<u16>, store: Option<std::path::PathBuf>) -> P2PConfig {
    P2PConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        seed_peers: seeds
            .into_iter()
            .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
            .collect(),
        // A test that discovered peers over the LAN would prove nothing about the file on disk —
        // and would cross-wire with any live node on the same segment.
        enable_mdns: false,
        peer_store_path: store,
        ..P2PConfig::default()
    }
}

/// Announce a reachable address, so the peer has something worth remembering. Without this the
/// only address in play is the one already configured as a seed, and the test could not tell
/// "remembered it" from "was told it".
fn config_announcing(port: u16, seeds: Vec<u16>, store: Option<std::path::PathBuf>) -> P2PConfig {
    P2PConfig {
        public_addr: Some(format!("/ip4/127.0.0.1/tcp/{port}")),
        ..config(port, seeds, store)
    }
}

fn spawn(cfg: P2PConfig) -> tokio::sync::mpsc::Receiver<P2PEvent> {
    let (service, _cmd, events) = P2PService::new(cfg, Arc::new(AtomicU64::new(0)), Arc::new(NoBlocks));
    tokio::spawn(async move { service.run().await });
    events
}

/// Wait for a peer connection, or give up.
async fn connected_within(events: &mut tokio::sync::mpsc::Receiver<P2PEvent>, secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(1), events.recv()).await {
            Ok(Some(P2PEvent::PeerConnected(_))) => return true,
            Ok(Some(_)) => continue,
            Ok(None) => return false,
            Err(_) => continue,
        }
    }
    false
}

/// The capability, stated as an operator would: a node that has met the network once can be
/// restarted and find it again on its own — no seed, no configuration, nothing but what it learned
/// while it was running.
///
/// Before this, every restart put a node back on its first start: `known_addrs` lived only in the
/// service loop, so a node that had gossiped with the whole network for weeks came back knowing
/// exactly what its operator had typed. In practice that is one built-in endpoint, which makes the
/// entire network's ability to admit anyone depend on one machine staying up. Bitcoin's DNS seeds
/// bootstrap the *first* start and `peers.dat` carries every one after it; this is that file.
#[tokio::test]
async fn a_node_that_has_met_the_network_finds_it_again_without_a_seed() {
    let dir = std::env::temp_dir().join(format!("helix-peer-memory-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("peers.txt");

    // The peer that stays up, announcing a dialable address.
    let mut host_events = spawn(config_announcing(19_711, vec![], None));
    tokio::spawn(async move { while host_events.recv().await.is_some() {} });

    // First run: dials the host as a seed, learns its announced address, writes it down.
    let mut first_events = spawn(config(19_712, vec![19_711], Some(store.clone())));
    assert!(
        connected_within(&mut first_events, 30).await,
        "precondition: the first run must reach the host at all"
    );

    // The peer-exchange tick is 30s, and the file is written on it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(75);
    while tokio::time::Instant::now() < deadline {
        if store.exists() && !helix_p2p::peer_store::load(&store).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let remembered = helix_p2p::peer_store::load(&store);
    assert!(
        remembered.iter().any(|a| a.contains("19711")),
        "the first run must have written down the host it met; file holds: {remembered:?}"
    );

    // Scope, stated so the next reader does not credit this test with more than it does: what is
    // proven here is that whatever a node knows reaches the disk, and that what is on disk gets
    // dialed on the next start. *How* an address enters `known_addrs` — a configured seed, or an
    // address learned from a peer-exchange announcement — is `select_new_addrs`' job and is
    // covered by its own unit tests.

    // Second run: a different node, on a different port, with NO seeds at all — only the file.
    // This is the assertion the whole feature exists for.
    let mut second_events = spawn(config(19_713, vec![], Some(store.clone())));
    assert!(
        connected_within(&mut second_events, 30).await,
        "a node with no seeds must still reach the network using the peers it remembered"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// The control that keeps the test above honest. Same node, same absent seeds, same everything —
/// but no memory. It must *not* connect, or the test above would pass on some other discovery path
/// (mDNS creeping back in, a stray listener) and would prove nothing about the file.
#[tokio::test]
async fn without_the_remembered_peers_the_same_node_finds_nobody() {
    let mut host_events = spawn(config_announcing(19_721, vec![], None));
    tokio::spawn(async move { while host_events.recv().await.is_some() {} });

    // No seeds, no peer store: there is no way for this node to learn the host exists.
    let mut orphan_events = spawn(config(19_722, vec![], None));

    assert!(
        !connected_within(&mut orphan_events, 15).await,
        "with no seeds and no remembered peers there is nothing to connect to — if this connects, \
         some other discovery path is active and the positive test proves nothing"
    );
}
