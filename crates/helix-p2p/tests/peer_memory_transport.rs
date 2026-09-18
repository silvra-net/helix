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
    let (service, _cmd, events) =
        P2PService::new(cfg, Arc::new(AtomicU64::new(0)), Arc::new(NoBlocks));
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

/// Wait for a connection to any peer *other than* `not`, or give up; returns its id.
///
/// The identity filter is load-bearing, and was found by the first version of the test below being
/// green for the wrong reason. At startup the redial tick fires immediately and dials the remembered
/// address a second time; that duplicate connection races the host going away, and its
/// `PeerConnected` for the *old* host sat in the channel while the test slept. A waiter that took any
/// `PeerConnected` read it as the reconnection — after 2.0 s, faster than the 30 s tick allows. The
/// returning host is a new process with a new identity, so only a different id proves it was reached.
async fn connected_to_a_peer_other_than(
    events: &mut tokio::sync::mpsc::Receiver<P2PEvent>,
    not: Option<&str>,
    secs: u64,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(1), events.recv()).await {
            Ok(Some(P2PEvent::PeerConnected(peer))) if Some(peer.as_str()) != not => {
                return Some(peer)
            }
            Ok(Some(_)) => continue,
            Ok(None) => return None,
            Err(_) => continue,
        }
    }
    None
}

/// Wait for `peer` to disconnect, or give up.
async fn disconnected_within(
    events: &mut tokio::sync::mpsc::Receiver<P2PEvent>,
    peer: &str,
    secs: u64,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(1), events.recv()).await {
            Ok(Some(P2PEvent::PeerDisconnected(p))) if p == peer => return true,
            Ok(Some(_)) => continue,
            Ok(None) => return false,
            Err(_) => continue,
        }
    }
    false
}

/// A running host that can be taken away again, which `spawn` cannot do.
fn spawn_host(port: u16) -> tokio::task::JoinHandle<()> {
    let (handle, mut events) = spawn_with_handle(config_announcing(port, vec![], None));
    tokio::spawn(async move { while events.recv().await.is_some() {} });
    handle
}

fn spawn_with_handle(
    cfg: P2PConfig,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::Receiver<P2PEvent>,
) {
    let (service, _cmd, events) =
        P2PService::new(cfg, Arc::new(AtomicU64::new(0)), Arc::new(NoBlocks));
    let handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    (handle, events)
}

/// Backlog #196, reproduced with real services: a node with **no seeds** loses its only peer, the
/// peer comes back, and nothing but this node can restore the link.
///
/// That is the shape of 2026-09-13. The production node has no seeds (it is the seed), a
/// 45-second network outage dropped its one peer, and the other validators — connected to each
/// other — had no reason to redial it. The redial at zero connections dialed only seeds, which it
/// does not have, so it sat at 0 peers for 7 h 36 min and was jailed.
///
/// The returning host has no seeds and no peer store, and mDNS is off everywhere, so it cannot find
/// the node on its own: a reconnection here can only come from the node's own redial. The first
/// connection comes from the remembered-peer dial at startup, which already worked before the fix —
/// the assertion that matters is the second one, and it only counts the *new* host's identity.
#[tokio::test]
async fn a_node_without_seeds_redials_the_peer_it_lost_once_that_peer_is_back() {
    let dir = std::env::temp_dir().join(format!("helix-peer-redial-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("peers.txt");
    let host_addr = "/ip4/127.0.0.1/tcp/19731".to_string();
    helix_p2p::peer_store::save(&store, &[host_addr].into_iter().collect());

    let started = tokio::time::Instant::now();
    let host = spawn_host(19_731);
    let (_node, mut node_events) = spawn_with_handle(config(19_732, vec![], Some(store.clone())));
    let first_host = connected_to_a_peer_other_than(&mut node_events, None, 30)
        .await
        .expect("precondition: the node must reach the host through its remembered address at all");

    // The outage: the host goes away entirely, taking its listener and connections with it.
    host.abort();
    assert!(
        disconnected_within(&mut node_events, &first_host, 30).await,
        "precondition: the node must notice that its only peer is gone"
    );
    // Let the old listener release the port before the host comes back on it.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _host_again = spawn_host(19_731);
    let host_back = started.elapsed();

    // The redial tick is 30 s, so one full interval plus slack.
    let reconnected = connected_to_a_peer_other_than(&mut node_events, Some(&first_host), 75).await;
    // Printed, because the timing is evidence of *which* path reconnected: the redial runs on the
    // 30-second peer-exchange tick, so a reconnection far faster than the tick allows points at some
    // other mechanism and deserves a look before this test is believed.
    eprintln!(
        "host back after {:.1}s, reconnected to the new host: {} after {:.1}s",
        host_back.as_secs_f64(),
        reconnected.is_some(),
        started.elapsed().as_secs_f64()
    );
    assert!(
        reconnected.is_some(),
        "a node with no seeds must redial the addresses it knows once it has no connection left — \
         otherwise a single dropped peer is permanent until someone restarts a node"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Wait for a connection to any peer whose id is not already `known`, or give up.
///
/// Same reason as `connected_to_a_peer_other_than`, generalised to two hosts: the surviving peer
/// keeps producing events throughout, and the redial dials every address it knows on every tick,
/// so a duplicate `PeerConnected` for a host that never left would otherwise read as the
/// reconnection the test is waiting for.
async fn connected_to_a_new_peer(
    events: &mut tokio::sync::mpsc::Receiver<P2PEvent>,
    known: &[String],
    secs: u64,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(1), events.recv()).await {
            Ok(Some(P2PEvent::PeerConnected(peer))) if !known.contains(&peer) => return Some(peer),
            Ok(Some(_)) => continue,
            Ok(None) => return None,
            Err(_) => continue,
        }
    }
    None
}

/// The production failure of 2026-09-17 and 2026-09-18, reproduced: a node that loses a peer but
/// **keeps one** must still go looking for the one it lost.
///
/// This is the case the #196 redial does not cover, and it is the one that actually happened. Both
/// times the production node's tunnel dropped every peer within 1.5 s, exactly one came back on its
/// own, and from then on the node held a single peer — above zero, so the redial (which asked for
/// *no* connections) never fired. It sat there for 5 h 22 min and 3 h 21 min while the chain it
/// validates stood, and only moved again when an operator's node dialed in from outside. An address
/// that would have restored it was in its peer file the whole time.
///
/// The surviving host is what makes this a different test from the one above rather than a slower
/// copy of it: it holds the node at one connection, which is the precondition the old rule failed
/// on. That precondition is asserted, not assumed — without it this test would silently become the
/// zero-peer test, which already passes.
#[tokio::test]
async fn a_node_that_still_has_one_peer_redials_the_one_it_lost() {
    let dir =
        std::env::temp_dir().join(format!("helix-peer-underconnected-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("peers.txt");
    helix_p2p::peer_store::save(
        &store,
        &[
            "/ip4/127.0.0.1/tcp/19741".to_string(),
            "/ip4/127.0.0.1/tcp/19742".to_string(),
        ]
        .into_iter()
        .collect(),
    );

    let started = tokio::time::Instant::now();
    let leaving = spawn_host(19_741);
    let _surviving = spawn_host(19_742);
    let (_node, mut node_events) = spawn_with_handle(config(19_743, vec![], Some(store.clone())));

    let mut met: Vec<String> = Vec::new();
    for _ in 0..2 {
        let peer = connected_to_a_new_peer(&mut node_events, &met, 30)
            .await
            .expect("precondition: the node must reach both remembered hosts before one leaves");
        met.push(peer);
    }

    // One host goes away entirely; the other stays, holding the node at a single connection.
    leaving.abort();
    let mut gone: Option<String> = None;
    for candidate in &met {
        if disconnected_within(&mut node_events, candidate, 30).await {
            gone = Some(candidate.clone());
            break;
        }
    }
    let gone = gone.expect("precondition: the node must notice the host that left");
    let survivor: Vec<String> = met.iter().filter(|p| **p != gone).cloned().collect();
    assert_eq!(
        survivor.len(),
        1,
        "precondition: exactly one peer must remain — with none this is the zero-peer test, \
         which passed before this fix and would prove nothing about it"
    );

    // Let the old listener release the port before the host comes back on it, with a new identity.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _back = spawn_host(19_741);
    let host_back = started.elapsed();

    // The redial tick is 30 s, so one full interval plus slack.
    let reconnected = connected_to_a_new_peer(&mut node_events, &met, 75).await;
    // Printed for the same reason as the test above: a reconnection faster than the 30-second tick
    // allows would mean some other path did it, and this test's conclusion would not follow.
    eprintln!(
        "host back after {:.1}s, held {} peer(s) meanwhile, reconnected to the new host: {} after {:.1}s",
        host_back.as_secs_f64(),
        survivor.len(),
        reconnected.is_some(),
        started.elapsed().as_secs_f64()
    );
    assert!(
        reconnected.is_some(),
        "a node holding fewer peers than it wants must keep dialing the addresses it knows — \
         asking for *zero* connections instead is what left production at one peer for 8 h 45 min"
    );

    std::fs::remove_dir_all(&dir).ok();
}
