//! `P2PConfig::outbound_peers` over real connections: a node stops at the number of peers it dials
//! itself, still admits every peer that dials it, and makes up the number when it falls short.
//!
//! The rules are pure functions with their own tests, and those pass just as well if nothing calls
//! them at the right place — a target checked only on the redial tick, say, would be green there and
//! let the startup dial reach every remembered address. Counting the peers the service announces is
//! the only way to see what a node operator sees.

use std::collections::HashSet;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use helix_p2p::blocksync::{BlockProvider, BlockSyncResponse};
use helix_p2p::{P2PConfig, P2PEvent, P2PService};
use tokio::sync::mpsc::Receiver;

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

fn config(port: u16, seeds: &[u16], outbound_peers: Option<usize>) -> P2PConfig {
    P2PConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        seed_peers: seeds.iter().map(|p| format!("/ip4/127.0.0.1/tcp/{p}")).collect(),
        // Nothing but the configured addresses may bring these nodes together, and a test beside a
        // live node must not cross-wire with it over the LAN.
        enable_mdns: false,
        outbound_peers,
        ..P2PConfig::default()
    }
}

fn spawn(cfg: P2PConfig) -> Receiver<P2PEvent> {
    let (service, _cmd, events) =
        P2PService::new(cfg, Arc::new(AtomicU64::new(0)), Arc::new(NoBlocks));
    tokio::spawn(async move { service.run().await });
    events
}

/// A node whose events nobody reads would stall its swarm on a full channel.
fn spawn_and_drain(cfg: P2PConfig) {
    let mut events = spawn(cfg);
    tokio::spawn(async move { while events.recv().await.is_some() {} });
}

/// The peers `events` announces as connected (and not since disconnected) after `secs`, read the
/// whole time so nothing is missed.
async fn connected_after(events: &mut Receiver<P2PEvent>, peers: &mut HashSet<String>, secs: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while let Ok(event) = tokio::time::timeout_at(deadline, events.recv()).await {
        match event {
            Some(P2PEvent::PeerConnected(p)) => {
                peers.insert(p);
            }
            Some(P2PEvent::PeerDisconnected(p)) => {
                peers.remove(&p);
            }
            Some(_) => {}
            None => break,
        }
    }
}

/// Four reachable seeds and a target of three: three peers, and the fourth closed before it is ever
/// announced — over the startup dial *and* a redial tick. Then a node that dials *in* is admitted
/// although the target is met, because the public seed has to keep admitting everyone who joins
/// through it. The control below is the same network without a target, so a fourth peer is shown
/// to be reachable at all.
#[tokio::test]
async fn a_node_dials_up_to_its_outbound_target_and_still_admits_peers_that_dial_in() {
    let listeners = [19_841, 19_842, 19_843, 19_844];
    for port in listeners {
        spawn_and_drain(config(port, &[], None));
    }
    let mut events = spawn(config(19_845, &listeners, Some(3)));
    let mut peers = HashSet::new();
    // 40 s: past the redial tick at 30 s, which must not dial the fourth either.
    connected_after(&mut events, &mut peers, 40).await;
    assert_eq!(
        peers.len(),
        3,
        "with four reachable seeds and HELIX_P2P_OUTBOUND_PEERS=3, exactly three must be announced"
    );

    // A node that dials this one is inbound, and the target says nothing about it. It also tells
    // the listeners this node's address in its peer exchange, so the one that was closed may dial
    // in as well — inbound too, and admitted: the target limits what this node dials, never who
    // reaches it. Hence four or five, and never three.
    spawn_and_drain(config(19_846, &[19_845], None));
    connected_after(&mut events, &mut peers, 15).await;
    assert!(
        (4..=5).contains(&peers.len()),
        "a peer that dials in must be admitted although the outbound target is met — {} announced",
        peers.len()
    );
}

#[tokio::test]
async fn without_an_outbound_target_the_same_node_dials_every_seed() {
    let listeners = [19_851, 19_852, 19_853, 19_854];
    for port in listeners {
        spawn_and_drain(config(port, &[], None));
    }
    let mut events = spawn(config(19_855, &listeners, None));
    let mut peers = HashSet::new();
    connected_after(&mut events, &mut peers, 15).await;
    assert_eq!(peers.len(), 4, "control: every one of the four seeds is reachable");
}

/// Short of its target with the floor met, the node dials known addresses on the redial tick until
/// the target is reached — and not one more. Three seeds are up at the start, two are not; a node
/// dialing in keeps the total above the floor, so only the top-up can explain a new peer. Once both
/// missing seeds are up, exactly one of them is dialed.
///
/// Every other node here dials nothing it does not have to: the seeds dial nothing at all
/// (`Some(0)`), the one that dials in stops at that one (`Some(1)`). Otherwise the count measured
/// the network instead of this node: the node hands the later seeds' addresses on in its peer
/// exchange, another peer dials one, that one learns this node's address the same way and dials it
/// — an inbound peer this node rightly admits, and a sixth peer the assertion read as a dial too
/// many. CI caught exactly that on 2026-10-14 (`906891d`, 6 against 5); this node's own dials are
/// capped where they complete, before they are announced, so a sixth can only ever be inbound.
#[tokio::test]
async fn a_node_short_of_its_outbound_target_makes_it_up_on_the_redial_tick_and_stops_there() {
    let up = [19_861, 19_862, 19_863];
    let later = [19_864, 19_865];
    for port in up {
        spawn_and_drain(config(port, &[], Some(0)));
    }
    let seeds: Vec<u16> = up.iter().chain(later.iter()).copied().collect();
    let mut events = spawn(config(19_866, &seeds, Some(4)));
    spawn_and_drain(config(19_867, &[19_866], Some(1)));

    let mut peers = HashSet::new();
    connected_after(&mut events, &mut peers, 10).await;
    assert_eq!(
        peers.len(),
        4,
        "precondition: three dialed seeds and the one peer that dialed in"
    );

    for port in later {
        spawn_and_drain(config(port, &[], Some(0)));
    }
    // The redial tick is 30 s; its first run was at startup, before the two were up.
    connected_after(&mut events, &mut peers, 45).await;
    assert_eq!(
        peers.len(),
        5,
        "short of HELIX_P2P_OUTBOUND_PEERS=4 with the floor met, the redial tick must dial exactly \
         one of the two seeds that came up — the target, and not past it"
    );

    // And it stays there over another tick.
    connected_after(&mut events, &mut peers, 35).await;
    assert_eq!(peers.len(), 5, "no further dial once the target is met");
}
