//! A peer that publishes what it likes into gossipsub, and whom the network ends up blaming.
//!
//! gossipsub here runs without application-level validation: a node forwards every message whose
//! envelope signature checks out *before* its own code has looked at the payload
//! (`libp2p-gossipsub` 0.47, `handle_received_message`). So an honest node relays whatever an
//! attacker injects. Whoever is charged for a bad payload decides whether a misbehaving peer is
//! cut off — or whether honest relays are, one hop further on, by nodes that only ever talked to
//! them. In a hub-and-spoke network (this chain's own shape, #177) the second is a partition.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use helix_p2p::blocksync::{BlockProvider, BlockSyncResponse};
use helix_p2p::{P2PCommand, P2PConfig, P2PEvent, P2PService, TOPIC_TRANSACTIONS};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, noise, tcp, yamux, Multiaddr, Swarm, SwarmBuilder};
use tokio::sync::mpsc;

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

fn config(port: u16, seeds: Vec<u16>) -> P2PConfig {
    P2PConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        seed_peers: seeds
            .into_iter()
            .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
            .collect(),
        enable_mdns: false,
        ..P2PConfig::default()
    }
}

fn spawn(cfg: P2PConfig) -> (mpsc::Sender<P2PCommand>, mpsc::Receiver<P2PEvent>) {
    let (service, commands, events) =
        P2PService::new(cfg, Arc::new(AtomicU64::new(0)), Arc::new(NoBlocks));
    tokio::spawn(async move { service.run().await });
    (commands, events)
}

/// A bare gossipsub node speaking exactly the protocol the service speaks — signed messages,
/// strict validation — and nothing else. It can publish any bytes on any topic.
fn hostile_gossiper() -> Swarm<gossipsub::Behaviour> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("tcp transport")
        .with_behaviour(|key| {
            let config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()
                .expect("gossipsub config");
            gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(key.clone()), config)
                .expect("gossipsub behaviour")
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build()
}

/// Wait for the first event matching `want`, returning it, or `None` after `within`.
async fn next_matching(
    events: &mut mpsc::Receiver<P2PEvent>,
    within: Duration,
    mut want: impl FnMut(&P2PEvent) -> bool,
) -> Option<P2PEvent> {
    tokio::time::timeout(within, async {
        while let Some(event) = events.recv().await {
            if want(&event) {
                return Some(event);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// Every event seen within `window` — for asserting that something did *not* happen.
async fn drain(events: &mut mpsc::Receiver<P2PEvent>, window: Duration) -> Vec<P2PEvent> {
    let mut seen = Vec::new();
    let _ = tokio::time::timeout(window, async {
        while let Some(event) = events.recv().await {
            seen.push(event);
        }
    })
    .await;
    seen
}

fn a_transaction() -> helix_core::Transaction {
    use helix_crypto::{Address, CryptoScheme, Hash, PublicKey, Signature};
    helix_core::Transaction {
        version: 1,
        tx_type: helix_core::TxType::Transfer,
        from: Address::from_public_key(&PublicKey::from_bytes(vec![7; 32])),
        to: None,
        amount: 1,
        fee: 1,
        nonce: 0,
        data: vec![],
        crypto_version: CryptoScheme::MlDsa,
        chain_id: Hash::digest(b"canary"),
        signature: Signature::from_bytes(vec![]),
        public_key: PublicKey::from_bytes(vec![7; 32]),
    }
}

/// The attack: an outsider with no stake connects to one honest node and publishes garbage.
///
/// R is honest and relays it, because gossipsub relays before anyone reads the payload. V never
/// spoke to the attacker — its only peer is R. If V charges whoever handed it the bytes, it charges
/// R, and five messages later V has banned an honest peer it depends on. On this chain every
/// operator reaches the others through V1 (#177): the same five messages would have every
/// validator ban V1.
#[tokio::test]
async fn garbage_relayed_by_an_honest_node_gets_the_attacker_cut_off_and_not_the_relay() {
    let (relay_cmd, mut relay_events) = spawn(config(19_761, vec![]));
    let (_victim_cmd, mut victim_events) = spawn(config(19_762, vec![19_761]));

    let relay = match next_matching(&mut victim_events, Duration::from_secs(15), |e| {
        matches!(e, P2PEvent::PeerConnected(_))
    })
    .await
    {
        Some(P2PEvent::PeerConnected(peer)) => peer,
        _ => panic!("the victim never connected to the relay"),
    };
    // One gossipsub heartbeat is enough for R to graft V into its transactions mesh; three leave
    // no doubt, so a missing ban below cannot be a message that simply never got forwarded — the
    // canary at the end checks that too.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut attacker = hostile_gossiper();
    let attacker_id = *attacker.local_peer_id();
    let topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);
    attacker.behaviour_mut().subscribe(&topic).unwrap();
    attacker
        .dial("/ip4/127.0.0.1/tcp/19761".parse::<Multiaddr>().unwrap())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let SwarmEvent::Behaviour(gossipsub::Event::Subscribed { topic: t, .. }) =
                attacker.select_next_some().await
            {
                if t == topic.hash() {
                    break;
                }
            }
        }
    })
    .await
    .expect("the relay never announced its transactions subscription to the attacker");

    // Twice the ban threshold, each distinct — gossipsub drops a payload it has already seen.
    for i in 0..10u32 {
        attacker
            .behaviour_mut()
            .publish(
                topic.clone(),
                format!("not a transaction #{i}").into_bytes(),
            )
            .expect("publish");
    }
    // Keep the attacker's swarm polled so its messages actually leave.
    tokio::spawn(async move {
        loop {
            attacker.select_next_some().await;
        }
    });

    let victim_saw = drain(&mut victim_events, Duration::from_secs(6)).await;
    let relay_banned_by_victim = victim_saw
        .iter()
        .any(|e| matches!(e, P2PEvent::PeerDisconnected(p) if *p == relay));
    let relay_saw = drain(&mut relay_events, Duration::from_millis(100)).await;
    let attacker_cut_off_by_relay = relay_saw
        .iter()
        .any(|e| matches!(e, P2PEvent::PeerDisconnected(p) if *p == attacker_id.to_string()));

    assert!(
        !relay_banned_by_victim,
        "the victim disconnected the honest relay for bytes the relay only forwarded — five \
         garbage messages from an outsider partitioned two honest nodes"
    );
    assert!(
        attacker_cut_off_by_relay,
        "the relay, which received the garbage straight from its author, must cut the author off"
    );

    // Positive control: the link the attack aimed at still carries traffic.
    relay_cmd
        .send(P2PCommand::BroadcastTransaction(a_transaction()))
        .await
        .unwrap();
    assert!(
        next_matching(&mut victim_events, Duration::from_secs(10), |e| {
            matches!(e, P2PEvent::NewTransaction(..))
        })
        .await
        .is_some(),
        "after the attack the victim no longer hears the relay"
    );
}

/// The forged-transaction report (#225), end to end across a real relay.
///
/// The author must survive the relay: V hears the transaction from R but must learn that the
/// attacker wrote it, or the node would report R. And the report must be charged only where the
/// author is connected: R, which the attacker talks to directly, cuts it off; V, which never spoke
/// to it, charges nobody — least of all R.
#[tokio::test]
async fn a_forged_transaction_is_charged_to_its_author_where_it_is_connected_and_nowhere_else() {
    let (relay_cmd, mut relay_events) = spawn(config(19_763, vec![]));
    let (victim_cmd, mut victim_events) = spawn(config(19_764, vec![19_763]));

    let relay = match next_matching(&mut victim_events, Duration::from_secs(15), |e| {
        matches!(e, P2PEvent::PeerConnected(_))
    })
    .await
    {
        Some(P2PEvent::PeerConnected(peer)) => peer,
        _ => panic!("the victim never connected to the relay"),
    };
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut attacker = hostile_gossiper();
    let attacker_id = attacker.local_peer_id().to_string();
    let topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);
    attacker.behaviour_mut().subscribe(&topic).unwrap();
    attacker
        .dial("/ip4/127.0.0.1/tcp/19763".parse::<Multiaddr>().unwrap())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let SwarmEvent::Behaviour(gossipsub::Event::Subscribed { topic: t, .. }) =
                attacker.select_next_some().await
            {
                if t == topic.hash() {
                    break;
                }
            }
        }
    })
    .await
    .expect("the relay never announced its transactions subscription to the attacker");

    // Well-formed on the wire — the P2P layer cannot tell it is forged; the node's signature
    // check can, and reports its author with `ForgedTransactionFrom`.
    attacker
        .behaviour_mut()
        .publish(topic.clone(), bincode::serialize(&a_transaction()).unwrap())
        .expect("publish");
    tokio::spawn(async move {
        loop {
            attacker.select_next_some().await;
        }
    });

    let author_seen_by = |events: P2PEvent| match events {
        P2PEvent::NewTransaction(_, author) => author,
        _ => None,
    };
    let at_victim = next_matching(&mut victim_events, Duration::from_secs(10), |e| {
        matches!(e, P2PEvent::NewTransaction(..))
    })
    .await
    .map(author_seen_by)
    .expect("the relayed transaction never reached the victim");
    assert_eq!(
        at_victim.as_deref(),
        Some(attacker_id.as_str()),
        "across a relay the author must still be the attacker, not the relay ({relay})"
    );
    let at_relay = next_matching(&mut relay_events, Duration::from_secs(10), |e| {
        matches!(e, P2PEvent::NewTransaction(..))
    })
    .await
    .map(author_seen_by)
    .expect("the relay never handed the transaction to its node");
    assert_eq!(at_relay.as_deref(), Some(attacker_id.as_str()));

    // What both nodes' signature checks would now report — past the ban threshold.
    for _ in 0..5 {
        relay_cmd
            .send(P2PCommand::ForgedTransactionFrom(attacker_id.clone()))
            .await
            .unwrap();
        victim_cmd
            .send(P2PCommand::ForgedTransactionFrom(attacker_id.clone()))
            .await
            .unwrap();
    }

    assert!(
        next_matching(&mut relay_events, Duration::from_secs(10), |e| {
            matches!(e, P2PEvent::PeerDisconnected(p) if *p == attacker_id)
        })
        .await
        .is_some(),
        "the relay, connected to the author, must cut it off"
    );
    let victim_saw = drain(&mut victim_events, Duration::from_secs(3)).await;
    assert!(
        !victim_saw
            .iter()
            .any(|e| matches!(e, P2PEvent::PeerDisconnected(p) if *p == relay)),
        "the victim held the relay to a transaction the relay did not write"
    );
    relay_cmd
        .send(P2PCommand::BroadcastTransaction(a_transaction_with_nonce(
            1,
        )))
        .await
        .unwrap();
    assert!(
        next_matching(&mut victim_events, Duration::from_secs(10), |e| {
            matches!(e, P2PEvent::NewTransaction(..))
        })
        .await
        .is_some(),
        "positive control: the victim still hears the relay"
    );
}

fn a_transaction_with_nonce(nonce: u64) -> helix_core::Transaction {
    helix_core::Transaction {
        nonce,
        ..a_transaction()
    }
}
