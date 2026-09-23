//! A peer that publishes what it likes into gossipsub, and whom the network ends up blaming.
//!
//! Until #228 gossipsub here ran without application-level validation: a node forwarded every
//! message whose envelope signature checked out *before* its own code had looked at the payload
//! (`libp2p-gossipsub` 0.47, `handle_received_message`). So an honest node relayed whatever an
//! attacker injected. Whoever is charged for a bad payload decides whether a misbehaving peer is
//! cut off — or whether honest relays are, one hop further on, by nodes that only ever talked to
//! them. In a hub-and-spoke network (this chain's own shape, #177) the second is a partition.
//!
//! Now a node forwards only what it has read and accepted. Both halves are tested here: that an
//! upgraded relay stops what it cannot vouch for, and — because a network is never upgraded all at
//! once — that a node behind an *old* relay still charges the author and not the relay (#225).

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use helix_p2p::blocksync::{BlockProvider, BlockSyncResponse};
use helix_p2p::{
    P2PCommand, P2PConfig, P2PEvent, P2PService, TransactionVerdict, TOPIC_TRANSACTIONS,
};
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
/// Before #228, R was honest and relayed it, because gossipsub relayed before anyone read the
/// payload. V never spoke to the attacker — its only peer is R. If V charges whoever handed it the
/// bytes, it charges R, and five messages later V has banned an honest peer it depends on. On this
/// chain every operator reaches the others through V1 (#177): the same five messages would have
/// every validator ban V1.
///
/// With both nodes upgraded, R no longer relays the garbage at all, so V keeping R is now
/// guaranteed twice over — which means this test alone no longer catches V charging the relay.
/// `garbage_through_an_old_relay_…` below does, with a relay that still forwards everything.
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

/// The forged-transaction verdict (#225, #228), end to end across a real relay.
///
/// R hears five forged transactions straight from their author, and its node answers each one
/// `Forged`. R must cut the author off, and forward none of them — so V, which only knows R, never
/// sees them and has nothing to hold against anyone, least of all R.
#[tokio::test]
async fn a_forged_transaction_is_charged_to_its_author_and_forwarded_to_nobody() {
    let (relay_cmd, mut relay_events) = spawn(config(19_763, vec![]));
    let (_victim_cmd, mut victim_events) = spawn(config(19_764, vec![19_763]));

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
    wait_for_subscription(&mut attacker, &topic).await;

    // Well-formed on the wire — the P2P layer cannot tell they are forged; the node's signature
    // check can. Distinct, or gossipsub drops the repeats as duplicates.
    for nonce in 0..5 {
        attacker
            .behaviour_mut()
            .publish(
                topic.clone(),
                bincode::serialize(&a_transaction_with_nonce(nonce)).unwrap(),
            )
            .expect("publish");
    }
    tokio::spawn(async move {
        loop {
            attacker.select_next_some().await;
        }
    });

    // What the relay's node answers after its signature check — past the ban threshold.
    for _ in 0..5 {
        match next_matching(&mut relay_events, Duration::from_secs(10), |e| {
            matches!(e, P2PEvent::NewTransaction(..))
        })
        .await
        {
            Some(P2PEvent::NewTransaction(_, Some(ticket))) => {
                assert_eq!(
                    ticket.author().as_deref(),
                    Some(attacker_id.as_str()),
                    "the ticket names who wrote the transaction"
                );
                ticket.answer(TransactionVerdict::Forged);
            }
            other => panic!("the relay never handed a gossiped transaction to its node: {other:?}"),
        }
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
            .any(|e| matches!(e, P2PEvent::NewTransaction(..))),
        "the relay forwarded a transaction its node had found forged"
    );
    assert!(
        !victim_saw
            .iter()
            .any(|e| matches!(e, P2PEvent::PeerDisconnected(p) if *p == relay)),
        "the victim held the relay to a transaction the relay did not write"
    );
    relay_cmd
        .send(P2PCommand::BroadcastTransaction(a_transaction_with_nonce(
            99,
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

/// #228, the transaction half: a transaction crosses a relay only once the relay's node has found
/// it valid — and then it does, with its author intact (#225: the next hop charges the author,
/// so it must learn who that is, not who relayed it).
///
/// Two transactions from one honest writer. The relay's node answers the second `Valid` and sits
/// on the first: the second must reach V and the first must not. Then the first's ticket is
/// dropped unanswered — which answers `Unjudged` — and it still must not. Against a relay that
/// forwards before it validates, the first crosses at once; against a relay that never reports,
/// the second never does.
#[tokio::test]
async fn a_transaction_crosses_the_relay_only_after_its_node_found_it_valid() {
    let (_relay_cmd, mut relay_events) = spawn(config(19_767, vec![]));
    let (_victim_cmd, mut victim_events) = spawn(config(19_768, vec![19_767]));

    if next_matching(&mut victim_events, Duration::from_secs(15), |e| {
        matches!(e, P2PEvent::PeerConnected(_))
    })
    .await
    .is_none()
    {
        panic!("the victim never connected to the relay");
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut writer = hostile_gossiper();
    let writer_id = writer.local_peer_id().to_string();
    let topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);
    writer.behaviour_mut().subscribe(&topic).unwrap();
    writer
        .dial("/ip4/127.0.0.1/tcp/19767".parse::<Multiaddr>().unwrap())
        .unwrap();
    wait_for_subscription(&mut writer, &topic).await;
    for nonce in [0, 1] {
        writer
            .behaviour_mut()
            .publish(
                topic.clone(),
                bincode::serialize(&a_transaction_with_nonce(nonce)).unwrap(),
            )
            .expect("publish");
    }
    tokio::spawn(async move {
        loop {
            writer.select_next_some().await;
        }
    });

    let mut held = None;
    for _ in 0..2 {
        match next_matching(&mut relay_events, Duration::from_secs(10), |e| {
            matches!(e, P2PEvent::NewTransaction(..))
        })
        .await
        {
            Some(P2PEvent::NewTransaction(tx, Some(ticket))) if tx.nonce == 1 => {
                ticket.answer(TransactionVerdict::Valid)
            }
            Some(P2PEvent::NewTransaction(_, Some(ticket))) => held = Some(ticket),
            other => panic!("the relay never handed a gossiped transaction to its node: {other:?}"),
        }
    }

    let crossed = next_matching(&mut victim_events, Duration::from_secs(10), |e| {
        matches!(e, P2PEvent::NewTransaction(..))
    })
    .await;
    match crossed {
        Some(P2PEvent::NewTransaction(tx, Some(ticket))) => {
            assert_eq!(
                tx.nonce, 1,
                "the transaction the relay has not checked crossed it"
            );
            assert_eq!(
                ticket.author().as_deref(),
                Some(writer_id.as_str()),
                "across a relay the author must still be the writer, not the relay"
            );
        }
        other => panic!(
            "a transaction the relay's node found valid never crossed the relay — its verdict \
             was not reported: {other:?}"
        ),
    }
    let before_drop = drain(&mut victim_events, Duration::from_secs(3)).await;
    drop(held.expect("the relay's node was handed both transactions"));
    let after_drop = drain(&mut victim_events, Duration::from_secs(3)).await;
    assert!(
        !before_drop
            .iter()
            .chain(after_drop.iter())
            .any(|e| matches!(e, P2PEvent::NewTransaction(..))),
        "a transaction crossed the relay without its node's say-so"
    );
}

/// The network is never upgraded all at once. Here the relay is an *old* build — a bare gossipsub
/// node that forwards whatever it receives — and V is current. The garbage reaches V; V must not
/// charge the relay for it (#225), or five messages from an outsider still partition honest nodes
/// wherever a hub has not been upgraded yet.
#[tokio::test]
async fn garbage_through_an_old_relay_is_never_held_against_the_relay() {
    let mut old_relay = hostile_gossiper();
    let relay_id = old_relay.local_peer_id().to_string();
    let topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);
    old_relay.behaviour_mut().subscribe(&topic).unwrap();
    old_relay
        .listen_on("/ip4/127.0.0.1/tcp/19769".parse::<Multiaddr>().unwrap())
        .unwrap();
    tokio::spawn(async move {
        loop {
            old_relay.select_next_some().await;
        }
    });
    let (_victim_cmd, mut victim_events) = spawn(config(19_770, vec![19_769]));
    if next_matching(
        &mut victim_events,
        Duration::from_secs(15),
        |e| matches!(e, P2PEvent::PeerConnected(p) if *p == relay_id),
    )
    .await
    .is_none()
    {
        panic!("the victim never connected to the old relay");
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut attacker = hostile_gossiper();
    attacker.behaviour_mut().subscribe(&topic).unwrap();
    attacker
        .dial("/ip4/127.0.0.1/tcp/19769".parse::<Multiaddr>().unwrap())
        .unwrap();
    wait_for_subscription(&mut attacker, &topic).await;
    for i in 0..10u32 {
        attacker
            .behaviour_mut()
            .publish(
                topic.clone(),
                format!("not a transaction #{i}").into_bytes(),
            )
            .expect("publish");
    }
    // The canary, sent last down the same path: if it arrives, the garbage did too.
    attacker
        .behaviour_mut()
        .publish(topic.clone(), bincode::serialize(&a_transaction()).unwrap())
        .expect("publish");
    tokio::spawn(async move {
        loop {
            attacker.select_next_some().await;
        }
    });

    let victim_saw = drain(&mut victim_events, Duration::from_secs(6)).await;
    assert!(
        victim_saw
            .iter()
            .any(|e| matches!(e, P2PEvent::NewTransaction(..))),
        "the canary never arrived, so the garbage cannot be shown to have arrived either"
    );
    assert!(
        !victim_saw
            .iter()
            .any(|e| matches!(e, P2PEvent::PeerDisconnected(p) if *p == relay_id)),
        "the victim disconnected an old relay for bytes the relay only forwarded"
    );
}

/// Poll `swarm` until the peer it dialled announces `topic` — before that, a publish has no mesh
/// to go to.
async fn wait_for_subscription(
    swarm: &mut Swarm<gossipsub::Behaviour>,
    topic: &gossipsub::IdentTopic,
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let SwarmEvent::Behaviour(gossipsub::Event::Subscribed { topic: t, .. }) =
                swarm.select_next_some().await
            {
                if t == topic.hash() {
                    break;
                }
            }
        }
    })
    .await
    .expect("the relay never announced its transactions subscription");
}

fn a_transaction_with_nonce(nonce: u64) -> helix_core::Transaction {
    helix_core::Transaction {
        nonce,
        ..a_transaction()
    }
}

const ALL_TOPICS: [&str; 5] = [
    helix_p2p::TOPIC_BLOCKS,
    helix_p2p::TOPIC_TRANSACTIONS,
    helix_p2p::TOPIC_VOTES,
    helix_p2p::TOPIC_COMMITTED_BLOCKS,
    helix_p2p::TOPIC_PEER_EXCHANGE,
];

/// A bare gossipsub node that listens on every topic and reports each message it receives — who
/// wrote it and on which topic. Connected to nothing but the relay under test, so everything it
/// sees, the relay forwarded.
async fn observe_through(
    relay_port: u16,
) -> (
    libp2p::PeerId,
    mpsc::UnboundedReceiver<(String, libp2p::PeerId)>,
) {
    let mut observer = hostile_gossiper();
    for topic in ALL_TOPICS {
        observer
            .behaviour_mut()
            .subscribe(&gossipsub::IdentTopic::new(topic))
            .unwrap();
    }
    let id = *observer.local_peer_id();
    observer
        .dial(
            format!("/ip4/127.0.0.1/tcp/{relay_port}")
                .parse::<Multiaddr>()
                .unwrap(),
        )
        .unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            if let SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) =
                observer.select_next_some().await
            {
                if let Some(author) = message.source {
                    let _ = tx.send((message.topic.into_string(), author));
                }
            }
        }
    });
    (id, rx)
}

fn a_block(height: u64) -> helix_core::Block {
    use helix_crypto::{Address, PublicKey, Signature};
    let pk = PublicKey::from_bytes(vec![7; 32]);
    let mut block = helix_core::block::genesis_block(
        Address::from_public_key(&pk),
        pk,
        Signature::from_bytes(vec![9; 32]),
        1_700_000_000_000,
    );
    block.header.height = height;
    block
}

fn a_vote(height: u64) -> helix_consensus::Vote {
    use helix_crypto::{Address, Hash, PublicKey, Signature};
    let pk = PublicKey::from_bytes(vec![7; 32]);
    helix_consensus::Vote {
        vote_type: helix_consensus::VoteType::Prevote,
        height,
        round: 0,
        block_hash: Hash::digest(b"a block"),
        validator: Address::from_public_key(&pk),
        public_key: pk,
        crypto_version: helix_core::CryptoVersion::MlDsa,
        signature: Signature::from_bytes(vec![1; 32]),
    }
}

/// #228: validation before forwarding, seen from the next hop.
///
/// Every consensus topic and peer exchange must still cross the relay — **with nobody reading
/// the relay's node-facing events**, because forwarding a consensus message must not wait on the
/// node. In a hub-and-spoke network a topic the relay forgot to report stops at the hub, and the
/// chain stops with it; this is the test that notices. And none of the attacker's garbage may
/// cross at all: an upgraded relay stops it, so operators still running an older build never see
/// it and never charge the relay for it.
#[tokio::test]
async fn an_upgraded_relay_forwards_every_consensus_topic_at_once_and_garbage_never() {
    let (_relay_cmd, _relay_events_nobody_reads) = spawn(config(19_765, vec![]));
    let (author_cmd, mut author_events) = spawn(config(19_766, vec![19_765]));
    let (_observer, mut seen) = observe_through(19_765).await;

    let mut attacker = hostile_gossiper();
    let attacker_id = *attacker.local_peer_id();
    for topic in ALL_TOPICS {
        attacker
            .behaviour_mut()
            .subscribe(&gossipsub::IdentTopic::new(topic))
            .unwrap();
    }
    attacker
        .dial("/ip4/127.0.0.1/tcp/19765".parse::<Multiaddr>().unwrap())
        .unwrap();

    if next_matching(&mut author_events, Duration::from_secs(15), |e| {
        matches!(e, P2PEvent::PeerConnected(_))
    })
    .await
    .is_none()
    {
        panic!("the author never connected to the relay");
    }
    // Mesh formation on every node, then keep the attacker's swarm polled from here on.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        let _ = tokio::time::timeout(Duration::from_millis(100), attacker.select_next_some()).await;
    }
    for (i, topic) in ALL_TOPICS.iter().enumerate() {
        let _ = attacker.behaviour_mut().publish(
            gossipsub::IdentTopic::new(*topic),
            format!("garbage #{i}").into_bytes(),
        );
    }
    tokio::spawn(async move {
        loop {
            attacker.select_next_some().await;
        }
    });

    author_cmd
        .send(P2PCommand::BroadcastVote(a_vote(10)))
        .await
        .unwrap();
    author_cmd
        .send(P2PCommand::BroadcastProposal(
            helix_consensus::Proposal::fresh(0, a_block(11)),
        ))
        .await
        .unwrap();
    author_cmd
        .send(P2PCommand::BroadcastBlock(a_block(10), vec![a_vote(10)]))
        .await
        .unwrap();

    // Peer exchange goes out every 30 s, and the first tick fires before any connection exists —
    // so the author's first readable announcement is up to half a minute away.
    //
    // Counted per writer: the relay announces itself on peer exchange too, straight to the
    // observer, and that must not stand in for the author's announcement crossing it. The author
    // is whoever wrote the vote — nobody else publishes one.
    let mut by_writer: std::collections::HashMap<
        libp2p::PeerId,
        std::collections::HashSet<String>,
    > = Default::default();
    let mut from_attacker = Vec::new();
    let want = [
        helix_p2p::TOPIC_VOTES,
        helix_p2p::TOPIC_BLOCKS,
        helix_p2p::TOPIC_COMMITTED_BLOCKS,
        helix_p2p::TOPIC_PEER_EXCHANGE,
    ];
    let from_author = |by_writer: &std::collections::HashMap<
        libp2p::PeerId,
        std::collections::HashSet<String>,
    >| {
        by_writer
            .values()
            .find(|topics| topics.contains(helix_p2p::TOPIC_VOTES))
            .cloned()
            .unwrap_or_default()
    };
    let _ = tokio::time::timeout(Duration::from_secs(45), async {
        while let Some((topic, source)) = seen.recv().await {
            if source == attacker_id {
                from_attacker.push(topic);
            } else {
                by_writer.entry(source).or_default().insert(topic);
            }
            let author = from_author(&by_writer);
            if want.iter().all(|t| author.contains(*t)) {
                break;
            }
        }
    })
    .await;
    // A little longer for any garbage still in flight.
    while let Ok(Some((topic, source))) =
        tokio::time::timeout(Duration::from_secs(2), seen.recv()).await
    {
        if source == attacker_id {
            from_attacker.push(topic);
        }
    }

    assert!(
        from_attacker.is_empty(),
        "the relay forwarded garbage it could not decode: {from_attacker:?}"
    );
    let from_author = from_author(&by_writer);
    for topic in want {
        assert!(
            from_author.contains(topic),
            "{topic} did not cross the relay — a topic whose validation result is never reported \
             is never forwarded, and in a hub-and-spoke network that stops the chain \
             (got: {from_author:?})"
        );
    }
}
