//! What answering block sync costs the node that answers.
//!
//! A block-sync request asks for up to a hundred blocks, and any connected peer may send one — no
//! stake, no account. The answer used to be built inside the swarm loop, awaited right there: the
//! loop that reads every socket and sends every vote this node casts stood still for as long as the
//! blocks took to read, and a peer that kept asking kept it standing (the shape of #224, from a
//! different door). These tests run a real service and put a slow answer in front of it.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use helix_consensus::{Vote, VoteType};
use helix_core::{genesis_block, Block};
use helix_crypto::{Address, Hash, KeyPair, Signature};
use helix_p2p::blocksync::{
    BlockProvider, BlockSyncCodec, BlockSyncRequest, BlockSyncResponse, BLOCKSYNC_PROTOCOL,
};
use helix_p2p::{P2PCommand, P2PConfig, P2PEvent, P2PService};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, request_response, tcp, yamux, Multiaddr, SwarmBuilder};
use tokio::sync::{mpsc, Notify};

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

fn a_block(kp: &KeyPair, height: u64) -> Block {
    let mut block = genesis_block(
        Address::from_public_key(&kp.public),
        kp.public.clone(),
        Signature::from_bytes(vec![]),
        0,
    );
    block.header.height = height;
    block
}

fn a_vote(kp: &KeyPair, height: u64) -> Vote {
    Vote {
        vote_type: VoteType::Prevote,
        height,
        round: 0,
        block_hash: Hash::digest(b"a block"),
        validator: Address::from_public_key(&kp.public),
        public_key: kp.public.clone(),
        crypto_version: kp.scheme,
        signature: Signature::from_bytes(vec![1; 16]),
    }
}

/// Answers every request after `delay` — a stand-in for reading a hundred full blocks — and says
/// when it starts, how many answers are being built at once, and the most there ever were.
struct SlowBlocks {
    kp: KeyPair,
    delay: Duration,
    started: Arc<Notify>,
    now: AtomicUsize,
    most: Arc<AtomicUsize>,
}

impl BlockProvider for SlowBlocks {
    fn blocks<'a>(
        &'a self,
        from_height: u64,
        _count: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = BlockSyncResponse> + Send + 'a>> {
        Box::pin(async move {
            let n = self.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.most.fetch_max(n, Ordering::SeqCst);
            self.started.notify_one();
            tokio::time::sleep(self.delay).await;
            self.now.fetch_sub(1, Ordering::SeqCst);
            BlockSyncResponse {
                blocks: vec![a_block(&self.kp, from_height.max(1))],
                tip_certificate: vec![a_vote(&self.kp, from_height.max(1))],
            }
        })
    }
}

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

fn slow_node(
    port: u16,
    delay: Duration,
) -> (mpsc::Sender<P2PCommand>, Arc<Notify>, Arc<AtomicUsize>) {
    let started = Arc::new(Notify::new());
    let most = Arc::new(AtomicUsize::new(0));
    let provider = SlowBlocks {
        kp: KeyPair::generate(),
        delay,
        started: started.clone(),
        now: AtomicUsize::new(0),
        most: most.clone(),
    };
    // Tip 5: a peer at 0 sees it ahead and asks it for blocks.
    let (service, commands, mut events) = P2PService::new(
        config(port, vec![]),
        Arc::new(AtomicU64::new(5)),
        Arc::new(provider),
    );
    tokio::spawn(async move { service.run().await });
    tokio::spawn(async move { while events.recv().await.is_some() {} });
    (commands, started, most)
}

/// While this node builds a block-sync answer, a vote it casts still leaves at once.
///
/// The requester here is an ordinary node that is behind: it asks, as every node does. The answer
/// takes three seconds to build, and the test casts a vote on the answering node the moment it
/// starts. Before the answer moved off the swarm loop, the vote waited out the three seconds — on
/// a real node the time it takes to read a hundred blocks, per request, for any peer that asks.
#[tokio::test]
async fn a_vote_is_not_held_up_while_the_node_answers_block_sync() {
    let (commands, started, _most) = slow_node(19_681, Duration::from_secs(3));

    let (behind, _behind_commands, mut behind_events) = P2PService::new(
        config(19_682, vec![19_681]),
        Arc::new(AtomicU64::new(0)),
        Arc::new(NoBlocks),
    );
    tokio::spawn(async move { behind.run().await });

    tokio::time::timeout(Duration::from_secs(60), started.notified())
        .await
        .expect("premise: the node behind asks for blocks, and the slow node starts answering");

    let kp = KeyPair::generate();
    let cast = Instant::now();
    commands
        .send(P2PCommand::BroadcastVote(a_vote(&kp, 7)))
        .await
        .unwrap();

    let arrived = loop {
        match tokio::time::timeout(Duration::from_secs(10), behind_events.recv()).await {
            Ok(Some(P2PEvent::NewVote(vote))) if vote.height == 7 => break cast.elapsed(),
            Ok(Some(_)) => continue,
            other => panic!("the vote never arrived: {:?}", other.map(|e| e.map(|_| ()))),
        }
    };
    println!("the vote arrived {arrived:?} after it was cast, while the answer was being built");
    assert!(
        arrived < Duration::from_millis(1_500),
        "the vote took {arrived:?} — it waited for the block-sync answer the node was building"
    );
}

/// A peer that sends many requests at once gets only a few answers built at a time.
///
/// Honest nodes ask one at a time, so this is only ever an attacker: a bare request-response
/// client, thirty requests in one go. Built without a bound, thirty answers of up to 8 MiB each
/// would be in memory together, from one connection.
#[tokio::test]
async fn many_requests_at_once_from_one_peer_are_not_all_answered_at_once() {
    let (_commands, _started, most) = slow_node(19_683, Duration::from_millis(500));

    let mut client = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("tcp transport")
        .with_behaviour(|_| {
            request_response::Behaviour::with_codec(
                BlockSyncCodec,
                [(
                    BLOCKSYNC_PROTOCOL,
                    request_response::ProtocolSupport::Outbound,
                )],
                request_response::Config::default().with_request_timeout(Duration::from_secs(60)),
            )
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    let target: Multiaddr = "/ip4/127.0.0.1/tcp/19683".parse().unwrap();
    client.dial(target).unwrap();

    let peer = loop {
        match tokio::time::timeout(Duration::from_secs(30), client.select_next_some()).await {
            Ok(SwarmEvent::ConnectionEstablished { peer_id, .. }) => break peer_id,
            Ok(_) => continue,
            Err(_) => panic!("premise: the client connects"),
        }
    };
    const SENT: usize = 30;
    for i in 0..SENT {
        client.behaviour_mut().send_request(
            &peer,
            BlockSyncRequest {
                from_height: 1 + i as u64,
                count: 100,
            },
        );
    }

    let mut settled = 0;
    let deadline = Instant::now() + Duration::from_secs(60);
    while settled < SENT && Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), client.select_next_some()).await {
            Ok(SwarmEvent::Behaviour(request_response::Event::Message {
                message: request_response::Message::Response { .. },
                ..
            }))
            | Ok(SwarmEvent::Behaviour(request_response::Event::OutboundFailure { .. })) => {
                settled += 1
            }
            _ => continue,
        }
    }
    assert_eq!(
        settled, SENT,
        "premise: every request was answered or refused"
    );

    let most = most.load(Ordering::SeqCst);
    println!("most answers built at once for one peer's {SENT} requests: {most}");
    assert!(most >= 1, "premise: the node answered at all");
    assert!(most <= 1, "{most} answers were built at once for one peer");
}

/// Serves `count` blocks of `bytes_each`, whole — no budget, the way the node's provider used to.
struct BigBlocks {
    kp: KeyPair,
    count: u64,
    bytes_each: usize,
}

impl BlockProvider for BigBlocks {
    fn blocks<'a>(
        &'a self,
        from_height: u64,
        _count: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = BlockSyncResponse> + Send + 'a>> {
        Box::pin(async move {
            let blocks = (from_height..from_height + self.count)
                .map(|h| {
                    let mut block = a_block(&self.kp, h);
                    block.header.node_version = "x".repeat(self.bytes_each);
                    block
                })
                .collect();
            BlockSyncResponse {
                blocks,
                tip_certificate: vec![a_vote(&self.kp, from_height)],
            }
        })
    }
}

/// The premise of the provider's byte budget, on the wire: an answer larger than
/// `RESPONSE_SIZE_MAXIMUM` never reaches the node that asked for it — it is cut off at the limit
/// and fails to decode, every time, so the requester cools the peer down and gets nowhere. The
/// same blocks in an answer that fits do arrive (the control), so it is the size and nothing else.
#[tokio::test]
async fn an_answer_larger_than_a_requester_reads_never_arrives() {
    let limit = helix_p2p::blocksync::RESPONSE_SIZE_MAXIMUM as usize;
    for (port, count, arrives) in [(19_685u16, 90u64, false), (19_687, 60, true)] {
        let bytes_each = 100 * 1024;
        let size = count as usize * bytes_each;
        assert_eq!(
            size > limit,
            !arrives,
            "premise: {count} blocks of 100 KB against {limit} B"
        );

        let (ahead, _ahead_commands, mut ahead_events) = P2PService::new(
            config(port, vec![]),
            Arc::new(AtomicU64::new(count)),
            Arc::new(BigBlocks {
                kp: KeyPair::generate(),
                count,
                bytes_each,
            }),
        );
        tokio::spawn(async move { ahead.run().await });
        tokio::spawn(async move { while ahead_events.recv().await.is_some() {} });
        let (behind, _behind_commands, mut behind_events) = P2PService::new(
            config(port + 1, vec![port]),
            Arc::new(AtomicU64::new(0)),
            Arc::new(NoBlocks),
        );
        tokio::spawn(async move { behind.run().await });

        let deadline = Instant::now() + Duration::from_secs(60);
        let mut got = None;
        while Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(2), behind_events.recv()).await {
                Ok(Some(P2PEvent::BlocksSynced(batch, _))) => {
                    got = Some(batch.blocks.len());
                    break;
                }
                Ok(None) => break,
                _ => continue,
            }
        }
        if arrives {
            assert_eq!(
                got,
                Some(count as usize),
                "control: {size} B fit, and all of it arrives"
            );
        } else {
            assert_eq!(got, None, "{size} B cannot be read, and nothing arrives");
        }
    }
}
