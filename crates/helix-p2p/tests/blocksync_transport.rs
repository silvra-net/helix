//! End-to-end proof that block sync works over the real libp2p wire (#138).
//!
//! Why this exists as an integration test and not another unit test: everything the unit tests
//! cover — the request bounds, the peer choice, the verifier, the provider — passes just as happily
//! when the transport is broken. The codec, the protocol negotiation, the request/response
//! behaviour, and the peer-exchange tip announcement that triggers a request are exactly the parts
//! that can only fail on a real connection, and they are the parts this mechanism exists for. A
//! green suite that never opened a socket would prove nothing about the outage it was built to fix.
//!
//! Two full `P2PService` instances on loopback TCP, mDNS off so nothing but the configured seed
//! address can bring them together.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use helix_consensus::Vote;
use helix_core::{genesis_block, Block};
use helix_crypto::{Address, KeyPair, Signature};
use helix_p2p::blocksync::{BlockProvider, BlockSyncResponse};
use helix_p2p::{P2PCommand, P2PConfig, P2PEvent, P2PService};

/// Blocks that chain from `Hash::ZERO`, signed by `kp` — enough structure for the transport to
/// carry; this test asserts about delivery, not about validity (the node layer owns that).
fn chained_blocks(kp: &KeyPair, count: u64) -> Vec<Block> {
    let mut prev = helix_crypto::Hash::ZERO;
    (1..=count)
        .map(|height| {
            let mut block = genesis_block(
                Address::from_public_key(&kp.public),
                kp.public.clone(),
                Signature::from_bytes(vec![]),
                0,
            );
            block.header.height = height;
            block.header.prev_hash = prev;
            block.header.signature = kp.sign(block.header.signing_hash().as_bytes()).unwrap();
            prev = block.hash();
            block
        })
        .collect()
}

/// A syntactically complete precommit. Deliberately not a *valid* one: this test is about whether
/// the wire carries the batch at all, and the service layer only distinguishes empty from non-empty.
/// Whether a certificate actually proves a quorum is checked in the node layer, which has the
/// validator set — and is covered there by its own tests.
fn stand_in_certificate(kp: &KeyPair) -> Vec<Vote> {
    vec![Vote {
        vote_type: helix_consensus::VoteType::Precommit,
        height: 5,
        round: 0,
        block_hash: helix_crypto::Hash::ZERO,
        validator: Address::from_public_key(&kp.public),
        public_key: kp.public.clone(),
        crypto_version: kp.scheme,
        signature: Signature::from_bytes(vec![]),
    }]
}

/// Serves a fixed set of blocks, with a non-empty stand-in certificate so the receiving *service*
/// forwards the batch. Certificate contents are the node layer's business.
struct FixedBlocks {
    blocks: Vec<Block>,
    certificate: Vec<Vote>,
}

impl BlockProvider for FixedBlocks {
    fn blocks<'a>(
        &'a self,
        from_height: u64,
        count: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = BlockSyncResponse> + Send + 'a>> {
        Box::pin(async move {
            let served: Vec<Block> = self
                .blocks
                .iter()
                .filter(|b| b.height() >= from_height)
                .take(count as usize)
                .cloned()
                .collect();
            if served.is_empty() {
                return BlockSyncResponse::empty();
            }
            BlockSyncResponse { blocks: served, tip_certificate: self.certificate.clone() }
        })
    }
}

/// Never serves anything — the node that is behind has nothing to give.
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

fn config(port: u16, seed: Option<u16>) -> P2PConfig {
    config_multi(port, seed.map(|p| vec![p]).unwrap_or_default())
}

fn config_multi(port: u16, seeds: Vec<u16>) -> P2PConfig {
    P2PConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        seed_peers: seeds
            .into_iter()
            .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
            .collect(),
        // Two independent Helix networks must never cross-wire through the LAN, and a test running
        // beside a live node would do exactly that.
        enable_mdns: false,
        ..P2PConfig::default()
    }
}

/// A node behind its peer asks for the blocks it is missing and receives them — over a real
/// connection, with no RPC endpoint involved anywhere.
///
/// This is the capability whose absence stalled production for 14.5 hours on 2026-07-29: a
/// validator one block short of the rest of the set, with no way to obtain that block and therefore
/// no way for the chain to move past it.
#[tokio::test]
async fn a_node_that_is_behind_receives_the_missing_blocks_over_p2p() {
    let kp = KeyPair::generate();
    let blocks = chained_blocks(&kp, 5);

    // The peer that is ahead: tip 5, holds all five blocks.
    let ahead_tip = Arc::new(AtomicU64::new(5));
    let (ahead, _ahead_cmd, mut ahead_events) = P2PService::new(
        config(19_646, None),
        ahead_tip,
        Arc::new(FixedBlocks {
            blocks: blocks.clone(),
            // One non-empty vote: the service only checks emptiness, the node layer verifies.
            certificate: stand_in_certificate(&kp),
        }),
    );
    tokio::spawn(async move { ahead.run().await });
    // Drain, so a full event channel never stalls the service under test.
    tokio::spawn(async move { while ahead_events.recv().await.is_some() {} });

    // The node that is behind: tip 0, dials the peer above.
    let behind_tip = Arc::new(AtomicU64::new(0));
    let (behind, _behind_cmd, mut behind_events) =
        P2PService::new(config(19_647, Some(19_646)), behind_tip, Arc::new(NoBlocks));
    tokio::spawn(async move { behind.run().await });

    // Generous: the peers must connect, exchange a peer-exchange announcement carrying the tip
    // height, and then complete one request/response round trip on the 2s driver tick.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut received: Option<BlockSyncResponse> = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), behind_events.recv()).await {
            Ok(Some(P2PEvent::BlocksSynced(batch, _peer))) => {
                received = Some(batch);
                break;
            }
            Ok(Some(_)) => continue, // PeerConnected and friends
            Ok(None) => break,       // service gone
            Err(_) => continue,      // tick again
        }
    }

    let batch = received.expect(
        "the node that is behind must receive a block-sync batch over P2P — no batch arrived, so \
         the request/response path did not complete",
    );
    assert_eq!(
        batch.blocks.iter().map(|b| b.height()).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5],
        "the whole missing range must arrive, in order"
    );
    assert!(!batch.tip_certificate.is_empty(), "the batch must carry its tip certificate");
}

/// The negative control that stops the test above from being a coincidence: two nodes at the same
/// height exchange announcements over the same real connection and must never trigger a batch. If
/// this also produced one, the mechanism would be firing on something other than being behind — and
/// every node in a healthy network would poll its peers forever.
#[tokio::test]
async fn two_nodes_at_the_same_height_never_exchange_blocks() {
    let kp = KeyPair::generate();
    let blocks = chained_blocks(&kp, 5);

    let a_tip = Arc::new(AtomicU64::new(5));
    let (a, _a_cmd, mut a_events) = P2PService::new(
        config(19_648, None),
        a_tip,
        Arc::new(FixedBlocks { blocks: blocks.clone(), certificate: stand_in_certificate(&kp) }),
    );
    tokio::spawn(async move { a.run().await });
    tokio::spawn(async move { while a_events.recv().await.is_some() {} });

    // Same tip as A, so neither is behind.
    let b_tip = Arc::new(AtomicU64::new(5));
    let (b, _b_cmd, mut b_events) = P2PService::new(
        config(19_649, Some(19_648)),
        b_tip,
        Arc::new(FixedBlocks { blocks, certificate: stand_in_certificate(&kp) }),
    );
    tokio::spawn(async move { b.run().await });

    // Long enough to cover several driver ticks and at least one peer-exchange announcement.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut connected = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), b_events.recv()).await {
            Ok(Some(P2PEvent::BlocksSynced(..))) => {
                panic!("two nodes at the same height must not exchange blocks");
            }
            Ok(Some(P2PEvent::PeerConnected(_))) => {
                connected = true;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    // Without this the test could "pass" simply because the two never met, proving nothing.
    assert!(
        connected,
        "the two nodes must actually have connected, or the absence of a batch means nothing"
    );
}

/// Backlog #140, and the positive control that entry asked for: a peer claiming the highest tip and
/// serving nothing must not be able to hold catch-up hostage.
///
/// Peer selection is by highest claimed tip and nothing else, and the answer costs the liar
/// nothing — an empty response is cheap and, before the cooldown, indistinguishable to the service
/// from "there was simply nothing new". So the node asked the same useless peer on every driver
/// tick, forever, while a healthy peer one block lower was never asked once. Not a security hole
/// (nothing unverified is ever adopted) but a liveness hole in exactly the scenario directed block
/// sync was built for: a node that cannot reach an RPC endpoint and needs its peers.
///
/// **The ordering here is the whole test, not incidental setup.** Connecting to both peers at once
/// is a race: if the healthy peer's tip announcement happens to land first, the liar is never asked
/// and the run passes without exercising anything — measured, this test passed with the fix removed
/// when the two were started together. So the liar goes first and gets several driver ticks alone,
/// and only then does the healthy peer appear. Without the cooldown the liar's tip of 999 beats the
/// honest 5 on every tick from then on, forever.
///
/// Deliberately over the real wire rather than against `best_blocksync_peer`: the unit tests can
/// only show that a peer *on* cooldown is skipped. Whether anything ever puts it there — an empty
/// response arriving as a perfectly successful round trip — is a property of the running service.
#[tokio::test]
async fn a_peer_that_claims_the_highest_tip_and_serves_nothing_cannot_stall_catch_up() {
    let kp = KeyPair::generate();
    let blocks = chained_blocks(&kp, 5);

    // The liar: announces a tip far above everyone and answers every request with nothing.
    let liar_tip = Arc::new(AtomicU64::new(999));
    let (liar, _liar_cmd, mut liar_events) =
        P2PService::new(config(19_651, None), liar_tip, Arc::new(NoBlocks));
    tokio::spawn(async move { liar.run().await });
    tokio::spawn(async move { while liar_events.recv().await.is_some() {} });

    // The node that is behind, initially knowing only the liar.
    let behind_tip = Arc::new(AtomicU64::new(0));
    let (behind, behind_cmd, mut behind_events) =
        P2PService::new(config(19_652, Some(19_651)), behind_tip, Arc::new(NoBlocks));
    tokio::spawn(async move { behind.run().await });

    // Let it connect, learn the liar's tip, and burn several 2s driver ticks against it — so the
    // liar is established as the highest claim well before any honest peer exists.
    let settle = tokio::time::Instant::now() + Duration::from_secs(40);
    while tokio::time::Instant::now() < settle {
        match tokio::time::timeout(Duration::from_secs(2), behind_events.recv()).await {
            Ok(Some(P2PEvent::BlocksSynced(..))) => {
                panic!("the liar serves nothing — no batch can legitimately arrive yet")
            }
            Ok(None) => break,
            _ => continue,
        }
    }

    // Now the honest peer appears, claiming a *lower* tip than the liar.
    let healthy_tip = Arc::new(AtomicU64::new(5));
    let (healthy, _healthy_cmd, mut healthy_events) = P2PService::new(
        config(19_650, None),
        healthy_tip,
        Arc::new(FixedBlocks { blocks, certificate: stand_in_certificate(&kp) }),
    );
    tokio::spawn(async move { healthy.run().await });
    tokio::spawn(async move { while healthy_events.recv().await.is_some() {} });
    behind_cmd
        .send(helix_p2p::P2PCommand::ConnectPeer(
            "/ip4/127.0.0.1/tcp/19650".parse().unwrap(),
        ))
        .await
        .expect("the behind node's command channel must be alive");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut received: Option<BlockSyncResponse> = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), behind_events.recv()).await {
            Ok(Some(P2PEvent::BlocksSynced(batch, _))) => {
                received = Some(batch);
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    let batch = received.expect(
        "catch-up must complete through the honest peer even though a peer claiming a higher tip \
         keeps answering with nothing — before #140 this waited forever",
    );
    assert_eq!(
        batch.blocks.iter().map(|b| b.height()).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5],
        "and it must be the real range, from the peer that actually had it",
    );
}

/// Backlog #147: a peer holding more than one connection is still *one* peer, and closing one of
/// them must not tear down the state the others still depend on.
///
/// This is the production outage of 2026-08-04/05 in miniature. `max_established_per_peer` is 4, so
/// several connections to the same peer are routine — both sides dialing, or a redial racing the
/// existing link. The service announced every one of them and, on `ConnectionClosed`, forgot the
/// peer wholesale: `peer_tips` lost its entry. That map is the block-sync driver's *only* notion of
/// who is ahead, so the node then never asked anyone for blocks again. A freshly started validator
/// sat on height 1 for 21 hours with the entire catch-up path intact and never once triggered,
/// while `peer_count` — which gates block production — counted connections instead of peers.
///
/// Deliberately over the real wire: whether a second dial to an already-connected peer produces a
/// second connection at all is a property of libp2p, not of our code, and it is the premise the
/// whole bug rests on.
#[tokio::test]
async fn a_second_connection_to_the_same_peer_is_not_a_second_peer() {
    let kp = KeyPair::generate();
    let blocks = chained_blocks(&kp, 5);

    let ahead_tip = Arc::new(AtomicU64::new(5));
    let (ahead, _ahead_cmd, mut ahead_events) = P2PService::new(
        config(19_660, None),
        ahead_tip,
        Arc::new(FixedBlocks { blocks, certificate: stand_in_certificate(&kp) }),
    );
    tokio::spawn(async move { ahead.run().await });
    tokio::spawn(async move { while ahead_events.recv().await.is_some() {} });

    let behind_tip = Arc::new(AtomicU64::new(0));
    let (behind, behind_cmd, mut behind_events) =
        P2PService::new(config(19_661, Some(19_660)), behind_tip, Arc::new(NoBlocks));
    tokio::spawn(async move { behind.run().await });

    let mut connects = 0usize;
    let mut disconnects = 0usize;
    let mut batch_arrived = false;
    let mut dialed_again = false;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), behind_events.recv()).await {
            Ok(Some(P2PEvent::PeerConnected(_))) => {
                connects += 1;
                // Dial the peer we are already connected to. `swarm.dial` on a bare multiaddr is
                // unconditional, so this genuinely opens a second connection rather than being
                // deduplicated away — that is what makes this deterministic instead of waiting for
                // a race to happen on its own. Once only: this is about the second connection, not
                // about how many we can stack up.
                if !dialed_again {
                    dialed_again = true;
                    let _ = behind_cmd
                        .send(P2PCommand::ConnectPeer(
                            "/ip4/127.0.0.1/tcp/19660".parse().unwrap(),
                        ))
                        .await;
                }
            }
            Ok(Some(P2PEvent::PeerDisconnected(_))) => disconnects += 1,
            Ok(Some(P2PEvent::BlocksSynced(..))) => batch_arrived = true,
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    assert!(dialed_again, "the peers must have connected at all, or this test proves nothing");
    assert_eq!(
        connects, 1,
        "one peer must be announced once, however many connections it holds — counting connections \
         is what let `peer_count` (which gates block production) drift away from reality",
    );
    assert_eq!(
        disconnects, 0,
        "the peer never went away, so no disconnect may be reported — this is the event that used \
         to wipe `peer_tips` and leave catch-up permanently unable to find anyone to ask",
    );
    assert!(
        batch_arrived,
        "and catch-up must still complete across the extra connection — the accounting fix is only \
         worth anything if block sync survives it",
    );
}

/// The control that keeps the test above from being a tautology (lesson 3): after teaching the
/// service to ignore *some* closures, a real departure must still be reported. A fix that simply
/// swallowed every disconnect would pass the assertions above and leave the node believing forever
/// in peers that are long gone.
#[tokio::test]
async fn a_peer_that_really_leaves_is_still_reported_as_gone() {
    let kp = KeyPair::generate();
    let blocks = chained_blocks(&kp, 5);

    let ahead_tip = Arc::new(AtomicU64::new(5));
    let (ahead, _ahead_cmd, mut ahead_events) = P2PService::new(
        config(19_662, None),
        ahead_tip,
        Arc::new(FixedBlocks { blocks, certificate: stand_in_certificate(&kp) }),
    );
    let ahead_task = tokio::spawn(async move { ahead.run().await });
    tokio::spawn(async move { while ahead_events.recv().await.is_some() {} });

    let behind_tip = Arc::new(AtomicU64::new(0));
    let (behind, _behind_cmd, mut behind_events) =
        P2PService::new(config(19_663, Some(19_662)), behind_tip, Arc::new(NoBlocks));
    tokio::spawn(async move { behind.run().await });

    // Wait until they are actually connected before killing anything.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut connected = false;
    while tokio::time::Instant::now() < deadline && !connected {
        if let Ok(Some(P2PEvent::PeerConnected(_))) =
            tokio::time::timeout(Duration::from_secs(2), behind_events.recv()).await
        {
            connected = true;
        }
    }
    assert!(connected, "the peers must connect first, or the departure below proves nothing");

    // Dropping the service takes its swarm — and every connection — down with it.
    ahead_task.abort();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut disconnects = 0usize;
    while tokio::time::Instant::now() < deadline && disconnects == 0 {
        if let Ok(Some(P2PEvent::PeerDisconnected(_))) =
            tokio::time::timeout(Duration::from_secs(2), behind_events.recv()).await
        {
            disconnects += 1;
        }
    }

    assert_eq!(
        disconnects, 1,
        "a peer whose last connection closed must be reported gone exactly once — otherwise the \
         node keeps counting a peer that no longer exists toward quorum",
    );
}


/// Backlog #154: the highest tip peers claim must be published, and must fall again when the peer
/// that claimed it leaves.
///
/// Over the wire because this is a wiring property, not a logic one: the pure function is covered
/// by unit tests and stays green whether or not anything ever calls it. What can actually break —
/// and would be invisible — is the update on peer *departure*. A claim that outlived its peer would
/// hold a caught-up node out of block production indefinitely, which is exactly the failure #152's
/// hold is only acceptable because it can be released from.
#[tokio::test]
async fn the_highest_peer_claim_is_published_and_retracted_with_its_peer() {
    let kp = KeyPair::generate();
    let blocks = chained_blocks(&kp, 5);

    let ahead_tip = Arc::new(AtomicU64::new(5));
    let (ahead, _ahead_cmd, mut ahead_events) = P2PService::new(
        config(19_670, None),
        ahead_tip,
        Arc::new(FixedBlocks { blocks, certificate: stand_in_certificate(&kp) }),
    );
    let ahead_task = tokio::spawn(async move { ahead.run().await });
    tokio::spawn(async move { while ahead_events.recv().await.is_some() {} });

    let claimed = Arc::new(AtomicU64::new(0));
    let (behind, _behind_cmd, mut behind_events) =
        P2PService::new(config(19_671, Some(19_670)), Arc::new(AtomicU64::new(0)), Arc::new(NoBlocks));
    let behind = behind.with_peer_tip_reporting(claimed.clone());
    tokio::spawn(async move { behind.run().await });
    tokio::spawn(async move { while behind_events.recv().await.is_some() {} });

    // The peer announces its tip on the peer-exchange interval.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline
        && claimed.load(std::sync::atomic::Ordering::Relaxed) == 0
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        claimed.load(std::sync::atomic::Ordering::Relaxed),
        5,
        "the peer's announced tip must be published"
    );

    // It leaves; its claim must go with it, or a caught-up node stays held forever.
    ahead_task.abort();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline
        && claimed.load(std::sync::atomic::Ordering::Relaxed) != 0
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        claimed.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a departed peer's claim must not linger — it would hold production indefinitely"
    );
}

/// Answers a request for more than `limit` blocks only after the asker has given up waiting, and a
/// smaller one at once — the shape of a link that carries a short answer in time and a full batch
/// not at all. Records every count it was asked for.
struct SlowForLargeBatches {
    blocks: Vec<Block>,
    certificate: Vec<Vote>,
    limit: u32,
    asked: std::sync::Mutex<Vec<u32>>,
}

impl BlockProvider for SlowForLargeBatches {
    fn blocks<'a>(
        &'a self,
        from_height: u64,
        count: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = BlockSyncResponse> + Send + 'a>> {
        Box::pin(async move {
            self.asked.lock().unwrap().push(count);
            if count > self.limit {
                // Past the 30 s request timeout: the asker has stopped waiting by now.
                tokio::time::sleep(Duration::from_secs(32)).await;
            }
            let served: Vec<Block> = self
                .blocks
                .iter()
                .filter(|b| b.height() >= from_height)
                .take(count as usize)
                .cloned()
                .collect();
            BlockSyncResponse { blocks: served, tip_certificate: self.certificate.clone() }
        })
    }
}

/// A node whose full-size requests never arrive in time asks for fewer blocks, and catches up.
///
/// On 2026-10-13 a validator on a home line, three hours behind, asked its peers for 100 blocks 147
/// times in a row. Every answer was ~4.6 MB on a connection already carrying the peer's gossip, and
/// every one timed out — so the next request was for 100 blocks again, and the node never moved.
/// Here the peer answers 50 blocks at once and 100 only after the timeout: the first request must be
/// a full batch (otherwise the test proves nothing about shrinking), and a batch must still arrive.
#[tokio::test]
async fn a_node_whose_full_batches_time_out_asks_for_fewer_and_catches_up() {
    let kp = KeyPair::generate();
    let blocks = chained_blocks(&kp, 200);
    let provider = Arc::new(SlowForLargeBatches {
        blocks,
        certificate: stand_in_certificate(&kp),
        limit: 50,
        asked: std::sync::Mutex::new(Vec::new()),
    });

    let ahead_tip = Arc::new(AtomicU64::new(200));
    let (ahead, _ahead_cmd, mut ahead_events) =
        P2PService::new(config(19_801, None), ahead_tip, provider.clone());
    tokio::spawn(async move { ahead.run().await });
    tokio::spawn(async move { while ahead_events.recv().await.is_some() {} });

    let behind_tip = Arc::new(AtomicU64::new(0));
    let (behind, _behind_cmd, mut behind_events) =
        P2PService::new(config(19_802, Some(19_801)), behind_tip, Arc::new(NoBlocks));
    tokio::spawn(async move { behind.run().await });

    // One timeout (30 s), one cooldown (10 s), one prompt answer — plus connecting.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(100);
    let mut received: Option<BlockSyncResponse> = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), behind_events.recv()).await {
            Ok(Some(P2PEvent::BlocksSynced(batch, _peer))) => {
                received = Some(batch);
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    let asked = provider.asked.lock().unwrap().clone();
    assert_eq!(
        asked.first().copied(),
        Some(helix_p2p::MAX_BLOCKSYNC_BATCH),
        "the first request must be a full batch, or this test proves nothing about shrinking: {asked:?}"
    );
    let batch = received.unwrap_or_else(|| {
        panic!(
            "no batch arrived in 100 s — the node kept asking for what the link cannot carry in \
             time. Requests seen by the peer: {asked:?}"
        )
    });
    assert!(
        !batch.blocks.is_empty() && batch.blocks.len() <= 50,
        "the batch that arrived must be one the link could carry: {} blocks, requests {asked:?}",
        batch.blocks.len()
    );
    assert_eq!(batch.blocks[0].height(), 1, "and it starts where the node is: {asked:?}");
}

/// A prevote that decodes — the service forwards it as `NewVote`; whether it is valid is the node
/// layer's business. A fresh round every call, so gossipsub does not drop it as a duplicate.
fn a_prevote(kp: &KeyPair, round: u32) -> Vote {
    Vote {
        vote_type: helix_consensus::VoteType::Prevote,
        height: 7,
        round,
        block_hash: helix_crypto::Hash::ZERO,
        validator: Address::from_public_key(&kp.public),
        public_key: kp.public.clone(),
        crypto_version: kp.scheme,
        signature: Signature::from_bytes(vec![1; 32]),
    }
}

/// A node far behind that is catching up stops hearing consensus gossip, and hears it again near
/// the tip — over a real connection, measured by whether the peer's votes still arrive.
///
/// The home validator of 2026-10-13 had its whole download (~3 MB/s) filled with gossip it could
/// not use, from every peer, while the block-sync answers it needed came in at ~50 kB/s. The three
/// phases here are the rule's three states: listening at first (no rise seen yet — the control that
/// the votes arrive at all), deaf while far behind and rising, listening again once close.
#[tokio::test]
async fn a_node_far_behind_and_catching_up_stops_hearing_votes_and_hears_them_again_near_the_tip() {
    let kp = KeyPair::generate();
    let ahead_tip = Arc::new(AtomicU64::new(5_000));
    let (ahead, ahead_cmd, mut ahead_events) = P2PService::new(
        config(19_803, None),
        ahead_tip,
        Arc::new(FixedBlocks {
            blocks: chained_blocks(&kp, 3),
            certificate: stand_in_certificate(&kp),
        }),
    );
    tokio::spawn(async move { ahead.run().await });
    tokio::spawn(async move { while ahead_events.recv().await.is_some() {} });

    let behind_tip = Arc::new(AtomicU64::new(0));
    let (behind, _behind_cmd, mut behind_events) =
        P2PService::new(config(19_804, Some(19_803)), behind_tip.clone(), Arc::new(NoBlocks));
    tokio::spawn(async move { behind.run().await });

    let mut round = 0u32;
    // Sends a fresh vote from the peer that is ahead and reports whether one arrived within `wait`.
    // Every other event is drained; a disconnect fails the test, since "no votes" must mean deaf,
    // not gone.
    macro_rules! a_vote_arrives_within {
        ($wait:expr) => {{
            let deadline = tokio::time::Instant::now() + $wait;
            let mut arrived = false;
            let mut next_send = tokio::time::Instant::now();
            while tokio::time::Instant::now() < deadline && !arrived {
                if tokio::time::Instant::now() >= next_send {
                    round += 1;
                    ahead_cmd
                        .send(P2PCommand::BroadcastVote(a_prevote(&kp, round)))
                        .await
                        .unwrap();
                    next_send = tokio::time::Instant::now() + Duration::from_secs(1);
                }
                match tokio::time::timeout(Duration::from_millis(200), behind_events.recv()).await {
                    Ok(Some(P2PEvent::NewVote(_))) => arrived = true,
                    Ok(Some(P2PEvent::PeerDisconnected(p))) => {
                        panic!("the peer disconnected ({p}) — silence would prove nothing")
                    }
                    Ok(Some(_)) | Err(_) => {}
                    Ok(None) => panic!("the service under test stopped"),
                }
            }
            arrived
        }};
    }

    // Phase 1, the control: connected and listening — votes arrive. No rise seen yet, so the gap of
    // 5000 alone must not make the node deaf.
    assert!(
        a_vote_arrives_within!(Duration::from_secs(60)),
        "the peer's votes never arrived — the connection or the subscription is broken, and the \
         rest of this test would prove nothing"
    );

    // Phase 2: catching up — the tip rises while the peer still claims to be far ahead. Peer
    // exchange brings that claim within 30 s; give it the time, then the votes must stop.
    let climbing = behind_tip.clone();
    let climber = tokio::spawn(async move {
        loop {
            climbing.fetch_add(10, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let deaf_by = tokio::time::Instant::now() + Duration::from_secs(70);
    let mut went_deaf = false;
    while tokio::time::Instant::now() < deaf_by {
        // Ten seconds of fresh votes, none heard: deaf (subscriptions take a moment to reach the
        // peer, so one quiet second would not be enough).
        if !a_vote_arrives_within!(Duration::from_secs(10)) {
            went_deaf = true;
            break;
        }
    }
    assert!(
        went_deaf,
        "far behind and catching up, the node kept receiving the peer's votes — it did not stop \
         listening (tip now {})",
        behind_tip.load(std::sync::atomic::Ordering::Relaxed)
    );

    // Phase 3: close to the tip — listening again.
    climber.abort();
    behind_tip.store(4_960, std::sync::atomic::Ordering::Relaxed);
    assert!(
        a_vote_arrives_within!(Duration::from_secs(30)),
        "close to the tip, the node did not start listening again"
    );
}

/// A follower hears neither votes nor gossiped committed blocks — over a real connection — and
/// hears votes again once it is told it is in the validator set.
///
/// On 2026-10-13 a home node back at the tip received ~2.5 MB/s per connection-sum of gossip it
/// could not keep up with; measured, most of it was committed blocks arriving in several copies
/// from every peer, and the votes after them. A follower follows by block sync instead, where each
/// block arrives once. (The fallback to gossip when block sync stalls is the rule's own test; here
/// the peer claims no tip above ours, so it must not engage.)
#[tokio::test]
async fn a_follower_hears_neither_votes_nor_gossiped_blocks_and_votes_again_once_it_validates() {
    let kp = KeyPair::generate();
    let (sender, sender_cmd, mut sender_events) =
        P2PService::new(config(19_805, None), Arc::new(AtomicU64::new(0)), Arc::new(NoBlocks));
    tokio::spawn(async move { sender.run().await });
    tokio::spawn(async move { while sender_events.recv().await.is_some() {} });
    let (follower, follower_cmd, mut follower_events) = P2PService::new(
        config(19_806, Some(19_805)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(NoBlocks),
    );
    tokio::spawn(async move { follower.run().await });

    let blocks = chained_blocks(&kp, 40);
    let mut next_block = 0usize;
    let mut round = 0u32;
    // For `window`, send a fresh vote and a fresh committed block every second, and count what the
    // follower receives of each. A disconnect fails the test: silence must mean "not subscribed".
    macro_rules! received_within {
        ($window:expr) => {{
            let deadline = tokio::time::Instant::now() + $window;
            let (mut votes, mut committed) = (0u32, 0u32);
            let mut next_send = tokio::time::Instant::now();
            while tokio::time::Instant::now() < deadline {
                if tokio::time::Instant::now() >= next_send {
                    round += 1;
                    sender_cmd.send(P2PCommand::BroadcastVote(a_prevote(&kp, round))).await.unwrap();
                    let block = blocks[next_block % blocks.len()].clone();
                    next_block += 1;
                    sender_cmd
                        .send(P2PCommand::BroadcastBlock(block, stand_in_certificate(&kp)))
                        .await
                        .unwrap();
                    next_send = tokio::time::Instant::now() + Duration::from_secs(1);
                }
                match tokio::time::timeout(Duration::from_millis(200), follower_events.recv()).await {
                    Ok(Some(P2PEvent::NewVote(_))) => votes += 1,
                    Ok(Some(P2PEvent::NewCommittedBlock(..))) => committed += 1,
                    Ok(Some(P2PEvent::PeerDisconnected(p))) => {
                        panic!("the peer disconnected ({p}) — silence would prove nothing")
                    }
                    Ok(Some(_)) | Err(_) => {}
                    Ok(None) => panic!("the service under test stopped"),
                }
            }
            (votes, committed)
        }};
    }

    // Control: connected, subscribed to everything — wait until votes arrive at all.
    let connect_by = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut heard = false;
    while tokio::time::Instant::now() < connect_by && !heard {
        heard = received_within!(Duration::from_secs(2)).0 > 0;
    }
    assert!(heard, "the votes never arrived — the connection is broken and this test proves nothing");

    // The control for the committed half: before following only, committed blocks arrive too.
    let (_, committed_before) = received_within!(Duration::from_secs(5));
    assert!(
        committed_before >= 2,
        "committed blocks must arrive while subscribed, or their absence below proves nothing: \
         {committed_before} in 5 s"
    );

    // Following only: after the unsubscribe has had time to reach the peer, no vote and no
    // gossiped committed block.
    follower_cmd.send(P2PCommand::FollowOnly(true)).await.unwrap();
    let _ = received_within!(Duration::from_secs(4));
    let (votes, committed) = received_within!(Duration::from_secs(10));
    assert_eq!(votes, 0, "a follower must not be sent the validators' votes");
    assert_eq!(committed, 0, "nor gossiped committed blocks — it follows by block sync");

    // In the validator set again: votes arrive.
    follower_cmd.send(P2PCommand::FollowOnly(false)).await.unwrap();
    let mut back = false;
    let back_by = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < back_by && !back {
        back = received_within!(Duration::from_secs(2)).0 > 0;
    }
    assert!(back, "told it validates again, the node did not hear votes again");
}
