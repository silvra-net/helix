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
use helix_p2p::{P2PConfig, P2PEvent, P2PService};

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
    P2PConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        seed_peers: seed
            .map(|p| vec![format!("/ip4/127.0.0.1/tcp/{p}")])
            .unwrap_or_default(),
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
            Ok(Some(P2PEvent::BlocksSynced(batch))) => {
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
            Ok(Some(P2PEvent::BlocksSynced(_))) => {
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
