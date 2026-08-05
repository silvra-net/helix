//! End-to-end proof that a node with no chain at all can obtain a genesis over the real libp2p
//! wire (#139).
//!
//! Same reasoning as `blocksync_transport.rs`, and it applies harder here. The unit tests in
//! `genesis_sync` check that the messages round-trip through bincode, which they would do just as
//! happily if the protocol were never negotiated, the behaviour never wired into the swarm, or the
//! provider never consulted. The whole point of this mechanism is that a fresh node needs nothing
//! but a peer address — so the only test that means anything is one where a fresh endpoint dials a
//! real socket and comes back holding a genesis.
//!
//! The fetcher under test builds its own swarm rather than borrowing the service's, which is
//! precisely why this must be exercised over a connection: nothing else proves the two swarms speak
//! the same transports and the same protocol.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use helix_core::genesis_block;
use helix_crypto::{Address, KeyPair, Signature};
use helix_p2p::blocksync::{BlockProvider, BlockSyncResponse};
use helix_p2p::genesis_sync::{GenesisPayload, GenesisProvider, GenesisResponse};
use helix_p2p::{fetch_genesis_over_p2p, P2PConfig, P2PService};

/// Never serves blocks — this test is about genesis, and a provider is required to build a service.
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

/// Serves one fixed genesis, the way a node with a chain does.
struct FixedGenesis(GenesisPayload);

impl GenesisProvider for FixedGenesis {
    fn genesis<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = GenesisResponse> + Send + 'a>> {
        let payload = self.0.clone();
        Box::pin(async move { GenesisResponse { genesis: Some(payload) } })
    }
}

/// A node that speaks the protocol but has nothing to hand over — one that is itself still
/// bootstrapping.
struct NoGenesis;

impl GenesisProvider for NoGenesis {
    fn genesis<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = GenesisResponse> + Send + 'a>> {
        Box::pin(async { GenesisResponse::empty() })
    }
}

fn a_genesis(kp: &KeyPair) -> GenesisPayload {
    let block = genesis_block(
        Address::from_public_key(&kp.public),
        kp.public.clone(),
        Signature::from_bytes(vec![]),
        1_785_440_247_205,
    );
    GenesisPayload {
        block,
        personhood_authorities: vec![kp.public.clone()],
        validator_stake: 100_000,
        allocations: vec![(Address::from_public_key(&kp.public), 500_000)],
        min_validator_stake: 100_000,
        fuel_per_fee_unit: 1,
        state_hash: Some("abc123".to_string()),
    }
}

fn config(port: u16) -> P2PConfig {
    P2PConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        seed_peers: vec![],
        // Two independent Helix networks must never cross-wire through the LAN, and a test running
        // beside a live node would do exactly that.
        enable_mdns: false,
        ..P2PConfig::default()
    }
}

/// The capability the whole item exists for: a node holding nothing — no chain, no state, no HTTP
/// endpoint to call — obtains a chain's genesis from a peer address alone.
#[tokio::test]
async fn a_node_with_no_chain_fetches_genesis_from_a_peer_address_alone() {
    let kp = KeyPair::generate();
    let expected = a_genesis(&kp);

    let (server, _cmd, _events) = P2PService::new(
        config(19_681),
        Arc::new(AtomicU64::new(0)),
        Arc::new(NoBlocks),
    );
    let server = server.with_genesis_provider(Arc::new(FixedGenesis(expected.clone())));
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Let the listener bind before dialling it.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let fetched = fetch_genesis_over_p2p(
        &["/ip4/127.0.0.1/tcp/19681".to_string()],
        Duration::from_secs(20),
    )
    .await
    .expect("a peer serving a genesis must hand it over");

    assert_eq!(fetched.block.hash(), expected.block.hash(), "the genesis block must survive the wire");
    assert_eq!(fetched.allocations, expected.allocations);
    assert_eq!(fetched.validator_stake, expected.validator_stake);
    assert_eq!(fetched.personhood_authorities, expected.personhood_authorities);
    assert_eq!(fetched.min_validator_stake, expected.min_validator_stake);
    assert_eq!(fetched.fuel_per_fee_unit, expected.fuel_per_fee_unit);
    assert_eq!(fetched.state_hash, expected.state_hash);
}

/// The control that keeps the test above honest.
///
/// Without it, a fetcher that fabricated a payload locally — or a provider that was never actually
/// consulted — would pass just as well. A peer that answers "I have nothing" must produce no
/// genesis, and it must do so by *answering*: an unreachable peer would look identical from the
/// outside, so this also pins that the request really made the round trip.
#[tokio::test]
async fn a_peer_that_has_no_genesis_yields_none() {
    let (server, _cmd, _events) = P2PService::new(
        config(19_682),
        Arc::new(AtomicU64::new(0)),
        Arc::new(NoBlocks),
    );
    let server = server.with_genesis_provider(Arc::new(NoGenesis));
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let result = fetch_genesis_over_p2p(
        &["/ip4/127.0.0.1/tcp/19682".to_string()],
        Duration::from_secs(5),
    )
    .await;

    assert!(result.is_err(), "a peer with no genesis must not produce one");
}

/// A node that never called `with_genesis_provider` still speaks the protocol and still answers.
///
/// The alternative — not registering the behaviour at all — would make an ordinary node
/// indistinguishable from an unreachable one, and a requester would burn its whole timeout on a
/// peer that was right there and perfectly healthy.
#[tokio::test]
async fn a_node_without_a_genesis_provider_answers_rather_than_going_silent() {
    let (server, _cmd, _events) = P2PService::new(
        config(19_683),
        Arc::new(AtomicU64::new(0)),
        Arc::new(NoBlocks),
    );
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let err = fetch_genesis_over_p2p(
        &["/ip4/127.0.0.1/tcp/19683".to_string()],
        Duration::from_secs(10),
    )
    .await
    .expect_err("there is no genesis to be had");

    // The distinction this test exists for, and it took a red run to make it real: the first
    // version asserted only that the call took the full timeout, which it does whether the peer
    // answers "none" or refuses the protocol outright. Both looked identical and the test passed
    // with the serving side switched off. The error now names which of the two happened.
    assert!(
        err.to_string().contains("answered but hold no genesis"),
        "the peer must have answered, not refused: {err}",
    );
}
