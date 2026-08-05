//! Fetching a chain's genesis from a peer over libp2p, before this node has a chain (#139).
//!
//! Runs its own short-lived swarm rather than going through [`crate::service::P2PService`], and
//! that is a deliberate choice rather than a shortcut. The service is constructed with the node's
//! store and event channels and starts as part of the node's own startup; asking it for a genesis
//! would mean bringing the whole node up *before* deciding which chain it is on, and reordering
//! that startup is how several of the worse bugs in this repo happened. A one-shot dial that
//! returns a payload and disappears cannot affect a running node at all.
//!
//! The swarm itself comes from the same [`crate::service::build_swarm`] the long-lived service
//! uses, so the two cannot end up speaking different transports — which they would have to for
//! this to fail in the confusing way.

use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use tracing::{debug, info, warn};

use crate::config::P2PConfig;
use crate::genesis_sync::GenesisPayload;
use crate::genesis_sync::GenesisRequest;
use crate::service::{build_swarm, HelixBehaviourEvent};
use crate::{P2PError, P2PResult};

/// How long the whole bootstrap may take, dialling included.
pub const GENESIS_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Ask `peers` for the chain's genesis and return the first usable answer.
///
/// Every address is dialled at once rather than in order. A seed list exists precisely because any
/// one of its entries may be down, and trying them one at a time would multiply one unreachable
/// peer into the whole timeout budget before the reachable one is ever contacted.
///
/// **The result is untrusted.** It arrives from whichever peer answered first, and this function
/// checks only that it parses. Every caller must put it through the configured genesis-hash
/// checkpoint before rebuilding or writing anything — that check is the only part of the join path
/// that does not originate with the peer being trusted, and it is what makes this transport safe to
/// use at all. See [`crate::genesis_sync`].
pub async fn fetch_genesis_over_p2p(
    peers: &[String],
    timeout: Duration,
) -> P2PResult<GenesisPayload> {
    if peers.is_empty() {
        return Err(P2PError::Transport(
            "no P2P peers configured to fetch genesis from".to_string(),
        ));
    }

    // Listening would be pointless — nobody knows this node exists yet — and mDNS would pull in
    // LAN peers that have nothing to do with the chain the operator named.
    let config = P2PConfig {
        enable_mdns: false,
        ..P2PConfig::default()
    };
    let mut swarm = build_swarm(&config).await?;

    let mut dialled = 0usize;
    for addr in peers {
        match addr.parse::<Multiaddr>() {
            Ok(ma) => match swarm.dial(ma) {
                Ok(()) => dialled += 1,
                Err(e) => warn!(peer = %addr, err = %e, "Could not dial peer for genesis"),
            },
            Err(e) => warn!(peer = %addr, err = %e, "Ignoring unparseable P2P peer address"),
        }
    }
    if dialled == 0 {
        return Err(P2PError::Transport(
            "none of the configured P2P peer addresses could be dialled".to_string(),
        ));
    }

    info!(peers = dialled, "Requesting genesis over P2P");

    // Whether any peer actually *answered*. Without this the two ways of coming back empty are
    // indistinguishable — a peer that replied "I have none" and a peer that refused the protocol
    // both end in the same silence until the deadline — and the caller cannot tell an out-of-date
    // seed from a network problem. The test that pins this was vacuous until it existed.
    let mut answered_without_genesis = 0usize;
    let mut request_failures = 0usize;

    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => {
                return Err(P2PError::Transport(if answered_without_genesis > 0 {
                    format!(
                        "{answered_without_genesis} peer(s) answered but hold no genesis to serve"
                    )
                } else if request_failures > 0 {
                    format!(
                        "{request_failures} peer(s) refused or failed the genesis request — \
                         they are most likely running a build without it"
                    )
                } else {
                    format!("no peer returned a genesis block within {timeout:?}")
                }));
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    debug!(peer = %peer_id, "Connected — asking for genesis");
                    swarm
                        .behaviour_mut()
                        .genesis_sync
                        .send_request(&peer_id, GenesisRequest);
                }
                SwarmEvent::Behaviour(HelixBehaviourEvent::GenesisSync(
                    libp2p::request_response::Event::Message {
                        peer,
                        message: libp2p::request_response::Message::Response { response, .. },
                        ..
                    },
                )) => match response.genesis {
                    Some(payload) => {
                        info!(peer = %peer, height = payload.block.height(), "Received genesis over P2P");
                        return Ok(payload);
                    }
                    // Not a failure of the peer: a node still bootstrapping answers honestly that
                    // it has nothing. Keep waiting for one that does, rather than giving up on the
                    // whole seed list because the first responder was itself new.
                    None => {
                        answered_without_genesis += 1;
                        debug!(peer = %peer, "Peer has no genesis to serve — waiting for another");
                    }
                },
                SwarmEvent::Behaviour(HelixBehaviourEvent::GenesisSync(
                    libp2p::request_response::Event::OutboundFailure { peer, error, .. },
                )) => {
                    request_failures += 1;
                    debug!(peer = %peer, err = %error, "Genesis request failed — waiting for another peer");
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    debug!(peer = ?peer_id, err = %error, "Could not connect while fetching genesis");
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_empty_peer_list_fails_immediately_rather_than_waiting() {
        let started = std::time::Instant::now();
        let err = fetch_genesis_over_p2p(&[], Duration::from_secs(30))
            .await
            .expect_err("no peers means no genesis");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "an empty list is knowable up front and must not burn the timeout",
        );
        assert!(err.to_string().contains("no P2P peers"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn addresses_that_cannot_be_parsed_are_reported_rather_than_dialled() {
        let err = fetch_genesis_over_p2p(&["not-a-multiaddr".to_string()], Duration::from_secs(30))
            .await
            .expect_err("nothing dialable");
        assert!(err.to_string().contains("could be dialled"), "unexpected error: {err}");
    }
}
