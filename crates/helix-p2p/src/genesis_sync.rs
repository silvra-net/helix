//! Serving and fetching the genesis block over libp2p (backlog #139).
//!
//! #138 gave a node that is *already on the chain* a way to recover from any lag without an
//! operator-configured RPC endpoint. It did not help a genuinely fresh one: adopting a genesis was
//! only ever possible through `GET /genesis` on a `sync_peer`, so joining still required somebody
//! to run a reachable HTTP server, and in practice that somebody was us. This module is the other
//! half — a peer address is enough.
//!
//! # Why the trust question is already answered
//!
//! A fresh node can check an offered genesis against nothing of its own: no state, no validator
//! set, no chain id. That is exactly why the RPC path was bound to a source the operator names
//! explicitly. Moving the same payload onto a gossip network would be strictly worse if nothing
//! else changed — which is why the anchor came first and separately: `HELIX_GENESIS_HASH` is
//! compared against a locally recomputed `Block::hash()` before anything is rebuilt or written
//! (the checkpoint model Bitcoin and Ethereum both use). With that in place the transport stops
//! mattering, and this module is only transport.
//!
//! The payload here carries a `state_hash` the peer claims, and it is worth being clear about what
//! that is not: it is self-certifying, both halves come from the same peer, and it can only catch
//! an *inconsistent* answer, never a coherently false one. The configured genesis hash is the only
//! check in the join path that does not originate with the peer being trusted.
//!
//! # Why its own protocol
//!
//! `/helix/genesis/1.0.0` sits next to `/helix/blocksync/1.0.0` rather than extending it. libp2p
//! negotiates protocols per stream, so a peer that speaks only blocksync is simply not asked —
//! no version bump, no shared message enum that both sides must agree to have grown, and the
//! existing sync path keeps working against every node already running.

use std::future::Future;
use std::pin::Pin;

use libp2p::futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use libp2p::swarm::StreamProtocol;
use serde::{Deserialize, Serialize};
use std::io;

use helix_core::Block;
use helix_crypto::{Address, PublicKey};

/// Wire protocol name. Bump the version on any incompatible change to the shapes below.
pub const GENESIS_PROTOCOL: StreamProtocol = StreamProtocol::new("/helix/genesis/1.0.0");

/// Hard ceiling on a decoded request. The request carries no fields at all; anything larger than
/// this is broken or hostile, and reading it to the end would be the amplification.
const REQUEST_SIZE_MAXIMUM: u64 = 256;

/// Hard ceiling on a decoded response. The genesis block itself is small; `allocations` is the only
/// field that grows, and at ~30 bytes per entry this still allows tens of thousands of them. A peer
/// cannot make us allocate more than this however much it claims to be sending.
const RESPONSE_SIZE_MAXIMUM: u64 = 4 * 1024 * 1024;

/// "Send me the genesis of the chain you are on."
///
/// Deliberately empty. There is exactly one genesis per chain and a fresh node has no way to
/// describe which one it wants — if it could, it would already know enough not to need this.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisRequest;

/// Everything needed to rebuild a chain's genesis state, exactly the inputs
/// `helix_executor::genesis::rebuild_genesis_state` takes.
///
/// The governance parameters are spelled out as individual fields rather than carried as the
/// executor's own `GovernanceParams`. Two reasons, and the second is the important one: `helix-p2p`
/// would otherwise have to depend on the entire state machine to move a couple of integers, and a
/// wire format that mirrors an internal type changes silently whenever that type does. Adding a
/// governance parameter now forces a decision here instead of quietly shipping a different message.
///
/// If someone forgets anyway, the failure is loud rather than silent: the joining node rebuilds the
/// state with a default for the missing field, the rebuild disagrees with the peer's `state_hash`,
/// and `verify_genesis_reconstruction` refuses the join.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenesisPayload {
    pub block: Block,
    pub personhood_authorities: Vec<PublicKey>,
    pub validator_stake: u64,
    pub allocations: Vec<(Address, u64)>,
    pub min_validator_stake: u64,
    pub fuel_per_fee_unit: u64,
    /// The hash the serving node's genesis state has, for the requester to check its own rebuild
    /// against. Self-certifying — see the module docs — and `None` from a node that has none.
    pub state_hash: Option<String>,
}

/// The answer to [`GenesisRequest`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GenesisResponse {
    /// `None` means "I cannot serve this", not "there is no genesis": a node still bootstrapping
    /// has nothing to hand over yet. A requester must treat it exactly like a failed request.
    pub genesis: Option<GenesisPayload>,
}

impl GenesisResponse {
    /// The honest "I have nothing for you" answer.
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Supplies the local genesis to serve an inbound request.
///
/// Same inversion as [`crate::blocksync::BlockProvider`], for the same reason: `helix-p2p` has no
/// storage dependency and should not grow one, and answering inside the swarm's own event loop
/// avoids routing a request out to the node and back into the right response slot.
pub trait GenesisProvider: Send + Sync + 'static {
    fn genesis<'a>(&'a self) -> Pin<Box<dyn Future<Output = GenesisResponse> + Send + 'a>>;
}

/// Bincode codec, following the shape of libp2p's own `cbor`/`json` codecs: read to a bounded
/// end-of-stream, then deserialize. Bincode because every other Helix wire format is bincode, and
/// a second serialization format is a second set of framing bugs.
#[derive(Debug, Clone, Default)]
pub struct GenesisCodec;

#[async_trait::async_trait]
impl request_response::Codec for GenesisCodec {
    type Protocol = StreamProtocol;
    type Request = GenesisRequest;
    type Response = GenesisResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(REQUEST_SIZE_MAXIMUM).read_to_end(&mut buf).await?;
        bincode::deserialize(&buf).map_err(decode_error)
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(RESPONSE_SIZE_MAXIMUM).read_to_end(&mut buf).await?;
        bincode::deserialize(&buf).map_err(decode_error)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&req).map_err(decode_error)?;
        io.write_all(&data).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&res).map_err(decode_error)?;
        io.write_all(&data).await?;
        io.close().await
    }
}

fn decode_error(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_response_carries_no_genesis() {
        assert!(GenesisResponse::empty().genesis.is_none());
    }

    /// The request has to survive a round trip even though it has no fields — an empty struct is
    /// exactly the shape a codec can get wrong without anyone noticing.
    #[test]
    fn the_request_round_trips_through_bincode() {
        let bytes = bincode::serialize(&GenesisRequest).expect("serializes");
        let back: GenesisRequest = bincode::deserialize(&bytes).expect("deserializes");
        assert_eq!(back, GenesisRequest);
    }

    #[test]
    fn an_empty_response_round_trips_through_bincode() {
        let bytes = bincode::serialize(&GenesisResponse::empty()).expect("serializes");
        let back: GenesisResponse = bincode::deserialize(&bytes).expect("deserializes");
        assert_eq!(back, GenesisResponse::empty());
    }
}
