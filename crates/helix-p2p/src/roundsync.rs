//! Directed round sync over libp2p request/response — asking a peer for the proposal and votes of
//! the height currently being decided.
//!
//! Gossip publishes each message exactly once, and libp2p's gossipsub identifies a message by a
//! hash of its bytes: re-publishing the same proposal is refused for `duplicate_cache_time`
//! (a minute, by default) with `PublishError::Duplicate`. The node re-offers its pending proposal
//! every tick precisely so a validator that connected — or finished catching up — after the first
//! broadcast can still see it, and that mechanism has never worked. Measured on 2026-08-26: 483
//! refused re-offers in one node's log, while a freshly activated validator sat waiting for a
//! proposal it could not obtain and the chain stopped at height 300.
//!
//! Block sync (`blocksync`) solves the same class of problem for *committed* blocks. This is the
//! equivalent for the block that is still being decided: the node that is missing something knows
//! it is missing it, so it asks, instead of hoping for a re-broadcast that never comes.
//!
//! Nothing served here is trusted. The requester feeds the answer through `receive_proposal` and
//! `add_vote` like any gossiped message — signatures, set membership, the lock rules and the
//! proposer schedule all still apply. A peer can answer with nothing or with junk; it cannot make
//! the asker accept anything it would have rejected on the wire.

use std::future::Future;
use std::pin::Pin;

use libp2p::futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use libp2p::swarm::StreamProtocol;
use serde::{Deserialize, Serialize};
use std::io;

use helix_consensus::{Proposal, Vote};

/// Wire protocol name. Bump the version on any incompatible change to the message shapes below —
/// libp2p negotiates it per stream, so a peer speaking only the old version is simply not served
/// rather than being fed something it will misparse.
pub const ROUNDSYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/helix/roundsync/1.0.0");

/// Hard ceiling on a decoded request. Requests are tiny (a height and a round); anything larger is
/// either broken or hostile, and reading it to the end would be the amplification.
const REQUEST_SIZE_MAXIMUM: u64 = 1024;

/// Hard ceiling on a decoded response: one proposal (a full block, bounded by the same 4 MB
/// gossipsub transmit limit a proposal has to fit through anyway) plus the votes of one height.
const RESPONSE_SIZE_MAXIMUM: u64 = 8 * 1024 * 1024;

/// Most votes a responder will ever return. A height's honest vote traffic is two per validator
/// per round plus whatever arrived early; this bounds what a peer can make us allocate without
/// bounding anything real.
pub const MAX_ROUNDSYNC_VOTES: usize = 512;

/// "What do you have for the height you are deciding?"
///
/// `round` is the round the asker is on. It is deliberately *not* a filter on the answer: a peer
/// on a later round should say so, because learning that is half the point — the asker's own
/// round-skip rule then pulls it forward. The field is there so the responder can log a useful
/// line and so a future version can serve a specific round's proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundSyncRequest {
    pub height: u64,
    pub round: u32,
}

/// What the peer holds for that height: its pending proposal, if any, and the votes it has
/// collected or buffered.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoundSyncResponse {
    pub proposal: Option<Proposal>,
    pub votes: Vec<Vote>,
}

impl RoundSyncResponse {
    /// The honest "I have nothing for that height" answer — a peer that is behind, or ahead and
    /// already past it. Distinct from a failed request: the peer answered.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether this answer carries anything worth applying.
    pub fn is_empty(&self) -> bool {
        self.proposal.is_none() && self.votes.is_empty()
    }

    /// Trim to what a responder is willing to send. Called on the serving side, so a bug in a
    /// provider cannot turn into an oversized frame the requester then refuses to decode.
    pub fn clamped(mut self) -> Self {
        self.votes.truncate(MAX_ROUNDSYNC_VOTES);
        self
    }
}

/// Supplies the round state to serve an inbound request.
///
/// Declared here and implemented by the node for the same reason as [`crate::BlockProvider`]:
/// `helix-p2p` holds no consensus engine, and answering inside the swarm loop avoids a round trip
/// out to the node and back to the right response slot.
pub trait RoundProvider: Send + Sync + 'static {
    /// The proposal and votes this node holds for `height`. Implementations return
    /// [`RoundSyncResponse::empty`] for any height they are not currently deciding.
    fn round_state<'a>(
        &'a self,
        height: u64,
        round: u32,
    ) -> Pin<Box<dyn Future<Output = RoundSyncResponse> + Send + 'a>>;
}

/// Bincode codec, following the shape of `BlockSyncCodec`: read to a bounded end-of-stream, then
/// deserialize.
#[derive(Debug, Clone, Default)]
pub struct RoundSyncCodec;

#[async_trait::async_trait]
impl request_response::Codec for RoundSyncCodec {
    type Protocol = StreamProtocol;
    type Request = RoundSyncRequest;
    type Response = RoundSyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(REQUEST_SIZE_MAXIMUM).read_to_end(&mut buf).await?;
        bincode::deserialize(&buf).map_err(decode_error)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
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
    fn an_oversized_vote_list_is_trimmed_before_it_goes_on_the_wire() {
        // Shape only — nothing here is verified, the clamp runs before any signature is looked at.
        let key = helix_crypto::PublicKey::from_bytes(vec![7u8; 32]);
        let vote = |i: u64| Vote {
            vote_type: helix_consensus::VoteType::Prevote,
            height: i,
            round: 0,
            block_hash: helix_crypto::Hash::ZERO,
            validator: helix_crypto::Address::from_public_key(&key),
            public_key: key.clone(),
            crypto_version: helix_crypto::CryptoScheme::MlDsa,
            signature: helix_crypto::Signature::from_bytes(vec![]),
        };
        let response = RoundSyncResponse {
            proposal: None,
            votes: (0..MAX_ROUNDSYNC_VOTES as u64 + 50).map(vote).collect(),
        }
        .clamped();

        assert_eq!(response.votes.len(), MAX_ROUNDSYNC_VOTES);
    }

    #[test]
    fn an_empty_answer_is_recognisable_as_one() {
        assert!(RoundSyncResponse::empty().is_empty());
    }
}
