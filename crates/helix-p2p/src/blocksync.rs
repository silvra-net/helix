//! Directed block sync over libp2p request/response (#138).
//!
//! Gossipsub can only broadcast, and a broadcast is a single shot with nobody obliged to listen.
//! That left one shape of failure with no way out at all: a node that missed a committed block had
//! no mechanism to *ask* for it. Its only catch-up route was `sync_blocks_from_peer` against an
//! operator-configured RPC endpoint — so a node without one could never recover, and every node
//! that did have one depended on somebody else's HTTP server to join the network.
//!
//! On 2026-07-29 that cost 14.5 hours of production downtime: a validator inside the quorum fell
//! one block behind, could not obtain that block from anyone, and the chain could not advance past
//! it. Peer-exchange tip announcements plus the gossip catch-up serve (#137) heal a small lag when
//! a peer volunteers; this module is the half that does not depend on volunteers, and it is what
//! lets a node join from genesis knowing nothing but one peer address.
//!
//! Deliberately bincode, not the `cbor`/`json` codecs libp2p ships: every other Helix wire format
//! is bincode, and a second serialization format on the wire is a second set of framing bugs.

use std::future::Future;
use std::pin::Pin;

use libp2p::futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use libp2p::swarm::StreamProtocol;
use serde::{Deserialize, Serialize};
use std::io;

use helix_consensus::Vote;
use helix_core::Block;

/// Wire protocol name. Bump the version on any incompatible change to the message shapes below —
/// libp2p negotiates it per stream, so a peer speaking only the old version is simply not served
/// rather than being fed something it will misparse.
pub const BLOCKSYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/helix/blocksync/1.0.0");

/// Largest batch a single request may ask for, and the most a responder will ever return.
///
/// A flat ceiling on size only — it bounds how much one request can cost, nothing more. It does
/// **not** by itself keep a batch inside a single validator-set epoch: it caps the length, not
/// where the range starts, so a 100-block batch beginning mid-epoch still straddles a rotation.
/// Confining a request to one signing set is the job of `blocksync_request_count`, which stops at
/// the boundary; see its documentation for why that matters to the receiver's quorum check.
///
/// Set equal to the epoch length because a batch can never usefully be longer than that anyway
/// once the boundary rule applies.
pub const MAX_BLOCKSYNC_BATCH: u32 = helix_consensus::EPOCH_LENGTH as u32;

/// Hard ceiling on a decoded request. Requests are tiny (two integers); anything larger is either
/// broken or hostile, and reading it to the end would be the amplification.
const REQUEST_SIZE_MAXIMUM: u64 = 1024;

/// Hard ceiling on a decoded response: `MAX_BLOCKSYNC_BATCH` blocks plus one commit certificate,
/// with generous headroom over the ~26 KB a production block currently occupies. A peer cannot make
/// us allocate more than this no matter what it claims to be sending.
const RESPONSE_SIZE_MAXIMUM: u64 = 8 * 1024 * 1024;

/// Ask a peer for up to `count` consecutive blocks starting at `from_height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSyncRequest {
    pub from_height: u64,
    pub count: u32,
}

/// A contiguous run of committed blocks, with the commit certificate for the **last** one.
///
/// One certificate, not one per block, because a chain already carries them: block `h`'s
/// certificate is block `h + 1`'s `last_commit`, which is inside this very batch for every block
/// below the last. Only the batch tip has no successor here to certify it.
///
/// That single certificate is what makes the whole batch trustworthy. Given an unbroken `prev_hash`
/// chain from the receiver's own tip up to a block that provably carries a BFT quorum, every block
/// in between is an ancestor of a finalized block — so finality transfers backwards across the
/// batch, and a peer cannot fabricate any of it without forging a quorum for the tip.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockSyncResponse {
    pub blocks: Vec<Block>,
    /// Precommits that finalized `blocks.last()`. Empty means "I hold no proof for this batch",
    /// which a receiver must treat exactly like a failed request — never as permission to adopt.
    pub tip_certificate: Vec<Vote>,
}

impl BlockSyncResponse {
    /// The "I have nothing for you" answer. Distinct from an error: the peer answered honestly, it
    /// simply cannot serve this range (pruned, ahead of its own tip, or no certificate to prove it).
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Supplies blocks to serve an inbound request.
///
/// Declared here and implemented by the node, rather than handing this crate a database handle:
/// `helix-p2p` has no storage dependency and should not grow one just to answer a request. The
/// inversion also keeps the whole inbound path inside the service's own event loop — no request-id
/// bookkeeping, no round trip through the node's event channel and back to the right response
/// slot, which is the scaffolding this design exists to avoid.
pub trait BlockProvider: Send + Sync + 'static {
    /// Blocks `from_height ..= from_height + count - 1` that this node holds, together with a
    /// certificate for the last one. Implementations return [`BlockSyncResponse::empty`] rather
    /// than a partial answer they cannot certify, and must clamp `count` themselves.
    fn blocks<'a>(
        &'a self,
        from_height: u64,
        count: u32,
    ) -> Pin<Box<dyn Future<Output = BlockSyncResponse> + Send + 'a>>;
}

/// Bincode codec for the two message types above, following the shape of libp2p's own `cbor`/`json`
/// codecs: read to a bounded end-of-stream, then deserialize.
#[derive(Debug, Clone, Default)]
pub struct BlockSyncCodec;

#[async_trait::async_trait]
impl request_response::Codec for BlockSyncCodec {
    type Protocol = StreamProtocol;
    type Request = BlockSyncRequest;
    type Response = BlockSyncResponse;

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

/// Clamp a peer-supplied `count` to something we are willing to serve. `0` stays `0` — an empty
/// request gets an empty answer rather than a silently widened one.
pub fn clamp_batch(count: u32) -> u32 {
    count.min(MAX_BLOCKSYNC_BATCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_for_more_than_the_cap_is_clamped() {
        assert_eq!(clamp_batch(u32::MAX), MAX_BLOCKSYNC_BATCH);
        assert_eq!(clamp_batch(MAX_BLOCKSYNC_BATCH + 1), MAX_BLOCKSYNC_BATCH);
    }

    #[test]
    fn a_request_within_the_cap_is_left_alone() {
        assert_eq!(clamp_batch(1), 1);
        assert_eq!(clamp_batch(MAX_BLOCKSYNC_BATCH), MAX_BLOCKSYNC_BATCH);
    }

    /// An empty ask must not be widened into a real one — otherwise a malformed or probing request
    /// would quietly cost us a full batch of upload.
    #[test]
    fn an_empty_request_stays_empty() {
        assert_eq!(clamp_batch(0), 0);
    }

    /// The cap must not exceed the epoch length. On its own that does not confine a batch to one
    /// signing set (`blocksync_request_count` does that by stopping at the boundary) — but a cap
    /// *larger* than an epoch would mean even a boundary-aligned request could span a rotation.
    #[test]
    fn the_batch_cap_does_not_exceed_one_epoch() {
        assert!(u64::from(MAX_BLOCKSYNC_BATCH) <= helix_consensus::EPOCH_LENGTH);
    }

    #[test]
    fn requests_and_responses_survive_a_bincode_round_trip() {
        let req = BlockSyncRequest { from_height: 26262, count: 20 };
        let bytes = bincode::serialize(&req).unwrap();
        assert_eq!(bincode::deserialize::<BlockSyncRequest>(&bytes).unwrap(), req);

        let res = BlockSyncResponse::empty();
        let bytes = bincode::serialize(&res).unwrap();
        let back: BlockSyncResponse = bincode::deserialize(&bytes).unwrap();
        assert!(back.blocks.is_empty() && back.tip_certificate.is_empty());
    }
}
