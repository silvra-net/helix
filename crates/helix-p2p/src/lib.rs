pub mod config;
mod conn_limits;
pub mod reputation;
pub mod service;

pub use config::P2PConfig;
pub use reputation::PeerReputation;
pub use service::{P2PCommand, P2PEvent, P2PService};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum P2PError {
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Gossipsub error: {0}")]
    Gossipsub(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type P2PResult<T> = Result<T, P2PError>;

/// Gossipsub topic names — versioned so future protocol upgrades can coexist
pub const TOPIC_BLOCKS: &str = "helix/blocks/1.0.0";
pub const TOPIC_TRANSACTIONS: &str = "helix/transactions/1.0.0";
pub const TOPIC_VOTES: &str = "helix/votes/1.0.0";
/// Finalized, committed blocks — broadcast after BFT quorum so lagging peers
/// can apply them directly without replaying the vote round.
pub const TOPIC_COMMITTED_BLOCKS: &str = "helix/committed-blocks/1.0.0";
/// Known-peer-address announcements — see `service::PeerExchangeMsg`'s doc comment for
/// why this exists (mDNS-only discovery and a single explicit seed-peer dial both leave
/// every follower connected to just one hub; if that hub goes down, followers connected
/// only to it have no path to each other).
pub const TOPIC_PEER_EXCHANGE: &str = "helix/peer-exchange/1.0.0";
