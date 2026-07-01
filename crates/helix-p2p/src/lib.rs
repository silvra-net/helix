pub mod config;
pub mod service;

pub use config::P2PConfig;
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
