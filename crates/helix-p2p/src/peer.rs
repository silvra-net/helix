use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;

/// Unique peer identifier derived from their node public key fingerprint
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(String);

impl PeerId {
    pub fn new(id: String) -> Self {
        PeerId(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: PeerId,
    pub addr: SocketAddr,
    /// Protocol version this peer is running
    pub protocol_version: u32,
    /// Last block height this peer reported
    pub best_height: u64,
}
