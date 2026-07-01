use helix_core::{Block, Transaction};
use helix_crypto::Hash;
use serde::{Deserialize, Serialize};



/// Messages exchanged between Helix nodes over P2P
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Initial handshake — exchange capabilities and best block
    Hello {
        protocol_version: u32,
        best_height: u64,
        best_hash: Hash,
        node_name: Option<String>,
    },

    /// Broadcast a newly proposed block to all peers
    NewBlock(Block),

    /// Broadcast a new transaction to all peers
    NewTransaction(Transaction),

    /// Request blocks between two heights (inclusive)
    GetBlocks { from_height: u64, to_height: u64 },

    /// Response to GetBlocks
    Blocks(Vec<Block>),

    /// Request a specific block by hash
    GetBlock(Hash),

    /// Heartbeat — keep connection alive, share current height
    Ping { height: u64 },
    Pong { height: u64 },
}
