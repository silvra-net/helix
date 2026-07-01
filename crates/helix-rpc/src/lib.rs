pub mod server;
pub mod types;

pub use server::start_rpc_server;
pub use types::{RpcError, RpcRequest, RpcResponse};

use helix_core::Block;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub tx_count: usize,
    pub validator: String,
    pub prev_hash: String,
    pub merkle_root: String,
}

impl From<Block> for BlockResponse {
    fn from(block: Block) -> Self {
        BlockResponse {
            hash: block.hash().to_hex(),
            height: block.height(),
            timestamp: block.header.timestamp,
            tx_count: block.tx_count(),
            validator: block.header.validator.to_string(),
            prev_hash: block.header.prev_hash.to_hex(),
            merkle_root: block.header.merkle_root.to_hex(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResponse {
    pub address: String,
    pub balance_hlx: f64,
    pub staked_hlx: f64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub version: String,
    pub height: u64,
    pub best_hash: String,
    pub peer_count: usize,
    pub is_syncing: bool,
    pub mempool_size: usize,
    pub total_accounts: usize,
    pub circulating_supply_hlx: f64,
    pub total_burned_hlx: f64,
}
