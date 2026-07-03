pub mod server;
pub mod types;

pub use server::start_rpc_server;
pub use types::{RpcError, RpcRequest, RpcResponse};

use helix_core::Block;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxResponse {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub amount_hlx: f64,
    pub fee_hlx: f64,
    pub tx_type: String,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub tx_count: usize,
    pub validator: String,
    pub prev_hash: String,
    pub merkle_root: String,
    pub transactions: Vec<TxResponse>,
}

impl From<Block> for BlockResponse {
    fn from(block: Block) -> Self {
        let transactions = block
            .transactions
            .iter()
            .map(|tx| TxResponse {
                hash: tx.hash().to_hex(),
                from: tx.from.to_string(),
                to: tx.to.as_ref().map(|a| a.to_string()),
                amount_hlx: tx.amount as f64 / 1_000_000_000.0,
                fee_hlx: tx.fee as f64 / 1_000_000_000.0,
                tx_type: format!("{:?}", tx.tx_type),
                nonce: tx.nonce,
            })
            .collect();
        BlockResponse {
            hash: block.hash().to_hex(),
            height: block.height(),
            timestamp: block.header.timestamp,
            tx_count: block.tx_count(),
            validator: block.header.validator.to_string(),
            prev_hash: block.header.prev_hash.to_hex(),
            merkle_root: block.header.merkle_root.to_hex(),
            transactions,
        }
    }
}

/// Block header only — no transaction bodies. Lets a light client sync the
/// chain of headers (and their signatures) without the bandwidth cost of
/// downloading every transaction in every block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderResponse {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub validator: String,
    pub prev_hash: String,
    pub merkle_root: String,
}

impl From<&Block> for HeaderResponse {
    fn from(block: &Block) -> Self {
        HeaderResponse {
            hash: block.hash().to_hex(),
            height: block.height(),
            timestamp: block.header.timestamp,
            validator: block.header.validator.to_string(),
            prev_hash: block.header.prev_hash.to_hex(),
            merkle_root: block.header.merkle_root.to_hex(),
        }
    }
}

/// One step of a Merkle inclusion proof, JSON-friendly (hex sibling hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStepResponse {
    pub sibling: String,
    pub sibling_is_right: bool,
}

impl From<&helix_crypto::MerkleProofStep> for ProofStepResponse {
    fn from(step: &helix_crypto::MerkleProofStep) -> Self {
        ProofStepResponse {
            sibling: step.sibling.to_hex(),
            sibling_is_right: step.sibling_is_right,
        }
    }
}

/// A Merkle inclusion proof for one transaction in one block. A light client
/// that already trusts `merkle_root` (e.g. from a `HeaderResponse` it
/// verified) can replay this proof to confirm the transaction was included,
/// without downloading the block's other transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxProofResponse {
    pub tx_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub merkle_root: String,
    pub leaf_index: usize,
    pub proof: Vec<ProofStepResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxHistoryEntry {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub amount_hlx: f64,
    pub fee_hlx: f64,
    pub tx_type: String,
    pub nonce: u64,
    pub block_height: u64,
    pub block_hash: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResponse {
    pub address: String,
    pub balance_hlx: f64,
    pub staked_hlx: f64,
    pub nonce: u64,
    pub has_code: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameResponse {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonhoodResponse {
    pub address: String,
    pub status: helix_identity::PersonhoodStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianResponse {
    pub address: String,
    pub guardians: Vec<String>,
    pub threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStatusResponse {
    pub address: String,
    /// Currently controlling public key fingerprint, if control was ever socially recovered.
    pub recovered_key_fingerprint: Option<String>,
    /// Guardian approvals collected so far for a pending recovery vote, if any.
    pub pending_approvals: Option<usize>,
    pub threshold: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceParamsResponse {
    pub min_validator_stake_hlx: f64,
    pub fuel_per_fee_unit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposalResponse {
    pub id: u64,
    pub proposer: String,
    pub param: String,
    pub new_value: u64,
    pub created_at_height: u64,
    pub yes_stake_hlx: f64,
    pub yes_votes: usize,
    pub executed: bool,
}

impl From<&helix_executor::GovernanceProposal> for GovernanceProposalResponse {
    fn from(p: &helix_executor::GovernanceProposal) -> Self {
        GovernanceProposalResponse {
            id: p.id,
            proposer: p.proposer.clone(),
            param: format!("{:?}", p.param),
            new_value: p.new_value,
            created_at_height: p.created_at_height,
            yes_stake_hlx: p.yes_stake as f64 / 1_000_000_000.0,
            yes_votes: p.voters.len(),
            executed: p.executed,
        }
    }
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
