//! The part of the Mesh (formerly Rosetta) data model this service speaks — the Data API
//! (network, block, account, mempool). Field names and shapes follow the specification at
//! <https://github.com/coinbase/mesh-specifications>.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIdentifier {
    pub blockchain: String,
    pub network: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockIdentifier {
    pub index: u64,
    pub hash: String,
}

/// A block named by height, by hash, or — both absent — the current one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialBlockIdentifier {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionIdentifier {
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountIdentifier {
    pub address: String,
    /// Helix has no sub-accounts in this API: every balance here is the liquid one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_account: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Currency {
    pub symbol: String,
    pub decimals: u32,
}

impl Currency {
    pub fn hlx() -> Self {
        Currency { symbol: "HLX".into(), decimals: 9 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Amount {
    /// Signed integer in the currency's smallest unit (nano-HLX), as a decimal string.
    pub value: String,
    pub currency: Currency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationIdentifier {
    pub index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub operation_identifier: OperationIdentifier,
    #[serde(rename = "type")]
    pub op_type: String,
    /// Absent in the mempool, where nothing has happened yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub account: AccountIdentifier,
    pub amount: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub transaction_identifier: TransactionIdentifier,
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub block_identifier: BlockIdentifier,
    pub parent_block_identifier: BlockIdentifier,
    /// Milliseconds since the Unix epoch.
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
}

/// A Mesh error. Sent with HTTP 500, as the specification asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshError {
    pub code: u32,
    pub message: String,
    pub retriable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ---------- requests ----------

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkRequest {
    pub network_identifier: NetworkIdentifier,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockRequest {
    pub network_identifier: NetworkIdentifier,
    pub block_identifier: PartialBlockIdentifier,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockTransactionRequest {
    pub network_identifier: NetworkIdentifier,
    pub block_identifier: BlockIdentifier,
    pub transaction_identifier: TransactionIdentifier,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountBalanceRequest {
    pub network_identifier: NetworkIdentifier,
    pub account_identifier: AccountIdentifier,
    #[serde(default)]
    pub block_identifier: Option<PartialBlockIdentifier>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MempoolTransactionRequest {
    pub network_identifier: NetworkIdentifier,
    pub transaction_identifier: TransactionIdentifier,
}
