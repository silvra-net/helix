//! The Helix node this service reads, through its public REST API — the same interface any
//! exchange integration uses, and nothing more. Only the fields this service needs are declared;
//! a node answering more is fine.

use anyhow::{anyhow, Context, Result};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    pub version: String,
    pub height: u64,
    pub best_hash: String,
    #[serde(default)]
    pub is_syncing: bool,
    #[serde(default)]
    pub sync_target_height: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Header {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Block {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: String,
    pub transactions: Vec<Tx>,
    /// Every liquid balance the block moved (#260). `None` when the node has no record of it.
    #[serde(default)]
    pub balance_changes: Option<Vec<BalanceChange>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tx {
    pub hash: String,
    pub from: String,
    #[serde(default)]
    pub to: Option<String>,
    pub amount_nano: String,
    pub fee_nano: String,
    #[serde(default)]
    pub memo: Option<String>,
    pub tx_type: helix_core::TxType,
    pub nonce: u64,
    /// `applied`, `failed` or `unknown`.
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BalanceChange {
    pub tx_index: Option<u32>,
    pub account: String,
    /// `transaction`, `reward` or `contract`.
    pub kind: String,
    pub delta_nano: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Genesis {
    pub allocations: Vec<Allocation>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Allocation {
    pub address: String,
    pub balance_nano: u64,
}

/// A pending transaction as `GET /transactions/:hash` answers while it waits.
#[derive(Debug, Clone, Deserialize)]
pub struct Pending {
    pub hash: String,
    pub status: String,
    pub from: String,
    #[serde(default)]
    pub to: Option<String>,
    pub amount_nano: String,
    pub fee_nano: String,
    pub tx_type: helix_core::TxType,
}

/// A liquid balance and the height it is from, read together (#261).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Balance {
    pub nano: u64,
    pub state_height: u64,
}

/// Why a request to the node did not produce an answer.
#[derive(Debug)]
pub enum NodeError {
    /// The node could not be reached or answered with something that is not its API.
    Unavailable(anyhow::Error),
    /// The node answered that the thing does not exist (HTTP 404).
    NotFound,
    /// The node refused the request (HTTP 400) — for an address, one that is not valid.
    Invalid(String),
    /// The node's rate limit refused this service (HTTP 429). It counts per client address, and
    /// this service is one client asking for every block.
    RateLimited,
}

pub struct Node {
    base: String,
    http: reqwest::Client,
}

impl Node {
    pub fn new(base: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("a TLS backend is available");
        Node { base: base.trim_end_matches('/').to_string(), http }
    }

    async fn get_value(&self, path: &str) -> Result<serde_json::Value, NodeError> {
        let url = format!("{}{}", self.base, path);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("could not reach the node at {url}"))
            .map_err(NodeError::Unavailable)?;
        let status = response.status();
        let body: serde_json::Value = response
            .json()
            .await
            .with_context(|| format!("{url} did not answer with JSON"))
            .map_err(NodeError::Unavailable)?;
        match status {
            s if s.is_success() => Ok(body),
            StatusCode::NOT_FOUND => {
                // A 404 that still carries an account's height is an answer: a valid address with
                // no history (#261). Handed back for `balance` to read.
                if body.get("state_height").is_some() {
                    Ok(body)
                } else {
                    Err(NodeError::NotFound)
                }
            }
            StatusCode::TOO_MANY_REQUESTS => Err(NodeError::RateLimited),
            StatusCode::BAD_REQUEST => Err(NodeError::Invalid(
                body["error"].as_str().unwrap_or("refused").to_string(),
            )),
            s => Err(NodeError::Unavailable(anyhow!("{url} answered HTTP {s}: {body}"))),
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, NodeError> {
        let value = self.get_value(path).await?;
        serde_json::from_value(value)
            .with_context(|| format!("{path}: an answer this service does not understand"))
            .map_err(NodeError::Unavailable)
    }

    pub async fn status(&self) -> Result<Status, NodeError> {
        self.get("/status").await
    }

    pub async fn header(&self, height: u64) -> Result<Header, NodeError> {
        self.get(&format!("/blocks/height/{height}/header")).await
    }

    pub async fn block_at(&self, height: u64) -> Result<Block, NodeError> {
        self.get(&format!("/blocks/height/{height}")).await
    }

    pub async fn block_by_hash(&self, hash: &str) -> Result<Block, NodeError> {
        self.get(&format!("/blocks/hash/{hash}")).await
    }

    pub async fn genesis(&self) -> Result<Genesis, NodeError> {
        self.get("/genesis").await
    }

    /// A liquid balance with the height it is from. A valid address the chain has never seen is
    /// a balance of zero at the height the node names.
    pub async fn balance(&self, address: &str) -> Result<Balance, NodeError> {
        let url = format!("/accounts/{address}");
        let value = self.get_value(&url).await?;
        let state_height = value["state_height"]
            .as_u64()
            .ok_or_else(|| NodeError::Unavailable(anyhow!("{url}: no state_height — a node older than #261")))?;
        let nano = match value["balance_nano"].as_str() {
            Some(n) => n
                .parse()
                .map_err(|_| NodeError::Unavailable(anyhow!("{url}: balance_nano {n:?} is not a number")))?,
            None => 0, // the 404 answer for an address with no history
        };
        Ok(Balance { nano, state_height })
    }

    pub async fn mempool(&self) -> Result<Vec<String>, NodeError> {
        let value = self.get_value("/mempool/transactions").await?;
        serde_json::from_value(value["transactions"].clone())
            .context("/mempool/transactions: no list of transactions")
            .map_err(NodeError::Unavailable)
    }

    pub async fn pending(&self, hash: &str) -> Result<Pending, NodeError> {
        let pending: Pending = self.get(&format!("/transactions/{hash}")).await?;
        if pending.status != "pending" {
            return Err(NodeError::NotFound);
        }
        Ok(pending)
    }
}
