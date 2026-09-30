//! The Helix node this wallet reads and submits through — its public REST API, the same one any
//! integration uses. Only the fields this service needs are declared.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use helix_core::Transaction;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    pub height: u64,
    pub best_hash: String,
    #[serde(default)]
    pub is_syncing: bool,
    pub base_fee_per_byte: u64,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub peer_count: u64,
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
    /// Every liquid balance the block moved (#260); `None` when the node has no record of it.
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

/// An account as the node reads it, with the height it is from (#261).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
    pub state_height: u64,
}

/// What `GET /transactions/:hash` says about a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxState {
    Pending,
    Applied,
    Failed(String),
    /// Left the pool unincluded; nothing charged, nonce unused.
    Expired,
    /// This node has never seen it (or has forgotten it since a restart).
    Unknown,
}

/// How requests reach the node: over HTTP to a node elsewhere, or straight into the routes of
/// the node this wallet runs inside (`helix start` with `HELIX_WALLET_RPC`) — the same handlers,
/// so the same answers, without a socket or the rate limit that counts every outside client.
enum Transport {
    Http { base: String, http: reqwest::Client },
    InProcess(axum::Router),
}

pub struct Node {
    transport: Transport,
}

fn parse_nano(text: &str, what: &str) -> Result<u64> {
    text.parse().map_err(|_| anyhow!("{what}: {text:?} is not a number of nano-HLX"))
}

/// The largest answer read: a full block rendered as JSON, with room.
const MAX_ANSWER_BYTES: usize = 64 * 1024 * 1024;

impl Node {
    pub fn new(base: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("a TLS backend is available");
        Node { transport: Transport::Http { base: base.trim_end_matches('/').to_string(), http } }
    }

    /// The node this process is — its RPC routes, called directly.
    pub fn in_process(routes: axum::Router) -> Self {
        Node { transport: Transport::InProcess(routes) }
    }

    pub fn url(&self) -> &str {
        match &self.transport {
            Transport::Http { base, .. } => base,
            Transport::InProcess(_) => "this node",
        }
    }

    /// One request, as status and body bytes.
    async fn request(&self, post: Option<Vec<u8>>, path: &str) -> Result<(StatusCode, Vec<u8>)> {
        match &self.transport {
            Transport::Http { base, http } => {
                let url = format!("{base}{path}");
                let builder = match post {
                    Some(body) => http.post(&url).header("content-type", "application/json").body(body),
                    None => http.get(&url),
                };
                let response = builder.send().await.with_context(|| format!("could not reach the node at {url}"))?;
                let status = response.status();
                let bytes = response.bytes().await.with_context(|| format!("{url}: the answer broke off"))?;
                Ok((status, bytes.to_vec()))
            }
            Transport::InProcess(routes) => {
                use tower::ServiceExt;
                let request = axum::http::Request::builder()
                    .method(if post.is_some() { "POST" } else { "GET" })
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(post.unwrap_or_default()))?;
                let response = routes.clone().oneshot(request).await.map_err(|e| anyhow!("{path}: {e}"))?;
                let status = response.status();
                let bytes = axum::body::to_bytes(response.into_body(), MAX_ANSWER_BYTES).await?;
                Ok((status, bytes.to_vec()))
            }
        }
    }

    /// A GET, retried while the node rate-limits this service. Returns the status with the body
    /// so each caller decides what a 404 means for it.
    async fn get_raw(&self, path: &str) -> Result<(StatusCode, serde_json::Value)> {
        let mut wait = Duration::from_millis(100);
        for _ in 0..8 {
            let (status, bytes) = self.request(None, path).await?;
            if status == StatusCode::TOO_MANY_REQUESTS {
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(Duration::from_secs(2));
                continue;
            }
            let body = serde_json::from_slice(&bytes)
                .with_context(|| format!("{path} on {} did not answer with JSON", self.url()))?;
            return Ok((status, body));
        }
        Err(anyhow!(
            "the node at {} keeps rate-limiting this service — start it with a higher \
             HELIX_RPC_RATE_LIMIT (e.g. 5000,1000), or run the wallet inside the node \
             (HELIX_WALLET_RPC), which is not rate-limited",
            self.url()
        ))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let (status, body) = self.get_raw(path).await?;
        if !status.is_success() {
            return Err(anyhow!("{path}: the node answered HTTP {status}: {body}"));
        }
        serde_json::from_value(body).with_context(|| format!("{path}: an answer this service does not understand"))
    }

    pub async fn status(&self) -> Result<Status> {
        self.get("/status").await
    }

    pub async fn header(&self, height: u64) -> Result<Header> {
        self.get(&format!("/blocks/height/{height}/header")).await
    }

    pub async fn block_at(&self, height: u64) -> Result<Block> {
        self.get(&format!("/blocks/height/{height}")).await
    }

    /// The height of the block with this hash, or `None` if the node has no such block.
    pub async fn height_of(&self, hash: &str) -> Result<Option<u64>> {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(None);
        }
        let (status, body) = self.get_raw(&format!("/blocks/hash/{hash}")).await?;
        match status {
            s if s.is_success() => Ok(body["height"].as_u64()),
            StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST => Ok(None),
            s => Err(anyhow!("/blocks/hash/{hash}: HTTP {s}: {body}")),
        }
    }

    /// An account's balance and nonce. A valid address the chain has never seen is zero.
    pub async fn account(&self, address: &str) -> Result<Account> {
        let path = format!("/accounts/{address}");
        let (status, body) = self.get_raw(&path).await?;
        let state_height = body["state_height"]
            .as_u64()
            .ok_or_else(|| anyhow!("{path}: no state_height — the node is older than 0.20.2"))?;
        match status {
            s if s.is_success() => Ok(Account {
                balance: parse_nano(body["balance_nano"].as_str().unwrap_or_default(), &path)?,
                nonce: body["nonce"].as_u64().ok_or_else(|| anyhow!("{path}: no nonce"))?,
                state_height,
            }),
            StatusCode::NOT_FOUND => Ok(Account { balance: 0, nonce: 0, state_height }),
            s => Err(anyhow!("{path}: HTTP {s}: {body}")),
        }
    }

    pub async fn tx_state(&self, hash: &str) -> Result<TxState> {
        let path = format!("/transactions/{hash}");
        let (status, body) = self.get_raw(&path).await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(if body["status"] == "expired" { TxState::Expired } else { TxState::Unknown });
        }
        if !status.is_success() {
            return Err(anyhow!("{path}: HTTP {status}: {body}"));
        }
        Ok(match body["status"].as_str() {
            Some("pending") => TxState::Pending,
            Some("applied") => TxState::Applied,
            Some("failed") => TxState::Failed(body["error"].as_str().unwrap_or("failed").to_string()),
            Some("expired") => TxState::Expired,
            _ => TxState::Unknown,
        })
    }

    /// Submit a signed transaction. `Err(Refused)` is the node's answer (a 400 with a reason);
    /// any other error means the answer never came, and the transaction may or may not be in.
    pub async fn submit(&self, tx: &Transaction) -> Result<(), Submit> {
        let body = serde_json::to_vec(tx).map_err(|e| Submit::Unreachable(e.to_string()))?;
        let (status, bytes) = self
            .request(Some(body), "/transactions")
            .await
            .map_err(|e| Submit::Unreachable(e.to_string()))?;
        if status.is_success() {
            return Ok(());
        }
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        let reason = body["error"].as_str().unwrap_or("refused").to_string();
        if same_transaction_again(&reason) {
            return Ok(());
        }
        if status == StatusCode::BAD_REQUEST {
            Err(Submit::Refused(reason))
        } else {
            Err(Submit::Unreachable(format!("HTTP {status}: {reason}")))
        }
    }
}

/// Whether a refusal only says this very transaction is already in the pool — harmless, as a
/// resubmission after a lost answer is. The node says so in exactly these words. Not any
/// "already": "Nonce already pending" and a spent nonce are *another* transaction holding this
/// one's slot, and treating those as success would report a withdrawal that never happens.
pub fn same_transaction_again(reason: &str) -> bool {
    reason.starts_with("Transaction ") && reason.ends_with(" already in mempool")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submit {
    Refused(String),
    Unreachable(String),
}

impl Block {
    pub fn tx_amount(tx: &Tx) -> Result<u64> {
        parse_nano(&tx.amount_nano, "amount_nano")
    }
    pub fn tx_fee(tx: &Tx) -> Result<u64> {
        parse_nano(&tx.fee_nano, "fee_nano")
    }
}

pub fn parse_delta(text: &str) -> Result<i128> {
    text.parse().map_err(|_| anyhow!("delta_nano: {text:?} is not a number"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};

    fn stand_in() -> axum::Router {
        axum::Router::new()
            .route(
                "/status",
                get(|| async {
                    axum::Json(serde_json::json!({ "height": 7, "best_hash": "h7", "base_fee_per_byte": 3, "version": "x" }))
                }),
            )
            .route(
                "/accounts/:a",
                get(|| async {
                    (reqwest::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({ "error": "not found", "state_height": 7 })))
                }),
            )
            .route(
                "/transactions",
                post(|body: String| async move {
                    // Answers as the node does: the body must be the transaction as JSON.
                    let tx: helix_core::Transaction = serde_json::from_str(&body).unwrap();
                    let reason = format!("Transaction {} already in mempool", tx.hash().to_hex());
                    (reqwest::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({ "error": reason })))
                }),
            )
    }

    /// Inside the node, the wallet calls the node's own routes: the same answers as over HTTP,
    /// status codes and bodies included, with no socket between them.
    #[tokio::test]
    async fn the_node_in_this_process_answers_like_the_node_over_http() {
        let local = Node::in_process(stand_in());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, stand_in()).await.unwrap() });
        let remote = Node::new(&format!("http://{addr}"));
        let kp = helix_crypto::KeyPair::generate();
        let from = helix_crypto::Address::from_public_key(&kp.public);
        let tx = Transaction {
            version: 1,
            tx_type: helix_core::TxType::Transfer,
            from: from.clone(),
            to: Some(from),
            amount: 1,
            fee: 1,
            nonce: 0,
            data: Vec::new(),
            crypto_version: kp.scheme,
            chain_id: helix_crypto::Hash::ZERO,
            signature: helix_crypto::Signature::from_bytes(vec![]),
            public_key: Some(kp.public.clone()),
        };
        for node in [&local, &remote] {
            let status = node.status().await.unwrap();
            assert_eq!((status.height, status.base_fee_per_byte), (7, 3));
            assert_eq!(node.account("hlxAnyone").await.unwrap(), Account { balance: 0, nonce: 0, state_height: 7 });
            assert_eq!(node.submit(&tx).await, Ok(()), "the same transaction again is not a refusal");
        }
        assert_eq!(local.url(), "this node");
    }

    #[test]
    fn only_this_transaction_already_in_the_pool_counts_as_submitted() {
        assert!(same_transaction_again("Transaction 3f2a… already in mempool"));
        for other in [
            "Nonce already pending: a transaction from hlxA with nonce 4 is already in the mempool",
            "Nonce already spent: hlxA is on nonce 5, this transaction signs nonce 4",
            "Fee below the block base fee",
        ] {
            assert!(!same_transaction_again(other), "{other}");
        }
    }
}
