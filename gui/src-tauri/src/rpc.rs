//! Thin async client over the node's public REST API (the same endpoints `helix`/`hlx` use).
//!
//! Reads only — the one write, submitting a signed transaction, is here too but the signing
//! happens in `pricing`/`commands` with a `KeyPair` that never leaves the backend.

use serde::{Deserialize, Serialize};

use helix_core::Transaction;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Network-wide status — mirrors the node's `NodeStatus` (only the fields the GUI shows).
/// Unknown fields are ignored, so this keeps working as the node adds more.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub version: String,
    pub height: u64,
    pub best_hash: String,
    pub peer_count: usize,
    pub is_syncing: bool,
    pub mempool_size: usize,
    pub circulating_supply_hlx: f64,
    /// What the next block charges per transaction byte. Absent on nodes older than the fee
    /// market — defaulted to 0 so the caller can fall back to an explicit fee.
    #[serde(default)]
    pub base_fee_per_byte: u64,
}

/// One account's on-chain position — a subset of the node's `AccountResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub address: String,
    pub balance_hlx: f64,
    pub staked_hlx: f64,
    #[serde(default)]
    pub unbonding_stake_hlx: f64,
    /// Block height at which `unbonding_stake` becomes claimable (0 = nothing unbonding).
    #[serde(default)]
    pub unbonding_unlock_height: u64,
    /// The validator the unbonding stake is still slashable for, or null for an own self-unstake.
    #[serde(default)]
    pub unbonding_source: Option<String>,
    pub nonce: u64,
}

/// One delegation this account holds — mirrors the node's `/accounts/:address/delegations` rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub validator: String,
    pub shares: u64,
    pub value_hlx: f64,
}

/// A validator's delegation pool — mirrors `/validators/:address/pool`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorPool {
    pub address: String,
    pub has_pool: bool,
    pub self_staked_hlx: f64,
    pub delegated_stake_hlx: f64,
    pub effective_stake_hlx: f64,
    pub total_shares: u64,
    pub commission_bps: Option<u16>,
}

/// One row of transaction history — mirrors the node's `TxHistoryEntry`, including the honest
/// `status` (`applied` / `failed` / `unknown`, never a bare "confirmed") and failure `error`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub amount_hlx: f64,
    pub fee_hlx: f64,
    pub tx_type: String,
    pub nonce: u64,
    pub block_height: u64,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
}

/// Outcome of submitting a signed transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResult {
    pub tx_hash: String,
    pub status: String,
}

pub async fn get_status(node: &str) -> Result<NetworkStatus, String> {
    client()
        .get(format!("{node}/status"))
        .send()
        .await
        .map_err(err)?
        .json::<NetworkStatus>()
        .await
        .map_err(err)
}

pub async fn get_account(node: &str, address: &str) -> Result<Account, String> {
    let resp = client()
        .get(format!("{node}/accounts/{address}"))
        .send()
        .await
        .map_err(err)?;
    if !resp.status().is_success() {
        return Err(format!("node returned {} for {address}", resp.status()));
    }
    resp.json::<Account>().await.map_err(err)
}

/// Current per-account nonce, or 0 if the account has never transacted (same fallback the CLI
/// uses). Never fails the send flow — a missing account is nonce 0.
pub async fn fetch_nonce(node: &str, address: &str) -> u64 {
    match get_account(node, address).await {
        Ok(a) => a.nonce,
        Err(_) => 0,
    }
}

pub async fn fetch_base_fee(node: &str) -> Result<u64, String> {
    Ok(get_status(node).await?.base_fee_per_byte)
}

pub async fn get_delegations(node: &str, address: &str) -> Result<Vec<Delegation>, String> {
    let value: serde_json::Value = client()
        .get(format!("{node}/accounts/{address}/delegations"))
        .send()
        .await
        .map_err(err)?
        .json()
        .await
        .map_err(err)?;
    let arr = value.get("delegations").cloned().unwrap_or(serde_json::Value::Array(vec![]));
    serde_json::from_value(arr).map_err(err)
}

pub async fn get_validator_pool(node: &str, validator: &str) -> Result<ValidatorPool, String> {
    let resp = client()
        .get(format!("{node}/validators/{validator}/pool"))
        .send()
        .await
        .map_err(err)?;
    if !resp.status().is_success() {
        return Err(format!("node returned {} for {validator}", resp.status()));
    }
    resp.json::<ValidatorPool>().await.map_err(err)
}

pub async fn get_history(node: &str, address: &str, limit: u32) -> Result<Vec<HistoryEntry>, String> {
    let value: serde_json::Value = client()
        .get(format!("{node}/accounts/{address}/transactions?limit={limit}"))
        .send()
        .await
        .map_err(err)?
        .json()
        .await
        .map_err(err)?;

    // The endpoint returns a bare array; accept a `{ "transactions": [...] }` wrapper too so a
    // future response-shape tweak doesn't silently blank the history.
    let arr = if value.is_array() {
        value
    } else {
        value.get("transactions").cloned().unwrap_or(serde_json::Value::Array(vec![]))
    };
    serde_json::from_value(arr).map_err(err)
}

/// Submit an already-signed transaction. A rejected transaction comes back as a non-2xx with an
/// `error` body; surface that verbatim rather than pretending it went through.
pub async fn submit_tx(node: &str, tx: &Transaction) -> Result<SubmitResult, String> {
    let resp = client()
        .post(format!("{node}/transactions"))
        .json(tx)
        .send()
        .await
        .map_err(err)?;
    let ok = resp.status().is_success();
    let body: serde_json::Value = resp.json().await.map_err(err)?;

    if !ok {
        let reason = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("transaction rejected");
        return Err(reason.to_string());
    }

    Ok(SubmitResult {
        tx_hash: body.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        status: body.get("status").and_then(|v| v.as_str()).unwrap_or("pending").to_string(),
    })
}
