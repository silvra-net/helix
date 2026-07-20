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
    /// Height this address may submit `Unjail` at, or `None` if it isn't downtime-jailed.
    #[serde(default)]
    pub jailed_until: Option<u64>,
    /// Consecutive blocks this address's precommit has been absent from `last_commit`, or
    /// `None` if it currently has none.
    #[serde(default)]
    pub missed_blocks: Option<u32>,
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

/// An account's social-recovery guardian set — mirrors `/accounts/:address/guardians`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianInfo {
    pub address: String,
    pub guardians: Vec<String>,
    /// How many guardians must approve a recovery (e.g. 3 of 5).
    pub threshold: usize,
}

/// An account's in-progress recovery vote — mirrors `/accounts/:address/recovery` (always 200;
/// `pending_approvals` is null when no recovery is under way).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStatus {
    pub address: String,
    #[serde(default)]
    pub recovered_key_fingerprint: Option<String>,
    #[serde(default)]
    pub pending_approvals: Option<usize>,
    #[serde(default)]
    pub threshold: Option<usize>,
}

/// One governance proposal — mirrors the node's `GovernanceProposalResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub proposer: String,
    pub param: String,
    pub new_value: u64,
    #[serde(default)]
    pub created_at_height: u64,
    #[serde(default)]
    pub yes_votes: u64,
    #[serde(default)]
    pub yes_stake_hlx: f64,
    #[serde(default)]
    pub executed: bool,
}

/// The runtime-adjustable protocol parameters — mirrors `/governance/params`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovParams {
    pub min_validator_stake_hlx: f64,
    pub fuel_per_fee_unit: u64,
}

/// The guardian set registered for an address, or `None` when none is (a 404 = "not registered").
pub async fn get_guardians(node: &str, address: &str) -> Result<Option<GuardianInfo>, String> {
    let resp = client()
        .get(format!("{node}/accounts/{address}/guardians"))
        .send()
        .await
        .map_err(err)?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("node returned {} for {address}/guardians", resp.status()));
    }
    resp.json::<GuardianInfo>().await.map(Some).map_err(err)
}

pub async fn get_recovery(node: &str, address: &str) -> Result<RecoveryStatus, String> {
    let resp = client()
        .get(format!("{node}/accounts/{address}/recovery"))
        .send()
        .await
        .map_err(err)?;
    if !resp.status().is_success() {
        return Err(format!("node returned {} for {address}/recovery", resp.status()));
    }
    resp.json::<RecoveryStatus>().await.map_err(err)
}

pub async fn get_proposals(node: &str) -> Result<Vec<Proposal>, String> {
    let value: serde_json::Value = client()
        .get(format!("{node}/governance/proposals"))
        .send()
        .await
        .map_err(err)?
        .json()
        .await
        .map_err(err)?;
    let arr = value.get("proposals").cloned().unwrap_or(serde_json::Value::Array(vec![]));
    serde_json::from_value(arr).map_err(err)
}

pub async fn get_gov_params(node: &str) -> Result<GovParams, String> {
    client()
        .get(format!("{node}/governance/params"))
        .send()
        .await
        .map_err(err)?
        .json::<GovParams>()
        .await
        .map_err(err)
}

/// Count how many of the last `window` blocks this address proposed — the honest "are you actually
/// validating right now?" signal. A wallet is a client and can't see whether you're running a node,
/// but blocks you proposed prove that you are. Returns `(mine, examined)`.
pub async fn recent_proposals(node: &str, address: &str, window: u64) -> Result<(u32, u32), String> {
    let height = get_status(node).await?.height;
    if height == 0 {
        return Ok((0, 0));
    }
    let from = height.saturating_sub(window.saturating_sub(1));
    let count = height - from + 1;
    // `/blocks/range` returns a bare array of the display `BlockResponse`; we only need the proposer.
    #[derive(Deserialize)]
    struct BlockProposer {
        validator: String,
    }
    let blocks: Vec<BlockProposer> = client()
        .get(format!("{node}/blocks/range?from={from}&count={count}"))
        .send()
        .await
        .map_err(err)?
        .json()
        .await
        .map_err(err)?;
    let mine = blocks.iter().filter(|b| b.validator == address).count() as u32;
    Ok((mine, blocks.len() as u32))
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

/// Resolve a `name.hlx` (with or without the suffix) to its owning address, or `None` if it is
/// not registered. A 404 is "not registered", not an error.
pub async fn resolve_name(node: &str, name: &str) -> Result<Option<String>, String> {
    let name = name.trim().trim_end_matches(".hlx");
    let resp = client().get(format!("{node}/names/{name}")).send().await.map_err(err)?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("node returned {} resolving {name}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(err)?;
    Ok(v.get("address").and_then(|a| a.as_str()).map(str::to_string))
}

/// The `.hlx` name registered to an address, if any (`None` when the address has no name).
pub async fn name_of(node: &str, address: &str) -> Result<Option<String>, String> {
    let resp = client().get(format!("{node}/accounts/{address}/name")).send().await.map_err(err)?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("node returned {} for {address}/name", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(err)?;
    Ok(v.get("name").and_then(|a| a.as_str()).map(str::to_string))
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
