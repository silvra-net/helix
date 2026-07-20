//! The Tauri command surface — everything the React frontend can call.
//!
//! The security boundary lives here: the frontend passes a node URL, a passphrase to unlock, an
//! amount to send — and gets back addresses, balances, and statuses. It never receives key bytes.
//! Signing happens under a short synchronous lock (never held across an `.await`) using the
//! `KeyPair` kept in `WalletState`.

use std::path::PathBuf;

use helix_core::TxType;
use helix_crypto::Address;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::pricing;
use crate::rpc;
use crate::state::{UnlockedWallet, WalletState};
use crate::wallet;

/// `wallet.json` under the app's data dir. Created on demand so a fresh install just works.
fn wallet_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("wallet.json"))
}

#[derive(Serialize)]
pub struct WalletMeta {
    /// A wallet file exists on disk.
    pub exists: bool,
    /// It is decrypted and held in memory this session.
    pub unlocked: bool,
    /// True when a file exists but needs a passphrase to unlock.
    pub encrypted: bool,
    pub address: Option<String>,
}

#[derive(Serialize)]
pub struct NewWallet {
    pub address: String,
    /// The 24 words — returned exactly once, for the user to write down. Not stored anywhere.
    pub mnemonic: String,
}

#[derive(Serialize)]
pub struct Overview {
    pub address: String,
    pub balance_hlx: f64,
    pub staked_hlx: f64,
    pub unbonding_hlx: f64,
    pub unbonding_unlock_height: u64,
    pub unbonding_source: Option<String>,
    pub nonce: u64,
    pub jailed_until: Option<u64>,
    pub missed_blocks: Option<u32>,
}

#[tauri::command]
pub fn wallet_status(app: AppHandle, state: State<'_, WalletState>) -> Result<WalletMeta, String> {
    let path = wallet_path(&app)?;
    let exists = wallet::exists_at(&path);
    let unlocked_addr = state.address();
    Ok(WalletMeta {
        exists,
        unlocked: unlocked_addr.is_some(),
        encrypted: exists && wallet::is_encrypted_at(&path).unwrap_or(false),
        address: unlocked_addr,
    })
}

#[tauri::command]
pub fn create_wallet(app: AppHandle, state: State<'_, WalletState>, passphrase: Option<String>) -> Result<NewWallet, String> {
    let path = wallet_path(&app)?;
    if wallet::exists_at(&path) {
        return Err("a wallet already exists — remove it before creating a new one".into());
    }
    // Never log `passphrase`/the mnemonic — only that creation succeeded or failed, and why,
    // same discipline as every other wallet command below.
    let created = wallet::create_at(&path, passphrase.as_deref()).inspect_err(|e| {
        log::error!("wallet creation failed: {e}");
    })?;
    let address = created.address.clone();
    let mnemonic = created.mnemonic.clone();
    log::info!("wallet created: {address}");
    *state.inner.lock().unwrap() = Some(UnlockedWallet { keypair: created.keypair, address: address.clone() });
    Ok(NewWallet { address, mnemonic })
}

#[tauri::command]
pub fn restore_wallet(app: AppHandle, state: State<'_, WalletState>, mnemonic: String, passphrase: Option<String>) -> Result<String, String> {
    let path = wallet_path(&app)?;
    let (keypair, address) = wallet::restore_at(&path, &mnemonic, passphrase.as_deref()).inspect_err(|e| {
        log::error!("wallet restore failed: {e}");
    })?;
    log::info!("wallet restored: {address}");
    *state.inner.lock().unwrap() = Some(UnlockedWallet { keypair, address: address.clone() });
    Ok(address)
}

#[tauri::command]
pub fn unlock_wallet(app: AppHandle, state: State<'_, WalletState>, passphrase: Option<String>) -> Result<String, String> {
    let path = wallet_path(&app)?;
    // The most common "why won't this work" support question in practice (wrong passphrase,
    // a wallet.json copied over from elsewhere) — worth its own line rather than relying on
    // the generic tx-submission logging below, which this never reaches if unlock fails.
    let (keypair, address) = wallet::load_at(&path, passphrase.as_deref()).inspect_err(|e| {
        log::error!("wallet unlock failed: {e}");
    })?;
    log::info!("wallet unlocked: {address}");
    *state.inner.lock().unwrap() = Some(UnlockedWallet { keypair, address: address.clone() });
    Ok(address)
}

#[tauri::command]
pub fn lock_wallet(state: State<'_, WalletState>) {
    *state.inner.lock().unwrap() = None;
}

/// Where `tauri-plugin-log` is writing the app's log file — shown (with a copy button) in
/// Settings, so "something went wrong" has an actual answer to "where do I even look" beyond
/// the transient in-app error toast. The one thing this app can't self-diagnose is itself not
/// starting at all; a fixed, documented location is what makes that reportable too.
#[tauri::command]
pub fn log_dir_path(app: AppHandle) -> Result<String, String> {
    Ok(app.path().app_log_dir().map_err(|e| e.to_string())?.display().to_string())
}

#[tauri::command]
pub async fn get_network(node: String) -> Result<rpc::NetworkStatus, String> {
    rpc::get_status(&node).await
}

#[tauri::command]
pub async fn get_overview(state: State<'_, WalletState>, node: String) -> Result<Overview, String> {
    let address = state.address().ok_or("wallet is locked")?;
    let account = rpc::get_account(&node, &address).await?;
    Ok(Overview {
        address: account.address,
        balance_hlx: account.balance_hlx,
        staked_hlx: account.staked_hlx,
        unbonding_hlx: account.unbonding_stake_hlx,
        unbonding_unlock_height: account.unbonding_unlock_height,
        unbonding_source: account.unbonding_source,
        nonce: account.nonce,
        jailed_until: account.jailed_until,
        missed_blocks: account.missed_blocks,
    })
}

#[tauri::command]
pub async fn get_history(state: State<'_, WalletState>, node: String, limit: Option<u32>) -> Result<Vec<rpc::HistoryEntry>, String> {
    let address = state.address().ok_or("wallet is locked")?;
    rpc::get_history(&node, &address, limit.unwrap_or(25)).await
}

/// The one place a transaction is built, priced, signed, and submitted — every send/stake/
/// delegate command funnels through here. Async fetches (nonce, base fee) run without the lock;
/// signing happens under a short synchronous lock that is never held across an `.await`.
async fn build_sign_submit(
    state: &WalletState,
    node: &str,
    tx_type: TxType,
    to: Option<Address>,
    amount: u64,
    data: Vec<u8>,
    fee: Option<u64>,
) -> Result<rpc::SubmitResult, String> {
    let from_str = state.address().ok_or("wallet is locked")?;
    let from = Address::from_str(&from_str).map_err(|e| e.to_string())?;

    let nonce = rpc::fetch_nonce(node, &from_str).await;
    let base_fee = match fee {
        Some(_) => 0,
        None => rpc::fetch_base_fee(node).await?,
    };

    // Captured before `tx_type` moves into `build_tx` below — just for the log line, so it
    // doesn't need `TxType: Copy`/an extra clone of anything bigger.
    let tx_type_label = format!("{tx_type:?}");

    let signed = {
        let guard = state.inner.lock().unwrap();
        let wallet = guard.as_ref().ok_or("wallet is locked")?;
        let mut tx = pricing::build_tx(tx_type, from, to, amount, nonce, data, &wallet.keypair);
        pricing::finalize_and_sign(&mut tx, fee, base_fee, &wallet.keypair)?;
        tx
    };

    // Central logging point for every transaction command (send, stake, delegate, unjail,
    // governance, …) rather than one call per command — this is the one place they all
    // actually go through, so it's also the one place that needs a log line to cover all of
    // them without touching every command individually.
    match rpc::submit_tx(node, &signed).await {
        Ok(result) => {
            log::info!("tx {tx_type_label} submitted: {} ({})", result.tx_hash, result.status);
            Ok(result)
        }
        Err(e) => {
            log::error!("tx {tx_type_label} submission failed: {e}");
            Err(e)
        }
    }
}

fn parse_validator(addr: &str) -> Result<Address, String> {
    Address::from_str(addr).map_err(|_| format!("'{addr}' is not a valid validator address"))
}

/// A recipient may be an `hlx…` address or a `name.hlx` — resolve names to an address first.
async fn resolve_recipient(node: &str, to: &str) -> Result<Address, String> {
    if let Ok(addr) = Address::from_str(to) {
        return Ok(addr);
    }
    match rpc::resolve_name(node, to).await? {
        Some(addr) => Address::from_str(&addr).map_err(|e| e.to_string()),
        None => Err(format!("'{to}' is neither a valid address nor a registered name")),
    }
}

#[tauri::command]
pub async fn send_hlx(state: State<'_, WalletState>, node: String, to: String, amount_hlx: f64, fee: Option<u64>) -> Result<rpc::SubmitResult, String> {
    let to_addr = resolve_recipient(&node, &to).await?;
    let amount = pricing::hlx_to_nano(amount_hlx)?;
    build_sign_submit(&state, &node, TxType::Transfer, Some(to_addr), amount, vec![], fee).await
}

// ---------- names ----------

#[tauri::command]
pub async fn register_name(state: State<'_, WalletState>, node: String, name: String) -> Result<rpc::SubmitResult, String> {
    // Registered without the .hlx suffix (the chain stores the bare name).
    let name = name.trim().trim_end_matches(".hlx").to_string();
    if name.is_empty() {
        return Err("enter a name".into());
    }
    build_sign_submit(&state, &node, TxType::RegisterName, None, 0, name.into_bytes(), None).await
}

#[tauri::command]
pub async fn resolve_name(node: String, name: String) -> Result<Option<String>, String> {
    rpc::resolve_name(&node, &name).await
}

/// The `.hlx` name registered to the unlocked wallet's address, if any.
#[tauri::command]
pub async fn my_name(state: State<'_, WalletState>, node: String) -> Result<Option<String>, String> {
    let address = state.address().ok_or("wallet is locked")?;
    rpc::name_of(&node, &address).await
}

// ---------- staking ----------

#[tauri::command]
pub async fn stake(state: State<'_, WalletState>, node: String, amount_hlx: f64) -> Result<rpc::SubmitResult, String> {
    let amount = pricing::hlx_to_nano(amount_hlx)?;
    build_sign_submit(&state, &node, TxType::Stake, None, amount, vec![], None).await
}

#[tauri::command]
pub async fn unstake(state: State<'_, WalletState>, node: String, amount_hlx: f64) -> Result<rpc::SubmitResult, String> {
    let amount = pricing::hlx_to_nano(amount_hlx)?;
    build_sign_submit(&state, &node, TxType::Unstake, None, amount, vec![], None).await
}

#[tauri::command]
pub async fn claim_unbonded(state: State<'_, WalletState>, node: String) -> Result<rpc::SubmitResult, String> {
    build_sign_submit(&state, &node, TxType::ClaimUnbonded, None, 0, vec![], None).await
}

/// Rejoin the active validator set after downtime-jailing — see `helix_account.jailed_until`
/// (surfaced in `Overview`/`ValidatorStatus`) for whether this account is currently jailed and
/// the height it can submit this from. Deliberately explicit, not automatic — see
/// `TxType::Unjail`'s doc comment.
#[tauri::command]
pub async fn unjail(state: State<'_, WalletState>, node: String) -> Result<rpc::SubmitResult, String> {
    build_sign_submit(&state, &node, TxType::Unjail, None, 0, vec![], None).await
}

#[tauri::command]
pub async fn delegate(state: State<'_, WalletState>, node: String, validator: String, amount_hlx: f64) -> Result<rpc::SubmitResult, String> {
    let v = parse_validator(&validator)?;
    let amount = pricing::hlx_to_nano(amount_hlx)?;
    build_sign_submit(&state, &node, TxType::Delegate, Some(v), amount, vec![], None).await
}

#[tauri::command]
pub async fn undelegate(state: State<'_, WalletState>, node: String, validator: String, amount_hlx: f64) -> Result<rpc::SubmitResult, String> {
    let v = parse_validator(&validator)?;
    let amount = pricing::hlx_to_nano(amount_hlx)?;
    build_sign_submit(&state, &node, TxType::Undelegate, Some(v), amount, vec![], None).await
}

#[tauri::command]
pub async fn redelegate(state: State<'_, WalletState>, node: String, from_validator: String, to_validator: String, amount_hlx: f64) -> Result<rpc::SubmitResult, String> {
    let src = parse_validator(&from_validator)?;
    let dst = parse_validator(&to_validator)?;
    let amount = pricing::hlx_to_nano(amount_hlx)?;
    // The destination rides in `to`; the source travels in `data` as its address string —
    // this is the one transaction that names two validators (mirrors the CLI).
    build_sign_submit(&state, &node, TxType::Redelegate, Some(dst), amount, src.to_string().into_bytes(), None).await
}

#[tauri::command]
pub async fn set_commission(state: State<'_, WalletState>, node: String, bps: u16) -> Result<rpc::SubmitResult, String> {
    // Commission rate as 2 little-endian bytes (basis points), same encoding the executor reads.
    build_sign_submit(&state, &node, TxType::SetCommission, None, 0, bps.to_le_bytes().to_vec(), None).await
}

#[tauri::command]
pub async fn get_delegations(state: State<'_, WalletState>, node: String) -> Result<Vec<rpc::Delegation>, String> {
    let address = state.address().ok_or("wallet is locked")?;
    rpc::get_delegations(&node, &address).await
}

#[tauri::command]
pub async fn get_validator_pool(state: State<'_, WalletState>, node: String) -> Result<rpc::ValidatorPool, String> {
    let address = state.address().ok_or("wallet is locked")?;
    rpc::get_validator_pool(&node, &address).await
}

// ---------- settings / backup ----------

/// Re-derive and return the 24-word recovery phrase, re-authenticating with the passphrase. This
/// is the deliberate "reveal" path (a wallet made before you wrote the words down would otherwise
/// have no backup) — distinct from the one-time reveal at creation. The words are shown in the UI
/// and never persisted.
#[tauri::command]
pub fn reveal_mnemonic(app: AppHandle, passphrase: Option<String>) -> Result<String, String> {
    let path = wallet_path(&app)?;
    wallet::reveal_mnemonic_at(&path, passphrase.as_deref())
}

/// The unlocked wallet's ML-DSA public key as hex — what a guardian needs from you to approve
/// rotating your account to a new key during social recovery.
#[tauri::command]
pub fn my_public_key(state: State<'_, WalletState>) -> Result<String, String> {
    let guard = state.inner.lock().unwrap();
    let wallet = guard.as_ref().ok_or("wallet is locked")?;
    Ok(hex::encode(wallet.keypair.public.as_bytes()))
}

// ---------- social recovery ----------

/// Register (or replace) your guardian set. The chain derives the approval threshold from the set
/// size (e.g. 3 of 5); 3–10 guardians. Encoded exactly as the CLI does: newline-joined addresses.
#[tauri::command]
pub async fn register_guardians(state: State<'_, WalletState>, node: String, guardians: Vec<String>) -> Result<rpc::SubmitResult, String> {
    let cleaned: Vec<String> = guardians.iter().map(|g| g.trim().to_string()).filter(|g| !g.is_empty()).collect();
    if cleaned.len() < 3 || cleaned.len() > 10 {
        return Err(format!("choose between 3 and 10 guardians (you gave {})", cleaned.len()));
    }
    for g in &cleaned {
        Address::from_str(g).map_err(|_| format!("'{g}' is not a valid guardian address"))?;
    }
    build_sign_submit(&state, &node, TxType::RegisterGuardians, None, 0, cleaned.join("\n").into_bytes(), None).await
}

/// As a registered guardian, approve rotating a lost account (`target`) to a `new_public_key`
/// (hex ML-DSA key the recovering owner shares with you). The target rides in `to`, the key in
/// `data` — same as the CLI.
#[tauri::command]
pub async fn approve_recovery(state: State<'_, WalletState>, node: String, target: String, new_public_key: String) -> Result<rpc::SubmitResult, String> {
    let target_addr = Address::from_str(target.trim()).map_err(|_| format!("'{target}' is not a valid address"))?;
    let key_bytes = hex::decode(new_public_key.trim()).map_err(|_| "the new public key is not valid hex".to_string())?;
    if key_bytes.is_empty() {
        return Err("enter the recovering account's new public key".into());
    }
    build_sign_submit(&state, &node, TxType::ApproveRecovery, Some(target_addr), 0, key_bytes, None).await
}

/// Cancel your own pending (sub-threshold) recovery request — the escape hatch that keeps a single
/// guardian from locking you out with one stray approval. Signed with your current key; no payload.
#[tauri::command]
pub async fn cancel_recovery(state: State<'_, WalletState>, node: String) -> Result<rpc::SubmitResult, String> {
    build_sign_submit(&state, &node, TxType::CancelRecoveryRequest, None, 0, vec![], None).await
}

#[tauri::command]
pub async fn get_guardians(state: State<'_, WalletState>, node: String) -> Result<Option<rpc::GuardianInfo>, String> {
    let address = state.address().ok_or("wallet is locked")?;
    rpc::get_guardians(&node, &address).await
}

/// Recovery status for any address — your own, or one you're a guardian for and being asked to help.
#[tauri::command]
pub async fn get_recovery(node: String, address: String) -> Result<rpc::RecoveryStatus, String> {
    let addr = Address::from_str(address.trim()).map_err(|_| format!("'{address}' is not a valid address"))?;
    rpc::get_recovery(&node, &addr.to_string()).await
}

// ---------- governance ----------

/// Which runtime parameter a proposal changes — the u8 tag the executor's `encode_proposal` reads
/// (0 = min validator stake, 1 = fuel per fee unit). Replicated here (9-byte payload) rather than
/// pulling in `helix-executor`; the encoding is consensus-stable.
fn governance_param_tag(param: &str) -> Result<u8, String> {
    match param {
        "min_validator_stake" => Ok(0),
        "fuel_per_fee_unit" => Ok(1),
        other => Err(format!("unknown governance parameter '{other}'")),
    }
}

#[tauri::command]
pub async fn create_proposal(state: State<'_, WalletState>, node: String, param: String, new_value: u64) -> Result<rpc::SubmitResult, String> {
    let mut data = Vec::with_capacity(9);
    data.push(governance_param_tag(&param)?);
    data.extend_from_slice(&new_value.to_le_bytes());
    build_sign_submit(&state, &node, TxType::CreateProposal, None, 0, data, None).await
}

/// Cast a stake-weighted yes-vote on a pending proposal (governance is yes-vote-to-quorum; there
/// is no "no"). Payload is the proposal id as 8 little-endian bytes, like `encode_vote`.
#[tauri::command]
pub async fn vote_proposal(state: State<'_, WalletState>, node: String, proposal_id: u64) -> Result<rpc::SubmitResult, String> {
    build_sign_submit(&state, &node, TxType::VoteProposal, None, 0, proposal_id.to_le_bytes().to_vec(), None).await
}

#[tauri::command]
pub async fn get_proposals(node: String) -> Result<Vec<rpc::Proposal>, String> {
    rpc::get_proposals(&node).await
}

#[tauri::command]
pub async fn get_gov_params(node: String) -> Result<rpc::GovParams, String> {
    rpc::get_gov_params(&node).await
}

// ---------- node / validator panel ----------

/// Everything the Node panel needs about *this wallet's* standing as a validator: how its stake
/// compares to the entry threshold, and whether it is actually producing blocks (proof it's
/// running a node). The network-wide status — height, peers, sync — comes from `get_network`.
#[derive(Serialize)]
pub struct ValidatorStatus {
    pub self_staked_hlx: f64,
    pub delegated_stake_hlx: f64,
    pub effective_stake_hlx: f64,
    pub commission_bps: Option<u16>,
    pub min_validator_stake_hlx: f64,
    /// Effective stake meets the entry threshold. Necessary to validate, but not sufficient — you
    /// must also run a node with this key (see `blocks_proposed`).
    pub eligible: bool,
    /// How many of the last `window` blocks this address actually proposed.
    pub blocks_proposed: u32,
    pub window: u32,
}

#[tauri::command]
pub async fn get_validator_status(state: State<'_, WalletState>, node: String) -> Result<ValidatorStatus, String> {
    let address = state.address().ok_or("wallet is locked")?;
    let pool = rpc::get_validator_pool(&node, &address).await?;
    let params = rpc::get_gov_params(&node).await?;
    // Block activity is a nice-to-have signal, never a reason to fail the whole panel.
    let (blocks_proposed, window) = rpc::recent_proposals(&node, &address, 20).await.unwrap_or((0, 0));
    Ok(ValidatorStatus {
        self_staked_hlx: pool.self_staked_hlx,
        delegated_stake_hlx: pool.delegated_stake_hlx,
        effective_stake_hlx: pool.effective_stake_hlx,
        commission_bps: pool.commission_bps,
        min_validator_stake_hlx: params.min_validator_stake_hlx,
        eligible: pool.effective_stake_hlx >= params.min_validator_stake_hlx,
        blocks_proposed,
        window,
    })
}
