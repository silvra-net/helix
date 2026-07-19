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
    let created = wallet::create_at(&path, passphrase.as_deref())?;
    let address = created.address.clone();
    let mnemonic = created.mnemonic.clone();
    *state.inner.lock().unwrap() = Some(UnlockedWallet { keypair: created.keypair, address: address.clone() });
    Ok(NewWallet { address, mnemonic })
}

#[tauri::command]
pub fn restore_wallet(app: AppHandle, state: State<'_, WalletState>, mnemonic: String, passphrase: Option<String>) -> Result<String, String> {
    let path = wallet_path(&app)?;
    let (keypair, address) = wallet::restore_at(&path, &mnemonic, passphrase.as_deref())?;
    *state.inner.lock().unwrap() = Some(UnlockedWallet { keypair, address: address.clone() });
    Ok(address)
}

#[tauri::command]
pub fn unlock_wallet(app: AppHandle, state: State<'_, WalletState>, passphrase: Option<String>) -> Result<String, String> {
    let path = wallet_path(&app)?;
    let (keypair, address) = wallet::load_at(&path, passphrase.as_deref())?;
    *state.inner.lock().unwrap() = Some(UnlockedWallet { keypair, address: address.clone() });
    Ok(address)
}

#[tauri::command]
pub fn lock_wallet(state: State<'_, WalletState>) {
    *state.inner.lock().unwrap() = None;
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

    let signed = {
        let guard = state.inner.lock().unwrap();
        let wallet = guard.as_ref().ok_or("wallet is locked")?;
        let mut tx = pricing::build_tx(tx_type, from, to, amount, nonce, data, &wallet.keypair);
        pricing::finalize_and_sign(&mut tx, fee, base_fee, &wallet.keypair)?;
        tx
    };

    rpc::submit_tx(node, &signed).await
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
