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
        nonce: account.nonce,
    })
}

#[tauri::command]
pub async fn get_history(state: State<'_, WalletState>, node: String, limit: Option<u32>) -> Result<Vec<rpc::HistoryEntry>, String> {
    let address = state.address().ok_or("wallet is locked")?;
    rpc::get_history(&node, &address, limit.unwrap_or(25)).await
}

#[tauri::command]
pub async fn send_hlx(state: State<'_, WalletState>, node: String, to: String, amount_hlx: f64, fee: Option<u64>) -> Result<rpc::SubmitResult, String> {
    let from_addr_str = state.address().ok_or("wallet is locked")?;
    let from = Address::from_str(&from_addr_str).map_err(|e| e.to_string())?;
    let to_addr = Address::from_str(&to).map_err(|_| format!("'{to}' is not a valid Helix address"))?;
    let amount = pricing::hlx_to_nano(amount_hlx)?;

    // Async work first, without the lock: the current nonce and (unless pinned) the base fee.
    let nonce = rpc::fetch_nonce(&node, &from_addr_str).await;
    let base_fee = match fee {
        Some(_) => 0,
        None => rpc::fetch_base_fee(&node).await?,
    };

    // Build + sign under a short synchronous lock — the guard is dropped before the next await.
    let signed = {
        let guard = state.inner.lock().unwrap();
        let wallet = guard.as_ref().ok_or("wallet is locked")?;
        let mut tx = pricing::build_tx(TxType::Transfer, from, Some(to_addr), amount, nonce, vec![], &wallet.keypair);
        pricing::finalize_and_sign(&mut tx, fee, base_fee, &wallet.keypair)?;
        tx
    };

    rpc::submit_tx(&node, &signed).await
}
