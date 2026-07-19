//! Helix Wallet — Tauri backend.
//!
//! Stage 1 (SA1–SA3 of backlog #83): connect to a node, show balance and history, receive, and
//! send a locally-signed transfer. Staking / names / governance are the next stages and slot in
//! as more commands + views without changing this shape.

mod commands;
mod pricing;
mod rpc;
mod state;
mod wallet;

use state::WalletState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(WalletState::default())
        .invoke_handler(tauri::generate_handler![
            commands::wallet_status,
            commands::create_wallet,
            commands::restore_wallet,
            commands::unlock_wallet,
            commands::lock_wallet,
            commands::get_network,
            commands::get_overview,
            commands::get_history,
            commands::send_hlx,
            commands::stake,
            commands::unstake,
            commands::claim_unbonded,
            commands::delegate,
            commands::undelegate,
            commands::redelegate,
            commands::set_commission,
            commands::get_delegations,
            commands::get_validator_pool,
            commands::register_name,
            commands::resolve_name,
            commands::my_name,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Helix Wallet");
}
