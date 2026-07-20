//! Helix Wallet — Tauri backend.
//!
//! Connect to a node, show balance and history, receive, and send locally-signed transactions:
//! transfers, staking/delegation, `.hlx` names, social recovery (guardians) and governance.
//! Every command hands the frontend addresses, amounts and statuses — the `KeyPair` that signs
//! never leaves this backend. New features slot in as more commands + views without changing this
//! shape.

mod commands;
mod node_process;
mod pricing;
mod rpc;
mod state;
mod wallet;

use node_process::NodeProcessState;
use state::WalletState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(WalletState::default())
        .manage(NodeProcessState::default())
        .invoke_handler(tauri::generate_handler![
            node_process::node_start,
            node_process::node_stop,
            node_process::node_process_status,
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
            commands::reveal_mnemonic,
            commands::my_public_key,
            commands::register_guardians,
            commands::approve_recovery,
            commands::cancel_recovery,
            commands::get_guardians,
            commands::get_recovery,
            commands::create_proposal,
            commands::vote_proposal,
            commands::get_proposals,
            commands::get_gov_params,
            commands::get_validator_status,
            commands::unjail,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Helix Wallet")
        .run(|app_handle, event| {
            // A node started from this app is this app's responsibility to stop — otherwise
            // closing the window leaves a validator process running invisibly in the
            // background, still holding the redb lock, until the user finds and kills it
            // manually (or it's still there next launch, blocking a fresh start).
            if let tauri::RunEvent::Exit = event {
                use tauri::Manager;
                let _ = node_process::node_stop(app_handle.state::<NodeProcessState>());
            }
        });
}
