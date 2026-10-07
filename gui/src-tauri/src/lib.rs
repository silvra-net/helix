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
        .plugin(
            tauri_plugin_log::Builder::new()
                // File + stdout, not the webview target — this is a diagnostic trail for a
                // human to read later (or attach to a bug report), not something the frontend
                // is meant to poll. The Node tab's own live console (node_process.rs) already
                // covers "watch this in real time".
                .target(tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::LogDir {
                    file_name: None,
                }))
                .target(tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Stdout))
                .level(log::LevelFilter::Info)
                // Keep a handful of past runs instead of one file that grows forever or gets
                // silently truncated on the crash that's actually worth reading about.
                .max_file_size(5_000_000)
                .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepAll)
                .build(),
        )
        .manage(WalletState::default())
        .manage(NodeProcessState::default())
        .setup(|app| {
            // The idle lock is enforced here, not in the webview — see `WalletState`. A plain
            // thread rather than a task on the async runtime: it must keep sweeping however busy
            // that runtime is, and it needs nothing from it.
            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("wallet-idle-lock".into())
                .spawn(move || loop {
                    std::thread::sleep(state::IDLE_SWEEP_EVERY);
                    use tauri::{Emitter, Manager};
                    if handle.state::<WalletState>().lock_if_idle() {
                        let minutes = state::IDLE_LOCK_AFTER.as_secs() / 60;
                        log::info!("wallet locked itself after {minutes} minutes without use");
                        let _ = handle.emit(state::WALLET_LOCKED_EVENT, minutes);
                    }
                })?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            node_process::node_start,
            node_process::node_stop,
            node_process::node_process_status,
            node_process::node_reset_chain,
            commands::wallet_status,
            commands::create_wallet,
            commands::restore_wallet,
            commands::unlock_wallet,
            commands::lock_wallet,
            commands::change_passphrase,
            commands::touch_wallet,
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
            commands::set_reward_address,
            commands::get_delegations,
            commands::get_validator_pool,
            commands::list_validators,
            commands::register_name,
            commands::name_price,
            commands::resolve_name,
            commands::my_name,
            commands::reveal_mnemonic,
            commands::my_public_key,
            commands::is_valid_address,
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
            commands::log_dir_path,
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

#[cfg(test)]
mod command_names {
    /// Every command name lives twice — registered here, invoked by name in `api.ts` — and a typo
    /// on either side compiles on both, then fails only when someone clicks the button. The two
    /// lists must be the same list.
    #[test]
    fn the_frontend_invokes_exactly_the_commands_registered_here() {
        use std::collections::BTreeSet;
        let lib = include_str!("lib.rs");
        let start = lib.find("generate_handler![").expect("the handler list");
        let end = start + lib[start..].find("])").expect("its end");
        let registered: BTreeSet<&str> = lib[start + "generate_handler![".len()..end]
            .split(',')
            .filter_map(|entry| entry.trim().rsplit("::").next())
            .filter(|name| !name.is_empty())
            .collect();

        let api = include_str!("../../src/api.ts");
        let invoked: BTreeSet<&str> = api
            .split("invoke<")
            .skip(1)
            .filter_map(|rest| rest.split("(\"").nth(1)?.split('"').next())
            .collect();

        // Positive control: both parsers found the lists at all.
        assert!(registered.len() >= 40, "registered: {registered:?}");
        assert!(invoked.len() >= 40, "invoked: {invoked:?}");
        let unknown: Vec<_> = invoked.difference(&registered).collect();
        let unused: Vec<_> = registered.difference(&invoked).collect();
        assert!(unknown.is_empty(), "api.ts invokes commands nobody registered: {unknown:?}");
        assert!(unused.is_empty(), "registered commands api.ts never invokes: {unused:?}");
    }
}

#[cfg(test)]
mod response_fields {
    /// Every field the frontend reads must survive the Rust struct it passes through.
    ///
    /// The webview never sees a node's answer directly: a command deserializes it into a struct
    /// here and serializes that struct again, so any field the struct does not name is dropped
    /// without a word. On 2026-08-27 the node gained `quorum_stake_hlx` and `expires_at_height`,
    /// `types.ts` and the governance view gained them too — and `rpc::Proposal` did not. The view
    /// then called `.toLocaleString()` on a missing number. `sync_target_height` went the same
    /// way, so the "catching up" banner could never appear. The TypeScript tests passed objects
    /// built by hand and never went through this crate, which is how both stayed unseen.
    ///
    /// The rule: an interface in `types.ts` that shares its name with a struct here lists no field
    /// the struct lacks. Fields only the struct has are fine.
    #[test]
    fn every_field_the_frontend_reads_passes_through_the_backend() {
        let ts = include_str!("../../src/types.ts");
        let sources = [
            include_str!("rpc.rs"),
            include_str!("commands.rs"),
            include_str!("node_process.rs"),
            include_str!("state.rs"),
            include_str!("wallet.rs"),
            include_str!("pricing.rs"),
        ];
        let mut compared = 0;
        let mut gaps = Vec::new();
        for block in ts.split("export interface ").skip(1) {
            let name = block.split_whitespace().next().unwrap_or("");
            let body = block.split_once('{').map(|(_, b)| b).unwrap_or("");
            let body = body.split("\n}").next().unwrap_or("");
            let fields: Vec<&str> = body
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with("//") && !l.starts_with('*') && !l.starts_with("/*"))
                .filter_map(|l| l.split_once(':').map(|(f, _)| f.trim_end_matches('?')))
                .filter(|f| !f.is_empty() && f.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                .collect();
            let needle = format!("pub struct {name} {{");
            let Some(src) = sources.iter().find(|s| s.contains(&needle)) else { continue };
            let start = src.find(&needle).unwrap() + needle.len();
            let end = start + src[start..].find("\n}").expect("struct end");
            let rust = &src[start..end];
            assert!(
                !rust.contains("serde(rename"),
                "{name} renames a field; this test compares names and would need to know"
            );
            compared += 1;
            for field in fields {
                if !rust.contains(&format!("pub {field}:")) {
                    gaps.push(format!("{name}.{field}"));
                }
            }
        }
        // Positive control: the parsers found the pairs at all.
        assert!(compared >= 15, "only {compared} interfaces matched a struct");
        assert!(gaps.is_empty(), "types.ts reads fields the backend drops: {gaps:?}");
    }
}
