//! Runs a real `helix start` node as a child process of the GUI, so a Helix Wallet install is
//! a complete validator setup on its own — no separate CLI download, no terminal. The binary
//! is bundled as a Tauri "sidecar" (`tauri.conf.json`'s `bundle.externalBin`, built from the
//! same `helix-node` crate the standalone CLI release ships): the exact same node code, not a
//! reimplementation, so its behavior (P2P, consensus, RPC) matches the documented CLI exactly.
//!
//! Output is streamed to the frontend as `node-log` events (one per line) rather than polled,
//! so the console view in `Node.tsx` behaves like a real terminal instead of a slow-refreshing
//! log viewer. `node-exited` fires once, with the exit status, when the process ends on its own
//! (crash, or a clean `node_stop`).

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

#[derive(Default)]
pub struct NodeProcessState {
    child: Mutex<Option<CommandChild>>,
}

#[derive(Clone, Serialize)]
pub struct LogLine {
    /// "stdout" | "stderr" — the console view colors stderr differently, same convention as
    /// a real terminal.
    pub stream: &'static str,
    pub line: String,
}

#[derive(Clone, Serialize)]
pub struct NodeExited {
    pub code: Option<i32>,
}

#[derive(Clone, Copy, Serialize)]
pub struct NodeProcessStatus {
    pub running: bool,
}

#[derive(Deserialize)]
pub struct NodeStartConfig {
    /// Directory the node keeps `validator-key.json`/`helix-data.redb` in. Defaults to the
    /// app's own data directory (same place `wallet.json` lives) if not given — a fresh
    /// install just works without the user ever choosing a path.
    pub data_dir: Option<String>,
    /// Path to an existing key file to run as (typically the wallet's own `wallet.json` —
    /// see `Node.tsx`'s doc comment on why the wallet key doubling as the validator key is
    /// the point, not a shortcut). `None` lets the node generate/load its own
    /// `validator-key.json` in `data_dir` as usual.
    pub validator_key_path: Option<String>,
    /// Passed through as `HELIX_SYNC_PEER` — `None` joins the public network via the
    /// built-in default seed, exactly like running the CLI with no flags.
    pub sync_peer: Option<String>,
}

/// Start `helix start` as a child process, streaming its output as `node-log` events until it
/// exits or `node_stop` kills it. Errors (rather than panicking) if a node is already running
/// under this app instance — one at a time, since two processes racing the same
/// `helix-data.redb` would corrupt it (redb takes an exclusive lock, so the second would just
/// fail to start anyway, but failing here is a clearer message than that).
#[tauri::command]
pub async fn node_start(
    app: AppHandle,
    state: State<'_, NodeProcessState>,
    config: NodeStartConfig,
) -> Result<(), String> {
    {
        let guard = state.child.lock().unwrap();
        if guard.is_some() {
            return Err("a node is already running".into());
        }
    }

    let data_dir = match config.data_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?.join("node");
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            dir
        }
    };

    let mut cmd = app
        .shell()
        .sidecar("helix")
        .map_err(|e| e.to_string())?
        .args(["start"])
        .current_dir(&data_dir);

    if let Some(key_path) = &config.validator_key_path {
        cmd = cmd.env("HELIX_VALIDATOR_KEY", key_path);
    }
    if let Some(peer) = &config.sync_peer {
        cmd = cmd.env("HELIX_SYNC_PEER", peer);
    }

    let (mut rx, child) = cmd.spawn().map_err(|e| {
        log::error!("failed to spawn the bundled node sidecar: {e}");
        e.to_string()
    })?;
    log::info!("local node started, data_dir={}", data_dir.display());
    *state.child.lock().unwrap() = Some(child);

    // Stream output for the lifetime of the process. Runs on Tauri's async runtime, not the
    // command's own call — `node_start` returns as soon as the process is spawned, it doesn't
    // block until exit.
    let app_for_task = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(bytes) => {
                    let _ = app_for_task.emit(
                        "node-log",
                        LogLine { stream: "stdout", line: String::from_utf8_lossy(&bytes).to_string() },
                    );
                }
                CommandEvent::Stderr(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).to_string();
                    // Persisted (unlike stdout, which the live console already covers and which
                    // would otherwise flood the app log with a routine "Block committed" line
                    // every ~2s) — stderr is the node's own signal that something is off, and is
                    // exactly what's missing after the fact if nobody was watching the console
                    // tab when it happened.
                    log::warn!("[node stderr] {text}");
                    let _ = app_for_task.emit("node-log", LogLine { stream: "stderr", line: text });
                }
                CommandEvent::Terminated(payload) => {
                    if let Some(state) = app_for_task.try_state::<NodeProcessState>() {
                        *state.child.lock().unwrap() = None;
                    }
                    log::info!("local node exited, code={:?}", payload.code);
                    let _ = app_for_task.emit("node-exited", NodeExited { code: payload.code });
                }
                _ => {}
            }
        }
    });

    Ok(())
}

/// Kill the running node, if any. A no-op (not an error) if none is running — the frontend
/// calls this unconditionally on app shutdown, and a running-but-not-tracked-here node
/// shouldn't happen but "stop" being idempotent is the safer default regardless.
#[tauri::command]
pub fn node_stop(state: State<'_, NodeProcessState>) -> Result<(), String> {
    let child = state.child.lock().unwrap().take();
    if let Some(child) = child {
        child.kill().map_err(|e| {
            log::error!("failed to kill the local node process: {e}");
            e.to_string()
        })?;
        log::info!("local node stopped by user");
    }
    Ok(())
}

#[tauri::command]
pub fn node_process_status(state: State<'_, NodeProcessState>) -> NodeProcessStatus {
    NodeProcessStatus { running: state.child.lock().unwrap().is_some() }
}
