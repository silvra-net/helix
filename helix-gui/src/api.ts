import { invoke } from "@tauri-apps/api/core";
import type {
  HistoryEntry,
  NetworkStatus,
  NewWallet,
  Overview,
  SubmitResult,
  WalletMeta,
} from "./types";

// One typed wrapper per Tauri command. Tauri maps camelCase JS args to the snake_case Rust
// parameters (so `amountHlx` reaches `amount_hlx`). Optional values are sent as null, not omitted.
export const api = {
  walletStatus: () => invoke<WalletMeta>("wallet_status"),

  createWallet: (passphrase?: string) =>
    invoke<NewWallet>("create_wallet", { passphrase: passphrase || null }),

  restoreWallet: (mnemonic: string, passphrase?: string) =>
    invoke<string>("restore_wallet", { mnemonic, passphrase: passphrase || null }),

  unlockWallet: (passphrase?: string) =>
    invoke<string>("unlock_wallet", { passphrase: passphrase || null }),

  lockWallet: () => invoke<void>("lock_wallet"),

  getNetwork: (node: string) => invoke<NetworkStatus>("get_network", { node }),

  getOverview: (node: string) => invoke<Overview>("get_overview", { node }),

  getHistory: (node: string, limit = 25) =>
    invoke<HistoryEntry[]>("get_history", { node, limit }),

  sendHlx: (node: string, to: string, amountHlx: number, fee?: number) =>
    invoke<SubmitResult>("send_hlx", { node, to, amountHlx, fee: fee ?? null }),
};

export const DEFAULT_NODE = "https://helix.silvra.net";
