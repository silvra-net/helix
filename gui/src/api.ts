import { invoke } from "@tauri-apps/api/core";
import type {
  Delegation,
  HistoryEntry,
  NetworkStatus,
  NewWallet,
  Overview,
  SubmitResult,
  ValidatorPool,
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

  // staking / delegation
  stake: (node: string, amountHlx: number) =>
    invoke<SubmitResult>("stake", { node, amountHlx }),

  unstake: (node: string, amountHlx: number) =>
    invoke<SubmitResult>("unstake", { node, amountHlx }),

  claimUnbonded: (node: string) => invoke<SubmitResult>("claim_unbonded", { node }),

  delegate: (node: string, validator: string, amountHlx: number) =>
    invoke<SubmitResult>("delegate", { node, validator, amountHlx }),

  undelegate: (node: string, validator: string, amountHlx: number) =>
    invoke<SubmitResult>("undelegate", { node, validator, amountHlx }),

  redelegate: (node: string, fromValidator: string, toValidator: string, amountHlx: number) =>
    invoke<SubmitResult>("redelegate", { node, fromValidator, toValidator, amountHlx }),

  setCommission: (node: string, bps: number) =>
    invoke<SubmitResult>("set_commission", { node, bps }),

  getDelegations: (node: string) => invoke<Delegation[]>("get_delegations", { node }),

  getValidatorPool: (node: string) => invoke<ValidatorPool>("get_validator_pool", { node }),

  // names
  registerName: (node: string, name: string) =>
    invoke<SubmitResult>("register_name", { node, name }),

  resolveName: (node: string, name: string) =>
    invoke<string | null>("resolve_name", { node, name }),

  myName: (node: string) => invoke<string | null>("my_name", { node }),
};

export const DEFAULT_NODE = "https://helix.silvra.net";
