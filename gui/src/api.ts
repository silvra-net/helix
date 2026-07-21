import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  Delegation,
  GovParams,
  GuardianInfo,
  HistoryEntry,
  LogLine,
  NetworkStatus,
  NewWallet,
  NodeExited,
  NodeProcessStatus,
  NodeStartConfig,
  Overview,
  Proposal,
  RecoveryStatus,
  SubmitResult,
  ValidatorPool,
  ValidatorStatus,
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

  // settings / backup
  revealMnemonic: (passphrase?: string) =>
    invoke<string>("reveal_mnemonic", { passphrase: passphrase || null }),

  myPublicKey: () => invoke<string>("my_public_key"),

  // Full address check including the checksum — the frontend cannot do this itself (base58 +
  // double-BLAKE3). Pure decoding, no network, safe to call while typing.
  isValidAddress: (candidate: string) => invoke<boolean>("is_valid_address", { candidate }),

  // social recovery
  registerGuardians: (node: string, guardians: string[]) =>
    invoke<SubmitResult>("register_guardians", { node, guardians }),

  approveRecovery: (node: string, target: string, newPublicKey: string) =>
    invoke<SubmitResult>("approve_recovery", { node, target, newPublicKey }),

  cancelRecovery: (node: string) => invoke<SubmitResult>("cancel_recovery", { node }),

  getGuardians: (node: string) => invoke<GuardianInfo | null>("get_guardians", { node }),

  getRecovery: (node: string, address: string) =>
    invoke<RecoveryStatus>("get_recovery", { node, address }),

  // governance
  createProposal: (node: string, param: string, newValue: number) =>
    invoke<SubmitResult>("create_proposal", { node, param, newValue }),

  voteProposal: (node: string, proposalId: number) =>
    invoke<SubmitResult>("vote_proposal", { node, proposalId }),

  getProposals: (node: string) => invoke<Proposal[]>("get_proposals", { node }),

  getGovParams: (node: string) => invoke<GovParams>("get_gov_params", { node }),

  // node / validator panel
  getValidatorStatus: (node: string) =>
    invoke<ValidatorStatus>("get_validator_status", { node }),

  unjail: (node: string) => invoke<SubmitResult>("unjail", { node }),

  // local node process — see node_process.rs. `config` fields are all optional; the backend
  // fills in sensible defaults (app data dir, public network) when omitted.
  nodeStart: (config: NodeStartConfig) => invoke<void>("node_start", { config }),

  nodeStop: () => invoke<void>("node_stop"),

  nodeProcessStatus: () => invoke<NodeProcessStatus>("node_process_status"),

  // Moves the local chain database aside (renamed, never deleted) so the next start
  // re-syncs. Returns the backup path. Fails while the node is running — it holds the file.
  nodeResetChain: () => invoke<string>("node_reset_chain"),

  // Live console output — each event is one line. Returns the unsubscribe function, same
  // shape as Tauri's own `listen()`, so a view can wire it up in a `useEffect` cleanup.
  onNodeLog: (handler: (line: LogLine) => void) =>
    listen<LogLine>("node-log", (e) => handler(e.payload)),

  onNodeExited: (handler: (e: NodeExited) => void) =>
    listen<NodeExited>("node-exited", (e) => handler(e.payload)),

  // Where tauri-plugin-log wrote this app's diagnostic trail — see lib.rs. Surfaced in
  // Settings so a community member hitting a bug can find it and attach it to a report.
  logDirPath: () => invoke<string>("log_dir_path"),
};

/// Public seed node — what a fresh install talks to before it has one of its own, so the wallet
/// works out of the box. A convenience, not the destination: every balance you read and every
/// transaction you send passes through someone else's machine, which can misreport the former
/// and observe the latter.
export const DEFAULT_NODE = "https://helix.silvra.net";

/// Where the bundled node's RPC lands. `node_process.rs` starts it without `HELIX_RPC_BIND`, so
/// it takes the compiled-in default.
///
/// Running your own node and still reading your balance off a stranger's server is the wrong way
/// round — not trusting anyone is the entire point of running one. `Validate.tsx` switches the
/// wallet here when the local node starts, and back when it stops.
export const LOCAL_NODE = "http://127.0.0.1:8545";

export const isLocalNode = (url: string) =>
  /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/i.test(url);
