// Mirrors the Rust DTOs in src-tauri. Field names match exactly (serde uses the Rust names),
// so keep them snake_case where the backend does.

export interface WalletMeta {
  exists: boolean;
  unlocked: boolean;
  encrypted: boolean;
  address: string | null;
}

export interface NewWallet {
  address: string;
  mnemonic: string;
}

export interface Overview {
  address: string;
  balance_hlx: number;
  staked_hlx: number;
  unbonding_hlx: number;
  unbonding_unlock_height: number;
  unbonding_source: string | null;
  nonce: number;
  jailed_until: number | null;
  missed_blocks: number | null;
}

export interface LogLine {
  stream: "stdout" | "stderr";
  line: string;
}

export interface NodeExited {
  code: number | null;
}

export interface NodeProcessStatus {
  running: boolean;
}

export interface NodeStartConfig {
  data_dir?: string | null;
  /** Omit to validate as this wallet's own address — see node_process.rs. */
  validator_key_path?: string | null;
  /** Only needed when the wallet file is encrypted. */
  validator_key_passphrase?: string | null;
  sync_peer?: string | null;
}

export interface Delegation {
  validator: string;
  shares: number;
  value_hlx: number;
}

export interface ValidatorPool {
  address: string;
  has_pool: boolean;
  self_staked_hlx: number;
  delegated_stake_hlx: number;
  effective_stake_hlx: number;
  total_shares: number;
  commission_bps: number | null;
}

export interface HistoryEntry {
  hash: string;
  from: string;
  to: string | null;
  amount_hlx: number;
  fee_hlx: number;
  tx_type: string;
  nonce: number;
  block_height: number;
  timestamp: number;
  status: string;
  error?: string | null;
}

export interface ValidatorSummary {
  address: string;
  effective_stake_hlx: number;
  self_staked_hlx: number;
  delegated_stake_hlx: number;
  /** null when the validator has never had a delegator and so never set a rate. */
  commission_bps: number | null;
  accepts_delegation: boolean;
  /** null before a fresh chain's first rotation — unknown, not "no". */
  active: boolean | null;
  jailed_until: number | null;
  missed_blocks: number | null;
}

export interface ValidatorList {
  validators: ValidatorSummary[];
  min_validator_stake_hlx: number;
}

export interface NetworkStatus {
  version: string;
  height: number;
  best_hash: string;
  peer_count: number;
  is_syncing: boolean;
  /** Tip being synced towards, when known — pair with `height` for real progress. */
  sync_target_height?: number | null;
  mempool_size: number;
  circulating_supply_hlx: number;
  base_fee_per_byte: number;
}

export interface SubmitResult {
  tx_hash: string;
  status: string;
}

export interface GuardianInfo {
  address: string;
  guardians: string[];
  threshold: number;
}

export interface RecoveryStatus {
  address: string;
  recovered_key_fingerprint: string | null;
  pending_approvals: number | null;
  threshold: number | null;
}

export interface Proposal {
  id: number;
  proposer: string;
  param: string;
  new_value: number;
  created_at_height: number;
  yes_votes: number;
  yes_stake_hlx: number;
  executed: boolean;
}

export interface GovParams {
  min_validator_stake_hlx: number;
  fuel_per_fee_unit: number;
}

export interface ValidatorStatus {
  self_staked_hlx: number;
  delegated_stake_hlx: number;
  effective_stake_hlx: number;
  commission_bps: number | null;
  min_validator_stake_hlx: number;
  eligible: boolean;
  blocks_proposed: number;
  window: number;
}
