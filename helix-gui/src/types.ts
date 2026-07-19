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
  nonce: number;
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

export interface NetworkStatus {
  version: string;
  height: number;
  best_hash: string;
  peer_count: number;
  is_syncing: boolean;
  mempool_size: number;
  circulating_supply_hlx: number;
  base_fee_per_byte: number;
}

export interface SubmitResult {
  tx_hash: string;
  status: string;
}
