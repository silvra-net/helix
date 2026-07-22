pub mod faucet;
pub mod rate_limit;
pub mod server;
pub mod types;

pub use server::start_rpc_server;
pub use types::{RpcError, RpcRequest, RpcResponse};

use helix_core::Block;
use helix_crypto::Hash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxResponse {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub amount_hlx: f64,
    pub fee_hlx: f64,
    pub tx_type: String,
    pub nonce: u64,
    /// What execution did with it: `applied`, `failed`, or `unknown` for blocks committed
    /// before receipts were stored. Same vocabulary as `TxHistoryEntry::status` — a
    /// transaction must not read as successful in a block listing and failed in its own
    /// detail view.
    pub status: String,
    /// Why it failed, straight from the executor. Absent unless `status` is `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub tx_count: usize,
    pub validator: String,
    pub prev_hash: String,
    pub merkle_root: String,
    /// EIP-1559 base fee for this block, in nano-HLX per transaction byte.
    pub base_fee_per_byte: u64,
    pub transactions: Vec<TxResponse>,
}

impl BlockResponse {
    /// Builds the display view of a block, asking `outcome` for each transaction's execution
    /// result (`(status, error)`, as produced by `server::receipt_outcome`).
    ///
    /// Deliberately not a `From<Block>`: an outcome lives in the receipt store, not in the
    /// block, so it cannot be derived from a `Block` alone. This used to be a `From` impl, and
    /// the result was that every block endpoint silently served transactions with no status at
    /// all — a failed transfer was indistinguishable from a settled one in any block listing.
    /// Taking the lookup as a parameter keeps that shortcut from existing while staying pure
    /// enough to unit-test without a database.
    pub fn new(block: &Block, mut outcome: impl FnMut(&Hash) -> (String, Option<String>)) -> Self {
        let transactions = block
            .transactions
            .iter()
            .map(|tx| {
                let hash = tx.hash();
                let (status, error) = outcome(&hash);
                TxResponse {
                    hash: hash.to_hex(),
                    from: tx.from.to_string(),
                    to: tx.to.as_ref().map(|a| a.to_string()),
                    amount_hlx: tx.amount as f64 / 1_000_000_000.0,
                    fee_hlx: tx.fee as f64 / 1_000_000_000.0,
                    tx_type: format!("{:?}", tx.tx_type),
                    nonce: tx.nonce,
                    status,
                    error,
                }
            })
            .collect();
        BlockResponse {
            hash: block.hash().to_hex(),
            height: block.height(),
            timestamp: block.header.timestamp,
            tx_count: block.tx_count(),
            validator: block.header.validator.to_string(),
            prev_hash: block.header.prev_hash.to_hex(),
            merkle_root: block.header.merkle_root.to_hex(),
            base_fee_per_byte: block.header.base_fee_per_byte,
            transactions,
        }
    }
}

/// Block header only — no transaction bodies. Lets a light client sync the
/// chain of headers (and their signatures) without the bandwidth cost of
/// downloading every transaction in every block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderResponse {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub validator: String,
    pub prev_hash: String,
    pub merkle_root: String,
    /// EIP-1559 base fee for this block, in nano-HLX per transaction byte.
    pub base_fee_per_byte: u64,
    /// Who attested the *parent* block — the addresses in `BlockHeader::last_commit`.
    ///
    /// Omitting this was a real diagnostic hole. It is the only record of who participated in
    /// consensus, the input the downtime counter is scored from, and the finality evidence a
    /// light client would need to trust a header at all. Without it, investigating the
    /// 2026-07-22 jailing loop through this endpoint showed every block as an empty
    /// certificate — the healthy ones included — which points at the wrong bug entirely.
    ///
    /// Addresses only: the signatures themselves are ML-DSA and would dominate the response of
    /// an endpoint whose whole purpose is to be small (they are what makes a full block ~37 KB).
    /// A verifier wanting to check them fetches the block from `/sync/blocks`.
    pub last_commit: Vec<String>,
}

impl From<&Block> for HeaderResponse {
    fn from(block: &Block) -> Self {
        HeaderResponse {
            hash: block.hash().to_hex(),
            height: block.height(),
            timestamp: block.header.timestamp,
            validator: block.header.validator.to_string(),
            prev_hash: block.header.prev_hash.to_hex(),
            merkle_root: block.header.merkle_root.to_hex(),
            base_fee_per_byte: block.header.base_fee_per_byte,
            last_commit: block
                .header
                .last_commit
                .iter()
                .map(|sig| sig.validator.to_string())
                .collect(),
        }
    }
}

/// One step of a Merkle inclusion proof, JSON-friendly (hex sibling hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStepResponse {
    pub sibling: String,
    pub sibling_is_right: bool,
}

impl From<&helix_crypto::MerkleProofStep> for ProofStepResponse {
    fn from(step: &helix_crypto::MerkleProofStep) -> Self {
        ProofStepResponse {
            sibling: step.sibling.to_hex(),
            sibling_is_right: step.sibling_is_right,
        }
    }
}

/// A Merkle inclusion proof for one transaction in one block. A light client
/// that already trusts `merkle_root` (e.g. from a `HeaderResponse` it
/// verified) can replay this proof to confirm the transaction was included,
/// without downloading the block's other transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxProofResponse {
    pub tx_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub merkle_root: String,
    pub leaf_index: usize,
    pub proof: Vec<ProofStepResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxHistoryEntry {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub amount_hlx: f64,
    pub fee_hlx: f64,
    pub tx_type: String,
    pub nonce: u64,
    pub block_height: u64,
    pub block_hash: String,
    pub timestamp: u64,
    /// What execution actually did with it: `applied`, `failed`, or `unknown` when this node
    /// has no receipt (blocks committed before receipts were stored). Deliberately not
    /// `confirmed` — being in a block is not an outcome, and reading it as one is how a
    /// rejected transfer came to look exactly like a successful payment in a wallet history.
    pub status: String,
    /// Why it failed, straight from the executor. Absent unless `status` is `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResponse {
    pub address: String,
    pub balance_hlx: f64,
    pub staked_hlx: f64,
    /// Stake in unbonding period (still slashable, not yet liquid)
    pub unbonding_stake_hlx: f64,
    /// Block height at which `unbonding_stake` becomes claimable (0 = no active unbonding)
    pub unbonding_unlock_height: u64,
    /// Whose misbehavior `unbonding_stake` is still slashable for: the validator it was
    /// undelegated from, or `null` when it is this account's own unstaked self-bond. Material
    /// to anyone reading `unbonding_stake_hlx` — that balance is not merely illiquid, it can
    /// still shrink, and this says who can shrink it.
    pub unbonding_source: Option<String>,
    pub nonce: u64,
    pub has_code: bool,
    /// Height at which this address may submit `Unjail`, or `null` if it isn't
    /// downtime-jailed. Presence (not the height itself) is what excludes it from
    /// `stakers()` — see `ChainState::jailed_until`'s doc comment.
    pub jailed_until: Option<u64>,
    /// Consecutive blocks this address's precommit has been absent from `last_commit`, or
    /// `null` if it currently has none — resets to `null` the instant it's seen signing
    /// again. 0 while jailed only if it was jailed and immediately unjailed without ever
    /// having signed since (rare in practice; `execute_unjail` clears both together).
    pub missed_blocks: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameResponse {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonhoodResponse {
    pub address: String,
    pub status: helix_identity::PersonhoodStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianResponse {
    pub address: String,
    pub guardians: Vec<String>,
    pub threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStatusResponse {
    pub address: String,
    /// Currently controlling public key fingerprint, if control was ever socially recovered.
    pub recovered_key_fingerprint: Option<String>,
    /// Guardian approvals collected so far for a pending recovery vote, if any.
    pub pending_approvals: Option<usize>,
    pub threshold: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceParamsResponse {
    pub min_validator_stake_hlx: f64,
    pub fuel_per_fee_unit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposalResponse {
    pub id: u64,
    pub proposer: String,
    pub param: String,
    pub new_value: u64,
    pub created_at_height: u64,
    pub yes_stake_hlx: f64,
    pub yes_votes: usize,
    pub executed: bool,
}

impl From<&helix_executor::GovernanceProposal> for GovernanceProposalResponse {
    fn from(p: &helix_executor::GovernanceProposal) -> Self {
        GovernanceProposalResponse {
            id: p.id,
            proposer: p.proposer.clone(),
            param: format!("{:?}", p.param),
            new_value: p.new_value,
            created_at_height: p.created_at_height,
            yes_stake_hlx: p.yes_stake as f64 / 1_000_000_000.0,
            yes_votes: p.voters.len(),
            executed: p.executed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub version: String,
    pub height: u64,
    pub best_hash: String,
    pub peer_count: usize,
    /// True while this node is still downloading history. It is **not** producing blocks in
    /// that state and its balances reflect only the part of the chain it has, so a client
    /// should show progress rather than present those numbers as final.
    pub is_syncing: bool,
    /// Tip this node is syncing towards, when known — pair it with `height` for a real
    /// progress figure ("12,400 of 44,000"). `None` when nothing is being synced, or when the
    /// target isn't known yet (no sync peer configured, or the peer hasn't answered).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_target_height: Option<u64>,
    pub mempool_size: usize,
    pub total_accounts: usize,
    pub circulating_supply_hlx: f64,
    pub total_burned_hlx: f64,
    /// Deterministic hash of this node's full chain state (`ChainState::state_hash`) — a
    /// diagnostic tool, not a protocol-level state root. It isn't committed to a block or
    /// checked as part of consensus. See `state_hash`'s doc comment for what it does and
    /// doesn't guarantee.
    ///
    /// **Compare it against `state_height`, not `height`.** This used to read "the state at
    /// `height`", and that was wrong: `height` comes from the block store while this comes from
    /// the in-memory `ChainState`, and the two advance at different moments inside
    /// `apply_finalized_block`. A response sampled in between carries height N-1 next to the
    /// state of N. Two nodes compared on that basis appear to have diverged when they have not —
    /// which is exactly what happened to two integration tests, and to the endpoint's own author,
    /// on 2026-07-22.
    pub state_hash: String,
    /// Height of the block whose execution produced `state_hash`, read under the same lock, so
    /// the two always belong together. This is the height to match on when comparing state
    /// across nodes.
    ///
    /// Can legitimately differ from `height` by one for a moment while a block is being
    /// committed. That is not a fault; it is the reason this field exists.
    pub state_height: u64,
    /// This node's own libp2p listen port. Lets a joining node derive a dialable seed
    /// address from a `sync_peer` URL (same host, this port) instead of relying solely on
    /// mDNS — which only works within one local multicast segment and never finds a peer
    /// reachable only over the open internet. See `resolve_seed_peer_multiaddr` in
    /// `helix-node` for the client side of this.
    pub p2p_port: u16,
    /// This node's announced, externally-dialable P2P multiaddr, if it set one
    /// (`HELIX_P2P_PUBLIC_ADDR`) — e.g. `/dns4/p2p.silvra.net/tcp/443/tls/ws` for a node
    /// reachable only over a WebSocket behind an HTTPS proxy / Cloudflare tunnel. A joining node
    /// dials *this* in preference to the raw-TCP address it would otherwise derive from
    /// `p2p_port`, which for a tunnelled node is unreachable and just burns a ~20 s dial timeout
    /// before the WebSocket seed is tried (the reason this field exists — see
    /// `resolve_seed_peer_multiaddr` in `helix-node`). `#[serde(default)]` so a node running an
    /// older build that never served this field still deserializes (to `None`, i.e. old
    /// raw-TCP-derivation behaviour). `None` also for any node that simply announces nothing.
    #[serde(default)]
    pub p2p_public_addr: Option<String>,
    /// The EIP-1559 base fee (nano-HLX per transaction byte) the next block will charge. A
    /// client needs it to price a transaction: the required fee is `base_fee_per_byte ×
    /// tx.size_bytes()`, and paying less means the transaction is rejected — so a flat,
    /// hardcoded fee is only ever right until the network gets busy enough to move this.
    pub base_fee_per_byte: u64,
    /// The balance this node's faucet tops an address up to, in HLX — `None` on any node that
    /// does not run one (see `crate::faucet`), **and also `None` while the faucet account is
    /// too empty to pay a grant**.
    ///
    /// The second condition is the useful one: a client should offer the faucet only where it
    /// will actually work, rather than show a button that answers "out of funds". Because it is
    /// derived from the balance on every request, the offer appears by itself when someone tops
    /// the account up and withdraws itself when it runs dry — no restart, no configuration
    /// change, nobody having to notice. `#[serde(default)]` keeps older nodes deserializing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faucet_topup_hlx: Option<f64>,
}
