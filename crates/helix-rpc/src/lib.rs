pub mod rate_limit;
pub mod server;
pub mod types;

pub use server::start_rpc_server;
pub use types::{RpcError, RpcRequest, RpcResponse};

use helix_core::{Block, CommitSig};
use helix_crypto::Hash;
use serde::{Deserialize, Serialize};

/// The commit certificate for the current chain tip — the precommit signatures that finalized it,
/// which will become the *next* block's [`helix_core::BlockHeader::last_commit`] once that block is
/// produced.
///
/// Unlike every other block's certificate, the tip's lives nowhere on disk yet: block N+1 (whose
/// header would carry block N's certificate) does not exist while N is the tip. It survives only in
/// the live BFT engine's `last_commit`. This type surfaces it over RPC (`GET /sync/tip-certificate`)
/// so a node catching up purely over RPC — which already reconstructs every *older* block's
/// certificate from the following block's header — can obtain the tip's too, and thus hold a
/// verifiable certificate for every block including the one it stops on. That in turn lets it stamp
/// a real (not empty) `last_commit` on the first block it proposes after such a sync, instead of
/// silently dropping the tip's participation record (#133, closing #114 for the RPC path).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TipCertificate {
    /// Height of the block these signatures attest — the serving node's current tip.
    pub height: u64,
    /// Hex hash of that block, so a consumer can confirm the certificate attests exactly the tip
    /// it just synced to before adopting it.
    pub block_hash: String,
    /// Full [`CommitSig`]s (not just addresses, unlike [`HeaderResponse::last_commit`]): the
    /// consumer is a syncing node that must *verify* every signature before adopting it, exactly as
    /// it verifies a block's embedded `last_commit`.
    pub signatures: Vec<CommitSig>,
}

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
    /// The proposer's node software version (`BlockHeader::node_version`, #128). Lets the explorer
    /// show which build produced each block. Empty for genesis / pre-#128 blocks.
    #[serde(default)]
    pub node_version: String,
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
            node_version: block.header.node_version.clone(),
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
    /// The proposer's node software version (`BlockHeader::node_version`, #128).
    #[serde(default)]
    pub node_version: String,
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
            node_version: block.header.node_version.clone(),
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

/// Operational diagnostics — the questions someone actually asks when a node misbehaves.
///
/// **Deliberately not the log.** Serving raw log output would be the obvious way to build this and
/// the wrong one: it makes every future `info!()` line a security decision that whoever writes it
/// is not making. On a node with a directly reachable listener the log carries peer addresses,
/// which is the network topology an eclipse attack needs; error paths carry filesystem paths. An
/// enumerated struct has the opposite property — what is exposed is written down here, and adding
/// to it is a deliberate act. `diagnostics_expose_no_addresses_keys_or_paths` enforces that.
///
/// Everything below is either already public on the chain, or says something about *this* node
/// that does not help an attacker reach it: no addresses, no paths, no identifiers of peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDiagnostics {
    pub version: String,
    /// Seconds since this process started serving.
    pub uptime_secs: u64,
    pub height: u64,
    pub state_height: u64,
    pub is_syncing: bool,
    pub peer_count: usize,
    /// Validators whose votes this node is not receiving. Note the direction: it is what this
    /// node observes, not a claim that those validators are down — it cannot tell an absent peer
    /// from a broken link to a healthy one.
    pub validators_not_heard_from: usize,
    /// Height at which this node last co-signed, and how long ago. `None` on a node that has not
    /// co-signed during this run — including every non-validator.
    pub last_cosigned_height: Option<u64>,
    pub last_cosigned_secs_ago: Option<u64>,
    /// This process's resident memory, and the machine's total, in KB. Zero where unreadable.
    /// Present because an out-of-memory kill leaves nothing in the node's own log and has cost
    /// this network a validator before.
    pub rss_kb: u64,
    pub machine_total_kb: u64,
    /// What the machine could still hand out, in KB — `MemAvailable`, not "free". Free memory on
    /// a healthy Linux box is near zero because the page cache uses the rest; the number that
    /// actually predicts an out-of-memory kill is this one.
    pub mem_available_kb: u64,
    /// Size of this node's chain database, in KB. **The path is deliberately absent** — the size
    /// says how much a chain costs to hold, the path describes the operator's machine. See the
    /// note on this struct.
    pub chain_db_kb: u64,
    /// Free and total space on the volume holding that database, in KB. Zero where unreadable.
    ///
    /// The pair that answers the question a chain database raises and cannot answer alone: it
    /// only ever grows, so "4 GB" means nothing without "of 370 GB, 308 free". A node that fills
    /// its disk stops, and stops in a way that leaves nothing useful in its own log.
    pub disk_free_kb: u64,
    pub disk_total_kb: u64,
    /// One-minute load average, and the cores it is spread across — a load of 8 means idle on
    /// this machine and desperate on a single-core VPS, so neither number is worth reporting
    /// without the other.
    pub load_avg_1: f64,
    pub cpu_count: usize,
    /// Threads and open file descriptors in this process. Both climb slowly when something
    /// leaks, and a descriptor limit hit at 3am reads as an unexplained refusal to accept peers.
    pub threads: u64,
    pub open_fds: u64,
    /// How the *previous* run of this node ended — the one thing that is unanswerable after the
    /// fact without it, and the reason this endpoint is useful for a node that has been
    /// restarting. `None` on a first run.
    pub previous_run: Option<PreviousRun>,
}

/// How the last run of this node ended. See `helix_node::run_record`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousRun {
    pub version: String,
    /// False means it was killed, crashed, or the machine went down — nothing marked it as an
    /// orderly stop.
    pub clean_exit: bool,
    pub ran_for_secs: u64,
    pub last_height: u64,
    pub last_seen_unix: u64,
    pub rss_kb: u64,
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
}
