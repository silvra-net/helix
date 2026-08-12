use std::collections::{BTreeMap, HashMap};

use helix_crypto::{Address, Hash, PublicKey};
use helix_identity::{GuardianSet, PersonhoodStatus, RecoveryRequest};
use serde::{Deserialize, Serialize};

use crate::governance::{GovernanceParams, GovernanceProposal};

/// Unbonding period in blocks — stake stays slashable for 7 days at the actual 2s block
/// time (`BLOCK_TIME_MS` in `helix-node`). Was 50_400 (7 days at an earlier, since-changed
/// 12s block time) — silently drifted to ~28 hours of real protection when block time was
/// tuned down, never caught since nothing enforces this constant against the live block
/// time. After this many blocks past the unstake tx, `ClaimUnbonded` releases the funds.
pub const UNBONDING_PERIOD: u64 = 302_400;

/// Consecutive blocks a validator's precommit must be absent from `BlockHeader::last_commit`
/// (see `record_block_participation`) before persisted downtime-jailing kicks in. This is the
/// *only* mechanism that removes a validator's power from the quorum, and it does so through
/// the shared chain state, so every node reaches the same verdict from the same blocks. A
/// per-node RAM-only exclusion used to sit in front of it (`helix-consensus`'s liveness jail);
/// it was removed on 2026-07-22 after it forked the live chain, because nodes could and did
/// disagree about who was excluded. 150 blocks ≈ 5 minutes at the 2s block time.
///
/// Note the consequence: jailing needs blocks, and blocks need quorum. A set that has lost
/// more than a third of its power halts and stays halted until the missing validators return —
/// `3f+1` arithmetic, not a gap. Tolerating one absence takes four validators.
pub const DOWNTIME_JAIL_THRESHOLD_BLOCKS: u32 = 150;

/// Minimum blocks a downtime-jailed validator must wait before `TxType::Unjail` is accepted —
/// see its doc comment for why unjailing isn't automatic. 300 blocks ≈ 10 minutes at the 2s
/// block time, matching Cosmos SDK's own default downtime-jail duration (600s). Deliberately
/// carries **no slash**: downtime alone isn't proof of malice (a validator's node crashing
/// and restarting is the common case, not the adversarial one) — slashing stays reserved for
/// provable misbehavior (`SLASH_FRACTION_BPS`, double-signing). Jailing alone is real
/// friction: while jailed, that stake earns nothing and casts no vote.
pub const MIN_JAIL_BLOCKS: u64 = 300;

/// Per-account ledger state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub address: String,
    /// Liquid balance in nano-HLX (1 HLX = 1_000_000_000 nano-HLX)
    pub balance: u64,
    /// Locked in PoS stake (still earning rewards, still slashable)
    pub staked: u64,
    /// Stake that has been queued for release but is still in the unbonding period.
    /// This amount is slashable for past misbehavior discovered during unbonding.
    #[serde(default)]
    pub unbonding_stake: u64,
    /// The block height at which `unbonding_stake` becomes claimable.
    /// 0 means there is no active unbonding.
    #[serde(default)]
    pub unbonding_unlock_height: u64,
    /// Which validator's misbehavior `unbonding_stake` is still slashable for: `None` when it
    /// is this account's own unstaked self-bond (`TxType::Unstake`), `Some(validator)` when it
    /// was redeemed out of that validator's delegation pool (`TxType::Undelegate`).
    ///
    /// Without this, unbonding capital is untraceable once it leaves a pool, and `slash` can
    /// only reach a validator's own account and its live pool — so a delegator who undelegated
    /// after the misbehavior but before the evidence transaction landed kept everything, which
    /// is precisely what the unbonding period exists to prevent (see `ChainState::slash`).
    #[serde(default)]
    pub unbonding_source: Option<String>,
    /// Next expected nonce — prevents replay attacks
    pub nonce: u64,
    /// Deployed WASM contract bytecode, if this account is a contract.
    #[serde(default)]
    pub code: Option<Vec<u8>>,
}

impl AccountState {
    pub fn new(address: &Address) -> Self {
        AccountState {
            address: address.to_string(),
            balance: 0,
            staked: 0,
            unbonding_stake: 0,
            unbonding_unlock_height: 0,
            unbonding_source: None,
            nonce: 0,
            code: None,
        }
    }

    /// Returns true if the unbonding period has passed and stake can be claimed.
    pub fn can_claim_unbonded(&self, current_height: u64) -> bool {
        self.unbonding_stake > 0
            && self.unbonding_unlock_height > 0
            && current_height >= self.unbonding_unlock_height
    }

    pub fn balance_hlx(&self) -> f64 {
        self.balance as f64 / 1_000_000_000.0
    }

    pub fn staked_hlx(&self) -> f64 {
        self.staked as f64 / 1_000_000_000.0
    }
}

/// Commission a validator keeps by default from delegator rewards, until it explicitly sets
/// its own rate via `TxType::SetCommission`. 1000 bps = 10% — high enough to be a meaningful
/// validator incentive to run reliable infrastructure, low enough that delegators still get
/// the large majority of what their stake earns.
pub const DEFAULT_COMMISSION_BPS: u16 = 1_000;

/// Hard ceiling on a validator's self-set commission rate. Not a protection against a
/// validator legitimately choosing to reward delegators poorly (a delegator can always see
/// the current rate before delegating, and un-delegate afterward) — it exists specifically to
/// bound the "advertise a low rate, then raise it after delegators are locked in" rug-pull:
/// even a maximally hostile rate change can never claim more than half of what delegators
/// earn.
pub const MAX_COMMISSION_BPS: u16 = 5_000;

/// Minimum fraction of a validator's effective stake (self + delegated, see
/// `ChainState::effective_stake`) that must be backed by the validator's own capital, in basis
/// points. Below this ratio a validator collects the full block-production/voting-power benefit
/// of `effective_stake()` while running almost entirely on delegators' capital — a moral-hazard
/// gap real chains (e.g. Cosmos) guard against, since slashing then falls mostly on the
/// delegators who trusted the validator rather than the validator itself. 1000 bps = 10%, i.e.
/// delegated stake is capped at 9x self-stake: generous enough not to bottleneck a well-run
/// validator's growth, but enough that a validator always keeps meaningful skin in the game.
pub const MIN_SELF_BOND_RATIO_BPS: u64 = 1_000;

/// Whether `self_staked` alone satisfies `MIN_SELF_BOND_RATIO_BPS` against an effective stake of
/// `self_staked + delegated`. An empty pool (`delegated == 0`) always passes trivially — the
/// ratio only bites once a validator actually has delegators to be under-collateralized against.
///
/// `self_staked` is deliberately the validator's active `AccountState::staked` only, never
/// `staked + unbonding_stake`, even though unbonding capital is still slashable for the rest of
/// `UNBONDING_PERIOD` and so is arguably still "at risk". Counting it would let a validator
/// attract fresh delegations on the strength of capital whose withdrawal it has already
/// announced: nothing re-checks the ratio when `TxType::ClaimUnbonded` later pays that capital
/// out, so the pool would silently end up under-collateralized with no transaction to reject.
/// Measuring only capital that is still committed keeps the check conservative in the direction
/// that protects delegators, which is the direction to err in.
pub fn self_bond_ratio_ok(self_staked: u64, delegated: u64) -> bool {
    let effective = self_staked as u128 + delegated as u128;
    if effective == 0 {
        return true;
    }
    self_staked as u128 * 10_000 >= effective * MIN_SELF_BOND_RATIO_BPS as u128
}

/// A validator's delegation pool: the collective stake backing it from delegators (kept
/// separate from the validator's own `AccountState::staked`, which is untouched by
/// delegation). Uses a shares-based accounting scheme (the same one Cosmos SDK's F1
/// distribution and liquid-staking protocols like Lido use) rather than tracking each
/// delegator's raw HLX balance directly: `total_delegated_stake` is the pool's current total
/// value, `total_shares` is how many claims are outstanding on it, and one delegator's value
/// is always `their_shares * total_delegated_stake / total_shares`. This makes both reward
/// distribution and slashing O(1) regardless of delegator count — a reward just adds to
/// `total_delegated_stake` (every existing share is instantly worth more, "auto-compounding"
/// with no per-delegator bookkeeping), and a slash just subtracts from it the same way,
/// without needing to touch every individual delegator's record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationPool {
    pub total_shares: u64,
    pub total_delegated_stake: u64,
    pub commission_bps: u16,
}

/// One `TxType::Redelegate`'s worth of capital that has left the source validator's pool for
/// `dst`'s, but is still inside the source's slashing window. Stored under the source validator
/// in `ChainState::redelegations`.
///
/// Slashing one of these does not touch the destination pool's other delegators: the loss is
/// taken by burning `delegator`'s own shares in `dst`, since they are the only one who chose to
/// back the misbehaving source validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redelegation {
    /// Address string of the delegator who moved the stake.
    pub delegator: String,
    /// Address string of the validator whose pool now holds it (and pays rewards on it).
    pub dst: String,
    /// nano-HLX still exposed to the source validator's slashing. Shrinks as slashes land.
    pub amount: u64,
    /// Height at which the source's slashing window closes and the entry is pruned.
    pub unlock_height: u64,
}

/// Full world state of the chain
/// The `chain_id` a state carries before anyone sets one.
///
/// Not `impl Default for Hash`: a blanket default on a hash type invites `Hash::default()` at call
/// sites where "no hash yet" is not a meaningful value, and a zero hash that silently stands in for
/// a real one is how a check turns into a formality. Named here so the one place that wants it says
/// what it means.
fn unset_chain_id() -> Hash {
    Hash::ZERO
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// Which chain this state belongs to: the genesis block's hash. Set by whoever builds or loads
    /// the state, checked against every transaction's `chain_id` (backlog #174).
    ///
    /// Deliberately **not** part of `state_hash`'s `Canonical` view. It is context, not consensus
    /// state — the genesis block already proves which chain this is, and folding it in would buy no
    /// safety while giving the genesis rebuild another way to disagree with a peer.
    ///
    /// Defaults to the zero hash, which matches no real genesis, so a node that forgot to set it
    /// rejects every transaction loudly instead of accepting foreign ones quietly. That direction
    /// is chosen: a stuck faucet is a bug report, a chain that honours another chain's signatures
    /// is a theft.
    #[serde(default = "unset_chain_id")]
    pub chain_id: Hash,
    /// address string → account state
    pub accounts: HashMap<String, AccountState>,
    /// Absolute HLX supply ceiling in nano-HLX (`genesis::TOTAL_SUPPLY_HLX`, fixed at
    /// genesis) — the hard cap that `total_issued` may asymptotically approach but never
    /// exceed. Distinct from `total_issued`: this never changes after genesis.
    pub total_supply: u64,
    /// Cumulative nano-HLX actually minted so far — the genesis allocation plus every
    /// block reward minted since (see `genesis::scheduled_block_reward`). Unlike
    /// `total_supply`, this grows over time; `circulating_supply()` is derived from this,
    /// not from `total_supply` directly, since most of the cap is unminted at any given
    /// height under the halving schedule (exactly like Bitcoin: the 21 M cap is a ceiling
    /// the emission schedule approaches, not an amount handed out at genesis).
    #[serde(default)]
    pub total_issued: u64,
    /// Cumulative burned fees — reduces circulating supply
    pub total_burned: u64,
    /// Registered human-readable names (without the `.hlx` suffix) → owning address string.
    pub names: HashMap<String, String>,
    /// Proof of Personhood status per address string. Absent entries are `Unverified`.
    pub personhood: HashMap<String, PersonhoodStatus>,
    /// Registered social-recovery guardians per address string. Absent = no guardians.
    pub guardians: HashMap<String, GuardianSet>,
    /// In-progress guardian approval votes to rotate an address's controlling key.
    pub recovery_requests: HashMap<String, RecoveryRequest>,
    /// Active recovery override key per address string. Once set, this key (not the one
    /// the address was originally derived from) must produce transaction signatures for it.
    pub recovery_keys: HashMap<String, PublicKey>,
    /// Runtime-adjustable protocol parameters — changed only via passed governance proposals.
    pub governance_params: GovernanceParams,
    /// Governance proposals by id, both pending and resolved.
    pub proposals: HashMap<u64, GovernanceProposal>,
    /// Next id to assign to a new proposal.
    pub next_proposal_id: u64,
    /// ZK personhood commitments that have already been claimed by some address.
    /// A `commitment`+`proof_bytes` pair becomes public the moment it's included in
    /// a block, and the STARK circuit only proves knowledge of a secret matching
    /// `commitment` — it never binds the proof to the claiming address. Without this
    /// set, anyone could copy a already-submitted proof verbatim into a
    /// `ProvePersonhood` tx from a different address and be granted the same
    /// `Verified` status for free, defeating Sybil resistance entirely.
    #[serde(default)]
    pub used_personhood_commitments: std::collections::HashSet<[u8; 16]>,
    /// Double-sign incidents (`"{validator}:{height}:{round}"`) already slashed via
    /// `SubmitDoubleSignEvidence`. A validator can only meaningfully double-sign once per
    /// (height, round); without this, the same proven incident could be resubmitted
    /// (by the same or a different reporter) to slash the validator repeatedly.
    #[serde(default)]
    pub slashed_double_sign_incidents: std::collections::HashSet<String>,
    /// The network's configured personhood-issuing authorities — set once at genesis (see
    /// `GenesisConfig`), never overridden afterward. `ProvePersonhood` transactions require
    /// a signature over the claimed commitment from ANY ONE of these keys; an empty list
    /// means no authority is configured, and `ProvePersonhood` is rejected outright rather
    /// than falling back to trusting the ZK proof alone (which anyone can self-issue for
    /// free — see `PersonhoodProofPayload`'s doc comment).
    ///
    /// Deliberately a list, not a single key: a single authority is a single point of
    /// failure and censorship — if that one key is lost, compromised, or its operator goes
    /// offline, personhood issuance for the entire network stops (or worse, a compromised
    /// key can mint fraudulent verifications). "Any one of N" doesn't make issuance
    /// decentralized in the Byzantine-fault-tolerant sense (a single compromised authority
    /// can still mint fraudulent verifications on its own — this isn't M-of-N threshold
    /// signing), but it does remove the single-operator availability risk, and lets a
    /// compromised key be retired without an outage as long as at least one other remains
    /// trustworthy. `Vec` rather than `HashSet`: `PublicKey` doesn't implement `Hash`, and
    /// this list is expected to stay small (a handful of authorities at most), so linear
    /// lookup is fine.
    #[serde(default)]
    pub personhood_authorities: Vec<PublicKey>,
    /// Delegation pool per validator address string. Absent entry = no delegators yet (or
    /// never had any) — not the same as an empty pool, which can't exist: a pool is only
    /// ever created by the first delegation and never removed once created, so `total_shares
    /// == 0` never actually occurs for a present entry outside of pathological 100%-slash
    /// scenarios (see `execute_delegate`'s doc comment for how new delegations handle that).
    #[serde(default)]
    pub validator_pools: HashMap<String, DelegationPool>,
    /// Delegator shares per validator address string: validator -> {delegator -> shares}.
    /// Split from `validator_pools` (rather than nesting shares inside the pool struct)
    /// because the pool itself is small and hashed/read every reward/slash, while this can
    /// grow large per popular validator and is only read/written on delegate/undelegate.
    #[serde(default)]
    pub delegator_shares: HashMap<String, HashMap<String, u64>>,
    /// Capital moved straight from one validator's pool into another's via
    /// `TxType::Redelegate`, keyed by the **source** validator it is still slashable for.
    /// Absent entry = nothing is currently redelegating away from that validator.
    ///
    /// This exists because redelegation lets stake skip the unbonding queue, which is the only
    /// thing that normally keeps departing capital within reach of `slash` (see
    /// `AccountState::unbonding_source`). Without tracking it, redelegating between a
    /// validator's double-sign and the evidence transaction proving it would be a strictly
    /// better escape than undelegating: instant, and the stake keeps earning at the
    /// destination. Entries are pruned by `prune_expired_redelegations` once their window
    /// closes.
    #[serde(default)]
    pub redelegations: HashMap<String, Vec<Redelegation>>,
    /// Per-contract persistent key-value storage: contract address string -> {key -> value}.
    /// Written only via `TxType::CallContract`'s `storage_write` host call (see
    /// `helix_vm::HostContext`) — a contract can only ever read/write its *own* entry here
    /// (there is no cross-contract call yet, so there is no way for one contract's execution
    /// to even name another contract's storage). Absent entry = this contract has never
    /// written anything, not an error.
    #[serde(default)]
    pub contract_storage: HashMap<String, HashMap<Vec<u8>, Vec<u8>>>,
    /// The bootstrap stake (nano-HLX) the genesis validator was given at height 0 — a record of
    /// what genesis originally configured, so a node joining long after startup via `GET /genesis`
    /// can rebuild byte-for-byte identical genesis state instead of only ever seeing today's
    /// `accounts`, which may have drifted from genesis by then (stakes changed, validators
    /// slashed, etc).
    ///
    /// It has to be recorded rather than re-derived for exactly the reason stated above: today's
    /// `accounts` may have drifted from genesis by any amount. But it also has to be recorded
    /// rather than read from a compile-time constant, which is what every joining node did
    /// before: `GenesisConfig::build_state` used to hardcode `VALIDATOR_GENESIS_STAKE_HLX`, so
    /// the constant was silently part of consensus — change it, and a node bootstrapping against
    /// an existing chain rebuilds a *different* genesis and diverges, the same trap
    /// `total_supply` carries (it is still reconstructed from a constant by
    /// `HelixDb::load_chain_state`'s caller). Storing it here is what lets the constant be
    /// retuned later without forking every chain that already launched under the old value.
    #[serde(default)]
    pub genesis_validator_stake: u64,
    /// Liquid balances handed out at genesis beyond any staked amounts (address, nano-HLX) —
    /// e.g. a faucet or an operator treasury. The third and last piece of genesis that cannot be
    /// re-derived from the genesis block, recorded here for the same reason as
    /// `genesis_validator_stake`: `GENESIS_PREFUND` is a
    /// compile-time default describing how a *new* chain would launch on this build, and a node
    /// joining an existing chain must not rebuild that chain's genesis from it.
    ///
    /// Empty for every chain launched so far, which is the only reason reading it back as empty
    /// is safe: an empty table is indistinguishable from an absent one, so a chain that had
    /// launched with a non-empty `GENESIS_PREFUND` before this field existed would come back
    /// wrong. None ever did — the constant has been `&[]` since well before any live chain's
    /// genesis. Chains launching from here on store whatever they actually allocated.
    #[serde(default)]
    pub genesis_allocations: Vec<(Address, u64)>,
    /// Addresses that currently meet `min_validator_stake` but have never yet been part of
    /// the active BFT validator set — waiting out one full epoch (`EPOCH_LENGTH` blocks)
    /// before `rotate_validator_set` admits them.
    ///
    /// Without this, a `Stake` transaction alone is enough to become quorum-critical the
    /// moment the next epoch boundary hits — no online-check, no advance warning, whether
    /// or not the staker has a node running at all. In a small validator set that can freeze
    /// the whole chain instantly (2-of-2 quorum needs both; found live on 2026-07-20 when a
    /// second validator staked and the epoch rotated before their node ever connected).
    /// Existing validators dropping below the threshold are NOT delayed — only entry is,
    /// since holding back a departure is the direction that risks an empty/stuck set, not
    /// this one (mirrors the asymmetry already established for slashing/jailing, which acts
    /// immediately on the way out but never early on the way in).
    #[serde(default)]
    pub pending_validators: std::collections::HashSet<Address>,
    /// The addresses actually entitled to vote in the current epoch — the set every block is
    /// proposed and precommitted against, rebuilt at each epoch boundary by
    /// `rotate_active_validators`.
    ///
    /// This exists because `stakers()` is *not* the same question. A staker who is serving out
    /// `pending_validators`' one-epoch delay qualifies by stake but is deliberately not in the
    /// quorum, so no one expects its signature and its vote would not be counted. Charging it
    /// with a missed block for that period punishes it for obeying the rule: found live on
    /// 2026-07-21, when a second validator staked and `record_block_participation` — which read
    /// `stakers()` — jailed it at 150 missed blocks, *before* the rotation that would have
    /// activated it ever arrived. Because jailing drops an address from `stakers()`, it also
    /// lost its accrued wait and re-entered as brand new after unjailing, so whether a new
    /// validator could join at all came down to where in the 100-block epoch it happened to
    /// stake.
    ///
    /// Empty means "no epoch boundary has been crossed under this field yet" (a state loaded
    /// from a database written before this field existed). Nobody is charged with a missed
    /// block until the next rotation fills it — deliberately the forgiving direction: a late
    /// jail costs at most `EPOCH_LENGTH` blocks of downtime accounting, whereas an early jail
    /// punishes the innocent.
    ///
    /// **Deliberately excluded from `state_hash`** (unlike `pending_validators`), and that is a
    /// considered trade, not an oversight. `state_hash` is nominally a diagnostic, but
    /// `verify_genesis_reconstruction` compares it when joining a chain — so adding a field to
    /// it changes the reconstructed genesis and locks every existing chain out of the upgrade.
    /// Measured on 2026-07-21: hashing this field made the binary rebuild genesis as
    /// `c5474b79…` against the live chain's `44e1c9d9…`, i.e. a running devnet would have needed
    /// a full reset purely to deploy a bug fix.
    ///
    /// Little detection is given up for that. This set has no effect of its own — it decides
    /// who `record_block_participation` scores, and that shows up in `missed_blocks` and
    /// `jailed_until`, which *are* hashed. Two nodes that disagreed here would diverge on those
    /// within a block or two and be caught anyway, one step later.
    #[serde(default)]
    pub active_validators: std::collections::HashSet<Address>,
    /// Validators serving their one-epoch **probation** (backlog #132): promoted out of
    /// `pending_validators` into the live signing set — so their precommits are gathered and land
    /// in `last_commit` — but carrying zero voting power and no proposer turn (see
    /// `helix_consensus::Validator::probationary`). This is what stops a "phantom" (an address
    /// that staked but has no live node signing for it) from ever becoming quorum-critical and
    /// freezing a small set: a probationer that never signs is simply not promoted. Hashed like
    /// `pending_validators`, so joining nodes agree on the signing set that shapes the proposer
    /// schedule.
    #[serde(default)]
    pub probationary_validators: std::collections::HashSet<Address>,
    /// Probationary validators whose signature has appeared in a committed `last_commit` during
    /// the current probation epoch — the on-chain, identical-on-every-node proof that a real node
    /// is running this key. Populated by `record_probation_liveness` from the same verified signer
    /// set `record_block_participation` uses, cleared at each rotation. Hashed so a divergence in
    /// who proved live surfaces immediately rather than silently changing a future active set.
    ///
    /// **Currently written but not read as a gate.** `rotate_active_validators` used to promote
    /// exactly `probationary_validators ∩ probation_seen`; that condition turned out to be
    /// unsatisfiable in practice and is disabled — see the comment there and backlog #141. The
    /// field is kept populated (it is part of `state_hash` and of the persisted state, so removing
    /// it is a state change, and #141 needs it) and `/validators` exposes it as
    /// `probation_liveness_seen`, which is what made the problem measurable in the first place.
    #[serde(default)]
    pub probation_seen: std::collections::HashSet<Address>,
    /// Height of the block whose execution produced the state currently in memory.
    ///
    /// Exists so `GET /status` can report a `state_hash` together with the height it belongs to.
    /// Without it that endpoint pairs a height read from the *block store* with a hash read from
    /// this struct, and `apply_finalized_block` updates the two at different moments — the
    /// `chain_state` write guard is released right after `execute_block`, while `put_block` runs
    /// a hundred-odd lines and several `.await` points later. Sampled in between, `/status`
    /// reports height N-1 beside the state of N: a pair that never logically existed.
    ///
    /// That is not cosmetic. A differing `state_hash` at the same height is the most alarming
    /// signal this chain has, it is what the deploy ritual compares before and after a restart,
    /// and it made two multi-validator integration tests fail roughly one run in three on
    /// 2026-07-22 while nothing was wrong with the chain.
    ///
    /// Written inside the same `chain_state` write lock as the execution itself, so any reader
    /// holding the read lock sees a height and a state hash that belong to each other. That is
    /// the whole mechanism — no new lock ordering, so no deadlock risk against the
    /// `store.write()` → `chain_state.read()` order used in the persist step.
    ///
    /// **Deliberately not part of `state_hash`**, for the same reason as `active_validators`
    /// above: `state_hash` is compared by `verify_genesis_reconstruction`, so anything added to
    /// the `Canonical` struct changes reconstructed genesis and locks every existing chain out
    /// of the upgrade. Nothing is given up — this field is a label for the hash, not an input to
    /// it, and two nodes at the same height disagreeing about *this* would already be
    /// disagreeing about everything it labels.
    #[serde(default)]
    pub applied_height: u64,
    /// Consecutive blocks (address string -> count) a validator's precommit has been absent
    /// from `BlockHeader::last_commit`, as counted by `record_block_participation`. Reset to
    /// absent the instant a signature from that validator is seen again — a handful of missed
    /// blocks proves nothing (a proposer momentarily behind on gossip, a validator mid-restart),
    /// only sustained absence does. Not the same thing as `helix-consensus`'s local, RAM-only
    /// `missed_rounds`, which since 2026-07-22 is purely a diagnostic (it decides what a
    /// stalled node *logs*, nothing else) — this is the persisted, on-chain layer that survives
    /// node restarts and has an actual consequence (`jailed_until`).
    #[serde(default)]
    pub missed_blocks: HashMap<String, u32>,
    /// Address string -> height at which a downtime-jailed validator may submit
    /// `TxType::Unjail`. Presence in this map (regardless of whether that height has passed)
    /// is what `stakers()` excludes on — jailing is never automatic-undone, an explicit
    /// `Unjail` transaction removes the entry. See `TxType::Unjail`'s doc comment for why
    /// auto-rejoining the instant a validator reappears would defeat the point.
    #[serde(default)]
    pub jailed_until: HashMap<String, u64>,
}

impl ChainState {
    /// A state with no chain identity yet — `chain_id` stays [`Hash::ZERO`] until the caller who
    /// knows the genesis block sets it (see `ChainState::chain_id`). Callers that skip that step
    /// get a state which rejects every transaction, which is the loud direction to fail in.
    pub fn new(total_supply: u64) -> Self {
        ChainState {
            chain_id: unset_chain_id(),
            accounts: HashMap::new(),
            total_supply,
            total_issued: 0,
            total_burned: 0,
            names: HashMap::new(),
            personhood: HashMap::new(),
            guardians: HashMap::new(),
            recovery_requests: HashMap::new(),
            recovery_keys: HashMap::new(),
            governance_params: GovernanceParams::default(),
            proposals: HashMap::new(),
            next_proposal_id: 0,
            used_personhood_commitments: std::collections::HashSet::new(),
            slashed_double_sign_incidents: std::collections::HashSet::new(),
            personhood_authorities: Vec::new(),
            validator_pools: HashMap::new(),
            delegator_shares: HashMap::new(),
            redelegations: HashMap::new(),
            contract_storage: HashMap::new(),
            genesis_validator_stake: 0,
            genesis_allocations: Vec::new(),
            pending_validators: std::collections::HashSet::new(),
            active_validators: std::collections::HashSet::new(),
            probationary_validators: std::collections::HashSet::new(),
            probation_seen: std::collections::HashSet::new(),
            applied_height: 0,
            missed_blocks: HashMap::new(),
            jailed_until: HashMap::new(),
        }
    }

    /// Read a value from `contract`'s own persistent storage. `None` if never set.
    pub fn contract_storage_read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        self.contract_storage.get(&contract.to_string())?.get(key).cloned()
    }

    /// Write a value into `contract`'s own persistent storage.
    pub fn contract_storage_write(&mut self, contract: &Address, key: Vec<u8>, value: Vec<u8>) {
        self.contract_storage.entry(contract.to_string()).or_default().insert(key, value);
    }

    pub fn get(&self, address: &Address) -> Option<&AccountState> {
        self.accounts.get(&address.to_string())
    }

    pub fn get_or_default(&self, address: &Address) -> AccountState {
        self.accounts
            .get(&address.to_string())
            .cloned()
            .unwrap_or_else(|| AccountState::new(address))
    }

    pub fn update_account<F>(&mut self, address: &Address, f: F)
    where
        F: FnOnce(&mut AccountState),
    {
        let key = address.to_string();
        let acc = self
            .accounts
            .entry(key)
            .or_insert_with(|| AccountState::new(address));
        f(acc);
    }

    pub fn set_balance(&mut self, address: &Address, balance: u64) {
        self.update_account(address, |acc| acc.balance = balance);
    }

    /// Set staked amount directly — used only in genesis to pre-stake the validator.
    pub fn set_validator_stake(&mut self, address: &Address, staked: u64) {
        self.update_account(address, |acc| acc.staked = staked);
    }

    pub fn circulating_supply(&self) -> u64 {
        self.total_issued.saturating_sub(self.total_burned)
    }

    /// Nano-HLX still available to be minted under `TOTAL_SUPPLY_HLX` before the block-reward
    /// schedule must stop regardless of what `scheduled_block_reward` would otherwise pay out.
    pub fn mintable_headroom(&self) -> u64 {
        self.total_supply.saturating_sub(self.total_issued)
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Slash a validator's stake by `fraction_bps` basis points (1/10000) on confirmed
    /// double-sign evidence. Slashed stake is burned — same deflationary treatment as
    /// tx fees, and it leaves the validator's stake (and future voting power) reduced.
    /// Returns the amount actually slashed in nano-HLX (0 if the address is unknown).
    ///
    /// Also slashes this validator's delegation pool (if any) by the same fraction. This is
    /// deliberate, not collateral damage: delegators sharing the misbehaving validator's
    /// downside is exactly what gives them a reason to pick a reliable one instead of just
    /// the lowest commission rate — a delegation model where delegators bore zero slashing
    /// risk would remove that incentive entirely. Applied in O(1) regardless of delegator
    /// count: shares outstanding don't change, only the pool's total value does, so every
    /// delegator's share is instantly worth proportionally less without visiting any of
    /// their individual records (see `DelegationPool`'s doc comment).
    ///
    /// Finally, slashes every account still unbonding *out of* this validator's pool
    /// (`AccountState::unbonding_source == Some(address)`). Those funds already left
    /// `validator_pools[address]` and so are out of reach of the pool slash above, but they were
    /// backing this validator when it misbehaved and stay slashable until their unbonding period
    /// ends — the same rule the validator's own unstaked self-bond has always followed. Skipping
    /// them let any delegator escape a slash in full simply by undelegating between the
    /// misbehavior and the (transaction-carried, so necessarily later) evidence landing.
    ///
    /// This last pass is linear in the number of accounts rather than indexed. Deliberate: a
    /// reverse validator→unbonding-delegators index would be derived consensus state that has to
    /// be kept in lockstep with the accounts it mirrors, and an index that silently drifts out of
    /// sync corrupts `state_hash` on some nodes and not others — a far worse failure than a scan.
    /// The scan cannot be used to grief the network either: slashing only ever runs on distinct,
    /// deduplicated double-sign incidents (see `slashed_double_sign_incidents`), so its frequency
    /// is bounded by real misbehavior, not by anything an attacker can pay to repeat.
    pub fn slash(&mut self, address: &Address, fraction_bps: u64) -> u64 {
        let key = address.to_string();
        if !self.accounts.contains_key(&key) {
            return 0;
        }
        let mut total: u64 = 0;

        {
            let acc = self.accounts.get_mut(&key).expect("checked above");
            // Slash from both active stake and unbonding stake — misbehavior during the
            // unbonding period must still carry consequences, otherwise a validator could
            // double-sign and immediately queue an unstake to escape punishment. Only this
            // account's OWN unstaked self-bond counts here (`unbonding_source == None`): if it
            // is unbonding out of some *other* validator's pool, that capital was never backing
            // this validator's misbehavior and is slashed by that validator's own slash instead.
            let slash_staked = (acc.staked as u128 * fraction_bps as u128 / 10_000) as u64;
            acc.staked -= slash_staked;
            total += slash_staked;

            if acc.unbonding_source.is_none() {
                let slash_unbonding =
                    (acc.unbonding_stake as u128 * fraction_bps as u128 / 10_000) as u64;
                acc.unbonding_stake -= slash_unbonding;
                total += slash_unbonding;
            }
        }

        if let Some(pool) = self.validator_pools.get_mut(&key) {
            let slash_pool = (pool.total_delegated_stake as u128 * fraction_bps as u128 / 10_000) as u64;
            pool.total_delegated_stake -= slash_pool;
            total += slash_pool;
        }

        // Delegated capital that has left the pool but is still inside its unbonding window.
        for acc in self.accounts.values_mut() {
            if acc.unbonding_source.as_deref() == Some(key.as_str()) {
                let slash_unbonding =
                    (acc.unbonding_stake as u128 * fraction_bps as u128 / 10_000) as u64;
                acc.unbonding_stake -= slash_unbonding;
                total += slash_unbonding;
            }
        }

        total += self.slash_redelegations_away_from(&key, fraction_bps);

        self.total_burned += total;
        total
    }

    /// Slash the capital that redelegated away from `src` and is still inside its window,
    /// wherever it now sits. Returns the nano-HLX slashed; the caller burns it.
    ///
    /// The loss lands on the redelegator alone — their shares in the destination pool are burned
    /// — rather than on the destination pool's value. Charging the pool would make every other
    /// delegator at the destination pay for a validator they never chose to back, which is the
    /// opposite of what makes shared slashing risk a useful incentive at all.
    fn slash_redelegations_away_from(&mut self, src: &str, fraction_bps: u64) -> u64 {
        let Some(mut entries) = self.redelegations.remove(src) else {
            return 0;
        };
        let mut total: u64 = 0;

        for entry in &mut entries {
            let slash_amt = (entry.amount as u128 * fraction_bps as u128 / 10_000) as u64;
            if slash_amt == 0 {
                continue;
            }
            let Some(pool) = self.validator_pools.get_mut(&entry.dst) else {
                continue;
            };
            if pool.total_delegated_stake == 0 || pool.total_shares == 0 {
                continue;
            }
            // Round the burned share count *up*, so rounding can never leave the redelegator
            // holding value the slash was supposed to take — the same direction
            // `execute_undelegate` rounds in, and for the same reason.
            let shares_to_burn = ((slash_amt as u128 * pool.total_shares as u128)
                .div_ceil(pool.total_delegated_stake as u128)) as u64;

            let Some(held) = self
                .delegator_shares
                .get_mut(&entry.dst)
                .and_then(|m| m.get_mut(&entry.delegator))
            else {
                continue;
            };
            // The redelegator may already have undelegated part of this position — take what is
            // still there and no more. What they undelegated is not lost to the slash: it went
            // into their unbonding queue tagged with `dst`, not `src`, so this entry is the only
            // claim `src` has on it. That is a deliberate, bounded leak; see `TxType::Redelegate`.
            let shares_to_burn = shares_to_burn.min(*held);
            if shares_to_burn == 0 {
                continue;
            }
            let value_burned =
                (shares_to_burn as u128 * pool.total_delegated_stake as u128 / pool.total_shares as u128) as u64;

            *held -= shares_to_burn;
            if *held == 0 {
                self.delegator_shares.get_mut(&entry.dst).unwrap().remove(&entry.delegator);
            }
            pool.total_shares -= shares_to_burn;
            pool.total_delegated_stake -= value_burned;
            entry.amount = entry.amount.saturating_sub(value_burned);
            total += value_burned;
        }

        self.redelegations.insert(src.to_string(), entries);
        total
    }

    /// Update `missed_blocks` from a newly-applied block's `last_commit`, jailing any address
    /// that crosses `DOWNTIME_JAIL_THRESHOLD_BLOCKS`. Called once per block, after the block's
    /// own transactions have executed (see `execute_block`) — `current_validators` is the
    /// active set as of the height being applied (the set the block was actually proposed and
    /// voted against), `signers` is who `BlockHeader::last_commit` proves participated in
    /// finalizing the *previous* block.
    ///
    /// `current_validators` must come from `active_validators`, never from `stakers()`: the two
    /// differ for exactly one epoch after a validator stakes, and charging a missed block in
    /// that window jails a validator that was never allowed to vote in the first place. See
    /// `active_validators`' doc comment for the live incident.
    ///
    /// Returns the addresses newly jailed this call — the caller (`helix-node`'s
    /// `apply_finalized_block`) also fast-jails them out of the live `BftEngine`'s
    /// `ValidatorSet` immediately, the same way `SubmitDoubleSignEvidence` already does for
    /// slashing, rather than waiting for the next epoch rotation to notice `stakers()` shrank.
    pub fn record_block_participation(
        &mut self,
        current_validators: &[Address],
        signers: &std::collections::HashSet<Address>,
        height: u64,
    ) -> Vec<Address> {
        // Absence from the certificate is only evidence of absence if the certificate is
        // credible in the first place — see `commit_certificate_carries_quorum`. Nothing is
        // recorded either way from one that isn't: no misses charged, no counters reset.
        if !self.commit_certificate_carries_quorum(current_validators, signers) {
            return Vec::new();
        }

        let mut newly_jailed = Vec::new();
        for addr in current_validators {
            let key = addr.to_string();
            if signers.contains(addr) {
                self.missed_blocks.remove(&key);
                continue;
            }
            let count = self.missed_blocks.entry(key.clone()).or_insert(0);
            *count += 1;
            if *count >= DOWNTIME_JAIL_THRESHOLD_BLOCKS && !self.jailed_until.contains_key(&key) {
                self.jailed_until.insert(key, height + MIN_JAIL_BLOCKS);
                // Out of the quorum from this block on, not merely at the next rotation — the
                // node fast-jails it out of the live `BftEngine` for the same reason. Leaving
                // it here would keep charging a validator that no longer counts.
                self.active_validators.remove(addr);
                newly_jailed.push(addr.clone());
            }
        }
        newly_jailed
    }

    /// Does `last_commit` prove that a real 2/3+1 majority signed the parent block?
    ///
    /// Downtime-jailing reads a validator's absence from the certificate as proof it was
    /// offline. That inference only holds if the certificate is complete, and **nothing forces
    /// it to be**: a proposer assembles `last_commit` from the precommits it happens to hold,
    /// and `CommitSig::verify` (which `execute_block` applies to every entry) can only catch
    /// *forged* signatures — never *omitted* ones. So the honest failure and the attack look
    /// identical on the wire:
    ///
    /// * Honest — a proposer that finalized via the gossip/RPC fast path never collected the
    ///   precommits at all and proposes with an empty certificate. Live on 2026-07-22: every
    ///   block from validator 2 carried `last_commit=[]`, and every block from validator 1
    ///   carried only validator 1, so validator 2 was charged a miss by *every* block on the
    ///   chain and jailed on a loop while validating perfectly well.
    /// * Hostile — a proposer simply leaves a rival's precommit out. Under the old
    ///   unconditional accounting that jails the rival in 150 blocks at zero cost and with no
    ///   evidence trail. With two validators it is a takeover; the victim's own node reports
    ///   itself healthy throughout.
    ///
    /// Requiring quorum power in the certificate closes both: an omitting proposer can no
    /// longer reach the threshold without including the very validators it is trying to
    /// exclude, so the certificate either accuses nobody or proves its own accusation.
    ///
    /// The trade is deliberate and one-directional: a genuinely offline validator goes unjailed
    /// for as long as certificates stay thin, so it keeps its seat and its power longer than it
    /// deserves. Failing to punish the guilty is recoverable; punishing the innocent, as the
    /// incident above shows, is not.
    ///
    /// Power is computed exactly as consensus computes it — same `ValidatorSet::new`, same
    /// 1 % cap, same `quorum_threshold` — so this can never disagree with the set that actually
    /// voted, and every node deriving it from identical state reaches the identical verdict.
    fn commit_certificate_carries_quorum(
        &self,
        current_validators: &[Address],
        signers: &std::collections::HashSet<Address>,
    ) -> bool {
        let set = helix_consensus::ValidatorSet::new(
            current_validators
                .iter()
                .map(|addr| {
                    helix_consensus::Validator::new(
                        addr.clone(),
                        self.effective_stake(addr),
                        self.has_personhood(addr),
                    )
                })
                .collect(),
            0,
        );
        let signed_power: u64 = set
            .validators
            .iter()
            .filter(|v| signers.contains(&v.address))
            .map(|v| v.voting_power)
            .sum();
        signed_power >= set.quorum_threshold()
    }

    /// Drop redelegation entries whose source-slashing window has closed. Called once per block
    /// (see `execute_block`) — without it every redelegation ever made would stay in consensus
    /// state forever, and each source validator's slash would walk a list that only grows.
    pub fn prune_expired_redelegations(&mut self, height: u64) {
        self.redelegations.retain(|_, entries| {
            entries.retain(|e| height < e.unlock_height && e.amount > 0);
            !entries.is_empty()
        });
    }

    /// Resolve a registered name (without `.hlx`) to its owning address string.
    pub fn resolve_name(&self, name: &str) -> Option<&str> {
        self.names.get(name).map(|s| s.as_str())
    }

    /// The name (without `.hlx`) registered for an address, if any.
    pub fn name_of(&self, address: &Address) -> Option<&str> {
        let addr = address.to_string();
        self.names
            .iter()
            .find(|(_, owner)| **owner == addr)
            .map(|(name, _)| name.as_str())
    }

    /// Proof of Personhood status for an address. Defaults to `Unverified` if unknown.
    pub fn personhood_status(&self, address: &Address) -> PersonhoodStatus {
        self.personhood
            .get(&address.to_string())
            .cloned()
            .unwrap_or(PersonhoodStatus::Unverified)
    }

    pub fn set_personhood_status(&mut self, address: &Address, status: PersonhoodStatus) {
        self.personhood.insert(address.to_string(), status);
    }

    pub fn has_personhood(&self, address: &Address) -> bool {
        self.personhood_status(address).is_verified()
    }

    /// The social-recovery guardian set registered for `address`, if any.
    pub fn guardians(&self, address: &Address) -> Option<&GuardianSet> {
        self.guardians.get(&address.to_string())
    }

    pub fn set_guardians(&mut self, address: &Address, set: GuardianSet) {
        self.guardians.insert(address.to_string(), set);
    }

    /// The in-progress guardian approval vote for recovering `address`, if any.
    pub fn recovery_request(&self, address: &Address) -> Option<&RecoveryRequest> {
        self.recovery_requests.get(&address.to_string())
    }

    pub fn set_recovery_request(&mut self, address: &Address, request: RecoveryRequest) {
        self.recovery_requests.insert(address.to_string(), request);
    }

    pub fn clear_recovery_request(&mut self, address: &Address) {
        self.recovery_requests.remove(&address.to_string());
    }

    /// The active guardian-recovered public key for `address`, if its control was ever
    /// socially recovered. `None` means the address is still controlled by its original key.
    pub fn recovery_key(&self, address: &Address) -> Option<&PublicKey> {
        self.recovery_keys.get(&address.to_string())
    }

    pub fn set_recovery_key(&mut self, address: &Address, key: PublicKey) {
        self.recovery_keys.insert(address.to_string(), key);
    }

    /// Addresses that meet the minimum stake threshold — candidates for the next validator epoch.
    ///
    /// Sorted by address: `self.accounts` is a `HashMap`, whose iteration order depends on
    /// a per-process random seed (Rust's `RandomState`, by design — DoS hardening) and is
    /// therefore *not* the same across independently-running validator processes, even
    /// with identical account state. `ValidatorSet::new()` does not sort its input, and
    /// `proposer_for_round()` picks the proposer by index into that list — so every node
    /// building a `ValidatorSet` from an unsorted `stakers()` could compute a different
    /// round-robin order, and thus disagree on whose turn it is, silently halting the
    /// chain the moment more than one validator is active. Found by actually running a
    /// multi-node local testnet: rock solid with a single validator (this was
    /// unreachable — a one-element list has only one possible order), silent full
    /// consensus stall at the very first epoch rotation with three.
    pub fn stakers(&self) -> Vec<(Address, u64)> {
        let min_stake = self.governance_params.min_validator_stake;
        let mut stakers: Vec<(Address, u64)> = self
            .accounts
            .values()
            .filter_map(|acc| {
                // Downtime-jailed: excluded until an explicit `Unjail` tx removes the entry,
                // regardless of stake — jailing never touches the stake itself, only
                // eligibility. See `jailed_until`'s doc comment.
                if self.jailed_until.contains_key(&acc.address) {
                    return None;
                }
                let addr = Address::from_str(&acc.address).ok()?;
                let effective = self.effective_stake(&addr);
                (effective >= min_stake).then_some((addr, effective))
            })
            .collect();
        stakers.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
        stakers
    }

    /// The validator set a node's live BFT engine should run, matching exactly what the
    /// consensus rotation last installed. A node that catches up through `sync_blocks_from_peer`
    /// executes blocks (rotating `active_validators` in state) but never mirrors that into the
    /// live engine — only the finalize path calls `rotate_validator_set` — so an engine built
    /// from the wrong source diverges on the round-robin proposer schedule and silently stalls
    /// the chain the moment more than one validator is active. See backlog #129 for the live
    /// incident (two operators, both freshly synced, both stalled at the first epoch after a
    /// reset).
    ///
    /// Prefer `active_validators` — the post-rotation truth, folded into `state_hash`, and the
    /// exact set `rotate_active_validators` produced (so a staker still serving its one-epoch
    /// activation delay is correctly *excluded*, unlike raw `stakers()` which would wrongly
    /// include it). Fall back to `stakers()` only when the field is empty, which on a chain
    /// launched fresh no longer happens: `GenesisConfig::build_state` seeds the genesis
    /// validators into `active_validators` at block 0 precisely so this fallback cannot hand a
    /// joining node the undelayed staker set during the first activation epoch (the window in
    /// which the first rotation has deferred everyone and the field would otherwise still be
    /// empty). The only remaining empty case is a database written *before* `active_validators`
    /// existed — a one-time upgrade migration — where every staker was already live and
    /// participating, so `stakers()` still ≈ the set the network runs until the next rotation
    /// repopulates the field. Address-sorted, byte for byte the order `rotate_active_validators`
    /// returns, so the computed proposer schedule is identical to a node that rotated live.
    pub fn engine_validator_set(&self) -> Vec<(Address, u64, bool)> {
        if self.active_validators.is_empty() {
            // Migration / genesis window before any rotation recorded an active set: every
            // qualifying staker runs as a full member, exactly as before probation existed.
            return self.stakers().into_iter().map(|(a, s)| (a, s, false)).collect();
        }
        self.tagged_engine_set()
    }

    /// The current set as a real [`helix_consensus::ValidatorSet`] — same membership, the same
    /// 1 % cap, the same `quorum_threshold`.
    ///
    /// The single place that turns chain state into a set, so voting power cannot be computed
    /// two ways and drift. `validators_from_state` in the node and the `/validators` RPC route
    /// both go through here: one builds the engine's live set, the other only reports it, and
    /// the point is that a reader is told exactly the numbers consensus is using rather than a
    /// second implementation of the rule that happens to agree today.
    ///
    /// The epoch is `0` because callers that care set their own — this exists for the power
    /// figures, which do not depend on it.
    pub fn consensus_validator_set(&self) -> helix_consensus::ValidatorSet {
        let validators = self
            .engine_validator_set()
            .into_iter()
            .map(|(addr, stake, probationary)| {
                let has_personhood = self.has_personhood(&addr);
                if probationary {
                    helix_consensus::Validator::new_probationary(addr, stake, has_personhood)
                } else {
                    helix_consensus::Validator::new(addr, stake, has_personhood)
                }
            })
            .collect();
        helix_consensus::ValidatorSet::new(validators, 0)
    }

    /// The signing set from the rotation's own truth: `active_validators` as full members
    /// (`probationary = false`) followed by `probationary_validators` (`true`, zero voting power —
    /// see `helix_consensus::Validator::probationary`), each group address-sorted so every node
    /// builds the identical proposer schedule. Returns empty when there is no full member: a set of
    /// only probationers carries no quorum power and must never be installed, so the caller keeps
    /// the set it already has (matching `rotate_validator_set`'s existing empty-list no-op).
    fn tagged_engine_set(&self) -> Vec<(Address, u64, bool)> {
        if self.active_validators.is_empty() {
            return Vec::new();
        }
        let mut active: Vec<&Address> = self.active_validators.iter().collect();
        active.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let mut prob: Vec<&Address> = self.probationary_validators.iter().collect();
        prob.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        active
            .into_iter()
            .map(|a| (a.clone(), self.effective_stake(a), false))
            .chain(prob.into_iter().map(|a| (a.clone(), self.effective_stake(a), true)))
            .collect()
    }

    /// Advance to the next epoch's signing set, in three tiers (backlog #132): a newly-qualifying
    /// staker waits one epoch in `pending_validators`, then one epoch in `probationary_validators`
    /// (in the set to sign, but zero voting power / no proposer turn), and is promoted to full
    /// `active_validators` only if its signature reached a committed `last_commit` during that
    /// probation epoch (`probation_seen`). A staker with no live node behind it therefore never
    /// becomes quorum-critical — it cycles pending → probation → pending without ever gaining
    /// power — which is what stops a phantom from freezing a small set. Returns the full signing
    /// set as `(address, effective_stake, probationary)` for the caller to build the consensus
    /// `ValidatorSet` from.
    ///
    /// Called from `execute_block` at every epoch boundary rather than from the node, because it
    /// mutates consensus state (`pending_validators`, `probationary_validators`, `probation_seen`
    /// — all folded into `state_hash`; `active_validators` is not, see its doc comment). Rotating
    /// only where blocks are *produced* would leave a node that caught up through
    /// `sync_blocks_from_peer` — which executes blocks but never rotated — computing a different
    /// set from the same blocks.
    pub fn rotate_active_validators(&mut self) -> Vec<(Address, u64, bool)> {
        let qualifying: std::collections::HashSet<Address> =
            self.stakers().into_iter().map(|(a, _)| a).collect();

        // Anyone who no longer meets the stake threshold leaves every tier — no credit for a wait
        // they didn't finish, the same rule the two-tier logic applied to `pending_validators`.
        self.active_validators.retain(|a| qualifying.contains(a));
        self.probationary_validators.retain(|a| qualifying.contains(a));
        self.pending_validators.retain(|a| qualifying.contains(a));
        self.probation_seen.retain(|a| qualifying.contains(a));

        // Promote everyone who has served the probation epoch.
        //
        // Promote only a probationer that demonstrably has a node running: its address is in
        // `probation_seen`. A phantom — a stake with no node behind it, the #132 failure mode —
        // never lands there, so it stays at zero voting power indefinitely and quorum never comes
        // to depend on it. It is not slashed and not evicted; it returns to the queue and joins
        // for real the epoch after someone finally runs the node it staked for.
        //
        // What fills `probation_seen` is `TxType::ProbationHeartbeat` — a transaction the
        // probationer signs. Three earlier designs tried to read the same fact out of the
        // consensus stream instead, and all three are worth remembering, because each looked
        // sufficient beforehand and each was disproved by measurement, not by argument:
        //
        //  1. **Its signature in a committed `last_commit`** (as #132 shipped). A probationer holds
        //     zero voting power, so its precommit never completes a quorum and is never awaited;
        //     worse, on a chain producing blocks it usually receives the finished block before the
        //     proposal it would have voted on, and votes not at all. Two correctly-staked,
        //     correctly *running* joiners cycled probation → pending → probation from height 30 to
        //     609 without ever activating.
        //  2. **Precommit what you adopt** (`BftEngine::attest_adopted_block`, kept — it improves
        //     certificates regardless). Narrows the gap but does not close it: a proposer can only
        //     fold a late precommit while it is still on that height, so the delivery window is one
        //     block interval and a peer under load runs behind it. At a 250 ms cadence the joiners
        //     attested 17 blocks each and the proposer folded none.
        //  3. **Reserved proposer turns**, so a running node puts a block bearing its own address
        //     on-chain. This proved liveness on the first try and **forked the chain**: a joiner
        //     that is behind proposes at its slot height on a tip nobody else has, and the network
        //     splits. Measured 2026-07-31 — two different blocks at height 225, the joiner stuck
        //     there while the incumbent ran on, and a full stall once the promotion made it
        //     quorum-critical. Reverted in full. It also made the proposer schedule depend on the
        //     probationary membership, which is exactly the class of local-view-dependent decision
        //     the #116/#117 fork taught us not to build.
        //
        // The transaction avoids all three failure modes structurally rather than by tuning: it
        // has no delivery window (it waits in the mempool), it needs no voting power, and it
        // touches neither the proposer schedule nor quorum, so it cannot fork anything. Signatures
        // still count when they do arrive — that path costs nothing and is a free second chance.
        //
        // The probation tier does two things now: for one epoch a new validator sits in the
        // signing set with zero voting power, so it syncs and participates without being
        // quorum-critical — and in that epoch it has to prove it exists.
        let promoted: Vec<Address> = self
            .probationary_validators
            .iter()
            .filter(|a| self.probation_seen.contains(*a))
            .cloned()
            .collect();
        for a in &promoted {
            self.active_validators.insert(a.clone());
        }

        // Pending stakers that have served their one-epoch delay enter probation: in the signing
        // set so they can prove liveness, but with zero voting power and no proposer turn, so they
        // cannot make the chain depend on them before they've shown a node is actually running.
        let new_probationary: std::collections::HashSet<Address> = self
            .pending_validators
            .iter()
            .filter(|a| !self.active_validators.contains(*a))
            .cloned()
            .collect();

        // Everyone qualifying who is neither active nor entering probation is new — or a probationer
        // that failed to prove liveness. Both (re)start the one-epoch pending delay, so a phantom
        // cycles pending → probation → pending indefinitely without ever becoming quorum-critical,
        // and rejoins for real the epoch after its node finally signs.
        let new_pending: std::collections::HashSet<Address> = qualifying
            .iter()
            .filter(|a| !self.active_validators.contains(*a) && !new_probationary.contains(*a))
            .cloned()
            .collect();

        self.probationary_validators = new_probationary;
        self.pending_validators = new_pending;
        self.probation_seen.clear(); // fresh window for the new probation cohort

        // On the very first rotation of a migrated chain (empty `active_validators`) this returns
        // empty — a no-op that leaves the sitting validators on the `stakers()` fallback set until
        // a promotion populates `active_validators` — exactly the old empty-list behaviour.
        self.tagged_engine_set()
    }

    /// Mark every probationary validator whose verified signature is in this block's `last_commit`
    /// as having proved itself live this epoch. `signers` is the same validated set
    /// `record_block_participation` scores against (see `execute_block`), so a proposer can neither
    /// fabricate nor omit a probationer's liveness beyond what it can already do for any signature.
    /// Accumulated across the probation epoch and consumed by `rotate_active_validators`.
    /// Whether `address` is serving probation *and* still owes the network its liveness proof.
    ///
    /// The single condition that bounds `TxType::ProbationHeartbeat`'s base-fee exemption: it is
    /// true for at most one transaction per probationer per epoch, and only for an address with
    /// `min_validator_stake` locked up. Read by the fee path *before* execution, so it must not
    /// depend on anything the transaction itself changes.
    pub fn probation_proof_outstanding(&self, address: &Address) -> bool {
        self.probationary_validators.contains(address) && !self.probation_seen.contains(address)
    }

    pub fn record_probation_liveness(
        &mut self,
        signers: &std::collections::HashSet<Address>,
        proposer: &Address,
    ) {
        if self.probationary_validators.is_empty() {
            return;
        }
        // Proposing is the proof that actually works. A probationer holds zero voting power, so its
        // precommit is never awaited and — on a chain producing blocks — it usually receives the
        // finished block before the proposal it would have voted on, and votes not at all. Two
        // attempts to read liveness out of the vote stream failed on exactly that (backlog #141).
        // A block's proposer, by contrast, is named in its signed header: on-chain, identical on
        // every node, with no delivery window to miss. `ValidatorSet::probation_proof_proposer`
        // gives each probationer the turns to produce one.
        if self.probationary_validators.contains(proposer) {
            self.probation_seen.insert(proposer.clone());
        }
        // Signatures still count when they do arrive — a probationer that manages to co-sign has
        // demonstrated the same thing, and there is no reason to make it wait for its own slot.
        for addr in signers {
            if self.probationary_validators.contains(addr) {
                self.probation_seen.insert(addr.clone());
            }
        }
    }

    /// An address's total stake-weighted backing for validator-set eligibility and BFT
    /// voting power: its own `AccountState::staked` plus whatever its delegation pool (if
    /// any) currently holds. This is deliberately *not* what counts for governance voting
    /// power (`total_staked`/`execute_vote_proposal` use `AccountState::staked` alone) —
    /// delegating to a validator earns a share of its block rewards, not a share of its
    /// governance influence; see `TxType::Delegate`'s doc comment.
    pub fn effective_stake(&self, address: &Address) -> u64 {
        let self_staked = self.accounts.get(&address.to_string()).map(|a| a.staked).unwrap_or(0);
        let delegated = self
            .validator_pools
            .get(&address.to_string())
            .map(|p| p.total_delegated_stake)
            .unwrap_or(0);
        self_staked.saturating_add(delegated)
    }

    /// Total HLX staked across every account — the governance voting-power pool. Deliberately
    /// self-stake only (not `effective_stake`) — see `effective_stake`'s doc comment.
    pub fn total_staked(&self) -> u64 {
        self.accounts.values().map(|acc| acc.staked).sum()
    }

    /// The largest *effective* stake (self plus delegated — see `effective_stake`) held by
    /// any single account. Used to bound how high governance can push `min_validator_stake`:
    /// a proposed value above this would
    /// disqualify every current staker at once, leaving `stakers()` empty — see the
    /// ceiling check in `execute_create_proposal`.
    pub fn max_single_stake(&self) -> u64 {
        self.accounts
            .keys()
            .filter_map(|k| Address::from_str(k).ok())
            .map(|addr| self.effective_stake(&addr))
            .max()
            .unwrap_or(0)
    }

    /// A delegator's current redeemable HLX value in a validator's pool — their shares'
    /// proportional cut of `total_delegated_stake`, reflecting any rewards auto-compounded
    /// or slashing applied since they delegated. `None` if this pool or this delegator's
    /// position in it doesn't exist.
    pub fn delegation_value(&self, validator: &Address, delegator: &Address) -> Option<u64> {
        let pool = self.validator_pools.get(&validator.to_string())?;
        if pool.total_shares == 0 {
            return None;
        }
        let shares = *self.delegator_shares.get(&validator.to_string())?.get(&delegator.to_string())?;
        Some((shares as u128 * pool.total_delegated_stake as u128 / pool.total_shares as u128) as u64)
    }

    /// A deterministic hash of the entire chain state — a diagnostic tool for noticing
    /// when two nodes have (for whatever reason) computed different results from the same
    /// block history. This is deliberately NOT a protocol-level state root: it isn't in
    /// `BlockHeader`, isn't signed, isn't checked as part of block validity, and doesn't
    /// gate consensus in any way. A real state root — committed in the header, verified by
    /// every node as part of applying a block — is a materially bigger change (wire format,
    /// full state-commitment scheme) and remains a separate, unstarted piece of work. What
    /// this DOES give operators today: call it after applying the same block on two nodes
    /// and compare. If they differ, something has diverged; if they match, nothing has (for
    /// everything covered by this hash).
    ///
    /// `HashMap`/`HashSet` iteration order is not stable across processes — Rust's default
    /// hasher (SipHash) uses a random per-process seed — so bincode-serializing one
    /// directly would make this hash different on every node even when their *contents*
    /// are identical, producing constant false positives. Every such collection is
    /// therefore rewritten into a sorted `BTreeMap`/`BTreeSet`/sorted `Vec` first,
    /// including ones nested inside stored values — `GovernanceProposal::voters` is a
    /// `HashSet<String>`, so proposals get the same treatment via `CanonicalProposal`
    /// rather than being hashed as-is.
    pub fn state_hash(&self) -> Hash {
        #[derive(Serialize)]
        struct CanonicalProposal<'a> {
            id: u64,
            proposer: &'a str,
            param: &'a crate::governance::GovernanceParam,
            new_value: u64,
            created_at_height: u64,
            voters: Vec<&'a str>,
            yes_stake: u64,
            total_staked_at_creation: u64,
            executed: bool,
        }

        #[derive(Serialize)]
        struct Canonical<'a> {
            accounts: BTreeMap<&'a str, &'a AccountState>,
            total_supply: u64,
            total_issued: u64,
            total_burned: u64,
            names: BTreeMap<&'a str, &'a str>,
            personhood: BTreeMap<&'a str, &'a PersonhoodStatus>,
            guardians: BTreeMap<&'a str, &'a GuardianSet>,
            recovery_requests: BTreeMap<&'a str, &'a RecoveryRequest>,
            recovery_keys: BTreeMap<&'a str, &'a PublicKey>,
            governance_params: &'a GovernanceParams,
            proposals: BTreeMap<u64, CanonicalProposal<'a>>,
            next_proposal_id: u64,
            used_personhood_commitments: std::collections::BTreeSet<[u8; 16]>,
            slashed_double_sign_incidents: std::collections::BTreeSet<&'a str>,
            // Sorted by raw bytes (PublicKey has no Ord impl) — treated as a set for
            // hashing purposes even though it's stored as an insertion-ordered Vec, so two
            // configs listing the same authorities in a different order still hash equal.
            personhood_authorities: std::collections::BTreeSet<&'a [u8]>,
            validator_pools: BTreeMap<&'a str, &'a DelegationPool>,
            // Nested HashMap -> HashMap, same non-determinism problem as everything else
            // here — flattened to a sorted map of maps rather than hashed as-is.
            delegator_shares: BTreeMap<&'a str, BTreeMap<&'a str, u64>>,
            // Only the outer map needs sorting: each `Vec<Redelegation>` is built by pushing
            // in transaction order and pruned with `retain`, both of which every node performs
            // identically, so the vector order is already consensus-deterministic.
            redelegations: BTreeMap<&'a str, &'a Vec<Redelegation>>,
            // Byte-string keys have no Ord impl conflict to worry about (unlike
            // PublicKey above) — Vec<u8> already implements Ord lexicographically.
            contract_storage: BTreeMap<&'a str, BTreeMap<&'a Vec<u8>, &'a Vec<u8>>>,
            genesis_validator_stake: u64,
            genesis_allocations: BTreeMap<&'a str, u64>,
            pending_validators: std::collections::BTreeSet<&'a str>,
            // `active_validators` is deliberately NOT hashed — see the note below the struct.
            probationary_validators: std::collections::BTreeSet<&'a str>,
            probation_seen: std::collections::BTreeSet<&'a str>,
            missed_blocks: BTreeMap<&'a str, u32>,
            jailed_until: BTreeMap<&'a str, u64>,
        }

        let canonical = Canonical {
            accounts: self.accounts.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            total_supply: self.total_supply,
            total_issued: self.total_issued,
            total_burned: self.total_burned,
            names: self.names.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
            personhood: self.personhood.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            guardians: self.guardians.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            recovery_requests: self.recovery_requests.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            recovery_keys: self.recovery_keys.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            governance_params: &self.governance_params,
            proposals: self
                .proposals
                .iter()
                .map(|(id, p)| {
                    let mut voters: Vec<&str> = p.voters.iter().map(|v| v.as_str()).collect();
                    voters.sort_unstable();
                    (
                        *id,
                        CanonicalProposal {
                            id: p.id,
                            proposer: &p.proposer,
                            param: &p.param,
                            new_value: p.new_value,
                            created_at_height: p.created_at_height,
                            voters,
                            yes_stake: p.yes_stake,
                            total_staked_at_creation: p.total_staked_at_creation,
                            executed: p.executed,
                        },
                    )
                })
                .collect(),
            next_proposal_id: self.next_proposal_id,
            used_personhood_commitments: self.used_personhood_commitments.iter().copied().collect(),
            slashed_double_sign_incidents: self.slashed_double_sign_incidents.iter().map(|s| s.as_str()).collect(),
            personhood_authorities: self.personhood_authorities.iter().map(|k| k.as_bytes()).collect(),
            validator_pools: self.validator_pools.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            delegator_shares: self
                .delegator_shares
                .iter()
                .map(|(k, v)| (k.as_str(), v.iter().map(|(dk, dv)| (dk.as_str(), *dv)).collect()))
                .collect(),
            redelegations: self.redelegations.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            contract_storage: self
                .contract_storage
                .iter()
                .map(|(k, v)| (k.as_str(), v.iter().collect()))
                .collect(),
            genesis_validator_stake: self.genesis_validator_stake,
            genesis_allocations: self
                .genesis_allocations
                .iter()
                .map(|(a, b)| (a.as_str(), *b))
                .collect(),
            pending_validators: self.pending_validators.iter().map(|a| a.as_str()).collect(),
            probationary_validators: self.probationary_validators.iter().map(|a| a.as_str()).collect(),
            probation_seen: self.probation_seen.iter().map(|a| a.as_str()).collect(),
            missed_blocks: self.missed_blocks.iter().map(|(k, v)| (k.as_str(), *v)).collect(),
            jailed_until: self.jailed_until.iter().map(|(k, v)| (k.as_str(), *v)).collect(),
        };

        let bytes = bincode::serialize(&canonical).expect("canonical chain state serialization is infallible");
        Hash::digest(&bytes)
    }

    pub fn proposal(&self, id: u64) -> Option<&GovernanceProposal> {
        self.proposals.get(&id)
    }

    pub fn set_proposal(&mut self, proposal: GovernanceProposal) {
        self.proposals.insert(proposal.id, proposal);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::GovernanceParam;
    use helix_crypto::KeyPair;

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&helix_crypto::PublicKey::from_bytes(vec![seed; 8]))
    }

    /// `active_validators` must stay out of `state_hash`, and this pins that as a decision
    /// rather than an accident. `verify_genesis_reconstruction` compares `state_hash` when a
    /// node joins a chain, so any field added to it changes the reconstructed genesis and
    /// locks every existing chain out of the upgrade — measured on 2026-07-21, where hashing
    /// this one field alone would have forced a full devnet reset just to ship a bug fix.
    ///
    /// Whoever "fixes" this by adding the field back: read the field's doc comment first, and
    /// be aware that doing so requires a chain reset. Nothing is lost by leaving it out —
    /// `missed_blocks`/`jailed_until`, the state this set actually drives, remain hashed, so a
    /// real disagreement still surfaces there within a block or two.
    /// The state hash must not depend on the order things were inserted.
    ///
    /// Every collection in `Canonical` is a `BTreeMap`/`BTreeSet` for exactly this reason, with
    /// the reasoning written out field by field. Nothing enforced it. A `HashMap` slipping into
    /// that struct — the natural thing to reach for when adding a field — makes the hash depend
    /// on iteration order, so two nodes with identical state report different hashes and the
    /// network looks forked when it is not. It would show up as an intermittent disagreement that
    /// changes between restarts, which is close to the worst thing to have to debug.
    #[test]
    fn the_state_hash_does_not_depend_on_insertion_order() {
        let mut forwards = ChainState::new(1_000_000);
        for i in 1..=8u8 {
            stake(&mut forwards, i, 1_000 + u64::from(i));
            forwards.names.insert(format!("name{i}"), addr(i).to_string());
            forwards.jailed_until.insert(addr(i).to_string(), u64::from(i) * 10);
            // Contract storage is the one map here whose keys and insertion order are chosen by
            // user code rather than by the protocol, so it is the one an attacker could actually
            // steer if it were ever hashed in iteration order.
            forwards.contract_storage_write(&addr(1), vec![i], vec![i, i]);
        }

        let mut backwards = ChainState::new(1_000_000);
        for i in (1..=8u8).rev() {
            stake(&mut backwards, i, 1_000 + u64::from(i));
            backwards.names.insert(format!("name{i}"), addr(i).to_string());
            backwards.jailed_until.insert(addr(i).to_string(), u64::from(i) * 10);
            backwards.contract_storage_write(&addr(1), vec![i], vec![i, i]);
        }

        assert_eq!(
            forwards.state_hash(),
            backwards.state_hash(),
            "same state, opposite insertion order — the hash must not be able to tell them apart",
        );
    }

    /// Every field that carries value or decides consensus has to reach the hash.
    ///
    /// A field left out of `Canonical` is worse than a wrong one: nodes disagree about it in
    /// silence, because the number they compare says they agree. That is exactly how #142 stayed
    /// hidden for 26 k blocks — a doubled block reward, identical block hashes, and a supply
    /// divergence nobody was looking at. `total_issued` and `total_burned` are in the hash today,
    /// and this pins them there along with the rest.
    #[test]
    fn every_value_bearing_field_changes_the_state_hash() {
        let base = || {
            let mut s = ChainState::new(1_000_000_000);
            stake(&mut s, 1, 5_000);
            s
        };

        let reference = base().state_hash();

        let mut issued = base();
        issued.total_issued += 1;
        assert_ne!(issued.state_hash(), reference, "total_issued must be hashed (#142)");

        let mut burned = base();
        burned.total_burned += 1;
        assert_ne!(burned.state_hash(), reference, "total_burned must be hashed");

        let mut balance = base();
        balance.update_account(&addr(1), |a| a.balance += 1);
        assert_ne!(balance.state_hash(), reference, "balances must be hashed");

        let mut staked = base();
        staked.update_account(&addr(1), |a| a.staked += 1);
        assert_ne!(staked.state_hash(), reference, "stake must be hashed");

        let mut unbonding = base();
        unbonding.update_account(&addr(1), |a| a.unbonding_stake += 1);
        assert_ne!(unbonding.state_hash(), reference, "unbonding capital must be hashed");

        let mut nonce = base();
        nonce.update_account(&addr(1), |a| a.nonce += 1);
        assert_ne!(nonce.state_hash(), reference, "nonces must be hashed — replay protection");

        let mut jailed = base();
        jailed.jailed_until.insert(addr(1).to_string(), 999);
        assert_ne!(jailed.state_hash(), reference, "jailing must be hashed — it gates the set");

        let mut missed = base();
        missed.missed_blocks.insert(addr(1).to_string(), 7);
        assert_ne!(missed.state_hash(), reference, "downtime counters must be hashed");

        let mut params = base();
        params.governance_params.min_validator_stake += 1;
        assert_ne!(
            params.state_hash(),
            reference,
            "governance parameters must be hashed — they decide who is a validator",
        );

        let mut pending = base();
        pending.pending_validators.insert(addr(2));
        assert_ne!(pending.state_hash(), reference, "the activation queue must be hashed");

        let mut probation = base();
        probation.probationary_validators.insert(addr(2));
        assert_ne!(probation.state_hash(), reference, "probation must be hashed");
    }

    #[test]
    fn active_validators_stays_out_of_the_state_hash() {
        let mut state = ChainState::new(1_000_000);
        stake(&mut state, 1, 1_000);
        let before = state.state_hash();

        state.active_validators.insert(addr(1));
        assert_eq!(
            state.state_hash(),
            before,
            "hashing active_validators would change genesis reconstruction and shut every \
             running chain out of the upgrade — see the field's doc comment"
        );

        // The state it drives is still hashed, so a genuine divergence is not invisible.
        state.missed_blocks.insert(addr(1).to_string(), 1);
        assert_ne!(
            state.state_hash(),
            before,
            "missed_blocks must stay in the hash — that is what makes the exclusion detectable"
        );
    }

    /// `applied_height` labels the hash; it must not be an input to it. Hashing it would change
    /// reconstructed genesis and lock every running chain out of the upgrade — the same trap
    /// `active_validators` documents, and one that has already cost this project a near-reset.
    #[test]
    fn applied_height_stays_out_of_the_state_hash() {
        let mut state = ChainState::new(1_000_000);
        stake(&mut state, 1, 1_000);
        let before = state.state_hash();

        state.applied_height = 72_769;
        assert_eq!(
            state.state_hash(),
            before,
            "a label for the state must not alter the state's hash — see the field's doc comment"
        );

        // And it is not silently ignored either: it is readable, which is the entire point,
        // since `/status` reports it alongside the hash it belongs to.
        assert_eq!(state.applied_height, 72_769);
    }

    #[test]
    fn state_hash_is_stable_regardless_of_account_insertion_order() {
        let mut forward = ChainState::new(1_000_000);
        for i in 0..20u8 {
            forward.update_account(&addr(i), |acc| {
                acc.balance = i as u64 * 1000;
                acc.staked = i as u64;
            });
        }

        let mut backward = ChainState::new(1_000_000);
        for i in (0..20u8).rev() {
            backward.update_account(&addr(i), |acc| {
                acc.balance = i as u64 * 1000;
                acc.staked = i as u64;
            });
        }

        assert_eq!(
            forward.state_hash(),
            backward.state_hash(),
            "identical accounts inserted in different order must hash the same"
        );
    }

    /// Regression test for a consensus-halting bug found by actually running a
    /// multi-node local testnet (single-validator devnets can never exercise this —
    /// a one-element list has only one possible order): `stakers()` used to return
    /// `self.accounts.values()` in raw HashMap iteration order, which depends on a
    /// per-process random seed. `ValidatorSet::new()` doesn't sort its input, and
    /// `proposer_for_round()` indexes into that list — so two validator processes
    /// with byte-identical stake could still disagree on round-robin order, and thus
    /// on whose turn it is to propose, silently halting the chain the moment more
    /// than one validator is active. `stakers()` must return the same order no
    /// matter what order the underlying HashMap happens to iterate in.
    /// What an out-of-range `min_validator_stake` does, demonstrated rather than assumed.
    ///
    /// This is the failure the governance path guards against, shown directly: `stakers()` filters
    /// on `effective >= min_stake`, so a value above what anyone holds leaves no set, no finalized
    /// blocks, and no way back — repealing it would need a vote counted by stake weight among
    /// validators that no longer exist.
    ///
    /// Reachable only by writing the parameter directly, as here. A *proposal* carrying such a
    /// value is refused at creation, capped against the largest single stake in existence — see
    /// `a_proposal_that_would_disqualify_every_validator_is_refused_at_creation` in the executor.
    /// This test exists to keep that guard's reason legible, and to fail loudly if `stakers()`
    /// ever stops filtering the way the guard assumes.
    ///
    /// Not hypothetical in the way it sounds: the units are the trap. `min_validator_stake` is
    /// nano-HLX, and proposing "200000" while meaning HLX is off by a factor of a billion. That
    /// exact confusion has already shipped once — `hlx governance propose` took nano where it
    /// documented HLX (fixed in 928c21f).
    #[test]
    fn a_min_stake_above_everyones_balance_empties_the_validator_set() {
        let mut state = ChainState::new(crate::genesis::TOTAL_SUPPLY_HLX * crate::genesis::NANO_PER_HLX);
        let v = addr(1);
        state.update_account(&v, |a| a.staked = 100_000 * crate::genesis::NANO_PER_HLX);
        assert_eq!(state.stakers().len(), 1, "precondition: a normal validator qualifies");

        // A plausible fat-finger: the whole supply, in nano, as the minimum.
        state.governance_params.min_validator_stake =
            crate::genesis::TOTAL_SUPPLY_HLX * crate::genesis::NANO_PER_HLX;

        assert!(
            state.stakers().is_empty(),
            "documents the failure mode: no validator can qualify, so no block can be finalized \
             and no vote can be counted to undo it",
        );
    }

    #[test]
    fn stakers_is_stable_regardless_of_account_insertion_order() {
        let mut forward = ChainState::new(1_000_000);
        forward.governance_params.min_validator_stake = 1;
        for i in 0..20u8 {
            forward.update_account(&addr(i), |acc| acc.staked = (i as u64) + 1);
        }

        let mut backward = ChainState::new(1_000_000);
        backward.governance_params.min_validator_stake = 1;
        for i in (0..20u8).rev() {
            backward.update_account(&addr(i), |acc| acc.staked = (i as u64) + 1);
        }

        assert_eq!(
            forward.stakers(),
            backward.stakers(),
            "identical stakers inserted in different order must come back in the same order"
        );
    }

    #[test]
    fn state_hash_changes_when_a_balance_changes() {
        let mut state = ChainState::new(0);
        state.set_balance(&addr(1), 100);
        let before = state.state_hash();

        state.set_balance(&addr(1), 101);
        let after = state.state_hash();

        assert_ne!(before, after, "a real state change must change the hash");
    }

    #[test]
    fn state_hash_is_stable_regardless_of_proposal_voter_order() {
        // GovernanceProposal::voters is a HashSet<String> — the one nested non-deterministic
        // collection in ChainState. This is the case CanonicalProposal exists to fix.
        let voters_a: std::collections::HashSet<String> =
            ["alice", "bob", "carol", "dave"].iter().map(|s| s.to_string()).collect();
        let voters_b: std::collections::HashSet<String> =
            ["dave", "carol", "bob", "alice"].iter().map(|s| s.to_string()).collect();
        assert_eq!(voters_a, voters_b, "sanity: these really are the same set");

        let base_proposal = GovernanceProposal {
            id: 0,
            proposer: "alice".to_string(),
            param: GovernanceParam::FuelPerFeeUnit,
            new_value: 42,
            created_at_height: 10,
            voters: voters_a,
            yes_stake: 400,
            total_staked_at_creation: 1000,
            executed: false,
        };

        let mut state_a = ChainState::new(0);
        state_a.set_proposal(base_proposal.clone());

        let mut state_b = ChainState::new(0);
        state_b.set_proposal(GovernanceProposal { voters: voters_b, ..base_proposal });

        assert_eq!(
            state_a.state_hash(),
            state_b.state_hash(),
            "same voters inserted in different order must hash the same"
        );
    }

    #[test]
    fn state_hash_is_stable_regardless_of_set_insertion_order() {
        let mut forward = ChainState::new(0);
        forward.used_personhood_commitments.insert([1u8; 16]);
        forward.used_personhood_commitments.insert([2u8; 16]);
        forward.slashed_double_sign_incidents.insert("v1:10:0".to_string());
        forward.slashed_double_sign_incidents.insert("v2:20:1".to_string());

        let mut backward = ChainState::new(0);
        backward.slashed_double_sign_incidents.insert("v2:20:1".to_string());
        backward.slashed_double_sign_incidents.insert("v1:10:0".to_string());
        backward.used_personhood_commitments.insert([2u8; 16]);
        backward.used_personhood_commitments.insert([1u8; 16]);

        assert_eq!(forward.state_hash(), backward.state_hash());
    }

    #[test]
    fn state_hash_reflects_personhood_authority() {
        let mut state = ChainState::new(0);
        let before = state.state_hash();

        state.personhood_authorities.push(KeyPair::generate().public);
        let after = state.state_hash();

        assert_ne!(before, after);
    }

    fn stake(state: &mut ChainState, seed: u8, amount: u64) {
        state.update_account(&addr(seed), |acc| acc.staked = amount);
    }

    /// The joiner-side half of #129: the set a synced node installs into its live engine must be
    /// the rotation's own truth (`active_validators`), address-sorted exactly as
    /// `rotate_active_validators` returns it — never raw `stakers()`, which would wrongly hand a
    /// still-pending staker quorum weight and desynchronise the round-robin proposer schedule
    /// from every node that rotated live, silently stalling the chain.
    #[test]
    fn engine_validator_set_mirrors_active_validators_not_raw_stakers() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 3, 100);
        stake(&mut state, 1, 100);
        stake(&mut state, 2, 100); // qualifies but will be held out of the active set

        // Before any rotation has populated `active_validators`, fall back to `stakers()` (every
        // qualifying staker a full member) so a fresh chain's genesis validators still run.
        let stakers_as_full: Vec<(Address, u64, bool)> =
            state.stakers().into_iter().map(|(a, s)| (a, s, false)).collect();
        assert_eq!(
            state.engine_validator_set(),
            stakers_as_full,
            "with no rotation yet, the engine set is the genesis staker set, all full members"
        );

        // Rotation makes {1,3} active; 2 is still serving its activation delay.
        state.active_validators = [addr(1), addr(3)].into_iter().collect();

        let mut expected = vec![(addr(1), 100u64, false), (addr(3), 100u64, false)];
        expected.sort_by(|(a, _, _), (b, _, _)| a.as_str().cmp(b.as_str()));
        assert_eq!(
            state.engine_validator_set(),
            expected,
            "engine set must be exactly the active validators, address-sorted, and must NOT \
             include the still-pending staker that stakers() would"
        );

        // Prove the two sources genuinely differ here, so the choice actually mattered.
        assert!(
            state.stakers().iter().any(|(a, _)| a == &addr(2)),
            "precondition: stakers() includes the pending staker"
        );
        assert!(
            !state.engine_validator_set().iter().any(|(a, _, _)| a == &addr(2)),
            "the pending staker must never reach the live engine set"
        );
    }

    /// The arithmetic the `/validators` route now publishes, pinned here rather than trusted.
    ///
    /// Two validators whose stakes differ by 20x end up with **identical** voting power, because
    /// both sit above the 1 % cap. This is the result that has been miscalculated twice from
    /// stake alone, and the reason the RPC reports power instead of leaving clients to derive it:
    /// "who has more stake" and "who has more say" are not the same question here.
    #[test]
    fn consensus_validator_set_caps_power_and_reports_quorum() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 100_000);
        stake(&mut state, 2, 2_000_000); // 20x the stake of validator 1
        state.active_validators = [addr(1), addr(2)].into_iter().collect();

        let set = state.consensus_validator_set();
        let power = |a: Address| {
            set.validators.iter().find(|v| v.address == a).unwrap().voting_power
        };

        // total_stake = 2,100,000 ⇒ cap = 21,000. Without personhood raw power is stake/2, so
        // validator 1 offers 50,000 and validator 2 offers 1,000,000 — both are cut to the cap.
        assert_eq!(power(addr(1)), 21_000);
        assert_eq!(power(addr(2)), 21_000);
        assert_eq!(
            power(addr(1)),
            power(addr(2)),
            "above the cap, twenty times the stake buys exactly no extra say"
        );

        assert_eq!(set.total_voting_power(), 42_000);
        assert_eq!(set.quorum_threshold(), 42_000 * 2 / 3 + 1);

        // The consequence that matters operationally: with two equal validators the threshold is
        // above what either one carries alone, so both must sign every block.
        assert!(
            power(addr(1)) < set.quorum_threshold(),
            "a two-validator set has no tolerance for one going quiet"
        );
    }

    /// Routing the node's engine set through `consensus_validator_set` must not change the set
    /// the engine ends up with — otherwise an upgraded validator would compute a different
    /// quorum from identical state than one still on the previous release, and the two would
    /// stop agreeing on blocks.
    ///
    /// This is the whole compatibility argument for that refactor, so it is a test rather than a
    /// comment. It rebuilds the set **the old way** (raw `Validator::new` straight from
    /// `engine_validator_set`) and the new way, installs both exactly as every call site does —
    /// through `ValidatorSet::new(…, epoch)` — and compares the results field by field.
    ///
    /// The reason they agree: `ValidatorSet::new` recomputes `voting_power` from `stake`,
    /// `has_personhood` and `probationary` unconditionally, and touches nothing else. So the
    /// power the new path computes early is overwritten by the identical value, and passing
    /// through it twice is the same as passing through it once.
    #[test]
    fn routing_the_engine_set_through_the_shared_builder_changes_nothing() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 100_000);
        stake(&mut state, 2, 2_000_000);
        stake(&mut state, 3, 150_000);
        state.active_validators = [addr(1), addr(2)].into_iter().collect();
        state.probationary_validators = [addr(3)].into_iter().collect();

        // Exactly what `validators_from_state` did before the refactor.
        let the_old_way: Vec<helix_consensus::Validator> = state
            .engine_validator_set()
            .into_iter()
            .map(|(a, s, probationary)| {
                let hp = state.has_personhood(&a);
                if probationary {
                    helix_consensus::Validator::new_probationary(a, s, hp)
                } else {
                    helix_consensus::Validator::new(a, s, hp)
                }
            })
            .collect();
        let the_new_way = state.consensus_validator_set().validators;

        // Every call site installs the result this way, so compare what the engine actually gets.
        const EPOCH: u64 = 7;
        let old = helix_consensus::ValidatorSet::new(the_old_way, EPOCH);
        let new = helix_consensus::ValidatorSet::new(the_new_way, EPOCH);

        assert_eq!(
            old.validators.len(),
            new.validators.len(),
            "membership must be identical"
        );
        for (o, n) in old.validators.iter().zip(new.validators.iter()) {
            // Order matters as much as content: the proposer schedule is derived from it, and
            // two nodes disagreeing about whose turn it is stall exactly like a fork.
            assert_eq!(o.address, n.address, "order and membership must match");
            assert_eq!(o.stake, n.stake);
            assert_eq!(o.voting_power, n.voting_power);
            assert_eq!(o.probationary, n.probationary);
            assert_eq!(o.has_personhood, n.has_personhood);
        }
        assert_eq!(old.total_voting_power(), new.total_voting_power());
        assert_eq!(old.quorum_threshold(), new.quorum_threshold());

        // Prove the fixture is not trivially equal: a set where everything is zero would pass
        // the loop above while testing nothing.
        assert!(new.total_voting_power() > 0, "precondition: the set carries real power");
        assert!(
            new.validators.iter().any(|v| v.probationary),
            "precondition: a probationer is present, since that is the branch most likely to differ"
        );
    }

    /// A probationer is in the set so its precommits are gathered, but weighs nothing — and the
    /// RPC must be able to tell that apart from "not in the set", which is why power is reported
    /// as an explicit zero here rather than by omitting the validator.
    #[test]
    fn consensus_validator_set_gives_probationers_zero_power() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 100_000);
        stake(&mut state, 2, 100_000);
        state.active_validators = [addr(1)].into_iter().collect();
        state.probationary_validators = [addr(2)].into_iter().collect();

        let set = state.consensus_validator_set();
        let prob = set.validators.iter().find(|v| v.address == addr(2)).unwrap();
        assert!(prob.probationary, "still in the set, so its signatures are collected");
        assert_eq!(prob.voting_power, 0, "but it carries no weight toward quorum");

        // Its stake must also stay out of the total that sets everyone else's cap.
        let full = set.validators.iter().find(|v| v.address == addr(1)).unwrap();
        assert_eq!(set.total_voting_power(), full.voting_power);
    }

    /// A probationary validator (backlog #132) is in the engine set so its precommits are gathered,
    /// but tagged so consensus gives it zero power and no proposer turn.
    #[test]
    fn engine_set_tags_probationary_validators() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 100);
        stake(&mut state, 2, 100);
        state.active_validators = [addr(1)].into_iter().collect();
        state.probationary_validators = [addr(2)].into_iter().collect();

        let set = state.engine_validator_set();
        assert_eq!(set.iter().find(|(a, _, _)| a == &addr(1)).unwrap().2, false, "active is full");
        assert_eq!(
            set.iter().find(|(a, _, _)| a == &addr(2)).unwrap().2,
            true,
            "the probationer must be tagged so it signs with no voting power",
        );
    }

    /// Convenience for the rotation tests: which addresses are active / probationary after a call.
    fn active_addrs(state: &ChainState) -> Vec<Address> {
        let mut v: Vec<Address> = state.active_validators.iter().cloned().collect();
        v.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        v
    }
    fn prob_addrs(state: &ChainState) -> Vec<Address> {
        let mut v: Vec<Address> = state.probationary_validators.iter().cloned().collect();
        v.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        v
    }

    /// The core property (backlog #132): a brand-new staker crosses the set in three steps —
    /// pending, then probation (in the set to sign but powerless), then full active only once it
    /// has proved a live node. Never quorum-critical before that, no matter its stake.
    #[test]
    fn a_new_staker_walks_pending_then_probation_then_active() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 100);
        stake(&mut state, 2, 100);
        state.active_validators = [addr(1)].into_iter().collect(); // 1 already active

        // Rotation 1: the newcomer sits in pending, out of the signing set entirely.
        state.rotate_active_validators();
        assert_eq!(active_addrs(&state), vec![addr(1)]);
        assert!(state.pending_validators.contains(&addr(2)), "newcomer waits one epoch in pending");
        assert!(prob_addrs(&state).is_empty());

        // Rotation 2: it enters probation — now in the signing set, but still not active.
        state.rotate_active_validators();
        assert_eq!(active_addrs(&state), vec![addr(1)], "a probationer is not yet quorum-critical");
        assert_eq!(prob_addrs(&state), vec![addr(2)]);
        assert!(state.pending_validators.is_empty());

        // During the probation epoch its signature lands in a committed last_commit. Recorded, and
        // visible via `/validators`, but no longer a condition of promotion (backlog #141) — the
        // sibling test below covers the case where this never happens, and reaches the same result.
        state.record_probation_liveness(&[addr(2)].into_iter().collect(), &addr(1));

        // Rotation 3: the probation epoch is served, so it is promoted to full active membership.
        state.rotate_active_validators();
        assert_eq!(active_addrs(&state), vec![addr(1), addr(2)], "the probationer activates");
        assert!(prob_addrs(&state).is_empty());
    }

    /// A probationer that proved it is running activates. Paired deliberately with the phantom
    /// test below: identical setup, one difference — this address is in `probation_seen`. Without
    /// the pair, a gate that promotes nobody would look exactly like a gate that works.
    #[test]
    fn a_probationer_that_proved_liveness_is_promoted() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 100);
        stake(&mut state, 2, 100);
        state.active_validators = [addr(1)].into_iter().collect();
        state.probationary_validators = [addr(2)].into_iter().collect();
        state.probation_seen = [addr(2)].into_iter().collect();

        state.rotate_active_validators();

        let mut got = active_addrs(&state);
        got.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let mut expected = vec![addr(1), addr(2)];
        expected.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(got, expected, "a probationer that proved it is running activates");
        assert!(prob_addrs(&state).is_empty(), "the probation cohort is consumed by promotion");
        assert!(state.probation_seen.is_empty(), "and the window resets for the next cohort");
    }

    /// The phantom case, and the whole point of #132: a stake with no node behind it sends no
    /// heartbeat, so `probation_seen` never names it, so it is not promoted. It returns to the
    /// queue and stays at zero voting power for as long as nobody runs the node it staked for —
    /// not slashed, not evicted, just not counted.
    ///
    /// This asserted the exact opposite between 2026-07-30 and 2026-07-31, while the gate had no
    /// proof it could rest on. Its inversion is the clearest statement that the protection is back.
    #[test]
    fn a_phantom_is_not_promoted_and_stays_powerless() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 100);
        stake(&mut state, 2, 100);
        state.active_validators = [addr(1)].into_iter().collect();
        state.probationary_validators = [addr(2)].into_iter().collect();

        state.rotate_active_validators();

        assert_eq!(
            active_addrs(&state),
            vec![addr(1)],
            "a validator whose node never sent a heartbeat must not join the quorum",
        );
        assert!(
            state.pending_validators.contains(&addr(2)),
            "it goes back to pending and may try again — this is a delay, not an eviction",
        );
        assert!(
            !state.tagged_engine_set().iter().any(|(a, _, probationary)| a == &addr(2) && !probationary),
            "and it must never appear as a full member",
        );
    }

    /// `record_probation_liveness` still records a proposal as proof, even though nothing consumes
    /// it while the gate is off — it is the correct semantics and what a fourth attempt at #141
    /// will build on. Pinned so the meaning does not quietly rot while unused.
    #[test]
    fn proposing_a_block_records_a_probationer_as_live() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 100);
        stake(&mut state, 2, 100);
        state.active_validators = [addr(1)].into_iter().collect();
        state.probationary_validators = [addr(2)].into_iter().collect();

        state.record_probation_liveness(&std::collections::HashSet::new(), &addr(2));
        assert!(
            state.probation_seen.contains(&addr(2)),
            "the proposer of a committed block has demonstrably got a node running"
        );

        // And a full member's own block says nothing about the probationer.
        state.probation_seen.clear();
        state.record_probation_liveness(&std::collections::HashSet::new(), &addr(1));
        assert!(state.probation_seen.is_empty(), "scoped to the probation cohort");
    }

    /// A staker that drops below the threshold before promotion forfeits its accrued wait —
    /// re-crossing later starts over, so a stake/unstake/restake cycle can't shortcut the delay.
    #[test]
    fn dropping_below_the_threshold_before_promotion_forfeits_the_wait() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 100);
        stake(&mut state, 2, 100);
        state.active_validators = [addr(1)].into_iter().collect();

        state.rotate_active_validators();
        assert!(state.pending_validators.contains(&addr(2)));

        // Unstakes below the threshold before the next rotation ever promotes it.
        stake(&mut state, 2, 0);
        state.rotate_active_validators();
        assert!(!state.pending_validators.contains(&addr(2)), "no longer qualifying — forgotten");
        assert!(prob_addrs(&state).is_empty());

        // Re-crosses the threshold — must restart at pending, not resume where it left off.
        stake(&mut state, 2, 100);
        state.rotate_active_validators();
        assert!(state.pending_validators.contains(&addr(2)), "re-crossing restarts the delay");
    }

    /// A validator already in the active set is never demoted or delayed by a rotation, even as
    /// its stake changes — being currently active takes priority.
    #[test]
    fn an_already_active_validator_stays_active() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 250);
        state.active_validators = [addr(1)].into_iter().collect();

        state.rotate_active_validators();
        assert_eq!(active_addrs(&state), vec![addr(1)]);
        assert!(state.pending_validators.is_empty());
        assert!(prob_addrs(&state).is_empty());
    }

    /// The point of persisted downtime-jailing: a validator missing from `last_commit` for
    /// `DOWNTIME_JAIL_THRESHOLD_BLOCKS` consecutive blocks gets jailed and immediately
    /// disappears from `stakers()` — regardless of stake — until it explicitly unjails.
    ///
    /// Four validators, not two: with two of equal weight a single signature is 1/2 of the
    /// power and can never reach the 2/3+1 threshold, so the certificate proves nothing and
    /// `commit_certificate_carries_quorum` (rightly) refuses to convict on it. Four is where a
    /// set first survives one absence — the same threshold BFT itself needs — and therefore the
    /// smallest set in which "this validator was absent" is a statement the chain can actually
    /// substantiate.
    #[test]
    fn sustained_absence_jails_and_removes_from_stakers() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        for n in 1..=4 {
            stake(&mut state, n, 1_000);
        }
        let validators = vec![addr(1), addr(2), addr(3), addr(4)];
        let signers_without_2: std::collections::HashSet<Address> =
            [addr(1), addr(3), addr(4)].into_iter().collect();

        let mut newly_jailed = Vec::new();
        for height in 0..DOWNTIME_JAIL_THRESHOLD_BLOCKS as u64 {
            newly_jailed = state.record_block_participation(&validators, &signers_without_2, height);
        }

        assert_eq!(newly_jailed, vec![addr(2)], "exactly the silent validator must be jailed");
        assert!(state.jailed_until.contains_key(&addr(2).to_string()));
        let staker_addrs: Vec<Address> = state.stakers().into_iter().map(|(a, _)| a).collect();
        let mut expected = vec![addr(1), addr(3), addr(4)];
        expected.sort_by(|a, b| a.as_str().cmp(b.as_str())); // `stakers()` orders by address
        assert_eq!(
            staker_addrs, expected,
            "jailed validator must vanish from stakers() despite its stake"
        );
    }

    /// The defence from `commit_certificate_carries_quorum`, in the shape it actually appeared
    /// on the live chain: every block carried a certificate too thin to prove anything, and the
    /// old unconditional accounting jailed a perfectly healthy validator on a 250-block loop.
    ///
    /// Run far past the threshold, so this can't pass merely by being slow.
    #[test]
    fn a_certificate_without_quorum_power_convicts_nobody() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        for n in 1..=4 {
            stake(&mut state, n, 1_000);
        }
        let validators = vec![addr(1), addr(2), addr(3), addr(4)];
        // Two of four: a real majority of the *set*, still short of 2/3+1 of the power. Exactly
        // what a proposer omitting two rivals would produce — and indistinguishable from an
        // honest proposer that simply never collected their precommits.
        let half: std::collections::HashSet<Address> = [addr(1), addr(2)].into_iter().collect();
        let empty = std::collections::HashSet::new();

        for height in 0..(DOWNTIME_JAIL_THRESHOLD_BLOCKS as u64 * 2) {
            assert!(
                state.record_block_participation(&validators, &half, height).is_empty(),
                "an under-quorum certificate must never jail anyone — height {height}"
            );
            assert!(
                state.record_block_participation(&validators, &empty, height).is_empty(),
                "an empty certificate must never jail anyone — height {height}"
            );
        }

        assert!(
            state.jailed_until.is_empty(),
            "no validator may be jailed on evidence that proves nothing"
        );
        assert!(
            state.missed_blocks.is_empty(),
            "an unproven certificate must not even accumulate misses — otherwise a proposer \
             could still drive a rival most of the way to the threshold and finish the job \
             with one honest block"
        );
    }

    /// A validator that goes quiet for a while but signs again before crossing the threshold
    /// must NOT be jailed — and a later silent stretch must start counting from zero, not
    /// carry over "credit" from the earlier near-miss. Mirrors the equivalent guarantee
    /// already proven for the RAM-only round-based mechanism in helix-consensus.
    ///
    /// Four validators for the reason given on `sustained_absence_jails_and_removes_from_stakers`
    /// — and here it matters twice over: with two, `commit_certificate_carries_quorum` would
    /// suppress every conviction, and this test would pass without exercising the reset at all.
    #[test]
    fn a_signature_partway_through_resets_the_miss_counter() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        for n in 1..=4 {
            stake(&mut state, n, 1_000);
        }
        let validators = vec![addr(1), addr(2), addr(3), addr(4)];
        let silent: std::collections::HashSet<Address> =
            [addr(1), addr(3), addr(4)].into_iter().collect();
        let both_sign: std::collections::HashSet<Address> =
            [addr(1), addr(2), addr(3), addr(4)].into_iter().collect();

        for height in 0..DOWNTIME_JAIL_THRESHOLD_BLOCKS as u64 - 1 {
            state.record_block_participation(&validators, &silent, height);
        }
        assert!(!state.jailed_until.contains_key(&addr(2).to_string()), "not jailed yet");
        assert_eq!(
            state.missed_blocks.get(&addr(2).to_string()).copied(),
            Some(DOWNTIME_JAIL_THRESHOLD_BLOCKS - 1),
            "the misses must actually have been counted — otherwise the reset below proves nothing"
        );

        // addr(2) signs once — counter must reset to zero, not just decrement.
        state.record_block_participation(&validators, &both_sign, DOWNTIME_JAIL_THRESHOLD_BLOCKS as u64 - 1);
        assert!(!state.missed_blocks.contains_key(&addr(2).to_string()));

        // One more silent block after the reset must NOT be enough to jail.
        let newly_jailed = state.record_block_participation(
            &validators,
            &silent,
            DOWNTIME_JAIL_THRESHOLD_BLOCKS as u64,
        );
        assert!(newly_jailed.is_empty(), "a single miss right after a reset must not jail");
    }
}
