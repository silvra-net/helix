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
/// (see `record_block_participation`) before persisted downtime-jailing kicks in. Sized to
/// fire only once blocks are already flowing again — the RAM-only, per-node
/// `helix-consensus::LIVENESS_JAIL_ROUNDS` mechanism is what actually keeps the chain
/// producing during the outage itself; this is the follow-up, on-chain layer that makes the
/// exclusion survive node restarts and requires an explicit `Unjail` to undo. 150 blocks ≈
/// 5 minutes at the 2s block time.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
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
    /// Additional validators pre-staked directly at genesis (address, nano-HLX stake),
    /// beyond the one bootstrap validator every chain has always had — see
    /// `GenesisConfig::extra_validators`'s doc comment for why this exists. The actual
    /// stake itself lives in `accounts` like any other; this is purely a record of what
    /// genesis originally configured, so a node joining long after startup via `GET
    /// /genesis` can rebuild byte-for-byte identical genesis state instead of only ever
    /// seeing today's `accounts`, which may have drifted from genesis by then (stakes
    /// changed, validators slashed, etc).
    #[serde(default)]
    pub genesis_extra_validators: Vec<(Address, u64)>,
    /// The bootstrap stake (nano-HLX) the *primary* genesis validator was given at height 0 —
    /// the same kind of record as `genesis_extra_validators`, for the one validator that
    /// predates it.
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
    /// `genesis_extra_validators` and `genesis_validator_stake`: `GENESIS_PREFUND` is a
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
    /// Consecutive blocks (address string -> count) a validator's precommit has been absent
    /// from `BlockHeader::last_commit`, as counted by `record_block_participation`. Reset to
    /// absent the instant a signature from that validator is seen again — a handful of missed
    /// blocks proves nothing (a proposer momentarily behind on gossip, a validator mid-restart),
    /// only sustained absence does. Not the same mechanism as `helix-consensus`'s local,
    /// RAM-only `missed_rounds`/`LIVENESS_JAIL_ROUNDS` (which exists purely to keep blocks
    /// producing at all during an outage) — this is the persisted, on-chain layer that survives
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
    pub fn new(total_supply: u64) -> Self {
        ChainState {
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
            genesis_extra_validators: Vec::new(),
            genesis_validator_stake: 0,
            genesis_allocations: Vec::new(),
            pending_validators: std::collections::HashSet::new(),
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
                newly_jailed.push(addr.clone());
            }
        }
        newly_jailed
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

    /// `stakers()`, but with new entries held out of the active set for one full epoch — see
    /// `pending_validators`' doc comment for why. `previously_active` is the validator set
    /// about to be replaced (i.e. still-current members are never delayed, only genuinely new
    /// ones); mutates `self.pending_validators` in place and returns exactly the addresses
    /// that should make up the new active set this rotation.
    ///
    /// Pure aside from that one mutation, so it's fully unit-testable without a chain, an
    /// engine, or block production — call it repeatedly with the previous call's own state to
    /// simulate consecutive rotations.
    pub fn stakers_after_delayed_activation(
        &mut self,
        previously_active: &std::collections::HashSet<Address>,
    ) -> Vec<(Address, u64)> {
        let current = self.stakers();
        let qualifying: std::collections::HashSet<&Address> = current.iter().map(|(a, _)| a).collect();
        // Anyone who no longer qualifies gets no credit for a wait they didn't finish —
        // re-crossing the threshold later starts the delay over.
        self.pending_validators.retain(|addr| qualifying.contains(addr));

        let mut activated = Vec::with_capacity(current.len());
        let mut still_new = std::collections::HashSet::new();
        for (addr, stake) in &current {
            if previously_active.contains(addr) || self.pending_validators.contains(addr) {
                activated.push((addr.clone(), *stake));
            } else {
                // First time crossing the threshold — sit out this rotation, eligible next time.
                still_new.insert(addr.clone());
            }
        }
        self.pending_validators = still_new;
        activated
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
            genesis_extra_validators: BTreeMap<&'a str, u64>,
            genesis_validator_stake: u64,
            genesis_allocations: BTreeMap<&'a str, u64>,
            pending_validators: std::collections::BTreeSet<&'a str>,
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
            genesis_extra_validators: self
                .genesis_extra_validators
                .iter()
                .map(|(a, s)| (a.as_str(), *s))
                .collect(),
            genesis_validator_stake: self.genesis_validator_stake,
            genesis_allocations: self
                .genesis_allocations
                .iter()
                .map(|(a, b)| (a.as_str(), *b))
                .collect(),
            pending_validators: self.pending_validators.iter().map(|a| a.as_str()).collect(),
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

    /// The core property this whole mechanism exists for: a brand-new staker must sit out
    /// the rotation in which they first qualify, and only activate on the *next* one — never
    /// immediately, no matter how large their stake.
    #[test]
    fn a_new_staker_is_deferred_one_rotation_then_activated() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 100); // already active
        stake(&mut state, 2, 100); // just crossed the threshold

        let previously_active: std::collections::HashSet<Address> = [addr(1)].into_iter().collect();

        let first_rotation = state.stakers_after_delayed_activation(&previously_active);
        assert_eq!(first_rotation, vec![(addr(1), 100)], "the new staker must not appear yet");
        assert!(
            state.pending_validators.contains(&addr(2)),
            "the new staker must be recorded as pending"
        );

        // Simulate the next rotation — the active set hasn't changed (addr(2) never got
        // promoted), so `previously_active` is unchanged too.
        let second_rotation = state.stakers_after_delayed_activation(&previously_active);
        let mut addrs: Vec<Address> = second_rotation.into_iter().map(|(a, _)| a).collect();
        addrs.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(addrs, vec![addr(1), addr(2)], "the staker must activate on the second rotation");
        assert!(state.pending_validators.is_empty(), "a promoted staker must leave the pending set");
    }

    /// A staker that drops back below the threshold before ever being promoted gets no
    /// credit for the wait already spent — re-crossing later must start the delay over, not
    /// pick up where it left off (otherwise a stake/unstake/restake cycle timed around
    /// rotations could shortcut the whole mechanism).
    #[test]
    fn dropping_below_the_threshold_before_promotion_forfeits_the_wait() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 2, 100);
        let empty: std::collections::HashSet<Address> = std::collections::HashSet::new();

        state.stakers_after_delayed_activation(&empty);
        assert!(state.pending_validators.contains(&addr(2)));

        // Unstakes back below the threshold before the next rotation ever promotes it.
        stake(&mut state, 2, 0);
        let after_drop = state.stakers_after_delayed_activation(&empty);
        assert!(after_drop.is_empty());
        assert!(state.pending_validators.is_empty(), "no longer qualifying — forgotten, not retained");

        // Re-crosses the threshold — must defer again, not activate immediately just
        // because it was pending once before.
        stake(&mut state, 2, 100);
        let after_restake = state.stakers_after_delayed_activation(&empty);
        assert!(after_restake.is_empty(), "re-crossing the threshold must restart the delay");
        assert!(state.pending_validators.contains(&addr(2)));
    }

    /// A validator already in the active set is never delayed, regardless of pending-set
    /// state — being currently active always takes priority.
    #[test]
    fn an_already_active_validator_is_never_delayed() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 250); // stake changed since last rotation, still qualifies
        let previously_active: std::collections::HashSet<Address> = [addr(1)].into_iter().collect();

        let activated = state.stakers_after_delayed_activation(&previously_active);
        assert_eq!(activated, vec![(addr(1), 250)]);
        assert!(state.pending_validators.is_empty());
    }

    /// The point of persisted downtime-jailing: a validator missing from `last_commit` for
    /// `DOWNTIME_JAIL_THRESHOLD_BLOCKS` consecutive blocks gets jailed and immediately
    /// disappears from `stakers()` — regardless of stake — until it explicitly unjails.
    #[test]
    fn sustained_absence_jails_and_removes_from_stakers() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 1_000);
        stake(&mut state, 2, 1_000);
        let validators = vec![addr(1), addr(2)];
        let signers_without_2: std::collections::HashSet<Address> = [addr(1)].into_iter().collect();

        let mut newly_jailed = Vec::new();
        for height in 0..DOWNTIME_JAIL_THRESHOLD_BLOCKS as u64 {
            newly_jailed = state.record_block_participation(&validators, &signers_without_2, height);
        }

        assert_eq!(newly_jailed, vec![addr(2)], "exactly the silent validator must be jailed");
        assert!(state.jailed_until.contains_key(&addr(2).to_string()));
        let staker_addrs: Vec<Address> = state.stakers().into_iter().map(|(a, _)| a).collect();
        assert_eq!(staker_addrs, vec![addr(1)], "jailed validator must vanish from stakers() despite its stake");
    }

    /// A validator that goes quiet for a while but signs again before crossing the threshold
    /// must NOT be jailed — and a later silent stretch must start counting from zero, not
    /// carry over "credit" from the earlier near-miss. Mirrors the equivalent guarantee
    /// already proven for the RAM-only round-based mechanism in helix-consensus.
    #[test]
    fn a_signature_partway_through_resets_the_miss_counter() {
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100;
        stake(&mut state, 1, 1_000);
        stake(&mut state, 2, 1_000);
        let validators = vec![addr(1), addr(2)];
        let silent: std::collections::HashSet<Address> = [addr(1)].into_iter().collect();
        let both_sign: std::collections::HashSet<Address> = [addr(1), addr(2)].into_iter().collect();

        for height in 0..DOWNTIME_JAIL_THRESHOLD_BLOCKS as u64 - 1 {
            state.record_block_participation(&validators, &silent, height);
        }
        assert!(!state.jailed_until.contains_key(&addr(2).to_string()), "not jailed yet");

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
