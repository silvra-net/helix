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
        }
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
    pub fn slash(&mut self, address: &Address, fraction_bps: u64) -> u64 {
        let key = address.to_string();
        let Some(acc) = self.accounts.get_mut(&key) else {
            return 0;
        };
        // Slash from both active stake and unbonding stake — misbehavior during the
        // unbonding period must still carry consequences, otherwise a validator could
        // double-sign and immediately queue an unstake to escape punishment.
        let slash_staked = (acc.staked as u128 * fraction_bps as u128 / 10_000) as u64;
        let slash_unbonding = (acc.unbonding_stake as u128 * fraction_bps as u128 / 10_000) as u64;
        acc.staked -= slash_staked;
        acc.unbonding_stake -= slash_unbonding;
        let mut total = slash_staked + slash_unbonding;

        if let Some(pool) = self.validator_pools.get_mut(&key) {
            let slash_pool = (pool.total_delegated_stake as u128 * fraction_bps as u128 / 10_000) as u64;
            pool.total_delegated_stake -= slash_pool;
            total += slash_pool;
        }

        self.total_burned += total;
        total
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
                let addr = Address::from_str(&acc.address).ok()?;
                let effective = self.effective_stake(&addr);
                (effective >= min_stake).then_some((addr, effective))
            })
            .collect();
        stakers.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
        stakers
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
}
