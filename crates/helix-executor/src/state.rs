use std::collections::{BTreeMap, HashMap};

use helix_crypto::{Address, Hash, PublicKey};
use helix_identity::{GuardianSet, PersonhoodStatus, RecoveryRequest};
use serde::{Deserialize, Serialize};

use crate::governance::{GovernanceParams, GovernanceProposal};

/// Unbonding period in blocks — stake stays slashable for 7 days (≈ 12s/block).
/// After this many blocks past the unstake tx, `ClaimUnbonded` releases the funds.
pub const UNBONDING_PERIOD: u64 = 50_400;

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
        let total = slash_staked + slash_unbonding;
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
    pub fn stakers(&self) -> Vec<(Address, u64)> {
        let min_stake = self.governance_params.min_validator_stake;
        self.accounts
            .values()
            .filter(|acc| acc.staked >= min_stake)
            .filter_map(|acc| Address::from_str(&acc.address).ok().map(|addr| (addr, acc.staked)))
            .collect()
    }

    /// Total HLX staked across every account — the governance voting-power pool.
    pub fn total_staked(&self) -> u64 {
        self.accounts.values().map(|acc| acc.staked).sum()
    }

    /// The largest `staked` amount held by any single account. Used to bound how high
    /// governance can push `min_validator_stake`: a proposed value above this would
    /// disqualify every current staker at once, leaving `stakers()` empty — see the
    /// ceiling check in `execute_create_proposal`.
    pub fn max_single_stake(&self) -> u64 {
        self.accounts.values().map(|acc| acc.staked).max().unwrap_or(0)
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
