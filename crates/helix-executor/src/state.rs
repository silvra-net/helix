use std::collections::HashMap;

use helix_crypto::{Address, PublicKey};
use helix_identity::{GuardianSet, PersonhoodStatus, RecoveryRequest};
use serde::{Deserialize, Serialize};

use crate::governance::{GovernanceParams, GovernanceProposal};

/// Per-account ledger state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub address: String,
    /// Liquid balance in nano-HLX (1 HLX = 1_000_000_000 nano-HLX)
    pub balance: u64,
    /// Locked in PoS stake
    pub staked: u64,
    /// Next expected nonce — prevents replay attacks
    pub nonce: u64,
    /// Deployed WASM contract bytecode, if this account is a contract.
    /// `#[serde(default)]` keeps deserialization of pre-Phase-7 redb data working.
    #[serde(default)]
    pub code: Option<Vec<u8>>,
}

impl AccountState {
    pub fn new(address: &Address) -> Self {
        AccountState {
            address: address.to_string(),
            balance: 0,
            staked: 0,
            nonce: 0,
            code: None,
        }
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
    /// Total HLX supply in nano-HLX (fixed at genesis)
    pub total_supply: u64,
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
}

impl ChainState {
    pub fn new(total_supply: u64) -> Self {
        ChainState {
            accounts: HashMap::new(),
            total_supply,
            total_burned: 0,
            names: HashMap::new(),
            personhood: HashMap::new(),
            guardians: HashMap::new(),
            recovery_requests: HashMap::new(),
            recovery_keys: HashMap::new(),
            governance_params: GovernanceParams::default(),
            proposals: HashMap::new(),
            next_proposal_id: 0,
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
        self.total_supply.saturating_sub(self.total_burned)
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
        let amount = (acc.staked as u128 * fraction_bps as u128 / 10_000) as u64;
        acc.staked -= amount;
        self.total_burned += amount;
        amount
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

    pub fn proposal(&self, id: u64) -> Option<&GovernanceProposal> {
        self.proposals.get(&id)
    }

    pub fn set_proposal(&mut self, proposal: GovernanceProposal) {
        self.proposals.insert(proposal.id, proposal);
    }
}
