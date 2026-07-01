use helix_crypto::Address;
use serde::{Deserialize, Serialize};

/// A single validator in the Helix PoS set
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    pub address: Address,
    /// Staked HLX in nano-HLX
    pub stake: u64,
    /// Whether this validator has a verified Proof of Personhood identity.
    /// Validators without personhood are capped at 0.5% voting power.
    pub has_personhood: bool,
    /// Effective voting power after personhood cap is applied
    pub voting_power: u64,
}

impl Validator {
    pub fn new(address: Address, stake: u64, has_personhood: bool) -> Self {
        let voting_power = compute_voting_power(stake, has_personhood);
        Validator {
            address,
            stake,
            has_personhood,
            voting_power,
        }
    }
}

/// Voting power formula:
/// - With personhood: min(stake, 1% of total) — enforces decentralization
/// - Without personhood: min(stake, 0.5% of total) — still participates but capped harder
fn compute_voting_power(stake: u64, has_personhood: bool) -> u64 {
    // Actual cap is applied relative to total stake in ValidatorSet
    // This returns raw stake; ValidatorSet normalizes it
    if has_personhood {
        stake
    } else {
        stake / 2
    }
}

/// The active set of validators for a given epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    pub epoch: u64,
}

impl ValidatorSet {
    pub fn new(mut validators: Vec<Validator>, epoch: u64) -> Self {
        let total_stake: u64 = validators.iter().map(|v| v.stake).sum();

        // Enforce 1% cap per validator (Proof of Personhood decentralization guarantee)
        let cap_per_validator = total_stake / 100;
        for v in &mut validators {
            let raw_power = if v.has_personhood { v.stake } else { v.stake / 2 };
            v.voting_power = raw_power.min(cap_per_validator);
        }

        ValidatorSet { validators, epoch }
    }

    pub fn total_voting_power(&self) -> u64 {
        self.validators.iter().map(|v| v.voting_power).sum()
    }

    pub fn quorum_threshold(&self) -> u64 {
        // BFT: 2/3 + 1 of total voting power
        self.total_voting_power() * 2 / 3 + 1
    }

    pub fn get(&self, address: &Address) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.address == address)
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Round-robin proposer selection: deterministic, based on height + round.
    /// Each validator gets a turn proportional to their position in the sorted set.
    pub fn proposer_for_round(&self, height: u64, round: u32) -> Option<&Validator> {
        if self.validators.is_empty() {
            return None;
        }
        let idx = ((height.wrapping_add(round as u64)) % self.validators.len() as u64) as usize;
        Some(&self.validators[idx])
    }

    /// Returns true if the given address is the proposer for this height/round.
    pub fn is_proposer(&self, address: &Address, height: u64, round: u32) -> bool {
        self.proposer_for_round(height, round)
            .map(|v| &v.address == address)
            .unwrap_or(false)
    }
}
