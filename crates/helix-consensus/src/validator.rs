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
    /// A newly-activated validator serving its one-epoch **probation** (see backlog #132): it is
    /// in the set so its precommits are gathered and land in `last_commit` — the on-chain proof
    /// that a node is actually running this key — but it carries **zero voting power** and is
    /// excluded from proposer selection. So a validator that staked but has no live node behind
    /// it (a "phantom") cannot become quorum-critical and freeze a small set; it simply never
    /// proves itself live and is dropped at the next rotation instead of activated. A live one's
    /// signature shows up in a committed `last_commit`, and `rotate_active_validators` promotes
    /// it to a full member. Quorum and proposer therefore run over full members only, which is
    /// what keeps this decision deterministic across nodes (it reads committed state, never a
    /// node's local view — the lesson of the #116/#117 fork).
    #[serde(default)]
    pub probationary: bool,
}

impl Validator {
    pub fn new(address: Address, stake: u64, has_personhood: bool) -> Self {
        let voting_power = compute_voting_power(stake, has_personhood);
        Validator {
            address,
            stake,
            has_personhood,
            voting_power,
            probationary: false,
        }
    }

    /// A validator in its probation epoch — in the set to sign (so its liveness is provable via
    /// `last_commit`) but with no voting power and no proposer turn. See `probationary`.
    pub fn new_probationary(address: Address, stake: u64, has_personhood: bool) -> Self {
        Validator {
            probationary: true,
            ..Validator::new(address, stake, has_personhood)
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
        // Probationary validators (backlog #132) carry no voting power and don't count toward the
        // total that sets the 1% cap: they are in the set only so their signatures are gathered
        // into `last_commit`. Basing the cap on their stake too would let a large-stake phantom
        // that never actually votes shrink everyone else's effective power for a whole epoch.
        let total_stake: u64 = validators.iter().filter(|v| !v.probationary).map(|v| v.stake).sum();

        // Enforce 1% cap per validator (Proof of Personhood decentralization guarantee)
        let cap_per_validator = total_stake / 100;
        for v in &mut validators {
            if v.probationary {
                v.voting_power = 0;
                continue;
            }
            let raw_power = if v.has_personhood { v.stake } else { v.stake / 2 };
            v.voting_power = raw_power.min(cap_per_validator);
        }

        ValidatorSet { validators, epoch }
    }

    /// The validators that count toward quorum and take proposer turns — everyone except those
    /// serving their probation epoch (see `Validator::probationary`).
    fn full_members(&self) -> impl Iterator<Item = &Validator> {
        self.validators.iter().filter(|v| !v.probationary)
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

    /// Immediately removes `address` from the set — e.g. right after a proven double-sign
    /// slash, so the validator loses BFT voting power starting from the very next round
    /// instead of continuing at full, stale power until the next epoch's
    /// `ValidatorSet::new()` rebuild (which could be up to `EPOCH_LENGTH` blocks away).
    ///
    /// Deliberately does NOT bump `epoch` or recompute the 1%-cap for the remaining
    /// validators against the new (smaller) total stake — this is a fast jailing
    /// mechanism, not a rotation. The remaining validators' `voting_power` stays as it was
    /// until the next real rotation recomputes it properly; that's an acceptable, temporary
    /// imprecision in exchange for removing the jailed validator's power immediately.
    ///
    /// Returns `true` if `address` was present and removed.
    pub fn remove(&mut self, address: &Address) -> bool {
        let before = self.validators.len();
        self.validators.retain(|v| &v.address != address);
        self.validators.len() != before
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Round-robin proposer selection: deterministic, based on height + round.
    /// Each validator gets a turn proportional to their position in the sorted set.
    ///
    /// Probationary validators are skipped — a phantom that staked the wrong key would otherwise
    /// take proposer turns it can never fulfil, timing out a round every rotation. They rejoin the
    /// schedule only once promoted to a full member (see `Validator::probationary`).
    pub fn proposer_for_round(&self, height: u64, round: u32) -> Option<&Validator> {
        let full: Vec<&Validator> = self.full_members().collect();
        if full.is_empty() {
            return None;
        }
        let idx = ((height.wrapping_add(round as u64)) % full.len() as u64) as usize;
        Some(full[idx])
    }

    /// Returns true if the given address is the proposer for this height/round.
    pub fn is_proposer(&self, address: &Address, height: u64, round: u32) -> bool {
        self.proposer_for_round(height, round)
            .map(|v| &v.address == address)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::KeyPair;

    fn rand_address() -> Address {
        Address::from_public_key(&KeyPair::generate().public)
    }

    #[test]
    fn remove_drops_the_validator_and_reports_it_was_present() {
        let a = rand_address();
        let b = rand_address();
        let mut set = ValidatorSet::new(
            vec![Validator::new(a.clone(), 100, true), Validator::new(b.clone(), 100, true)],
            0,
        );

        assert!(set.remove(&a));
        assert!(set.get(&a).is_none());
        assert!(set.get(&b).is_some(), "unrelated validator must be unaffected");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn remove_reports_false_for_an_address_not_in_the_set() {
        let a = rand_address();
        let stranger = rand_address();
        let mut set = ValidatorSet::new(vec![Validator::new(a, 100, true)], 0);

        assert!(!set.remove(&stranger));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn a_probationary_validator_has_zero_power_and_does_not_move_the_quorum() {
        let a = rand_address();
        let b = rand_address();
        // One full validator plus a probationer with a far larger stake.
        let full_only = ValidatorSet::new(vec![Validator::new(a.clone(), 100_000, true)], 0);
        let with_prob = ValidatorSet::new(
            vec![
                Validator::new(a.clone(), 100_000, true),
                Validator::new_probationary(b.clone(), 900_000, true),
            ],
            0,
        );

        // The probationer carries no power...
        assert_eq!(with_prob.get(&b).unwrap().voting_power, 0);
        // ...so total power and the quorum threshold are exactly what they were without it —
        // its huge stake neither counts nor shifts the 1% cap on the full member.
        assert_eq!(with_prob.total_voting_power(), full_only.total_voting_power());
        assert_eq!(with_prob.quorum_threshold(), full_only.quorum_threshold());
        assert_eq!(
            with_prob.get(&a).unwrap().voting_power,
            full_only.get(&a).unwrap().voting_power,
            "the full member's capped power must not change when a probationer joins the set",
        );
    }

    #[test]
    fn the_proposer_schedule_skips_probationary_validators() {
        let a = rand_address();
        let b = rand_address();
        let set = ValidatorSet::new(
            vec![
                Validator::new(a.clone(), 100_000, true),
                Validator::new_probationary(b.clone(), 100_000, true),
            ],
            0,
        );
        // Every height/round must land on the one full member, never the probationer.
        for h in 0..10u64 {
            for r in 0..4u32 {
                assert_eq!(set.proposer_for_round(h, r).unwrap().address, a);
                assert!(!set.is_proposer(&b, h, r), "a probationer is never the proposer");
            }
        }
    }

    #[test]
    fn a_set_of_only_probationers_has_no_proposer_and_no_quorum_power() {
        // Can't happen in practice (a probationer only ever joins an existing active set), but the
        // math must not divide by zero or hand out a turn nobody can take.
        let set = ValidatorSet::new(vec![Validator::new_probationary(rand_address(), 100_000, true)], 0);
        assert!(set.proposer_for_round(0, 0).is_none());
        assert_eq!(set.total_voting_power(), 0);
    }

    #[test]
    fn remove_does_not_bump_the_epoch() {
        let a = rand_address();
        let b = rand_address();
        let mut set = ValidatorSet::new(
            vec![Validator::new(a.clone(), 100, true), Validator::new(b, 100, true)],
            7,
        );

        set.remove(&a);
        assert_eq!(set.epoch, 7, "jailing is not a rotation — epoch must stay unchanged");
    }
}
