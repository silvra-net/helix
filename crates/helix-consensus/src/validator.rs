use std::collections::HashSet;

use helix_crypto::{Address, Hash};
use serde::{Deserialize, Serialize};

use crate::{Vote, VoteType};

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
        Validator {
            address,
            stake,
            has_personhood,
            // Placeholder until this validator is placed in a `ValidatorSet` (audit B3). Effective
            // power depends on the *set's* total stake (the 1% cap), which a lone `Validator` cannot
            // know — `ValidatorSet::new` is the single place that computes it, and it overwrites this
            // for every member. Left at 0, never the raw stake, so an accidental read of an
            // un-setted validator's power is an obvious zero rather than a plausible-looking
            // uncapped number that silently overstates its weight.
            voting_power: 0,
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

    /// Total voting power of the **distinct, in-set** validators that cast a valid precommit for
    /// exactly `(height, block_hash)` among `votes`. This is the tally `verify_last_commit` and
    /// `verified_commit_certificate` deliberately omit: those prove each signature genuine, this
    /// answers how much of the set's power stands behind the block.
    ///
    /// A vote counts only if it is a precommit for this exact `(height, block_hash)`, its signature
    /// verifies, its validator is in this set, and that validator has not already been counted
    /// (equivocation or a duplicate contributes its power once, never twice). A signer outside this
    /// set contributes nothing — its power here is zero by definition, which is what makes this a
    /// tally *this* set can trust.
    pub fn precommit_power(&self, votes: &[Vote], height: u64, block_hash: &Hash) -> u64 {
        let mut seen: HashSet<Address> = HashSet::new();
        votes
            .iter()
            .filter(|v| {
                v.vote_type == VoteType::Precommit
                    && v.height == height
                    && &v.block_hash == block_hash
                    && v.verify_signature().is_ok()
                    && seen.insert(v.validator.clone())
            })
            .filter_map(|v| self.get(&v.validator))
            .map(|val| val.voting_power)
            .sum()
    }

    /// True if `votes` proves BFT finality for `(height, block_hash)`: the in-set precommit signers
    /// among them sum to at least [`quorum_threshold`](Self::quorum_threshold). This is the gate a
    /// node must apply before adopting an *externally* finalized block (the committed-block gossip
    /// fast path, and any RPC catch-up that adopts a tip on a peer's word) — a proposer's own
    /// self-consistent signature proves authorship, never that 2/3 of the set finalized the block.
    /// Without it a single Byzantine validator can gossip a block it alone signed and fork every
    /// receiver off the real chain.
    pub fn precommits_reach_quorum(&self, votes: &[Vote], height: u64, block_hash: &Hash) -> bool {
        // An empty set has a quorum threshold of 1 and no members to meet it, so nothing can ever
        // reach quorum against it — reject rather than divide the network on a vacuous certificate.
        if self.total_voting_power() == 0 {
            return false;
        }
        self.precommit_power(votes, height, block_hash) >= self.quorum_threshold()
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
    use helix_core::block::CryptoVersion;
    use helix_crypto::{KeyPair, Signature};

    /// A precommit vote for `(height, block_hash)` genuinely signed by `kp`, the shape a real
    /// commit certificate carries. `round` is fixed at 0 — irrelevant to the power tally.
    fn precommit(kp: &KeyPair, height: u64, block_hash: Hash) -> Vote {
        let mut v = Vote {
            vote_type: VoteType::Precommit,
            height,
            round: 0,
            block_hash,
            validator: Address::from_public_key(&kp.public),
            public_key: kp.public.clone(),
            crypto_version: CryptoVersion::MlDsa,
            signature: Signature::from_bytes(vec![]),
        };
        v.signature = kp.sign(&v.signing_bytes()).unwrap();
        v
    }

    /// Two equal-stake, personhood-verified validators — a 2-of-2 set, matching the live chain.
    fn two_validator_set(a: &KeyPair, b: &KeyPair) -> ValidatorSet {
        ValidatorSet::new(
            vec![
                Validator::new(Address::from_public_key(&a.public), 100_000, true),
                Validator::new(Address::from_public_key(&b.public), 100_000, true),
            ],
            0,
        )
    }

    /// A1: a certificate with precommits from the whole set proves finality — this is the honest
    /// path (a finalizer broadcasting the block it just committed) and must be adopted.
    #[test]
    fn a_full_certificate_reaches_quorum() {
        let (a, b) = (KeyPair::generate(), KeyPair::generate());
        let set = two_validator_set(&a, &b);
        let hash = Hash::digest(b"block-5");
        let cert = vec![precommit(&a, 5, hash), precommit(&b, 5, hash)];
        assert!(set.precommits_reach_quorum(&cert, 5, &hash));
    }

    /// A1, the attack: a single Byzantine validator gossips a block it alone signed. Its lone
    /// precommit is genuine, but one of two is below the 2/3 threshold — the certificate must NOT
    /// reach quorum, so a receiver drops the block instead of forking onto it.
    #[test]
    fn a_single_signature_does_not_reach_quorum() {
        let (a, b) = (KeyPair::generate(), KeyPair::generate());
        let set = two_validator_set(&a, &b);
        let hash = Hash::digest(b"evil-block");
        let cert = vec![precommit(&a, 5, hash)];
        assert!(!set.precommits_reach_quorum(&cert, 5, &hash));
    }

    /// A signer outside the set (a freshly generated throwaway key) contributes zero power, so
    /// padding a certificate with out-of-set signatures can never manufacture a quorum.
    #[test]
    fn an_out_of_set_signer_contributes_no_power() {
        let (a, b, outsider) = (KeyPair::generate(), KeyPair::generate(), KeyPair::generate());
        let set = two_validator_set(&a, &b);
        let hash = Hash::digest(b"block-5");
        // One real signer plus a genuine signature from a non-member: still one-of-two.
        let cert = vec![precommit(&a, 5, hash), precommit(&outsider, 5, hash)];
        assert_eq!(set.precommit_power(&cert, 5, &hash), set.get(&Address::from_public_key(&a.public)).unwrap().voting_power);
        assert!(!set.precommits_reach_quorum(&cert, 5, &hash));
    }

    /// Precommits for a different block, height, or of the wrong vote type never count toward this
    /// block's quorum — the exact-match filter is what stops a certificate from one block being
    /// replayed to finalize another.
    #[test]
    fn mismatched_votes_are_excluded_from_the_tally() {
        let (a, b) = (KeyPair::generate(), KeyPair::generate());
        let set = two_validator_set(&a, &b);
        let hash = Hash::digest(b"block-5");
        let other = Hash::digest(b"other-block");

        let wrong_hash = vec![precommit(&a, 5, other), precommit(&b, 5, other)];
        assert!(!set.precommits_reach_quorum(&wrong_hash, 5, &hash), "certificate for another block");

        let wrong_height = vec![precommit(&a, 6, hash), precommit(&b, 6, hash)];
        assert!(!set.precommits_reach_quorum(&wrong_height, 5, &hash), "certificate for another height");

        let mut prevotes = vec![precommit(&a, 5, hash), precommit(&b, 5, hash)];
        for v in &mut prevotes {
            v.vote_type = VoteType::Prevote;
            v.signature = match v.validator == Address::from_public_key(&a.public) {
                true => a.sign(&v.signing_bytes()).unwrap(),
                false => b.sign(&v.signing_bytes()).unwrap(),
            };
        }
        assert!(!set.precommits_reach_quorum(&prevotes, 5, &hash), "prevotes are not precommits");
    }

    /// A forged signature (right validator address, wrong key) is filtered out before its power is
    /// counted, so it cannot help reach quorum.
    #[test]
    fn a_forged_signature_contributes_no_power() {
        let (a, b, attacker) = (KeyPair::generate(), KeyPair::generate(), KeyPair::generate());
        let set = two_validator_set(&a, &b);
        let hash = Hash::digest(b"block-5");
        // A precommit claiming to be from `b` but signed by the attacker's key.
        let mut forged = precommit(&attacker, 5, hash);
        forged.validator = Address::from_public_key(&b.public);
        let cert = vec![precommit(&a, 5, hash), forged];
        assert!(!set.precommits_reach_quorum(&cert, 5, &hash), "a forged second signature is not real quorum");
    }

    /// One validator signing twice contributes its power once, never twice — equivocation cannot
    /// inflate a lone validator into a quorum.
    #[test]
    fn a_duplicated_signer_is_counted_once() {
        let (a, b) = (KeyPair::generate(), KeyPair::generate());
        let set = two_validator_set(&a, &b);
        let hash = Hash::digest(b"block-5");
        let cert = vec![precommit(&a, 5, hash), precommit(&a, 5, hash)];
        assert_eq!(
            set.precommit_power(&cert, 5, &hash),
            set.get(&Address::from_public_key(&a.public)).unwrap().voting_power,
            "the same signer counts once"
        );
        assert!(!set.precommits_reach_quorum(&cert, 5, &hash));
    }

    /// B3: a bare `Validator::new` carries zero power (it cannot know the set's total stake); only
    /// `ValidatorSet::new` computes the real, capped value. Guards against a future reader trusting
    /// an un-setted validator's `voting_power`.
    #[test]
    fn a_bare_validator_has_zero_power_until_placed_in_a_set() {
        let v = Validator::new(rand_address(), 100_000, true);
        assert_eq!(v.voting_power, 0, "power is unknown until the set applies its cap");

        let set = ValidatorSet::new(vec![v.clone()], 0);
        assert!(set.get(&v.address).unwrap().voting_power > 0, "the set computes real power");
    }

    /// An empty set (no members) can never certify anything — guards the divide-by-nothing edge so
    /// a vacuous certificate is rejected rather than trivially accepted.
    #[test]
    fn an_empty_set_never_reaches_quorum() {
        let set = ValidatorSet::new(vec![], 0);
        let hash = Hash::digest(b"block-5");
        assert!(!set.precommits_reach_quorum(&[], 5, &hash));
    }

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
