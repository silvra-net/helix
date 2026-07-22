use std::collections::HashMap;

use helix_crypto::{Address, Hash};

use crate::{ConsensusError, ConsensusResult, DoubleSignEvidence, ValidatorSet, Vote, VoteType};

/// Collects votes for a single (height, round, vote_type) tuple.
/// Enforces one vote per validator and tracks accumulated voting power per block hash.
pub struct VoteSet {
    pub height: u64,
    pub round: u32,
    pub vote_type: VoteType,
    /// One vote per validator address
    votes: HashMap<String, Vote>,
    /// Accumulated voting power per block hash
    power_by_hash: HashMap<[u8; 32], u64>,
    validator_set: ValidatorSet,
}

impl VoteSet {
    pub fn new(height: u64, round: u32, vote_type: VoteType, validator_set: ValidatorSet) -> Self {
        VoteSet {
            height,
            round,
            vote_type,
            votes: HashMap::new(),
            power_by_hash: HashMap::new(),
            validator_set,
        }
    }

    /// Add a vote. Returns the voting power now behind the vote's block hash.
    /// Errors on: unknown validator, duplicate vote, wrong height/round/type.
    pub fn add(&mut self, vote: Vote) -> ConsensusResult<u64> {
        if vote.height != self.height || vote.round != self.round {
            return Err(ConsensusError::InvalidVote {
                reason: format!(
                    "vote is for height={}/round={}, expected {}/{}",
                    vote.height, vote.round, self.height, self.round
                ),
            });
        }
        if vote.vote_type != self.vote_type {
            return Err(ConsensusError::InvalidVote {
                reason: "vote type mismatch".into(),
            });
        }

        let addr_str = vote.validator.to_string();

        let validator = self
            .validator_set
            .get(&vote.validator)
            .ok_or_else(|| ConsensusError::UnknownValidator(vote.validator.clone()))?;

        vote.verify_signature()?;

        if let Some(existing) = self.votes.get(&addr_str) {
            if existing.block_hash != vote.block_hash {
                // Same validator, same height/round/type, different block hash — this
                // validator signed two conflicting votes. The signature check above
                // already proved both votes came from the claimed validator's key, so
                // this is real equivocation, not a forgery attempt.
                return Err(ConsensusError::DoubleSign(Box::new(DoubleSignEvidence {
                    validator: vote.validator.clone(),
                    height: vote.height,
                    round: vote.round,
                    vote_a: existing.clone(),
                    vote_b: vote,
                })));
            }
            return Err(ConsensusError::DuplicateVote(vote.validator.clone()));
        }

        let power = validator.voting_power;
        let hash_key = *vote.block_hash.as_bytes();

        self.votes.insert(addr_str, vote);
        let entry = self.power_by_hash.entry(hash_key).or_insert(0);
        *entry += power;

        Ok(*entry)
    }

    /// Returns the block hash that has reached quorum (2/3+1), if any.
    pub fn quorum_hash(&self) -> Option<Hash> {
        let threshold = self.validator_set.quorum_threshold();
        self.power_by_hash
            .iter()
            .find(|(_, &power)| power >= threshold)
            .map(|(hash_bytes, _)| Hash::from_bytes(*hash_bytes))
    }

    pub fn has_quorum(&self) -> bool {
        self.quorum_hash().is_some()
    }

    /// The individual votes backing the block hash that has currently reached quorum — the
    /// raw material for a proof-of-lock certificate (see `Proposal::pol`). Empty if no hash
    /// has reached quorum yet. Each returned vote is one already validated by `add` (correct
    /// height/round/type, in-set validator, verified signature), so the certificate they form
    /// is self-verifying to any receiver.
    pub fn quorum_votes(&self) -> Vec<Vote> {
        let Some(hash) = self.quorum_hash() else {
            return Vec::new();
        };
        self.votes_for(&hash)
    }

    /// The votes backing one specific block hash, whether or not it reached quorum here.
    ///
    /// `quorum_votes` can only answer for the hash *this* vote set saw reach quorum. When a block
    /// is finalized somewhere else and arrives already committed, this node may still hold real
    /// precommits for it — collected in the round it was driving before the finished block
    /// overtook it. Those are worth keeping (see
    /// `BftEngine::sync_to_externally_finalized_block`), and the caller knows the hash even
    /// though this set never tallied quorum for it.
    ///
    /// Same guarantee as `quorum_votes`: every vote returned went through `add`, so it is
    /// signature-verified and from an in-set validator at the right height/round/type.
    pub fn votes_for(&self, hash: &Hash) -> Vec<Vote> {
        let key = *hash.as_bytes();
        self.votes
            .values()
            .filter(|v| *v.block_hash.as_bytes() == key)
            .cloned()
            .collect()
    }

    pub fn total_power_seen(&self) -> u64 {
        self.power_by_hash.values().sum()
    }

    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    pub fn has_voted(&self, address: &Address) -> bool {
        self.votes.contains_key(&address.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::{KeyPair, Signature};

    fn validator_set_of(keypair: &KeyPair) -> ValidatorSet {
        let address = Address::from_public_key(&keypair.public);
        ValidatorSet::new(vec![crate::Validator::new(address, 1_000, true)], 0)
    }

    fn signed_vote(keypair: &KeyPair, height: u64, round: u32, block_hash: Hash) -> Vote {
        let mut vote = Vote {
            vote_type: VoteType::Prevote,
            height,
            round,
            block_hash,
            validator: Address::from_public_key(&keypair.public),
            public_key: keypair.public.clone(),
            crypto_version: keypair.scheme,
            signature: Signature::from_bytes(vec![]),
        };
        vote.signature = keypair.sign(&vote.signing_bytes()).unwrap();
        vote
    }

    #[test]
    fn accepts_correctly_signed_vote() {
        let kp = KeyPair::generate();
        let block_hash = Hash::digest(b"block");
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, validator_set_of(&kp));
        assert!(vote_set.add(signed_vote(&kp, 1, 0, block_hash)).is_ok());
    }

    /// An attacker who doesn't hold the validator's private key cannot forge a
    /// vote just by knowing (or guessing) the validator's address.
    #[test]
    fn rejects_vote_signed_by_a_different_key_than_the_claimed_validator() {
        let kp = KeyPair::generate();
        let attacker = KeyPair::generate();
        let block_hash = Hash::digest(b"block");
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, validator_set_of(&kp));

        let mut forged = signed_vote(&attacker, 1, 0, block_hash);
        forged.validator = Address::from_public_key(&kp.public);

        assert!(vote_set.add(forged).is_err());
    }

    /// A validator signing two votes for the same height/round/type but different
    /// block hashes is equivocation — the second `add()` call must surface it as
    /// `DoubleSign` evidence, not a plain `DuplicateVote`.
    #[test]
    fn detects_double_sign_on_conflicting_votes() {
        let kp = KeyPair::generate();
        let hash_a = Hash::digest(b"block a");
        let hash_b = Hash::digest(b"block b");
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, validator_set_of(&kp));

        vote_set.add(signed_vote(&kp, 1, 0, hash_a)).unwrap();
        let err = vote_set.add(signed_vote(&kp, 1, 0, hash_b)).unwrap_err();

        match err {
            ConsensusError::DoubleSign(evidence) => {
                assert!(evidence.is_valid());
                assert_eq!(evidence.validator, Address::from_public_key(&kp.public));
            }
            other => panic!("expected DoubleSign, got {other:?}"),
        }
    }

    /// Re-sending the exact same vote (e.g. a network retry) is not equivocation —
    /// it must stay a plain `DuplicateVote`, not trigger slashing evidence.
    #[test]
    fn resending_the_same_vote_is_a_plain_duplicate() {
        let kp = KeyPair::generate();
        let hash_a = Hash::digest(b"block a");
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, validator_set_of(&kp));

        vote_set.add(signed_vote(&kp, 1, 0, hash_a)).unwrap();
        let err = vote_set.add(signed_vote(&kp, 1, 0, hash_a)).unwrap_err();

        assert!(matches!(err, ConsensusError::DuplicateVote(_)));
    }

    #[test]
    fn rejects_vote_with_tampered_block_hash() {
        let kp = KeyPair::generate();
        let block_hash = Hash::digest(b"block");
        let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote, validator_set_of(&kp));

        let mut tampered = signed_vote(&kp, 1, 0, block_hash);
        tampered.block_hash = Hash::digest(b"different block");

        assert!(vote_set.add(tampered).is_err());
    }
}
