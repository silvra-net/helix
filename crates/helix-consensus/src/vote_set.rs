use std::collections::HashMap;

use helix_crypto::{Address, Hash};

use crate::{ConsensusError, ConsensusResult, ValidatorSet, Vote, VoteType};

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

        if self.votes.contains_key(&addr_str) {
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
