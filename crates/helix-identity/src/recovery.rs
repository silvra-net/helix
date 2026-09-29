use std::collections::HashSet;

use helix_crypto::{Address, PublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Guardian set bounds: enough for a meaningful M-of-N quorum, capped to bound state size.
pub const MIN_GUARDIANS: usize = 3;
pub const MAX_GUARDIANS: usize = 10;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecoveryError {
    #[error("at least {MIN_GUARDIANS} guardians are required")]
    TooFewGuardians,
    #[error("at most {MAX_GUARDIANS} guardians are allowed")]
    TooManyGuardians,
    #[error("duplicate guardian address")]
    DuplicateGuardian,
    #[error("an address cannot be its own guardian")]
    SelfGuardian,
    #[error("sender is not a registered guardian for this address")]
    NotAGuardian,
    #[error("this guardian already votes for this key")]
    DuplicateApproval,
}

/// An address's social-recovery guardians. `threshold()` of `guardians` (3-of-5 for the
/// canonical 5-guardian set) must approve a new public key before control of the address
/// can be recovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianSet {
    pub guardians: Vec<Address>,
}

impl GuardianSet {
    pub fn new(owner: &Address, guardians: Vec<Address>) -> Result<Self, RecoveryError> {
        if guardians.len() < MIN_GUARDIANS {
            return Err(RecoveryError::TooFewGuardians);
        }
        if guardians.len() > MAX_GUARDIANS {
            return Err(RecoveryError::TooManyGuardians);
        }
        if guardians.iter().any(|g| g == owner) {
            return Err(RecoveryError::SelfGuardian);
        }
        let mut seen = HashSet::with_capacity(guardians.len());
        for g in &guardians {
            if !seen.insert(g.clone()) {
                return Err(RecoveryError::DuplicateGuardian);
            }
        }
        Ok(GuardianSet { guardians })
    }

    /// ceil(guardians.len() * 3 / 5) — 3-of-5 for the canonical 5-guardian set.
    pub fn threshold(&self) -> usize {
        (self.guardians.len() * 3 + 4) / 5
    }

    pub fn contains(&self, addr: &Address) -> bool {
        self.guardians.iter().any(|g| g == addr)
    }
}

/// An in-progress guardian vote to rotate an address's controlling public key.
///
/// Every guardian holds **one** vote, for one key, and may move it; a key wins when `threshold`
/// guardians name it (#251). The request used to hold a single key and a list of approvals, and a
/// vote for any other key replaced the whole request — so while the owner's key was lost, one
/// guardian could erase the others' progress with a single transaction, as often as it liked.
/// Votes are kept in the order they were cast, which every node executes identically, so the
/// request serialises the same everywhere.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub votes: Vec<RecoveryVote>,
}

/// One guardian's current choice of replacement key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryVote {
    pub guardian: Address,
    pub new_public_key: PublicKey,
}

impl RecoveryRequest {
    pub fn new() -> Self {
        RecoveryRequest::default()
    }

    /// Records `guardian`'s vote for `key`, replacing any earlier vote of theirs, and returns
    /// `true` once `threshold` guardians name `key`. Naming the key it already names is refused.
    pub fn approve(
        &mut self,
        guardian: Address,
        key: PublicKey,
        threshold: usize,
    ) -> Result<bool, RecoveryError> {
        if self
            .votes
            .iter()
            .any(|v| v.guardian == guardian && v.new_public_key == key)
        {
            return Err(RecoveryError::DuplicateApproval);
        }
        self.votes.retain(|v| v.guardian != guardian);
        self.votes.push(RecoveryVote {
            guardian,
            new_public_key: key.clone(),
        });
        Ok(self.approvals_for(&key) >= threshold)
    }

    /// How many guardians currently name `key`.
    pub fn approvals_for(&self, key: &PublicKey) -> usize {
        self.votes.iter().filter(|v| &v.new_public_key == key).count()
    }

    /// Each key some guardian names, with its number of votes, in the order each key was first
    /// named among the current votes.
    pub fn tally(&self) -> Vec<(&PublicKey, usize)> {
        let mut tally: Vec<(&PublicKey, usize)> = Vec::new();
        for vote in &self.votes {
            match tally.iter_mut().find(|(k, _)| *k == &vote.new_public_key) {
                Some((_, n)) => *n += 1,
                None => tally.push((&vote.new_public_key, 1)),
            }
        }
        tally
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::KeyPair;

    fn rand_address() -> Address {
        Address::from_public_key(&KeyPair::generate().public)
    }

    fn guardians(n: usize) -> Vec<Address> {
        (0..n).map(|_| rand_address()).collect()
    }

    #[test]
    fn new_rejects_too_few_guardians() {
        let owner = rand_address();
        let err = GuardianSet::new(&owner, guardians(2)).unwrap_err();
        assert_eq!(err, RecoveryError::TooFewGuardians);
    }

    #[test]
    fn new_rejects_too_many_guardians() {
        let owner = rand_address();
        let err = GuardianSet::new(&owner, guardians(MAX_GUARDIANS + 1)).unwrap_err();
        assert_eq!(err, RecoveryError::TooManyGuardians);
    }

    #[test]
    fn new_rejects_self_guardian() {
        let owner = rand_address();
        let mut g = guardians(4);
        g.push(owner.clone());
        let err = GuardianSet::new(&owner, g).unwrap_err();
        assert_eq!(err, RecoveryError::SelfGuardian);
    }

    #[test]
    fn new_rejects_duplicate_guardian() {
        let owner = rand_address();
        let dup = rand_address();
        let g = vec![dup.clone(), dup, rand_address(), rand_address()];
        let err = GuardianSet::new(&owner, g).unwrap_err();
        assert_eq!(err, RecoveryError::DuplicateGuardian);
    }

    #[test]
    fn threshold_is_3_of_5() {
        let owner = rand_address();
        let set = GuardianSet::new(&owner, guardians(5)).unwrap();
        assert_eq!(set.threshold(), 3);
    }

    #[test]
    fn approve_reaches_threshold_and_rejects_duplicates() {
        let owner = rand_address();
        let set = GuardianSet::new(&owner, guardians(5)).unwrap();
        let threshold = set.threshold();

        let new_key = KeyPair::generate().public;
        let mut request = RecoveryRequest::new();

        let vote = request.approve(set.guardians[0].clone(), new_key.clone(), threshold);
        assert_eq!(vote, Ok(false));
        let vote = request.approve(set.guardians[1].clone(), new_key.clone(), threshold);
        assert_eq!(vote, Ok(false));
        assert_eq!(request.approve(set.guardians[2].clone(), new_key.clone(), threshold), Ok(true));

        let err = request.approve(set.guardians[0].clone(), new_key, threshold).unwrap_err();
        assert_eq!(err, RecoveryError::DuplicateApproval);
    }

    #[test]
    fn a_vote_for_another_key_moves_one_vote_and_leaves_the_rest() {
        let owner = rand_address();
        let set = GuardianSet::new(&owner, guardians(5)).unwrap();
        let (chosen, other) = (KeyPair::generate().public, KeyPair::generate().public);
        let mut request = RecoveryRequest::new();

        request.approve(set.guardians[0].clone(), chosen.clone(), 3).unwrap();
        request.approve(set.guardians[1].clone(), chosen.clone(), 3).unwrap();
        request.approve(set.guardians[4].clone(), other.clone(), 3).unwrap();
        assert_eq!(request.tally(), vec![(&chosen, 2), (&other, 1)]);

        // Guardian 1 moves to `other`: its vote for `chosen` goes, nobody else's does.
        request.approve(set.guardians[1].clone(), other.clone(), 3).unwrap();
        assert_eq!(request.approvals_for(&chosen), 1);
        assert_eq!(request.approvals_for(&other), 2);
        assert_eq!(request.votes.len(), 3, "one vote per guardian, never two");
    }
}
