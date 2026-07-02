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
    #[error("this guardian has already approved this recovery request")]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub new_public_key: PublicKey,
    pub approvals: Vec<Address>,
}

impl RecoveryRequest {
    pub fn new(new_public_key: PublicKey) -> Self {
        RecoveryRequest {
            new_public_key,
            approvals: vec![],
        }
    }

    /// Record `guardian`'s approval, returning `true` once `threshold` approvals are reached.
    pub fn approve(&mut self, guardian: Address, threshold: usize) -> Result<bool, RecoveryError> {
        if self.approvals.contains(&guardian) {
            return Err(RecoveryError::DuplicateApproval);
        }
        self.approvals.push(guardian);
        Ok(self.approvals.len() >= threshold)
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
        let mut request = RecoveryRequest::new(new_key);

        assert_eq!(request.approve(set.guardians[0].clone(), threshold), Ok(false));
        assert_eq!(request.approve(set.guardians[1].clone(), threshold), Ok(false));
        assert_eq!(request.approve(set.guardians[2].clone(), threshold), Ok(true));

        let err = request.approve(set.guardians[0].clone(), threshold).unwrap_err();
        assert_eq!(err, RecoveryError::DuplicateApproval);
    }
}
