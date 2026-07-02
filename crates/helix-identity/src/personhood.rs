use helix_crypto::Address;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Attestations required (Phase 1 social graph) before an identity is marked `Verified`.
pub const ATTESTATION_THRESHOLD: usize = 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PersonhoodError {
    #[error("identity is already verified")]
    AlreadyVerified,
    #[error("identity was revoked: {0}")]
    Revoked(String),
    #[error("this address has already attested this identity")]
    DuplicateAttestation,
}

/// Proof of Personhood verification status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersonhoodStatus {
    /// Not yet verified
    Unverified,
    /// Verification in progress — awaiting attestations
    Pending {
        /// Addresses that have already attested
        attestations: Vec<Address>,
        /// Attestations needed to reach threshold
        threshold: usize,
    },
    /// Fully verified — one unique human per address
    Verified {
        /// Block height at which verification was finalized
        verified_at_height: u64,
    },
    /// Revoked (e.g. fraud detected via ZK proof)
    Revoked { reason: String },
}

impl PersonhoodStatus {
    pub fn is_verified(&self) -> bool {
        matches!(self, PersonhoodStatus::Verified { .. })
    }

    /// Record a social attestation from `attester`, returning the resulting status.
    /// `Unverified` -> `Pending` -> `Verified` once [`ATTESTATION_THRESHOLD`] unique
    /// attestations have been collected. Phase 1 sybil resistance is social-graph only;
    /// ZK-STARK-based verification replaces this in a later phase.
    pub fn attest(self, attester: Address, height: u64) -> Result<Self, PersonhoodError> {
        match self {
            PersonhoodStatus::Verified { .. } => Err(PersonhoodError::AlreadyVerified),
            PersonhoodStatus::Revoked { reason } => Err(PersonhoodError::Revoked(reason)),
            PersonhoodStatus::Unverified => Ok(PersonhoodStatus::Pending {
                attestations: vec![attester],
                threshold: ATTESTATION_THRESHOLD,
            }),
            PersonhoodStatus::Pending {
                mut attestations,
                threshold,
            } => {
                if attestations.contains(&attester) {
                    return Err(PersonhoodError::DuplicateAttestation);
                }
                attestations.push(attester);
                if attestations.len() >= threshold {
                    Ok(PersonhoodStatus::Verified {
                        verified_at_height: height,
                    })
                } else {
                    Ok(PersonhoodStatus::Pending {
                        attestations,
                        threshold,
                    })
                }
            }
        }
    }
}

/// A ZK-based proof that an address belongs to a unique human.
/// The actual ZK-STARK proof bytes are stored here — verified on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonhoodProof {
    pub address: Address,
    /// Social attestations from existing verified identities
    pub attestations: Vec<Attestation>,
    /// Optional ZK-STARK proof (Phase 2 — replaces social attestations)
    pub zk_proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub attester: Address,
    pub attestee: Address,
    /// Block height when this attestation was submitted
    pub height: u64,
}

impl PersonhoodProof {
    /// Phase 1: social graph attestation (5 guardians, threshold configurable)
    pub fn from_social(address: Address, attestations: Vec<Attestation>) -> Self {
        PersonhoodProof {
            address,
            attestations,
            zk_proof: None,
        }
    }

    pub fn attestation_count(&self) -> usize {
        self.attestations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::{Address, KeyPair};

    fn rand_address() -> Address {
        Address::from_public_key(&KeyPair::generate().public)
    }

    #[test]
    fn attest_transitions_unverified_to_pending_to_verified() {
        let mut status = PersonhoodStatus::Unverified;
        for i in 0..ATTESTATION_THRESHOLD {
            status = status.attest(rand_address(), 100 + i as u64).unwrap();
        }
        assert!(status.is_verified());
        assert_eq!(status, PersonhoodStatus::Verified { verified_at_height: 100 + ATTESTATION_THRESHOLD as u64 - 1 });
    }

    #[test]
    fn attest_rejects_duplicate_attester() {
        let attester = rand_address();
        let status = PersonhoodStatus::Unverified.attest(attester.clone(), 1).unwrap();
        let err = status.attest(attester, 2).unwrap_err();
        assert_eq!(err, PersonhoodError::DuplicateAttestation);
    }

    #[test]
    fn attest_rejects_already_verified() {
        let status = PersonhoodStatus::Verified { verified_at_height: 5 };
        let err = status.attest(rand_address(), 10).unwrap_err();
        assert_eq!(err, PersonhoodError::AlreadyVerified);
    }

    #[test]
    fn attest_rejects_revoked() {
        let status = PersonhoodStatus::Revoked { reason: "fraud".to_string() };
        let err = status.attest(rand_address(), 10).unwrap_err();
        assert_eq!(err, PersonhoodError::Revoked("fraud".to_string()));
    }
}
