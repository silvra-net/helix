use helix_crypto::Address;
use serde::{Deserialize, Serialize};

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
