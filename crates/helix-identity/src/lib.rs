pub mod name;
pub mod personhood;
pub mod recovery;

pub use name::{HelixName, NameError};
pub use personhood::{PersonhoodError, PersonhoodProof, PersonhoodStatus, ATTESTATION_THRESHOLD};
pub use recovery::{GuardianSet, RecoveryError, RecoveryRequest, MAX_GUARDIANS, MIN_GUARDIANS};

use helix_crypto::Address;

/// A complete identity on the Helix network
#[derive(Debug, Clone)]
pub struct Identity {
    pub address: Address,
    pub name: Option<HelixName>,
    pub personhood: PersonhoodStatus,
    /// Social recovery guardians (3-of-5 threshold)
    pub guardians: Vec<Address>,
}

impl Identity {
    pub fn new(address: Address) -> Self {
        Identity {
            address,
            name: None,
            personhood: PersonhoodStatus::Unverified,
            guardians: vec![],
        }
    }

    pub fn has_personhood(&self) -> bool {
        matches!(self.personhood, PersonhoodStatus::Verified { .. })
    }

    /// A recovery quorum requires ceil(guardians.len() * 3 / 5) signatures
    pub fn recovery_threshold(&self) -> usize {
        let n = self.guardians.len();
        (n * 3 + 4) / 5
    }
}
