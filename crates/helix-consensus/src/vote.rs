use helix_core::block::CryptoVersion;
use helix_crypto::{Address, Hash, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::{ConsensusError, ConsensusResult};

/// BFT vote phase (Tendermint-style two-phase commit)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Phase 1: validator signals it received a valid block proposal
    Prevote,
    /// Phase 2: validator commits — once 2/3+ precommit, block is final
    Precommit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash,
    pub validator: Address,
    /// Public key of the voting validator. `Address` is a one-way BLAKE3 hash of it,
    /// so the key must travel with the vote for `signature` to be verifiable.
    pub public_key: PublicKey,
    /// Which crypto scheme the validator signed with — supports migration, mirrors
    /// `BlockHeader::crypto_version`.
    pub crypto_version: CryptoVersion,
    /// Signature over (vote_type, height, round, block_hash, crypto_version)
    pub signature: Signature,
}

impl Vote {
    /// The bytes that get signed — deterministic canonical encoding. Includes
    /// `crypto_version` so a vote can't be replayed under a different scheme tag
    /// than the one it was actually signed with.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Domain separation: a signature over a vote can never be reinterpreted as a
        // signature over a block header or transaction (which carry their own distinct
        // domain tags), even if the remaining bytes happened to line up.
        bytes.extend_from_slice(b"helix-vote-v1:");
        bytes.extend_from_slice(match self.vote_type {
            VoteType::Prevote => b"prevote:",
            VoteType::Precommit => b"precommit:",
        });
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.round.to_le_bytes());
        bytes.extend_from_slice(self.block_hash.as_bytes());
        bytes.push(self.crypto_version as u8);
        bytes
    }

    /// Verify that `public_key` belongs to `validator` and that `signature` is a
    /// valid signature (under this vote's declared `crypto_version`) over this
    /// vote's contents. A forged vote (right address, no private key) fails here —
    /// this is what makes votes trustworthy once they start arriving over the
    /// network instead of only from `self`.
    pub fn verify_signature(&self) -> ConsensusResult<()> {
        if Address::from_public_key(&self.public_key) != self.validator {
            return Err(ConsensusError::InvalidVote {
                reason: format!(
                    "public key does not derive validator address {}",
                    self.validator
                ),
            });
        }
        helix_crypto::verify_with_scheme(
            self.crypto_version,
            &self.public_key,
            &self.signing_bytes(),
            &self.signature,
        )
        .map_err(ConsensusError::Crypto)
    }
}
