use helix_crypto::{Address, Hash};
use serde::{Deserialize, Serialize};

use crate::Vote;

/// Evidence of a validator double-signing two conflicting votes at the same height/round.
/// Submitted on-chain to trigger slashing (Phase 5 foundation; slashing execution in Phase 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    pub validator: Address,
    pub height: u64,
    pub round: u32,
    /// The two conflicting votes (same validator, same height/round, different block hashes)
    pub vote_a: Vote,
    pub vote_b: Vote,
}

impl DoubleSignEvidence {
    /// Verify that this evidence is structurally valid (same validator/height/round, different hashes).
    /// Does NOT verify signatures — that happens at the execution layer.
    pub fn is_valid(&self) -> bool {
        self.vote_a.validator == self.vote_b.validator
            && self.vote_a.height == self.vote_b.height
            && self.vote_a.round == self.vote_b.round
            && self.vote_a.vote_type == self.vote_b.vote_type
            && self.vote_a.block_hash != self.vote_b.block_hash
            && self.vote_a.validator == self.validator
    }

    pub fn conflicting_hashes(&self) -> (Hash, Hash) {
        (self.vote_a.block_hash.clone(), self.vote_b.block_hash.clone())
    }
}
