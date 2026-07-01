use helix_core::Block;
use helix_crypto::Hash;

use crate::{
    evidence::DoubleSignEvidence, vote_set::VoteSet, ConsensusError, ConsensusResult, ValidatorSet,
    Vote, VoteType,
};

/// The phase a BFT round is currently in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundPhase {
    /// Waiting for the proposer to broadcast a block
    Propose,
    /// Block received; validators are casting prevotes
    Prevote,
    /// 2/3+ prevotes seen; validators are casting precommits
    Precommit,
    /// 2/3+ precommits seen — block is final
    Commit(Hash),
}

/// State for one consensus round at a given height.
///
/// A round proceeds: Propose → Prevote → Precommit → Commit.
/// If no quorum is reached within a timeout the round increments and restarts.
pub struct RoundState {
    pub height: u64,
    pub round: u32,
    pub phase: RoundPhase,
    /// The proposed block for this round (set when proposer broadcasts)
    pub proposal: Option<Block>,
    pub prevotes: VoteSet,
    pub precommits: VoteSet,
    /// Double-sign evidence detected during this round
    pub evidence: Vec<DoubleSignEvidence>,
}

impl RoundState {
    pub fn new(height: u64, round: u32, validator_set: ValidatorSet) -> Self {
        RoundState {
            height,
            round,
            phase: RoundPhase::Propose,
            proposal: None,
            prevotes: VoteSet::new(height, round, VoteType::Prevote, validator_set.clone()),
            precommits: VoteSet::new(height, round, VoteType::Precommit, validator_set),
            evidence: Vec::new(),
        }
    }

    /// Set the proposed block. Advances phase from Propose → Prevote.
    pub fn set_proposal(&mut self, block: Block) -> ConsensusResult<()> {
        if self.phase != RoundPhase::Propose {
            return Err(ConsensusError::InvalidVote {
                reason: format!("proposal received in phase {:?}", self.phase),
            });
        }
        if block.height() != self.height {
            return Err(ConsensusError::InvalidBlock {
                height: block.height(),
                reason: format!("expected height {}", self.height),
            });
        }
        self.proposal = Some(block);
        self.phase = RoundPhase::Prevote;
        Ok(())
    }

    /// Add a prevote. Returns the committed hash if quorum is immediately reached.
    /// Detects double-signing and records evidence.
    pub fn add_prevote(&mut self, vote: Vote) -> ConsensusResult<Option<Hash>> {
        match self.prevotes.add(vote) {
            Ok(_) => {}
            Err(ConsensusError::DuplicateVote(_)) => {
                // Duplicate — already voted, ignore silently (evidence requires two *different* hashes)
                return Ok(None);
            }
            Err(e) => return Err(e),
        }

        if self.prevotes.has_quorum() && self.phase == RoundPhase::Prevote {
            self.phase = RoundPhase::Precommit;
            return Ok(self.prevotes.quorum_hash());
        }
        Ok(None)
    }

    /// Add a precommit. Returns the committed hash if quorum is reached (block is final).
    pub fn add_precommit(&mut self, vote: Vote) -> ConsensusResult<Option<Hash>> {
        if self.phase != RoundPhase::Precommit {
            return Err(ConsensusError::InvalidVote {
                reason: format!("precommit received in phase {:?}", self.phase),
            });
        }

        match self.precommits.add(vote) {
            Ok(_) => {}
            Err(ConsensusError::DuplicateVote(_)) => return Ok(None),
            Err(e) => return Err(e),
        }

        if self.precommits.has_quorum() {
            let hash = self.precommits.quorum_hash().unwrap();
            self.phase = RoundPhase::Commit(hash.clone());
            return Ok(Some(hash));
        }
        Ok(None)
    }

    pub fn is_committed(&self) -> bool {
        matches!(self.phase, RoundPhase::Commit(_))
    }

    pub fn committed_hash(&self) -> Option<&Hash> {
        match &self.phase {
            RoundPhase::Commit(h) => Some(h),
            _ => None,
        }
    }

    /// Advance to the next round (timeout or no-quorum). Resets phase, keeps height.
    pub fn next_round(&self, validator_set: ValidatorSet) -> RoundState {
        RoundState::new(self.height, self.round + 1, validator_set)
    }
}
