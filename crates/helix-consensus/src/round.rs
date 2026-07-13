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
    /// Precommits that arrived before this node's own round reached
    /// `RoundPhase::Precommit` — see `add_precommit`'s doc comment.
    pending_precommits: Vec<Vote>,
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
            pending_precommits: Vec::new(),
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
            Err(ConsensusError::DoubleSign(evidence)) => {
                self.evidence.push(*evidence);
                return Ok(None);
            }
            Err(e) => return Err(e),
        }

        if self.prevotes.has_quorum() && self.phase == RoundPhase::Prevote {
            self.phase = RoundPhase::Precommit;

            // Replay any precommits that arrived while we were still waiting on
            // our own prevote quorum (see add_precommit's doc comment) — a faster
            // peer's precommit can easily beat our own phase transition across a
            // real network. If replaying them alone reaches precommit quorum, that
            // takes precedence: the round is fully committed, not just at prevote
            // quorum, and callers only ever check `is_committed()` afterward
            // (neither `add_vote` nor `receive_proposal` reads this return value).
            // Best-effort replay: a single malformed/mismatched buffered vote
            // (already impossible in practice, since add_precommit only ever
            // buffers votes matching this exact height+round, but VoteSet::add
            // does its own independent validation too — defense in depth) must
            // not abort a prevote-quorum transition that has legitimately just
            // happened. Skip and keep draining rather than propagating with `?`.
            let buffered = std::mem::take(&mut self.pending_precommits);
            for vote in buffered {
                if let Ok(Some(hash)) = self.apply_precommit(vote) {
                    return Ok(Some(hash));
                }
            }

            return Ok(self.prevotes.quorum_hash());
        }
        Ok(None)
    }

    /// Add a precommit. Returns the committed hash if quorum is reached (block is final).
    ///
    /// A precommit that arrives while this round is still in `Prevote` phase isn't
    /// invalid — it just outran this node's own progress through the round (a
    /// faster validator can reach precommit before a slower one has even tallied
    /// prevote quorum locally). Buffered rather than dropped, and replayed once
    /// `add_prevote` brings this round's own phase to `Precommit`: found by
    /// running a real multi-node testnet, where dropping it meant a slow node
    /// relied entirely on the `NewCommittedBlock` gossip fallback to ever catch up
    /// on quorum reached by faster peers — correct, but wasteful of a vote that
    /// had already arrived and was simply thrown away.
    pub fn add_precommit(&mut self, vote: Vote) -> ConsensusResult<Option<Hash>> {
        if self.phase == RoundPhase::Prevote && vote.height == self.height && vote.round == self.round {
            self.pending_precommits.push(vote);
            return Ok(None);
        }
        if self.phase != RoundPhase::Precommit {
            return Err(ConsensusError::InvalidVote {
                reason: format!("precommit received in phase {:?}", self.phase),
            });
        }
        self.apply_precommit(vote)
    }

    fn apply_precommit(&mut self, vote: Vote) -> ConsensusResult<Option<Hash>> {
        match self.precommits.add(vote) {
            Ok(_) => {}
            Err(ConsensusError::DuplicateVote(_)) => return Ok(None),
            Err(ConsensusError::DoubleSign(evidence)) => {
                self.evidence.push(*evidence);
                return Ok(None);
            }
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
