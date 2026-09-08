pub mod engine;
pub mod evidence;
pub mod proposal;
pub mod round;
pub mod validator;
pub mod vote;
pub mod vote_set;

pub use engine::{
    proposal_timeout_ticks, round_timeout_ticks, BftEngine, PROPOSAL_PULL_TICKS,
    PROPOSAL_TIMEOUT_TICKS, ROUND_TIMEOUT_TICKS,
};
pub use evidence::DoubleSignEvidence;
pub use proposal::Proposal;
pub use round::{RoundPhase, RoundState};
pub use validator::{Validator, ValidatorSet};
pub use vote::{Vote, VoteType, NIL_BLOCK_HASH};
pub use vote_set::VoteSet;

use helix_core::Block;
use helix_crypto::{Address, Hash, KeyPair};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("Invalid block at height {height}: {reason}")]
    InvalidBlock { height: u64, reason: String },

    #[error("Invalid vote: {reason}")]
    InvalidVote { reason: String },

    #[error("Not enough voting power: got {got}, need {need}")]
    InsufficientVotingPower { got: u64, need: u64 },

    #[error("Validator {0} is not in the active set")]
    UnknownValidator(Address),

    #[error("Duplicate vote from validator {0}")]
    DuplicateVote(Address),

    #[error("Double-sign evidence detected")]
    DoubleSign(Box<DoubleSignEvidence>),

    #[error("Not the proposer for height {height} round {round}")]
    NotProposer { height: u64, round: u32 },

    /// This node's turn came while its own stored chain is not the parent of the block it would
    /// build — its tip is `tip`, but a block for `height` must be built on `height - 1`.
    ///
    /// Producing anyway is what the live chain did until 2026-09-08: a validator one block behind
    /// proposed height 157570 on the hash of block 157568, every peer rejected it with
    /// `prev_hash mismatch`, and the round was lost. With six validators and a quorum of five,
    /// one lost round per proposer rotation is enough to stall the chain — and from outside it
    /// looks like split prevotes (#192), because that is exactly what a rejected proposal
    /// produces: some nodes prevote the block, the rest prevote nil.
    #[error("cannot propose block {height}: this node's chain ends at {tip}, not {}", height - 1)]
    ProposerBehind { height: u64, tip: u64 },

    #[error("Awaiting votes from peers for height {height} round {round}")]
    AwaitingVotes { height: u64, round: u32 },

    #[error("No active consensus round")]
    NoActiveRound,

    #[error("Crypto error: {0}")]
    Crypto(#[from] helix_crypto::CryptoError),
}

pub type ConsensusResult<T> = Result<T, ConsensusError>;

/// Number of blocks per validator epoch. At each multiple of this height the
/// active `ValidatorSet` is rebuilt from current stake (see `BftEngine::rotate_validator_set`).
pub const EPOCH_LENGTH: u64 = 100;

/// Fraction of a double-signing validator's stake burned per confirmed
/// `DoubleSignEvidence` (basis points, 1/10000). 500 = 5%.
pub const SLASH_FRACTION_BPS: u64 = 500;

/// Core consensus engine interface.
/// Helix uses BFT finality (Tendermint-style) over a PoS + Personhood validator set.
pub trait ConsensusEngine: Send + Sync {
    fn validate_block(&self, block: &Block) -> ConsensusResult<()>;
    fn add_vote(&mut self, keypair: &KeyPair, vote: Vote) -> ConsensusResult<Option<Block>>;
    fn is_finalized(&self, block_hash: &Hash) -> bool;
    fn validator_set(&self) -> &ValidatorSet;
}
