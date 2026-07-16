pub mod engine;
pub mod evidence;
pub mod proposal;
pub mod round;
pub mod validator;
pub mod vote;
pub mod vote_set;

pub use engine::{BftEngine, PROPOSAL_TIMEOUT_TICKS, ROUND_TIMEOUT_TICKS};
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
