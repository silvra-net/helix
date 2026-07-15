use helix_core::Block;
use serde::{Deserialize, Serialize};

use crate::Vote;

/// A block proposal tagged with the BFT round it was proposed in.
///
/// The round number isn't part of the block itself — only the winning proposal's content
/// ends up on-chain, and the header format must stay stable across rounds/restarts — so it
/// travels alongside the block only while the proposal is in flight over P2P.
///
/// `valid_round`/`pol` carry Tendermint's *proof-of-lock* for a re-proposal. When a
/// proposer is locked on a value from an earlier round `vr` (it saw a prevote-quorum for it
/// there, but that round never reached a precommit-quorum so didn't commit), it re-proposes
/// that exact value with `valid_round = Some(vr)` and `pol` = the 2/3+ prevotes that formed
/// the quorum. A receiver locked on a *different* value only unlocks and prevotes this one if
/// the POL verifies against `vr` — that certificate is what makes a re-proposal safe to
/// accept no matter who relays it, since it proves the network genuinely reached a (newer)
/// lock on the value. A fresh proposal (a proposer's own brand-new block) carries
/// `valid_round = None` and an empty `pol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub round: u32,
    #[serde(default)]
    pub valid_round: Option<u32>,
    pub block: Block,
    #[serde(default)]
    pub pol: Vec<Vote>,
}

impl Proposal {
    /// A proposer's own brand-new block for `round` — no proof-of-lock.
    pub fn fresh(round: u32, block: Block) -> Self {
        Proposal { round, valid_round: None, block, pol: Vec::new() }
    }

    /// A re-proposal of a value locked in `valid_round`, carrying the prevote certificate
    /// (`pol`) that justifies it.
    pub fn reproposal(round: u32, valid_round: u32, block: Block, pol: Vec<Vote>) -> Self {
        Proposal { round, valid_round: Some(valid_round), block, pol }
    }

    /// True if this is a re-proposal (carries a proof-of-lock round).
    pub fn is_reproposal(&self) -> bool {
        self.valid_round.is_some()
    }
}
