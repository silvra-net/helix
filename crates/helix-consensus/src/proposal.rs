use helix_core::Block;
use serde::{Deserialize, Serialize};

/// A block proposal tagged with the BFT round it was proposed in.
///
/// The round number isn't part of the block itself — only the winning
/// proposal's content ends up on-chain, and the header format must stay
/// stable across rounds/restarts — so it travels alongside the block only
/// while the proposal is in flight over P2P.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub round: u32,
    pub block: Block,
}
