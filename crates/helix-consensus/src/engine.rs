use std::time::{SystemTime, UNIX_EPOCH};

use helix_core::{block::CryptoVersion, Block, BlockHeader, Transaction};
use helix_crypto::{merkle_root, Address, Hash, KeyPair, Signature};
use tracing::info;

use crate::{
    round::{RoundPhase, RoundState},
    ConsensusError, ConsensusResult, DoubleSignEvidence, Validator, ValidatorSet, Vote, VoteType,
};

/// BFT consensus engine — Tendermint-style two-phase commit.
///
/// Supports both single-validator devnet (auto-commits with own votes) and
/// multi-validator mode (waits for votes from peers via P2P).
///
/// Round lifecycle: Propose → Prevote → Precommit → Commit
pub struct BftEngine {
    pub validator_set: ValidatorSet,
    pub address: Address,
    current_height: u64,
    /// Active round state; None between commits
    round: Option<RoundState>,
    /// Double-sign evidence collected from finalized rounds, awaiting the caller
    /// to apply slashing and drain it via `take_evidence()`.
    pending_evidence: Vec<DoubleSignEvidence>,
}

impl BftEngine {
    pub fn new(validator_set: ValidatorSet, address: Address, genesis_height: u64) -> Self {
        BftEngine {
            validator_set,
            address,
            current_height: genesis_height,
            round: None,
            pending_evidence: Vec::new(),
        }
    }

    /// Build and sign a new block, drive it through a full BFT round, and return it.
    ///
    /// In single-validator mode the engine casts its own prevote + precommit immediately,
    /// reaching quorum on its own (100% voting power). In multi-validator mode the caller
    /// must feed external votes via `add_vote()` until `is_finalized()` returns true.
    pub fn produce_block(
        &mut self,
        keypair: &KeyPair,
        prev_hash: Hash,
        transactions: Vec<Transaction>,
    ) -> ConsensusResult<Block> {
        let height = self.current_height + 1;
        let round_num = 0u32;

        self.assert_is_validator()?;

        // Only the designated proposer for this height/round should produce a block.
        // In single-validator devnet we are always the proposer.
        if !self
            .validator_set
            .is_proposer(&self.address, height, round_num)
        {
            return Err(ConsensusError::NotProposer {
                height,
                round: round_num,
            });
        }

        let block = self.build_signed_block(keypair, height, prev_hash, transactions)?;
        let block_hash = block.hash();

        // Start round: Propose → Prevote
        let mut round = RoundState::new(height, round_num, self.validator_set.clone());
        round.set_proposal(block.clone())?;

        // Cast own prevote
        let prevote = self.cast_vote(keypair, VoteType::Prevote, height, round_num, block_hash.clone())?;
        round.add_prevote(prevote)?;

        // Cast own precommit (only valid if we just moved to Precommit phase)
        if round.phase == RoundPhase::Precommit {
            let precommit = self.cast_vote(keypair, VoteType::Precommit, height, round_num, block_hash.clone())?;
            round.add_precommit(precommit)?;
        }

        if !round.is_committed() {
            // Multi-validator: store round and wait for external votes
            self.round = Some(round);
            return Err(ConsensusError::AwaitingVotes { height, round: round_num });
        }

        self.finalize(height, round);

        info!(
            height,
            hash = %block_hash,
            "Block committed"
        );

        Ok(block)
    }

    /// Add a vote received from a peer. Returns the finalized block hash if quorum is reached.
    pub fn add_vote(&mut self, vote: Vote) -> ConsensusResult<Option<Hash>> {
        let round = self
            .round
            .as_mut()
            .ok_or(ConsensusError::NoActiveRound)?;

        let quorum_hash = match vote.vote_type {
            VoteType::Prevote => round.add_prevote(vote)?,
            VoteType::Precommit => round.add_precommit(vote)?,
        };

        if let Some(hash) = &quorum_hash {
            let height = round.height;
            info!(height, hash = %hash, "BFT quorum reached — block finalized");
            let round = self.round.take().unwrap();
            self.finalize(height, round);
        }

        Ok(quorum_hash)
    }

    /// Returns true if the engine has finalized the block with the given hash.
    pub fn is_finalized(&self, block_hash: &Hash) -> bool {
        self.round
            .as_ref()
            .and_then(|r| r.committed_hash())
            .map(|h| h == block_hash)
            .unwrap_or(false)
    }

    /// Validate a block proposed by another validator (used when receiving from peers).
    pub fn validate_block(&self, block: &Block) -> ConsensusResult<()> {
        let h = block.height();

        if h != self.current_height + 1 {
            return Err(ConsensusError::InvalidBlock {
                height: h,
                reason: format!(
                    "expected height {}, got {}",
                    self.current_height + 1,
                    h
                ),
            });
        }

        if !block.verify_merkle_root() {
            return Err(ConsensusError::InvalidBlock {
                height: h,
                reason: "merkle root mismatch".into(),
            });
        }

        self.validator_set
            .get(&block.header.validator)
            .ok_or_else(|| ConsensusError::UnknownValidator(block.header.validator.clone()))?;

        // Verify the proposer is correct for this height/round 0
        if !self
            .validator_set
            .is_proposer(&block.header.validator, h, 0)
        {
            return Err(ConsensusError::InvalidBlock {
                height: h,
                reason: format!("{} is not the proposer for height {}", block.header.validator, h),
            });
        }

        Ok(())
    }

    pub fn current_height(&self) -> u64 {
        self.current_height
    }

    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub fn has_active_round(&self) -> bool {
        self.round.is_some()
    }

    /// Drain double-sign evidence accumulated since the last call. Callers should
    /// apply slashing (stake deduction) for each returned evidence.
    pub fn take_evidence(&mut self) -> Vec<DoubleSignEvidence> {
        std::mem::take(&mut self.pending_evidence)
    }

    /// Rotate to a new validator set for the next epoch (called every `EPOCH_LENGTH`
    /// blocks). A no-op if `validators` is empty — an empty set would halt block
    /// production entirely, so the current epoch is kept alive instead.
    pub fn rotate_validator_set(&mut self, validators: Vec<Validator>) {
        if validators.is_empty() {
            return;
        }
        let next_epoch = self.validator_set.epoch + 1;
        self.validator_set = ValidatorSet::new(validators, next_epoch);
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn build_signed_block(
        &self,
        keypair: &KeyPair,
        height: u64,
        prev_hash: Hash,
        transactions: Vec<Transaction>,
    ) -> ConsensusResult<Block> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before epoch")
            .as_millis() as u64;

        let tx_hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();
        let merkle = merkle_root(&tx_hashes);

        let mut header = BlockHeader {
            version: 1,
            height,
            timestamp,
            prev_hash,
            merkle_root: merkle,
            validator: self.address.clone(),
            crypto_version: CryptoVersion::MlDsa,
            signature: Signature::from_bytes(vec![]),
        };

        let signing_hash = header.signing_hash();
        header.signature = keypair
            .sign(signing_hash.as_bytes())
            .map_err(ConsensusError::Crypto)?;

        Ok(Block { header, transactions })
    }

    fn cast_vote(
        &self,
        keypair: &KeyPair,
        vote_type: VoteType,
        height: u64,
        round: u32,
        block_hash: Hash,
    ) -> ConsensusResult<Vote> {
        let mut vote = Vote {
            vote_type,
            height,
            round,
            block_hash,
            validator: self.address.clone(),
            public_key: keypair.public.clone(),
            signature: Signature::from_bytes(vec![]),
        };
        let signing_bytes = vote.signing_bytes();
        vote.signature = keypair
            .sign(&signing_bytes)
            .map_err(ConsensusError::Crypto)?;
        Ok(vote)
    }

    fn finalize(&mut self, height: u64, round: RoundState) {
        self.current_height = height;
        self.pending_evidence.extend(round.evidence);
        self.round = None;
    }

    fn assert_is_validator(&self) -> ConsensusResult<()> {
        self.validator_set
            .get(&self.address)
            .ok_or_else(|| ConsensusError::UnknownValidator(self.address.clone()))?;
        Ok(())
    }
}
