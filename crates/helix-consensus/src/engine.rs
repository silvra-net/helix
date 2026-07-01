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
    /// Votes cast by this node, awaiting the caller to broadcast them via
    /// `take_outbound_votes()`.
    outbound_votes: Vec<Vote>,
    /// Hash of the most recently finalized block, so `is_finalized()` still
    /// answers correctly after the round that committed it has been cleared.
    last_committed: Option<Hash>,
}

impl BftEngine {
    pub fn new(validator_set: ValidatorSet, address: Address, genesis_height: u64) -> Self {
        BftEngine {
            validator_set,
            address,
            current_height: genesis_height,
            round: None,
            pending_evidence: Vec::new(),
            outbound_votes: Vec::new(),
            last_committed: None,
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
        let prevote = cast_vote(&self.address, keypair, VoteType::Prevote, height, round_num, block_hash.clone())?;
        round.add_prevote(prevote.clone())?;
        self.outbound_votes.push(prevote);

        // Cast own precommit (only valid if we just moved to Precommit phase)
        if round.phase == RoundPhase::Precommit {
            let precommit = cast_vote(&self.address, keypair, VoteType::Precommit, height, round_num, block_hash.clone())?;
            round.add_precommit(precommit.clone())?;
            self.outbound_votes.push(precommit);
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

    /// Add a vote received from a peer, validating it and folding it into the
    /// active round's `VoteSet`. Returns the finalized block once precommit
    /// quorum (2/3+1) is reached — a prevote quorum only advances the round to
    /// the Precommit phase and does not finalize anything.
    ///
    /// If the incoming vote is the one that tips prevotes over quorum, this
    /// node casts (and returns via `take_outbound_votes()`) its own precommit
    /// for the agreed block — otherwise a round could stall forever waiting on
    /// a precommit nobody ever sends when quorum is only reached step-by-step
    /// over the network instead of all at once.
    pub fn add_vote(&mut self, keypair: &KeyPair, vote: Vote) -> ConsensusResult<Option<Block>> {
        let round = self
            .round
            .as_mut()
            .ok_or(ConsensusError::NoActiveRound)?;

        let was_prevote_phase = round.phase == RoundPhase::Prevote;
        match vote.vote_type {
            VoteType::Prevote => round.add_prevote(vote)?,
            VoteType::Precommit => round.add_precommit(vote)?,
        };

        if was_prevote_phase
            && round.phase == RoundPhase::Precommit
            && !round.precommits.has_voted(&self.address)
        {
            let height = round.height;
            let round_num = round.round;
            if let Some(block_hash) = round.proposal.as_ref().map(|b| b.hash()) {
                let precommit =
                    cast_vote(&self.address, keypair, VoteType::Precommit, height, round_num, block_hash)?;
                self.outbound_votes.push(precommit.clone());
                round.add_precommit(precommit)?;
            }
        }

        if !round.is_committed() {
            return Ok(None);
        }

        let height = round.height;
        let hash = round
            .committed_hash()
            .cloned()
            .expect("is_committed() just confirmed a commit hash is present");
        info!(height, hash = %hash, "BFT quorum reached — block finalized");

        let mut round = self.round.take().unwrap();
        let block = round.proposal.take().filter(|b| b.hash() == hash);
        self.finalize(height, round);

        Ok(block)
    }

    /// Receive a block proposed by another validator over P2P, join the round
    /// it starts, and cast this node's own prevote (and, if that single vote
    /// already tips quorum, the follow-up precommit too — mirroring
    /// `produce_block`'s own-vote logic). Returns the finalized block if this
    /// node's vote alone reaches quorum, `None` if the round still awaits
    /// further peer votes via `add_vote()`.
    ///
    /// A proposal for a height we've already finalized (a stale retransmit,
    /// or our own proposal echoed back by gossipsub) is silently ignored
    /// rather than treated as an error.
    pub fn receive_proposal(&mut self, keypair: &KeyPair, block: Block) -> ConsensusResult<Option<Block>> {
        if block.height() <= self.current_height {
            return Ok(None);
        }

        self.assert_is_validator()?;
        self.validate_block(&block)?;

        let height = block.height();
        let round_num = 0u32;

        // Already tracking a round for this height — e.g. duplicate gossip
        // delivery of the same proposal. Don't clobber accumulated votes.
        if self.round.as_ref().is_some_and(|r| r.height == height) {
            return Ok(None);
        }

        let block_hash = block.hash();
        let mut round = RoundState::new(height, round_num, self.validator_set.clone());
        round.set_proposal(block)?;

        let prevote = cast_vote(&self.address, keypair, VoteType::Prevote, height, round_num, block_hash.clone())?;
        round.add_prevote(prevote.clone())?;
        self.outbound_votes.push(prevote);

        if round.phase == RoundPhase::Precommit {
            let precommit = cast_vote(&self.address, keypair, VoteType::Precommit, height, round_num, block_hash)?;
            round.add_precommit(precommit.clone())?;
            self.outbound_votes.push(precommit);
        }

        if !round.is_committed() {
            self.round = Some(round);
            return Ok(None);
        }

        let hash = round
            .committed_hash()
            .cloned()
            .expect("is_committed() just confirmed a commit hash is present");
        let block = round.proposal.take().filter(|b| b.hash() == hash);
        self.finalize(height, round);

        Ok(block)
    }

    /// Drain votes cast by this node since the last call, for the caller to
    /// broadcast to peers via P2P.
    pub fn take_outbound_votes(&mut self) -> Vec<Vote> {
        std::mem::take(&mut self.outbound_votes)
    }

    /// Returns true if the engine has finalized the block with the given hash.
    pub fn is_finalized(&self, block_hash: &Hash) -> bool {
        self.last_committed.as_ref() == Some(block_hash)
    }

    /// The block currently proposed for the active round, if any — e.g. so a
    /// caller can inspect what this node is waiting on votes for.
    pub fn pending_proposal(&self) -> Option<&Block> {
        self.round.as_ref().and_then(|r| r.proposal.as_ref())
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

    fn finalize(&mut self, height: u64, round: RoundState) {
        self.current_height = height;
        self.last_committed = round.committed_hash().cloned();
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

/// Build and sign a vote. Free function (not a method) so it can be called
/// while a `&mut RoundState` borrowed from `BftEngine::round` is still live.
fn cast_vote(
    address: &Address,
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
        validator: address.clone(),
        public_key: keypair.public.clone(),
        signature: Signature::from_bytes(vec![]),
    };
    let signing_bytes = vote.signing_bytes();
    vote.signature = keypair
        .sign(&signing_bytes)
        .map_err(ConsensusError::Crypto)?;
    Ok(vote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::KeyPair;

    /// A 4-validator set with equal stake, all capped identically to the same
    /// 1% ceiling — so reaching 2/3+1 quorum requires exactly 3 of the 4.
    struct FourValidators {
        self_kp: KeyPair,
        self_addr: Address,
        a_kp: KeyPair,
        b_kp: KeyPair,
        validator_set: ValidatorSet,
    }

    fn four_validators() -> FourValidators {
        let self_kp = KeyPair::generate();
        let a_kp = KeyPair::generate();
        let b_kp = KeyPair::generate();
        let c_kp = KeyPair::generate();
        let self_addr = Address::from_public_key(&self_kp.public);
        let a_addr = Address::from_public_key(&a_kp.public);
        let b_addr = Address::from_public_key(&b_kp.public);
        let c_addr = Address::from_public_key(&c_kp.public);

        // self_addr must land at index 1 so it's the proposer for height 1,
        // round 0 (proposer_for_round uses (height + round) % len).
        let validator_set = ValidatorSet::new(
            vec![
                Validator::new(a_addr.clone(), 1_000, true),
                Validator::new(self_addr.clone(), 1_000, true),
                Validator::new(b_addr.clone(), 1_000, true),
                Validator::new(c_addr, 1_000, true),
            ],
            0,
        );

        FourValidators { self_kp, self_addr, a_kp, b_kp, validator_set }
    }

    fn peer_vote(kp: &KeyPair, vote_type: VoteType, height: u64, round: u32, hash: Hash) -> Vote {
        let addr = Address::from_public_key(&kp.public);
        cast_vote(&addr, kp, vote_type, height, round, hash).unwrap()
    }

    /// Reproduces the exact scenario Phase 5c wires up: this node proposes,
    /// its own prevote alone doesn't reach quorum (4 equal validators, 1% cap
    /// each), so it awaits peer votes. A prevote quorum arriving from peers
    /// must NOT finalize the block by itself (that was the pre-fix bug) — it
    /// should only trigger this node's own precommit. Finalization only
    /// happens once precommit quorum is reached too.
    #[test]
    fn finalizes_only_on_precommit_quorum_not_prevote_quorum() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 0);

        let err = engine
            .produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        assert!(matches!(err, ConsensusError::AwaitingVotes { height: 1, round: 0 }));

        let outbound = engine.take_outbound_votes();
        assert_eq!(outbound.len(), 1, "only the proposer's own prevote so far");
        assert_eq!(outbound[0].vote_type, VoteType::Prevote);

        let block_hash = engine.pending_proposal().unwrap().hash();

        // First peer prevote: still short of quorum (2 of 4 validators).
        let prevote_a = peer_vote(&v.a_kp, VoteType::Prevote, 1, 0, block_hash.clone());
        assert_eq!(engine.add_vote(&v.self_kp, prevote_a).unwrap(), None);
        assert!(engine.take_outbound_votes().is_empty());

        // Second peer prevote tips prevotes over quorum (3 of 4) — this must
        // only advance the round and make the engine cast ITS OWN precommit,
        // not finalize the block outright.
        let prevote_b = peer_vote(&v.b_kp, VoteType::Prevote, 1, 0, block_hash.clone());
        assert_eq!(
            engine.add_vote(&v.self_kp, prevote_b).unwrap(),
            None,
            "prevote quorum must not finalize the block"
        );
        let outbound = engine.take_outbound_votes();
        assert_eq!(outbound.len(), 1, "engine should have cast its own precommit");
        assert_eq!(outbound[0].vote_type, VoteType::Precommit);
        assert_eq!(outbound[0].validator, v.self_addr);
        assert!(!engine.is_finalized(&block_hash));

        // One more precommit (2 of 4) still isn't quorum for precommits.
        let precommit_a = peer_vote(&v.a_kp, VoteType::Precommit, 1, 0, block_hash.clone());
        assert_eq!(engine.add_vote(&v.self_kp, precommit_a).unwrap(), None);

        // Third precommit (3 of 4, matching self + a + b) reaches quorum —
        // only now must the block actually finalize.
        let precommit_b = peer_vote(&v.b_kp, VoteType::Precommit, 1, 0, block_hash.clone());
        let finalized = engine.add_vote(&v.self_kp, precommit_b).unwrap();
        let finalized = finalized.expect("precommit quorum must finalize the block");
        assert_eq!(finalized.hash(), block_hash);
        assert!(engine.is_finalized(&block_hash));
        assert_eq!(engine.current_height(), 1);
    }

    #[test]
    fn add_vote_without_active_round_errors() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 0);

        let vote = peer_vote(&v.a_kp, VoteType::Prevote, 1, 0, Hash::digest(b"block"));
        assert!(matches!(
            engine.add_vote(&v.self_kp, vote),
            Err(ConsensusError::NoActiveRound)
        ));
    }

    /// The Phase 5c-follow-up scenario: a non-proposer node receives another
    /// validator's proposal over P2P via `receive_proposal()`, joins that
    /// round, and casts its own prevote — then peer votes trickle in over
    /// `add_vote()` exactly as in the proposer-side test above, until
    /// precommit quorum finalizes the block.
    #[test]
    fn receive_proposal_from_peer_joins_round_and_casts_own_prevote() {
        let v = four_validators();

        // b is the proposer for height 2, round 0 ((2 + 0) % 4 == 2).
        let mut proposer_engine = BftEngine::new(
            v.validator_set.clone(),
            Address::from_public_key(&v.b_kp.public),
            1,
        );
        let err = proposer_engine
            .produce_block(&v.b_kp, Hash::digest(b"block-1"), vec![])
            .unwrap_err();
        assert!(matches!(err, ConsensusError::AwaitingVotes { height: 2, round: 0 }));
        let block = proposer_engine.pending_proposal().unwrap().clone();
        let block_hash = block.hash();
        let b_prevote = proposer_engine.take_outbound_votes().into_iter().next().unwrap();

        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        let result = engine.receive_proposal(&v.self_kp, block).unwrap();
        assert_eq!(result, None, "a single prevote shouldn't reach quorum yet");
        let outbound = engine.take_outbound_votes();
        assert_eq!(outbound.len(), 1, "receiving the proposal casts our own prevote");
        assert_eq!(outbound[0].vote_type, VoteType::Prevote);
        assert_eq!(outbound[0].validator, v.self_addr);

        // b's own prevote (2 of 4) still isn't quorum.
        assert_eq!(engine.add_vote(&v.self_kp, b_prevote).unwrap(), None);

        // a's prevote tips prevotes over quorum (3 of 4) — advances the round
        // and makes this node cast its own precommit, without finalizing yet.
        let a_prevote = peer_vote(&v.a_kp, VoteType::Prevote, 2, 0, block_hash.clone());
        assert_eq!(
            engine.add_vote(&v.self_kp, a_prevote).unwrap(),
            None,
            "prevote quorum must not finalize the block"
        );
        let outbound = engine.take_outbound_votes();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].vote_type, VoteType::Precommit);

        let b_precommit = peer_vote(&v.b_kp, VoteType::Precommit, 2, 0, block_hash.clone());
        assert_eq!(engine.add_vote(&v.self_kp, b_precommit).unwrap(), None);

        let a_precommit = peer_vote(&v.a_kp, VoteType::Precommit, 2, 0, block_hash.clone());
        let finalized = engine
            .add_vote(&v.self_kp, a_precommit)
            .unwrap()
            .expect("precommit quorum must finalize the block");
        assert_eq!(finalized.hash(), block_hash);
        assert!(engine.is_finalized(&block_hash));
        assert_eq!(engine.current_height(), 2);
    }

    /// A proposal for a height we've already finalized — e.g. our own block
    /// echoed back by gossipsub, or a stale retransmit — must be ignored
    /// rather than rejected as an error or allowed to start a phantom round.
    #[test]
    fn receive_proposal_for_already_finalized_height_is_ignored() {
        let v = four_validators();
        let mut producer = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let _ = producer.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        let block = producer.pending_proposal().unwrap().clone();

        // Already past height 1.
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        assert_eq!(engine.receive_proposal(&v.self_kp, block).unwrap(), None);
        assert!(!engine.has_active_round());
    }

    /// A block claiming to be proposed by a validator other than the one
    /// actually assigned to this height/round must be rejected — otherwise
    /// any validator could force through its own proposal out of turn.
    #[test]
    fn receive_proposal_from_wrong_proposer_is_rejected() {
        let v = four_validators();
        let mut proposer_engine = BftEngine::new(
            v.validator_set.clone(),
            Address::from_public_key(&v.b_kp.public),
            1,
        );
        let _ = proposer_engine.produce_block(&v.b_kp, Hash::digest(b"block-1"), vec![]);
        let mut block = proposer_engine.pending_proposal().unwrap().clone();
        block.header.validator = Address::from_public_key(&v.a_kp.public);

        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        let err = engine.receive_proposal(&v.self_kp, block).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidBlock { height: 2, .. }));
    }
}
