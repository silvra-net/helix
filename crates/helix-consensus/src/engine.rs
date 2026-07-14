use std::time::{SystemTime, UNIX_EPOCH};

use helix_core::{Block, BlockHeader, Transaction};
use helix_crypto::{merkle_root, Address, Hash, KeyPair, Signature};
use tracing::info;

use crate::{
    round::{RoundPhase, RoundState},
    ConsensusError, ConsensusResult, DoubleSignEvidence, Validator, ValidatorSet, Vote, VoteType,
};

/// Number of block-production ticks a round may sit without reaching
/// precommit quorum before it's considered stalled and advanced to the next
/// round (e.g. the proposer was offline, or its block failed validation for
/// enough peers that quorum can never be reached). See `BftEngine::advance_round`.
///
/// Deliberately generous: a *healthy* round finalizes the instant votes cross
/// quorum (well under one tick once the gossip mesh is up), so this only bounds
/// how long the network waits before giving up on a genuinely stuck round. Set
/// too low, validators whose per-round timers are even slightly skewed (normal
/// at startup) keep advancing past each other — precommits then land on a round
/// the receiver has already left and get dropped, so no round ever completes its
/// two-phase commit. A wide window keeps every validator on the same round long
/// enough for prevotes *and* precommits to both propagate. Only faulty-proposer
/// recovery pays the cost, never the common case.
pub const ROUND_TIMEOUT_TICKS: u32 = 15;

/// Cap on votes buffered ahead of the round they belong to (see
/// `BftEngine::buffered_votes`). Bounds the memory a peer can make us hold by
/// flooding votes for a round we haven't started; comfortably above the handful
/// of real early-arriving votes a normal validator set produces per round.
const MAX_BUFFERED_VOTES: usize = 512;

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
    /// Round the most recently finalized block was actually committed in —
    /// needed to re-validate that block's proposer if it's rebroadcast to a
    /// peer catching up (see `last_committed_round()`).
    last_committed_round: Option<u32>,
    /// Ticks the active round has sat without reaching precommit quorum,
    /// via `note_round_tick()`. Reset whenever a round starts or finalizes.
    round_ticks: u32,
    /// Votes for the next height that arrived before we had a matching round to
    /// fold them into — most often a peer's prevote that beat the proposal it
    /// votes on across the network (gossipsub doesn't order the two). Without
    /// holding these, that early vote is lost, and in a small validator set
    /// losing even one prevote keeps a node one short of quorum forever. Drained
    /// and replayed the moment the matching round is created (see
    /// `apply_buffered_votes`); cleared when the height advances.
    buffered_votes: Vec<Vote>,
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
            last_committed_round: None,
            round_ticks: 0,
            buffered_votes: Vec::new(),
        }
    }

    /// Hold a vote that couldn't be applied to the current round yet (it's for a
    /// round we haven't started — typically a prevote that outran its proposal).
    /// Bounded and deduplicated; stale votes (for a height we've already passed)
    /// are never buffered.
    fn buffer_vote(&mut self, vote: Vote) {
        if vote.height != self.current_height + 1 || self.buffered_votes.len() >= MAX_BUFFERED_VOTES {
            return;
        }
        let dup = self.buffered_votes.iter().any(|v| {
            v.validator == vote.validator && v.round == vote.round && v.vote_type == vote.vote_type
        });
        if !dup {
            self.buffered_votes.push(vote);
        }
    }

    /// Replay any buffered votes that belong to `round`, folding them in exactly
    /// as `add_vote` would (including casting our own follow-up precommit if a
    /// replayed prevote tips prevote quorum). Best-effort: a buffered vote that
    /// no longer applies cleanly is skipped, never fatal. Called right after a
    /// round is created so votes that arrived ahead of the proposal aren't lost.
    fn apply_buffered_votes(&mut self, keypair: &KeyPair, round: &mut RoundState) {
        let height = round.height;
        let round_num = round.round;
        let mut matching = Vec::new();
        let mut keep = Vec::with_capacity(self.buffered_votes.len());
        for v in self.buffered_votes.drain(..) {
            if v.height == height && v.round == round_num {
                matching.push(v);
            } else if v.height == height {
                keep.push(v); // a later round of the same height — may still be used
            }
            // else: stale (past height) — drop
        }
        self.buffered_votes = keep;

        for v in matching {
            let was_prevote = round.phase == RoundPhase::Prevote;
            let _ = match v.vote_type {
                VoteType::Prevote => round.add_prevote(v),
                VoteType::Precommit => round.add_precommit(v),
            };
            // Mirror add_vote: if a replayed prevote just tipped prevote quorum,
            // cast our own precommit so the round can progress to commit.
            if was_prevote
                && round.phase == RoundPhase::Precommit
                && !round.precommits.has_voted(&self.address)
            {
                if let Some(block_hash) = round.proposal.as_ref().map(|b| b.hash()) {
                    if let Ok(precommit) = cast_vote(
                        &self.address,
                        keypair,
                        VoteType::Precommit,
                        height,
                        round_num,
                        block_hash,
                    ) {
                        self.outbound_votes.push(precommit.clone());
                        let _ = round.add_precommit(precommit);
                    }
                }
            }
        }
    }

    /// The round number of the currently active round, if any — so the block
    /// production loop can re-broadcast the pending proposal under the right round.
    pub fn active_round_num(&self) -> Option<u32> {
        self.round.as_ref().map(|r| r.round)
    }

    /// How many *other* validators must be connected and voting for this node to
    /// be able to reach quorum. While fewer than this are reachable, quorum is
    /// impossible no matter how many rounds are burned — so the caller holds the
    /// current round instead of advancing (and running ahead of validators that
    /// will join at round 0). Zero for a single-validator set, where this node's
    /// own power already meets quorum and block production never waits on peers.
    pub fn peers_needed_for_quorum(&self) -> usize {
        let quorum = self.validator_set.quorum_threshold();
        let my_power = self
            .validator_set
            .get(&self.address)
            .map(|v| v.voting_power)
            .unwrap_or(0);
        if my_power >= quorum {
            return 0;
        }
        // Greedily count the fewest strongest other validators whose combined
        // power (with ours) crosses the quorum threshold.
        let mut others: Vec<u64> = self
            .validator_set
            .validators
            .iter()
            .filter(|v| v.address != self.address)
            .map(|v| v.voting_power)
            .collect();
        others.sort_unstable_by(|a, b| b.cmp(a));
        let mut acc = my_power;
        let mut count = 0;
        for p in others {
            if acc >= quorum {
                break;
            }
            acc += p;
            count += 1;
        }
        count
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

        self.propose(keypair, height, round_num, prev_hash, transactions)
    }

    /// Called once per block-production tick while a round is active but not
    /// yet finalized. Increments the stall counter and reports whether the
    /// round has now been active long enough (`ROUND_TIMEOUT_TICKS`) to be
    /// considered stalled and advanced via `advance_round`.
    pub fn note_round_tick(&mut self) -> bool {
        self.round_ticks += 1;
        self.round_ticks >= ROUND_TIMEOUT_TICKS
    }

    /// Force a stalled round to advance to round+1 — e.g. the proposer was
    /// offline, or its block failed validation for enough peers that quorum
    /// could never be reached. Drops the stalled round's accumulated votes
    /// (they're bucketed under the old round number and don't carry over).
    ///
    /// If this node is the proposer for the new round, builds and signs a
    /// fresh proposal (fresh timestamp — the old one is stale) and casts its
    /// own votes exactly as `produce_block` does, returning
    /// `AwaitingVotes`/`Ok` the same way. If some other validator is the new
    /// proposer, returns `NotProposer` — the caller should just wait for that
    /// validator's `Proposal` to arrive over P2P and hit `receive_proposal`.
    pub fn advance_round(
        &mut self,
        keypair: &KeyPair,
        prev_hash: Hash,
        transactions: Vec<Transaction>,
    ) -> ConsensusResult<Block> {
        let stalled = self.round.take().ok_or(ConsensusError::NoActiveRound)?;
        let height = stalled.height;
        let round_num = stalled.round + 1;
        self.pending_evidence.extend(stalled.evidence);

        if !self.validator_set.is_proposer(&self.address, height, round_num) {
            self.round_ticks = 0;
            return Err(ConsensusError::NotProposer { height, round: round_num });
        }

        self.propose(keypair, height, round_num, prev_hash, transactions)
    }

    /// Build a signed block, start a fresh round for it, cast this node's own
    /// prevote (and follow-up precommit, if that single vote already reaches
    /// quorum), and store the round in `self` awaiting further peer votes.
    /// Shared by `produce_block` (round 0 of a new height) and
    /// `advance_round` (round N+1 of a stalled height) — the only difference
    /// between the two call sites is how `height`/`round_num` are computed.
    fn propose(
        &mut self,
        keypair: &KeyPair,
        height: u64,
        round_num: u32,
        prev_hash: Hash,
        transactions: Vec<Transaction>,
    ) -> ConsensusResult<Block> {
        self.round_ticks = 0;

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

        // Fold in any votes that arrived before this round existed.
        self.apply_buffered_votes(keypair, &mut round);

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
        // A vote for the next height but a round we're not currently running
        // (ahead of our active round, or arriving before we have any round for
        // this height) isn't a protocol violation — it's a vote we simply can't
        // fold in yet. Buffer it instead of erroring: it's most often a prevote
        // that beat its own proposal across the network, and dropping it leaves a
        // small validator set one vote short of quorum for good. It's replayed the
        // instant the matching round starts (`apply_buffered_votes`).
        if vote.height == self.current_height + 1 {
            let not_our_round = match self.round.as_ref() {
                Some(r) => vote.round != r.round,
                None => true,
            };
            if not_our_round {
                self.buffer_vote(vote);
                return Ok(None);
            }
        }

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
    /// rather than treated as an error. Likewise, a proposal for a round
    /// older than one we're already tracking (or have already advanced past
    /// via `advance_round`) is stale and ignored rather than clobbering
    /// newer round state.
    pub fn receive_proposal(&mut self, keypair: &KeyPair, round_num: u32, block: Block) -> ConsensusResult<Option<Block>> {
        if block.height() <= self.current_height {
            return Ok(None);
        }

        self.assert_is_validator()?;
        self.validate_block(&block, round_num)?;

        let height = block.height();

        // Already tracking this round (or a later one) for this height —
        // e.g. duplicate gossip delivery, or a stale proposal that arrived
        // after we (or the network) already moved past it.
        if self.round.as_ref().is_some_and(|r| r.height == height && r.round >= round_num) {
            return Ok(None);
        }

        let block_hash = block.hash();
        let mut round = RoundState::new(height, round_num, self.validator_set.clone());
        round.set_proposal(block)?;
        self.round_ticks = 0;

        let prevote = cast_vote(&self.address, keypair, VoteType::Prevote, height, round_num, block_hash.clone())?;
        round.add_prevote(prevote.clone())?;
        self.outbound_votes.push(prevote);

        if round.phase == RoundPhase::Precommit {
            let precommit = cast_vote(&self.address, keypair, VoteType::Precommit, height, round_num, block_hash)?;
            round.add_precommit(precommit.clone())?;
            self.outbound_votes.push(precommit);
        }

        // Fold in any votes for this round that arrived before the proposal did.
        self.apply_buffered_votes(keypair, &mut round);

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

    /// The round the most recently finalized block actually committed in —
    /// needed to correctly re-validate that block's proposer if it's
    /// rebroadcast to a peer that's exactly one block behind.
    pub fn last_committed_round(&self) -> Option<u32> {
        self.last_committed_round
    }

    /// The block currently proposed for the active round, if any — e.g. so a
    /// caller can inspect what this node is waiting on votes for.
    pub fn pending_proposal(&self) -> Option<&Block> {
        self.round.as_ref().and_then(|r| r.proposal.as_ref())
    }

    /// Validate a block proposed by another validator (used when receiving from peers).
    pub fn validate_block(&self, block: &Block, round: u32) -> ConsensusResult<()> {
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

        // Chain continuity: a proposal can have the right height, a valid proposer
        // signature, and still not build on the block we actually finalized last —
        // e.g. a proposer that raced this node's own commit and embedded the prev_hash
        // of a sibling that lost. Without this check, `receive_proposal` would vote
        // for (and this node's own peers help finalize) a block that silently forks
        // the chain: this is the same guard `NewCommittedBlock`'s passive gossip path
        // already applies (see node.rs's "does not chain from our tip" check) — this
        // is the self-produced/BFT-voted path's missing counterpart to it. `None`
        // means this engine was never seeded with a real tip (only exercised by tests
        // that construct blocks with an arbitrary prev_hash) — skip rather than reject.
        if let Some(expected_prev) = &self.last_committed {
            if &block.header.prev_hash != expected_prev {
                return Err(ConsensusError::InvalidBlock {
                    height: h,
                    reason: format!(
                        "prev_hash mismatch: expected {}, got {}",
                        expected_prev, block.header.prev_hash
                    ),
                });
            }
        }

        block
            .header
            .verify_signature()
            .map_err(|e| ConsensusError::InvalidBlock {
                height: h,
                reason: format!("invalid proposer signature: {e}"),
            })?;

        if !block.verify_merkle_root() {
            return Err(ConsensusError::InvalidBlock {
                height: h,
                reason: "merkle root mismatch".into(),
            });
        }

        self.validator_set
            .get(&block.header.validator)
            .ok_or_else(|| ConsensusError::UnknownValidator(block.header.validator.clone()))?;

        // Verify the proposer is correct for this height/round
        if !self
            .validator_set
            .is_proposer(&block.header.validator, h, round)
        {
            return Err(ConsensusError::InvalidBlock {
                height: h,
                reason: format!(
                    "{} is not the proposer for height {} round {}",
                    block.header.validator, h, round
                ),
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
            public_key: keypair.public.clone(),
            crypto_version: keypair.scheme,
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
        self.last_committed_round = Some(round.round);
        self.pending_evidence.extend(round.evidence);
        self.round = None;
        self.round_ticks = 0;
        // Buffered votes were for the height we just finalized — now stale.
        self.buffered_votes.clear();
    }

    /// Sync bookkeeping to a block that was finalized *without* going through this
    /// engine's own `receive_proposal`/`add_vote` — i.e. one that arrived already
    /// fully committed (the `NewCommittedBlock` P2P gossip topic, or catch-up sync),
    /// rather than as a proposal/votes this engine itself processed to quorum.
    ///
    /// Without this, `current_height` only ever advances via `finalize()`, called
    /// from `receive_proposal`/`add_vote` — a node whose next block happens to
    /// arrive via the committed-block fast path instead (a real, common race once
    /// more than one validator is proposing) silently stops advancing its own
    /// height tracking even though `ChainState`/the block store move on correctly.
    /// The next locally-driven proposal or vote is then compared against that
    /// stale height and rejected — found by running a multi-node local testnet:
    /// a node stuck this way rejects every subsequent proposal and vote with
    /// "expected height N, got N+1", and since this can happen to more than one
    /// validator at once, it can silently halt the whole chain.
    ///
    /// The committing round isn't known here (the gossiped block carries no round
    /// number), so `last_committed_round` is cleared to `None` rather than guessed
    /// — callers already treat "unknown" as round 0 (see `last_committed_round()`'s
    /// doc comment).
    pub fn sync_to_externally_finalized_block(&mut self, height: u64, block_hash: Hash) {
        if height <= self.current_height {
            return;
        }
        self.current_height = height;
        self.last_committed = Some(block_hash);
        self.last_committed_round = None;
        self.round = None;
        self.round_ticks = 0;
        self.buffered_votes.clear();
    }

    /// Seed `last_committed` with the real chain tip's hash right after construction,
    /// when resuming an existing chain (as opposed to a fresh test engine that starts
    /// at height 0 with no prior block). Without this, `validate_block`'s prev_hash
    /// check would silently skip validation for every proposal until this engine's
    /// own first `finalize()` — the exact restart window where a stale/diverged
    /// proposal is most likely to slip through unnoticed.
    pub fn seed_last_committed(&mut self, hash: Hash) {
        self.last_committed = Some(hash);
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
        crypto_version: keypair.scheme,
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
        c_kp: KeyPair,
        c_addr: Address,
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
                Validator::new(c_addr.clone(), 1_000, true),
            ],
            0,
        );

        FourValidators { self_kp, self_addr, a_kp, b_kp, c_kp, c_addr, validator_set }
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

    /// Regression test for a real (if self-healing) inefficiency found by running
    /// a multi-node local testnet: a faster peer's precommit routinely arrives
    /// before this node's own round has reached precommit phase, since votes and
    /// phase transitions race independently across a real network. That must not
    /// be rejected — it should count toward quorum once this node catches up to
    /// precommit phase itself, without needing the peer to resend anything.
    #[test]
    fn a_precommit_that_arrives_before_prevote_quorum_is_buffered_and_counted() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 0);

        let err = engine
            .produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        assert!(matches!(err, ConsensusError::AwaitingVotes { height: 1, round: 0 }));
        engine.take_outbound_votes();
        let block_hash = engine.pending_proposal().unwrap().hash();

        // a's precommit arrives while this engine is still in Prevote phase (only
        // self's own prevote has been cast so far). Before this fix, this was
        // ConsensusError::InvalidVote { "precommit received in phase Prevote" }.
        let precommit_a = peer_vote(&v.a_kp, VoteType::Precommit, 1, 0, block_hash.clone());
        assert_eq!(
            engine.add_vote(&v.self_kp, precommit_a).unwrap(),
            None,
            "an early precommit must be buffered, not rejected"
        );

        // Two more prevotes reach prevote quorum (self + a + b = 3 of 4), which
        // must replay the buffered precommit (a) and cast this engine's own —
        // 2 of the 3 precommits needed for quorum, without a or self resending.
        let prevote_a = peer_vote(&v.a_kp, VoteType::Prevote, 1, 0, block_hash.clone());
        assert_eq!(engine.add_vote(&v.self_kp, prevote_a).unwrap(), None);
        let prevote_b = peer_vote(&v.b_kp, VoteType::Prevote, 1, 0, block_hash.clone());
        assert_eq!(engine.add_vote(&v.self_kp, prevote_b).unwrap(), None);
        assert!(!engine.is_finalized(&block_hash), "only 2 of 4 precommits so far");

        // b's precommit is the third (a[buffered] + self + b) — quorum, finalized.
        let precommit_b = peer_vote(&v.b_kp, VoteType::Precommit, 1, 0, block_hash.clone());
        let finalized = engine.add_vote(&v.self_kp, precommit_b).unwrap();
        assert_eq!(
            finalized.expect("a's buffered precommit must count toward quorum").hash(),
            block_hash
        );
        assert!(engine.is_finalized(&block_hash));
    }

    /// A prevote that arrives *before* the proposal it votes on (a normal race —
    /// gossipsub doesn't order the two across the network) must be buffered and
    /// replayed once the round starts, not dropped. In a small validator set,
    /// losing one early prevote leaves a node permanently one short of quorum, so
    /// no round ever finalizes — the real bug that stalled cold-started
    /// multi-validator networks at height 1.
    #[test]
    fn a_vote_arriving_before_its_proposal_is_buffered_and_counted() {
        let v = four_validators();

        // b is the proposer for height 2, round 0 ((2 + 0) % 4 == 2) — build its block.
        let mut proposer_engine =
            BftEngine::new(v.validator_set.clone(), Address::from_public_key(&v.b_kp.public), 1);
        proposer_engine
            .produce_block(&v.b_kp, Hash::digest(b"block-1"), vec![])
            .unwrap_err();
        let block = proposer_engine.pending_proposal().unwrap().clone();
        let block_hash = block.hash();

        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);

        // a's prevote arrives with no active round yet — buffered, not an error.
        let a_prevote = peer_vote(&v.a_kp, VoteType::Prevote, 2, 0, block_hash.clone());
        assert_eq!(
            engine.add_vote(&v.self_kp, a_prevote).unwrap(),
            None,
            "a vote for the next height with no active round must be buffered, not rejected"
        );

        // Now the proposal arrives: the round starts, this node casts its own prevote,
        // and the buffered a-prevote is replayed — giving 2 of 4 (self + a).
        assert_eq!(engine.receive_proposal(&v.self_kp, 0, block).unwrap(), None);

        // b's prevote is the third (self + a[buffered] + b) → prevote quorum, which
        // makes this node cast its own precommit. That precommit only appears if the
        // buffered a-prevote actually counted; with it lost, self + b would be just 2.
        let b_prevote = peer_vote(&v.b_kp, VoteType::Prevote, 2, 0, block_hash.clone());
        assert_eq!(engine.add_vote(&v.self_kp, b_prevote).unwrap(), None);
        let outbound = engine.take_outbound_votes();
        assert!(
            outbound.iter().any(|vt| vt.vote_type == VoteType::Precommit),
            "reaching prevote quorum via the buffered vote must make this node precommit"
        );
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
        let result = engine.receive_proposal(&v.self_kp, 0, block).unwrap();
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

    /// Regression test for a real chain-corruption bug found by battle-testing a live
    /// 3-node testnet: a proposal can have the right height, a valid proposer signature,
    /// merkle root, and proposer-for-this-round assignment, yet still embed a `prev_hash`
    /// that doesn't chain from the block this engine actually finalized last (e.g. a
    /// proposer that raced this node's own commit and built on a sibling that lost).
    /// Before this fix, `validate_block` never checked `prev_hash` at all, so this node
    /// would prevote/precommit for it and help finalize a block that silently forks the
    /// chain — observed in practice as two validators' locally-committed chains sharing
    /// consecutive heights but not actually hash-chaining, permanently desyncing whichever
    /// node's honest gap-sync then (correctly) refused to apply the discontinuous block.
    #[test]
    fn receive_proposal_with_wrong_prev_hash_is_rejected() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 2);
        engine.seed_last_committed(Hash::digest(b"the-real-tip"));

        // c is the proposer for height 3, round 0 ((3 + 0) % 4 == 3, c's index).
        let mut proposer_engine = BftEngine::new(v.validator_set.clone(), v.c_addr.clone(), 2);
        let _ = proposer_engine.produce_block(&v.c_kp, Hash::digest(b"a-different-sibling"), vec![]);
        let block = proposer_engine.pending_proposal().unwrap().clone();

        let result = engine.receive_proposal(&v.self_kp, 0, block);
        assert!(
            matches!(
                &result,
                Err(ConsensusError::InvalidBlock { reason, .. }) if reason.contains("prev_hash mismatch")
            ),
            "a proposal built on the wrong prev_hash must be rejected, not voted for: {result:?}"
        );
        assert!(!engine.has_active_round(), "the rejected proposal must not start a round");
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
        assert_eq!(engine.receive_proposal(&v.self_kp, 0, block).unwrap(), None);
        assert!(!engine.has_active_round());
    }

    /// Regression test for a chain-halting bug found by actually running a
    /// multi-node local testnet: a block that arrives already fully committed
    /// (the `NewCommittedBlock` gossip topic, modeled here by
    /// `sync_to_externally_finalized_block` instead of driving the block through
    /// `receive_proposal`/`add_vote`) must still leave the engine able to accept
    /// the *next* real proposal. Before the fix, only `receive_proposal`/`add_vote`
    /// advanced `current_height` (via the private `finalize()`) — a block applied
    /// through the committed-block fast path left it stale, so the very next
    /// proposal was rejected with an "expected height" error even though the
    /// chain had legitimately moved on.
    #[test]
    fn sync_to_externally_finalized_block_lets_the_next_real_proposal_through() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 1);

        // Height 2 arrived already committed — no receive_proposal/add_vote call.
        engine.sync_to_externally_finalized_block(2, Hash::digest(b"block-2"));
        assert_eq!(engine.current_height(), 2);
        assert!(!engine.has_active_round(), "any stale round for height 2 must be cleared");

        // c is the proposer for height 3, round 0 ((3 + 0) % 4 == 3, c's index).
        let mut proposer_engine = BftEngine::new(v.validator_set.clone(), v.c_addr.clone(), 2);
        let _ = proposer_engine.produce_block(&v.c_kp, Hash::digest(b"block-2"), vec![]);
        let block = proposer_engine.pending_proposal().unwrap().clone();

        // Before the fix this failed with InvalidBlock { reason: "expected height 2, got 3" }.
        let result = engine.receive_proposal(&v.self_kp, 0, block);
        assert!(result.is_ok(), "the next real proposal must not be rejected: {result:?}");
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
        let err = engine.receive_proposal(&v.self_kp, 0, block).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidBlock { height: 2, .. }));
    }

    /// Proposer selection is strict round-robin ((height + round) % len), so
    /// after self proposes round 0 (index 1) it is never round 1's proposer
    /// too (that falls to `b`, index 2) — a stalled round must make self
    /// defer rather than force through a second proposal of its own.
    #[test]
    fn stalled_round_defers_to_next_proposer_when_not_self() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 0);

        let err = engine
            .produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        assert!(matches!(err, ConsensusError::AwaitingVotes { height: 1, round: 0 }));
        engine.take_outbound_votes();

        // No peer votes ever arrive for round 0 — it stalls.
        for _ in 0..ROUND_TIMEOUT_TICKS - 1 {
            assert!(!engine.note_round_tick(), "must not time out early");
        }
        assert!(engine.note_round_tick(), "must time out after ROUND_TIMEOUT_TICKS");

        let err = engine
            .advance_round(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        assert!(matches!(err, ConsensusError::NotProposer { height: 1, round: 1 }));
        assert!(!engine.has_active_round(), "stalled round is dropped either way");
        assert!(engine.take_outbound_votes().is_empty(), "no vote cast when deferring");
    }

    /// The full liveness-fix loop: round 0 stalls, both the original
    /// proposer and the next-in-line validator (`b`) independently notice
    /// the timeout, `b` — being round 1's proposer — produces a fresh
    /// proposal, and the round finalizes normally once quorum is reached on
    /// round 1.
    #[test]
    fn next_proposer_reproposes_after_timeout_and_round_finalizes() {
        let v = four_validators();

        let mut self_engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let _ = self_engine.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        let round0_block = self_engine.pending_proposal().unwrap().clone();
        self_engine.take_outbound_votes();
        for _ in 0..ROUND_TIMEOUT_TICKS {
            self_engine.note_round_tick();
        }
        let err = self_engine
            .advance_round(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        assert!(matches!(err, ConsensusError::NotProposer { height: 1, round: 1 }));

        // `b` independently observed the same round-0 proposal (e.g. via
        // gossip), times out the same way, and — being round 1's proposer —
        // re-proposes with a fresh block.
        let b_addr = Address::from_public_key(&v.b_kp.public);
        let mut b_engine = BftEngine::new(v.validator_set.clone(), b_addr, 0);
        b_engine.receive_proposal(&v.b_kp, 0, round0_block).unwrap();
        b_engine.take_outbound_votes();
        for _ in 0..ROUND_TIMEOUT_TICKS {
            b_engine.note_round_tick();
        }
        let err = b_engine
            .advance_round(&v.b_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        assert!(matches!(err, ConsensusError::AwaitingVotes { height: 1, round: 1 }));
        let round1_block = b_engine.pending_proposal().unwrap().clone();
        let round1_hash = round1_block.hash();
        let b_prevote = b_engine.take_outbound_votes().into_iter().next().unwrap();
        assert_eq!(b_prevote.round, 1);

        // self picks up b's round-1 proposal, joins the round, and votes it
        // to finality exactly like any ordinary (non-timed-out) round.
        let result = self_engine.receive_proposal(&v.self_kp, 1, round1_block).unwrap();
        assert_eq!(result, None);
        let outbound = self_engine.take_outbound_votes();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].round, 1);

        assert_eq!(self_engine.add_vote(&v.self_kp, b_prevote).unwrap(), None);
        let a_prevote = peer_vote(&v.a_kp, VoteType::Prevote, 1, 1, round1_hash.clone());
        assert_eq!(
            self_engine.add_vote(&v.self_kp, a_prevote).unwrap(),
            None,
            "prevote quorum must not finalize the block"
        );
        let outbound = self_engine.take_outbound_votes();
        assert_eq!(outbound.len(), 1, "prevote quorum triggers self's own precommit");
        assert_eq!(outbound[0].vote_type, VoteType::Precommit);

        let a_precommit = peer_vote(&v.a_kp, VoteType::Precommit, 1, 1, round1_hash.clone());
        assert_eq!(self_engine.add_vote(&v.self_kp, a_precommit).unwrap(), None);
        let b_precommit = peer_vote(&v.b_kp, VoteType::Precommit, 1, 1, round1_hash.clone());
        let finalized = self_engine
            .add_vote(&v.self_kp, b_precommit)
            .unwrap()
            .expect("round-1 precommit quorum must finalize the block");
        assert_eq!(finalized.hash(), round1_hash);
        assert_eq!(self_engine.current_height(), 1);
        assert_eq!(self_engine.last_committed_round(), Some(1));
    }

    /// A round-0 proposal arriving *after* this node already joined round 1
    /// (e.g. a slow/duplicate gossip delivery of the original, now-stale
    /// proposal) must not clobber the round-1 state it's already tracking.
    #[test]
    fn stale_round_proposal_after_advance_is_ignored() {
        let v = four_validators();

        let mut self_engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let _ = self_engine.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        let round0_block = self_engine.pending_proposal().unwrap().clone();
        self_engine.take_outbound_votes();
        for _ in 0..ROUND_TIMEOUT_TICKS {
            self_engine.note_round_tick();
        }
        self_engine
            .advance_round(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();

        let b_addr = Address::from_public_key(&v.b_kp.public);
        let mut b_engine = BftEngine::new(v.validator_set, b_addr, 0);
        b_engine.receive_proposal(&v.b_kp, 0, round0_block.clone()).unwrap();
        for _ in 0..ROUND_TIMEOUT_TICKS {
            b_engine.note_round_tick();
        }
        b_engine
            .advance_round(&v.b_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        let round1_block = b_engine.pending_proposal().unwrap().clone();

        self_engine.receive_proposal(&v.self_kp, 1, round1_block).unwrap();
        self_engine.take_outbound_votes();
        assert_eq!(self_engine.pending_proposal().map(|b| b.height()), Some(1));

        // Re-deliver the stale round-0 proposal.
        let result = self_engine.receive_proposal(&v.self_kp, 0, round0_block).unwrap();
        assert_eq!(result, None);
        assert_eq!(
            self_engine.take_outbound_votes().len(),
            0,
            "stale round-0 proposal must not cast a new vote or reset round-1 state"
        );
    }
}
