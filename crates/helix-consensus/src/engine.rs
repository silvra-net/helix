use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use helix_core::{Block, BlockHeader, CommitSig, Transaction};
use helix_crypto::{merkle_root, Address, Hash, KeyPair, Signature};
use tracing::{debug, info};

use crate::{
    round::{RoundPhase, RoundState},
    ConsensusError, ConsensusResult, DoubleSignEvidence, Proposal, Validator, ValidatorSet, Vote,
    VoteType, NIL_BLOCK_HASH,
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
///
/// **15 until 2026-08-27, and by then it was 15 for reasons two other mechanisms had taken
/// over.** The skew argument above is now carried by the per-round backoff
/// (`ROUND_TIMEOUT_STEP_TICKS` — the node that is ahead holds longer, so the gap closes) and by
/// the round-skip rule (`peer_round_to_jump_to`), neither of which existed when this was chosen.
/// What was left was the cost: in a two- or three-validator set a nil quorum is unreachable
/// without the proposer, so **every** round that loses its proposal falls through to this
/// backstop and costs the whole window. Measured on the live chain over 995 blocks: 99.8 % land
/// under 3 s (median 1.43 s, p99 2.49 s) and the two that did not were 18.6 s and exactly
/// 30.00 s — the backstop, to the centisecond.
///
/// 8 ticks is still more than six times the p99 of a complete propose→prevote→precommit→commit
/// cycle, so the margin the paragraph above asks for is intact. Measured rather than argued, on
/// `tests/round_convergence.rs` (two real engines, ten network shapes, 200 ticks each): commits
/// rose in **every** shape — 11→19 at zero latency, 5→15 and 4→12 in the middle, and 3→4 even at
/// the extreme 8-tick latency this file's harness uses to stand in for a broken network. Nothing
/// regressed, which is the half that mattered.
pub const ROUND_TIMEOUT_TICKS: u32 = 8;

/// Block-production ticks a validator waits for its round's proposal before giving up on it and
/// prevoting **nil** (`NIL_BLOCK_HASH`) — see `note_round_tick`.
///
/// This is the knob that decides how fast a dead proposer is routed around, and it can be short
/// precisely *because* it doesn't decide when the round ends: a nil prevote is a claim about
/// this node ("no proposal reached me"), not a unilateral move to the next round. The round only
/// advances once 2/3+ of the power says the same thing, so validators leave together and the
/// per-node timer skew that forces `ROUND_TIMEOUT_TICKS` to be so generous cannot pull them
/// apart here. Being early merely costs a nil prevote that fails to reach quorum.
///
/// **Being early is not free any more, which is why this went from 2 to 4 on 2026-08-27.**
/// Casting nil closes the round to proposals (`RoundState::open_for_nil_prevote`) — a second,
/// different prevote would be equivocation — so the nil window is also the deadline for the
/// round-sync pull to bring the missing proposal in. At 2 ticks the pull got **one** attempt and
/// one network round trip; if that single answer was late, the round was dead and the full
/// backstop was spent. At 4 it gets three attempts, and the only thing it costs is four extra
/// seconds before a genuinely dead proposer is routed around — in a set of two or three, not even
/// that, since nil quorum is unreachable there without the proposer anyway.
pub const PROPOSAL_TIMEOUT_TICKS: u32 = 4;

/// The nil prevote has to be cast strictly before the round it belongs to can time out,
/// otherwise the backstop fires first and no nil quorum ever forms — the dead-proposer latency
/// would silently regress to the old behavior while every test still passed. Compile-time so
/// tuning either constant can't quietly break the ordering they depend on.
const _: () = assert!(PROPOSAL_TIMEOUT_TICKS < ROUND_TIMEOUT_TICKS);

/// Ticks added to both timeouts per round already spent on this height — Tendermint's
/// `timeoutPropose(round) = base + round · delta`.
///
/// **This is what makes two validators converge again, and its absence is what froze the chain.**
/// With a *fixed* window both nodes burn rounds at exactly the same rate, so a phase offset
/// between their clocks is preserved forever: each one's proposal arrives at the other after that
/// other has already left the round, is discarded as stale, and the height never commits. Measured
/// 2026-08-26 on the runtime-join test — A sat on rounds 54/56/58 receiving B's proposals for
/// 53/55/57, and vice versa, for as long as the test ran. Both nodes agreed on the set, the
/// height, the quorum and each other's presence; only the round numbers never met.
///
/// Growing the window breaks the symmetry: the node that is *ahead* holds each round longer than
/// the node behind it, so the gap closes on its own and the two land in the same round. The
/// classic partial-synchrony argument — eventually the timeout exceeds the real message delay —
/// is the same reason Tendermint does it.
const PROPOSAL_TIMEOUT_STEP_TICKS: u32 = 2;
const ROUND_TIMEOUT_STEP_TICKS: u32 = 5;

/// Rounds after which the growth stops. Unbounded backoff is what the textbook prescribes, but a
/// chain that spent 2434 rounds on one height (live, 2026-08-05) would come back to windows
/// measured in hours and look dead long after the fault was fixed. The cap trades the theoretical
/// guarantee for an operational one; the round-skip rule below (`peer_round_to_jump_to`) is what
/// carries convergence past the cap, and it does not depend on timing at all.
const TIMEOUT_BACKOFF_MAX_ROUNDS: u32 = 8;

/// Ticks a round waits for its proposal before *asking a peer* for it (`missing_proposal`).
///
/// Strictly below the nil-prevote window, and that ordering is the whole point. Asking at the same
/// moment nil is cast is asking too late: `RoundState::open_for_nil_prevote` deliberately closes
/// the round to proposals — a second, conflicting prevote from this node would be equivocation —
/// so an answer that arrives after it cannot be used for anything. Measured 2026-08-26, when this
/// was set to the nil window: the answer came back within 200 ms, carried the proposal, and was
/// discarded eight times in a row while the height sat still.
///
/// One tick is cheap because it costs nothing on a healthy round: a proposal that arrived is
/// already here, and `missing_proposal` returns `None` before any request is built.
pub const PROPOSAL_PULL_TICKS: u32 = 1;

/// Asking has to happen strictly before the round stops being able to use the answer.
const _: () = assert!(PROPOSAL_PULL_TICKS < PROPOSAL_TIMEOUT_TICKS);

/// Ticks to wait for round `round`'s proposal before prevoting nil.
pub fn proposal_timeout_ticks(round: u32) -> u32 {
    PROPOSAL_TIMEOUT_TICKS + PROPOSAL_TIMEOUT_STEP_TICKS * round.min(TIMEOUT_BACKOFF_MAX_ROUNDS)
}

/// Ticks round `round` may sit without precommit quorum before the backstop advances it.
pub fn round_timeout_ticks(round: u32) -> u32 {
    ROUND_TIMEOUT_TICKS + ROUND_TIMEOUT_STEP_TICKS * round.min(TIMEOUT_BACKOFF_MAX_ROUNDS)
}

/// Both windows are linear in the round, so checking the two ends checks every round between
/// them: the nil prevote must still be cast strictly before its round's backstop fires, at round 0
/// and at the cap alike. Without this a larger proposal step than round step would silently
/// disable the nil-quorum fast path at high rounds.
const _: () = assert!(PROPOSAL_TIMEOUT_STEP_TICKS <= ROUND_TIMEOUT_STEP_TICKS);

/// Consecutive missed rounds (neither a prevote nor a precommit seen from a validator, see
/// `record_round_liveness`) before this node starts *reporting* that validator as silent.
/// Two rounds, so a single gossip hiccup stays quiet but a genuinely absent validator is
/// named within about a minute — the operator of a stalled chain needs to know *who* it is
/// waiting for, and until 2026-07-22 the node logged nothing at all during a stall (#111).
///
/// **This threshold no longer removes anyone from the quorum, and must never be made to
/// again.** It used to: a validator silent for 20 rounds had its voting power locally zeroed,
/// which lowered this node's quorum threshold until its own vote sufficed. That is unsound by
/// construction, and it forked the live chain on 2026-07-22 at height 66918 — see
/// `record_round_liveness` for the argument and
/// `two_nodes_that_each_consider_the_other_silent_cannot_both_finalize` for the proof.
pub const LIVENESS_SILENCE_WARN_ROUNDS: u32 = 2;

/// Ticks this node waits, under-connected (`peer_count < peers_needed_for_quorum()`), before
/// ticking the round clock anyway — see `note_peer_wait_tick`. 60 ticks × `BLOCK_TIME_MS`
/// (2s) = 2 minutes.
///
/// This was 300 (10 minutes) on the theory that it "matched" the old liveness-jail window.
/// It never matched it — the two ran **in sequence**, so a restart with no peer connected cost
/// this window *plus* that one; measured at over 20 minutes on the live 2-of-2 chain on
/// 2026-07-21. That second window is gone (the liveness jail was removed on 2026-07-22, see
/// `LIVENESS_SILENCE_WARN_ROUNDS`), so this gate is now the whole of the startup delay. It
/// stays short anyway: nothing about waiting longer makes an absent peer arrive.
///
/// Two minutes still covers what this gate is for — letting a validator that starts a few
/// seconds later join at round 0 rather than finding this node already ahead. A peer that has
/// not appeared within two minutes is not about to, and the cost of assuming otherwise is paid
/// in chain downtime.
pub const PEER_WAIT_TIMEOUT_TICKS: u32 = 60;

/// Nothing ticks the round clock until `PEER_WAIT_TIMEOUT_TICKS` expires, so this window is
/// pure added latency on every restart — it delays the first round even when the peers are
/// already there. It used to be 300 ticks (10 minutes), and together with the since-removed
/// liveness jail that measured at over 20 minutes of stall on the live chain. Compile-time so
/// raising it back toward those numbers fails the build rather than production. `helix-node`
/// drives one tick per `BLOCK_TIME_MS` (2s), so 90 ticks is 3 minutes.
const _: () = assert!(PEER_WAIT_TIMEOUT_TICKS <= 90);

/// Cap on votes buffered ahead of the round they belong to (see
/// `BftEngine::buffered_votes`). Bounds the memory a peer can make us hold by
/// flooding votes for a round we haven't started; comfortably above the handful
/// of real early-arriving votes a normal validator set produces per round.
const MAX_BUFFERED_VOTES: usize = 512;

/// What one validator's participation in a **timed-out** round says about it.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum LivenessVerdict {
    /// Neither a prevote nor a precommit from this validator reached us. The only case that
    /// counts toward `missed_rounds` and the only one the "Validator silent" line may name.
    Silent,
    /// We heard from it. `missing_precommit` marks the case that used to be invisible: the round
    /// reached prevote quorum and then stalled, and this validator's precommit is the one that
    /// did not arrive.
    Heard { missing_precommit: bool },
}

/// Who was heard from in a timed-out round, and whether that was enough power to have closed it.
///
/// Exists because on 2026-09-04 this question could not be answered from six and a half hours of
/// log. The engine computes every part of it on every timed-out round and threw all of it away
/// except the names over a silence threshold — so "who voted in this round" was reconstructable
/// only by grepping counters and inferring, which produced two wrong diagnoses in one day.
///
/// The distinction that matters is `enough_power_heard`. "Votes are missing" and "the votes were
/// there and the round still did not close" are different failures with different fixes, and
/// nothing in the log separated them.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct RoundAttendance {
    /// Other validators whose prevote or precommit reached us this round.
    pub heard: Vec<Address>,
    /// Other validators we heard nothing from.
    pub silent: Vec<Address>,
    /// Voting power behind `heard`, plus this node's own if it voted. What the round actually had.
    pub power_heard: u64,
    pub quorum: u64,
    pub reached_prevote_quorum: bool,
}

impl RoundAttendance {
    /// Was there enough voting power in the room? A `false` here says the round could not have
    /// closed whatever else is true, and points at the absent validators. A `true` says the power
    /// was present and the round failed anyway — which is not a liveness problem at all and sends
    /// the diagnosis somewhere completely different.
    pub(crate) fn enough_power_heard(&self) -> bool {
        self.power_heard >= self.quorum
    }
}

/// Build the summary from what the round holds. Separated from the logging for the same reason
/// `liveness_verdict` is: a rule that can only be checked by reading a log line is a rule nothing
/// tests.
///
/// `participants` is `(address, voting_power, heard_from)` for every *other* validator that can
/// hold a round up. `own_power` is this node's own, counted only when it voted itself — a node
/// that did not vote must not credit itself with power the round never had.
pub(crate) fn round_attendance(
    participants: &[(Address, u64, bool)],
    own_power: u64,
    quorum: u64,
    reached_prevote_quorum: bool,
) -> RoundAttendance {
    let mut heard = Vec::new();
    let mut silent = Vec::new();
    let mut power_heard = own_power;
    for (address, power, was_heard) in participants {
        if *was_heard {
            power_heard = power_heard.saturating_add(*power);
            heard.push(address.clone());
        } else {
            silent.push(address.clone());
        }
    }
    RoundAttendance { heard, silent, power_heard, quorum, reached_prevote_quorum }
}

/// Classify one validator's participation in a round that timed out.
///
/// The distinction that matters is *which phase* failed. A precommit is only cast once prevote
/// quorum is reached (`lock_and_precommit`), so in a round that never got that far every
/// validator is missing one — flagging that would name the whole set and say nothing. Only when
/// the round *did* reach prevote quorum is a missing precommit a real, attributable diagnosis.
///
/// Kept separate from `record_round_liveness` because otherwise it is only observable through a
/// log line, and a rule that can only be checked by reading logs is a rule nothing tests.
fn liveness_verdict(
    prevoted: bool,
    precommitted: bool,
    reached_prevote_quorum: bool,
) -> LivenessVerdict {
    if !prevoted && !precommitted {
        return LivenessVerdict::Silent;
    }
    LivenessVerdict::Heard {
        missing_precommit: reached_prevote_quorum && !precommitted,
    }
}

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
    /// Tendermint locking state for the *current height* (all `None`/empty between heights).
    /// Set when this node observes a prevote-quorum for a value: `locked_round` is the round
    /// it locked in, `locked_block` is the value, and `locked_pol` is the 2/3+ prevote
    /// certificate that formed the quorum. While locked, this node re-proposes `locked_block`
    /// (with the POL) whenever it's the proposer of a later round, and refuses to prevote any
    /// *different* value unless it sees a proof-of-lock from a round at least as new as
    /// `locked_round`. This is the safety mechanism that stops two different blocks from both
    /// reaching quorum at the same height across rounds (a fork): once 2/3 of the power locks
    /// on a value, the >1/3 that hold the lock withhold their prevotes from any conflicting
    /// value, so no conflicting value can ever reach a prevote-quorum. Reset every time the
    /// height advances (`finalize`/`sync_to_externally_finalized_block`).
    locked_round: Option<u32>,
    locked_block: Option<Block>,
    locked_pol: Vec<Vote>,
    /// The round this node currently considers active for the pending height
    /// (`current_height + 1`), tracked **even when no `RoundState` exists** — i.e. while a
    /// non-proposer waits for someone else's proposal. Without this, the round clock only ran
    /// for the node that actually proposed (the only one with an active round), so a
    /// dead/offline proposer stalled the height forever: every other validator waited for a
    /// proposal that never came, with nothing advancing them to the next round's (live)
    /// proposer. `advance_round` now bumps this and re-elects a proposer even from a
    /// no-active-round wait. Reset to 0 each time the height advances.
    pending_round: u32,
    /// EIP-1559 base fee (nano-HLX per tx byte) that the *next* block to be produced or
    /// accepted must carry (see `helix_core::fee`). It is not consensus state the engine
    /// derives itself — the node, which holds the store, recomputes it from each committed
    /// block via `set_base_fee_per_byte()` (deterministically, `fee::next_base_fee_per_byte`
    /// of the parent's fee and byte-usage). Production stamps it into the header; a received
    /// proposal is rejected unless its header carries exactly this value, so a proposer can't
    /// pick an arbitrary base fee.
    current_base_fee_per_byte: u64,
    /// Consecutive rounds (see `record_round_liveness`) each other validator has gone
    /// without casting a prevote or precommit this node saw. Purely local/observational —
    /// never persisted, never part of `ChainState`/`state_hash`, and not something nodes are
    /// expected to agree on. **Diagnostic only:** it decides what this node *logs* about a
    /// stall, never who counts toward quorum. Reset to 0 for a validator the instant it votes
    /// again; absent rather than stored as 0.
    missed_rounds: HashMap<Address, u32>,
    /// The silent set as it stood the last time it was reported. Only *changes* are worth an
    /// `info!`: a steady situation says the same thing every round and teaches an operator to skim
    /// the log, while every transition — someone dropping out, someone coming back — is the line a
    /// later diagnosis actually needs and cannot reconstruct afterwards.
    last_reported_silent: Vec<Address>,
    /// The precommit quorum certificate that finalized `current_height`, carried forward one
    /// height so the *next* block this engine proposes can attach it as `last_commit` — see
    /// `BlockHeader::last_commit`'s doc comment for why it travels one block late. Empty after
    /// `sync_to_externally_finalized_block` (a block adopted from gossip/RPC catch-up, not
    /// tallied by this engine's own `VoteSet` — nothing to attach then; the next block this
    /// node proposes simply attests no signers for that one height, which the executor's
    /// downtime counter tolerates as a single miss, not a jailing trigger).
    last_commit: Vec<Vote>,
    /// Consecutive ticks this node has been held back by the peer-count gate in
    /// `block_production_loop` (`peer_count < peers_needed_for_quorum()`) — see
    /// `note_peer_wait_tick`. Reset via `reset_peer_wait` the moment enough peers are
    /// connected again.
    peer_wait_ticks: u32,
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
            locked_round: None,
            locked_block: None,
            locked_pol: Vec::new(),
            pending_round: 0,
            current_base_fee_per_byte: helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
            missed_rounds: HashMap::new(),
            last_reported_silent: Vec::new(),
            peer_wait_ticks: 0,
            last_commit: Vec::new(),
        }
    }

    /// Record a tick spent waiting for peers below `peers_needed_for_quorum()` (the gate in
    /// `block_production_loop`). Returns `true` once `PEER_WAIT_TIMEOUT_TICKS` has been
    /// reached — the caller should stop waiting and tick the round clock anyway. Without this,
    /// a validator that never reconnects (or never existed as a running node in the first
    /// place) holds this node in the `continue` branch forever: the round clock never runs, so
    /// nothing ever times out and the node reports nothing about what it is waiting for
    /// (`record_round_liveness` only runs on a round timeout). The peer-count gate itself
    /// stays in place for the cold-start case it was built for (letting late-joining
    /// validators catch up at round 0 instead of finding this node many rounds ahead) — this
    /// only bounds how long that grace period lasts.
    pub fn note_peer_wait_tick(&mut self) -> bool {
        self.peer_wait_ticks += 1;
        self.peer_wait_ticks >= PEER_WAIT_TIMEOUT_TICKS
    }

    /// Enough peers are connected again — clear the wait counter so a future disconnect gets
    /// the full grace period, not whatever was left over from an earlier one.
    pub fn reset_peer_wait(&mut self) {
        self.peer_wait_ticks = 0;
    }

    /// The base fee (nano-HLX per tx byte) the next block must carry. Exposed so the node can
    /// initialize/refresh it from the persisted chain tip after a restart.
    pub fn base_fee_per_byte(&self) -> u64 {
        self.current_base_fee_per_byte
    }

    /// Set the base fee the next produced/accepted block must carry. The node calls this after
    /// each commit (and once at startup) with `fee::next_base_fee_per_byte` of the chain tip —
    /// keeping the value out of the engine's own state, since only the node holds the blocks.
    pub fn set_base_fee_per_byte(&mut self, base_fee_per_byte: u64) {
        self.current_base_fee_per_byte = base_fee_per_byte;
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

    /// Whether `candidate` — the round a vote just arrived for — is a round peers have
    /// demonstrably already reached and this node has not: Tendermint's round-skip rule, and the
    /// half of round synchronization that does not depend on timing at all.
    ///
    /// "Demonstrably" is `> total_voting_power / 3`: strictly more than the fault budget, so at
    /// least one honest validator is genuinely in that round. Anything less could be a single
    /// faulty node pulling this one away from a round the rest of the network is still in.
    ///
    /// Every vote counted here is signature-verified against the active set first. Buffered votes
    /// are *not* verified when they arrive (they are only checked on replay, inside `VoteSet::add`),
    /// so without this a peer could push us to any round it liked with a forged vote for a
    /// validator that never signed one.
    ///
    /// **What a peer can do with this, and why it is acceptable.** A validator holding more than a
    /// third of the power can make us skip rounds. It could already do exactly that by proposing
    /// at a high round (`receive_proposal` adopts a newer round), so this adds no capability. And
    /// skipping rounds commits nothing: what gets finalized still needs a quorum *inside* one
    /// round, and `locked_round`/`locked_block`/`should_prevote` — the entire cross-round safety
    /// argument — are untouched here. The cost of being dragged forward is liveness, never a fork.
    fn peer_round_to_jump_to(&self, candidate: u32) -> Option<u32> {
        let current = self.active_round_number();
        if candidate <= current {
            return None;
        }
        let height = self.current_height + 1;
        let fault_budget = self.validator_set.total_voting_power() / 3;

        // Scoped to the round that just arrived rather than scanning the whole buffer, and that
        // is a bound, not a shortcut: the buffer holds up to `MAX_BUFFERED_VOTES` entries, so
        // re-scanning it per incoming vote would let a peer turn one message into hundreds of
        // ML-DSA verifications. Deduplication is per (validator, round, type), so one round can
        // hold at most two votes per set member — the work here is bounded by the validator set,
        // not by what a peer sends. Nothing is lost by ignoring the other rounds: a round with
        // enough power behind it keeps producing votes, and the next one pulls us there.
        let mut voters: HashMap<Address, u64> = HashMap::new();
        for vote in &self.buffered_votes {
            if vote.height != height || vote.round != candidate {
                continue;
            }
            let Some(validator) = self.validator_set.get(&vote.validator) else {
                continue;
            };
            // Skip a probationer before paying for a signature verification: it carries zero
            // voting power (#132), so it cannot move the sum below past the fault budget however
            // many votes it sends. The threshold measured in *power* is what actually enforces
            // "a probationer cannot pull the set to its round"; this is the cheap short-circuit,
            // not the rule — removing it changes performance, not behaviour.
            if validator.voting_power == 0 || vote.verify_signature().is_err() {
                continue;
            }
            voters.insert(vote.validator.clone(), validator.voting_power);
        }

        (voters.values().sum::<u64>() > fault_budget).then_some(candidate)
    }

    /// Leave the round this node is on for `round`, because the network is provably there already
    /// (see `peer_round_to_jump_to`). Abandons the active round if there is one.
    ///
    /// Deliberately *not* `record_round_liveness`: that names whoever failed to vote in a round
    /// that timed out, and this round did not time out — it is being skipped because we are the
    /// late one. Counting a silence here would report the validators that are ahead of us as the
    /// reason we are behind them.
    fn jump_to_round(&mut self, round: u32) {
        if let Some(abandoned) = self.round.take() {
            self.pending_evidence.extend(abandoned.evidence);
        }
        debug!(
            height = self.current_height + 1,
            from = self.pending_round,
            to = round,
            "Skipping ahead to the round peers have already reached"
        );
        self.pending_round = round;
        self.round_ticks = 0;
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
            let _ = match v.vote_type {
                VoteType::Prevote => round.add_prevote(v),
                VoteType::Precommit => round.add_precommit(v),
            };
            // If a replayed prevote just tipped prevote quorum, lock on the value and cast
            // our own precommit so the round can progress to commit.
            lock_and_precommit(
                &self.address,
                keypair,
                round,
                &mut self.outbound_votes,
                &mut self.locked_round,
                &mut self.locked_block,
                &mut self.locked_pol,
            );
        }
    }

    /// The round number of the currently active round, if any — so the block
    /// production loop can re-broadcast the pending proposal under the right round.
    pub fn active_round_num(&self) -> Option<u32> {
        self.round.as_ref().map(|r| r.round)
    }

    /// Whether the next block is this node's to make: it is the designated proposer for the
    /// height it is deciding, in the round it has actually reached.
    ///
    /// The block loop needs this to tell two very different silences apart. If it is our turn,
    /// nothing is being waited on — `produce_block` opens the round on the next tick. If it is
    /// *not* our turn, we are waiting on a proposer that may be dead, may be behind and
    /// proposing on a `prev_hash` we rejected, or may simply be slow — and then the round clock
    /// has to run, or the height never moves again (backlog #143).
    pub fn is_our_turn(&self) -> bool {
        self.validator_set
            .is_proposer(&self.address, self.current_height + 1, self.pending_round)
    }

    /// How many *other* validators must be connected and voting for this node to
    /// be able to reach quorum. While fewer than this are reachable, quorum is
    /// impossible no matter how many rounds are burned — so the caller holds the
    /// current round instead of advancing (and running ahead of validators that
    /// will join at round 0). Zero for a single-validator set, where this node's
    /// own power already meets quorum and block production never waits on peers.
    /// How many *other* validators have been silent long enough to be reported as the reason the
    /// round is not closing — the same threshold that produces the "Validator silent" warnings.
    ///
    /// Exists so the health loop can tell two situations apart that look identical from outside
    /// the consensus path: this node has stopped participating, or this node is fine and waiting
    /// on somebody else. Those call for opposite actions, and until now the health line gave the
    /// same advice for both — telling the operator of a perfectly healthy node to restart it.
    /// Confirmed live on 2026-08-06: peers connected, one validator silent for 86 rounds, and the
    /// health line recommended a restart that demonstrably changed nothing.
    ///
    /// Note carefully what this counts, because the name invites the wrong reading (R2): it is
    /// validators whose votes *this node is not seeing*. That is not the same as validators that
    /// are down — on 2026-07-29 a validator was reported silent 596 times while producing blocks
    /// perfectly well, because the missing piece was the link between them, not the peer. Anything
    /// phrased on top of this must say "not seeing their votes", never "they are offline".
    pub fn silent_peer_validators(&self) -> usize {
        self.missed_rounds
            .values()
            .filter(|missed| **missed >= LIVENESS_SILENCE_WARN_ROUNDS)
            .count()
    }

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
        // The round the engine has actually reached for this height — NOT a hardcoded 0.
        // The block loop calls `produce_block` whenever there is no active round and the
        // round hasn't timed out yet; after the engine has timed out through several rounds
        // (every proposer for them silent), `pending_round` is well past 0. Hardcoding 0
        // here made a proposer re-propose round 0 after already reaching round N — a round
        // regression that is self-equivocation, which the signing guard then withholds,
        // silently freezing any set small enough to need every member (the 2026-07-24 stall,
        // and the round-0 fingerprint of the #125 double-sign slashes). Using `pending_round`
        // keeps propose/advance_round consistent: we only ever propose the round we're on.
        let round_num = self.pending_round;

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

    /// Called once per block-production tick while this height is unfinalized. Drives both
    /// timeouts and reports whether the caller should now `advance_round`.
    ///
    /// Two clocks, doing different jobs:
    ///
    /// * `PROPOSAL_TIMEOUT_TICKS` (short) — no proposal arrived, so cast a **nil prevote** and
    ///   broadcast it. This does not end the round; it publishes this node's view so the
    ///   network can form an opinion. Cast at most once per round (a second, conflicting
    ///   prevote from us would be equivocation).
    /// * `ROUND_TIMEOUT_TICKS` (long) — backstop. If nil never reaches quorum either (say too
    ///   much of the power is down to form *any* 2/3 majority), the round still has to end
    ///   eventually, or the height stalls forever. This is the pre-nil-vote behavior, kept.
    ///
    /// The fast path is neither of these: `should_advance_round` fires as soon as prevotes
    /// reach quorum on nil, typically one tick after the nil prevotes go out.
    ///
    /// **Why abandoning a round on prevote-nil quorum is safe.** Advancing the round commits
    /// nothing, so it cannot fork the chain; the only real question is whether it could
    /// abandon a round in which some honest validator had already precommitted a block. It
    /// cannot: a precommit requires a prevote quorum for that block, and prevote quorums for
    /// nil and for a block are mutually exclusive. Each needs `2N/3 + 1` of the power, so both
    /// together need more than `4N/3` — over `N/3` of the power would have to prevote both,
    /// i.e. equivocate, which exceeds the `f < N/3` fault budget BFT assumes (and is
    /// individually slashable, see `VoteSet::add`). For the same reason no lock can have formed
    /// in a round that reaches nil quorum, so `locked_round`/`locked_block` are untouched and
    /// Tendermint's cross-round safety argument (`should_prevote`) carries over unchanged.
    pub fn note_round_tick(&mut self, keypair: &KeyPair) -> bool {
        self.round_ticks += 1;

        // Both windows widen with the round (`proposal_timeout_ticks`): the round number is
        // fixed for as long as the round lasts, so the value cannot change underneath the `==`.
        let round = self.active_round_number();

        if self.round_ticks == proposal_timeout_ticks(round) {
            self.prevote_nil(keypair);
        }

        if self.should_advance_round() {
            return true;
        }

        self.round_ticks >= round_timeout_ticks(round)
    }

    /// The round this node is currently deciding the pending height in — the active round's
    /// number if it holds one, otherwise the round it is waiting for a proposal in.
    fn active_round_number(&self) -> u32 {
        self.round.as_ref().map_or(self.pending_round, |r| r.round)
    }

    /// Whether the network has agreed (2/3+ prevotes for `NIL_BLOCK_HASH`) that the active
    /// round has nothing to commit, so the caller should `advance_round` to the next proposer
    /// immediately rather than sitting out the rest of `ROUND_TIMEOUT_TICKS`.
    pub fn should_advance_round(&self) -> bool {
        self.round
            .as_ref()
            .is_some_and(|r| r.prevotes.quorum_hash() == Some(NIL_BLOCK_HASH))
    }

    /// Cast this node's nil prevote for the round it is currently waiting on, creating the
    /// `RoundState` if the wait never had one (the dead-proposer case: a non-proposer holds no
    /// round until a proposal arrives). Silent no-op if we already hold a proposal for this
    /// round, already prevoted in it, or aren't in the validator set — all cases where a nil
    /// prevote would be either wrong or a self-inflicted double-sign.
    fn prevote_nil(&mut self, keypair: &KeyPair) {
        if self.assert_is_validator().is_err() {
            return;
        }
        let height = self.current_height + 1;
        let round_num = self.round.as_ref().map_or(self.pending_round, |r| r.round);

        // Never nil-prevote a round this node is itself the proposer of. There is nothing to give
        // up on: the proposal is ours to make, and the block-production loop makes it in this very
        // tick — `produce_block` runs right after `note_round_tick` when no round was active.
        //
        // Without this, both happen in the same tick and in this order: the clock fires, nil is
        // cast for (h, r), then `propose` builds a fresh `RoundState` over it and casts a prevote
        // for the real block at the same (h, r). That is textbook equivocation — two different
        // prevotes, same height, same round — and the only thing that stopped it from being
        // gossiped and slashed was the persisted signing guard refusing the second one. The cost
        // was paid anyway: the proposer's own prevote never went out, so its own proposal could
        // not gather the vote it needed and the round died. Measured 2026-08-26 on the
        // four-validator test — two of these per run, every run, always `mark = NIL at (h, 0)`
        // against an offered block hash at (h, 0) (backlog #176).
        if self
            .validator_set
            .is_proposer(&self.address, height, round_num)
        {
            return;
        }

        // Inspect any existing round before touching `self.round`. A proposal that did arrive
        // (phase past `Propose`) means there is nothing to abandon — our prevote for the real
        // value is already cast, or deliberately withheld by the lock rule.
        if let Some(round) = self.round.as_ref() {
            if round.phase != RoundPhase::Propose || round.prevotes.has_voted(&self.address) {
                return;
            }
        }

        // Sign before creating anything. Doing it the other way round leaves a round behind on
        // a signing failure — opened for nil, holding neither a vote nor a proposal — and
        // `receive_proposal` then turns away this round's real proposal on the grounds that we
        // are already tracking it. Self-healing via the backstop timeout, but only after
        // throwing away a round for no reason.
        let Ok(vote) = cast_vote(
            &self.address,
            keypair,
            VoteType::Prevote,
            height,
            round_num,
            NIL_BLOCK_HASH,
        ) else {
            return;
        };

        let validator_set = self.validator_set.clone();
        let round = self
            .round
            .get_or_insert_with(|| RoundState::new(height, round_num, validator_set));
        if round.open_for_nil_prevote().is_err() {
            return;
        }
        let _ = round.add_prevote(vote.clone());
        self.outbound_votes.push(vote);
        // Peers' nil prevotes for this round may already be buffered (they hit their own
        // proposal timeout first) — fold them in now that a round exists to hold them, so
        // quorum can be reached without waiting for a re-send that gossipsub never makes.
        let mut round = self.round.take().expect("just inserted above");
        self.apply_buffered_votes(keypair, &mut round);
        self.round = Some(round);
    }

    /// Advance the pending height to its next round — e.g. the round's proposer was offline,
    /// or its block failed validation for enough peers that quorum could never be reached.
    ///
    /// Works in **both** states this can happen from:
    ///  - We have an active (stalled) round we proposed/joined: drop it (its votes are bucketed
    ///    under the old round and don't carry over) and advance from `stalled.round + 1`.
    ///  - We have *no* active round — a non-proposer that's been waiting for a proposal that
    ///    never arrived (its round's proposer is dead/offline): advance from
    ///    `pending_round + 1`. This is the case that used to stall the height forever, since
    ///    only the proposer ever held a round and thus ran the round clock at all.
    ///
    /// If this node is the proposer for the new round, builds and signs a fresh proposal
    /// (re-proposing a locked value with its proof-of-lock if held — see `propose`) and casts
    /// its own votes, returning `AwaitingVotes`/`Ok`. Otherwise returns `NotProposer` and
    /// records the new round as pending, so the caller waits for that round's proposer's
    /// `Proposal` (and `receive_proposal` accepts it rather than rejecting it as stale).
    pub fn advance_round(
        &mut self,
        keypair: &KeyPair,
        prev_hash: Hash,
        transactions: Vec<Transaction>,
    ) -> ConsensusResult<Block> {
        let height = self.current_height + 1;
        let from_round = match self.round.take() {
            Some(stalled) => {
                self.record_round_liveness(&stalled);
                self.pending_evidence.extend(stalled.evidence);
                stalled.round
            }
            None => self.pending_round,
        };
        let round_num = from_round + 1;
        self.pending_round = round_num;
        self.round_ticks = 0;

        if !self.validator_set.is_proposer(&self.address, height, round_num) {
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
        self.pending_round = round_num;

        // If we're locked on a value from an earlier round of this height, re-propose that
        // exact value (with its proof-of-lock certificate) instead of building a fresh block.
        // Abandoning a value a prevote-quorum already formed on is precisely how two different
        // blocks could each reach quorum across rounds — the fork this prevents.
        let (block, valid_round, pol) = match (self.locked_round, self.locked_block.clone()) {
            (Some(lr), Some(locked_block)) => (locked_block, Some(lr), self.locked_pol.clone()),
            _ => (
                self.build_signed_block(keypair, height, prev_hash, transactions)?,
                None,
                Vec::new(),
            ),
        };
        let block_hash = block.hash();

        // Start round: Propose → Prevote
        let mut round = RoundState::new(height, round_num, self.validator_set.clone());
        round.set_proposal(block.clone(), valid_round, pol)?;

        // Cast own prevote for our proposal.
        let prevote = cast_vote(&self.address, keypair, VoteType::Prevote, height, round_num, block_hash.clone())?;
        round.add_prevote(prevote.clone())?;
        self.outbound_votes.push(prevote);

        // If our own prevote alone already reached quorum (single-validator devnet), lock on
        // the value and cast our own precommit.
        lock_and_precommit(
            &self.address,
            keypair,
            &mut round,
            &mut self.outbound_votes,
            &mut self.locked_round,
            &mut self.locked_block,
            &mut self.locked_pol,
        );

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
        // A vote on the height being decided proves the sender is participating, so clear its
        // silence counter here as well as in `record_round_liveness` — that one only runs on a
        // round timeout, which is exactly the event a returning validator prevents.
        //
        // Height-gated on purpose. A peer stuck on a fork votes on its own tip forever: those
        // votes can never be counted here, and treating them as presence would report a healthy
        // peer while the chain sits still. Presence is not the question — participation is.
        if vote.height == self.current_height + 1 {
            self.missed_rounds.remove(&vote.validator);
        }

        // Helix never precommits nil (see `note_round_tick`), so a precommit carrying
        // `NIL_BLOCK_HASH` is not something an honest validator produces. Refuse it at the
        // boundary rather than letting it accumulate power behind the nil key, where enough of
        // it would drive a round to `Commit(NIL)` and finalize a height with no block.
        if vote.vote_type == VoteType::Precommit && vote.block_hash == NIL_BLOCK_HASH {
            return Err(ConsensusError::InvalidVote {
                reason: "precommit for nil — Helix advances rounds on prevote-nil quorum and \
                         never precommits nil"
                    .into(),
            });
        }

        // A precommit for the block we *just* committed still has a job to do, even though the
        // round it belonged to is gone: it belongs in the commit certificate.
        //
        // Without this, a validator whose precommit was never *needed* for quorum can never get
        // its signature into a certificate at all — and one class of validator is never needed by
        // construction. A #132 probationer carries zero voting power on purpose, so it can never be
        // the vote that tips a quorum, is never waited for, and its precommit lands after
        // `finalize` has already taken the round. Promotion out of probation requires exactly that
        // signature to appear in a committed `last_commit`, so the probationer cycled
        // probation → pending → probation forever and no new validator could ever activate.
        // Measured, not theorised: a three-validator devnet sat at height 500+ with two staked,
        // correctly-running joiners still inactive.
        //
        // This alone does **not** fix that — measured too. When the active set can finalize on its
        // own, the proposer never broadcasts a proposal at all (it commits inside `produce_block`
        // and gossips the finished block), so peers cast no precommit for this to collect. Closing
        // the probation loop needs that second half; see backlog #141, for which this is the
        // prerequisite. It is worth having on its own regardless: a certificate that names
        // everyone who actually stood behind a block is strictly better evidence than one that
        // names only whoever happened to be needed.
        //
        // The certificate for height h is stamped into block h+1's header, a whole block interval
        // later, so a late precommit collected here is in the block on time.
        //
        // Safe on every axis that matters:
        // - It cannot change what was finalized. The commit already happened; this only enriches
        //   the record of *who stood behind it*.
        // - It cannot forge presence. The signature is verified and must come from an in-set
        //   validator for exactly this `(height, block_hash)`, so only the key holder can produce
        //   it — a phantom with no running node still never appears, which is the whole point of
        //   probation.
        // - It cannot diverge between nodes. Every node reads participation from the *committed
        //   block's* `last_commit`, identical everywhere; the proposer's local view decides what
        //   goes in, exactly as it already does for #114's certificate.
        if vote.vote_type == VoteType::Precommit
            && vote.height == self.current_height
            && self.last_committed.as_ref() == Some(&vote.block_hash)
        {
            let in_set = self.validator_set.get(&vote.validator).is_some();
            let already_known = self
                .last_commit
                .iter()
                .any(|v| v.validator == vote.validator);
            if in_set && !already_known && vote.verify_signature().is_ok() {
                debug!(
                    height = vote.height,
                    validator = %vote.validator,
                    "Late precommit folded into the commit certificate"
                );
                self.last_commit.push(vote);
            }
            return Ok(None);
        }

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
                let arrived_at = vote.round;
                self.buffer_vote(vote);
                // A vote from a round ahead of ours is also evidence of where the network is.
                // Without acting on it, two validators whose round clocks drifted apart each keep
                // buffering the other's votes and neither ever arrives in a round the other is
                // still in — the freeze measured on 2026-08-26.
                if let Some(round) = self.peer_round_to_jump_to(arrived_at) {
                    self.jump_to_round(round);
                }
                return Ok(None);
            }
        }

        let round = self
            .round
            .as_mut()
            .ok_or(ConsensusError::NoActiveRound)?;

        match vote.vote_type {
            VoteType::Prevote => round.add_prevote(vote)?,
            VoteType::Precommit => round.add_precommit(vote)?,
        };

        // If this vote just tipped prevote quorum, lock on the agreed value (capturing the
        // prevote certificate) and cast our own precommit — otherwise a round could stall
        // forever waiting on a precommit nobody sends when quorum is reached step-by-step.
        lock_and_precommit(
            &self.address,
            keypair,
            round,
            &mut self.outbound_votes,
            &mut self.locked_round,
            &mut self.locked_block,
            &mut self.locked_pol,
        );

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
    pub fn receive_proposal(&mut self, keypair: &KeyPair, proposal: Proposal) -> ConsensusResult<Option<Block>> {
        let Proposal { round: round_num, valid_round, block, pol } = proposal;

        // Proposing on the height we are deciding is participation, so it clears the proposer's
        // liveness strikes — same reasoning, and the same height gate, as in `add_vote`: a
        // proposal for a different history proves the sender is running, not that it is helping
        // decide the block we are stuck on.
        if block.height() == self.current_height + 1 {
            self.missed_rounds.remove(&block.header.validator);
        }

        if block.height() <= self.current_height {
            return Ok(None);
        }

        self.assert_is_validator()?;
        self.validate_block(&block, round_num, valid_round, &pol)?;

        let height = block.height();

        // Already tracking this round (or a later one) for this height —
        // e.g. duplicate gossip delivery, or a stale proposal that arrived
        // after we (or the network) already moved past it.
        if self.round.as_ref().is_some_and(|r| r.height == height && r.round >= round_num) {
            return Ok(None);
        }

        // Stale round for the pending height: we've already advanced past it via a round
        // timeout (`advance_round` bumped `pending_round`) even though we never held a
        // `RoundState` for it — a non-proposer that timed out waiting. Without this a
        // late-arriving proposal for the abandoned round would restart it.
        if height == self.current_height + 1 && round_num < self.pending_round {
            return Ok(None);
        }

        let block_hash = block.hash();
        let mut round = RoundState::new(height, round_num, self.validator_set.clone());
        round.set_proposal(block, valid_round, pol)?;
        self.round_ticks = 0;
        // Adopt this round as the pending one — a proposal for a *newer* round than we'd
        // reached pulls us forward onto it (round synchronization via the proposal itself).
        self.pending_round = round_num;

        // Tendermint prevote gate: prevote this value only if we hold no conflicting lock
        // (or the proposal's proof-of-lock, already verified by `validate_block`, justifies
        // unlocking). If we're locked on a different value without a new-enough POL, abstain
        // — still track the round to tally peers' votes, but withhold our own prevote. That
        // withholding is exactly what stops a value conflicting with a 2/3 lock from ever
        // reaching a prevote-quorum.
        if self.should_prevote(&block_hash, valid_round) {
            let prevote = cast_vote(&self.address, keypair, VoteType::Prevote, height, round_num, block_hash)?;
            round.add_prevote(prevote.clone())?;
            self.outbound_votes.push(prevote);

            // If our own prevote alone already reached quorum, lock and precommit.
            lock_and_precommit(
                &self.address,
                keypair,
                &mut round,
                &mut self.outbound_votes,
                &mut self.locked_round,
                &mut self.locked_block,
                &mut self.locked_pol,
            );
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

    /// The precommit votes that finalized the most recently committed block — its commit
    /// certificate. After `finalize` this is the quorum that carried the block; it is also what
    /// `build_signed_block` folds into the *next* block's `last_commit`. Exposed so the node can
    /// gossip it alongside a committed block (#114): a peer that receives the block over the
    /// committed-blocks fast path never collected these votes itself, so without them its own next
    /// `last_commit` would be empty — leaving the block's participation unrecorded for downtime
    /// accounting and its finality unprovable to a light client. Empty at genesis / before the
    /// first finalize.
    pub fn commit_certificate(&self) -> Vec<Vote> {
        self.last_commit.clone()
    }

    /// The block currently proposed for the active round, if any — e.g. so a
    /// caller can inspect what this node is waiting on votes for.
    pub fn pending_proposal(&self) -> Option<&Block> {
        self.round.as_ref().and_then(|r| r.proposal.as_ref())
    }

    /// The full proposal envelope this node is currently tracking — the block plus its
    /// proof-of-lock metadata (`valid_round`/`pol`) — for (re)broadcast to peers. Callers
    /// must broadcast this rather than reconstructing `Proposal { round, block }`, or a
    /// re-proposed (locked) value would lose the POL certificate that lets locked peers
    /// accept it. `None` when there's no active proposal.
    pub fn pending_proposal_envelope(&self) -> Option<Proposal> {
        let r = self.round.as_ref()?;
        let block = r.proposal.clone()?;
        Some(Proposal {
            round: r.round,
            valid_round: r.proposal_valid_round,
            block,
            pol: r.proposal_pol.clone(),
        })
    }

    /// The `(height, round)` this node is waiting on a proposal for and cannot produce itself —
    /// the one thing a peer can hand it that gossip no longer will.
    ///
    /// `None` in every case where asking would be pointless: we already hold the proposal, we are
    /// this round's proposer (so it is ours to make), the round is one tick old and the proposal
    /// may simply still be in flight (`PROPOSAL_PULL_TICKS`), or we have already prevoted nil and
    /// so could no longer use an answer.
    pub fn missing_proposal(&self) -> Option<(u64, u32)> {
        let height = self.current_height + 1;
        let round = self.active_round_number();
        if self.round.as_ref().is_some_and(|r| r.proposal.is_some()) {
            return None;
        }
        if self.validator_set.is_proposer(&self.address, height, round) {
            return None;
        }
        // Already prevoted in this round — which here means nil, since holding a proposal was
        // ruled out above. The round is closed to proposals from that moment on
        // (`open_for_nil_prevote`), so an answer could not be applied and asking for one is a
        // request per tick that can only ever be discarded.
        if self.round.as_ref().is_some_and(|r| r.prevotes.has_voted(&self.address)) {
            return None;
        }
        if self.round_ticks < PROPOSAL_PULL_TICKS {
            return None;
        }
        Some((height, round))
    }

    /// Everything this node holds for the height it is currently deciding: the proposal envelope
    /// and every vote it has collected or buffered for that height. This is what a peer gets when
    /// it *asks* what it missed — the pull half of round synchronization.
    ///
    /// A pull is needed because gossip cannot re-deliver. Every message is published once; the
    /// node re-offers its pending proposal each tick, but gossipsub derives a message's identity
    /// from a hash of its bytes and refuses to publish the same bytes again for a minute
    /// (`duplicate_cache_time`), so the re-offer never reaches a peer that was not listening the
    /// first time — measured 2026-08-26, 483 refusals in a single node's log while the chain sat
    /// still. A validator that was catching up during the one broadcast therefore had no way to
    /// obtain the proposal at all, and the round could only time out.
    ///
    /// Nothing here is trusted by the receiver: it feeds the answer through `receive_proposal` and
    /// `add_vote`, exactly as if it had arrived over gossip, so signatures, set membership and the
    /// lock rules are all still applied. A peer can withhold or lie; it cannot make us accept
    /// anything we would have rejected from the same bytes on the wire.
    ///
    /// Empty for any height but the one being decided — a committed height is served by block
    /// sync, which carries the quorum certificate that proves it.
    pub fn round_evidence(&self, height: u64) -> (Option<Proposal>, Vec<Vote>) {
        if height != self.current_height + 1 {
            return (None, Vec::new());
        }
        let mut votes = Vec::new();
        if let Some(round) = self.round.as_ref() {
            votes.extend(round.prevotes.all_votes());
            votes.extend(round.precommits.all_votes());
        }
        votes.extend(
            self.buffered_votes
                .iter()
                .filter(|v| v.height == height)
                .cloned(),
        );
        (self.pending_proposal_envelope(), votes)
    }

    /// Tendermint prevote gate. `valid_round` is the proposal's proof-of-lock round (already
    /// verified against the block by `validate_block` when `Some`). Prevote the value iff we
    /// hold no lock, our lock is already on this exact value, or the proposal proves a lock
    /// from a round at least as new as ours (the network has demonstrably moved on). Otherwise
    /// abstain — withholding the prevote is what makes a value conflicting with a 2/3 lock
    /// unable to ever reach quorum.
    fn should_prevote(&self, block_hash: &Hash, valid_round: Option<u32>) -> bool {
        match (self.locked_round, self.locked_block.as_ref()) {
            (None, _) => true,
            (Some(_), Some(locked)) if &locked.hash() == block_hash => true,
            (Some(locked_round), _) => valid_round.is_some_and(|vr| vr >= locked_round),
        }
    }

    /// Verify a proof-of-lock certificate: `pol` must be prevotes from distinct validators in
    /// the active set, every one for `block_hash` at (`height`, `valid_round`), with a
    /// verified signature, whose combined voting power reaches the quorum threshold. This is
    /// what lets any node safely accept a re-proposal's unlock claim without having itself
    /// witnessed round `valid_round` — the certificate proves the network genuinely reached a
    /// prevote-quorum on the value there.
    fn verify_pol(
        &self,
        pol: &[Vote],
        block_hash: &Hash,
        height: u64,
        valid_round: u32,
    ) -> ConsensusResult<()> {
        let mut counted: HashSet<String> = HashSet::new();
        let mut power: u64 = 0;
        for vote in pol {
            if vote.vote_type != VoteType::Prevote
                || vote.height != height
                || vote.round != valid_round
                || &vote.block_hash != block_hash
            {
                return Err(ConsensusError::InvalidVote {
                    reason: "proof-of-lock vote does not match the re-proposed value/round".into(),
                });
            }
            let validator = self
                .validator_set
                .get(&vote.validator)
                .ok_or_else(|| ConsensusError::UnknownValidator(vote.validator.clone()))?;
            vote.verify_signature()?;
            if counted.insert(vote.validator.to_string()) {
                power += validator.voting_power;
            }
        }
        let quorum = self.validator_set.quorum_threshold();
        if power < quorum {
            return Err(ConsensusError::InsufficientVotingPower { got: power, need: quorum });
        }
        Ok(())
    }

    /// Verify a block's `last_commit` — the precommit signatures it claims finalized its
    /// parent (`prev_hash`, at `height - 1`). Unlike `verify_pol`, this does NOT require the
    /// combined power to reach quorum: `last_commit` exists to feed downtime-jailing (see
    /// `CommitSig`'s doc comment), not to re-prove the parent's finality — that's already
    /// established by `prev_hash` chaining and this engine's own live quorum tracking of the
    /// round that actually committed it. What IS enforced: every signature must be genuine (a
    /// proposer can't invent "X signed" to shield X from a miss) and no validator can be
    /// double-counted. An address no longer in the *current* validator set is dropped rather
    /// than rejected outright — the parent height's actual set could differ slightly around an
    /// epoch rotation boundary, and a stale-but-genuine signature shouldn't fail the block.
    fn verify_last_commit(
        &self,
        last_commit: &[CommitSig],
        height: u64,
        parent_hash: &Hash,
    ) -> ConsensusResult<()> {
        if height == 0 {
            return Ok(()); // genesis has no parent to attest
        }
        let mut seen: HashSet<String> = HashSet::new();
        for sig in last_commit {
            sig.verify(height - 1, parent_hash)
                .map_err(|e| ConsensusError::InvalidBlock {
                    height,
                    reason: format!("invalid last_commit signature from {}: {e}", sig.validator),
                })?;
            if !seen.insert(sig.validator.to_string()) {
                return Err(ConsensusError::InvalidBlock {
                    height,
                    reason: format!("duplicate last_commit signature from {}", sig.validator),
                });
            }
        }
        Ok(())
    }

    /// Validate a block proposed by another validator (used when receiving from peers).
    ///
    /// `valid_round`/`pol` carry a re-proposal's proof-of-lock (see `Proposal`). For a fresh
    /// proposal both are `None`/empty and the proposer is checked against the current `round`.
    /// For a re-proposal the block is the one originally proposed in `valid_round` (its header
    /// still carries that round's proposer's signature), so the proposer is checked against
    /// `valid_round` instead — and the POL certificate is verified to prove the network really
    /// reached a prevote-quorum on this value there.
    pub fn validate_block(
        &self,
        block: &Block,
        round: u32,
        valid_round: Option<u32>,
        pol: &[Vote],
    ) -> ConsensusResult<()> {
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

        // A block larger than the network will carry is not a block anyone can act on. Voting for
        // one is voting for a round that cannot finish: gossipsub will not transmit it, so no peer
        // ever sees it and no quorum ever forms. See `Block::exceeds_size_limit` — the same rule
        // every other admission path applies, and it has to be the same one, because a size limit
        // half the network enforces is a fork.
        //
        // Ahead of the merkle root and the proposer signature deliberately. Both walk the whole
        // block; measuring it is the cheaper question, and there is no reason to hash and verify
        // megabytes that are going to be thrown away for their size regardless.
        if block.exceeds_size_limit() {
            return Err(ConsensusError::InvalidBlock {
                height: h,
                reason: format!(
                    "block carries {} transaction bytes, over the {}-byte limit",
                    block.transaction_bytes(),
                    helix_core::fee::MAX_BLOCK_BYTES
                ),
            });
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


        // EIP-1559: the base fee is not the proposer's to choose — it's deterministically
        // derived from the parent block (the node refreshes `current_base_fee_per_byte` after
        // every commit). Reject any header that doesn't carry exactly the expected value, so a
        // proposer can't lower it to cheapen its own spam or raise it to grief others. Same
        // value for a re-proposal, since the base fee is per-height, not per-round.
        if block.header.base_fee_per_byte != self.current_base_fee_per_byte {
            return Err(ConsensusError::InvalidBlock {
                height: h,
                reason: format!(
                    "base_fee_per_byte mismatch: expected {}, got {}",
                    self.current_base_fee_per_byte, block.header.base_fee_per_byte
                ),
            });
        }

        self.verify_last_commit(&block.header.last_commit, h, &block.header.prev_hash)?;

        self.validator_set
            .get(&block.header.validator)
            .ok_or_else(|| ConsensusError::UnknownValidator(block.header.validator.clone()))?;

        // Verify the proposer is correct — for a *fresh* proposal, which is the round
        // proposer's alone to make.
        //
        // A re-proposal deliberately is not checked this way, and the attempt to is what
        // stalled the live chain twice on 2026-09-01. `valid_round` is the round a prevote
        // quorum formed in, NOT the round the block was proposed in, and the two come apart
        // the moment a round reaches a prevote quorum but no precommit quorum — the ordinary
        // outcome of a single lost precommit. The value is then locked at a round whose
        // proposer never built it, every later round re-proposes it carrying that
        // `valid_round`, every peer measures the header's proposer against that round's
        // schedule, and no round can ever close again. Observed at heights 276420 and 280939:
        // the same rejection every few seconds, its round number frozen at the lock round
        // while the rounds themselves climbed, until every node was restarted.
        //
        // What legitimises a re-proposal is the POL verified below: prevotes from 2/3+ of the
        // set, for exactly this block, at exactly `valid_round`. A value that cannot be forged
        // without those signatures does not additionally need its header measured against a
        // proposer schedule — and that header's proposer was confirmed to be a set member
        // immediately above.
        if valid_round.is_none()
            && !self.validator_set.is_proposer(&block.header.validator, h, round)
        {
            return Err(ConsensusError::InvalidBlock {
                height: h,
                reason: format!(
                    "{} is not the proposer for height {} round {}",
                    block.header.validator, h, round
                ),
            });
        }

        // A lock can only come from a round already left behind. This is the bound the
        // proposer check used to supply for re-proposals: without it a replayed certificate
        // could name any round at all.
        if let Some(vr) = valid_round {
            if vr >= round {
                return Err(ConsensusError::InvalidBlock {
                    height: h,
                    reason: format!(
                        "re-proposal for round {round} claims a proof-of-lock from round {vr} \
                         — a lock can only come from a round already past"
                    ),
                });
            }
        }

        // A re-proposal must carry a valid proof-of-lock: a prevote-quorum for exactly this
        // value at `valid_round`. This is what lets a locked peer safely unlock and prevote it
        // without having itself witnessed that round.
        if let Some(vr) = valid_round {
            self.verify_pol(pol, &block.hash(), h, vr)?;
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

    /// Install the validator set a synced node computed from chain state, at an explicit
    /// `epoch`, *without* the per-boundary `+1` bump [`rotate_validator_set`] applies.
    ///
    /// The catch-up paths (`sync_blocks_from_peer`, reached from the P2P gap-fill and the
    /// periodic `rpc_sync_loop`) apply finalized blocks — so `execute_block` rotates
    /// `active_validators` in chain state — but never travel the finalize path that calls
    /// `rotate_validator_set`. A validator that crosses its *own* activation rotation while
    /// catching up would otherwise keep the stale set it built at startup: it never finds
    /// itself in the set, so `assert_is_validator` fails and it neither proposes nor votes,
    /// silently stalling a small chain that now counts it toward quorum. That is the live-sync
    /// half of the join-stall bug — the startup rebuild only closed the restart case, leaving a
    /// node that activates *while already running and catching up* still stuck.
    ///
    /// `epoch` is supplied by the caller (`height / EPOCH_LENGTH`, the same expression the
    /// startup engine build uses) because the engine holds no block height of its own. The set
    /// is rebuilt through `ValidatorSet::new`, so the 1% voting-power cap and the address-sorted
    /// proposer order come out byte-for-byte identical to a node that rotated live — the whole
    /// point, since a divergent proposer order silently halts multi-validator consensus.
    ///
    /// Returns whether the active membership actually changed, so the caller can log an
    /// operator-facing line only when something moved. A no-op on an empty candidate list, for
    /// the same reason as `rotate_validator_set`: dropping to zero validators would halt block
    /// production, so the previous set is kept.
    pub fn set_validator_set(&mut self, validators: Vec<Validator>, epoch: u64) -> bool {
        if validators.is_empty() {
            return false;
        }
        let before: HashSet<Address> =
            self.validator_set.validators.iter().map(|v| v.address.clone()).collect();
        let after: HashSet<Address> = validators.iter().map(|v| v.address.clone()).collect();
        let changed = before != after;
        self.validator_set = ValidatorSet::new(validators, epoch);
        changed
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Update `missed_rounds` from a round that just timed out (via `advance_round`) without
    /// reaching quorum, and name whoever has been silent long enough to be the reason. Every
    /// other validator in `self.validator_set` who cast neither a prevote nor a precommit this
    /// node saw in `stalled` gets its counter bumped; anyone who voted — even nil — is reset.
    /// A single missed round proves nothing (gossip delay, a node mid-restart); only sustained
    /// silence does.
    ///
    /// **Silence is reported, never acted on. This is the whole point.** Until 2026-07-22 a
    /// validator silent for 20 rounds had its voting power locally zeroed
    /// (`liveness_adjusted_validator_set`), which lowered *this node's* quorum threshold until
    /// its own vote sufficed, so the chain kept producing blocks through an outage. The
    /// argument for it was that removing power can only make a hash cross a threshold sooner,
    /// never make two hashes cross one in the same round. That is true within one node and
    /// irrelevant across two, which is where forks live.
    ///
    /// The mechanism was unsound by construction, not merely mistuned. Write `T` for the set's
    /// total voting power, `Q = 2T/3+1`, and `A` for the power actually available to vote. If
    /// `A >= Q` the round reaches quorum against the *full* set and the exclusion changes
    /// nothing. So the exclusion is only ever load-bearing when `A < Q` — precisely when this
    /// node finalizes a block backed by less than two thirds of the real staked power. Two
    /// disjoint groups can each do that at the same height, and they did: on 2026-07-22 both
    /// live validators had locally excluded each other and each finalized its own height 66918
    /// (`ca38cd4b…` against `f18b2d4d…`). There is no threshold that keeps the mechanism useful
    /// and safe, because "useful" *is* "committed below quorum".
    ///
    /// What replaces it is nothing, deliberately: a set that has lost more than a third of its
    /// power halts, which is what `3f+1` means and what every BFT chain does. A halt is visible
    /// and recoverable; a fork silently duplicates history and every balance in it. The cost
    /// falls on 2-of-2, which tolerates zero absences by arithmetic — the answer to that is a
    /// fourth validator, not a lower bar.
    fn record_round_liveness(&mut self, stalled: &RoundState) {
        // (see `LivenessVerdict` for how the three outcomes are told apart)
        // Only validators that can actually hold a round up. A probationer carries
        // `voting_power = 0` and is excluded from `full_members()`, so it takes no proposer turn
        // and contributes nothing toward quorum — its silence cannot stall anything. Reporting it
        // as the reason sends the operator after the wrong node, which is not hypothetical: the
        // live chain named `hlxSpsWWU…` in this line for days, at `voting_power=0`, while the vote
        // actually missing went unnamed. Same failure as #171, one layer down.
        let members: Vec<(Address, u64)> = self
            .validator_set
            .full_members()
            .filter(|v| v.address != self.address && v.voting_power > 0)
            .map(|v| (v.address.clone(), v.voting_power))
            .collect();

        // Drop counters for anyone no longer counted here (rotated out, or still probationary):
        // `silent_peer_validators` reads this map, and an entry nobody can ever reset again would
        // report a permanently silent validator that consensus is not even waiting for.
        let counted: HashSet<Address> = members.iter().map(|(a, _)| a.clone()).collect();
        self.missed_rounds.retain(|a, _| counted.contains(a));

        // Which phase failed decides who is worth naming. A precommit is only cast once prevote
        // quorum is reached (`lock_and_precommit`), so in a round that never got that far every
        // validator is missing one and naming them would name the whole set.
        let reached_prevote_quorum = stalled.prevotes.quorum_hash().is_some();

        // Collected for the attendance line below, from the same three facts the verdict uses —
        // one pass, not a second walk over the round.
        let mut participants: Vec<(Address, u64, bool)> = Vec::with_capacity(members.len());

        for (address, voting_power) in members {
            let prevoted = stalled.prevotes.has_voted(&address);
            let precommitted = stalled.precommits.has_voted(&address);
            participants.push((address.clone(), voting_power, prevoted || precommitted));

            match liveness_verdict(prevoted, precommitted, reached_prevote_quorum) {
            LivenessVerdict::Heard { missing_precommit } => {
                self.missed_rounds.remove(&address);
                // Heard from — but not with the vote this round was waiting on. This case was
                // invisible: a prevote alone counted as proof of life, so the validator whose
                // precommits never arrive, the one holding up a round that *did* reach prevote
                // quorum, was filed as healthy and never named at all.
                if missing_precommit {
                    tracing::warn!(
                        validator = %address,
                        voting_power,
                        quorum_threshold = self.validator_set.quorum_threshold(),
                        "Prevoted, but its precommit never arrived here — this round had prevote quorum and stalled one phase later"
                    );
                }
                continue;
            }
            LivenessVerdict::Silent => {}
            }

            let missed = self.missed_rounds.entry(address.clone()).or_insert(0);
            *missed += 1;
            if *missed >= LIVENESS_SILENCE_WARN_ROUNDS {
                // The one line an operator of a stalled chain needs. Every round, because a
                // stalled chain logs nothing else and "how long already" is half the diagnosis.
                tracing::warn!(
                    validator = %address,
                    missed_rounds = *missed,
                    voting_power,
                    quorum_threshold = self.validator_set.quorum_threshold(),
                    total_voting_power = self.validator_set.total_voting_power(),
                    "Validator silent — consensus cannot reach quorum without its votes"
                );
            }
        }

        // The line that was missing on 2026-09-04, when "who voted in this round" had to be
        // inferred from counters and was inferred wrongly, twice.
        //
        // Only on a *change* of the silent set, and that is the whole design: a stalled chain
        // repeats its situation every round, so reporting it every round teaches an operator to
        // skim past exactly the lines that matter. Every transition gets one line and every steady
        // stretch gets none, which is also what makes it affordable at `info!` — the level a
        // diagnosis after the fact can actually rely on, since `debug!` has to have been switched
        // on before the incident nobody knew was coming (#190).
        let own_voted = stalled.prevotes.has_voted(&self.address)
            || stalled.precommits.has_voted(&self.address);
        let own_power = if own_voted {
            self.validator_set.get(&self.address).map(|v| v.voting_power).unwrap_or(0)
        } else {
            0
        };
        let attendance = round_attendance(
            &participants,
            own_power,
            self.validator_set.quorum_threshold(),
            reached_prevote_quorum,
        );
        if attendance.silent != self.last_reported_silent {
            self.last_reported_silent = attendance.silent.clone();
            let names = |v: &[Address]| {
                if v.is_empty() {
                    "none".to_string()
                } else {
                    v.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
                }
            };
            tracing::info!(
                height = self.current_height + 1,
                heard = %names(&attendance.heard),
                silent = %names(&attendance.silent),
                power_heard = attendance.power_heard,
                quorum = attendance.quorum,
                enough_power_heard = attendance.enough_power_heard(),
                reached_prevote_quorum,
                own_vote_counted = own_voted,
                "Who this round was heard from changed. `enough_power_heard=false` means the round \
                 could not have closed and the named validators are why; `true` means the power was \
                 present and it failed anyway, which is a different problem entirely."
            );
        }
    }

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

        let last_commit = self
            .last_commit
            .iter()
            .map(|vote| helix_core::CommitSig {
                validator: vote.validator.clone(),
                public_key: vote.public_key.clone(),
                crypto_version: vote.crypto_version,
                round: vote.round,
                signature: vote.signature.clone(),
            })
            .collect();

        let mut header = BlockHeader {
            version: 1,
            height,
            timestamp,
            prev_hash,
            merkle_root: merkle,
            validator: self.address.clone(),
            public_key: keypair.public.clone(),
            crypto_version: keypair.scheme,
            // The proposer stamps its own build here, then signs the header over it (#128). The
            // workspace shares one version, so this crate's `CARGO_PKG_VERSION` is the running
            // node's version.
            node_version: env!("CARGO_PKG_VERSION").to_string(),
            base_fee_per_byte: self.current_base_fee_per_byte,
            last_commit,
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
        self.last_commit = round.precommits.quorum_votes();
        self.pending_evidence.extend(round.evidence);
        self.round = None;
        self.round_ticks = 0;
        // Buffered votes were for the height we just finalized — now stale.
        self.buffered_votes.clear();
        // Locks are per-height: the value for this height is committed, so release the lock
        // before the next height's rounds begin.
        self.clear_locks();
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
    pub fn sync_to_externally_finalized_block(
        &mut self,
        height: u64,
        block_hash: Hash,
        certificate: Vec<Vote>,
    ) {
        if height <= self.current_height {
            return;
        }
        // Keep the precommits this node already collected for exactly this block, instead of
        // discarding them along with the round.
        //
        // The round being torn down here is usually not an empty one: in a live multi-validator
        // network this node was voting on the very block that just arrived finished, and it holds
        // real, signature-verified precommits for it — it simply lost the race to finalize
        // locally. Dropping them means the next block it proposes carries an empty `last_commit`,
        // and that certificate is the only record of who participated. Measured on the live chain
        // 2026-07-22, after two validators were finally both producing: **14 of 20 consecutive
        // blocks carried an empty certificate**, i.e. participation went unrecorded for 70 % of
        // the chain.
        //
        // Only votes for `block_hash` itself are kept, so the certificate still attests exactly
        // the block it is attached to — a vote for any other hash would produce a `last_commit`
        // that every receiving node's `verify_last_commit` would (correctly) reject.
        let salvaged = self
            .round
            .as_ref()
            .filter(|round| round.height == height)
            .map(|round| round.precommits.votes_for(&block_hash))
            .unwrap_or_default();

        // The other half of the gap (#114): a node that never saw the votes at all — a pure
        // committed-blocks/RPC follower, or a validator that fell behind and caught up over the
        // fast path — has nothing to salvage. It now receives the finalizer's own certificate
        // alongside the block and adopts it, so its next proposed block carries a real
        // `last_commit` rather than an empty one. `certificate` arrives over the wire from an
        // untrusted peer, so it is verified here exactly as `verify_last_commit` checks a
        // certificate embedded in a received block — every signature genuine for this
        // `(height, block_hash)`, no validator counted twice — and anything failing is dropped.
        // Membership against the current validator set is deliberately not checked (same accepted
        // approximation as `verify_last_commit`: the parent height's set can differ slightly around
        // a rotation, and a stale-but-genuine signature must not be discarded).
        //
        // **The two are merged, not ranked.** Preferring the salvage whenever it exists — which is
        // what this did until 2026-08-27 — throws away a full quorum certificate in favour of this
        // node's own single precommit, because that is exactly the situation: the node cast its
        // precommit, lost the race to finalize, and the block arrived carrying the winner's
        // complete certificate. Measured on the live chain: **20 % of all blocks** (203 of a
        // 1000-block sample, every one of them proposed by the node that habitually loses that
        // race) carried a `last_commit` with a single signature where a quorum of two existed. Two
        // things then break downstream — an RPC-syncing node cannot prove those blocks final and
        // stops dead (see `sync_blocks_from_peer`), and #132's probation gate loses the very
        // evidence it promotes on.
        //
        // Merging is strictly better than either half alone and cannot be worse than the old
        // behaviour: every salvaged vote is still there, in front, so the participating path keeps
        // its own first-hand view; the peer's votes are appended only for validators the salvage
        // does not already name, and only after `verified_commit_certificate` has checked each
        // signature for this exact `(height, block_hash)`.
        let mut commit = salvaged;
        for vote in self.verified_commit_certificate(certificate, height, &block_hash) {
            if !commit.iter().any(|held| held.validator == vote.validator) {
                commit.push(vote);
            }
        }

        self.current_height = height;
        self.last_committed = Some(block_hash);
        self.last_committed_round = None;
        self.round = None;
        self.round_ticks = 0;
        self.buffered_votes.clear();
        self.last_commit = commit;
        self.clear_locks();
    }

    /// Cast this node's own precommit for the block it just adopted over the committed-block fast
    /// path, so that the network has a record that this node was live and agreed with it.
    ///
    /// **This does not, on its own, resurrect #132's probation gate** — measured, see
    /// `ChainState::rotate_active_validators`. The proposer can only fold a late precommit while it
    /// is still on that height, so the delivery window is one block interval, and a peer under load
    /// runs behind it. What this does buy is real and unconditional: certificates that name
    /// everyone who stood behind a block rather than only whoever happened to be needed, and a
    /// downtime counter that stops charging misses against nodes that are demonstrably keeping up.
    ///
    /// The problem it addresses (backlog #141): a node that adopts a finished block never voted on it,
    /// and on a busy chain that is the *normal* case, not an edge case. Measured on a three-node
    /// devnet: the two joiners adopted 186 and 190 blocks over the fast path and finalized only 12
    /// and 14 through proposal/vote. The finished block and the proposal are gossiped on separate
    /// topics microseconds apart, and whenever the block wins the race the peer is already at that
    /// height, so `receive_proposal` discards the proposal unread and no vote is ever cast. A
    /// validator can therefore run perfectly and appear in no `last_commit` at all — which is why
    /// #132's probation gate could never be satisfied, and why the downtime counter charges misses
    /// against nodes that are demonstrably keeping up.
    ///
    /// The vote is genuine, not a formality: it is cast only after the caller has verified the
    /// block (in-set proposer, chains from our tip, quorum certificate) and adopted it. Committing
    /// to a value this node has already accepted as final states nothing it does not believe.
    ///
    /// **The round comes from the adopted certificate, never invented.** Signing round 0 by default
    /// would mean signing a second, different value for a round this node may already have voted
    /// in — equivocation, and equivocation is what gets a validator slashed. Taking the round from
    /// the certificate that carried the block makes this precommit agree with the one the network
    /// already accepted, so a genuine conflict is a genuine double-sign and the node's signing
    /// guard (which sees this vote like any other, via `take_outbound_votes`) correctly withholds
    /// it. With no certificate there is no round to agree with, and nothing is cast.
    ///
    /// Deliberately not added to this node's own `last_commit`: a vote the signing guard refuses
    /// must not reach the wire, and `last_commit` is stamped into the next block this node
    /// proposes — which is the wire.
    pub fn attest_adopted_block(&mut self, keypair: &KeyPair) {
        let Some(block_hash) = self.last_committed else {
            return;
        };
        if self.validator_set.get(&self.address).is_none() {
            return;
        }
        // Already in the certificate — this node voted the block through itself (the salvage path
        // in `sync_to_externally_finalized_block`), so there is nothing to add.
        if self.last_commit.iter().any(|v| v.validator == self.address) {
            return;
        }
        let Some(round) = self.last_commit.first().map(|v| v.round) else {
            return;
        };
        if let Ok(vote) = cast_vote(
            &self.address,
            keypair,
            VoteType::Precommit,
            self.current_height,
            round,
            block_hash,
        ) {
            debug!(
                height = self.current_height,
                round, "Attesting a block adopted over the fast path"
            );
            self.outbound_votes.push(vote);
        }
    }

    /// Filter a commit certificate received over the wire down to the precommit votes that are
    /// genuinely usable as a `last_commit` for `(height, block_hash)`: a precommit (not a prevote)
    /// for exactly this block, with a signature that verifies, and no validator appearing twice.
    /// Mirrors `verify_last_commit`'s checks — this is the same trust decision, just applied to a
    /// gossiped certificate before it becomes this node's own rather than to one already embedded
    /// in a validated block.
    fn verified_commit_certificate(
        &self,
        certificate: Vec<Vote>,
        height: u64,
        block_hash: &Hash,
    ) -> Vec<Vote> {
        let mut seen: HashSet<Address> = HashSet::new();
        certificate
            .into_iter()
            .filter(|vote| {
                vote.vote_type == VoteType::Precommit
                    && vote.height == height
                    && &vote.block_hash == block_hash
                    && vote.verify_signature().is_ok()
                    && seen.insert(vote.validator.clone())
            })
            .collect()
    }

    /// Release the per-height Tendermint lock and reset the round counter. Called whenever the
    /// height advances (either through our own `finalize` or an externally finalized block) —
    /// the value for the old height is settled, so nothing carries over to constrain the next
    /// height's prevotes, and the next height starts fresh at round 0.
    fn clear_locks(&mut self) {
        self.locked_round = None;
        self.locked_block = None;
        self.locked_pol.clear();
        self.pending_round = 0;
    }

    /// Seed `last_committed` with the real chain tip's hash right after construction,
    /// when resuming an existing chain (as opposed to a fresh test engine that starts
    /// at height 0 with no prior block). Without this, `validate_block`'s prev_hash
    /// check would silently skip validation for every proposal until this engine's
    /// own first `finalize()` — the exact restart window where a stale/diverged
    /// proposal is most likely to slip through unnoticed.
    /// Resume at `round` for the pending height after a restart, instead of starting over at 0.
    ///
    /// A round number lives only in memory, so a restarting validator rejoins wherever the network
    /// happens to be — which can be *below* where this node had already climbed. Its double-sign
    /// guard then correctly refuses every vote at a round it has already signed, and the node is
    /// mute until the network works its way back up. Measured on production 2026-08-05: a validator
    /// that had reached round 10 restarted into round 7 and withheld its votes for three and a half
    /// minutes at roughly thirty seconds a round, with the chain stopped the whole time because a
    /// two-validator set needs both. The longer the stall before the restart, the longer the
    /// silence after it — and the health log was recommending exactly that restart.
    ///
    /// Resuming *above* the guard's mark is the safe direction, and it is not merely safe but
    /// actively useful: `receive_proposal` adopts a higher round from a peer, so this node pulls
    /// the others up to it rather than waiting for them to time out to where it already is.
    ///
    /// No-op unless `height` is the pending height and `round` is genuinely ahead — this must never
    /// be able to drag a healthy engine backwards.
    pub fn resume_at_round(&mut self, height: u64, round: u32) {
        if height != self.current_height + 1 || round <= self.pending_round {
            return;
        }
        self.pending_round = round;
    }

    /// The round this engine would next act at for the pending height. Exposed so the node can
    /// report it and so tests can pin the resume behaviour.
    pub fn pending_round(&self) -> u32 {
        self.pending_round
    }

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

/// Shared "prevote quorum reached" handling, applied everywhere a round can cross into
/// `Precommit` phase. Two effects, both idempotent:
///  1. Capture the lock — record the value behind the prevote quorum and the prevote
///     certificate (`quorum_votes`) so a later round re-proposes it and this node refuses
///     conflicting values (see `BftEngine::locked_round`). The lock only advances forward
///     (never to an older round).
///  2. Cast this node's own precommit for the agreed value, unless it already has.
///
/// A free function taking the engine's fields by disjoint `&mut` so it can run while `round`
/// (borrowed from `self.round`) is live — the same reason `cast_vote` is free-standing.
#[allow(clippy::too_many_arguments)]
fn lock_and_precommit(
    address: &Address,
    keypair: &KeyPair,
    round: &mut RoundState,
    outbound: &mut Vec<Vote>,
    locked_round: &mut Option<u32>,
    locked_block: &mut Option<Block>,
    locked_pol: &mut Vec<Vote>,
) {
    if round.phase != RoundPhase::Precommit {
        return;
    }
    let Some(hash) = round.prevotes.quorum_hash() else {
        return;
    };
    // A prevote quorum on *nil* means the network agreed there is nothing to commit here — it
    // is the signal to abandon the round (`should_advance_round`), never to precommit. Casting
    // a precommit for `NIL_BLOCK_HASH` would let precommits reach quorum on nil, drive the
    // round to `Commit(NIL)`, and finalize a height with no block behind it.
    if hash == NIL_BLOCK_HASH {
        return;
    }
    // Never precommit a value we don't hold. A round opened for a nil prevote carries no
    // proposal, yet still tallies peers' prevotes — so peers who *did* receive the proposal can
    // carry it to a prevote quorum here. Precommitting off the back of that would mean pledging
    // to a block this node has never seen, let alone validated. (In a round we joined via
    // `receive_proposal` the proposal is always present and matches, so this changes nothing
    // about the common path.)
    if !round.proposal.as_ref().is_some_and(|b| b.hash() == hash) {
        return;
    }
    // Lock on the value behind the prevote quorum (only ever advancing the lock forward).
    if locked_round.is_none_or(|lr| round.round >= lr) {
        if let Some(block) = round.proposal.as_ref().filter(|b| b.hash() == hash) {
            *locked_round = Some(round.round);
            *locked_block = Some(block.clone());
            *locked_pol = round.prevotes.quorum_votes();
        }
    }
    // Cast our own precommit for the agreed value if we haven't already.
    if !round.precommits.has_voted(address) {
        if let Ok(precommit) =
            cast_vote(address, keypair, VoteType::Precommit, round.height, round.round, hash)
        {
            outbound.push(precommit.clone());
            let _ = round.add_precommit(precommit);
        }
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

    /// Backlog #143: a proposer that is *behind* proposes on a `prev_hash` nobody else has. Every
    /// peer rejects the block as invalid — and then the height must still advance, by timing the
    /// round out and moving to the next proposer, exactly as it does for a proposer that says
    /// nothing at all.
    ///
    /// This is not a hypothetical: it stalled a three-node devnet twice on 2026-07-30, dead, for
    /// over ten minutes. The condition — "your turn arrives while you are still catching up" — is
    /// the normal state of a node after a restart or a network blip, so it is not specific to the
    /// misconfigured validator that happened to surface it.
    ///
    /// Engine-level first, to place the fault: if this passes, the round machinery recovers and the
    /// stall lives in the node's block-production loop instead.
    #[test]
    fn an_invalid_proposal_does_not_prevent_the_round_from_advancing() {
        let v = four_validators();

        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 1);
        // Give this node a committed tip, so it has something for the stale block to disagree with.
        let our_tip = Hash::digest(b"the real tip");
        engine.sync_to_externally_finalized_block(5, our_tip, vec![]);
        let height = engine.current_height() + 1;

        // b is the legitimate round-0 proposer for height 6 ((6 + 0) % 4 == 2, b's index) — the
        // rejection below must come from the prev_hash, not from proposing out of turn.
        let b_addr = Address::from_public_key(&v.b_kp.public);
        assert!(v.validator_set.is_proposer(&b_addr, height, 0));

        // It is on the right height, but building on a tip that is not ours: the state of any
        // node whose turn arrives while it is still catching up.
        let mut stale = BftEngine::new(v.validator_set.clone(), b_addr, height - 1);
        let _ = stale.produce_block(&v.b_kp, Hash::digest(b"a tip nobody else has"), vec![]);
        let bad_block = stale.pending_proposal().unwrap().clone();

        // Rejected — the block does not chain from our tip.
        let rejected = engine.receive_proposal(&v.self_kp, Proposal::fresh(0, bad_block));
        assert!(rejected.is_err(), "precondition: the stale proposal must be refused");

        // Now run the round clock out, exactly as `block_production_loop` does.
        let mut timed_out = false;
        for _ in 0..ROUND_TIMEOUT_TICKS {
            if engine.note_round_tick(&v.self_kp) {
                timed_out = true;
                break;
            }
        }
        assert!(
            timed_out,
            "the round must time out after a rejected proposal — otherwise nothing ever moves the \
             height on, which is the stall this pins"
        );

        // And advancing must reach a round this node can actually propose in, so the height
        // continues rather than waiting forever on a proposer that cannot produce a valid block.
        let mut advanced_to = None;
        for _ in 0..v.validator_set.len() {
            match engine.advance_round(&v.self_kp, our_tip, vec![]) {
                Ok(block) => {
                    advanced_to = Some(block.height());
                    break;
                }
                Err(ConsensusError::AwaitingVotes { .. }) => {
                    advanced_to = Some(height);
                    break;
                }
                // Someone else's turn in that round — keep advancing, as the loop does.
                Err(ConsensusError::NotProposer { .. }) => continue,
                Err(e) => panic!("advancing after a rejected proposal must not error: {e}"),
            }
        }
        assert_eq!(
            advanced_to,
            Some(height),
            "after a rejected proposal the height must still be reachable through a later round"
        );
    }

    fn peer_vote(kp: &KeyPair, vote_type: VoteType, height: u64, round: u32, hash: Hash) -> Vote {
        let addr = Address::from_public_key(&kp.public);
        cast_vote(&addr, kp, vote_type, height, round, hash).unwrap()
    }

    /// Sets up one full-power validator that finalizes alone, plus a zero-power #132 probationer.
    fn full_power_plus_probationer() -> (KeyPair, Address, KeyPair, Address, ValidatorSet) {
        let full_kp = KeyPair::generate();
        let full_addr = Address::from_public_key(&full_kp.public);
        let probationer_kp = KeyPair::generate();
        let probationer_addr = Address::from_public_key(&probationer_kp.public);
        let set = ValidatorSet::new(
            vec![
                Validator::new(full_addr.clone(), 100_000, true),
                Validator::new_probationary(probationer_addr.clone(), 100_000, true),
            ],
            0,
        );
        (full_kp, full_addr, probationer_kp, probationer_addr, set)
    }

    /// Height these tests produce at. Not 1: heights whose position in the epoch falls in
    /// [`PROBATION_PROOF_SLOTS`] belong to the probationer, so the full member could not propose
    /// there at all — and every test here needs it to. Height 1 is such a slot, which is exactly
    /// the schedule working; it just makes it the wrong height to test *other* things at.
    const OFF_SLOT_PARENT: u64 = 4;

    /// The full member's engine, advanced to a height where the next block is its turn.
    fn engine_at_off_slot(set: ValidatorSet, address: Address) -> BftEngine {
        let mut engine = BftEngine::new(set, address, 0);
        engine.sync_to_externally_finalized_block(
            OFF_SLOT_PARENT,
            Hash::digest(b"parent"),
            vec![],
        );
        engine
    }

    /// #132's activation was unreachable whenever the existing set already held quorum without the
    /// probationer — which is *always*, because a probationer carries zero voting power by design.
    ///
    /// Promotion out of probation requires the probationer's signature to appear in a committed
    /// `last_commit` (`ChainState::record_probation_liveness`). But `finalize` sets `last_commit`
    /// from the precommits the round held at the instant it committed, and a round commits the
    /// moment quorum is reached. A zero-power vote can never be the one that tips a quorum, so it
    /// is never required and never waited for. With a single full-power validator the window is
    /// exactly zero: it finalizes inside `produce_block`, before any peer vote can be delivered.
    /// The probationer cycled probation → pending → probation forever, so no new validator could
    /// activate at all. Measured against a real devnet, which sat at height 500+ with two staked,
    /// correctly-running joiners still inactive.
    ///
    /// The fix collects a late precommit for the block just committed into the certificate, which
    /// block h+1 stamps a full block interval later.
    #[test]
    fn a_late_precommit_for_the_committed_block_joins_the_certificate() {
        let (full_kp, full_addr, probationer_kp, probationer_addr, set) =
            full_power_plus_probationer();
        assert_eq!(
            set.get(&probationer_addr).unwrap().voting_power,
            0,
            "a probationer holds no voting power — the premise of the whole failure"
        );

        let mut engine = engine_at_off_slot(set, full_addr.clone());
        let block = engine
            .produce_block(&full_kp, Hash::digest(b"parent"), vec![])
            .expect("the sole full-power validator reaches quorum on its own precommit");
        assert_eq!(
            engine.current_height(),
            OFF_SLOT_PARENT + 1,
            "it finalized without any peer vote"
        );
        assert!(
            !engine
                .commit_certificate()
                .iter()
                .any(|v| v.validator == probationer_addr),
            "precondition: the probationer cannot have been in the certificate at commit time"
        );

        // Its precommit arrives now — as early as a real network ever could deliver it.
        let late = peer_vote(&probationer_kp, VoteType::Precommit, OFF_SLOT_PARENT + 1, 0, block.hash());
        engine.add_vote(&full_kp, late).expect("a late precommit is not an error");

        assert!(
            engine
                .commit_certificate()
                .iter()
                .any(|v| v.validator == probationer_addr),
            "the probationer's signature must now be in the certificate — without it `probation_seen` \
             never records it and it can never be promoted"
        );
    }

    /// A node that adopts a finished block over the fast path casts its own precommit for it —
    /// the liveness signal #141 needs, and the one a probationer can actually produce (it never
    /// wins a race it holds no voting power in).
    #[test]
    fn adopting_a_block_over_the_fast_path_produces_an_attesting_precommit() {
        let (full_kp, full_addr, probationer_kp, probationer_addr, set) =
            full_power_plus_probationer();
        let block_hash = Hash::digest(b"externally finalized");

        // The certificate the finalizer gossips alongside the block, cast in round 3 — the round
        // this node must agree with rather than inventing one.
        let finalizers_precommit = cast_vote(
            &full_addr,
            &full_kp,
            VoteType::Precommit,
            1,
            3,
            block_hash,
        )
        .unwrap();

        let mut engine = BftEngine::new(set, probationer_addr.clone(), 0);
        engine.sync_to_externally_finalized_block(1, block_hash, vec![finalizers_precommit]);
        assert!(
            engine.take_outbound_votes().is_empty(),
            "precondition: adopting the block alone casts nothing"
        );

        engine.attest_adopted_block(&probationer_kp);

        let outbound = engine.take_outbound_votes();
        assert_eq!(outbound.len(), 1, "exactly one attestation");
        let vote = &outbound[0];
        assert_eq!(vote.validator, probationer_addr);
        assert_eq!(vote.vote_type, VoteType::Precommit);
        assert_eq!(vote.height, 1);
        assert_eq!(vote.block_hash, block_hash);
        assert_eq!(
            vote.round, 3,
            "the round must come from the adopted certificate — inventing round 0 would sign a \
             second value for a round this node may already have voted in, i.e. equivocate"
        );
        assert!(vote.verify_signature().is_ok(), "and it must be a genuine signature");
    }

    /// Nothing is cast when there is no certificate to agree with: with no round the vote could
    /// only be invented, which is the equivocation risk this must not take.
    #[test]
    fn a_block_adopted_without_a_certificate_is_not_attested() {
        let (_full_kp, _full_addr, probationer_kp, probationer_addr, set) =
            full_power_plus_probationer();
        let mut engine = BftEngine::new(set, probationer_addr, 0);
        engine.sync_to_externally_finalized_block(1, Hash::digest(b"no certificate"), vec![]);

        engine.attest_adopted_block(&probationer_kp);

        assert!(
            engine.take_outbound_votes().is_empty(),
            "no certificate means no round to agree with, so nothing may be signed"
        );
    }

    /// A node that voted the block through itself is already in the certificate — attesting again
    /// would duplicate its own signature in any tally computed over `last_commit`.
    #[test]
    fn a_node_already_in_the_certificate_does_not_attest_again() {
        let (full_kp, full_addr, _p_kp, _p_addr, set) = full_power_plus_probationer();
        let mut engine = engine_at_off_slot(set, full_addr.clone());
        let block = engine
            .produce_block(&full_kp, Hash::digest(b"parent"), vec![])
            .expect("finalizes alone");
        assert!(
            engine.commit_certificate().iter().any(|v| v.validator == full_addr),
            "precondition: this node's own precommit carried the block"
        );
        let _ = engine.take_outbound_votes();

        engine.attest_adopted_block(&full_kp);

        assert!(
            engine.take_outbound_votes().is_empty(),
            "already attested by having voted — no second signature for {}",
            block.height()
        );
    }

    /// The property that must survive the fix: folding in late precommits must not turn into
    /// crediting presence that nobody proved. A phantom — staked, in the set, no node running —
    /// sends nothing, so it stays absent from the certificate.
    ///
    /// That absence does not currently keep it out of the validator set (promotion is
    /// unconditional, backlog #141), but it is the signal a fix for #141 has to build on, and it is
    /// what `missed_blocks` scores it on either way.
    #[test]
    fn a_phantom_probationer_that_never_votes_stays_out_of_the_certificate() {
        let (full_kp, full_addr, _phantom_kp, phantom_addr, set) = full_power_plus_probationer();
        let mut engine = engine_at_off_slot(set, full_addr);
        engine
            .produce_block(&full_kp, Hash::digest(b"parent"), vec![])
            .expect("finalizes alone");

        assert!(
            !engine.commit_certificate().iter().any(|v| v.validator == phantom_addr),
            "a probationer whose node never signs must never appear in a certificate"
        );
    }

    /// A late precommit for some *other* block must not be folded in. Otherwise a validator could
    /// have its signature over one value recorded as backing a different one.
    #[test]
    fn a_late_precommit_for_a_different_block_is_not_folded_in() {
        let (full_kp, full_addr, probationer_kp, probationer_addr, set) =
            full_power_plus_probationer();
        let mut engine = engine_at_off_slot(set, full_addr);
        engine
            .produce_block(&full_kp, Hash::digest(b"parent"), vec![])
            .expect("finalizes alone");

        let wrong = peer_vote(
            &probationer_kp,
            VoteType::Precommit,
            1,
            0,
            Hash::digest(b"some other block"),
        );
        let _ = engine.add_vote(&full_kp, wrong);

        assert!(
            !engine.commit_certificate().iter().any(|v| v.validator == probationer_addr),
            "a precommit for another block is not evidence about this one"
        );
    }

    /// A validator outside the set cannot inject itself into the certificate by voting late.
    #[test]
    fn a_late_precommit_from_outside_the_set_is_not_folded_in() {
        let (full_kp, full_addr, _p_kp, _p_addr, set) = full_power_plus_probationer();
        let mut engine = engine_at_off_slot(set, full_addr);
        let block = engine
            .produce_block(&full_kp, Hash::digest(b"parent"), vec![])
            .expect("finalizes alone");

        let outsider_kp = KeyPair::generate();
        let outsider_addr = Address::from_public_key(&outsider_kp.public);
        let vote = peer_vote(&outsider_kp, VoteType::Precommit, 1, 0, block.hash());
        let _ = engine.add_vote(&full_kp, vote);

        assert!(
            !engine.commit_certificate().iter().any(|v| v.validator == outsider_addr),
            "an out-of-set signer must never reach the certificate"
        );
    }

    /// The same signer arriving twice must be counted once — a duplicated entry would inflate any
    /// power tally computed over the certificate (`precommits_reach_quorum`).
    #[test]
    fn a_late_precommit_is_not_folded_in_twice() {
        let (full_kp, full_addr, probationer_kp, probationer_addr, set) =
            full_power_plus_probationer();
        let mut engine = engine_at_off_slot(set, full_addr);
        let block = engine
            .produce_block(&full_kp, Hash::digest(b"parent"), vec![])
            .expect("finalizes alone");

        let vote = peer_vote(&probationer_kp, VoteType::Precommit, OFF_SLOT_PARENT + 1, 0, block.hash());
        let _ = engine.add_vote(&full_kp, vote.clone());
        let _ = engine.add_vote(&full_kp, vote);

        let count = engine
            .commit_certificate()
            .iter()
            .filter(|v| v.validator == probationer_addr)
            .count();
        assert_eq!(count, 1, "a duplicate must not be appended a second time");
    }

    /// The point of #78: a validator waiting on a dead proposer prevotes nil after the short
    /// `PROPOSAL_TIMEOUT_TICKS`, not the long `ROUND_TIMEOUT_TICKS`. Discriminates against the
    /// old behavior, where nothing at all was cast until the round timed out.
    #[test]
    fn a_missing_proposal_draws_a_nil_prevote_after_the_short_proposal_timeout() {
        let v = four_validators();
        // Height 2, round 0's proposer is b ((2 + 0) % 4 == 2) — self just waits.
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);

        for _ in 0..PROPOSAL_TIMEOUT_TICKS - 1 {
            assert!(!engine.note_round_tick(&v.self_kp));
            assert!(
                engine.take_outbound_votes().is_empty(),
                "must not give up on the proposer before PROPOSAL_TIMEOUT_TICKS"
            );
        }
        assert!(
            !engine.note_round_tick(&v.self_kp),
            "a nil prevote alone is not quorum — the round must not end here"
        );

        let outbound = engine.take_outbound_votes();
        assert_eq!(outbound.len(), 1, "the proposal timeout must cast exactly one vote");
        assert_eq!(outbound[0].vote_type, VoteType::Prevote);
        assert_eq!(outbound[0].block_hash, NIL_BLOCK_HASH);
        assert_eq!(outbound[0].validator, v.self_addr);
    }

    /// The nil prevote is cast at most once per round. A second one for the same round would be
    /// a different `block_hash` from the same validator — indistinguishable from equivocation.
    #[test]
    fn the_nil_prevote_is_cast_only_once_however_long_the_round_drags_on() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);

        for _ in 0..ROUND_TIMEOUT_TICKS {
            engine.note_round_tick(&v.self_kp);
        }

        let outbound = engine.take_outbound_votes();
        assert_eq!(outbound.len(), 1, "one nil prevote per round, not one per tick: {outbound:?}");
    }

    /// Reproduces the 2026-07-24 stall (#127): with the other proposers silent, a validator
    /// times out through rounds, so the block loop reaches `produce_block` while `self.round`
    /// is None and `pending_round` has advanced past 0. `produce_block` used to hardcode round
    /// 0 — regressing the round, which is self-equivocation the signing guard then withholds,
    /// silently freezing a set that needs every member. It must respect the round reached.
    #[test]
    fn produce_block_respects_the_advanced_round_and_never_regresses_to_zero() {
        let v = four_validators();
        // genesis_height 0 → we decide height 1. self (index 1) IS the round-0 proposer
        // for height 1 ((1 + 0) % 4 == 1) but NOT the round-1 proposer ((1 + 1) % 4 == 2).
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let prev = Hash::digest(b"prev");

        // Time out of round 0 onto round 1, where self isn't the proposer: this leaves
        // self.round = None with pending_round = 1 — the exact state the block loop then
        // calls produce_block in.
        let advanced = engine.advance_round(&v.self_kp, prev, vec![]);
        assert!(
            matches!(advanced, Err(ConsensusError::NotProposer { height: 1, round: 1 })),
            "advance_round should leave us waiting on round 1's proposer: {advanced:?}"
        );

        // The bug: produce_block hardcoded round 0, and self IS the round-0 proposer, so it
        // would build a round-0 block — a regression from round 1.
        let produced = engine.produce_block(&v.self_kp, prev, vec![]);
        assert!(
            matches!(produced, Err(ConsensusError::NotProposer { height: 1, round: 1 })),
            "produce_block must respect pending_round (1), not regress to round 0: {produced:?}"
        );
        assert!(
            engine.take_outbound_votes().iter().all(|vote| vote.round == 1),
            "no round-0 vote may be produced after the engine has advanced to round 1"
        );
    }

    /// Once 2/3+ of the power has prevoted nil, the round is abandoned immediately — this is
    /// the mechanism that replaces waiting out `ROUND_TIMEOUT_TICKS`, and it is what makes a
    /// dead proposer cost seconds instead of half a minute.
    #[test]
    fn nil_prevote_quorum_ends_the_round_without_waiting_for_the_full_timeout() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);

        for _ in 0..PROPOSAL_TIMEOUT_TICKS {
            engine.note_round_tick(&v.self_kp);
        }
        assert!(!engine.should_advance_round(), "one nil prevote (ours) is not a quorum");

        // Two peers hit the same dead proposer and say so. 3 of 4 == quorum.
        for kp in [&v.a_kp, &v.c_kp] {
            let nil = peer_vote(kp, VoteType::Prevote, 2, 0, NIL_BLOCK_HASH);
            engine.add_vote(&v.self_kp, nil).unwrap();
        }

        assert!(engine.should_advance_round(), "nil quorum must end the round at once");
        assert!(
            engine.note_round_tick(&v.self_kp),
            "the tick loop must be told to advance now, not at ROUND_TIMEOUT_TICKS"
        );
        // Round 1's proposer is c ((2 + 1) % 4 == 3), so self defers rather than proposing.
        let err = engine.advance_round(&v.self_kp, Hash::digest(b"tip-1"), vec![]).unwrap_err();
        assert!(matches!(err, ConsensusError::NotProposer { height: 2, round: 1 }), "{err:?}");
    }

    /// **The self-slash guard.** A validator that prevoted nil, then finally receives the
    /// proposal it gave up on, must not prevote a second time in that round: `VoteSet::add`
    /// reads two different hashes from one validator in one round as equivocation, and that
    /// costs a 5% slash. Nil voting must never be able to punish an honest, merely slow node.
    #[test]
    fn a_late_proposal_after_our_nil_prevote_does_not_make_us_double_sign() {
        let v = four_validators();
        let b_addr = Address::from_public_key(&v.b_kp.public);
        let mut proposer = BftEngine::new(v.validator_set.clone(), b_addr, 1);
        let _ = proposer.produce_block(&v.b_kp, Hash::digest(b"tip-1"), vec![]);
        let late_block = proposer.pending_proposal().unwrap().clone();

        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        for _ in 0..PROPOSAL_TIMEOUT_TICKS {
            engine.note_round_tick(&v.self_kp);
        }
        assert_eq!(engine.take_outbound_votes().len(), 1, "nil prevote is cast");

        // b's proposal finally arrives — slow, not malicious.
        engine.receive_proposal(&v.self_kp, Proposal::fresh(0, late_block)).unwrap();

        assert!(
            engine.take_outbound_votes().is_empty(),
            "a second prevote here would be self-inflicted equivocation"
        );
        assert!(
            engine.take_evidence().is_empty(),
            "and it must not manufacture double-sign evidence against ourselves"
        );
    }

    /// A nil round holds no proposal, but still tallies peers' prevotes — including prevotes
    /// for the real block, from peers that did receive it. This node must not precommit that
    /// block: it has never seen the bytes, let alone validated them.
    #[test]
    fn we_never_precommit_a_block_we_do_not_hold() {
        let v = four_validators();
        let b_addr = Address::from_public_key(&v.b_kp.public);
        let mut proposer = BftEngine::new(v.validator_set.clone(), b_addr, 1);
        let _ = proposer.produce_block(&v.b_kp, Hash::digest(b"tip-1"), vec![]);
        let block_hash = proposer.pending_proposal().unwrap().hash();

        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        for _ in 0..PROPOSAL_TIMEOUT_TICKS {
            engine.note_round_tick(&v.self_kp);
        }
        engine.take_outbound_votes();

        // The other three did get the proposal and carry it to a prevote quorum in our round.
        for kp in [&v.a_kp, &v.b_kp, &v.c_kp] {
            let pv = peer_vote(kp, VoteType::Prevote, 2, 0, block_hash);
            engine.add_vote(&v.self_kp, pv).unwrap();
        }

        assert!(
            engine.take_outbound_votes().is_empty(),
            "precommitting a block we never received would be pledging to unvalidated bytes"
        );
    }

    /// Helix advances rounds on prevote-nil quorum and never precommits nil, so a precommit
    /// for nil can only come from a faulty or hostile peer. Accepting it would let power pile
    /// up behind the nil key and drive a round to `Commit(NIL)` — finalizing a height with no
    /// block behind it.
    #[test]
    fn a_precommit_for_nil_is_rejected_outright() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        for _ in 0..PROPOSAL_TIMEOUT_TICKS {
            engine.note_round_tick(&v.self_kp);
        }

        let nil_precommit = peer_vote(&v.a_kp, VoteType::Precommit, 2, 0, NIL_BLOCK_HASH);
        let err = engine.add_vote(&v.self_kp, nil_precommit).unwrap_err();
        assert!(
            matches!(&err, ConsensusError::InvalidVote { reason } if reason.contains("nil")),
            "{err:?}"
        );
    }

    /// A validator that *did* get the proposal prevotes the real value on the same tick the
    /// proposal timeout would otherwise fire — the timeout must not talk it out of a healthy
    /// round. Guards against a nil vote stomping the common path.
    #[test]
    fn a_round_with_a_proposal_never_draws_a_nil_prevote() {
        let v = four_validators();
        let b_addr = Address::from_public_key(&v.b_kp.public);
        let mut proposer = BftEngine::new(v.validator_set.clone(), b_addr, 1);
        let _ = proposer.produce_block(&v.b_kp, Hash::digest(b"tip-1"), vec![]);
        let block = proposer.pending_proposal().unwrap().clone();
        let block_hash = block.hash();

        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        engine.receive_proposal(&v.self_kp, Proposal::fresh(0, block)).unwrap();
        let prevote = engine.take_outbound_votes();
        assert_eq!(prevote[0].block_hash, block_hash, "prevoted the real value");

        for _ in 0..ROUND_TIMEOUT_TICKS {
            engine.note_round_tick(&v.self_kp);
        }
        assert!(
            engine.take_outbound_votes().iter().all(|vote| vote.block_hash != NIL_BLOCK_HASH),
            "a round that has its proposal must never nil-vote against it"
        );
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
        assert_eq!(engine.receive_proposal(&v.self_kp, Proposal::fresh(0, block)).unwrap(), None);

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

    /// A block this node was actively voting on can arrive already finalized (gossip won the
    /// race). The round is torn down — but the precommits it collected for that exact block are
    /// real, and they are the only evidence of who took part. Dropping them makes the next block
    /// this node proposes carry an empty certificate, which is why 14 of 20 consecutive blocks on
    /// the live chain recorded no participation at all on 2026-07-22.
    #[test]
    fn precommits_survive_a_block_that_arrives_already_finalized() {
        let v = four_validators();

        // b proposes height 2; this node joins the round and prevotes.
        let mut proposer_engine =
            BftEngine::new(v.validator_set.clone(), Address::from_public_key(&v.b_kp.public), 1);
        let _ = proposer_engine.produce_block(&v.b_kp, Hash::digest(b"block-1"), vec![]);
        let block = proposer_engine.pending_proposal().unwrap().clone();
        let block_hash = block.hash();

        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        engine.receive_proposal(&v.self_kp, Proposal::fresh(0, block)).unwrap();
        // Prevote quorum makes this node cast its own precommit...
        engine.add_vote(&v.self_kp, peer_vote(&v.b_kp, VoteType::Prevote, 2, 0, block_hash)).unwrap();
        engine.add_vote(&v.self_kp, peer_vote(&v.a_kp, VoteType::Prevote, 2, 0, block_hash)).unwrap();
        // ...and one peer precommit lands, still short of quorum locally.
        engine.add_vote(&v.self_kp, peer_vote(&v.b_kp, VoteType::Precommit, 2, 0, block_hash)).unwrap();
        assert!(engine.has_active_round(), "the round must still be open for this to mean anything");

        // The finished block overtakes us via the committed-block fast path.
        engine.sync_to_externally_finalized_block(2, block_hash, vec![]);

        assert_eq!(engine.current_height(), 2);
        let signers: Vec<&Address> = engine.last_commit.iter().map(|v| &v.validator).collect();
        assert!(
            signers.contains(&&v.self_addr),
            "our own precommit for the committed block must survive the round teardown"
        );
        assert!(
            signers.contains(&&Address::from_public_key(&v.b_kp.public)),
            "and so must the peer precommit we had already verified"
        );
        assert!(
            engine.last_commit.iter().all(|vote| vote.block_hash == block_hash),
            "only votes for the block actually committed may be carried forward"
        );
    }

    /// #114, the other half: a node that never saw the votes at all — a pure committed-blocks/RPC
    /// follower, or one that fell behind and caught up over the fast path — has nothing to salvage.
    /// It now adopts the certificate gossiped with the block, so its own next `last_commit` records
    /// who took part instead of being empty. The certificate is untrusted, so a vote for the wrong
    /// block and a prevote-not-precommit are both filtered out; only genuine precommits for exactly
    /// this block survive.
    #[test]
    fn a_fast_path_receiver_adopts_the_gossiped_commit_certificate() {
        let v = four_validators();
        // This node holds no round for height 2 — it never participated, it only received the
        // finished block. Without the certificate its `last_commit` would be empty.
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        assert!(!engine.has_active_round(), "precondition: no round to salvage from");

        let block_hash = Hash::digest(b"committed-block-2");
        let a_addr = Address::from_public_key(&v.a_kp.public);
        let b_addr = Address::from_public_key(&v.b_kp.public);
        let certificate = vec![
            peer_vote(&v.a_kp, VoteType::Precommit, 2, 0, block_hash),
            peer_vote(&v.b_kp, VoteType::Precommit, 2, 0, block_hash),
            // Junk that must be dropped: a precommit for a different block…
            peer_vote(&v.a_kp, VoteType::Precommit, 2, 0, Hash::digest(b"other-block")),
            // …and a prevote (not a precommit) for the right block.
            peer_vote(&v.b_kp, VoteType::Prevote, 2, 0, block_hash),
        ];

        engine.sync_to_externally_finalized_block(2, block_hash, certificate);

        assert_eq!(engine.current_height(), 2);
        let signers: Vec<&Address> = engine.last_commit.iter().map(|vote| &vote.validator).collect();
        assert!(signers.contains(&&a_addr) && signers.contains(&&b_addr), "both genuine precommits are adopted");
        assert_eq!(engine.last_commit.len(), 2, "the wrong-block precommit and the prevote are filtered out");
        assert!(
            engine.last_commit.iter().all(|vote| vote.block_hash == block_hash
                && vote.vote_type == VoteType::Precommit),
            "only precommits for exactly the committed block may be carried forward"
        );
    }

    /// **This test asserted the opposite until 2026-08-27, and the assertion was the bug.**
    ///
    /// It was written as a positive control that "the participating path is untouched": a node
    /// holding its own precommits kept them and ignored the gossiped certificate. That is a
    /// perfectly reasonable-sounding rule and it cost the chain a fifth of its commit
    /// certificates. The situation it describes is not a rare one — it is the *normal* one for a
    /// node that loses the finalize race: it holds exactly one precommit, its own, and the
    /// finished block arrives carrying the winner's complete quorum. Preferring the salvage then
    /// means writing a one-signature `last_commit` while holding a two-signature certificate.
    /// Measured on the live chain: 203 of a 1000-block sample, every one from the node that
    /// habitually lost that race, which left an RPC-syncing node unable to prove those blocks
    /// final and permanently stuck (see `sync_blocks_from_peer`).
    ///
    /// The rule now is that the two are merged, so this checks both halves: the node's own
    /// precommit survives (the original point of the salvage) **and** the extra signer that only
    /// the gossiped certificate names is picked up.
    #[test]
    fn a_gossiped_certificate_is_merged_with_this_nodes_own_precommits() {
        let v = four_validators();
        let mut proposer_engine =
            BftEngine::new(v.validator_set.clone(), Address::from_public_key(&v.b_kp.public), 1);
        let _ = proposer_engine.produce_block(&v.b_kp, Hash::digest(b"block-1"), vec![]);
        let block = proposer_engine.pending_proposal().unwrap().clone();
        let block_hash = block.hash();

        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        engine.receive_proposal(&v.self_kp, Proposal::fresh(0, block)).unwrap();
        engine.add_vote(&v.self_kp, peer_vote(&v.b_kp, VoteType::Prevote, 2, 0, block_hash)).unwrap();
        engine.add_vote(&v.self_kp, peer_vote(&v.a_kp, VoteType::Prevote, 2, 0, block_hash)).unwrap();
        engine.add_vote(&v.self_kp, peer_vote(&v.b_kp, VoteType::Precommit, 2, 0, block_hash)).unwrap();
        assert!(engine.has_active_round(), "precondition: this node has its own round to salvage");

        // The certificate carries a third signer (a) this node never precommitted itself.
        let a_addr = Address::from_public_key(&v.a_kp.public);
        let certificate = vec![peer_vote(&v.a_kp, VoteType::Precommit, 2, 0, block_hash)];
        engine.sync_to_externally_finalized_block(2, block_hash, certificate);

        let signers: Vec<&Address> = engine.last_commit.iter().map(|vote| &vote.validator).collect();
        assert!(
            signers.contains(&&v.self_addr),
            "this node's own first-hand precommit must survive the round teardown"
        );
        assert!(
            signers.contains(&&Address::from_public_key(&v.b_kp.public)),
            "and so must the peer precommit it had already verified itself"
        );
        assert!(
            signers.contains(&&a_addr),
            "the signer only the gossiped certificate names must be picked up too — dropping it \
             is how a full quorum became a one-signature certificate on 20 % of live blocks"
        );
        assert_eq!(
            engine.last_commit.len(),
            3,
            "merged, not concatenated: no validator may appear twice, or any tally computed over \
             this certificate double-counts it"
        );
    }

    /// The safety half: precommits for some *other* block must never be salvaged. Attaching them
    /// would build a `last_commit` attesting a block that was not committed, and every receiving
    /// node's `verify_last_commit` would reject the resulting proposal — a self-inflicted stall.
    #[test]
    fn salvaged_precommits_never_include_a_different_block() {
        let v = four_validators();

        let mut proposer_engine =
            BftEngine::new(v.validator_set.clone(), Address::from_public_key(&v.b_kp.public), 1);
        let _ = proposer_engine.produce_block(&v.b_kp, Hash::digest(b"block-1"), vec![]);
        let block = proposer_engine.pending_proposal().unwrap().clone();
        let block_hash = block.hash();

        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 1);
        engine.receive_proposal(&v.self_kp, Proposal::fresh(0, block)).unwrap();
        engine.add_vote(&v.self_kp, peer_vote(&v.b_kp, VoteType::Prevote, 2, 0, block_hash)).unwrap();
        engine.add_vote(&v.self_kp, peer_vote(&v.a_kp, VoteType::Prevote, 2, 0, block_hash)).unwrap();
        engine.add_vote(&v.self_kp, peer_vote(&v.b_kp, VoteType::Precommit, 2, 0, block_hash)).unwrap();

        // A different block wins at this height (e.g. a later round we never saw).
        let other_hash = Hash::digest(b"some-other-block");
        engine.sync_to_externally_finalized_block(2, other_hash, vec![]);

        assert!(
            engine.last_commit.is_empty(),
            "no precommit we hold attests the block that was actually committed, so the \
             certificate must stay empty rather than attest the wrong one"
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
        let result = engine.receive_proposal(&v.self_kp, Proposal::fresh(0, block)).unwrap();
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

        let result = engine.receive_proposal(&v.self_kp, Proposal::fresh(0, block));
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
        assert_eq!(engine.receive_proposal(&v.self_kp, Proposal::fresh(0, block)).unwrap(), None);
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
        engine.sync_to_externally_finalized_block(2, Hash::digest(b"block-2"), vec![]);
        assert_eq!(engine.current_height(), 2);
        assert!(!engine.has_active_round(), "any stale round for height 2 must be cleared");

        // c is the proposer for height 3, round 0 ((3 + 0) % 4 == 3, c's index).
        let mut proposer_engine = BftEngine::new(v.validator_set.clone(), v.c_addr.clone(), 2);
        let _ = proposer_engine.produce_block(&v.c_kp, Hash::digest(b"block-2"), vec![]);
        let block = proposer_engine.pending_proposal().unwrap().clone();

        // Before the fix this failed with InvalidBlock { reason: "expected height 2, got 3" }.
        let result = engine.receive_proposal(&v.self_kp, Proposal::fresh(0, block));
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
        let err = engine.receive_proposal(&v.self_kp, Proposal::fresh(0, block)).unwrap_err();
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
            assert!(!engine.note_round_tick(&v.self_kp), "must not time out early");
        }
        assert!(engine.note_round_tick(&v.self_kp), "must time out after ROUND_TIMEOUT_TICKS");

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
            self_engine.note_round_tick(&v.self_kp);
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
        b_engine.receive_proposal(&v.b_kp, Proposal::fresh(0, round0_block)).unwrap();
        b_engine.take_outbound_votes();
        for _ in 0..ROUND_TIMEOUT_TICKS {
            b_engine.note_round_tick(&v.b_kp);
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
        let result = self_engine.receive_proposal(&v.self_kp, Proposal::fresh(1, round1_block)).unwrap();
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
            self_engine.note_round_tick(&v.self_kp);
        }
        self_engine
            .advance_round(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();

        let b_addr = Address::from_public_key(&v.b_kp.public);
        let mut b_engine = BftEngine::new(v.validator_set, b_addr, 0);
        b_engine.receive_proposal(&v.b_kp, Proposal::fresh(0, round0_block.clone())).unwrap();
        for _ in 0..ROUND_TIMEOUT_TICKS {
            b_engine.note_round_tick(&v.b_kp);
        }
        b_engine
            .advance_round(&v.b_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        let round1_block = b_engine.pending_proposal().unwrap().clone();

        self_engine.receive_proposal(&v.self_kp, Proposal::fresh(1, round1_block)).unwrap();
        self_engine.take_outbound_votes();
        assert_eq!(self_engine.pending_proposal().map(|b| b.height()), Some(1));

        // Re-deliver the stale round-0 proposal.
        let result = self_engine.receive_proposal(&v.self_kp, Proposal::fresh(0, round0_block)).unwrap();
        assert_eq!(result, None);
        assert_eq!(
            self_engine.take_outbound_votes().len(),
            0,
            "stale round-0 proposal must not cast a new vote or reset round-1 state"
        );
    }

    // ── Tendermint cross-round vote locking ─────────────────────────────────
    //
    // These exercise the safety mechanism that prevents two different blocks
    // from both reaching quorum at the same height across rounds (a fork). Once
    // a node sees a prevote-quorum for value A it *locks* on A: it re-proposes A
    // (with the proof-of-lock) when it proposes a later round, and refuses to
    // prevote any *conflicting* value B unless the proposal carries a POL from a
    // round at least as new as its lock. The withheld prevotes are exactly what
    // keep B from ever reaching a prevote-quorum against a 2/3 lock.

    /// Drive `self` (the height-1/round-0 proposer) to a prevote quorum on its
    /// own block, so it locks on that value in round 0. Returns the engine, the
    /// locked block, and its hash.
    fn locked_self_engine(v: &FourValidators) -> (BftEngine, Block, Hash) {
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        engine
            .produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        engine.take_outbound_votes();
        let block = engine.pending_proposal().unwrap().clone();
        let hash = block.hash();

        // Two peer prevotes tip prevote quorum (self + a + b = 3 of 4) — this is
        // where lock_and_precommit captures the lock.
        engine
            .add_vote(&v.self_kp, peer_vote(&v.a_kp, VoteType::Prevote, 1, 0, hash.clone()))
            .unwrap();
        engine
            .add_vote(&v.self_kp, peer_vote(&v.b_kp, VoteType::Prevote, 1, 0, hash.clone()))
            .unwrap();
        engine.take_outbound_votes();

        assert_eq!(engine.locked_round, Some(0), "reaching prevote quorum must lock the round");
        assert!(engine.locked_block.is_some());
        assert!(!engine.locked_pol.is_empty(), "the lock must capture the prevote certificate");
        (engine, block, hash)
    }

    /// Build a *different* block for height 1, round 1 (proposed by `b`), so we
    /// have a value that conflicts with the one `self` is locked on.
    fn conflicting_round1_block(v: &FourValidators) -> Block {
        // self ((1 + 0) % 4 == 1) is round 0's proposer — build its block first.
        let mut self_engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        self_engine
            .produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        let round0 = self_engine.pending_proposal().unwrap().clone();

        // b joins round 0, then times it out so it — round 1's proposer
        // ((1 + 1) % 4 == 2, b's index) — builds a fresh, conflicting round-1 block.
        let b_addr = Address::from_public_key(&v.b_kp.public);
        let mut b_engine = BftEngine::new(v.validator_set.clone(), b_addr, 0);
        b_engine
            .receive_proposal(&v.b_kp, Proposal::fresh(0, round0))
            .unwrap();
        b_engine.take_outbound_votes();
        for _ in 0..ROUND_TIMEOUT_TICKS {
            b_engine.note_round_tick(&v.b_kp);
        }
        b_engine
            .advance_round(&v.b_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        b_engine.pending_proposal().unwrap().clone()
    }

    /// A proposal too large for the network to carry must be refused before a vote is cast.
    ///
    /// Voting for one is voting for a round that cannot finish: gossipsub will not transmit a block
    /// past `max_message_size`, so no peer ever sees it, no quorum ever forms, and the next proposer
    /// rebuilds the same block from the same mempool. Until the size limit existed, a 1000-
    /// transaction block was 5.2 MB against a 4 MB transmit limit, and nothing anywhere said no.
    #[test]
    fn a_proposal_larger_than_the_network_will_carry_is_refused() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);

        // Produced by this node, so every other property (height, signature, base fee, chaining)
        // is correct and size is the only thing left to reject it on.
        engine
            .produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        let mut block = engine.pending_proposal().unwrap().clone();

        let mut t = oversized_transaction();
        t.data = vec![0u8; helix_core::fee::MAX_BLOCK_BYTES as usize + 1];
        block.transactions = vec![t];

        let mut verifier = BftEngine::new(v.validator_set.clone(), v.c_addr.clone(), 0);
        verifier.seed_last_committed(Hash::digest(b"genesis"));
        let err = verifier
            .validate_block(&block, 0, None, &[])
            .expect_err("an oversized proposal must not be votable");
        assert!(
            format!("{err}").contains("over the"),
            "expected a size rejection, got: {err}"
        );
    }

    /// The control. The same block under the limit has to pass, or the rule is a liveness bug
    /// rather than a fix — and a limit that rejected ordinary blocks would look identical from the
    /// outside to the stall it was built to prevent.
    #[test]
    fn a_proposal_within_the_limit_is_not_refused_for_its_size() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        engine
            .produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        let block = engine.pending_proposal().unwrap().clone();

        let mut verifier = BftEngine::new(v.validator_set.clone(), v.c_addr.clone(), 0);
        verifier.seed_last_committed(Hash::digest(b"genesis"));
        // May still fail for unrelated reasons in other tests' setups; here it must simply not be
        // the size that stops it.
        if let Err(e) = verifier.validate_block(&block, 0, None, &[]) {
            assert!(!format!("{e}").contains("over the"), "rejected for size: {e}");
        }
    }

    fn oversized_transaction() -> helix_core::Transaction {
        use helix_core::transaction::TxType;
        let kp = KeyPair::generate();
        helix_core::Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: Address::from_public_key(&kp.public),
            to: Some(Address::from_public_key(&kp.public)),
            amount: 1,
            fee: 1,
            nonce: 0,
            data: vec![],
            crypto_version: kp.scheme,
            chain_id: helix_crypto::Hash::ZERO,
            signature: helix_crypto::Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        }
    }

    /// The production incident of 2026-08-05 in one assertion.
    ///
    /// A validator that had climbed to round 10 restarted and rejoined at round 7, below its own
    /// double-sign mark. The guard then correctly refused every vote — a value was already signed
    /// at those rounds — so the node stayed mute for three and a half minutes while a
    /// two-validator chain that needed both of them stood still.
    #[test]
    fn a_restart_resumes_above_the_round_this_key_already_signed() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        assert_eq!(engine.pending_round(), 0, "a fresh engine starts at round 0");

        engine.resume_at_round(1, 11);
        assert_eq!(engine.pending_round(), 11);
    }

    /// The control that matters more than the test above: this must never drag an engine backwards.
    /// A stale mark that pulled a healthy node down to an older round would re-open the very
    /// equivocation window the double-sign guard exists to close.
    #[test]
    fn resuming_can_never_move_an_engine_to_an_earlier_round() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        engine.resume_at_round(1, 11);

        engine.resume_at_round(1, 4);
        assert_eq!(engine.pending_round(), 11, "an older mark must be ignored");
        engine.resume_at_round(1, 11);
        assert_eq!(engine.pending_round(), 11, "the same mark changes nothing");
    }

    /// A mark for a height this engine is not working on says nothing about its current round.
    /// Applying it would be reading one height's round number into another's.
    #[test]
    fn a_mark_for_another_height_is_ignored() {
        let v = four_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);

        engine.resume_at_round(7, 11);
        assert_eq!(engine.pending_round(), 0);
        engine.resume_at_round(0, 11);
        assert_eq!(engine.pending_round(), 0);
    }

    /// The core safety property: a node locked on value A withholds its prevote
    /// from a *fresh* (no proof-of-lock) proposal of a conflicting value B. That
    /// withheld prevote is what stops B from reaching a prevote-quorum against
    /// the lock — without it, two values could each reach quorum and fork.
    #[test]
    fn locked_node_abstains_from_prevoting_a_conflicting_fresh_proposal() {
        let v = four_validators();
        let (mut engine, _block_a, hash_a) = locked_self_engine(&v);

        let block_b = conflicting_round1_block(&v);
        assert_ne!(block_b.hash(), hash_a, "the round-1 block must genuinely conflict");

        // b's round-1 proposal is fresh (valid_round = None). self is locked on A,
        // so it must abstain — join the round to tally peers, but cast no prevote.
        let result = engine
            .receive_proposal(&v.self_kp, Proposal::fresh(1, block_b.clone()))
            .unwrap();
        assert_eq!(result, None);
        assert!(
            engine.take_outbound_votes().is_empty(),
            "a locked node must not prevote a conflicting value that carries no proof-of-lock"
        );
        // The lock is unchanged — still on A from round 0.
        assert_eq!(engine.locked_round, Some(0));
        assert_eq!(engine.locked_block.as_ref().map(|b| b.hash()), Some(hash_a));
    }

    /// The controlled unlock: a node locked on A *does* prevote a conflicting
    /// value B when the proposal proves a prevote-quorum (POL) formed on B in a
    /// round at least as new as the lock. The certificate is what makes this
    /// safe — it shows the network genuinely moved on to B.
    #[test]
    fn locked_node_unlocks_and_prevotes_a_reproposal_with_a_valid_pol() {
        let v = four_validators();
        let (mut engine, _block_a, hash_a) = locked_self_engine(&v);

        let block_b = conflicting_round1_block(&v);
        let hash_b = block_b.hash();
        assert_ne!(hash_b, hash_a);

        // A genuine prevote-quorum for B at round 1 (a + b + c = 3 of 4).
        let pol = vec![
            peer_vote(&v.a_kp, VoteType::Prevote, 1, 1, hash_b.clone()),
            peer_vote(&v.b_kp, VoteType::Prevote, 1, 1, hash_b.clone()),
            peer_vote(&v.c_kp, VoteType::Prevote, 1, 1, hash_b.clone()),
        ];

        // c re-proposes B in round 2 carrying B's round-1 POL. self, locked on A
        // from round 0, must unlock (1 >= 0) and prevote B.
        let proposal = Proposal::reproposal(2, 1, block_b.clone(), pol);
        let result = engine.receive_proposal(&v.self_kp, proposal).unwrap();
        assert_eq!(result, None);

        let outbound = engine.take_outbound_votes();
        assert_eq!(outbound.len(), 1, "a valid POL must let the locked node prevote the re-proposed value");
        assert_eq!(outbound[0].vote_type, VoteType::Prevote);
        assert_eq!(outbound[0].block_hash, hash_b);
    }

    /// A re-proposal whose proof-of-lock doesn't actually carry a quorum must be
    /// rejected outright — a locked node can't be tricked into unlocking by a
    /// forged/insufficient certificate.
    #[test]
    fn reproposal_with_insufficient_pol_is_rejected() {
        let v = four_validators();
        let engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let block_b = conflicting_round1_block(&v);
        let hash_b = block_b.hash();

        // Only two prevotes — one short of the 3-of-4 quorum.
        let pol = vec![
            peer_vote(&v.a_kp, VoteType::Prevote, 1, 1, hash_b.clone()),
            peer_vote(&v.b_kp, VoteType::Prevote, 1, 1, hash_b.clone()),
        ];
        let err = engine.verify_pol(&pol, &hash_b, 1, 1).unwrap_err();
        assert!(matches!(err, ConsensusError::InsufficientVotingPower { .. }));

        // And the same shortfall makes the whole re-proposal fail validation.
        let err = engine
            .validate_block(&block_b, 2, Some(1), &pol)
            .unwrap_err();
        assert!(matches!(err, ConsensusError::InsufficientVotingPower { .. }));
    }

    /// When a locked node is the proposer of a later round, it re-proposes the
    /// exact value it locked on, carrying the proof-of-lock — never a fresh
    /// block that would abandon the value a prevote-quorum already formed on.
    #[test]
    fn locked_proposer_reproposes_its_locked_value_with_the_pol() {
        let v = four_validators();
        let (mut engine, _block_a, hash_a) = locked_self_engine(&v);

        // self is the proposer for round 4 too ((1 + 4) % 4 == 1). Proposing there
        // while locked must re-propose A, not build a fresh block.
        let err = engine
            .propose(&v.self_kp, 1, 4, Hash::digest(b"genesis"), vec![])
            .unwrap_err();
        assert!(matches!(err, ConsensusError::AwaitingVotes { round: 4, .. }));

        let envelope = engine.pending_proposal_envelope().unwrap();
        assert_eq!(envelope.valid_round, Some(0), "a re-proposal must tag the round it locked in");
        assert_eq!(envelope.block.hash(), hash_a, "the locked value must be re-proposed unchanged");
        assert!(!envelope.pol.is_empty(), "the re-proposal must carry the proof-of-lock certificate");
    }

    // ── Dead-proposer round recovery ────────────────────────────────────────
    //
    // A non-proposer holds no `RoundState` while it waits for the round's proposer to
    // broadcast — so if that proposer is dead/offline, nothing on the waiting node runs the
    // round clock, and the height would stall forever. `advance_round` must therefore work
    // even with no active round: bump the pending round and let the next round's (live)
    // proposer step up. Without this a single offline validator halts the whole chain, which
    // defeats the point of running ≥4 validators for fault tolerance.

    /// self (index 1) is NOT height-4 round-0's proposer (that's index 0) — so it's waiting
    /// with no active round. If that proposer never delivers, timing out and calling
    /// `advance_round` must promote self into round 1 (whose proposer *is* self: (4+1)%4==1)
    /// and have it propose, rather than erroring `NoActiveRound` and stalling.
    #[test]
    fn a_waiting_non_proposer_advances_the_round_when_the_proposer_is_dead() {
        let v = four_validators();
        // genesis_height 3 → pending height 4. Round 0 proposer = (4+0)%4 = 0 (not self).
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 3);
        assert!(!engine.has_active_round(), "a non-proposer starts with no round to run");

        // The round-0 proposer is dead — no proposal ever arrives. Time out and advance.
        let err = engine
            .advance_round(&v.self_kp, Hash::digest(b"tip-3"), vec![])
            .unwrap_err();
        assert!(
            matches!(err, ConsensusError::AwaitingVotes { height: 4, round: 1 }),
            "self is round 1's proposer and must step up from a no-active-round wait, got {err:?}"
        );
        let envelope = engine.pending_proposal_envelope().expect("self should now have proposed");
        assert_eq!(envelope.round, 1, "the recovered proposal must be for round 1");
        assert_eq!(envelope.block.height(), 4);
    }

    /// When the node advancing isn't the *new* round's proposer either, it defers (records the
    /// new pending round and waits) rather than erroring — and a late proposal for the round it
    /// already abandoned is rejected as stale instead of restarting it.
    #[test]
    fn advance_round_from_no_active_round_defers_to_the_new_proposer_and_rejects_stale() {
        let v = four_validators();
        // genesis_height 1 → pending height 2. Round 1 proposer = (2+1)%4 = 3 (not self, idx 1).
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 1);

        let err = engine
            .advance_round(&v.self_kp, Hash::digest(b"tip-1"), vec![])
            .unwrap_err();
        assert!(
            matches!(err, ConsensusError::NotProposer { height: 2, round: 1 }),
            "self isn't round 1's proposer here, so it must defer, got {err:?}"
        );
        assert!(!engine.has_active_round(), "deferring must not leave a phantom round");

        // A now-stale round-0 proposal (from the dead proposer, finally relayed) must not
        // restart the abandoned round. b is height-2 round-0's proposer ((2+0)%4==2).
        let b_addr = Address::from_public_key(&v.b_kp.public);
        let mut b_engine = BftEngine::new(v.validator_set, b_addr, 1);
        b_engine.produce_block(&v.b_kp, Hash::digest(b"tip-1"), vec![]).unwrap_err();
        let stale_round0 = b_engine.pending_proposal().unwrap().clone();

        assert_eq!(
            engine.receive_proposal(&v.self_kp, Proposal::fresh(0, stale_round0)).unwrap(),
            None,
            "a proposal for the round we already advanced past must be ignored"
        );
        assert!(!engine.has_active_round());
    }

    /// A 2-validator set with equal stake — the case that actually froze prod on 2026-07-20:
    /// `quorum_threshold()` needs `2/3+1` of total power, so with two equal validators neither
    /// can ever reach it alone until liveness exclusion kicks in.
    struct TwoValidators {
        self_kp: KeyPair,
        self_addr: Address,
        peer_kp: KeyPair,
        validator_set: ValidatorSet,
    }

    fn two_validators() -> TwoValidators {
        let self_kp = KeyPair::generate();
        let peer_kp = KeyPair::generate();
        let self_addr = Address::from_public_key(&self_kp.public);
        let peer_addr = Address::from_public_key(&peer_kp.public);
        // self_addr at index 1 so it's the proposer for height 1, round 0
        // (proposer_for_round uses (height + round) % len).
        let validator_set = ValidatorSet::new(
            vec![
                Validator::new(peer_addr, 1_000, true),
                Validator::new(self_addr.clone(), 1_000, true),
            ],
            0,
        );
        TwoValidators { self_kp, self_addr, peer_kp, validator_set }
    }

    /// Runs this node's round clock to its timeout (exactly as `block_production_loop` does,
    /// tick by tick) and then calls `advance_round` once — mirroring the real production loop
    /// rather than poking engine internals directly.
    fn tick_to_timeout_and_advance(engine: &mut BftEngine, kp: &KeyPair) {
        loop {
            if engine.note_round_tick(kp) {
                break;
            }
        }
        engine.take_outbound_votes();
        let _ = engine.advance_round(kp, Hash::digest(b"genesis"), vec![]);
        engine.take_outbound_votes();
    }

    /// `last_commit` is how downtime-jailing (`helix-executor::ChainState::
    /// record_block_participation`) learns who actually signed the parent block — a forged
    /// entry could otherwise let a malicious proposer manufacture "X signed" (shielding a
    /// colluding validator from a miss) or, just as bad, get accepted as proof that an
    /// innocent validator signed something it never did. `verify_last_commit` must reject a
    /// signature that doesn't actually verify.
    #[test]
    fn verify_last_commit_rejects_a_forged_signature() {
        let v = two_validators();
        let engine = BftEngine::new(v.validator_set, v.self_addr, 5);
        let parent_hash = Hash::digest(b"parent");

        let mut sig = peer_vote(&v.peer_kp, VoteType::Precommit, 5, 0, parent_hash);
        // Tamper with the signed content after signing — the signature no longer matches.
        sig.round = 1;
        let commit_sig = helix_core::CommitSig {
            validator: sig.validator,
            public_key: sig.public_key,
            crypto_version: sig.crypto_version,
            round: sig.round,
            signature: sig.signature,
        };

        let err = engine.verify_last_commit(&[commit_sig], 6, &parent_hash).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidBlock { .. }));
    }

    /// The same validator can't be counted twice toward participation by repeating its
    /// signature in `last_commit`.
    #[test]
    fn verify_last_commit_rejects_a_duplicate_validator() {
        let v = two_validators();
        let engine = BftEngine::new(v.validator_set, v.self_addr, 5);
        let parent_hash = Hash::digest(b"parent");
        let vote = peer_vote(&v.peer_kp, VoteType::Precommit, 6, 0, parent_hash);
        let commit_sig = helix_core::CommitSig {
            validator: vote.validator,
            public_key: vote.public_key,
            crypto_version: vote.crypto_version,
            round: vote.round,
            signature: vote.signature,
        };

        let err = engine
            .verify_last_commit(&[commit_sig.clone(), commit_sig], 7, &parent_hash)
            .unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidBlock { .. }));
    }

    #[test]
    fn verify_last_commit_is_a_no_op_at_genesis() {
        let v = two_validators();
        let engine = BftEngine::new(v.validator_set, v.self_addr, 0);
        // Height 0 has no parent to attest — an empty (or even non-empty) last_commit must
        // not be rejected for "missing" a parent that doesn't exist.
        assert!(engine.verify_last_commit(&[], 0, &Hash::ZERO).is_ok());
    }

    /// `set_validator_set` installs the set a synced node derived from chain state at an explicit
    /// epoch, *without* `rotate_validator_set`'s `+1` bump — the fix for a validator that
    /// activates while catching up over the sync path (which never calls `rotate_validator_set`).
    /// It must add the newcomer to the *live* set and report the membership change, so the joiner
    /// stops being absent from its own set (the "bonded but silent" trap) and starts voting.
    #[test]
    fn set_validator_set_adds_the_activated_validator_at_the_given_epoch() {
        let v = two_validators();
        let peer_addr = Address::from_public_key(&v.peer_kp.public);
        // Start from a stale, self-only set at epoch 1 — what a joiner built at startup, behind
        // the genesis validator, before its own activation rotation ever landed.
        let mut engine = BftEngine::new(
            ValidatorSet::new(vec![Validator::new(v.self_addr.clone(), 1_000, true)], 1),
            v.self_addr.clone(),
            250,
        );
        assert!(
            engine.validator_set().get(&peer_addr).is_none(),
            "precondition: the peer is not in the stale startup set"
        );

        let changed = engine.set_validator_set(v.validator_set.validators.clone(), 2);

        assert!(changed, "adding a validator is a membership change");
        assert!(engine.validator_set().get(&v.self_addr).is_some());
        assert!(
            engine.validator_set().get(&peer_addr).is_some(),
            "the activated peer must be in the live set now"
        );
        assert_eq!(
            engine.validator_set().epoch,
            2,
            "epoch is set to the value passed, not bumped by one like a rotation"
        );
    }

    /// A periodic catch-up that applied blocks but crossed no rotation must not be reported as a
    /// change — the caller uses the return value to decide whether to log, and a per-poll line
    /// while nothing moved is exactly the noise operators complained about.
    #[test]
    fn set_validator_set_reports_no_change_when_membership_is_identical() {
        let v = two_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 300);

        let changed = engine.set_validator_set(v.validator_set.validators.clone(), 3);

        assert!(!changed, "same set of addresses must report unchanged");
        assert_eq!(engine.validator_set().len(), 2, "the set itself is still intact");
    }

    /// An empty candidate list must never replace a live set — switching to zero validators halts
    /// block production. Matches `rotate_validator_set`'s own empty guard.
    #[test]
    fn set_validator_set_is_a_no_op_on_an_empty_candidate_list() {
        let v = two_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let before = engine.validator_set().len();

        let changed = engine.set_validator_set(vec![], 9);

        assert!(!changed, "an empty list is a no-op, not a change");
        assert_eq!(
            engine.validator_set().len(),
            before,
            "the previous set must survive an empty candidate list"
        );
        assert_eq!(engine.validator_set().epoch, 0, "a no-op must not touch the epoch either");
    }

    /// Rounds a silent peer is left silent for in the tests below. Far past the 20 rounds the
    /// removed liveness jail used to fire at, so reintroducing any variant of it fails here.
    const SILENT_ROUNDS: u32 = 40;

    /// **The fork that removed the liveness jail.** Two nodes, no messages between them, each
    /// therefore seeing the other as permanently silent — the exact live situation on
    /// 2026-07-22, when both production validators had locally excluded each other and each
    /// finalized its own height 66918 (`ca38cd4b…` against `f18b2d4d…`).
    ///
    /// Neither may finalize anything. With two equal validators a quorum is 2/3+1 of the *full*
    /// staked power, which one alone cannot reach — and no amount of observed silence may lower
    /// that bar, because the observation is local and the two nodes can disagree about it.
    /// Halting here is the correct answer: `3f+1` says a 2-set tolerates zero absences.
    ///
    /// Mutation check: restore `liveness_adjusted_validator_set` and both engines finalize.
    #[test]
    fn two_nodes_that_each_consider_the_other_silent_cannot_both_finalize() {
        let v = two_validators();
        // Same set, same ordering, two different identities — as two real nodes see it.
        let peer_addr = Address::from_public_key(&v.peer_kp.public);
        let mut ours = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let mut theirs = BftEngine::new(v.validator_set.clone(), peer_addr, 0);

        // Each proposes its own block for height 1 and hears nothing back, ever.
        let _ = ours.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        let _ = theirs.produce_block(&v.peer_kp, Hash::digest(b"genesis"), vec![]);
        for _ in 0..SILENT_ROUNDS {
            tick_to_timeout_and_advance(&mut ours, &v.self_kp);
            tick_to_timeout_and_advance(&mut theirs, &v.peer_kp);
        }

        assert_eq!(
            (ours.current_height(), theirs.current_height()),
            (0, 0),
            "each node saw only its own vote, which is below a 2-of-2 quorum — a node that \
             finalizes here has committed a block less than 2/3+1 of the staked power stands \
             behind, and the other node can do the same with a different block: that is a fork"
        );
    }

    /// A probationer holds `voting_power = 0` and is excluded from `full_members()`, so it takes
    /// no proposer turn and adds nothing to quorum — the round is not waiting on it and cannot
    /// be, whatever it does. Naming it as the reason sends the operator to inspect a node whose
    /// silence is free.
    ///
    /// Not hypothetical: production logged exactly this for days about `hlxSpsWWU…`, at
    /// `voting_power=0`, in the line that reads "consensus cannot reach quorum without its
    /// votes" — while the vote that was actually missing went unnamed.
    ///
    /// Mutation check: iterate `validator_set.validators` again instead of `full_members()`.
    #[test]
    fn a_probationary_validator_is_never_named_as_the_reason_a_round_stalled() {
        let v = two_validators();
        let peer_addr = Address::from_public_key(&v.peer_kp.public);
        let probationer = Address::from_public_key(&KeyPair::generate().public);
        let mut validators = v.validator_set.validators.clone();
        validators.push(Validator::new_probationary(probationer.clone(), 1_000, true));
        let set = ValidatorSet::new(validators, 0);
        assert_eq!(
            set.get(&probationer).unwrap().voting_power,
            0,
            "premise of this test: a probationer carries no power"
        );
        let mut engine = BftEngine::new(set, v.self_addr.clone(), 0);

        let _ = engine.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        for _ in 0..SILENT_ROUNDS {
            tick_to_timeout_and_advance(&mut engine, &v.self_kp);
        }

        assert_eq!(
            engine.missed_rounds.get(&probationer),
            None,
            "a validator with no voting power cannot hold a round up, so it must never be \
             counted — or reported — as the reason one timed out"
        );
        assert!(
            engine.missed_rounds.get(&peer_addr).copied().unwrap_or(0) > 0,
            "the full member that really is silent must still be counted, or this test would \
             pass just as well with the counting removed altogether"
        );
    }

    /// A validator we heard prevote is not silent — whatever else is wrong with it. Reporting
    /// it as silent points at an absent node when the node is present.
    #[test]
    fn a_validator_heard_in_prevote_is_not_silent() {
        assert_eq!(
            liveness_verdict(true, false, false),
            LivenessVerdict::Heard { missing_precommit: false }
        );
    }

    /// The case that used to be invisible: the round reached prevote quorum and then stalled,
    /// and this validator's precommit is the one missing. Before, a prevote alone reset the
    /// silence counter and nothing looked at the second phase, so the validator actually holding
    /// the round up was filed as healthy and never named.
    #[test]
    fn a_missing_precommit_after_prevote_quorum_is_its_own_diagnosis() {
        assert_eq!(
            liveness_verdict(true, false, true),
            LivenessVerdict::Heard { missing_precommit: true },
            "prevote quorum was reached and this validator's precommit did not arrive — that is \
             the vote the round is stuck on, and it must be nameable"
        );
    }

    /// And it is only a diagnosis *because* prevote quorum was reached. Without it every
    /// validator is missing a precommit — they are cast only after prevote quorum — so flagging
    /// that would name the whole set and mean nothing.
    #[test]
    fn a_missing_precommit_without_prevote_quorum_is_not_reported() {
        assert_eq!(
            liveness_verdict(true, false, false),
            LivenessVerdict::Heard { missing_precommit: false },
            "no prevote quorum means nobody precommitted yet — that is the protocol working, \
             not a validator to name"
        );
    }

    /// Silence is the absence of *both* phases. A validator that only precommitted (its prevote
    /// lost in gossip) is still one we heard from.
    #[test]
    fn only_hearing_nothing_at_all_counts_as_silent() {
        assert_eq!(liveness_verdict(false, false, false), LivenessVerdict::Silent);
        assert_eq!(liveness_verdict(false, false, true), LivenessVerdict::Silent);
        assert_eq!(
            liveness_verdict(false, true, true),
            LivenessVerdict::Heard { missing_precommit: false },
            "a precommit is proof of life even if we never saw the prevote"
        );
    }

    /// The other half of the same rule, stated positively: silence is *reported*, never acted
    /// on. A peer that has said nothing for far longer than the old jail window keeps every bit
    /// of its voting power, so this node's quorum threshold never moves.
    #[test]
    fn a_silent_validator_keeps_its_voting_power_and_the_chain_waits() {
        let v = two_validators();
        let peer_addr = Address::from_public_key(&v.peer_kp.public);
        let expected_power = v.validator_set.get(&peer_addr).unwrap().voting_power;
        let quorum = v.validator_set.quorum_threshold();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);

        let _ = engine.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        for _ in 0..SILENT_ROUNDS {
            tick_to_timeout_and_advance(&mut engine, &v.self_kp);
        }

        assert_eq!(
            engine.validator_set.get(&peer_addr).unwrap().voting_power,
            expected_power,
            "silence is observational — it must not touch the voting power quorum is measured \
             against"
        );
        assert_eq!(engine.validator_set.quorum_threshold(), quorum, "the bar must not move");
        assert_eq!(engine.current_height(), 0, "and so the height must not advance alone");
        assert!(
            engine.missed_rounds.get(&peer_addr).copied().unwrap_or(0) >= SILENT_ROUNDS,
            "the silence must still be counted, so the node can name who it is waiting for"
        );
    }

    /// What `silent_peer_validators` counts, pinned at the boundary.
    ///
    /// The health line acts on this number: above zero it tells the operator that restarting
    /// *their* node will not help. Counting a single missed round would fire that on ordinary
    /// gossip delay and teach people to ignore it — the same way the old unconditional "restart"
    /// advice became noise.
    #[test]
    fn a_validator_is_not_counted_as_silent_after_one_missed_round() {
        let v = two_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let _ = engine.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);

        tick_to_timeout_and_advance(&mut engine, &v.self_kp);
        assert_eq!(
            engine.silent_peer_validators(),
            0,
            "one missed round is gossip delay or a restart, not a reason to tell somebody their \
             node is fine and someone else's is not"
        );

        for _ in 0..LIVENESS_SILENCE_WARN_ROUNDS {
            tick_to_timeout_and_advance(&mut engine, &v.self_kp);
        }
        assert_eq!(
            engine.silent_peer_validators(),
            1,
            "sustained silence is exactly what the health line needs to know about"
        );
    }

    /// A returning validator has to stop being reported as silent the moment it participates
    /// again — `record_round_liveness` alone cannot do it, since a validator that votes is
    /// exactly what stops rounds from timing out and running it.
    #[test]
    fn a_reconnecting_validator_stops_being_reported_as_silent() {
        let v = two_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let peer_addr = Address::from_public_key(&v.peer_kp.public);

        let _ = engine.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        for _ in 0..SILENT_ROUNDS {
            tick_to_timeout_and_advance(&mut engine, &v.self_kp);
        }
        assert!(
            engine.missed_rounds.contains_key(&peer_addr),
            "precondition: the peer must be recorded as silent before it returns"
        );

        // It reconnects and votes on the round currently in flight.
        let height = engine.current_height() + 1;
        let round = engine.pending_round; // privat, aber der Test liegt im selben Modul
        let block_hash = engine
            .pending_proposal()
            .map(|b| b.hash())
            .unwrap_or_else(|| Hash::digest(b"whatever-is-in-flight"));
        let _ = engine.add_vote(
            &v.self_kp,
            peer_vote(&v.peer_kp, VoteType::Prevote, height, round, block_hash),
        );

        assert!(
            !engine.missed_rounds.contains_key(&peer_addr),
            "one vote on the height being decided proves participation — a node that keeps \
             reporting it as silent sends its operator chasing an outage that has ended"
        );
    }

    /// A peer stuck on its own fork votes continuously, so it looks alive to any presence-based
    /// check, while none of its votes can ever be counted here. It must stay reported as silent:
    /// that report is what tells an operator the chain is stalled *on this peer* rather than
    /// waiting on nothing.
    #[test]
    fn a_peer_voting_on_a_different_history_is_still_reported_as_silent() {
        let v = two_validators();
        // Start at 10 so the peer can be genuinely behind us, the way a forked node is: it keeps
        // voting on its own tip while we have long moved past that height.
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 10);
        let peer_addr = Address::from_public_key(&v.peer_kp.public);

        let _ = engine.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        for _ in 0..SILENT_ROUNDS {
            let stale = peer_vote(
                &v.peer_kp,
                VoteType::Prevote,
                5, // we are deciding height 11
                0,
                Hash::digest(b"block-on-their-fork"),
            );
            let _ = engine.add_vote(&v.self_kp, stale);
            tick_to_timeout_and_advance(&mut engine, &v.self_kp);
        }

        assert!(
            engine.missed_rounds.get(&peer_addr).copied().unwrap_or(0) >= SILENT_ROUNDS,
            "votes on a height we are not deciding are not participation — counting them \
             reports a peer as healthy while the chain sits still"
        );
    }

    /// A peer that goes quiet for a while but votes again must have its counter reset to zero,
    /// not merely paused — otherwise a later, separate silence inherits the old credit and gets
    /// reported far sooner than it happened. Proves the reset in `record_round_liveness`, not
    /// just its increment.
    ///
    /// Asserted on `missed_rounds` directly, because since the liveness jail was removed the
    /// counter has no effect on the height: a test that watched `current_height()` here would
    /// pass no matter what the counter did.
    #[test]
    fn a_vote_partway_through_resets_the_missed_round_counter() {
        let v = two_validators();
        let peer_addr = Address::from_public_key(&v.peer_kp.public);
        let mut engine = BftEngine::new(v.validator_set, v.self_addr.clone(), 0);

        let _ = engine.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        engine.take_outbound_votes();

        // Build up a few rounds of silence to have something that could carry over.
        for _ in 0..5 {
            tick_to_timeout_and_advance(&mut engine, &v.self_kp);
        }
        assert_eq!(
            engine.missed_rounds.get(&peer_addr).copied(),
            Some(5),
            "precondition: five silent rounds must have been counted"
        );

        // Open (or confirm) a round for the current pending round, exactly as `prevote_nil`
        // would at this round's proposal window — needed to know the real round number to
        // target; `active_round_num()` is `None` right after the loop above, since the last
        // `advance_round` call always clears `self.round` before returning.
        //
        // The window is asked for by round rather than hardcoded to `PROPOSAL_TIMEOUT_TICKS`:
        // it widens with the round (see `proposal_timeout_ticks`), and by here this engine is
        // five rounds in.
        for _ in 0..proposal_timeout_ticks(engine.pending_round()) {
            engine.note_round_tick(&v.self_kp);
        }
        engine.take_outbound_votes();

        // Peer reconnects and votes for whatever this node currently has active — nil if
        // self is mid-wait, the real value if self is mid-proposal; either counts as "voted".
        let active_round = engine.active_round_num().expect("a round must be open by now");
        let target_hash = engine
            .pending_proposal()
            .map(|b| b.hash())
            .unwrap_or(NIL_BLOCK_HASH);
        let peer_prevote = peer_vote(&v.peer_kp, VoteType::Prevote, 1, active_round, target_hash);
        let _ = engine.add_vote(&v.self_kp, peer_prevote);
        engine.take_outbound_votes();

        // Finish out this round (which now holds the peer's vote) and advance. The peer voted,
        // so `record_round_liveness` must clear it — and then the *next* silent round has to
        // start over at 1, not resume at 6.
        loop {
            if engine.note_round_tick(&v.self_kp) {
                break;
            }
        }
        engine.take_outbound_votes();
        let _ = engine.advance_round(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        engine.take_outbound_votes();
        assert_eq!(
            engine.missed_rounds.get(&peer_addr).copied().unwrap_or(0),
            0,
            "a round the peer voted in must clear its counter outright"
        );

        tick_to_timeout_and_advance(&mut engine, &v.self_kp);
        assert_eq!(
            engine.missed_rounds.get(&peer_addr).copied(),
            Some(1),
            "the next silence must start from scratch — carrying credit over would report a \
             peer that has been gone for one round as gone for six"
        );
    }


    // ── Round synchronization (2026-08-26): the freeze a fixed round window caused ──────────

    /// **The equivocation the signing guard was catching twice per run.** A node that is the
    /// proposer for a round must not nil-prevote it: the block-production loop calls
    /// `note_round_tick` and then, in the same tick, `produce_block`. With nil cast first, `propose`
    /// builds a fresh round over it and casts a prevote for the real block at the same
    /// (height, round) — two different prevotes, one round, which is exactly what gets a validator
    /// slashed 5 %. Only the persisted `SigningGuard` stopped it from going out, and it stopped the
    /// *useful* one: the proposer's own prevote for its own block.
    ///
    /// Mutation check: remove the `is_proposer` guard in `prevote_nil` and this fails.
    #[test]
    fn the_proposer_of_a_round_never_prevotes_nil_in_it() {
        let v = two_validators();
        // `two_validators` puts `self_addr` at the index that proposes height 1, round 0.
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        assert!(
            engine.validator_set.is_proposer(&v.self_addr, 1, 0),
            "precondition: this node is the proposer for height 1 round 0"
        );

        // Run the clock past the nil window without ever proposing — the state the loop is in when
        // it has been held back a tick or two (sync gate, peer wait) before `produce_block` runs.
        for _ in 0..proposal_timeout_ticks(0) + 3 {
            engine.note_round_tick(&v.self_kp);
        }

        let cast = engine.take_outbound_votes();
        assert!(
            cast.is_empty(),
            "the proposer gave up on a proposal that is its own to make and cast {} vote(s): {:?}",
            cast.len(),
            cast.iter().map(|c| (c.round, c.block_hash)).collect::<Vec<_>>()
        );

        // …and the proposal it then makes carries exactly one prevote, its own, uncontested.
        engine
            .produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![])
            .expect_err("a two-validator set awaits the peer's vote");
        let after = engine.take_outbound_votes();
        assert_eq!(after.len(), 1, "exactly one prevote for the proposed block");
        assert_ne!(
            after[0].block_hash, NIL_BLOCK_HASH,
            "and it must be for the block, not nil — a nil here is the equivocation"
        );
    }


    /// The windows must actually widen. Two validators with a fixed window burn rounds at
    /// identical rates, so a phase offset between their clocks survives forever and each one's
    /// proposal always lands in a round the other has already left — measured live, height 300,
    /// both nodes healthy and agreeing on everything but the round number.
    ///
    /// Mutation check: set `PROPOSAL_TIMEOUT_STEP_TICKS`/`ROUND_TIMEOUT_STEP_TICKS` to 0 and this
    /// fails.
    #[test]
    fn a_later_round_waits_longer_than_an_earlier_one() {
        assert!(
            proposal_timeout_ticks(3) > proposal_timeout_ticks(0),
            "a later round must give the proposal more time, or two drifted validators never meet"
        );
        assert!(
            round_timeout_ticks(3) > round_timeout_ticks(0),
            "the backstop has to widen with it, or the wider proposal window is simply cut off"
        );
        // The nil prevote must still be cast strictly inside its own round, at every round.
        for round in [0, 1, 5, TIMEOUT_BACKOFF_MAX_ROUNDS, TIMEOUT_BACKOFF_MAX_ROUNDS + 50] {
            assert!(
                proposal_timeout_ticks(round) < round_timeout_ticks(round),
                "round {round}: nil has to be cast before the backstop fires"
            );
        }
        assert_eq!(
            proposal_timeout_ticks(TIMEOUT_BACKOFF_MAX_ROUNDS + 1_000),
            proposal_timeout_ticks(TIMEOUT_BACKOFF_MAX_ROUNDS),
            "growth stops at the cap — a chain that spent thousands of rounds on one height must \
             not come back with windows measured in hours"
        );
    }

    /// Tendermint's round-skip rule: enough voting power in a later round is proof the network is
    /// there, and this node follows rather than waiting out a round nobody else is in.
    ///
    /// Mutation check: remove the `peer_round_to_jump_to` call in `add_vote` and this fails.
    #[test]
    fn a_vote_from_a_round_ahead_pulls_this_node_forward() {
        let v = two_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        assert_eq!(engine.pending_round(), 0, "precondition: this node starts at round 0");

        let ahead = peer_vote(&v.peer_kp, VoteType::Prevote, 1, 7, NIL_BLOCK_HASH);
        engine.add_vote(&v.self_kp, ahead).expect("a vote from a later round is not an error");

        assert_eq!(
            engine.pending_round(),
            7,
            "half the set voting in round 7 is where the round is — sitting in round 0 waiting \
             for a proposal nobody will make again is the freeze this rule exists to end"
        );
    }

    /// The jump counts *verified* votes only. Buffered votes are not checked when they arrive
    /// (only on replay, inside `VoteSet::add`), so without the signature check here a single
    /// forged message would move this node to any round its sender liked.
    #[test]
    fn a_forged_vote_cannot_drag_this_node_to_another_round() {
        let v = two_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);

        let mut forged = peer_vote(&v.peer_kp, VoteType::Prevote, 1, 9, NIL_BLOCK_HASH);
        // Signed for round 9, presented as round 11: the signature no longer matches the content.
        forged.round = 11;
        engine.add_vote(&v.self_kp, forged).expect("a vote we cannot use is not an error");

        assert_eq!(
            engine.pending_round(),
            0,
            "an unverifiable vote is not evidence of anything"
        );
    }

    /// A probationer holds zero voting power by construction (#132), so where it happens to be is
    /// no evidence of where the quorum is — and following it would hand a stake with no chain
    /// weight behind it the power to move everyone else's rounds.
    ///
    /// Mutation check, stated precisely because neither obvious single-line mutation makes this
    /// red — measured, not assumed. Deleting the `voting_power == 0` short-circuit leaves it green
    /// (a zero-power vote adds zero to the sum either way), and switching the threshold to a vote
    /// *count* leaves it green too (the short-circuit already dropped the probationer). Only both
    /// together turn it red, which is the honest description of this test: it pins the behaviour
    /// against two independent guards, not one implementation detail.
    #[test]
    fn a_zero_power_probationer_cannot_pull_the_set_to_its_round() {
        let (full_kp, full_addr, probationer_kp, _, set) = full_power_plus_probationer();
        let mut engine = BftEngine::new(set, full_addr, 0);

        let ahead = peer_vote(&probationer_kp, VoteType::Prevote, 1, 12, NIL_BLOCK_HASH);
        engine.add_vote(&full_kp, ahead).expect("a probationer's vote is not an error");

        assert_eq!(engine.pending_round(), 0, "zero power proves nothing about the round");
    }

    /// The pull is asked for only when it can help: not on the tick the round opened (the
    /// proposal may still be in flight), never when the proposal is ours to make, and — the
    /// ordering that matters — *before* this node prevotes nil, because a round closed for nil
    /// can no longer accept the answer.
    #[test]
    fn a_missing_proposal_is_only_reported_once_waiting_for_it_stopped_being_normal() {
        let v = two_validators();
        // Round 0 of height 1 belongs to `self_addr` (see `two_validators`), so start at round 1,
        // where this node is *not* the proposer and has to wait for one.
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let _ = engine.advance_round(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        engine.take_outbound_votes();
        assert_eq!(engine.pending_round(), 1);

        assert_eq!(
            engine.missing_proposal(),
            None,
            "a round that just opened has a proposal in flight, not a missing one"
        );

        engine.note_round_tick(&v.self_kp);
        engine.take_outbound_votes();

        assert_eq!(
            engine.missing_proposal(),
            Some((1, 1)),
            "a tick later it is not coming by itself — gossip publishes once, and the re-offer \
             is refused as a duplicate"
        );

        // …and the asking has to stop once nil is cast: `open_for_nil_prevote` closes the round to
        // proposals, so from here an answer could only be discarded. Measured 2026-08-26: eight
        // answers carrying the proposal, all thrown away, while the height stood still.
        for _ in 0..proposal_timeout_ticks(1) {
            engine.note_round_tick(&v.self_kp);
        }
        engine.take_outbound_votes();
        assert_eq!(
            engine.missing_proposal(),
            None,
            "after prevoting nil this node cannot use a proposal for this round — asking anyway \
             is one wasted request per tick"
        );
    }

    /// The proposer of a round has nothing to ask anyone for.
    #[test]
    fn the_proposer_never_asks_a_peer_for_its_own_proposal() {
        let v = two_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        // Round 0 of height 1 is this node's turn.
        for _ in 0..proposal_timeout_ticks(0) + 5 {
            engine.note_round_tick(&v.self_kp);
        }
        engine.take_outbound_votes();

        assert_eq!(engine.missing_proposal(), None, "we are the one who makes it");
    }

    /// What a peer gets when it asks: the proposal we hold and the votes we have seen — and
    /// nothing at all for a height we are not deciding, which block sync serves with a quorum
    /// certificate instead.
    #[test]
    fn round_evidence_serves_the_pending_proposal_and_stays_empty_for_other_heights() {
        let v = two_validators();
        let mut engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let _ = engine.produce_block(&v.self_kp, Hash::digest(b"genesis"), vec![]);
        engine.take_outbound_votes();

        let (proposal, votes) = engine.round_evidence(1);
        assert!(proposal.is_some(), "the height being decided must be servable");
        assert!(
            votes.iter().any(|vote| vote.validator == v.self_addr),
            "our own prevote is part of what a peer is missing"
        );

        let (nothing, none) = engine.round_evidence(2);
        assert!(nothing.is_none() && none.is_empty(), "we hold no round for another height");
    }

    /// A value locked in a *later* round than the one it was proposed in must still be
    /// re-proposable. `locked_round` is the round a prevote quorum formed in — not the round
    /// the block was proposed in — and the two differ whenever a round reaches a prevote
    /// quorum but not a precommit quorum, which is the ordinary outcome of a lost precommit.
    ///
    /// Live incident 2026-09-01: the chain stalled twice this way (heights 276420 and 280939,
    /// 39 minutes and 21+ minutes). Every peer refused the same re-proposal with "is not the
    /// proposer for height N round R", with R frozen at the lock round while the rounds
    /// themselves kept climbing — the signature of a `valid_round` that no longer matches the
    /// block's proposing round. Nothing recovers on its own from there: every later round
    /// re-proposes the same locked value with the same `valid_round`, and every peer rejects
    /// it for the same reason.
    #[test]
    fn a_value_locked_in_a_later_round_than_it_was_proposed_in_is_still_re_proposable() {
        let v = four_validators();
        let engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);

        // Block A is proposed by `self`, height 1's round-0 proposer ((1 + 0) % 4 == 1).
        let (_locked, block_a, hash_a) = locked_self_engine(&v);
        assert!(v.validator_set.is_proposer(&v.self_addr, 1, 0));

        // Round 0 lost its precommits, so round 1 re-proposed A and *that* round is where the
        // prevote quorum formed. b — not self — is round 1's proposer ((1 + 1) % 4 == 2), so
        // the lock round and the block's proposing round now name different validators.
        let b_addr = Address::from_public_key(&v.b_kp.public);
        assert!(v.validator_set.is_proposer(&b_addr, 1, 1));
        let pol_round_1 = vec![
            peer_vote(&v.a_kp, VoteType::Prevote, 1, 1, hash_a.clone()),
            peer_vote(&v.b_kp, VoteType::Prevote, 1, 1, hash_a.clone()),
            peer_vote(&v.c_kp, VoteType::Prevote, 1, 1, hash_a.clone()),
        ];
        engine
            .verify_pol(&pol_round_1, &hash_a, 1, 1)
            .expect("three of four prevotes is a genuine quorum for round 1");

        // Round 2's proposer re-proposes A carrying that certificate. The POL is what proves
        // the network locked this value in round 1; A's header names round 0's proposer
        // because that is who built it, and no rule says those have to be the same validator.
        engine
            .validate_block(&block_a, 2, Some(1), &pol_round_1)
            .expect("a re-proposal backed by a genuine POL must be accepted");
    }

    /// The bound the proposer check used to supply for re-proposals, now standing on its own:
    /// a proof-of-lock can only come from a round already left behind. Without it a replayed
    /// certificate could name any round at all, and `receive_proposal` adopts a proposal's
    /// round as its own — so one recorded POL would let anyone drag every node to an arbitrary
    /// round number for the rest of the height.
    #[test]
    fn a_reproposal_claiming_a_lock_from_its_own_or_a_later_round_is_refused() {
        let v = four_validators();
        let engine = BftEngine::new(v.validator_set.clone(), v.self_addr.clone(), 0);
        let (_locked, block_a, hash_a) = locked_self_engine(&v);

        // A genuine round-1 certificate — the same one the test above proves is acceptable
        // when it backs a *later* round.
        let pol = vec![
            peer_vote(&v.a_kp, VoteType::Prevote, 1, 1, hash_a.clone()),
            peer_vote(&v.b_kp, VoteType::Prevote, 1, 1, hash_a.clone()),
            peer_vote(&v.c_kp, VoteType::Prevote, 1, 1, hash_a.clone()),
        ];
        engine.validate_block(&block_a, 2, Some(1), &pol).expect("round 2 > lock round 1 is fine");

        for claimed in [1u32, 0] {
            let err = engine.validate_block(&block_a, claimed, Some(1), &pol).unwrap_err();
            match err {
                ConsensusError::InvalidBlock { reason, .. } => assert!(
                    reason.contains("a lock can only come from a round already past"),
                    "round {claimed} against a round-1 lock must be refused for the lock \
                     ordering, got: {reason}"
                ),
                other => panic!("expected InvalidBlock for round {claimed}, got {other:?}"),
            }
        }
    }
    /// The distinction the whole attendance line exists for, and the one nothing in the log made
    /// on 2026-09-04: "the votes were not there" against "the votes were there and the round still
    /// did not close". Those are different failures with different fixes, and six and a half hours
    /// of log could not tell them apart.
    #[test]
    fn attendance_says_whether_the_round_could_have_closed_at_all() {
        let a = Address::from_public_key(&KeyPair::generate().public);
        let b = Address::from_public_key(&KeyPair::generate().public);
        let c = Address::from_public_key(&KeyPair::generate().public);
        let d = Address::from_public_key(&KeyPair::generate().public);

        // Five validators of 500 each, quorum 1667 — four have to be heard from.
        let quorum = 1667;
        let heard_from_three = round_attendance(
            &[(a.clone(), 500, true), (b.clone(), 500, true), (c.clone(), 500, false), (d.clone(), 500, false)],
            500,
            quorum,
            false,
        );
        assert_eq!(heard_from_three.power_heard, 1500, "own 500 plus the two heard from");
        assert!(
            !heard_from_three.enough_power_heard(),
            "1500 is under the quorum of {quorum}: this round could not have closed, and the two \
             silent validators are the reason"
        );
        assert_eq!(heard_from_three.silent, vec![c.clone(), d.clone()]);

        let heard_from_four = round_attendance(
            &[(a, 500, true), (b, 500, true), (c, 500, true), (d.clone(), 500, false)],
            500,
            quorum,
            true,
        );
        assert!(
            heard_from_four.enough_power_heard(),
            "2000 clears the quorum — a round that still failed here is not a missing-votes problem"
        );
        assert_eq!(heard_from_four.silent, vec![d]);
    }

    /// A node that did not vote itself must not credit itself with power the round never had.
    /// Getting this backwards would report "there was enough power" for a round this node sat out,
    /// which is the one reading that sends a diagnosis away from the node that is actually broken.
    #[test]
    fn a_node_that_did_not_vote_does_not_count_its_own_power() {
        let a = Address::from_public_key(&KeyPair::generate().public);
        let silent_self = round_attendance(&[(a.clone(), 500, true)], 0, 900, false);
        assert_eq!(silent_self.power_heard, 500, "only what actually voted");
        assert!(!silent_self.enough_power_heard());

        let voting_self = round_attendance(&[(a, 500, true)], 500, 900, false);
        assert_eq!(voting_self.power_heard, 1000);
        assert!(voting_self.enough_power_heard());
    }

}
