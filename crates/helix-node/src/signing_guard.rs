//! Double-sign protection: a durably persisted high-water mark of the last position this
//! validator signed a vote at, so a restart — or a second process started with a copy of the
//! same key — can never broadcast a *conflicting* vote at a position it has already signed.
//!
//! This is the standard defence every serious validator runs (Tendermint calls it
//! `priv_validator_state.json`). Helix lacked it, and on 2026-07-23 two honest operators were
//! slashed 5% for nothing more than restarting their node: `hlxRy5cA…` at height 32484 and
//! `hlxcjmGL…` at height 48089, both at round 0 — the fingerprint of an equivocation produced by
//! a second instance / a lost round state, not by malice. `CommitSig::verify` only stops forged
//! signatures; nothing stopped a validator from *honestly* signing the same height twice across a
//! restart. This closes that gap.
//!
//! ## Why this lives on the broadcast path, not in the consensus engine
//!
//! Double-sign evidence is only ever manufactured from two conflicting votes a *peer* observes
//! (`helix_consensus::VoteSet::add_vote`). A vote a node never gossips can never become evidence
//! against it. So guarding the single point where outbound votes leave the node
//! (`broadcast_outbound_votes`) is sufficient to prevent the slash, and keeps the BFT engine — the
//! highest-blast-radius code in the tree — completely untouched.
//!
//! ## The state file lives next to `validator-key.json`, not in the chain data dir
//!
//! It belongs to the *signing identity*, not to a particular copy of the chain: a validator that
//! wipes its data dir and re-syncs must still remember what its key already signed.

use std::path::PathBuf;

use helix_consensus::{Vote, VoteType};
use helix_crypto::Hash;
use serde::{Deserialize, Serialize};
use tracing::error;

/// A signable position within the BFT protocol, **totally ordered** as `(height, round, step)`.
/// `step` orders the two vote phases inside one round: a prevote (1) always precedes a precommit
/// (2). Field order matters — the derived `Ord` compares height first, then round, then step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct Position {
    height: u64,
    round: u32,
    step: u8,
}

fn step_of(vote_type: &VoteType) -> u8 {
    match vote_type {
        VoteType::Prevote => 1,
        VoteType::Precommit => 2,
    }
}

/// The last position signed, plus the value signed there. Serialized as the on-disk state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedState {
    position: Position,
    /// The block hash signed at `position`. An identical re-sign (same hash) is allowed — that is
    /// a harmless gossip re-send, not equivocation — but a *different* hash at the same position
    /// is exactly the double-sign we refuse.
    block_hash: Hash,
    /// The chain this state belongs to — the genesis block's hash. A persisted mark from a
    /// *different* genesis (a reset to a brand-new chain that reuses this key) is discarded on
    /// load, because the old chain's heights are unrelated to the new one: keeping it left the
    /// validator refusing every vote on the reset chain until it climbed past the old high-water
    /// mark — the "bonded but silent" stall diagnosed live on 2026-07-26 (a key last signed at
    /// height ~48089 on a chain that was then reset to genesis could not vote again until #48089).
    /// Within one chain this is constant, so it never weakens the cross-restart double-sign
    /// protection: a restart on the *same* chain still carries the mark forward. A pre-upgrade
    /// state file without this field simply fails to parse and falls back to the chain-height
    /// floor (see [`load`]) — safe, since the floor already forbids signing at or below the tip.
    chain_id: Hash,
}

/// Outcome of checking a candidate vote against the high-water mark.
///
/// The two refusals are kept apart because they mean opposite things to whoever reads the log.
/// They were one variant with one message until 2026-08-26, and that message asserted the wrong
/// one: every withheld vote was reported as "already signed a different value … (most likely a
/// restart)" — including the 30-odd per four-validator test run where nothing had restarted at
/// all. An operator who reads that goes looking for a second node holding a copy of their key.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Safe to broadcast this vote.
    Allow,
    /// A *different value* at a position this key has already signed. This is the real
    /// equivocation case, and the one that means "a second node may be running with this key".
    RefuseConflict,
    /// A position *below* the high-water mark: this key has already signed further ahead than the
    /// vote being offered. Not equivocation in itself — the engine is behind where the key has
    /// been, which is what a restart, a round that was left, or a catch-up looks like. Refused
    /// anyway, because signing backwards is exactly how a fork gets two signatures.
    RefuseRegression,
}

impl Decision {
    /// Whether this decision withholds the vote.
    pub fn is_refusal(&self) -> bool {
        !matches!(self, Decision::Allow)
    }
}

pub struct SigningGuard {
    /// `None` disables the guard entirely (permit everything, persist nothing). Only for tests
    /// and non-signing nodes — a real validator always loads a `Some` path via [`load`].
    path: Option<PathBuf>,
    last: SignedState,
    /// The genesis hash of the chain this guard is running on. Stamped into every state it
    /// persists and compared on load, so a mark from a different chain is never applied here.
    chain_id: Hash,
}

impl SigningGuard {
    /// A guard that permits every vote and writes no state — for tests. (A real validator always
    /// goes through [`load`]; a pure follower never casts a vote, so its `outbound` is empty and
    /// the guard is never even consulted.)
    #[cfg(test)]
    pub fn unguarded() -> Self {
        SigningGuard {
            path: None,
            last: SignedState {
                position: Position { height: 0, round: 0, step: 0 },
                block_hash: Hash::ZERO,
                chain_id: Hash::ZERO,
            },
            chain_id: Hash::ZERO,
        }
    }

    /// Load the persisted high-water mark, seeding a conservative floor at `chain_height` so that
    /// even a fresh install (no state file yet) can never sign at or below the already-committed
    /// tip. The floor pins `round`/`step` to their maxima, so the first vote it will ever permit
    /// is `(chain_height + 1, 0, prevote)`.
    ///
    /// A present, parseable file that sits *above* the floor wins — it additionally remembers the
    /// exact round/step/value within the height the node was mid-signing when it stopped. An
    /// unreadable file falls back to the floor with a loud error rather than refusing to start:
    /// the floor alone already prevents the overwhelmingly common restart case, and bricking a
    /// validator on a stat/parse hiccup would be its own outage.
    /// `chain_id` is the genesis hash of the chain this node is running. A persisted mark whose
    /// `chain_id` differs is from another chain (a reset that reused this key) and is discarded in
    /// favour of the floor — otherwise the old chain's far-higher heights would make every vote on
    /// the new chain look like a regression and the validator would sit bonded-but-silent forever.
    pub fn load(path: PathBuf, chain_height: u64, chain_id: Hash) -> Self {
        let floor = SignedState {
            position: Position { height: chain_height, round: u32::MAX, step: u8::MAX },
            block_hash: Hash::ZERO,
            chain_id,
        };
        let last = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<SignedState>(&bytes) {
                // A mark from a *different* genesis is meaningless here — the old chain's votes can
                // never be equivocation on this one. Reset to the floor so a genesis reset doesn't
                // permanently gag this validator; double-sign protection continues on the new chain.
                Ok(state) if state.chain_id != chain_id => {
                    tracing::info!(
                        path = %path.display(),
                        "signing-state belongs to a different chain (genesis hash changed) — \
                         resetting the double-sign high-water mark to this chain's floor. This is \
                         expected after a chain reset; protection continues on the new chain."
                    );
                    floor
                }
                Ok(state) if state.position > floor.position => state,
                Ok(_) => floor, // stale file at/below the chain tip — the floor is safer
                Err(e) => {
                    error!(
                        err = %e, path = %path.display(),
                        "signing-state file is unreadable (or predates chain-id tagging) — falling \
                         back to the chain-height floor; inspect it if this validator was ever \
                         unexpectedly slashed"
                    );
                    floor
                }
            },
            Err(_) => floor, // no file yet: first run under this feature
        };
        SigningGuard { path: Some(path), last, chain_id }
    }

    /// Decide whether `vote` is safe to broadcast, durably advancing the high-water mark first
    /// when it does. Never returns `Allow` for a *different* value at or below a position already
    /// signed. A durable-write failure is treated as `Refuse` — if we cannot record that we signed
    /// here, a later restart would not know either, so allowing it would reopen the exact hole
    /// this guard closes.
    /// The `(height, round)` this key last signed at, if it is guarded at all.
    ///
    /// Read at startup so the engine can resume above it rather than below — see
    /// `BftEngine::resume_at_round` for why coming back *under* this mark gags the node.
    /// The position and value this key last signed — for the one log line that has to name both
    /// sides of a conflict. Without it "already signed a different value" is a claim the reader
    /// cannot check, and the two real conflicts per four-validator run (measured 2026-08-26) are
    /// indistinguishable from the 26 harmless stale ones.
    pub fn last_signed_detail(&self) -> Option<(u64, u32, u8, Hash)> {
        self.path.as_ref()?;
        Some((
            self.last.position.height,
            self.last.position.round,
            self.last.position.step,
            self.last.block_hash,
        ))
    }

    pub fn last_signed(&self) -> Option<(u64, u32)> {
        self.path.as_ref()?;
        Some((self.last.position.height, self.last.position.round))
    }

    pub fn check(&mut self, vote: &Vote) -> Decision {
        let Some(path) = self.path.clone() else {
            return Decision::Allow; // unguarded (tests / non-signing nodes)
        };
        let pos = Position {
            height: vote.height,
            round: vote.round,
            step: step_of(&vote.vote_type),
        };

        if pos < self.last.position {
            return Decision::RefuseRegression; // e.g. a restart resuming on an older height
        }
        if pos == self.last.position {
            // Same slot: only a byte-identical re-send is safe.
            return if vote.block_hash == self.last.block_hash {
                Decision::Allow
            } else {
                Decision::RefuseConflict
            };
        }

        // The position advances the high-water mark: record it durably *before* allowing it out.
        let state = SignedState { position: pos, block_hash: vote.block_hash, chain_id: self.chain_id };
        if let Err(e) = Self::persist(&path, &state) {
            error!(err = %e, "could not persist signing state — refusing the vote to stay safe");
            // A regression, in the sense that matters here: the mark did not move, so nothing may
            // go out on top of it.
            return Decision::RefuseRegression;
        }
        self.last = state;
        Decision::Allow
    }

    /// Atomically replace the state file: write a sibling temp file, fsync it, then rename over
    /// the target. A crash can leave the temp file behind but never a torn state file.
    fn persist(path: &PathBuf, state: &SignedState) -> std::io::Result<()> {
        use std::io::Write;
        let bytes = serde_json::to_vec(state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut tmp = path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::KeyPair;

    fn vote(height: u64, round: u32, vote_type: VoteType, hash: Hash) -> Vote {
        let kp = KeyPair::generate();
        Vote {
            vote_type,
            height,
            round,
            block_hash: hash,
            validator: helix_crypto::Address::from_public_key(&kp.public),
            public_key: kp.public.clone(),
            crypto_version: kp.scheme,
            signature: helix_crypto::Signature::from_bytes(vec![]),
        }
    }

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn guard(height: u64) -> (SigningGuard, tempdir::Guard) {
        let dir = tempdir::Guard::new();
        (SigningGuard::load(dir.path(), height, hash(0xAA)), dir)
    }

    #[test]
    fn allows_a_first_vote_above_the_floor() {
        let (mut g, _d) = guard(100);
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(1))), Decision::Allow);
    }

    #[test]
    fn refuses_a_conflicting_vote_at_the_same_slot() {
        let (mut g, _d) = guard(100);
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(1))), Decision::Allow);
        // Same height/round/step, different value — the double-sign we exist to stop.
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(2))), Decision::RefuseConflict);
    }

    /// Why `BftEngine::resume_at_round` exists, stated as the guard sees it.
    ///
    /// After a restart the engine rejoins wherever the network is, which can be below the round
    /// this key already signed. Every vote there is refused — correctly, a value was signed at that
    /// round already and signing another is the slash two operators took in July. The node is
    /// simply mute until the network climbs back past the mark. Resuming *above* it is what makes
    /// the difference between voting now and voting in three and a half minutes.
    #[test]
    fn a_vote_below_the_mark_is_refused_while_one_above_it_is_allowed() {
        let (mut g, _d) = guard(100);
        // Climb to round 10 at height 101, as a validator does while a chain is stalled.
        assert_eq!(g.check(&vote(101, 10, VoteType::Prevote, hash(1))), Decision::Allow);

        // Rejoining at round 7 after a restart: refused, and rightly so.
        assert_eq!(g.check(&vote(101, 7, VoteType::Prevote, hash(2))), Decision::RefuseRegression);
        assert_eq!(g.check(&vote(101, 9, VoteType::Prevote, hash(2))), Decision::RefuseRegression);

        // Resuming above the mark instead: allowed immediately.
        assert_eq!(g.check(&vote(101, 11, VoteType::Prevote, hash(2))), Decision::Allow);
    }

    /// The mark has to be readable, or the engine cannot resume above something it cannot see.
    #[test]
    fn the_last_signed_position_is_reportable() {
        let (mut g, _d) = guard(100);
        assert_eq!(g.check(&vote(101, 10, VoteType::Prevote, hash(1))), Decision::Allow);
        assert_eq!(g.last_signed(), Some((101, 10)));
    }

    /// An unguarded node has no mark to resume from, and must not invent one.
    #[test]
    fn an_unguarded_node_reports_no_mark() {
        assert_eq!(SigningGuard::unguarded().last_signed(), None);
    }

    #[test]
    fn allows_an_identical_resend_at_the_same_slot() {
        let (mut g, _d) = guard(100);
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(1))), Decision::Allow);
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(1))), Decision::Allow);
    }

    #[test]
    fn prevote_then_precommit_in_the_same_round_both_pass() {
        let (mut g, _d) = guard(100);
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(1))), Decision::Allow);
        assert_eq!(g.check(&vote(101, 0, VoteType::Precommit, hash(1))), Decision::Allow);
    }

    #[test]
    fn refuses_a_precommit_then_a_prevote_regression_in_the_same_round() {
        let (mut g, _d) = guard(100);
        assert_eq!(g.check(&vote(101, 0, VoteType::Precommit, hash(1))), Decision::Allow);
        // A prevote (step 1) after a precommit (step 2) at the same height/round is a step
        // regression — refuse it.
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(1))), Decision::RefuseRegression);
    }

    #[test]
    fn refuses_everything_at_or_below_the_chain_height_floor() {
        let (mut g, _d) = guard(100);
        // The tip (height 100) is already committed — the node must never vote there again.
        assert_eq!(g.check(&vote(100, 0, VoteType::Prevote, hash(1))), Decision::RefuseRegression);
        assert_eq!(g.check(&vote(50, 5, VoteType::Precommit, hash(1))), Decision::RefuseRegression);
    }

    #[test]
    fn a_later_round_after_a_conflict_still_advances() {
        let (mut g, _d) = guard(100);
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(1))), Decision::Allow);
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(2))), Decision::RefuseConflict);
        // Round 1 is a strictly higher position — a fresh, legitimate vote.
        assert_eq!(g.check(&vote(101, 1, VoteType::Prevote, hash(2))), Decision::Allow);
    }

    #[test]
    fn the_high_water_mark_survives_a_reload() {
        let dir = tempdir::Guard::new();
        {
            let mut g = SigningGuard::load(dir.path(), 100, hash(0xAA));
            assert_eq!(g.check(&vote(101, 2, VoteType::Precommit, hash(7))), Decision::Allow);
        }
        // A "restart" on the SAME chain (same chain_id): a new guard over the same file must
        // refuse a conflicting re-sign at 101/2.
        let mut g = SigningGuard::load(dir.path(), 100, hash(0xAA));
        assert_eq!(g.check(&vote(101, 2, VoteType::Precommit, hash(9))), Decision::RefuseConflict);
        // …and the identical value is still fine.
        assert_eq!(g.check(&vote(101, 2, VoteType::Precommit, hash(7))), Decision::Allow);
    }

    /// A genesis reset (a new chain that reuses the same validator key) must clear the high-water
    /// mark. Keeping it left the validator refusing every vote on the reset chain until it climbed
    /// past the old height — the "bonded but silent" stall diagnosed live on 2026-07-26, where a
    /// key that had signed up to ~#48089 on the pre-reset chain could not vote on the fresh chain
    /// at #1501. On the pre-fix code this final assertion was `Refuse`.
    #[test]
    fn a_reset_to_a_new_genesis_clears_the_high_water_mark() {
        let dir = tempdir::Guard::new();
        {
            // Chain A: sign high up, exactly as the stalled validator had.
            let mut g = SigningGuard::load(dir.path(), 100, hash(0xAA));
            assert_eq!(g.check(&vote(48089, 0, VoteType::Precommit, hash(1))), Decision::Allow);
        }
        // Reset to chain B (different genesis hash), back at a low tip. The stale #48089 mark from
        // chain A must NOT gag this validator here — the old chain's votes can't be equivocation
        // on this one.
        let mut g = SigningGuard::load(dir.path(), 1500, hash(0xBB));
        assert_eq!(g.check(&vote(1501, 0, VoteType::Prevote, hash(2))), Decision::Allow);
        // …and within chain B, double-sign protection is fully back: a conflicting re-sign at the
        // same slot is still refused.
        assert_eq!(g.check(&vote(1501, 0, VoteType::Prevote, hash(3))), Decision::RefuseConflict);
    }

    /// Minimal self-cleaning temp path helper — avoids a dev-dependency just for these tests.
    mod tempdir {
        use std::path::PathBuf;
        pub struct Guard(PathBuf);
        impl Guard {
            pub fn new() -> Self {
                let p = std::env::temp_dir().join(format!(
                    "helix-signing-guard-{}-{}.json",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                Guard(p)
            }
            pub fn path(&self) -> PathBuf {
                self.0.clone()
            }
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
                let mut tmp = self.0.clone().into_os_string();
                tmp.push(".tmp");
                let _ = std::fs::remove_file(PathBuf::from(tmp));
            }
        }
    }
}
