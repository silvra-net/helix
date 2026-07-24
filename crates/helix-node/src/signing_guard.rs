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
}

/// Outcome of checking a candidate vote against the high-water mark.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Safe to broadcast this vote.
    Allow,
    /// Broadcasting this vote would equivocate (a different value at, or a regression below, a
    /// position already signed) — drop it.
    Refuse,
}

pub struct SigningGuard {
    /// `None` disables the guard entirely (permit everything, persist nothing). Only for tests
    /// and non-signing nodes — a real validator always loads a `Some` path via [`load`].
    path: Option<PathBuf>,
    last: SignedState,
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
            },
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
    pub fn load(path: PathBuf, chain_height: u64) -> Self {
        let floor = SignedState {
            position: Position { height: chain_height, round: u32::MAX, step: u8::MAX },
            block_hash: Hash::ZERO,
        };
        let last = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<SignedState>(&bytes) {
                Ok(state) if state.position > floor.position => state,
                Ok(_) => floor, // stale file at/below the chain tip — the floor is safer
                Err(e) => {
                    error!(
                        err = %e, path = %path.display(),
                        "signing-state file is unreadable — falling back to the chain-height floor; \
                         inspect it if this validator was ever unexpectedly slashed"
                    );
                    floor
                }
            },
            Err(_) => floor, // no file yet: first run under this feature
        };
        SigningGuard { path: Some(path), last }
    }

    /// Decide whether `vote` is safe to broadcast, durably advancing the high-water mark first
    /// when it does. Never returns `Allow` for a *different* value at or below a position already
    /// signed. A durable-write failure is treated as `Refuse` — if we cannot record that we signed
    /// here, a later restart would not know either, so allowing it would reopen the exact hole
    /// this guard closes.
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
            return Decision::Refuse; // regression, e.g. a restart resuming on an older height
        }
        if pos == self.last.position {
            // Same slot: only a byte-identical re-send is safe.
            return if vote.block_hash == self.last.block_hash {
                Decision::Allow
            } else {
                Decision::Refuse
            };
        }

        // The position advances the high-water mark: record it durably *before* allowing it out.
        let state = SignedState { position: pos, block_hash: vote.block_hash };
        if let Err(e) = Self::persist(&path, &state) {
            error!(err = %e, "could not persist signing state — refusing the vote to stay safe");
            return Decision::Refuse;
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
        (SigningGuard::load(dir.path(), height), dir)
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
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(2))), Decision::Refuse);
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
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(1))), Decision::Refuse);
    }

    #[test]
    fn refuses_everything_at_or_below_the_chain_height_floor() {
        let (mut g, _d) = guard(100);
        // The tip (height 100) is already committed — the node must never vote there again.
        assert_eq!(g.check(&vote(100, 0, VoteType::Prevote, hash(1))), Decision::Refuse);
        assert_eq!(g.check(&vote(50, 5, VoteType::Precommit, hash(1))), Decision::Refuse);
    }

    #[test]
    fn a_later_round_after_a_conflict_still_advances() {
        let (mut g, _d) = guard(100);
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(1))), Decision::Allow);
        assert_eq!(g.check(&vote(101, 0, VoteType::Prevote, hash(2))), Decision::Refuse);
        // Round 1 is a strictly higher position — a fresh, legitimate vote.
        assert_eq!(g.check(&vote(101, 1, VoteType::Prevote, hash(2))), Decision::Allow);
    }

    #[test]
    fn the_high_water_mark_survives_a_reload() {
        let dir = tempdir::Guard::new();
        {
            let mut g = SigningGuard::load(dir.path(), 100);
            assert_eq!(g.check(&vote(101, 2, VoteType::Precommit, hash(7))), Decision::Allow);
        }
        // A "restart": a new guard over the same file must refuse a conflicting re-sign at 101/2.
        let mut g = SigningGuard::load(dir.path(), 100);
        assert_eq!(g.check(&vote(101, 2, VoteType::Precommit, hash(9))), Decision::Refuse);
        // …and the identical value is still fine.
        assert_eq!(g.check(&vote(101, 2, VoteType::Precommit, hash(7))), Decision::Allow);
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
