//! Two real `BftEngine`s on a network that delivers every message — just not instantly.
//!
//! **The regression this guards is a chain that stopped and could not restart itself.** On
//! 2026-08-26 a freshly activated validator joined a two-validator set and the height never moved
//! again: both nodes agreed on the validator set, the quorum, the height and each other's
//! presence, and each kept receiving the other's proposal for a round it had already left — A on
//! rounds 54/56/58 receiving proposals for 53/55/57, B the mirror image. Nothing was down, nothing
//! disagreed, and nothing timed out into recovery, because both round clocks ran at the same fixed
//! rate and preserved their offset forever.
//!
//! What is modelled here is exactly that: latency, a start-time skew, and — the detail that makes
//! the model faithful rather than flattering — **a message is only ever delivered once**.
//! Gossipsub identifies a message by a hash of its bytes and refuses to publish the same bytes
//! again for a minute, so the node's per-tick re-offer of its pending proposal never reaches a
//! peer that missed the first broadcast. A harness that re-delivered the proposal every tick would
//! quietly repair the very failure being tested.
//!
//! Not modelled: the round-sync pull (`helix_p2p::roundsync`), which is the *other* half of the
//! fix and needs a network. This file therefore measures what the engine alone can recover from,
//! which is the stricter question.

use helix_consensus::{BftEngine, Proposal, Validator, ValidatorSet, Vote};
use helix_crypto::{Address, Hash, KeyPair};

#[derive(Clone)]
enum Msg {
    Prop(Box<Proposal>),
    Vote(Box<Vote>),
}

struct Node {
    engine: BftEngine,
    kp: KeyPair,
    prev: Hash,
    /// Payload identities already published. Gossipsub's content-addressed duplicate cache is
    /// what this stands in for — see the module comment.
    published: std::collections::HashSet<String>,
    committed: Vec<(u64, Hash)>,
}

impl Node {
    fn new(set: ValidatorSet, kp: KeyPair, genesis: Hash) -> Self {
        let addr = Address::from_public_key(&kp.public);
        Node {
            engine: BftEngine::new(set, addr, 0),
            kp,
            prev: genesis,
            published: Default::default(),
            committed: Vec::new(),
        }
    }

    fn note_commit(&mut self, block: &helix_core::Block) {
        self.prev = block.hash();
        self.committed.push((block.height(), block.hash()));
    }

    fn offer_proposal(&mut self, out: &mut Vec<Msg>) {
        if let Some(p) = self.engine.pending_proposal_envelope() {
            let key = format!("{}:{}:{}", p.block.height(), p.round, p.block.hash());
            if self.published.insert(key) {
                out.push(Msg::Prop(Box::new(p)));
            }
        }
    }

    /// One block-production tick, mirroring `block_production_loop`.
    fn tick(&mut self, out: &mut Vec<Msg>) {
        self.offer_proposal(out);
        let stalled = self.engine.note_round_tick(&self.kp);
        let prev = self.prev;
        let produced = if stalled {
            self.engine.advance_round(&self.kp, prev, vec![])
        } else {
            self.engine.produce_block(&self.kp, prev, vec![])
        };
        if let Ok(block) = produced {
            self.note_commit(&block);
        }
        self.offer_proposal(out);
        for v in self.engine.take_outbound_votes() {
            out.push(Msg::Vote(Box::new(v)));
        }
    }

    fn deliver(&mut self, msg: &Msg, out: &mut Vec<Msg>) {
        let finalized = match msg {
            Msg::Prop(p) => self.engine.receive_proposal(&self.kp, (**p).clone()).ok().flatten(),
            Msg::Vote(v) => self.engine.add_vote(&self.kp, (**v).clone()).ok().flatten(),
        };
        if let Some(block) = finalized {
            self.note_commit(&block);
        }
        for v in self.engine.take_outbound_votes() {
            out.push(Msg::Vote(Box::new(v)));
        }
    }
}

struct Outcome {
    a_commits: usize,
    b_commits: usize,
    a_round: u32,
    b_round: u32,
}

/// `latency` = ticks a message spends in flight. `skew` = ticks node B starts late.
fn run(latency: usize, skew: usize, ticks: usize) -> Outcome {
    let kp_a = KeyPair::generate();
    let kp_b = KeyPair::generate();
    let set = ValidatorSet::new(
        vec![
            Validator::new(Address::from_public_key(&kp_a.public), 1_000, true),
            Validator::new(Address::from_public_key(&kp_b.public), 1_000, true),
        ],
        0,
    );
    let genesis = Hash::digest(b"genesis");
    let mut a = Node::new(set.clone(), kp_a, genesis);
    let mut b = Node::new(set, kp_b, genesis);

    let mut wire: Vec<(usize, bool, Msg)> = Vec::new();

    for t in 0..ticks {
        for (at, to_b, m) in std::mem::take(&mut wire) {
            if at > t {
                wire.push((at, to_b, m));
                continue;
            }
            let mut out = Vec::new();
            if to_b {
                b.deliver(&m, &mut out);
            } else {
                a.deliver(&m, &mut out);
            }
            for m in out {
                wire.push((t + latency, !to_b, m));
            }
        }

        let mut out_a = Vec::new();
        a.tick(&mut out_a);
        for m in out_a {
            wire.push((t + latency, true, m));
        }

        if t >= skew {
            let mut out_b = Vec::new();
            b.tick(&mut out_b);
            for m in out_b {
                wire.push((t + latency, false, m));
            }
        }
    }
    Outcome {
        a_commits: a.committed.len(),
        b_commits: b.committed.len(),
        a_round: a.engine.pending_round(),
        b_round: b.engine.pending_round(),
    }
}

/// Every combination of delay and start skew must still produce blocks, on **both** nodes.
///
/// The 8-tick case is the one that reproduced the live freeze: before the round window widened
/// with the round (`proposal_timeout_ticks`) and before a vote from a later round pulled a node
/// forward (`peer_round_to_jump_to`), node A committed nothing at all in 200 ticks and the two
/// engines ended three rounds apart.
///
/// Mutation check, measured rather than assumed: setting `PROPOSAL_TIMEOUT_STEP_TICKS` and
/// `ROUND_TIMEOUT_STEP_TICKS` to 0 turns this red exactly as the live chain went — `latency=8`
/// drops to `a=0 b=1` commits, ending three rounds apart. Dropping the round-skip call in
/// `add_vote` instead leaves it **green**: with only two engines and this much traffic the widened
/// window alone is enough to bring them back together, so this file does not prove that rule. Its
/// proof is `a_vote_from_a_round_ahead_pulls_this_node_forward` in the engine's own tests; it earns
/// its place here for the cases this model does not reach — a node many rounds behind, and rounds
/// past the backoff cap, where timing alone no longer converges.
/// `#[ignore]` and release-only, for a measured reason: this runs two real engines through 200
/// ticks apiece for ten network shapes, and every round signs and verifies real ML-DSA. In a debug
/// build that is **26 minutes** (measured 2026-08-26), which would make `cargo test --workspace`
/// unusable; in release it is 30 seconds.
///
/// Skipped is not passed (and this repo has been burned by that before), so it is not left to
/// anyone's memory: `scripts/build-all.sh` runs it, which is the gate every release goes through.
/// By hand:
/// `cargo test --release -p helix-consensus --test round_convergence -- --ignored --nocapture`
#[test]
#[ignore = "two full BFT engines × 200 ticks × 10 network shapes — 30s in release, 26min in debug; run via scripts/build-all.sh or with --release --ignored"]
fn two_validators_keep_committing_however_their_clocks_are_offset() {
    for (latency, skew) in [(0, 0), (1, 0), (2, 0), (3, 0), (1, 1), (2, 1), (3, 2), (5, 3), (8, 0), (8, 4)] {
        let out = run(latency, skew, 200);
        println!(
            "latency={latency} skew={skew} -> commits a={} b={} rounds a={} b={}",
            out.a_commits, out.b_commits, out.a_round, out.b_round
        );
        assert!(
            out.a_commits > 0 && out.b_commits > 0,
            "latency={latency} skew={skew}: the chain stopped — a={} b={} committed, ending on \
             rounds {}/{}. Two validators that never meet in the same round is the 2026-08-26 \
             freeze, not a slow network.",
            out.a_commits,
            out.b_commits,
            out.a_round,
            out.b_round
        );
        assert_eq!(
            out.a_commits, out.b_commits,
            "latency={latency} skew={skew}: both nodes must finalize the same blocks — one \
             counting more than the other means a commit that the other never saw"
        );
    }
}
