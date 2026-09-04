//! *n* real `BftEngine`s on a network this file can break on purpose.
//!
//! **Why this exists.** On 2026-09-04 the chain stood for 6 h 20 min. The repository had 821
//! passing tests at that moment and not one of them was capable of noticing: every failure in the
//! last five outages was "one node misses something and never recovers", and a single-process unit
//! test cannot express that. The same sentence appears over and over in the project log — green
//! tests while the mechanism never ran (#179 twice in one day, #147, #139, #180's removed check
//! that no test ever covered). More tests of that shape would not have helped. A harness that can
//! *withhold a message* would have.
//!
//! [`round_convergence`] is the seed this grows from: two engines, latency, start skew, and the
//! one detail that makes the model faithful rather than flattering — a gossiped message is
//! delivered **once**. What is added here is a validator count above two, faults that can be aimed
//! at a chosen node at a chosen tick, and the two transports that file leaves out.
//!
//! # The three transports, and why they are not one
//!
//! Collapsing them is how a harness quietly repairs the failure it is meant to catch.
//!
//! * **Gossip** (proposals, votes) — broadcast, delivered at most once per recipient, and *lost
//!   forever* if the recipient cannot take it at that instant. Gossipsub identifies a message by a
//!   hash of its bytes and refuses the same bytes for a minute, which is longer than a round: the
//!   sender's per-tick re-offer never reaches a peer that missed the first broadcast. A harness
//!   that redelivers on retry is testing a network we do not have.
//! * **Committed-block gossip** — a finished block plus the certificate proving it, adopted
//!   through [`BftEngine::sync_to_externally_finalized_block`]. Also once-only, and it applies
//!   **only on top of the recipient's own tip**. That restriction is not decoration: it is exactly
//!   how a node ends up one block behind with no way back, which is what happened on 2026-09-04.
//! * **Round-sync pull** — a request and its answer. This one *can* redeliver, which is the whole
//!   reason it was built. Modelling it separately is what makes it possible to ask whether it
//!   actually rescues anybody, instead of assuming it does.
//!
//! # What a test here has to do
//!
//! Reproduce the failure before it proves a fix. A recovery assertion that also holds when nothing
//! is broken measures nothing (Lehre 3, and #147's transport test which stayed green through its
//! own mutation). Every scenario below therefore states what it looked like when it was red.

use helix_consensus::{BftEngine, Proposal, Validator, ValidatorSet, Vote};
use helix_core::Block;
use helix_crypto::{Address, Hash, KeyPair};
use std::collections::HashSet;

/// Which path a message travelled. The file's whole premise is that these behave differently, so
/// a fault has to be able to name one — swallowing "a proposal" without saying *how it arrived*
/// silently blinds the node to the pull answer as well, which turns a test of the pull into a test
/// of nothing. Found by the pull test refusing to go green, not by reading.
#[derive(Clone, Copy, PartialEq)]
enum Transport {
    /// Broadcast, at most once per recipient, never resent.
    Gossip,
    /// The answer to a question this node asked. Redelivery is the point of it.
    Pull,
}

#[derive(Clone)]
enum Msg {
    Prop(Box<Proposal>),
    Vote(Box<Vote>),
    /// A block that is already final, carrying the quorum certificate that proves it. The
    /// `Applying committed block from peer` path.
    Committed(Box<Block>, Vec<Vote>),
}

impl Msg {
    fn is_proposal(&self) -> bool {
        matches!(self, Msg::Prop(_))
    }
}

struct Node {
    engine: BftEngine,
    kp: KeyPair,
    prev: Hash,
    /// Stands in for gossipsub's content-addressed duplicate cache: the same proposal is put on
    /// the wire once and never again.
    published: HashSet<String>,
    /// `(tick, height, hash)`. The tick makes block *cadence* measurable rather than only
    /// liveness; the hash is what lets a fork be told from a lag.
    committed: Vec<(usize, u64, Hash)>,
}

impl Node {
    fn new(set: ValidatorSet, kp: KeyPair, genesis: Hash) -> Self {
        let addr = Address::from_public_key(&kp.public);
        Node {
            engine: BftEngine::new(set, addr, 0),
            kp,
            prev: genesis,
            published: HashSet::new(),
            committed: Vec::new(),
        }
    }

    fn height(&self) -> u64 {
        self.engine.current_height()
    }

    fn note_commit(&mut self, block: &Block, t: usize, out: &mut Vec<Msg>) {
        self.prev = block.hash();
        self.committed.push((t, block.height(), block.hash()));
        // A node that finalizes locally is the one that tells everyone else. This is the transport
        // whose loss cost 6 h 20 min on 2026-09-04, so it is a real message here, not a side
        // effect of the tick loop.
        out.push(Msg::Committed(
            Box::new(block.clone()),
            self.engine.commit_certificate(),
        ));
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
    fn tick(&mut self, t: usize, out: &mut Vec<Msg>) {
        self.offer_proposal(out);
        let stalled = self.engine.note_round_tick(&self.kp);
        let prev = self.prev;
        let produced = if stalled {
            self.engine.advance_round(&self.kp, prev, vec![])
        } else {
            self.engine.produce_block(&self.kp, prev, vec![])
        };
        if let Ok(block) = produced {
            self.note_commit(&block, t, out);
        }
        self.offer_proposal(out);
        for v in self.engine.take_outbound_votes() {
            out.push(Msg::Vote(Box::new(v)));
        }
    }

    fn deliver(&mut self, msg: &Msg, t: usize, out: &mut Vec<Msg>) {
        match msg {
            Msg::Prop(p) => {
                if let Ok(Some(block)) =
                    self.engine.receive_proposal(&self.kp, (**p).clone())
                {
                    self.note_commit(&block, t, out);
                }
            }
            Msg::Vote(v) => {
                if let Ok(Some(block)) = self.engine.add_vote(&self.kp, (**v).clone()) {
                    self.note_commit(&block, t, out);
                }
            }
            Msg::Committed(block, cert) => {
                // Adopted only directly on top of our own tip, because that is the only thing the
                // node can actually do: `Applying committed block from peer` verifies the block
                // chains onto the local head. A node two blocks behind cannot close the gap this
                // way and needs block-sync — which lives a layer up and is deliberately *not*
                // simulated here, so that a gap shows up as a stuck node instead of being papered
                // over by a mechanism this crate does not own.
                if block.height() == self.height() + 1 && block.header.prev_hash == self.prev {
                    self.engine.sync_to_externally_finalized_block(
                        block.height(),
                        block.hash(),
                        cert.clone(),
                    );
                    self.prev = block.hash();
                    self.committed.push((t, block.height(), block.hash()));
                    self.engine.attest_adopted_block(&self.kp);
                }
            }
        }
        for v in self.engine.take_outbound_votes() {
            out.push(Msg::Vote(Box::new(v)));
        }
    }
}

/// A window `[from, to)` in ticks.
#[derive(Clone, Copy)]
struct Window {
    from: usize,
    to: usize,
}

impl Window {
    fn covers(&self, t: usize) -> bool {
        t >= self.from && t < self.to
    }
}

struct Sim {
    nodes: Vec<Node>,
    /// `(deliver_at_tick, recipient, message, how it travelled)`
    wire: Vec<(usize, usize, Msg, Transport)>,
    latency: usize,
    t: usize,
    /// Emits nothing, ever — but still receives. This is the faithful shape of what we observe in
    /// production: `Validator silent` says *this node is not seeing their votes*, never that the
    /// peer is down (R2). It also lets a silent validator come back cleanly, which a node that
    /// stopped receiving could not.
    silent: HashSet<usize>,
    /// Off the network entirely for a window: no ticks, and messages in flight to it are lost.
    offline: Vec<(usize, Window)>,
    /// Still running and still heard by everyone, but receives nothing. The one-way glitch, and
    /// the only fault that produces a *precisely* sized gap: a node that is deaf for k blocks is
    /// exactly k behind, which is what makes the recoverable-gap boundary measurable at all.
    deaf: Vec<(usize, Window)>,
    /// While the window is open, nodes inside `side` and nodes outside cannot reach each other.
    partition: Option<(Vec<usize>, Window)>,
    /// Swallow the next `n` inbound **gossiped** proposals aimed at one node. The narrowest fault in
    /// the file and the most useful: losing exactly one message is what a real chain does all the
    /// time, and recovering from it is the property that keeps failing.
    swallow_proposals: Vec<(usize, usize)>,
    roundsync: bool,
}

impl Sim {
    fn new(n: usize, latency: usize) -> Self {
        let kps: Vec<KeyPair> = (0..n).map(|_| KeyPair::generate()).collect();
        let set = ValidatorSet::new(
            kps.iter()
                .map(|kp| Validator::new(Address::from_public_key(&kp.public), 1_000, true))
                .collect(),
            0,
        );
        let genesis = Hash::digest(b"genesis");
        Sim {
            nodes: kps
                .into_iter()
                .map(|kp| Node::new(set.clone(), kp, genesis))
                .collect(),
            wire: Vec::new(),
            latency,
            t: 0,
            silent: HashSet::new(),
            offline: Vec::new(),
            deaf: Vec::new(),
            partition: None,
            swallow_proposals: Vec::new(),
            roundsync: false,
        }
    }

    fn silent(mut self, i: usize) -> Self {
        self.silent.insert(i);
        self
    }

    fn offline(mut self, i: usize, from: usize, to: usize) -> Self {
        self.offline.push((i, Window { from, to }));
        self
    }

    fn deaf(mut self, i: usize, from: usize, to: usize) -> Self {
        self.deaf.push((i, Window { from, to }));
        self
    }

    fn partition(mut self, side: &[usize], from: usize, to: usize) -> Self {
        self.partition = Some((side.to_vec(), Window { from, to }));
        self
    }

    fn swallow_proposals(mut self, i: usize, count: usize) -> Self {
        self.swallow_proposals.push((i, count));
        self
    }

    fn with_roundsync(mut self) -> Self {
        self.roundsync = true;
        self
    }

    fn quorum(&self) -> u64 {
        self.nodes[0].engine.validator_set().quorum_threshold()
    }

    fn is_offline(&self, i: usize, t: usize) -> bool {
        self.offline.iter().any(|(n, w)| *n == i && w.covers(t))
    }

    fn is_deaf(&self, i: usize, t: usize) -> bool {
        self.deaf.iter().any(|(n, w)| *n == i && w.covers(t))
    }

    fn reachable(&self, from: usize, to: usize, t: usize) -> bool {
        match &self.partition {
            Some((side, w)) if w.covers(t) => {
                side.contains(&from) == side.contains(&to)
            }
            _ => true,
        }
    }

    /// Returns true when this message must not reach `to` — and consumes one unit of the fault, so
    /// "swallow exactly one" means exactly one.
    fn swallowed(&mut self, to: usize, m: &Msg, via: Transport) -> bool {
        if !m.is_proposal() || via != Transport::Gossip {
            return false;
        }
        let bucket = &mut self.swallow_proposals;
        for (node, left) in bucket.iter_mut() {
            if *node == to && *left > 0 {
                *left -= 1;
                return true;
            }
        }
        false
    }

    fn broadcast(&mut self, from: usize, msgs: Vec<Msg>) {
        if self.silent.contains(&from) {
            return;
        }
        let t = self.t;
        for m in msgs {
            for to in 0..self.nodes.len() {
                if to == from || !self.reachable(from, to, t) {
                    continue;
                }
                self.wire.push((t + self.latency, to, m.clone(), Transport::Gossip));
            }
        }
    }

    /// The pull, modelled as what it is: a question and an answer, not a rebroadcast. It is the one
    /// transport here that may deliver something a node already missed.
    fn pull_round_state(&mut self) {
        let t = self.t;
        let n = self.nodes.len();
        for i in 0..n {
            if self.is_offline(i, t) || self.is_deaf(i, t) {
                continue;
            }
            let Some((height, _round)) = self.nodes[i].engine.missing_proposal() else {
                continue;
            };
            for j in 0..n {
                if j == i || !self.reachable(j, i, t) || self.is_offline(j, t) {
                    continue;
                }
                let (proposal, votes) = self.nodes[j].engine.round_evidence(height);
                if proposal.is_none() && votes.is_empty() {
                    continue;
                }
                if let Some(p) = proposal {
                    self.wire
                        .push((t + self.latency, i, Msg::Prop(Box::new(p)), Transport::Pull));
                }
                for v in votes {
                    self.wire
                        .push((t + self.latency, i, Msg::Vote(Box::new(v)), Transport::Pull));
                }
                break; // one peer per tick, as the node does
            }
        }
    }

    fn step(&mut self) {
        let t = self.t;

        for (at, to, m, via) in std::mem::take(&mut self.wire) {
            if at > t {
                self.wire.push((at, to, m, via));
                continue;
            }
            // In flight when the recipient went down: gossip does not retry, so it is gone.
            if self.is_offline(to, t) || self.is_deaf(to, t) || self.swallowed(to, &m, via) {
                continue;
            }
            let mut out = Vec::new();
            self.nodes[to].deliver(&m, t, &mut out);
            self.broadcast(to, out);
        }

        for i in 0..self.nodes.len() {
            if self.is_offline(i, t) {
                continue;
            }
            let mut out = Vec::new();
            self.nodes[i].tick(t, &mut out);
            self.broadcast(i, out);
        }

        if self.roundsync {
            self.pull_round_state();
        }

        self.t += 1;
    }

    fn run(&mut self, ticks: usize) -> &mut Self {
        for _ in 0..ticks {
            self.step();
        }
        self
    }

    fn heights(&self) -> Vec<u64> {
        self.nodes.iter().map(|n| n.height()).collect()
    }

    /// Blocks committed by any node strictly after `tick` — the "did it come back" question.
    fn commits_after(&self, tick: usize) -> usize {
        self.nodes
            .iter()
            .map(|n| n.committed.iter().filter(|(t, _, _)| *t > tick).count())
            .max()
            .unwrap_or(0)
    }

    /// Mean ticks between consecutive commits on the node that got furthest. This is the number
    /// that turns "blocks sometimes take minutes" into something a test can hold a bound on.
    fn mean_commit_interval(&self) -> f64 {
        let best = self
            .nodes
            .iter()
            .max_by_key(|n| n.committed.len())
            .expect("a simulation always has nodes");
        if best.committed.len() < 2 {
            return f64::INFINITY;
        }
        let first = best.committed.first().unwrap().0;
        let last = best.committed.last().unwrap().0;
        (last - first) as f64 / (best.committed.len() - 1) as f64
    }

    /// Every height that two nodes both hold must be the *same block* on both. This is the one
    /// assertion in the file that is about safety rather than liveness, and it is the property the
    /// project has actually lost once: on 2026-07-22 two validators each finalized their own
    /// height 66918, `ca38cd4b…` against `f18b2d4d…`, because each had locally written the other
    /// out of the quorum. A stalled chain is recoverable; two histories are not.
    ///
    /// Compares committed chains rather than tips, because a fork below the tip is still a fork —
    /// and comparing only tips would call two nodes on different heights "not forked" for the
    /// uninteresting reason that there is nothing to compare.
    fn assert_no_fork(&self, ctx: &str) {
        for (i, a) in self.nodes.iter().enumerate() {
            for (j, b) in self.nodes.iter().enumerate().skip(i + 1) {
                for (_, height, hash) in &a.committed {
                    let Some((_, _, other)) =
                        b.committed.iter().find(|(_, h, _)| h == height)
                    else {
                        continue;
                    };
                    assert_eq!(
                        hash, other,
                        "{ctx}: nodes {i} and {j} both committed height {height} but not the same \
                         block — that is a fork, the one outcome a halt is supposed to buy"
                    );
                }
            }
        }
    }
}

/// Baseline: nothing broken. Exists so every degraded number below has something to be measured
/// against — a "the chain still runs" assertion that never saw a healthy run is not a comparison.
#[test]
#[ignore = "5 real BFT engines × 200 ticks of real ML-DSA — run with --release --ignored, or via scripts/build-all.sh"]
fn five_healthy_validators_commit_on_every_round() {
    let mut sim = Sim::new(5, 1);
    sim.run(200);
    let interval = sim.mean_commit_interval();
    println!("healthy: heights={:?} mean interval={interval:.2} ticks", sim.heights());
    assert!(
        sim.heights().iter().all(|h| *h > 10),
        "a healthy five-validator set produced almost nothing: {:?}",
        sim.heights()
    );
    sim.assert_no_fork("healthy");
}

/// One silent validator out of five is inside the fault budget — `floor((n-1)/3) = 1` — so the
/// chain must keep producing. What it must *not* do is produce at the same speed: the silent
/// node's proposer turn still comes round, and it costs a full round timeout every time.
///
/// This is the 2026-09-04 chain measured in a test instead of in a log. Live, every fifth block
/// took 10.0 s and carried 16–23 transactions while the other four took 2.0 s with 2–9. The
/// transactions were the *symptom*: at ~2 tx/s a 10-second wait fills a block with 20.
#[test]
#[ignore = "5 real BFT engines × 200 ticks of real ML-DSA — run with --release --ignored, or via scripts/build-all.sh"]
fn a_single_silent_validator_costs_its_proposer_slot_but_not_the_chain() {
    let mut healthy = Sim::new(5, 1);
    healthy.run(200);
    let healthy_interval = healthy.mean_commit_interval();

    let mut sim = Sim::new(5, 1).silent(4);
    sim.run(200);
    let degraded_interval = sim.mean_commit_interval();

    println!(
        "one silent of five: heights={:?} interval {healthy_interval:.2} -> {degraded_interval:.2} ticks",
        sim.heights()
    );
    assert!(
        sim.heights().iter().take(4).all(|h| *h > 5),
        "one silent validator of five is within the fault budget, yet the chain stopped: {:?}",
        sim.heights()
    );
    assert!(
        degraded_interval > healthy_interval,
        "the silent validator's proposer turn must cost a round timeout, but the cadence was \
         unchanged ({healthy_interval:.2} -> {degraded_interval:.2}). Either the harness is not \
         reaching that node's turn or the proposer rotation skips it — both make every liveness \
         number in this file meaningless"
    );
    sim.assert_no_fork("one silent of five");
}

/// Two silent of five is *outside* the budget: 3 × the per-validator power is below the quorum, so
/// the chain must stop — and must start again the moment one of them speaks.
///
/// This is 2026-09-04 exactly: `k6QWX` fell silent and our own node fell one block behind, which
/// took two of five out of the quorum at once. The chain stood for 6 h 20 min. Both halves matter
/// here: stopping is correct BFT behaviour, and *resuming without intervention* is the part that
/// was never proven.
#[test]
#[ignore = "5 real BFT engines × 300 ticks of real ML-DSA — run with --release --ignored, or via scripts/build-all.sh"]
fn two_silent_of_five_stop_the_chain_and_it_resumes_when_one_returns() {
    let mut sim = Sim::new(5, 1).silent(3).silent(4);
    sim.run(150);
    let stalled_at = sim.heights();
    println!("two silent of five: heights={stalled_at:?} quorum={}", sim.quorum());
    assert!(
        stalled_at.iter().all(|h| *h <= 1),
        "three of five is below quorum, so nothing may be committed — got {stalled_at:?}. A chain \
         that finalizes below quorum is not slow, it is forked"
    );

    // Node 3 comes back. Nothing else changes.
    sim.silent.remove(&3);
    let resumed_from = sim.t;
    sim.run(150);
    println!("after one returns: heights={:?}", sim.heights());
    assert!(
        sim.commits_after(resumed_from) > 0,
        "the fourth validator came back and the chain still produced nothing — it did not recover \
         on its own, which on the live chain means somebody has to notice and restart a node"
    );
    sim.assert_no_fork("two silent, one returns");
}

/// How large a gap can the consensus engine close **on its own**? Measured answer: **none — not
/// even one block.**
///
/// This is #188 reduced to a mechanism. On 2026-09-04 our node was exactly one block behind and
/// never recovered; the chain stood 6 h 20 min because a validator below the tip cannot vote on
/// the next height and is therefore missing from the quorum. The reflex reading was "block-sync
/// failed to fire". The sharper truth is that **nothing else could have fired**, and both
/// re-delivery paths are blind to a height gap by construction:
///
/// * committed-block gossip carries a block exactly once, and a receiver adopts it only at
///   `current_height + 1` — so the block that would close the gap is precisely the one already
///   lost, and every later one is refused for chaining onto a tip the node does not hold;
/// * the round-sync pull is answered only for the *server's* `current_height + 1`
///   (`round_evidence`, engine.rs:1207), so a node behind in height asks a question no peer will
///   answer. It rescues a node that missed a proposal, never one that missed a block.
///
/// So block-sync is not a backstop, it is the sole path, and a single dropped gossip message
/// removes a validator from the quorum until it runs. On a five-validator chain with a fault
/// budget of one, that is one lost message away from a halt.
///
/// Asserted here: the fault reproduces, and the other four carry on regardless. The gap itself is
/// printed rather than asserted, because its size is a property of where the layers are cut —
/// block-sync lives in `helix-node` — and a test that turned red the day somebody closed the gap
/// would be punishing the fix. The assertion that block-sync *does* close it belongs in a harness
/// at that layer, which does not exist yet (#189).
fn deaf_then_listen(window: usize, settle: usize) -> (u64, u64, Vec<u64>) {
    let deaf_from = 40;
    let mut sim = Sim::new(5, 1).deaf(4, deaf_from, deaf_from + window).with_roundsync();
    sim.run(deaf_from + window);
    let at_recovery = sim.heights();
    let gap_then = at_recovery.iter().max().unwrap() - at_recovery[4];
    sim.run(settle);
    let end = sim.heights();
    let gap_end = end.iter().max().unwrap() - end[4];
    sim.assert_no_fork("deaf window");
    (gap_then, gap_end, end)
}

#[test]
#[ignore = "5 real BFT engines × ~250 ticks of real ML-DSA — run with --release --ignored, or via scripts/build-all.sh"]
fn a_height_gap_is_never_closed_by_consensus_alone_however_small_it_is() {
    for window in [5, 40] {
        let (gap_then, gap_end, end) = deaf_then_listen(window, 150);
        println!(
            "deaf {window} ticks: gap at recovery={gap_then}, after 150 more ticks={gap_end}, heights={end:?}"
        );
        // Positive control. Without this the rest of the test would pass for the uninteresting
        // reason that nothing was ever lost — the exact shape #147's transport test had when it
        // survived its own mutation and was deleted rather than kept.
        assert!(
            gap_then > 0,
            "deafness of {window} ticks cost node 4 nothing, so this test is measuring an intact \
             network and not a recovery"
        );
        assert!(
            end.iter().take(4).all(|h| *h > 10),
            "the four validators that stayed connected must keep producing — one of five is \
             inside the fault budget. Heights: {end:?}"
        );
    }
}

/// A node never receives a proposal by gossip **while the set has no spare capacity** — so its
/// prevote is one the round cannot close without, and the pull is the only way it can ever hold a
/// block to vote for.
///
/// Two red runs were needed to arrive at this scenario, and both are the reason it is worth
/// keeping. The first version swallowed three proposals with five healthy validators and passed
/// with the pull switched off: four of five is exactly quorum, so the round closed without the
/// deaf node. The second added a silent validator to spend the budget and *still* passed with the
/// pull off — three lost proposals cost three rounds, and the next proposer's block arrived
/// normally. Only when the node is blind to proposals for the whole run does its vote become
/// unavoidable, and only then does the pull carry anything.
///
/// The comparison is made inside the test rather than against a hard-coded number: the same
/// scenario runs twice, with the pull and without. A calibrated constant would drift the first
/// time a timeout changes and quietly stop measuring anything.
#[test]
#[ignore = "10 real BFT engines × 250 ticks of real ML-DSA — run with --release --ignored, or via scripts/build-all.sh"]
fn the_round_sync_pull_carries_a_node_whose_vote_the_quorum_cannot_spare() {
    let blind = 10_000; // effectively "every proposal, for the whole run"

    let mut without = Sim::new(5, 1).silent(4).swallow_proposals(2, blind);
    without.run(250);
    let without_best = *without.heights().iter().max().unwrap();

    let mut with = Sim::new(5, 1).silent(4).swallow_proposals(2, blind).with_roundsync();
    with.run(250);
    let with_best = *with.heights().iter().max().unwrap();

    println!(
        "node 2 blind to gossiped proposals, node 4 silent: without pull={with_out} with pull={with_best}",
        with_out = without_best
    );
    assert!(
        with_best > 5,
        "with the pull available the chain should run close to normally, got {with_best} blocks"
    );
    assert!(
        with_best > without_best * 3 / 2,
        "the pull made no real difference ({without_best} -> {with_best} blocks). Gossip will not \
         resend a proposal — content-addressed duplicate cache, 60 s, longer than a round — so a \
         node whose vote the quorum cannot spare has no other way to obtain one"
    );
    with.assert_no_fork("pull under a spent fault budget");
}

/// A validator restarts mid-round — a deploy, an upgrade, an OOM kill. The everyday event, and
/// the one the live chain hits most often.
///
/// Scope, stated so the name cannot outgrow it: this asserts that **the network** keeps producing
/// while one of five is away, which is what the fault budget promises. It deliberately does *not*
/// assert that the returning node catches up, because after 40 ticks away its gap is several
/// blocks and closing that is block-sync's job, one layer up in `helix-node`. Asserting it here
/// would make the consensus suite red for a mechanism it does not contain — and the measurement
/// that does belong here is in `a_node_one_block_behind_is_carried_back_by_the_next_committed_block`.
#[test]
#[ignore = "5 real BFT engines × 250 ticks of real ML-DSA — run with --release --ignored, or via scripts/build-all.sh"]
fn a_validator_restarting_mid_round_does_not_stop_the_chain() {
    let mut sim = Sim::new(5, 1).offline(2, 60, 100).with_roundsync();
    sim.run(60);
    let before = *sim.heights().iter().max().unwrap();
    sim.run(190);
    let heights = sim.heights();
    let best = *heights.iter().max().unwrap();
    println!("node 2 offline ticks 60..100: height {before} -> {heights:?}");
    assert!(
        best > before + 10,
        "one of five was away for 40 ticks — inside the fault budget of floor((5-1)/3)=1 — and the \
         chain did not keep going: {before} -> {heights:?}"
    );
    let together = heights.iter().filter(|h| **h == best).count();
    assert!(
        together >= 4,
        "the four validators that never left must stay on the same height; got {heights:?}"
    );
    sim.assert_no_fork("validator restart");
}

/// A split that leaves neither side a quorum. Both sides must stop, and — the assertion that
/// actually matters — neither may finalize anything, because two finalizing sides is a fork.
///
/// The project has been here for real: on 2026-07-22 two validators locally excluded each other
/// and each finalized its own height 66918, `ca38cd4b…` against `f18b2d4d…`. The mechanism that
/// allowed it was removed; this is the test that says it stays removed.
#[test]
#[ignore = "5 real BFT engines × 250 ticks of real ML-DSA — run with --release --ignored, or via scripts/build-all.sh"]
fn a_split_with_no_quorum_on_either_side_stalls_without_forking() {
    let mut sim = Sim::new(5, 1).partition(&[0, 1, 2], 50, 150).with_roundsync();
    sim.run(50);
    let before = *sim.heights().iter().max().unwrap();
    sim.run(100);
    let during = sim.heights();
    println!("split 3|2 from tick 50: before={before} during={during:?}");
    assert!(
        during.iter().all(|h| *h <= before + 1),
        "a 3|2 split of five leaves 3 × power below the quorum on the larger side, so neither side \
         may finalize — heights moved from {before} to {during:?}"
    );
    sim.assert_no_fork("during split");

    sim.run(100);
    println!("after heal: heights={:?}", sim.heights());
    assert!(
        sim.commits_after(150) > 0,
        "the partition healed and the chain never restarted: {:?}",
        sim.heights()
    );
    sim.assert_no_fork("after heal");
}
