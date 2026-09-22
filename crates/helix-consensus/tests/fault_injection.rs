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
        // The engine now checks that the parent is the block directly below the one it builds.
        // In this model the two never drift — that is the point of the check, which exists for
        // the live node where the store and the consensus height can.
        let prev_height = self.engine.current_height();
        // No executor behind these engines, so there is no state to hash: the state-root
        // field is deliberately inert here (`Hash::ZERO` out, `None` in). These numbers are
        // the baseline that shows the change left consensus dynamics alone.
        let produced = if stalled {
            self.engine.advance_round(&self.kp, prev, prev_height, Hash::ZERO, vec![])
        } else {
            self.engine.produce_block(&self.kp, prev, prev_height, Hash::ZERO, vec![])
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
                    self.engine.receive_proposal(&self.kp, (**p).clone(), None)
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
    /// Extra ticks every message needs to reach this node. The narrowest way to split a round:
    /// slow enough and the proposal lands *after* the node has already prevoted nil, so it votes —
    /// it is heard from, it counts toward the power in the room — but for a different value than
    /// everyone else. No value reaches two thirds and the round dies with a full house.
    slow: Vec<(usize, usize)>,
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
    /// Validators that sign two conflicting votes for every one they cast (see `equivocate`).
    byzantine: HashSet<usize>,
    /// Byzantine nodes tell the lower and upper halves of the network different values.
    split_brain: bool,
}

impl Sim {
    fn new(n: usize, latency: usize) -> Self {
        let kps: Vec<KeyPair> = (0..n).map(|_| KeyPair::generate()).collect();
        let set = ValidatorSet::new(
            kps.iter()
                .map(|kp| Validator::with_key(
                    Address::from_public_key(&kp.public),
                    Some(kp.public.clone()),
                    1_000,
                    true,
                ))
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
            slow: Vec::new(),
            partition: None,
            swallow_proposals: Vec::new(),
            roundsync: false,
            byzantine: HashSet::new(),
            split_brain: false,
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

    fn slow(mut self, i: usize, extra_ticks: usize) -> Self {
        self.slow.push((i, extra_ticks));
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

    fn byzantine(mut self, i: usize) -> Self {
        self.byzantine.insert(i);
        self
    }

    fn split_brain(mut self) -> Self {
        self.split_brain = true;
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

    fn extra_latency(&self, to: usize) -> usize {
        self.slow.iter().find(|(n, _)| *n == to).map(|(_, d)| *d).unwrap_or(0)
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
        // A byzantine node's votes go out *twice*, the second for a different value and correctly
        // signed by the same key — real equivocation, not a forgery. The distinction is the whole
        // point: a forged signature is refused at the boundary and proves nothing about consensus,
        // while a validator signing two conflicting things is a live validator doing exactly what
        // the protocol is built to survive. Splitting it here rather than inside the node keeps
        // the production path free of any "be evil" switch.
        // Split-brain equivocation is *targeted*: half the network is told one value and half the
        // other, which is the only version of this attack that could actually fork a chain. The
        // undirected kind — both votes to everyone — is measurably harmless, and this harness said
        // so before the distinction existed: two undirected equivocators of five committed 83
        // blocks against an honest baseline of 66, because the honest half of each pair of votes
        // still counted and the other half was simply discarded.
        if self.split_brain && self.byzantine.contains(&from) {
            self.broadcast_split(from, msgs);
            return;
        }
        let msgs = self.equivocate(from, msgs);
        for m in msgs {
            for to in 0..self.nodes.len() {
                if to == from || !self.reachable(from, to, t) {
                    continue;
                }
                let at = t + self.latency + self.extra_latency(to);
                self.wire.push((at, to, m.clone(), Transport::Gossip));
            }
        }
    }

    /// Tell the lower half of the network one value and the upper half another, both signed.
    ///
    /// Each honest node receives exactly **one** vote per (height, round) from this validator, so
    /// none of them sees a conflict locally — the equivocation is invisible to every individual
    /// participant and exists only in the difference between them. That is what makes it the
    /// dangerous shape: there is no single node that could refuse it.
    fn broadcast_split(&mut self, from: usize, msgs: Vec<Msg>) {
        let t = self.t;
        let half = self.nodes.len() / 2;
        // Signed up front, while only a shared borrow of the node is needed: `KeyPair` is not
        // `Clone` (deliberately — a signing key that copies itself around is a key that ends up
        // somewhere unintended), so the twins cannot be built inside the send loop below.
        let pairs: Vec<(Msg, Option<Msg>)> = {
            let kp = &self.nodes[from].kp;
            msgs.into_iter()
                .map(|m| {
                    let twin = match &m {
                        Msg::Vote(v) => {
                            let mut tw = (**v).clone();
                            tw.block_hash = Hash::digest(b"the other branch");
                            tw.signature =
                                kp.sign(&tw.signing_bytes()).expect("sign the twin vote");
                            Some(Msg::Vote(Box::new(tw)))
                        }
                        _ => None,
                    };
                    (m, twin)
                })
                .collect()
        };
        for (m, twin) in pairs {
            for to in 0..self.nodes.len() {
                if to == from || !self.reachable(from, to, t) {
                    continue;
                }
                let at = t + self.latency + self.extra_latency(to);
                let msg = match (&twin, to >= half) {
                    (Some(tw), true) => tw.clone(),
                    _ => m.clone(),
                };
                self.wire.push((at, to, msg, Transport::Gossip));
            }
        }
    }

    /// Duplicate a byzantine node's votes with a conflicting block hash, signed by its own key.
    fn equivocate(&self, from: usize, msgs: Vec<Msg>) -> Vec<Msg> {
        if !self.byzantine.contains(&from) {
            return msgs;
        }
        let kp = &self.nodes[from].kp;
        let mut out = Vec::with_capacity(msgs.len() * 2);
        for m in msgs {
            if let Msg::Vote(v) = &m {
                let mut twin = (**v).clone();
                // A different value for the same (height, round, type) — which is precisely what
                // `VoteSet::add` is meant to catch and turn into double-sign evidence.
                twin.block_hash = Hash::digest(b"the other branch");
                twin.signature = kp.sign(&twin.signing_bytes()).expect("sign the twin vote");
                out.push(m);
                out.push(Msg::Vote(Box::new(twin)));
                continue;
            }
            out.push(m);
        }
        out
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
                let at = t + self.latency + self.extra_latency(i);
                if let Some(p) = proposal {
                    self.wire.push((at, i, Msg::Prop(Box::new(p)), Transport::Pull));
                }
                for v in votes {
                    self.wire.push((at, i, Msg::Vote(Box::new(v)), Transport::Pull));
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

    /// The highest count any node has of rounds it lost while hearing enough power to close them.
    fn rounds_lost_with_quorum_power(&self) -> u64 {
        self.nodes
            .iter()
            .map(|n| n.engine.rounds_lost_with_quorum_power())
            .max()
            .unwrap_or(0)
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
    /// Double-sign evidence every node has accumulated. Drains it, which is what the node layer
    /// does too — nothing here reads it twice.
    fn evidence_collected(&mut self) -> usize {
        self.nodes.iter_mut().map(|n| n.engine.take_evidence().len()).sum()
    }

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

/// A round can fail with **every** validator heard from, and this is the shape that has cost this
/// chain the most: the votes arrive, they just do not agree on a value.
///
/// Measured live on 2026-09-04, three minutes after the attendance line was deployed (#192): one
/// round with 2e12 of power heard against a quorum of 1.667e12 and `reached_prevote_quorum=false`.
/// Enough voting power in the room and no prevote quorum can only mean the prevotes went to
/// different values — some to the block, some to nil, because the proposal did not reach everyone
/// inside its window.
///
/// **Why it matters more than it sounds.** "Four of five voted" reads like the round should have
/// closed, and that reading is what put a wrong diagnosis into this project's notes twice in one
/// day. Availability and agreement are different properties; a validator that votes nil because it
/// never saw the proposal is present, counted, and useless.
///
/// Constructed with one silent validator, so the fault budget is spent and the slow node's nil
/// prevote is the difference between a round closing and dying — which is exactly the state
/// production was in. The negative control is the point of the pair: a healthy set must never
/// register one of these, or the counter measures something other than what its name says.
#[test]
#[ignore = "10 real BFT engines × 200 ticks of real ML-DSA — run with --release --ignored, or via scripts/build-all.sh"]
fn a_proposal_that_arrives_too_late_splits_the_prevotes_and_kills_a_full_round() {
    let mut healthy = Sim::new(5, 1);
    healthy.run(200);
    assert_eq!(
        healthy.rounds_lost_with_quorum_power(),
        0,
        "a healthy set must never lose a round while hearing enough power — if it does, this \
         counter is measuring something other than a split vote and every number below is noise"
    );

    // Node 3 receives everything six ticks late, which is past the proposal window, so it has
    // already prevoted nil by the time the block reaches it. Node 4 is silent, so the budget of
    // one is spent and the split is decisive rather than absorbed.
    let mut split = Sim::new(5, 1).silent(4).slow(3, 6);
    split.run(200);
    let lost = split.rounds_lost_with_quorum_power();
    println!(
        "one silent, one six ticks late: heights={:?}, rounds lost with quorum power={lost}",
        split.heights()
    );
    assert!(
        lost > 0,
        "the slow node votes — nil, for a proposal it had not yet seen — so the power in the room \
         clears the quorum and the round still cannot close. Not seeing that here means the fault \
         is not reaching the proposal window, and the live observation of 2026-09-04 has no \
         regression test"
    );
    split.assert_no_fork("split prevotes");
}

/// **A validator that signs two conflicting votes for everything it casts.**
///
/// The fault class every other test here leaves out. Silence, lag, partition and dropped messages
/// are all things that happen *to* a node; this is a node doing something no correct one ever
/// does, with a valid key and a valid signature — which is why it cannot be refused at the
/// boundary the way a forgery can. It is the case BFT exists for, and the one the five production
/// outages of the last month were never this: every one of them was a node that went quiet.
///
/// Five validators, one byzantine, so `3f+1` holds with f=1 and the protocol is owed both
/// guarantees. They are asserted in the order they matter:
///
/// 1. **Safety.** No two nodes commit different blocks at the same height. This is the one that
///    must never bend — a halt costs hours, a fork costs the chain.
/// 2. **Liveness.** The honest four keep finalising. A protocol that survives byzantium by
///    stopping has not survived it.
/// 3. **Evidence.** Equivocation is detectable, because slashing is what makes it expensive
///    rather than free.
#[test]
fn a_validator_signing_two_conflicting_votes_forks_nothing_and_stops_nothing() {
    let mut honest = Sim::new(5, 1);
    honest.run(200);
    let baseline = honest.heights().iter().copied().max().unwrap_or(0);

    let mut sim = Sim::new(5, 1).byzantine(4);
    sim.run(200);
    let heights = sim.heights();
    let evidence = sim.evidence_collected();
    println!(
        "one equivocator of five: heights={heights:?} (honest baseline {baseline}), \
         double-sign evidence observed {evidence}x"
    );

    // 1 — the guarantee that must not bend.
    sim.assert_no_fork("one validator equivocating on every vote");

    // 2 — and it must not have cost the chain its liveness either. Compared against the honest
    // run rather than against zero: a threshold picked out of the air would pass a chain that
    // crawled, and crawling under one byzantine node out of five is itself a failure.
    let best = heights.iter().copied().max().unwrap_or(0);
    assert!(
        best * 2 >= baseline,
        "one equivocator of five took the chain from {baseline} to {best} — the honest four hold \
         a quorum without it and must keep finalising"
    );

    // 3 — detectable. Without this the attack is free, and a free attack is one that gets run.
    assert!(
        evidence > 0,
        "nobody noticed a validator signing two different values for the same height and round; \
         double-sign evidence is what makes equivocation cost its stake"
    );
}

/// The same attack, but the equivocator is also the *proposer* it takes turns being — and the
/// honest nodes are slowed enough that its two conflicting votes land in different orders at
/// different peers.
///
/// Order is the interesting variable: a node that saw the good vote first and a node that saw the
/// twin first hold different first impressions of the same validator. If anything downstream
/// treats "the first vote I saw" as the truth, this is where the two halves of the network stop
/// agreeing — and it would show up as a fork rather than as a rejected vote.
#[test]
fn conflicting_votes_arriving_in_different_orders_still_agree_on_one_chain() {
    let mut sim = Sim::new(5, 2).byzantine(2).slow(3, 3).slow(4, 1);
    sim.run(250);
    println!(
        "equivocator with reordered delivery: heights={:?}, evidence={}",
        sim.heights(),
        sim.evidence_collected()
    );
    sim.assert_no_fork("conflicting votes delivered in different orders");
}

/// **Do five honest validators accuse each other of double-signing?**
///
/// Found while red-running the byzantine test above: with the attack switched off, the run still
/// reported 264 pieces of double-sign evidence. Either the harness manufactures it, or honest
/// nodes really do produce conflicting votes — and the second would mean a validator can be
/// slashed 5 % of its stake for doing nothing wrong, which is worse than any attack tested here.
///
/// No faults at all: no silence, no latency beyond one tick, no byzantine node. Anything this
/// finds, an honest network finds.
#[test]
fn honest_validators_never_accuse_each_other_of_double_signing() {
    let mut sim = Sim::new(5, 1);
    sim.run(200);
    // Inspect before asserting: "there is evidence" is a symptom, and the shape of the conflict
    // is what says whether this is the harness or the engine.
    let mut detail: Vec<String> = Vec::new();
    let mut evidence = 0usize;
    for (i, n) in sim.nodes.iter_mut().enumerate() {
        let all = n.engine.take_evidence();
        // Counted in full, shown in part: the assertion is about *whether* honest nodes accuse
        // each other, and a count that silently reported only the first few per node would
        // understate a regression by whatever factor the sample happened to be.
        evidence += all.len();
        for e in all.into_iter().take(3) {
            detail.push(format!(
                "node{i} saw {} at h{} r{} type {:?}: {} vs {}",
                &e.validator.to_string()[..10],
                e.height,
                e.round,
                e.vote_a.vote_type,
                &e.vote_a.block_hash.to_hex()[..8],
                &e.vote_b.block_hash.to_hex()[..8],
            ));
        }
    }
    println!("five honest validators, 200 ticks: heights={:?}, evidence={evidence}", sim.heights());
    for d in detail.iter().take(10) {
        println!("  {d}");
    }
    assert_eq!(
        evidence, 0,
        "honest validators produced {evidence} pieces of double-sign evidence against each other. \
         Evidence is what slashing runs on, so this is a validator losing stake for behaving \
         correctly — or, if the evidence is never acted on, a detector that cries wolf so often \
         that a real equivocation is indistinguishable from the noise"
    );
}

/// **Two equivocators of five — one more than the protocol is owed.**
///
/// `3f+1` with five validators buys f=1. At two, every guarantee about *progress* is void and the
/// chain is allowed to do nothing at all. Exactly one thing is still owed, and it is the one that
/// matters: **it must not fork.** A halt costs hours and is recoverable by people; two nodes
/// finalising different blocks at the same height is not recoverable by anyone.
///
/// This is the boundary the whole design is built on, and it had no test. The five production
/// outages of the last month were all halts — which is the *correct* failure, and this is what
/// says so on purpose rather than by luck.
#[test]
fn two_equivocators_of_five_may_halt_the_chain_but_must_never_fork_it() {
    let mut sim = Sim::new(5, 1).byzantine(3).byzantine(4);
    sim.run(250);
    let heights = sim.heights();
    let evidence = sim.evidence_collected();
    println!("two equivocators of five: heights={heights:?}, evidence={evidence}");

    // The guarantee. Nothing else here is asserted as a requirement, because nothing else is owed.
    sim.assert_no_fork("two of five equivocating, past the fault budget");

    // Stated rather than asserted: whether it also kept moving is worth knowing and is not a
    // promise. A run that halts here is correct; one that forks is not.
    assert!(
        evidence > 0,
        "two validators equivocating must still be detectable — undetected equivocation past the \
         fault budget is an attack with no cost at all"
    );
}

/// A byzantine validator that equivocates **and** is slow, so its two conflicting votes reach the
/// honest nodes at different times as well as in different orders.
///
/// Timing is the variable a same-tick delivery hides: if anything treats "the vote I already had"
/// as settled and refuses the second rather than recording the conflict, evidence disappears while
/// the equivocation still happened — the attack becomes free.
#[test]
fn an_equivocator_whose_votes_arrive_apart_is_still_caught() {
    let mut sim = Sim::new(5, 1).byzantine(1).slow(1, 4);
    sim.run(250);
    let evidence = sim.evidence_collected();
    println!("slow equivocator: heights={:?}, evidence={evidence}", sim.heights());
    sim.assert_no_fork("an equivocator whose votes arrive apart");
    assert!(
        evidence > 0,
        "an equivocation spread over four ticks must still be recorded — catching it only when \
         both votes land together would make the attack free by simply waiting"
    );
}

/// **The dangerous shape: a validator that tells half the network one value and half another.**
///
/// The undirected equivocation above is measurably harmless — both votes reach everyone, the
/// honest one still counts, and the chain does not even slow down. This is the version that could
/// actually fork a chain: each honest node receives exactly one vote per round from the attacker,
/// so **no individual node ever sees a conflict**. There is nothing for any single participant to
/// refuse. The disagreement exists only in the difference between them, which is precisely the
/// situation quorum arithmetic is supposed to survive.
///
/// With five validators and one attacker, neither half can reach the 4-of-5 quorum on its own
/// value — that is the claim, and this is the test of it rather than a re-derivation of it.
#[test]
fn a_validator_telling_each_half_of_the_network_a_different_value_forks_nothing() {
    let mut sim = Sim::new(5, 1).byzantine(2).split_brain();
    sim.run(250);
    println!(
        "split-brain equivocator: heights={:?}, evidence={}",
        sim.heights(),
        sim.evidence_collected()
    );
    sim.assert_no_fork("one validator feeding each half a different value");
}

/// The same split-brain attack from **two** validators — past the fault budget, where progress is
/// no longer owed and only safety is.
///
/// This is the worst case the design admits: two of five lying in a coordinated, targeted way,
/// with no honest node able to detect either of them locally. If a fork is reachable at all, it is
/// reachable here.
#[test]
fn two_split_brain_validators_past_the_fault_budget_still_cannot_fork_the_chain() {
    let mut sim = Sim::new(5, 1).byzantine(3).byzantine(4).split_brain();
    sim.run(300);
    println!(
        "two split-brain equivocators: heights={:?}, evidence={}",
        sim.heights(),
        sim.evidence_collected()
    );
    sim.assert_no_fork("two validators feeding each half a different value");
}
