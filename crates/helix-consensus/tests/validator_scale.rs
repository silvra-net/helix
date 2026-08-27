//! What the consensus rules actually do as the validator set grows — and how many failures a set
//! of a given size really survives.
//!
//! **This chain has got that arithmetic wrong twice by hand**, both times in the direction that
//! matters: believing three validators tolerate one failure. They tolerate none. With every
//! validator above the 1 % voting-power cap they are all exactly equal, so the threshold is
//! `2N/3 + 1` of `N` equal shares — three of three at N=3, three of four at N=4. The difference
//! decides whether the chain keeps producing when somebody reboots, and it has cost this chain
//! real outages.
//!
//! `four_validators_survive_one_going_offline` in `helix-node` proves the four-node case with
//! real processes. That is the right test for the integration, and the wrong one for the *rule*:
//! spawning eleven node processes to find out what eleven validators tolerate is neither
//! affordable nor necessary. These run the real `ValidatorSet` and real `BftEngine`s in process.

use std::collections::HashMap;

use helix_consensus::{BftEngine, Proposal, Validator, ValidatorSet, Vote};
use helix_crypto::{Address, Hash, KeyPair};

/// A set of `n` equal validators, built exactly as the chain builds one.
fn equal_set(n: usize, stake: u64) -> (Vec<KeyPair>, ValidatorSet) {
    let kps: Vec<KeyPair> = (0..n).map(|_| KeyPair::generate()).collect();
    let validators = kps
        .iter()
        .map(|kp| Validator::new(Address::from_public_key(&kp.public), stake, true))
        .collect();
    (kps, ValidatorSet::new(validators, 0))
}

/// How many validators may be absent before the remainder can no longer reach quorum.
fn tolerated_failures(set: &ValidatorSet) -> usize {
    let members: Vec<u64> = set.full_members().map(|v| v.voting_power).collect();
    let quorum = set.quorum_threshold();
    let total: u64 = members.iter().sum();
    // Remove the *strongest* first: the worst case for liveness is losing the heaviest members.
    let mut sorted = members.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let mut lost = 0u64;
    for (i, power) in sorted.iter().enumerate() {
        lost += power;
        if total - lost < quorum {
            return i;
        }
    }
    members.len()
}

/// The rule, stated once and checked across the whole range an operator might run.
///
/// `floor((n - 1) / 3)` — the standard BFT figure, and the one the project guide quotes. It is
/// asserted here against the *real* `ValidatorSet::quorum_threshold`, not restated, so a change to
/// how power or the threshold is computed has to come past this test rather than past a comment.
#[test]
fn a_set_of_n_equal_validators_tolerates_exactly_floor_n_minus_1_over_3_failures() {
    for n in 1..=25usize {
        let (_kps, set) = equal_set(n, 10_000 * 1_000_000_000);
        let expected = (n - 1) / 3;
        assert_eq!(
            tolerated_failures(&set),
            expected,
            "a set of {n} must survive exactly {expected} absent validators (quorum {} of {})",
            set.quorum_threshold(),
            set.total_voting_power(),
        );
    }
}

/// The three numbers this project keeps having to re-derive, pinned so nobody has to.
#[test]
fn the_sizes_that_actually_matter_are_what_the_notes_say_they_are() {
    let tolerance = |n: usize| tolerated_failures(&equal_set(n, 10_000 * 1_000_000_000).1);
    assert_eq!(tolerance(1), 0, "a sole validator is not fault tolerance, it is no faults");
    assert_eq!(tolerance(2), 0);
    assert_eq!(tolerance(3), 0, "three is the trap — it feels redundant and tolerates nothing");
    assert_eq!(tolerance(4), 1, "four is the first set that survives one reboot");
    assert_eq!(tolerance(7), 2, "seven is the first that survives two");
    assert_eq!(tolerance(10), 3);
}

/// The 1 % cap, and **exactly where it stops applying** — which is the half that gets misread.
///
/// Measured live on 2026-07-22 and written into the project guide: a validator with 5,000 HLX and
/// one with 100,000 both reported `voting_power = 1050000000000`. True, and it is easy to shorten
/// that into "stake does not matter", which is false. `voting_power = min(raw, total_stake/100)`,
/// so the cap equalises everyone *above* it and leaves everyone below it weighted by stake. A set
/// where one member sits under the cap is not a set of equals, and reasoning about it as though it
/// were is how the quorum arithmetic gets it wrong.
///
/// This test failed when first written, against a premise of mine rather than against the code —
/// worth keeping as the shape it actually is.
#[test]
fn the_one_percent_cap_equalises_everyone_above_it_and_nobody_below_it() {
    let kps: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate()).collect();
    // Total 1.31 M ⇒ cap = 13,100. The first sits under it, the other three are far above.
    let stakes = [10_000u64, 50_000, 250_000, 1_000_000];
    let validators: Vec<Validator> = kps
        .iter()
        .zip(stakes)
        .map(|(kp, s)| Validator::new(Address::from_public_key(&kp.public), s * 1_000_000_000, true))
        .collect();
    let set = ValidatorSet::new(validators, 0);
    let powers: Vec<u64> = set.full_members().map(|v| v.voting_power).collect();

    let cap = set.full_members().map(|v| v.stake).sum::<u64>() / 100;
    assert_eq!(cap, 13_100 * 1_000_000_000, "premise: the cap sits between the first stake and the rest");
    assert_eq!(powers[0], 10_000 * 1_000_000_000, "below the cap, stake is the power");
    assert!(
        powers[1..].windows(2).all(|w| w[0] == w[1]),
        "above the cap, a twentyfold difference in stake must produce identical power: {powers:?}"
    );
    assert_eq!(powers[1], cap, "and that identical power is exactly the cap");

    // The consequence worth stating: a whale buys no extra say. Staking twenty times more than
    // the next validator leaves it with the same vote.
    assert_eq!(powers[3], powers[1], "the largest stake in the set has no more weight than the third");
}

/// Four equals really are four equals — the control for the test above, so "they are all the same"
/// is asserted somewhere it is actually true rather than inferred from a set where it is not.
#[test]
fn a_set_of_equal_stakes_above_the_cap_has_identical_power_throughout() {
    let (_kps, set) = equal_set(4, 100_000 * 1_000_000_000);
    let powers: Vec<u64> = set.full_members().map(|v| v.voting_power).collect();
    assert!(powers.windows(2).all(|w| w[0] == w[1]), "{powers:?}");
    assert_eq!(tolerated_failures(&set), 1, "and it behaves like four equals");
}

/// The proposer schedule has to visit everybody, or a validator can stake, run correctly and never
/// propose — invisible in a small set and obvious in a large one.
#[test]
fn every_validator_gets_a_proposer_turn_and_they_come_round_evenly() {
    for n in [2usize, 4, 7, 11] {
        let (_kps, set) = equal_set(n, 10_000 * 1_000_000_000);
        let mut turns: HashMap<Address, usize> = HashMap::new();
        for height in 0..(n as u64 * 20) {
            let p = set.proposer_for_round(height, 0).expect("a proposer");
            *turns.entry(p.address.clone()).or_default() += 1;
        }
        assert_eq!(turns.len(), n, "every one of the {n} validators must get turns");
        assert!(
            turns.values().all(|&t| t == 20),
            "and evenly — a schedule that favours anyone is a schedule someone can grind: {turns:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Running engines, not just arithmetic.
// ---------------------------------------------------------------------------------------------

struct Net {
    engines: Vec<BftEngine>,
    kps: Vec<KeyPair>,
    prev: Hash,
    /// Payload identities already published, per node. Gossipsub identifies a message by a hash of
    /// its bytes and refuses the same bytes for a minute, so a re-offer never reaches a peer that
    /// missed the first broadcast — a harness that re-delivered would quietly repair the failure
    /// it is meant to expose.
    published: Vec<std::collections::HashSet<String>>,
    committed: Vec<u64>,
    /// Indices that are switched off: they neither tick nor receive.
    down: Vec<usize>,
}

enum Msg {
    Prop(Box<Proposal>),
    Vote(Box<Vote>),
}

impl Net {
    fn new(n: usize, down: Vec<usize>) -> Self {
        let (kps, set) = equal_set(n, 10_000 * 1_000_000_000);
        let genesis = Hash::digest(b"scale-genesis");
        let engines = kps
            .iter()
            .map(|kp| BftEngine::new(set.clone(), Address::from_public_key(&kp.public), 0))
            .collect();
        Net {
            engines,
            kps,
            prev: genesis,
            published: vec![Default::default(); n],
            committed: vec![0; n],
            down,
        }
    }

    fn live(&self, i: usize) -> bool {
        !self.down.contains(&i)
    }

    fn offer(&mut self, i: usize, out: &mut Vec<(usize, Msg)>) {
        if let Some(p) = self.engines[i].pending_proposal_envelope() {
            let key = format!("{}:{}:{}", p.block.height(), p.round, p.block.hash());
            if self.published[i].insert(key) {
                out.push((i, Msg::Prop(Box::new(p))));
            }
        }
    }

    fn tick(&mut self, i: usize, out: &mut Vec<(usize, Msg)>) {
        self.offer(i, out);
        let stalled = self.engines[i].note_round_tick(&self.kps[i]);
        let prev = self.prev;
        let produced = if stalled {
            self.engines[i].advance_round(&self.kps[i], prev, vec![])
        } else {
            self.engines[i].produce_block(&self.kps[i], prev, vec![])
        };
        if let Ok(block) = produced {
            self.prev = block.hash();
            self.committed[i] += 1;
        }
        self.offer(i, out);
        for v in self.engines[i].take_outbound_votes() {
            out.push((i, Msg::Vote(Box::new(v))));
        }
    }

    fn deliver(&mut self, to: usize, msg: &Msg, out: &mut Vec<(usize, Msg)>) {
        let finalized = match msg {
            Msg::Prop(p) => {
                self.engines[to].receive_proposal(&self.kps[to], (**p).clone()).ok().flatten()
            }
            Msg::Vote(v) => self.engines[to].add_vote(&self.kps[to], (**v).clone()).ok().flatten(),
        };
        if let Some(block) = finalized {
            self.prev = block.hash();
            self.committed[to] += 1;
        }
        for v in self.engines[to].take_outbound_votes() {
            out.push((to, Msg::Vote(Box::new(v))));
        }
    }

    /// Run `ticks` rounds of the whole set, broadcasting every message to every live peer with
    /// `latency` ticks of delay.
    fn run(&mut self, ticks: usize, latency: usize) {
        let n = self.engines.len();
        let mut wire: Vec<(usize, usize, std::rc::Rc<Msg>)> = Vec::new();
        for t in 0..ticks {
            for (at, to, m) in std::mem::take(&mut wire) {
                if at > t {
                    wire.push((at, to, m));
                    continue;
                }
                if !self.live(to) {
                    continue;
                }
                let mut out = Vec::new();
                self.deliver(to, &m, &mut out);
                for (from, msg) in out {
                    let msg = std::rc::Rc::new(msg);
                    for peer in 0..n {
                        if peer != from {
                            wire.push((t + latency, peer, msg.clone()));
                        }
                    }
                }
            }
            for i in 0..n {
                if !self.live(i) {
                    continue;
                }
                let mut out = Vec::new();
                self.tick(i, &mut out);
                for (from, msg) in out {
                    let msg = std::rc::Rc::new(msg);
                    for peer in 0..n {
                        if peer != from {
                            wire.push((t + latency, peer, msg.clone()));
                        }
                    }
                }
            }
        }
    }

    /// Blocks committed by the healthy part of the set.
    fn live_commits(&self) -> u64 {
        (0..self.engines.len()).filter(|i| self.live(*i)).map(|i| self.committed[i]).max().unwrap_or(0)
    }
}

/// Seven validators keep producing with two of them dead — the property the whole "get to seven"
/// plan rests on, run against real engines rather than a table.
#[test]
#[ignore = "seven real BFT engines × 400 ticks, every round signing and verifying real ML-DSA — ~1 min in release, far longer in debug; run via scripts/build-all.sh or with --release --ignored"]
fn seven_validators_keep_committing_with_two_of_them_dead() {
    let mut net = Net::new(7, vec![5, 6]);
    net.run(400, 1);
    assert!(
        net.live_commits() > 0,
        "seven validators must tolerate two failures — this is the arithmetic the plan to reach \
         seven is built on, and if it is wrong the plan is wrong"
    );
}

/// And the boundary in the other direction: with three of seven gone the set is *below* quorum and
/// must stop. A set that kept committing here would mean the threshold was not being enforced —
/// the far worse failure, because it is silent.
#[test]
#[ignore = "seven real BFT engines × 400 ticks — ~1 min in release; run via scripts/build-all.sh or with --release --ignored"]
fn seven_validators_stop_when_a_third_of_them_is_gone() {
    let mut net = Net::new(7, vec![4, 5, 6]);
    net.run(400, 1);
    assert_eq!(
        net.live_commits(),
        0,
        "four of seven is below the 2/3+1 threshold — committing anyway means the quorum rule is \
         not being enforced, which is worse than stopping"
    );
}
