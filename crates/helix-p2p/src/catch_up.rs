//! Catching up over block sync from several peers at once.
//!
//! Until 2026-10-21 a node behind the tip kept **one** block-sync request out at a time. That made
//! the time one answer takes the bound on catch-up, whatever the size of the answer — and under
//! load that time is not set by the bytes. Measured on the production validator that afternoon,
//! 340 blocks behind: answers for 5, 6, 8, 12 and 27 blocks each took 10–30 s, and the same peers
//! later delivered 49 blocks in 6–10 s. At ~5 blocks per 20 s the node fell further behind a chain
//! that adds one every 2.2 s, and every timeout halved the next request on top. Per-request
//! latency is the thing to beat, and the way to beat a latency is to have several requests out.
//!
//! Each request goes to a different peer and asks for a different, consecutive range — nothing is
//! fetched twice, so the bytes the network spends on a node's catch-up stay what they were; they
//! are only spread over more uplinks. Answers can arrive in any order and are handed to the node
//! strictly in order, one at a time, because a batch is verified against the state the previous
//! one leaves behind (its first block must chain from our tip, its certificate is checked against
//! the validator set that state holds). What the node verifies and how is unchanged.
//!
//! The plan is generic over the peer, request id and answer types so it can be tested without a
//! swarm — libp2p's request ids have no public constructor.

use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;

/// How many block-sync requests a node keeps out at once, each to a different peer.
///
/// Four, because a peer serves at most two answers at a time and one per asker
/// (`MAX_BLOCKSYNC_SERVES`): four askers at most take two places on each of two peers, and a node
/// with fewer than four usable peers simply asks fewer. Enough to put the measured 20 s latency
/// behind the chain's pace with the smallest batch (4 × 5 blocks per 20 s against one block per
/// ~2 s), few enough that a node does not occupy the serving places of every peer it has.
pub(crate) const PARALLEL_REQUESTS: usize = 4;

/// How many ranges — asked for or answered and waiting for their turn — the plan holds at once.
///
/// Bounds memory: an answer is at most `MAX_RESPONSE_BLOCK_BYTES` (~7 MiB), so six cost at most
/// ~42 MiB, and only while a node is behind. Two more than the requests in flight, so answers that
/// arrived ahead of a slow one do not stop the next requests from going out at once.
pub(crate) const MAX_RANGES: usize = PARALLEL_REQUESTS + 2;

/// Driver ticks (2 s each) a batch handed to the node may take before the plan stops waiting for
/// its report. The node reports every outcome (`BlocksyncAdvance`, `BlocksyncBatchRejected`), but
/// by `try_send`, which can drop a report when the command queue is full; the tip sample catches
/// most of that, this catches the rest. A minute is far above what applying a batch takes.
pub(crate) const HANDED_TIMEOUT_TICKS: u32 = 30;

/// One request to send: `count` blocks from `from`, to `peer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ask<P> {
    pub peer: P,
    pub from: u64,
    pub count: u32,
}

/// What became of an answer, as far as the caller has to act on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Answered<P> {
    /// Kept until its turn.
    Held,
    /// The peer served nothing. It claimed a tip above the range, so this contradicts its own
    /// announcement — the caller cools it down, as for any empty answer (#140).
    Empty(P),
    /// The peer served blocks other than the ones asked for: not starting at the first one, or
    /// running past the last. An honest node never does — it serves what was asked or a prefix
    /// of it (the byte budget). Dropped, and the caller cools the peer down.
    Misfit(P),
    /// No request with this id is outstanding — the range was dropped meanwhile (our tip passed
    /// it, its peer was forgotten). Nothing to do.
    Unknown,
}

#[derive(Debug)]
enum State<I, B> {
    Asked(I),
    Held(B),
}

#[derive(Debug)]
struct Range<P, I, B> {
    /// The last height this range covers: what was asked for until an answer arrives, then what
    /// the answer actually holds (a peer may serve a prefix — its byte budget, #248).
    last: u64,
    peer: P,
    state: State<I, B>,
}

#[derive(Debug)]
struct Handed {
    last: u64,
    ticks: u32,
}

/// The requests a catching-up node has out and the answers it holds until they can be applied.
#[derive(Debug)]
pub(crate) struct CatchUp<P, I, B> {
    /// Keyed by first height. Disjoint, and never covering a height at or below the tip the plan
    /// last saw.
    ranges: BTreeMap<u64, Range<P, I, B>>,
    /// The batch the node is applying now, if any — no longer in `ranges`, and not to be asked for
    /// again while the node works on it.
    handed: Option<Handed>,
}

impl<P, I, B> Default for CatchUp<P, I, B> {
    fn default() -> Self {
        Self {
            ranges: BTreeMap::new(),
            handed: None,
        }
    }
}

impl<P: Clone + Eq + Hash, I: Eq, B> CatchUp<P, I, B> {
    /// Whether this node is asking for blocks at all — a request out, or a batch being applied.
    /// What the stall report's `requesting` means (#190).
    pub(crate) fn is_asking(&self) -> bool {
        self.handed.is_some()
            || self
                .ranges
                .values()
                .any(|r| matches!(r.state, State::Asked(_)))
    }

    fn asked(&self) -> usize {
        self.ranges
            .values()
            .filter(|r| matches!(r.state, State::Asked(_)))
            .count()
    }

    /// The next request to send, if there is room for one and anyone to send it to.
    ///
    /// Fills the **lowest** height nothing covers yet, so a hole left by a failed request is
    /// asked for again before the plan reaches further ahead. `choose(from, busy)` names a peer
    /// that can serve `from` and is not in `busy` (the peers already answering one of ours),
    /// with the tip it claims; `count_for(below, peer_tip)` is how many blocks one request from
    /// `below + 1` may cover (the epoch rule, `blocksync_request_count`). `limit` is the highest
    /// height worth asking for at all (a protocol upgrade this build does not run, #267).
    ///
    /// Returns the request without recording it: the caller sends it and calls [`Self::asked_for`]
    /// with the id libp2p gives it.
    pub(crate) fn next_ask(
        &self,
        our_tip: u64,
        limit: Option<u64>,
        batch: u32,
        mut choose: impl FnMut(u64, &HashSet<P>) -> Option<(P, u64)>,
        count_for: impl Fn(u64, u64) -> u32,
    ) -> Option<Ask<P>> {
        if self.asked() >= PARALLEL_REQUESTS || self.ranges.len() >= MAX_RANGES {
            return None;
        }
        // The lowest uncovered height, and where the next covered stretch begins above it.
        let mut from = our_tip.saturating_add(1);
        if let Some(h) = &self.handed {
            from = from.max(h.last.saturating_add(1));
        }
        let mut next_covered = None;
        for (&start, range) in self.ranges.range(..) {
            if range.last < from {
                continue;
            }
            if start > from {
                next_covered = Some(start);
                break;
            }
            from = range.last.saturating_add(1);
        }
        if limit.is_some_and(|l| from > l) {
            return None;
        }
        let busy: HashSet<P> = self
            .ranges
            .values()
            .filter(|r| matches!(r.state, State::Asked(_)))
            .map(|r| r.peer.clone())
            .collect();
        let (peer, peer_tip) = choose(from, &busy)?;
        let mut count = u64::from(count_for(from - 1, peer_tip).min(batch));
        if let Some(next) = next_covered {
            count = count.min(next - from);
        }
        if let Some(l) = limit {
            count = count.min(l + 1 - from);
        }
        if count == 0 {
            return None;
        }
        Some(Ask {
            peer,
            from,
            count: count as u32,
        })
    }

    /// Record a request that went out.
    pub(crate) fn asked_for(&mut self, ask: Ask<P>, id: I) {
        let last = ask.from + u64::from(ask.count) - 1;
        self.ranges.insert(
            ask.from,
            Range {
                last,
                peer: ask.peer,
                state: State::Asked(id),
            },
        );
    }

    /// An answer arrived. `heights` is the first and last height it holds, `None` when empty.
    pub(crate) fn answered(
        &mut self,
        id: &I,
        answer: B,
        heights: Option<(u64, u64)>,
    ) -> Answered<P> {
        let Some(from) = self
            .ranges
            .iter()
            .find(|(_, r)| matches!(&r.state, State::Asked(i) if i == id))
            .map(|(&from, _)| from)
        else {
            return Answered::Unknown;
        };
        let Some((first, last)) = heights else {
            let range = self.ranges.remove(&from).expect("found above");
            return Answered::Empty(range.peer);
        };
        let range = self.ranges.get_mut(&from).expect("found above");
        if first != from || last < first || last > range.last {
            let range = self.ranges.remove(&from).expect("found above");
            return Answered::Misfit(range.peer);
        }
        range.last = last;
        range.state = State::Held(answer);
        Answered::Held
    }

    /// A request failed (timeout, broken stream, closed connection). Returns the peer it went to,
    /// `None` if the range was dropped meanwhile. The range becomes a hole the next ask fills.
    pub(crate) fn failed(&mut self, id: &I) -> Option<P> {
        let from = self
            .ranges
            .iter()
            .find(|(_, r)| matches!(&r.state, State::Asked(i) if i == id))
            .map(|(&from, _)| from)?;
        self.ranges.remove(&from).map(|r| r.peer)
    }

    /// The next batch for the node, if it is the one that continues our tip. A batch reaching back
    /// below the tip is handed over all the same — another path moved the tip while it was in
    /// flight — and the node skips what it holds.
    ///
    /// Order needs nothing more than that: the batch after the one being applied starts above our
    /// tip until that one is applied, so it waits by itself.
    pub(crate) fn take_next(&mut self, our_tip: u64) -> Option<(B, P)> {
        self.drop_below(our_tip);
        let (&from, range) = self.ranges.iter().next()?;
        if from > our_tip.saturating_add(1) || !matches!(range.state, State::Held(_)) {
            return None;
        }
        let range = self.ranges.remove(&from).expect("just seen");
        let State::Held(answer) = range.state else {
            unreachable!("checked above")
        };
        self.handed = Some(Handed {
            last: range.last,
            ticks: 0,
        });
        Some((answer, range.peer))
    }

    /// The node reported the outcome of the batch it was given: applied up to `new_tip` (all of it
    /// or a proven prefix), or nothing new. Either way it is ready for the next one, and whatever
    /// the batch did not cover becomes a hole the next ask fills.
    pub(crate) fn node_reported(&mut self, new_tip: u64) {
        self.handed = None;
        self.drop_below(new_tip);
    }

    /// The node threw the batch it was given away. Its peer is cooled down by the caller; the range
    /// is asked for again, from someone else.
    pub(crate) fn node_rejected(&mut self) {
        self.handed = None;
    }

    /// Stop asking `peer` for anything and drop what it served (it proved to be on another
    /// history). A request still out to it is simply never matched again.
    pub(crate) fn forget_peer(&mut self, peer: &P) {
        self.ranges.retain(|_, r| &r.peer != peer);
    }

    /// One driver tick: forget what our tip has passed, and give up waiting for a report the node
    /// never sent.
    pub(crate) fn tick(&mut self, our_tip: u64) {
        self.drop_below(our_tip);
        if let Some(h) = self.handed.as_mut() {
            if our_tip >= h.last {
                self.handed = None;
            } else {
                h.ticks += 1;
                if h.ticks >= HANDED_TIMEOUT_TICKS {
                    self.handed = None;
                }
            }
        }
    }

    /// Drop every range our tip has passed entirely. A range that only reaches back below it stays:
    /// its upper part is still needed.
    fn drop_below(&mut self, our_tip: u64) {
        self.ranges.retain(|_, r| r.last > our_tip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Plan = CatchUp<&'static str, u32, &'static str>;

    /// Every peer can serve anything up to `tip`, and the epoch rule never bites.
    fn anyone(
        peers: &'static [&'static str],
        tip: u64,
    ) -> impl FnMut(u64, &HashSet<&'static str>) -> Option<(&'static str, u64)> {
        move |_, busy| peers.iter().find(|p| !busy.contains(*p)).map(|p| (*p, tip))
    }

    fn up_to(below: u64, peer_tip: u64) -> u32 {
        peer_tip.saturating_sub(below).min(50) as u32
    }

    /// Ask as many times as the plan allows, recording each with a fresh id.
    fn ask_all(
        plan: &mut Plan,
        tip: u64,
        batch: u32,
        peers: &'static [&'static str],
        peer_tip: u64,
    ) -> Vec<Ask<&'static str>> {
        let mut out = Vec::new();
        while let Some(ask) = plan.next_ask(tip, None, batch, anyone(peers, peer_tip), up_to) {
            plan.asked_for(ask.clone(), out.len() as u32);
            out.push(ask);
        }
        out
    }

    const PEERS: &[&str] = &["a", "b", "c", "d", "e", "f"];

    /// The point of the module: a node 300 behind has four requests out at once, each to its own
    /// peer, for consecutive ranges that do not overlap.
    #[test]
    fn a_node_far_behind_asks_several_peers_for_consecutive_ranges() {
        let mut plan = Plan::default();
        let asks = ask_all(&mut plan, 1000, 10, PEERS, 1300);

        assert_eq!(asks.len(), PARALLEL_REQUESTS, "{asks:?}");
        let froms: Vec<u64> = asks.iter().map(|a| a.from).collect();
        assert_eq!(froms, vec![1001, 1011, 1021, 1031]);
        let peers: HashSet<_> = asks.iter().map(|a| a.peer).collect();
        assert_eq!(
            peers.len(),
            PARALLEL_REQUESTS,
            "each request to a different peer"
        );
        assert!(plan.is_asking());
    }

    /// Positive control for the above: one block behind needs one request, not four.
    #[test]
    fn a_node_one_block_behind_sends_one_request() {
        let mut plan = Plan::default();
        let asks = ask_all(&mut plan, 1000, 50, PEERS, 1001);
        assert_eq!(
            asks,
            vec![Ask {
                peer: "a",
                from: 1001,
                count: 1
            }]
        );
    }

    /// With fewer usable peers than the limit, the plan asks fewer — never the same peer twice.
    #[test]
    fn no_peer_is_asked_twice_at_once() {
        let mut plan = Plan::default();
        let asks = ask_all(&mut plan, 1000, 10, &["a", "b"], 1300);
        assert_eq!(asks.len(), 2);
        assert_ne!(asks[0].peer, asks[1].peer);
    }

    /// Answers that arrive out of order wait; the node gets them in order, one at a time.
    #[test]
    fn answers_are_handed_to_the_node_in_order_and_one_at_a_time() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);

        // The second range answers first: nothing to hand over yet.
        assert_eq!(
            plan.answered(&1, "second", Some((1011, 1020))),
            Answered::Held
        );
        assert_eq!(plan.take_next(1000), None, "1001..1010 is still missing");

        assert_eq!(
            plan.answered(&0, "first", Some((1001, 1010))),
            Answered::Held
        );
        assert_eq!(plan.take_next(1000), Some(("first", "a")));
        // The node is applying "first": "second" waits for it, though it is ready.
        assert_eq!(plan.take_next(1000), None);

        plan.node_reported(1010);
        assert_eq!(plan.take_next(1010), Some(("second", "b")));
    }

    /// A failed request leaves a hole, and the hole is asked for again before anything further
    /// ahead — from a peer that is not busy.
    #[test]
    fn a_failed_range_is_asked_for_again_before_anything_further_ahead() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);
        assert_eq!(plan.failed(&1), Some("b"));

        let again = plan
            .next_ask(1000, None, 10, anyone(PEERS, 1300), up_to)
            .expect("room for one more");
        assert_eq!(again.from, 1011, "the hole first");
        assert_eq!(again.count, 10, "and no more than the hole");
        assert!(
            !["a", "c", "d"].contains(&again.peer),
            "not a peer already answering us"
        );
    }

    /// A hole is never filled past the next range: the request is cut to fit.
    #[test]
    fn a_request_for_a_hole_stops_where_the_next_range_begins() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);
        plan.failed(&0); // 1001..1010 gone, 1011.. still out

        let again = plan
            .next_ask(1000, None, 50, anyone(PEERS, 1300), up_to)
            .unwrap();
        assert_eq!((again.from, again.count), (1001, 10));
    }

    /// An honest peer may serve a prefix (its byte budget). The rest becomes a hole.
    #[test]
    fn a_shorter_answer_is_kept_and_the_rest_asked_for() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);
        assert_eq!(
            plan.answered(&0, "prefix", Some((1001, 1004))),
            Answered::Held
        );

        let again = plan
            .next_ask(1000, None, 50, anyone(PEERS, 1300), up_to)
            .unwrap();
        assert_eq!((again.from, again.count), (1005, 6));
    }

    /// Blocks other than those asked for are not held — whatever else they are, they are not the
    /// range the plan is waiting for.
    #[test]
    fn an_answer_for_another_range_is_refused() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);
        assert_eq!(
            plan.answered(&0, "late start", Some((1002, 1010))),
            Answered::Misfit("a")
        );
        assert_eq!(
            plan.answered(&1, "too long", Some((1011, 1021))),
            Answered::Misfit("b")
        );
        assert_eq!(plan.answered(&2, "nothing", None), Answered::Empty("c"));
        assert_eq!(
            plan.answered(&99, "unasked", Some((1, 2))),
            Answered::Unknown
        );
        // All three are holes again.
        let again = plan
            .next_ask(1000, None, 10, anyone(PEERS, 1300), up_to)
            .unwrap();
        assert_eq!(again.from, 1001);
    }

    /// Another path (consensus, gossip) moved the tip past a range: it is dropped. One that only
    /// reaches back below the tip is handed over — the node skips what it already holds.
    #[test]
    fn ranges_the_tip_passed_are_dropped_and_overlapping_ones_kept() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);
        plan.answered(&0, "first", Some((1001, 1010)));
        plan.answered(&1, "second", Some((1011, 1020)));

        assert_eq!(
            plan.take_next(1015),
            Some(("second", "b")),
            "first was passed; second overlaps"
        );
    }

    /// While the node applies a batch, its range is not a hole: nobody is asked for it again.
    #[test]
    fn the_batch_being_applied_is_not_asked_for_again() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);
        plan.answered(&0, "first", Some((1001, 1010)));
        assert_eq!(plan.take_next(1000), Some(("first", "a")));

        let next = plan
            .next_ask(1000, None, 10, anyone(PEERS, 1300), up_to)
            .unwrap();
        assert_eq!(
            next.from, 1041,
            "past everything asked for or being applied"
        );
    }

    /// The node never reports (a dropped `try_send`): the plan stops waiting once the tip shows
    /// the batch applied, and after the timeout in any case.
    #[test]
    fn a_lost_report_does_not_wedge_the_plan() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);
        plan.answered(&0, "first", Some((1001, 1010)));
        plan.answered(&1, "second", Some((1011, 1020)));
        plan.take_next(1000).unwrap();

        plan.tick(1010);
        assert_eq!(
            plan.take_next(1010),
            Some(("second", "b")),
            "the tip says it applied"
        );

        for _ in 0..HANDED_TIMEOUT_TICKS - 1 {
            plan.tick(1010);
        }
        assert!(
            plan.handed.is_some(),
            "still waiting just before the timeout"
        );
        plan.tick(1010);
        assert!(plan.handed.is_none(), "given up after the timeout");
    }

    /// The node rejected the batch: the range is asked for again.
    #[test]
    fn a_rejected_batch_is_asked_for_again() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);
        plan.answered(&0, "bad", Some((1001, 1010)));
        plan.take_next(1000).unwrap();
        plan.node_rejected();

        let again = plan
            .next_ask(1000, None, 10, anyone(PEERS, 1300), up_to)
            .unwrap();
        assert_eq!(again.from, 1001);
    }

    /// The batch only partly applied (a proven prefix): the rest is asked for again, and the plan
    /// does not wait for a report that already came.
    #[test]
    fn a_partly_applied_batch_leaves_the_rest_to_ask_for() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);
        plan.answered(&0, "first", Some((1001, 1010)));
        plan.take_next(1000).unwrap();
        plan.node_reported(1007);

        let again = plan
            .next_ask(1007, None, 10, anyone(PEERS, 1300), up_to)
            .unwrap();
        assert_eq!((again.from, again.count), (1008, 3));
    }

    /// Never past a protocol upgrade this build does not run.
    #[test]
    fn nothing_is_asked_for_past_the_limit() {
        let plan = Plan::default();
        let ask = plan
            .next_ask(1000, Some(1004), 50, anyone(PEERS, 1300), up_to)
            .unwrap();
        assert_eq!((ask.from, ask.count), (1001, 4));
        assert!(plan
            .next_ask(1004, Some(1004), 50, anyone(PEERS, 1300), up_to)
            .is_none());
    }

    /// Memory is bounded: answers waiting behind a slow first range stop new requests at
    /// `MAX_RANGES`.
    #[test]
    fn held_answers_behind_a_slow_one_are_bounded() {
        let mut plan = Plan::default();
        let mut id = 0u32;
        // The first range never answers; every later one does at once.
        while let Some(ask) = plan.next_ask(1000, None, 10, anyone(PEERS, 100_000), up_to) {
            let (from, last) = (ask.from, ask.from + u64::from(ask.count) - 1);
            plan.asked_for(ask, id);
            if id > 0 {
                plan.answered(&id, "held", Some((from, last)));
            }
            id += 1;
            assert!(id < 100, "the plan never stopped asking");
        }
        assert_eq!(plan.ranges.len(), MAX_RANGES);
    }

    /// A peer proved to be on another history: what it served is dropped and the range asked for
    /// again from someone else.
    #[test]
    fn a_forgotten_peer_loses_its_ranges() {
        let mut plan = Plan::default();
        ask_all(&mut plan, 1000, 10, PEERS, 1300);
        plan.answered(&0, "foreign", Some((1001, 1010)));
        plan.forget_peer(&"a");
        assert_eq!(plan.take_next(1000), None);
        let again = plan
            .next_ask(1000, None, 10, anyone(&["e"], 1300), up_to)
            .unwrap();
        assert_eq!((again.peer, again.from), ("e", 1001));
    }
}
