use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use libp2p::{
    futures::StreamExt,
    gossipsub, mdns, request_response,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use helix_consensus::{Proposal, Vote};
use helix_core::{Block, Transaction};

use crate::blocksync::{
    clamp_batch, BlockProvider, BlockSyncCodec, BlockSyncRequest, BlockSyncResponse,
    BLOCKSYNC_PROTOCOL, MAX_BLOCKSYNC_BATCH,
};
use crate::config::P2PConfig;
use crate::genesis_sync::{GenesisCodec, GenesisProvider, GenesisResponse, GENESIS_PROTOCOL};
use crate::roundsync::{
    RoundProvider, RoundSyncCodec, RoundSyncRequest, RoundSyncResponse, ROUNDSYNC_PROTOCOL,
};
use crate::conn_limits::IpConnLimiter;
use crate::peer_store;
use crate::reputation::PeerReputation;
use crate::{
    P2PError, P2PResult, TOPIC_BLOCKS, TOPIC_COMMITTED_BLOCKS, TOPIC_PEER_EXCHANGE,
    TOPIC_TRANSACTIONS, TOPIC_VOTES,
};

/// Events received FROM the P2P network → node
#[derive(Debug)]
pub enum P2PEvent {
    NewProposal(Proposal),
    NewTransaction(Transaction),
    NewVote(Vote),
    /// A peer broadcast a committed block (already past BFT quorum), together with the commit
    /// certificate — the precommit votes that finalized it. The receiving node applies the block
    /// after verifying the proposer signature, and adopts the certificate as its own `last_commit`
    /// when it never collected those votes itself (the committed-blocks fast path), so the block's
    /// participation and finality are not lost (#114).
    NewCommittedBlock(Block, Vec<Vote>),
    PeerConnected(String),
    PeerDisconnected(String),
    /// This node started announcing `addr` as its own, after a peer confirmed it could reach it.
    ///
    /// Purely so the node layer can log it once, in the operator's terms. The decision itself is
    /// already made by the time this is sent.
    SelfAddressAnnounced(String),
    /// A peer announced, on the periodic peer-exchange gossip, a committed tip *below* ours and
    /// close enough behind to be worth serving over gossip. The node layer answers by
    /// re-broadcasting the committed blocks that peer is missing, each with its commit
    /// certificate, on the committed-blocks topic.
    ///
    /// This is the recovery path whose absence stalled production for 14.5 hours on 2026-07-29
    /// (#137): a `NewCommittedBlock` broadcast fires exactly once, at commit time, and a peer
    /// whose link happens to be down in that instant never hears about the block again. There is
    /// no way to ask for it — so the only catch-up route was an operator-configured RPC
    /// `sync_peer`, which the origin node does not have. A validator that is part of the quorum
    /// and one block behind then deadlocks the chain outright: it cannot advance without the
    /// block, and the block cannot be superseded without its vote.
    PeerBehind {
        /// The committed height that peer announced. It needs `peer_tip + 1` onwards.
        peer_tip: u64,
    },
    /// A peer answered our block-sync request with a contiguous batch of committed blocks and a
    /// commit certificate for the last one (#138). Entirely untrusted: the node layer verifies the
    /// chain, every proposer signature, and the batch tip's quorum *before* anything is written.
    /// A block-sync batch, and the peer that served it — the node reports back via
    /// `P2PCommand::BlocksyncBatchRejected` if it does not verify (backlog #140).
    BlocksSynced(BlockSyncResponse, String),
    /// A peer answered our round-sync request with what it holds for the height being decided:
    /// its pending proposal and the votes it has seen. Entirely untrusted — the node feeds both
    /// through `receive_proposal`/`add_vote`, the same paths a gossiped message takes.
    RoundSynced(RoundSyncResponse, String),
}

/// Commands sent TO the P2P network FROM the node
#[derive(Debug)]
pub enum P2PCommand {
    BroadcastProposal(Proposal),
    BroadcastTransaction(Transaction),
    BroadcastVote(Vote),
    /// Broadcast a committed block, with its commit certificate (the finalizing precommit votes),
    /// to help lagging peers catch up and carry finality with the block (#114).
    BroadcastBlock(Block, Vec<Vote>),
    ConnectPeer(Multiaddr),
    /// Ask a connected peer what it holds for the height this node is deciding — the proposal it
    /// is voting on, and the votes it has collected.
    ///
    /// Sent when this node is waiting on a proposal that has not arrived. It cannot arrive by
    /// itself: gossipsub publishes each message once and refuses to re-publish the same bytes for
    /// a minute, so the proposer's per-tick re-offer never reaches a node that was not listening
    /// during the one broadcast that counted. See the `roundsync` module.
    RequestRoundSync { height: u64, round: u32 },
    /// The node could not verify the block-sync batch this peer served (backlog #140). The service
    /// cannot tell that by itself: from here a batch that fails verification and one that applies
    /// cleanly are both just a non-empty response. Without this the peer keeps being picked — it
    /// is by definition the one claiming the highest tip — and catch-up never moves.
    BlocksyncBatchRejected(String),
    /// A peer proved, by what it served, that it is on a different history: its batch did not
    /// chain from our tip. Stronger than [`Self::BlocksyncBatchRejected`] and used instead of it,
    /// because a cooldown only paces the retries — the peer keeps its claimed tip, keeps winning
    /// `best_blocksync_peer`, and keeps being asked forever.
    ///
    /// **This is evidence, where `PeerChain` is advertisement.** A node from before peer exchange
    /// carried `genesis_hash` reports none, which is `PeerChain::Unknown`, which is deliberately
    /// treated as `Same` — refusing the unknown costs more than it saves. Live on 2026-08-27: a
    /// node still running the chain that was reset away on 2026-08-26 sat at height 477,478, was
    /// never recognised as foreign because it advertised nothing, and had V1 fetching and
    /// discarding a 56-block batch every ten seconds — 310 of them, the exact noise #175 exists to
    /// end. Worse than noise: it claimed the highest tip on the network by an order of magnitude,
    /// so it won every `best_blocksync_peer` choice, which is precisely the wrong peer to prefer
    /// when a real validator needs to catch up.
    BlocksyncPeerOnAnotherChain(String),
    /// A synced batch is on disk and `tip_height` has moved — ask for the next one now instead of
    /// waiting out the rest of `blocksync_interval`.
    ///
    /// The service cannot detect this for itself either: it hands the batch off and never learns
    /// whether or when it was applied. Requesting only on the 2s interval made that period the
    /// floor on the gap between consecutive batches, holding catch-up to `MAX_BLOCKSYNC_BATCH`
    /// blocks per tick — 50 blocks/s — with the link idle in between. See
    /// `request_blocks_if_behind`.
    ///
    /// Carries the height the node just reached. That height is not merely a convenience: the
    /// `tip_height` this service requests against is a **5-second sample** of the store
    /// (`node.rs`, the announce loop), sized for the 30s peer-exchange announcement and far too
    /// coarse for this. Between a batch landing and the next sample, catch-up re-requested the
    /// range it had just applied; the node dropped it as `<= base` without a word, and — the
    /// answer being non-empty and verifying fine — nothing charged a cooldown or logged a
    /// retry. That capped catch-up at one batch per *sample*, 20 blocks/s, not per tick.
    BlocksyncAdvance(u64),
    /// Start announcing `addr` as this node's own on peer exchange.
    ///
    /// Separate from the probe because the two happen on different nodes: whoever asked
    /// `/whoami` gets the verdict, and only that node announces. It lives here rather than in the
    /// node layer because `known_addrs` lives in this task, and the address must become this
    /// node's `self_addr` in the same moment — the filter that stops it dialing its own
    /// announcement when a peer echoes it back.
    AnnounceSelfAddress(String),
}

#[derive(NetworkBehaviour)]
pub(crate) struct HelixBehaviour {
    gossipsub: gossipsub::Behaviour,
    /// LAN peer auto-discovery — `Toggle`d off when `P2PConfig::enable_mdns` is false
    /// (deterministic seed-peer-only peering; see that field's doc comment). When off it
    /// emits no events, so the `Mdns` match arms below simply never fire.
    mdns: Toggle<mdns::tokio::Behaviour>,
    /// Global/pending/per-peer connection caps (backlog #44) — a connection flood
    /// (real or Sybil, distinct `PeerId` per socket) can't grow the swarm's
    /// established/pending connection tables past these bounds.
    connection_limits: libp2p::connection_limits::Behaviour,
    /// Per-source-IP connection cap (backlog #44) — `connection_limits` above has
    /// no notion of IP, so a Sybil attacker presenting a fresh `PeerId` per socket
    /// isn't bounded by it; this closes that gap.
    ip_limits: IpConnLimiter,
    /// Directed block sync (#138). The only behaviour here that can *ask* a specific peer for
    /// something instead of shouting into a topic — which is what a node needs to catch up without
    /// an operator-configured RPC endpoint. See the `blocksync` module.
    blocksync: request_response::Behaviour<BlockSyncCodec>,
    /// Serving the genesis block itself (#139). Separate protocol from `blocksync`, so a peer
    /// running an older build is simply never asked rather than being handed a message it would
    /// misparse. This is what lets a node with no chain at all join from a peer address alone,
    /// instead of needing somebody to run a reachable HTTP endpoint.
    pub(crate) genesis_sync: request_response::Behaviour<GenesisCodec>,
    /// Asking a peer for the proposal and votes of the height being decided right now. Block sync
    /// covers what is already committed; this covers the block that is still being agreed on, and
    /// exists because gossip refuses to re-publish a message it has already sent (see the
    /// `roundsync` module).
    roundsync: request_response::Behaviour<RoundSyncCodec>,
}

pub struct P2PService {
    config: P2PConfig,
    event_tx: mpsc::Sender<P2PEvent>,
    command_rx: mpsc::Receiver<P2PCommand>,
    /// This node's committed tip height, announced on every peer-exchange broadcast so peers can
    /// tell they are behind us (and we can tell we are behind them) without any new protocol.
    ///
    /// Deliberately a shared counter rather than a value the node pushes over `command_rx` and we
    /// cache: a cached height is only as fresh as the last commit, and a node that is *stalled* —
    /// precisely the node that needs serving — never commits again, so it would announce a stale
    /// or zero tip forever and be refused as "too far behind" by `should_serve_catchup`. Reading
    /// the store's real height cannot drift.
    tip_height: Arc<AtomicU64>,
    /// This node's genesis hash, announced in peer exchange so a peer on a different chain can be
    /// named as such instead of silently rejecting everything (see `foreign_chain_warning`). Empty
    /// on a service that was never told, which simply announces nothing.
    genesis_hash: String,
    /// Answers inbound genesis requests (#139). `None` on a node with nothing to serve — every
    /// test in this crate, and any endpoint that is itself still bootstrapping.
    genesis_provider: Option<Arc<dyn GenesisProvider>>,
    /// Answers inbound round-sync requests. `None` on a service with no consensus engine behind
    /// it — every test in this crate — which then answers honestly that it holds nothing.
    round_provider: Option<Arc<dyn RoundProvider>>,
    /// Answers inbound block-sync requests (#138). Supplied by the node, which owns the store —
    /// see [`BlockProvider`] for why the dependency points this way.
    block_provider: Arc<dyn BlockProvider>,
    /// Highest tip any connected peer currently claims, published for the node (backlog #154).
    ///
    /// Peer-supplied and therefore untrusted, which is why the node may only use it in the safe
    /// direction: as a reason to keep *holding* block production, never as a reason to start. A
    /// peer claiming too low cannot release us early — this is a maximum over all peers, so one
    /// honest higher claim dominates. A peer claiming too high can hold us, which costs this node
    /// its own liveness and nothing else, and only while the RPC catch-up (the other, independent
    /// release path) also stays unavailable.
    highest_peer_tip: Option<Arc<AtomicU64>>,
}

impl P2PService {
    pub fn new(
        config: P2PConfig,
        tip_height: Arc<AtomicU64>,
        block_provider: Arc<dyn BlockProvider>,
    ) -> (Self, mpsc::Sender<P2PCommand>, mpsc::Receiver<P2PEvent>) {
        let (event_tx, event_rx) = mpsc::channel(256);
        let (command_tx, command_rx) = mpsc::channel(256);
        (
            P2PService {
                config,
                event_tx,
                command_rx,
                tip_height,
                block_provider,
                genesis_hash: String::new(),
                genesis_provider: None,
                round_provider: None,
                highest_peer_tip: None,
            },
            command_tx,
            event_rx,
        )
    }

    /// Publish the highest tip claimed by any connected peer into `slot` (backlog #154).
    ///
    /// Opt-in rather than a constructor argument so the many call sites that do not care — every
    /// test in this crate among them — stay as they are.
    pub fn with_peer_tip_reporting(mut self, slot: Arc<AtomicU64>) -> Self {
        self.highest_peer_tip = Some(slot);
        self
    }

    /// Announce which chain this node is on, so a peer on another one can be told (#164).
    ///
    /// Opt-in like the other two, so every test in this crate stays as it is — and a service that
    /// does not set it announces an empty hash, which reads as "did not say" rather than as a
    /// mismatch.
    pub fn announcing_genesis(mut self, genesis_hash: String) -> Self {
        self.genesis_hash = genesis_hash;
        self
    }

    /// Serve the local genesis to peers that ask for it (#139).
    ///
    /// Opt-in for the same reason as `with_peer_tip_reporting`: the tests in this crate and every
    /// other caller that has no genesis to offer stay exactly as they are, and a node that does not
    /// set one answers honestly that it has nothing rather than pretending the protocol is absent.
    pub fn with_genesis_provider(mut self, provider: Arc<dyn GenesisProvider>) -> Self {
        self.genesis_provider = Some(provider);
        self
    }

    /// Serve the round this node is deciding to peers that ask for it.
    ///
    /// Opt-in like the others: a service without one answers "nothing for that height", which is
    /// the truthful answer for a node that runs no consensus engine.
    pub fn with_round_provider(mut self, provider: Arc<dyn RoundProvider>) -> Self {
        self.round_provider = Some(provider);
        self
    }

    pub async fn run(self) -> P2PResult<()> {
        // Destructure so we can move fields into the loop without borrowing `self`
        let event_tx = self.event_tx;
        let mut command_rx = self.command_rx;
        let config = self.config;
        let tip_height = self.tip_height;
        let block_provider = self.block_provider;
        let genesis_provider = self.genesis_provider;
        let round_provider = self.round_provider;
        let our_genesis = self.genesis_hash;
        let highest_peer_tip = self.highest_peer_tip;

        let mut swarm = build_swarm(&config).await?;

        let local_peer_id = swarm.local_peer_id().to_string();

        let block_topic = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
        let tx_topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);
        let vote_topic = gossipsub::IdentTopic::new(TOPIC_VOTES);
        let committed_topic = gossipsub::IdentTopic::new(TOPIC_COMMITTED_BLOCKS);
        let peer_exchange_topic = gossipsub::IdentTopic::new(TOPIC_PEER_EXCHANGE);

        swarm.behaviour_mut().gossipsub.subscribe(&block_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&tx_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&vote_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&committed_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&peer_exchange_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;

        let listen_addr: Multiaddr = format!(
            "/ip4/{}/tcp/{}",
            config.listen_addr.ip(),
            config.listen_addr.port()
        )
        .parse()
        .map_err(|e: libp2p::multiaddr::Error| P2PError::Transport(e.to_string()))?;

        swarm.listen_on(listen_addr)
            .map_err(|e| P2PError::Transport(e.to_string()))?;

        // Plaintext `/ws` on purpose: where this is used, TLS is terminated by the proxy in
        // front of us (see `P2PConfig::ws_listen_addr`), and peers dial `/tls/ws` at *its*
        // port 443. Binding this to a public interface without such a proxy would be the
        // caller's mistake, not a default.
        if let Some(ws_addr) = config.ws_listen_addr {
            let ws_listen: Multiaddr = format!("/ip4/{}/tcp/{}/ws", ws_addr.ip(), ws_addr.port())
                .parse()
                .map_err(|e: libp2p::multiaddr::Error| P2PError::Transport(e.to_string()))?;
            swarm.listen_on(ws_listen)
                .map_err(|e| P2PError::Transport(e.to_string()))?;
            info!(ws_listen = %ws_addr, "P2P WebSocket listener started");
        }

        // Kept for the whole run, not just this first pass: these are the only addresses this
        // node knows how to reach on its own, and it has to be able to dial them again after a
        // disconnect (see the redial in the peer-exchange tick below).
        let seed_addrs: Vec<Multiaddr> = config
            .seed_peers
            .iter()
            .filter_map(|peer_addr| peer_addr.parse::<Multiaddr>().ok())
            .collect();

        // Peers remembered from previous runs (`crate::peer_store`). Dialed *in addition to* the
        // seeds, never instead of them: these addresses came from the network, so treating them as
        // a replacement would let a peer that gossiped enough addresses decide who this node talks
        // to. As an addition they can only widen the ways back onto the network.
        let remembered: Vec<Multiaddr> = config
            .peer_store_path
            .as_deref()
            .map(peer_store::load)
            .unwrap_or_default()
            .iter()
            .filter_map(|addr| addr.parse::<Multiaddr>().ok())
            .collect();
        if !remembered.is_empty() {
            info!(
                count = remembered.len(),
                "Dialing peers remembered from a previous run"
            );
        }

        for addr in seed_addrs.iter().chain(remembered.iter()) {
            let _ = swarm.dial(addr.clone());
        }

        info!(listen = %config.listen_addr, peer_id = %local_peer_id, "P2P service started");

        // Misbehavior scoring — disconnects and refuses reconnection for peers
        // that repeatedly send malformed protocol messages.
        let mut reputation = PeerReputation::new();

        // Peer exchange — every address we know how to dial, seeded with our own public
        // address (if configured) and our seed peers. Without this, a node that only ever
        // dials the single configured `seed_peers` address is permanently dependent on that
        // one peer staying up: mDNS never crosses the open internet, and nothing else ever
        // tells this node about any *other* peer to fall back on. See `TOPIC_PEER_EXCHANGE`'s
        // doc comment and `PeerExchangeMsg` below for the full picture.
        let mut known_addrs: HashSet<String> = HashSet::new();
        // Peer versions we've already warned about, so a persistent mismatch on the 30s
        // peer-exchange tick is logged once rather than every tick (#109).
        let mut peer_warnings = PeerWarnings::default();
        // Tip each peer last announced, so the block-sync driver below knows who to ask (#138).
        // Bounded by the connection limit and pruned on disconnect, so it cannot grow unbounded.
        let mut peer_tips: HashMap<PeerId, u64> = HashMap::new();
        // Unreadable peer-exchange messages per peer (backlog #166). Lives beside `peer_tips`
        // because it is the same kind of thing: per-peer state the loop owns and the pure helpers
        // must not.
        let mut unreadable_peer_exchange_counts: HashMap<PeerId, u32> = HashMap::new();
        // The address this node announces as its own. Starts as whatever the operator configured
        // and stays there for a node behind a proxy, whose reachable address it cannot discover.
        // A successful probe replaces it — so it must be a variable, not `config.public_addr`,
        // which is fixed at startup and is also the `self_addr` filter that keeps this node from
        // dialing its own announcement when it comes back around the gossip.
        let mut announced_self: Option<String> = config.public_addr.clone();
        // Peers we have announced as connected, so `PeerConnected`/`PeerDisconnected` reach the
        // node strictly in pairs (backlog #147).
        //
        // libp2p reports connections, not peers, and `max_established_per_peer` is 4 — so a peer
        // both sides dial, or redial, legitimately holds several at once. Announcing every one of
        // them made a *connection* teardown look like the *peer* leaving: `peer_tips` lost its
        // entry, and since that map is the block-sync driver's only notion of who is ahead, the
        // node then never asked anyone for blocks again. That is how a freshly started validator
        // sat on height 1 for 21 hours with the catch-up path fully intact but never triggered.
        //
        // The set also keeps the two events symmetric across the ban path below, which
        // disconnects *without* announcing — an unpaired `PeerDisconnected` would underflow the
        // node's `peer_count` (`AtomicUsize`) to `usize::MAX` and make every quorum-peer check
        // trivially pass.
        let mut connected_peers: HashSet<PeerId> = HashSet::new();
        // Makes a peer that never stays connected visible (backlog #149).
        let mut flaps = FlapTracker::new(std::time::Instant::now());
        // One outstanding request at a time. Without this, every driver tick while a slow batch is
        // in transit would fire another request for the same range — turning our own catch-up into
        // a flood. Cleared on a response and on any failure, so a peer that never answers costs one
        // request and one timeout, not a wedged sync.
        let mut blocksync_in_flight = false;
        // Peers that have *demonstrated* a different history, whatever they advertise. See
        // `P2PCommand::BlocksyncPeerOnAnotherChain`.
        let mut foreign_by_evidence: HashSet<PeerId> = HashSet::new();
        // One outstanding round-sync request at a time, and the peer to ask next (round-robin
        // over whoever is connected).
        let mut roundsync_in_flight = false;
        let mut roundsync_next_peer: usize = 0;
        // Driver ticks left before each peer may be asked for blocks again (backlog #140).
        //
        // `best_blocksync_peer` picks the highest claimed tip, which is deterministic — so a peer
        // that never answers, or serves batches that do not verify, is picked again on every tick
        // forever while a healthy peer one block lower sits untouched. Neither case is worth a ban
        // (the first may be a slow link, the second may be an honest peer that raced our own tip),
        // but both have to stop costing us the catch-up. A cooldown is the smallest thing that
        // turns "always the same peer" into "work through the peers that are ahead of us".
        let mut blocksync_cooldown: HashMap<PeerId, u32> = HashMap::new();
        if let Some(addr) = &config.public_addr {
            known_addrs.insert(addr.clone());
        }
        for peer_addr in &config.seed_peers {
            known_addrs.insert(peer_addr.clone());
        }
        for addr in &remembered {
            known_addrs.insert(addr.to_string());
        }
        // Written whenever the set differs from what is on disk. `known_addrs` never shrinks
        // (nothing removes from it — the cap in `select_new_addrs` stops it filling instead), so
        // the length is a sufficient change marker.
        //
        // Starts at 0, *not* at the current length, so the first tick always writes even for a
        // node whose only address is its configured seed. That node has nothing new to learn, but
        // it does have something to lose: if its configuration is replaced or misplaced, the file
        // is then the only remaining record of how to reach the network. It also means the file
        // always exists, so "who does my node know?" has an answer on disk rather than only in a
        // running process — which is the state this whole mechanism was missing.
        let mut saved_addr_count = 0;

        // Re-announce periodically, not just on connect — a message published right as a
        // connection is established can be lost before gossipsub's mesh for the topic has
        // even formed with that peer (same race as the ML-KEM Hello below), and this is also
        // how newly learned addresses (from a peer exchange we received) eventually reach
        // peers we were already connected to before we learned them.
        let mut peer_exchange_interval = tokio::time::interval(Duration::from_secs(30));

        // Block-sync driver (#138). Far more often than the 30-second announcement tick, because a
        // node that is genuinely behind should not wait half a minute between batches: one batch is
        // capped at an epoch, so a long catch-up is many requests and the interval is the floor on
        // how fast it can proceed. Cheap when idle — with nobody ahead of us it is one map scan.
        let mut blocksync_interval = tokio::time::interval(Duration::from_secs(2));

        loop {
            tokio::select! {
                event = swarm.next() => {
                    let Some(event) = event else { break };
                    match event {
                        SwarmEvent::Behaviour(HelixBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { propagation_source, message, .. }
                        )) => {
                            let peer_str = propagation_source.to_string();
                            if reputation.is_banned(&peer_str) {
                                continue;
                            }

                            let topic = message.topic.as_str();

                            let malformed = if topic == TOPIC_PEER_EXCHANGE {
                                let outcome = handle_peer_exchange_message(
                                    &message.data,
                                    &mut known_addrs,
                                    announced_self.as_deref(),
                                    &mut swarm,
                                    &mut peer_warnings,
                                    tip_height.load(Ordering::Relaxed),
                                    &our_genesis,
                                );
                                if let Some(tip) = outcome.announced_tip {
                                    // Credit the tip to whoever *wrote* the announcement, not to
                                    // whoever handed it to us. gossipsub floods, so
                                    // `propagation_source` is merely the last hop, and
                                    // `PeerExchangeMsg` carries no sender field of its own — so
                                    // this used to file every relayed announcement under the
                                    // relaying peer. For a node with a single connection (a fresh
                                    // one behind the tunnel, which is exactly the node that needs
                                    // catch-up) *every* announcement arrives that way, so its seed
                                    // inherited the highest tip anyone in the network claimed.
                                    // `best_blocksync_peer` picks by highest claim, so catch-up
                                    // then asked that one peer for blocks it does not have, got a
                                    // short or empty answer, and put its only usable peer on a 10s
                                    // cooldown — on repeat.
                                    //
                                    // The set runs gossipsub with `MessageAuthenticity::Signed`
                                    // and `ValidationMode::Strict`, so `message.source` is a
                                    // signature-checked origin, not a self-declared one. Falling
                                    // back to the relay keeps the old behaviour for the case the
                                    // types allow but Strict rejects before it reaches us.
                                    let origin = message.source.unwrap_or(propagation_source);
                                    if record_peer_tip(
                                        &mut peer_tips,
                                        &foreign_by_evidence,
                                        origin,
                                        tip,
                                        TipSource::PeerExchange,
                                    ) {
                                        publish_highest_peer_tip(&highest_peer_tip, &peer_tips);
                                    }
                                }
                                if let Some(peer_tip) = outcome.serve_from_tip {
                                    let _ = event_tx
                                        .send(P2PEvent::PeerBehind { peer_tip })
                                        .await;
                                }
                                // An unreadable peer-exchange message is an old build far more often
                                // than it is an attack (#166), so it is counted per peer rather
                                // than charged on sight — see `unreadable_peer_exchange`.
                                if outcome.malformed {
                                    let seen = unreadable_peer_exchange_counts
                                        .entry(propagation_source)
                                        .and_modify(|n| *n += 1)
                                        .or_insert(1);
                                    let (message, strike) =
                                        unreadable_peer_exchange(&peer_str, *seen);
                                    if let Some(message) = message {
                                        warn!("{message}");
                                    }
                                    strike
                                } else {
                                    false
                                }
                            } else {
                                let outcome =
                                    handle_app_message(topic, &message.data, &event_tx).await;
                                // A gossiped block is a live statement about its sender's height,
                                // and it arrives with every block rather than once per
                                // `peer_exchange_interval`. Without it `peer_tips` has exactly one
                                // source, 30s apart, so a node that just started knows no tip at
                                // all for up to half a minute and does not sync while it waits —
                                // connected, behind, and idle.
                                //
                                // Raise-only, deliberately. Peer exchange is the authority on what
                                // a peer holds and must stay able to *lower* a tip (a peer that
                                // reset now claims less, #175); an old block replayed through the
                                // mesh must never push a tip back up.
                                if let Some(height) = outcome.observed_height {
                                    let origin = message.source.unwrap_or(propagation_source);
                                    if record_peer_tip(
                                        &mut peer_tips,
                                        &foreign_by_evidence,
                                        origin,
                                        height,
                                        TipSource::GossipedBlock,
                                    ) {
                                        publish_highest_peer_tip(&highest_peer_tip, &peer_tips);
                                    }
                                    // Learning the tip is the fix; requesting against it here is
                                    // deliberately left to `blocksync_interval`. `tip_height` is a
                                    // 5-second sample of our own store, so during ordinary
                                    // operation — where blocks arrive by consensus, not by sync —
                                    // our sampled tip trails the block we just committed, and
                                    // firing a request per gossiped block would ask peers for
                                    // blocks we already hold, on every block. The interval picks
                                    // the tip up within 2s, which is the entire latency saved.
                                }
                                outcome.malformed
                            };

                            if malformed && reputation.record_infraction(&peer_str) {
                                warn!(peer = %peer_str, "peer exceeded misbehavior threshold — disconnecting");
                                let _ = swarm.disconnect_peer_id(propagation_source);
                            }
                        }

                        SwarmEvent::Behaviour(HelixBehaviourEvent::GenesisSync(
                            request_response::Event::Message { peer, message, .. }
                        )) => {
                            match message {
                                request_response::Message::Request { channel, .. } => {
                                    // Answered inside the swarm loop like a block-sync request, and
                                    // read-only in the same way: the requester supplies nothing at
                                    // all, so there is no input here to get wrong.
                                    let response = match &genesis_provider {
                                        Some(provider) => provider.genesis().await,
                                        // Honest "nothing to give" rather than silence. A node that
                                        // is itself still bootstrapping speaks the protocol but has
                                        // no genesis, and letting the request time out instead would
                                        // be indistinguishable from an unreachable peer.
                                        None => GenesisResponse::empty(),
                                    };
                                    debug!(
                                        peer = %peer,
                                        served = response.genesis.is_some(),
                                        "Answering a genesis request"
                                    );
                                    let _ = swarm
                                        .behaviour_mut()
                                        .genesis_sync
                                        .send_response(channel, response);
                                }
                                // Outbound genesis requests are made by the one-shot bootstrap in
                                // `genesis_bootstrap`, which owns its own swarm and never reaches
                                // this loop — a running node already has a genesis and never asks.
                                request_response::Message::Response { .. } => {}
                            }
                        }
                        SwarmEvent::Behaviour(HelixBehaviourEvent::Blocksync(
                            request_response::Event::Message { peer, message, .. }
                        )) => {
                            match message {
                                request_response::Message::Request { request, channel, .. } => {
                                    // Answered right here, inside the swarm loop, via the injected
                                    // provider — no request-id bookkeeping and no round trip out to
                                    // the node and back to the correct response slot. Serving is
                                    // read-only and cannot be turned into anything else: the
                                    // requester picks a height range, nothing more.
                                    let count = clamp_batch(request.count);
                                    let response = block_provider
                                        .blocks(request.from_height, count)
                                        .await;
                                    debug!(
                                        peer = %peer,
                                        from = request.from_height,
                                        asked = request.count,
                                        served = response.blocks.len(),
                                        "Answering a block-sync request"
                                    );
                                    let _ = swarm
                                        .behaviour_mut()
                                        .blocksync
                                        .send_response(channel, response);
                                }
                                request_response::Message::Response { response, .. } => {
                                    blocksync_in_flight = false;
                                    if response.blocks.is_empty() {
                                        // We only ask peers that claim a tip above ours, so an
                                        // empty answer contradicts what this peer announced. It
                                        // costs the peer nothing to keep claiming a high tip and
                                        // serving nothing, and selection is by highest claim — so
                                        // without a cooldown here that is a free way to occupy our
                                        // one in-flight request forever (backlog #140). The
                                        // charitable readings — pruned history, a tip announced a
                                        // moment before a restart — are equally well served by
                                        // asking someone else for the next ten seconds.
                                        blocksync_cooldown
                                            .insert(peer, BLOCKSYNC_PEER_COOLDOWN_TICKS);
                                        debug!(peer = %peer, "Block-sync peer claimed to be ahead but served nothing — trying another peer");
                                    } else {
                                        info!(
                                            peer = %peer,
                                            blocks = response.blocks.len(),
                                            "Received a block-sync batch"
                                        );
                                        let _ = event_tx
                                            .send(P2PEvent::BlocksSynced(response, peer.to_string()))
                                            .await;
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(HelixBehaviourEvent::Blocksync(
                            request_response::Event::OutboundFailure { peer, error, .. }
                        )) => {
                            // Clearing the in-flight flag alone is not enough: `best_blocksync_peer`
                            // is deterministic, so the next tick would pick this same unresponsive
                            // peer again, and the one after that, forever — this comment used to
                            // claim "possibly against a different peer", which was never true
                            // (backlog #140). The cooldown is what actually moves us to someone else.
                            blocksync_in_flight = false;
                            blocksync_cooldown.insert(peer, BLOCKSYNC_PEER_COOLDOWN_TICKS);
                            debug!(peer = %peer, err = %error, "Block-sync request failed — trying another peer");
                        }
                        SwarmEvent::Behaviour(HelixBehaviourEvent::Blocksync(
                            request_response::Event::InboundFailure { peer, error, .. }
                        )) => {
                            debug!(peer = %peer, err = %error, "Failed to answer a block-sync request");
                        }

                        SwarmEvent::Behaviour(HelixBehaviourEvent::Roundsync(
                            request_response::Event::Message { peer, message, .. }
                        )) => {
                            match message {
                                request_response::Message::Request { request, channel, .. } => {
                                    // Answered inside the swarm loop like the other two, and
                                    // read-only in the same way: the requester names a height and
                                    // a round and gets what this node already holds for it.
                                    let response = match &round_provider {
                                        Some(provider) => provider
                                            .round_state(request.height, request.round)
                                            .await
                                            .clamped(),
                                        // A service with no engine behind it says so honestly
                                        // rather than letting the request time out, which is
                                        // indistinguishable from an unreachable peer.
                                        None => RoundSyncResponse::empty(),
                                    };
                                    debug!(
                                        peer = %peer,
                                        height = request.height,
                                        round = request.round,
                                        proposal = response.proposal.is_some(),
                                        votes = response.votes.len(),
                                        "Answering a round-sync request"
                                    );
                                    let _ = swarm
                                        .behaviour_mut()
                                        .roundsync
                                        .send_response(channel, response);
                                }
                                request_response::Message::Response { response, .. } => {
                                    roundsync_in_flight = false;
                                    if response.is_empty() {
                                        // Not a fault: a peer that is behind us, or one that has
                                        // already committed the height, genuinely holds nothing.
                                        // No cooldown either — unlike block sync, we did not pick
                                        // this peer because it claimed to have something.
                                        debug!(peer = %peer, "Round-sync peer holds nothing for this height");
                                    } else {
                                        debug!(
                                            peer = %peer,
                                            proposal = response.proposal.is_some(),
                                            votes = response.votes.len(),
                                            "Received round-sync state"
                                        );
                                        let _ = event_tx
                                            .send(P2PEvent::RoundSynced(response, peer.to_string()))
                                            .await;
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(HelixBehaviourEvent::Roundsync(
                            request_response::Event::OutboundFailure { peer, error, .. }
                        )) => {
                            // Only the in-flight slot is freed. There is deliberately no cooldown
                            // and no strike: the next request goes to the next peer in rotation
                            // anyway, and a round-sync request is asked at most once per round —
                            // far too little traffic for a peer's failure to be worth remembering.
                            roundsync_in_flight = false;
                            debug!(peer = %peer, err = %error, "Round-sync request failed");
                        }
                        SwarmEvent::Behaviour(HelixBehaviourEvent::Roundsync(
                            request_response::Event::InboundFailure { peer, error, .. }
                        )) => {
                            debug!(peer = %peer, err = %error, "Failed to answer a round-sync request");
                        }

                        SwarmEvent::Behaviour(HelixBehaviourEvent::Mdns(
                            mdns::Event::Discovered(peers)
                        )) => {
                            for (peer_id, addr) in peers {
                                info!(peer = %peer_id, "mDNS peer discovered");
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                let _ = swarm.dial(addr);
                            }
                        }
                        SwarmEvent::Behaviour(HelixBehaviourEvent::Mdns(
                            mdns::Event::Expired(peers)
                        )) => {
                            for (peer_id, _) in peers {
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            }
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!(addr = %address, "P2P listening");
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            let peer_str = peer_id.to_string();
                            let banned = match multiaddr_ip(endpoint.get_remote_address()) {
                                Some(ip) => reputation.note_connection(&peer_str, &ip),
                                None => reputation.is_banned(&peer_str),
                            };
                            if banned {
                                warn!(peer = %peer_str, "rejecting connection from banned peer/IP");
                                let _ = swarm.disconnect_peer_id(peer_id);
                                continue;
                            }

                            // Only the first connection to a peer makes it a *new* peer. Further
                            // ones are routine (both sides dialing, a redial racing the existing
                            // link) and must not be announced again — see `connected_peers`.
                            if !connected_peers.insert(peer_id) {
                                debug!(
                                    peer = %peer_id,
                                    "Additional connection to an already-connected peer"
                                );
                                continue;
                            }

                            info!(peer = %peer_id, "Peer connected");

                            // Counted here, in the branch that treats this as a *new* peer, so
                            // the extra connections of one healthy peer are not mistaken for
                            // churn — that distinction only exists since #147.
                            if flaps.note_reconnect(peer_id, std::time::Instant::now()) {
                                warn!(
                                    peer = %peer_id,
                                    reconnects = FLAP_THRESHOLD,
                                    "Peer keeps reconnecting — it is not staying connected long \
                                     enough to be useful (no stable gossip mesh, no block sync). \
                                     Usually a bad link or a proxy timing the connection out on \
                                     their side, not misbehaviour."
                                );
                            }

                            // Add every accepted peer to gossipsub's explicit-peer set so it
                            // always forwards messages to them, not just to whatever subset its
                            // heartbeat-driven mesh happens to graft. Previously this was done
                            // ONLY for mDNS-discovered peers (see the Mdns::Discovered arm) —
                            // so a peer reached via seed-peer dial or peer exchange (the only
                            // paths that work across a real network or with mDNS disabled) got
                            // a weak, slow-forming mesh. In a small validator set relaying
                            // consensus votes/proposals through a hub node (B↔C only via A),
                            // that left cross-validator votes undelivered and rounds drifting
                            // without ever finalizing. A single production validator never
                            // exercised this; three did.
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);

                            // Announce what we know right away too — don't make a freshly
                            // connected peer wait up to 30s for the periodic tick just to
                            // learn about other peers it could dial.
                            broadcast_known_addrs(
                                &mut swarm,
                                &peer_exchange_topic,
                                &known_addrs,
                                tip_height.load(Ordering::Relaxed),
                                &our_genesis,
                            );

                            let _ = event_tx.send(P2PEvent::PeerConnected(peer_str)).await;
                        }
                        SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                            // `num_established` is what is *left* to this peer. Dropping it (the
                            // `..` this replaces) treated one closing connection as the whole peer
                            // going away, tearing down state that several still-live connections
                            // depended on — see `connected_peers` for the outage that caused.
                            // `contains`, not `remove`: while other connections remain the peer must
                            // stay in the set, or the next one would be announced as a new peer.
                            if !peer_departed(num_established, connected_peers.contains(&peer_id)) {
                                debug!(
                                    peer = %peer_id,
                                    remaining = num_established,
                                    "Connection closed, peer itself has not left"
                                );
                                continue;
                            }
                            connected_peers.remove(&peer_id);
                            // `info!`, matching "Peer connected" above — the asymmetry this
                            // replaces (connect at `info!`, disconnect at `debug!`) is not
                            // cosmetic. On 2026-07-29 a dropped link to one validator cost 14.5
                            // hours of production downtime, and the disconnect that started it was
                            // invisible: the outage had to be reconstructed backwards from the
                            // *reconnect* lines, which were the only trace at the default log
                            // level. A lost peer is exactly as newsworthy as a gained one.
                            info!(peer = %peer_id, "Peer disconnected");
                            peer_tips.remove(&peer_id);
                            publish_highest_peer_tip(&highest_peer_tip, &peer_tips);
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            reputation.on_disconnect(&peer_id.to_string());
                            let _ = event_tx
                                .send(P2PEvent::PeerDisconnected(peer_id.to_string()))
                                .await;
                        }
                        _ => {}
                    }
                }

                _ = blocksync_interval.tick() => {
                    // Age the cooldowns first, so a peer sat out its penalty by the time this tick
                    // chooses. Entries are removed at zero rather than kept at zero, which is what
                    // keeps this map bounded by the peers we actually failed against.
                    blocksync_cooldown.retain(|_, ticks| {
                        *ticks -= 1;
                        *ticks > 0
                    });
                    request_blocks_if_behind(
                        &mut swarm,
                        &peer_tips,
                        &blocksync_cooldown,
                        tip_height.load(Ordering::Relaxed),
                        &mut blocksync_in_flight,
                    );
                }

                _ = peer_exchange_interval.tick() => {
                    broadcast_known_addrs(
                        &mut swarm,
                        &peer_exchange_topic,
                        &known_addrs,
                        tip_height.load(Ordering::Relaxed),
                        &our_genesis,
                    );

                    // Redial the seeds while this node has no connection at all.
                    //
                    // Every other way back into the network needs a connection this node no
                    // longer has: peer exchange is gossip (nobody is listening), and mDNS only
                    // reaches the local segment. The initial dial above happens exactly once, at
                    // startup, and `ConnectionClosed` only cleans up — so before this, a single
                    // disconnect was permanent. Restarting the seed node dropped every validator
                    // off the network until each operator manually restarted their own node.
                    // Seen live on 2026-07-22: a routine `pm2 restart` of the production node
                    // left the second validator disconnected indefinitely, `peer_count: 0`, while
                    // its node reported itself healthy.
                    //
                    // Only while fully disconnected, so a node with a working mesh never dials on
                    // a timer; one attempt per seed per interval, so a seed that stays down costs
                    // one connection attempt every 30s and nothing else.
                    // `info!`, not `debug!`: an operator staring at `peer_count: 0` needs to see
                    // that the node is trying, and how often — the silent-wait failure mode from
                    // the peer/liveness windows is exactly what made this class of problem so
                    // hard to tell apart from a hung node.
                    // Save on this tick rather than at shutdown: a node is far more often killed
                    // than asked to stop (`pm2 restart`, OOM, power), and a file only written on a
                    // clean exit is one that is missing exactly when the restart was unplanned.
                    if let Some(path) = config.peer_store_path.as_deref() {
                        if known_addrs.len() != saved_addr_count {
                            peer_store::save(path, &known_addrs);
                            saved_addr_count = known_addrs.len();
                        }
                    }

                    if swarm.connected_peers().next().is_none() && !seed_addrs.is_empty() {
                        info!(seeds = seed_addrs.len(), "No peers connected — redialing seed peers");
                        for addr in &seed_addrs {
                            let _ = swarm.dial(addr.clone());
                        }
                    }
                }

                Some(cmd) = command_rx.recv() => {
                    match cmd {
                        P2PCommand::BroadcastProposal(proposal) => {
                            if let Ok(data) = bincode::serialize(&proposal) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub
                                    .publish(block_topic.clone(), data)
                                {
                                    // Was `debug!`, i.e. invisible by default. A proposal that does
                                    // not go out produces a round that cannot finish, and the only
                                    // other symptom is a climbing round number — the single most
                                    // expensive thing to diagnose in this codebase's history.
                                    //
                                    // `Duplicate` is not that. The node re-offers its pending
                                    // proposal every tick so a validator that connects late still
                                    // sees it, and gossipsub rejecting the repeat is that mechanism
                                    // working: the message went out the first time. Warning about it
                                    // fires every two seconds on a perfectly healthy chain, and a
                                    // line that cries wolf that often is worse than no line at all —
                                    // it teaches an operator to skip exactly the warning that
                                    // matters. Measured live on 2026-08-05: 92 of these in 300 log
                                    // lines while the chain was finalizing blocks normally.
                                    if matches!(e, gossipsub::PublishError::Duplicate) {
                                        debug!("Proposal re-offer deduplicated — already published");
                                    } else {
                                        warn!(error = %e, "Proposal broadcast failed — this round cannot reach a quorum");
                                    }
                                }
                            }
                        }
                        P2PCommand::RequestRoundSync { height, round } => {
                            if roundsync_in_flight {
                                // One at a time. The answer is only useful inside the round that
                                // asked for it, so queueing more would just deliver stale rounds.
                                debug!(height, round, "Round-sync request already in flight");
                            } else {
                                let peers: Vec<PeerId> = swarm.connected_peers().copied().collect();
                                if peers.is_empty() {
                                    debug!(height, round, "No peer to ask for the round");
                                } else {
                                    // Rotate rather than always asking the same peer: the one that
                                    // cannot answer is often exactly the one whose silence put us
                                    // here, and a deterministic pick would ask it forever (the
                                    // mistake #140 fixed for block sync).
                                    let peer = peers[roundsync_next_peer % peers.len()];
                                    roundsync_next_peer = roundsync_next_peer.wrapping_add(1);
                                    debug!(peer = %peer, height, round, "Asking a peer for the round we are missing");
                                    swarm.behaviour_mut().roundsync.send_request(
                                        &peer,
                                        RoundSyncRequest { height, round },
                                    );
                                    roundsync_in_flight = true;
                                }
                            }
                        }
                        P2PCommand::BroadcastTransaction(tx) => {
                            if let Ok(data) = bincode::serialize(&tx) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub
                                    .publish(tx_topic.clone(), data)
                                {
                                    debug!("Tx broadcast: {}", e);
                                }
                            }
                        }
                        P2PCommand::BroadcastVote(vote) => {
                            if let Ok(data) = bincode::serialize(&vote) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub
                                    .publish(vote_topic.clone(), data)
                                {
                                    debug!("Vote broadcast: {}", e);
                                }
                            }
                        }
                        P2PCommand::BroadcastBlock(block, commit) => {
                            // The certificate travels as the second element of a (block, commit)
                            // tuple on the committed-blocks topic — a wire-format change from the
                            // bare `Block` this used to carry, so it needs a coordinated upgrade
                            // (#114/#109); the receive side below parses the same shape.
                            if let Ok(data) = bincode::serialize(&(&block, &commit)) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub
                                    .publish(committed_topic.clone(), data)
                                {
                                    if matches!(e, gossipsub::PublishError::Duplicate) {
                                        debug!("Committed-block re-offer deduplicated — already published");
                                    } else {
                                        warn!(error = %e, "Committed block broadcast failed — peers will have to fetch this block instead");
                                    }
                                }
                            }
                        }
                        P2PCommand::ConnectPeer(addr) => {
                            let _ = swarm.dial(addr);
                        }
                        P2PCommand::AnnounceSelfAddress(addr) => {
                            // Dropping the address this replaces is the one place anything is ever
                            // removed from `known_addrs`, and it is deliberate: on a connection
                            // whose address changes, keeping the old one would have this node
                            // broadcasting a growing list of addresses that no longer reach it,
                            // and every peer that learned one would keep dialing into nothing.
                            // Only *this node's own* previous address is dropped — never one
                            // learned from a peer, which this node has no standing to call dead.
                            if announced_self.as_deref() == Some(addr.as_str()) {
                                continue; // already announcing it; nothing to say
                            }
                            if let Some(previous) = announced_self.replace(addr.clone()) {
                                known_addrs.remove(&previous);
                                info!(
                                    old = %previous,
                                    new = %addr,
                                    "This node's reachable address changed — announcing the new \
                                     one and dropping the old"
                                );
                            }
                            known_addrs.insert(addr.clone());
                            let _ = event_tx.send(P2PEvent::SelfAddressAnnounced(addr)).await;
                        }
                        P2PCommand::BlocksyncPeerOnAnotherChain(peer) => {
                            match peer.parse::<PeerId>() {
                                Ok(peer_id) => {
                                    // Forget its tip and stop believing any it sends later. Not a
                                    // ban and not a disconnect: it is a peer we simply have nothing
                                    // to learn blocks from. It stays connected, its gossip is still
                                    // validated on its merits, and if it ever resyncs onto this
                                    // chain a restart of either side clears this.
                                    if foreign_by_evidence.insert(peer_id) {
                                        warn!(
                                            peer = %peer,
                                            "This peer serves blocks that do not chain from our tip \
                                             — it is on a different history. No longer asking it for \
                                             blocks or believing the tip it claims."
                                        );
                                    }
                                    peer_tips.remove(&peer_id);
                                    publish_highest_peer_tip(&highest_peer_tip, &peer_tips);
                                }
                                Err(_) => warn!(peer = %peer, "Unparseable peer id in block-sync report"),
                            }
                        }
                        P2PCommand::BlocksyncBatchRejected(peer) => {
                            // The node verified the batch and threw it away. From the service's own
                            // view that is indistinguishable from success — it only ever sees a
                            // non-empty response — so without this report the same peer is asked
                            // again every tick, being the one claiming the highest tip (#140).
                            //
                            // A cooldown, not a ban: an honest peer can serve a batch we reject
                            // because our own tip moved underneath it. Repeat offenders simply keep
                            // earning cooldowns, and never get to hold up catch-up in between.
                            match peer.parse::<PeerId>() {
                                Ok(peer_id) => {
                                    blocksync_cooldown.insert(peer_id, BLOCKSYNC_PEER_COOLDOWN_TICKS);
                                    warn!(peer = %peer, "Block-sync batch failed verification — asking a different peer");
                                }
                                Err(e) => debug!(peer = %peer, err = %e, "Unparseable peer id in block-sync rejection"),
                            }
                        }
                        P2PCommand::BlocksyncAdvance(new_tip) => {
                            // Pull the sampled tip forward to what the node actually holds. Raise
                            // only: this races the 5s announce loop, and a command that waited in
                            // the queue must never walk the tip backwards.
                            let our_tip = tip_height.fetch_max(new_tip, Ordering::Relaxed).max(new_tip);
                            request_blocks_if_behind(
                                &mut swarm,
                                &peer_tips,
                                &blocksync_cooldown,
                                our_tip,
                                &mut blocksync_in_flight,
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Extracts the bare IP address (if any) from a `Multiaddr`, ignoring the
/// port/transport suffix, so the same address at different ports still maps
/// to the same reputation entry.
pub(crate) fn multiaddr_ip(addr: &Multiaddr) -> Option<String> {
    addr.iter().find_map(|proto| match proto {
        libp2p::multiaddr::Protocol::Ip4(ip) => Some(ip.to_string()),
        libp2p::multiaddr::Protocol::Ip6(ip) => Some(ip.to_string()),
        _ => None,
    })
}

// ─── Peer exchange ────────────────────────────────────────────────────────────

/// Cap on both how many addresses we remember (`known_addrs`) and — since the merge loop in
/// `select_new_addrs` bails out as soon as the cap is hit — implicitly on how many addresses
/// a single hostile peer's oversized announcement can ever cause us to dial. One cap serves
/// both purposes; a separate per-message limit would add complexity without closing a gap
/// this one doesn't already close.
const MAX_KNOWN_PEER_ADDRS: usize = 200;

/// This node's software version, stamped into every peer-exchange broadcast (#109). The
/// workspace shares one version, so this crate's `CARGO_PKG_VERSION` is the running node's
/// version — the same reasoning the signed `node_version` block header relies on (#128).
const OUR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How far behind a peer may be and still be served its missing blocks over gossip (#137).
///
/// Two jobs in one bound. It keeps the mechanism aimed at what it is for — healing the *small*,
/// self-inflicted lag of a node that missed a one-shot commit broadcast, which is a handful of
/// blocks at most — while a genuinely far-behind node (a fresh join, a long outage) still belongs
/// on the bulk RPC sync path, where blocks are fetched in batches instead of splattered across a
/// broadcast topic.
///
/// It is also the anti-amplification cap. The announced height is an unauthenticated number from
/// the network: without a bound, one peer claiming `tip_height: 0` on a 26 000-block chain would
/// have us republish the entire chain, every 30 seconds, to *every* peer. With it, the worst a
/// lying announcement can extract is this many blocks per announcement — and claiming to be
/// hopelessly behind (the cheap lie) buys nothing at all, because it fails the bound.
/// Public so the node layer bounds its own serve loop against the *same* number rather than a
/// second copy of it: the height in a [`P2PEvent::PeerBehind`] is peer-supplied, and re-checking it
/// at the point where blocks are actually read and broadcast is what makes that loop safe on its
/// own terms. One constant, two enforcement points — not two constants.
pub const MAX_CATCHUP_SERVE_BLOCKS: u64 = 20;

#[derive(Debug, Serialize, Deserialize)]
struct PeerExchangeMsg {
    peers: Vec<String>,
    /// The sender's software version. `peer_version_warning` in the node layer only catches a
    /// mismatch at *join* time; this rides the periodic peer-exchange gossip so a peer that
    /// upgrades (or downgrades) while we keep running is noticed too (#109). Adding this field
    /// changes the topic's bincode payload — a coordinated upgrade, bundled with the release that
    /// already resets the chain.
    version: String,
    /// The sender's committed tip height (#137). Purely informational — it can only ever make us
    /// send blocks we have already committed, never influence what we accept: every block the
    /// receiver takes back in is re-verified from scratch (proposer signature, known validator,
    /// `prev_hash` chain, and the commit certificate's quorum). So a peer lying about its height
    /// gains nothing but a bounded amount of our upload.
    tip_height: u64,
    /// The sender's genesis hash — which chain it is actually on.
    ///
    /// Nothing carried this before, and two nodes on different chains connected perfectly happily:
    /// they gossiped at each other and every single message was rejected on its own merits, one at
    /// a time, with nobody ever saying why. An operator whose chain data predates a reset sees only
    /// that their chain stopped moving — the same symptom as every other stall, and the one that
    /// has cost this project days of diagnosis more than once.
    ///
    /// Bitcoin solves this a layer lower, with per-network magic bytes that stop a wrong-network
    /// peer completing the handshake at all. This is the diagnostic half of the same idea: it does
    /// not prevent the connection, it explains it.
    ///
    /// Empty from a node that has no genesis yet, which is not a lie worth acting on.
    #[serde(default)]
    genesis_hash: String,
}

/// Whether a peer announcing `peer_tip` should be served the blocks it is missing, given our own
/// committed tip. Behind us, and by no more than [`MAX_CATCHUP_SERVE_BLOCKS`].
///
/// Split out as a pure function so the bound is testable without a `Swarm` — including the two
/// cases that matter and are easy to get backwards: a peer *ahead* of us must never trigger a
/// serve (we are the ones behind then, and we have nothing it needs), and a peer claiming an
/// absurdly low height must be refused rather than served the whole chain.
fn should_serve_catchup(peer_tip: u64, our_tip: u64) -> bool {
    peer_tip < our_tip && our_tip - peer_tip <= MAX_CATCHUP_SERVE_BLOCKS
}

/// Merges `incoming` into `known`, skipping our own address and anything already known, and
/// stopping as soon as `known` reaches `MAX_KNOWN_PEER_ADDRS`. Returns only the addresses that
/// were actually new, for the caller to dial. Pure and side-effect-free apart from mutating
/// `known` — kept separate from the actual dialing so it's testable without a real `Swarm`.
fn select_new_addrs(
    known: &mut HashSet<String>,
    incoming: &[String],
    self_addr: Option<&str>,
) -> Vec<String> {
    let mut new_addrs = Vec::new();
    for addr in incoming {
        if known.len() >= MAX_KNOWN_PEER_ADDRS {
            break;
        }
        if Some(addr.as_str()) == self_addr {
            continue;
        }
        if known.insert(addr.clone()) {
            new_addrs.push(addr.clone());
        }
    }
    new_addrs
}

/// The warning text for a peer running a different version than ours, or `None` when it matches
/// or we have already warned about this exact version. The `warned` set dedups so a mismatch that
/// keeps arriving on the 30-second peer-exchange tick is logged once, not forever. Pure, so the
/// dedup and same-version cases are testable without a `Swarm`.
///
/// It cannot say *which* peer — the gossiped message carries no sender identity — only that
/// *some* peer on the network runs a different build, which is the fact an operator needs.
fn foreign_version_warning(their: &str, ours: &str, warned: &mut HashSet<String>) -> Option<String> {
    if their == ours || !warned.insert(their.to_string()) {
        return None;
    }
    Some(format!(
        "A peer on the network runs Helix {their}, this node runs {ours}. Peers aren't required to \
         match, but a consensus-rule difference between builds shows up as silent disagreement — \
         mismatched jailing, votes that never count, a chain that stalls without an error. Make \
         sure every validator runs the same version."
    ))
}

/// The warning text for a peer on a different chain, or `None` when it matches, when either side
/// has no genesis to compare, or when we have already warned about this exact hash.
///
/// Deduped like [`foreign_version_warning`] so a peer that keeps announcing on the 30-second tick
/// is logged once rather than forever. Pure, so every branch is testable without a `Swarm`.
///
/// Warns and does not disconnect, deliberately and consistently with how this codebase treats every
/// other peer-level disagreement (version mismatch, flapping): the value here is the sentence, not
/// the enforcement. A comparison bug that disconnected instead would partition the network, and a
/// foreign-chain peer already costs nothing — every message it sends is rejected on its own merits,
/// and the block-sync cooldown (#140) stops us asking it twice.
/// Which chain a peer says it is on, from its announced genesis hash.
///
/// The three-way answer is the whole point (backlog #175). Collapsing `Unknown` into `Foreign`
/// would be the tempting simplification and it is wrong in the most common case there is: the very
/// first message from a peer running a build older than 0.10.1 carries no hash, and a node that
/// refuses to learn tips from anyone who has not identified their chain stops asking anybody
/// anything. Collapsing it into `Same` is the bug this exists to fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerChain {
    /// Same genesis as ours — trust its tip as far as any unauthenticated claim can be trusted.
    Same,
    /// A different genesis. Its blocks can never apply here and its tip means nothing to us.
    Foreign,
    /// It did not say (older build, or no genesis of its own yet). Treated as `Same` would be,
    /// because refusing the unknown costs more than it saves.
    Unknown,
}

fn peer_chain(theirs: &str, ours: &str) -> PeerChain {
    if theirs.is_empty() || ours.is_empty() {
        PeerChain::Unknown
    } else if theirs == ours {
        PeerChain::Same
    } else {
        PeerChain::Foreign
    }
}

fn foreign_chain_warning(theirs: &str, ours: &str, warned: &mut HashSet<String>) -> Option<String> {
    // An empty hash is a node that has no genesis yet, not a node on another chain.
    if peer_chain(theirs, ours) != PeerChain::Foreign {
        return None;
    }
    if !warned.insert(theirs.to_string()) {
        return None;
    }
    Some(format!(
        "A peer on the network is on a DIFFERENT CHAIN: its genesis is {theirs}, ours is {ours}. \
         Nothing it sends can be accepted and nothing we send can be accepted by it. The usual \
         cause is chain data left over from before a reset — clear the data directory and let the \
         node re-join, or point it at the right network. Until then that peer's chain is stopped \
         and this one cannot help it."
    ))
}

/// What the caller has to act on after a peer-exchange message.
#[derive(Debug, Default, PartialEq, Eq)]
struct PeerExchangeOutcome {
    /// The message was malformed — the sender should be charged a misbehavior strike.
    malformed: bool,
    /// The tip the sender claims, whenever the message parsed at all. Recorded per peer so the
    /// block-sync driver knows who is worth asking for blocks (#138).
    announced_tip: Option<u64>,
    /// The sender's announced tip, when it is behind us by a servable margin (#137). The caller
    /// turns this into a [`P2PEvent::PeerBehind`]; `None` means nothing to serve.
    serve_from_tip: Option<u64>,
}

/// What has already been reported about peers, so a disagreement that arrives on every
/// 30-second peer-exchange tick is logged once instead of forever.
///
/// The two sets are grouped rather than passed separately because they are the same kind of thing —
/// a fact about a peer that is worth saying exactly once — and they are always needed together.
#[derive(Default)]
struct PeerWarnings {
    /// Software versions already reported (#109).
    versions: HashSet<String>,
    /// Genesis hashes already reported as foreign (#164).
    chains: HashSet<String>,
}

/// The peer-exchange payload as it was before `genesis_hash` existed.
///
/// Kept so a peer running the previous release stays readable. bincode is not self-describing, so
/// `#[serde(default)]` on the new field cannot rescue a shorter payload — measured, the older
/// message fails to decode as the newer struct with "unexpected end of file", while the newer
/// message decodes fine as the older struct (trailing bytes are ignored). The break is one-way,
/// and this is the side that has to absorb it.
#[derive(Debug, Serialize, Deserialize)]
struct PeerExchangeMsgV1 {
    peers: Vec<String>,
    version: String,
    tip_height: u64,
}

/// Decode a peer-exchange message, accepting the previous release's shape as well.
///
/// The fallback is not leniency about malformed input — it is the difference between "older build"
/// and "misbehaving", and getting that wrong here is expensive: an unparseable peer-exchange message
/// charges a misbehavior strike, the message arrives every 30 seconds, and five strikes ban the
/// peer. Without this, adding one field would have banned a healthy co-signing validator inside
/// three minutes and stalled a two-validator chain — while every test passed, because no test runs
/// two different builds against each other.
fn decode_peer_exchange(data: &[u8]) -> Option<PeerExchangeMsg> {
    if let Ok(msg) = bincode::deserialize::<PeerExchangeMsg>(data) {
        return Some(msg);
    }
    match bincode::deserialize::<PeerExchangeMsgV1>(data) {
        Ok(old) => Some(PeerExchangeMsg {
            peers: old.peers,
            version: old.version,
            tip_height: old.tip_height,
            // Not "no genesis" but "did not say" — `foreign_chain_warning` treats the two the same
            // and stays quiet, which is right: an older peer's chain is not knowable from here.
            genesis_hash: String::new(),
        }),
        Err(_) => None,
    }
}

/// How many unreadable peer-exchange messages from one peer count as misbehaviour rather than as an
/// old build (backlog #166).
///
/// Peer exchange runs every 30 s, so a genuinely outdated node crosses this in about a minute and
/// a half and is then treated like any other misbehaving peer — five strikes and it is banned,
/// which is the correct end state: it cannot participate in this chain anyway. What the threshold
/// buys is the *first* minute, in which the log says something true about what is happening instead
/// of accusing a peer of sending garbage.
///
/// Not zero, and that is the part worth defending: an attacker who could send unlimited junk
/// without ever earning a strike would have a free channel. Repetition is what separates the two,
/// so repetition is what is counted.
const UNREADABLE_PEER_EXCHANGE_TOLERANCE: u32 = 3;

/// What to do about a peer whose peer-exchange message this build cannot read.
///
/// The message that made this necessary: `Malformed peer-exchange message: io error: unexpected end
/// of file`, seen right after the 0.10.1 deploy. It reads like an attack or a broken network, and
/// it means neither — a node running 0.8.x sends a payload with one field where this build expects
/// four, so both decoder shapes reject it. Whoever reads that line goes looking in the wrong place,
/// which is the same failure as #150's restart advice and the stale-genesis lockout: accurate about
/// the symptom, wrong about the cause, and therefore worse than silence.
fn unreadable_peer_exchange(peer: &str, seen: u32) -> (Option<String>, bool) {
    let strike = seen >= UNREADABLE_PEER_EXCHANGE_TOLERANCE;
    // Once, on the first occurrence — the same once-per-peer dedup `foreign_version_warning` uses.
    // This arrives every 30 s per peer and repeating it says nothing new.
    let message = (seen == 1).then(|| {
        format!(
            "A peer ({peer}) is sending peer-exchange messages this build cannot read. Almost \
             always this means it runs a Helix older than 0.9.0, whose message format this version \
             no longer understands — not that it is sending garbage. It cannot take part in this \
             chain until its operator upgrades it. If it keeps this up it will be treated as \
             misbehaving and disconnected."
        )
    });
    (message, strike)
}

/// Returns what the caller must act on: whether the sender misbehaved, and whether it is behind us
/// and should be served the blocks it is missing.
fn handle_peer_exchange_message(
    data: &[u8],
    known_addrs: &mut HashSet<String>,
    self_addr: Option<&str>,
    swarm: &mut libp2p::Swarm<HelixBehaviour>,
    warnings: &mut PeerWarnings,
    our_tip: u64,
    our_genesis: &str,
) -> PeerExchangeOutcome {
    let msg = match decode_peer_exchange(data) {
        Some(m) => m,
        None => {
            return PeerExchangeOutcome {
                malformed: true,
                announced_tip: None,
                serve_from_tip: None,
            };
        }
    };

    // Catch a peer that upgraded (or downgraded) while we keep running — the gap join-time
    // `peer_version_warning` cannot see (#109).
    if let Some(warning) = foreign_version_warning(&msg.version, OUR_VERSION, &mut warnings.versions) {
        warn!("{warning}");
    }

    // And catch the peer that is not on this chain at all.
    if let Some(warning) = foreign_chain_warning(&msg.genesis_hash, our_genesis, &mut warnings.chains) {
        warn!("{warning}");
    }

    for addr in select_new_addrs(known_addrs, &msg.peers, self_addr) {
        match addr.parse::<Multiaddr>() {
            Ok(multiaddr) => {
                debug!(addr = %addr, "Dialing newly learned peer address");
                let _ = swarm.dial(multiaddr);
            }
            Err(e) => {
                debug!(addr = %addr, err = %e, "Peer exchange gave an unparseable address — skipping");
            }
        }
    }

    tip_outcome(&msg, our_tip, our_genesis)
}

/// What a decoded peer-exchange message means for syncing: whose tip we record, and whom we serve.
///
/// Split out from `handle_peer_exchange_message` because that one needs a live `Swarm` to dial the
/// addresses it learns, which is exactly the kind of dependency that leaves the interesting decision
/// untested. This half is pure.
fn tip_outcome(msg: &PeerExchangeMsg, our_tip: u64, our_genesis: &str) -> PeerExchangeOutcome {
    // A peer on another chain gets no say in what we sync (backlog #175). Its height is a real
    // number about a chain we are not on, and letting it through made a freshly reset node chase
    // its own dead history: right after the 2026-08-07 reset, V1 sat at height 70 while operator
    // nodes still on the old chain claimed 36378, so it declared itself behind, block-synced from
    // them every second, and discarded every batch — two WARN lines a second, forever. Harmless to
    // the chain and corrosive to the log, which is how operators learn to skim warnings.
    //
    // `Unknown` deliberately behaves like `Same`: see `PeerChain`.
    if peer_chain(&msg.genesis_hash, our_genesis) == PeerChain::Foreign {
        return PeerExchangeOutcome {
            malformed: false,
            announced_tip: None,
            serve_from_tip: None,
        };
    }

    // The other direction of the same comparison: a peer ahead of us means *we* are missing blocks.
    // The caller records the height and the block-sync driver (#138) asks this peer for them.
    // `debug!`, not `warn!`: while a node is doing a normal bulk sync this is true and unremarkable
    // on every tick.
    if msg.tip_height > our_tip {
        debug!(
            our_tip,
            peer_tip = msg.tip_height,
            "A peer reports a higher committed tip than ours — this node is behind"
        );
    }

    PeerExchangeOutcome {
        malformed: false,
        announced_tip: Some(msg.tip_height),
        serve_from_tip: should_serve_catchup(msg.tip_height, our_tip).then_some(msg.tip_height),
    }
}

/// The peer worth asking for blocks: whichever known peer claims the highest tip, provided it is
/// actually above ours. `None` when nobody is ahead — which is the normal, healthy state.
///
/// Claims are unauthenticated, so "highest" is not "most trustworthy" — it only decides *who to ask
/// first*. A peer that lies about its height, or answers with junk, costs one round trip: the batch
/// fails verification in the node layer, nothing is written, and the next tick tries again. That is
/// why this can be a naive maximum rather than a reputation calculation.
/// Driver ticks a peer sits out after failing to serve us blocks — either by not answering at all,
/// or by serving a batch the node could not verify (backlog #140).
///
/// Long enough that the next tick genuinely reaches someone else, short enough that a peer with a
/// brief hiccup is not written off: at the 2 s driver interval this is ten seconds. Deliberately
/// not a ban — neither failure proves misbehaviour, and the goal here is to keep catching up, not
/// to punish.
const BLOCKSYNC_PEER_COOLDOWN_TICKS: u32 = 5;

/// How long a window the flap detector counts reconnects over, and how many it tolerates in one
/// (backlog #149).
///
/// Derived from the real outage rather than picked: the peer that flapped through the 2026-08-04/05
/// stall produced 434 connect/disconnect lines in 21 hours — 217 cycles, about **10 reconnects an
/// hour**, sustained. A healthy peer that loses its link occasionally does one or two. Five an hour
/// sits clear of normal churn and still catches that peer in the first hour instead of after
/// someone happens to read 868 log lines.
const FLAP_WINDOW: Duration = Duration::from_secs(3600);
const FLAP_THRESHOLD: u32 = 5;

/// Counts how often each peer reconnects, so a peer that never stays connected becomes visible.
///
/// It went unnoticed for 21 hours that one peer was reconnecting every 30 seconds. Nothing treated
/// that as remarkable — it is just `info!` lines, indistinguishable from normal churn unless you
/// already suspect it. A peer in this state is not noise: gossipsub never forms a stable mesh with
/// it, block sync cannot use it, and before #147 every cycle also tore down our accounting for it.
///
/// Warns, never bans. A flapping peer is usually the victim — a bad link, a proxy timing it out —
/// and disconnecting it would remove a validator whose votes the chain may need. Same reasoning as
/// the block-sync cooldown (#140): the goal is to make it visible, not to punish it.
struct FlapTracker {
    window_start: std::time::Instant,
    reconnects: HashMap<PeerId, u32>,
    warned: HashSet<PeerId>,
}

impl FlapTracker {
    fn new(now: std::time::Instant) -> Self {
        FlapTracker { window_start: now, reconnects: HashMap::new(), warned: HashSet::new() }
    }

    /// Records a reconnect and reports whether this peer has just crossed the threshold — `true`
    /// exactly once per peer per window, so a peer flapping all day produces one line an hour, not
    /// one per cycle.
    ///
    /// Clearing both maps on the window roll is also what bounds them: without it, a peer churning
    /// through fresh `PeerId`s would grow this map for the process's lifetime.
    fn note_reconnect(&mut self, peer: PeerId, now: std::time::Instant) -> bool {
        if now.duration_since(self.window_start) >= FLAP_WINDOW {
            self.window_start = now;
            self.reconnects.clear();
            self.warned.clear();
        }
        let count = self.reconnects.entry(peer).or_insert(0);
        *count += 1;
        *count >= FLAP_THRESHOLD && self.warned.insert(peer)
    }
}

/// Publishes the highest tip any peer currently claims (backlog #154). Called wherever `peer_tips`
/// changes, so a peer that leaves cannot leave its claim standing behind it — a stale high claim
/// would hold a caught-up node out of block production indefinitely.
fn publish_highest_peer_tip(slot: &Option<Arc<AtomicU64>>, peer_tips: &HashMap<PeerId, u64>) {
    if let Some(slot) = slot {
        slot.store(peer_tips.values().copied().max().unwrap_or(0), Ordering::Relaxed);
    }
}

/// Whether a closed connection means the *peer* is gone and its state must be torn down.
///
/// A named function rather than two inline conditions because getting this wrong is expensive and
/// invisible (backlog #147): treating any closure as a departure wipes `peer_tips`, which is the
/// block-sync driver's only record of who is ahead, and a node that has forgotten every peer's tip
/// never asks anyone for blocks again. That kept a freshly started validator on height 1 for 21
/// hours with the whole catch-up path intact.
///
/// - `remaining_connections`: libp2p's `num_established`, i.e. what is *left* to this peer. Several
///   connections per peer are routine — `max_established_per_peer` is 4, and a live run reaches it.
/// - `was_announced`: whether we ever reported this peer as connected. The ban path disconnects
///   without announcing, and an unpaired `PeerDisconnected` underflows the node's `peer_count`
///   (`AtomicUsize`) to `usize::MAX`, which makes every quorum-peer check pass.
fn peer_departed(remaining_connections: u32, was_announced: bool) -> bool {
    remaining_connections == 0 && was_announced
}

/// Pick the peer to ask for blocks: the highest claimed tip above ours, skipping anyone
/// serving a cooldown and anyone we are **not currently connected to**.
///
/// The connection filter exists because `peer_tips` is now keyed by the validator that
/// *originated* the announcement rather than the one that relayed it to us (see the
/// `TOPIC_PEER_EXCHANGE` arm). That is the honest attribution, but it means the map can name a
/// peer we have no connection to — and `send_request` to one of those buys a dial attempt and
/// an `OutboundFailure`, which costs the *responding* peer a cooldown it did not earn. Asking
/// only reachable peers keeps the higher-quality tip data without paying for it in failures.
/// Where a peer's claimed tip came from. The two sources are not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TipSource {
    /// A peer-exchange message: the peer's own statement about what it holds. Authoritative, so
    /// it may *lower* a tip — a peer that reset now legitimately claims less (#175).
    PeerExchange,
    /// The height of a block this peer gossiped. Raise-only: an old block replayed through the
    /// mesh must never push a tip back up.
    GossipedBlock,
}

/// The one place a peer's claimed tip enters `peer_tips`. Returns whether the claim was accepted
/// — i.e. whether the peer is allowed to inform our sync at all. Deliberately *not* "the map
/// changed": the caller republishes the highest tip on every accepted claim, exactly as both call
/// sites did before they were merged, so this stays a pure refactor for every peer but the
/// excluded one.
///
/// It exists because the gate below was written once and then missed by the second writer.
/// `peer_tips` is the sole input to `best_blocksync_peer`, and it had two authors: the
/// peer-exchange path checked `foreign_by_evidence`, the gossiped-block path — added later, to
/// stop a freshly started node idling for up to 30s without a known tip — did not. So a peer that
/// had already *proved* a different history walked straight back in through its own gossip.
///
/// That is not a theoretical hole, it is a loop, measured on 2026-09-02 against the node still
/// running the pre-reset 280941 chain: it proposes a block, that block's height lands in
/// `peer_tips`, it wins `best_blocksync_peer` on the highest claimed tip, serves 46 blocks that do
/// not chain from our tip, `BlocksyncPeerOnAnotherChain` drops the tip again — and the next
/// gossiped proposal puts it right back. 49 proposal→request pairs in a single log, every gap
/// exactly 1.0s. The evidence set held perfectly the whole time; it was simply asked at one of the
/// two doors.
fn record_peer_tip(
    peer_tips: &mut HashMap<PeerId, u64>,
    foreign_by_evidence: &HashSet<PeerId>,
    origin: PeerId,
    height: u64,
    source: TipSource,
) -> bool {
    // A peer that has already served a batch off another history gets no say in what we sync,
    // whatever it now claims and however it claims it.
    if foreign_by_evidence.contains(&origin) {
        return false;
    }
    match source {
        TipSource::PeerExchange => {
            peer_tips.insert(origin, height);
        }
        TipSource::GossipedBlock => {
            let entry = peer_tips.entry(origin).or_insert(height);
            if *entry < height {
                *entry = height;
            }
        }
    }
    true
}

fn best_blocksync_peer<F: Fn(&PeerId) -> bool>(
    peer_tips: &HashMap<PeerId, u64>,
    our_tip: u64,
    cooldown: &HashMap<PeerId, u32>,
    is_connected: F,
) -> Option<(PeerId, u64)> {
    peer_tips
        .iter()
        .filter(|(peer, &tip)| {
            tip > our_tip && !cooldown.contains_key(*peer) && is_connected(peer)
        })
        .max_by_key(|(_, &tip)| tip)
        .map(|(peer, &tip)| (*peer, tip))
}

/// Send one block-sync request if we are behind and a usable peer is available. Returns whether
/// a request went out. No-op while one is already in flight.
///
/// Extracted so catch-up can be driven by **progress** and not only by the clock. Requests used
/// to be issued exclusively from `blocksync_interval`, which made that 2s period a floor on the
/// time between one batch and the next: catch-up was capped at `MAX_BLOCKSYNC_BATCH` blocks per
/// tick — 50 blocks/s — however fast the link, the peer and the local apply actually were. At
/// the 2026-08-25 tip of ~477k blocks that is 2.7 hours of syncing with the connection idle
/// ~99% of the time. The node now reports each applied batch (`P2PCommand::BlocksyncAdvance`)
/// and this runs again immediately, so the next request leaves as soon as the previous batch is
/// on disk.
///
/// The interval stays, as the backstop: it covers every case where no progress report arrives —
/// a rejected batch, a dropped event, a peer that only just announced a higher tip, or a tip we
/// learned from a gossiped block while nothing was in flight.
fn request_blocks_if_behind(
    swarm: &mut libp2p::Swarm<HelixBehaviour>,
    peer_tips: &HashMap<PeerId, u64>,
    cooldown: &HashMap<PeerId, u32>,
    our_tip: u64,
    in_flight: &mut bool,
) -> bool {
    if *in_flight {
        return false;
    }
    let candidate = {
        let connected = &*swarm;
        best_blocksync_peer(peer_tips, our_tip, cooldown, |p| connected.is_connected(p))
    };
    let Some((peer, peer_tip)) = candidate else {
        return false;
    };
    let count = blocksync_request_count(our_tip, peer_tip);
    if count == 0 {
        return false;
    }
    debug!(
        peer = %peer,
        from = our_tip + 1,
        count,
        peer_tip,
        "Requesting missing blocks from a peer that is ahead"
    );
    swarm
        .behaviour_mut()
        .blocksync
        .send_request(&peer, BlockSyncRequest { from_height: our_tip + 1, count });
    *in_flight = true;
    true
}

/// How many blocks to ask for, given where we are and what the peer claims. Zero when we are not
/// behind, which the caller reads as "do not send a request at all".
///
/// Bounded by two things, and the second is the subtle one. Beyond the flat batch cap, a request
/// must not reach past the **validator-set rotation** that follows our tip. The executor rotates
/// `active_validators` while executing a block whose height is a multiple of `EPOCH_LENGTH`, after
/// that block's own participation is scored — so every block in `(k·L, (k+1)·L]` is signed by the
/// one set installed at `k·L`, and that is the set a receiver can derive from the state it already
/// trusts.
///
/// This matters because the receiver checks the batch tip's certificate against its **pre-batch**
/// set, which is the only set an attacker cannot influence. (Deriving the set by applying the batch
/// first would be self-certifying: whoever supplies the blocks would supply the set that validates
/// them.) A batch straddling a rotation would therefore be checked against a set that never signed
/// its tip, and honest blocks would be rejected. Stopping at the boundary keeps every batch inside
/// one set, at the cost of a shorter request every `EPOCH_LENGTH` blocks.
fn blocksync_request_count(our_tip: u64, peer_tip: u64) -> u32 {
    if peer_tip <= our_tip {
        return 0;
    }
    let from = our_tip + 1;
    let epoch_len = helix_consensus::EPOCH_LENGTH;
    let last_of_signing_group = ((from - 1) / epoch_len + 1) * epoch_len;
    let last = peer_tip.min(last_of_signing_group);
    (last - our_tip).min(u64::from(MAX_BLOCKSYNC_BATCH)) as u32
}

/// Publishes our full current `known_addrs` set on the peer-exchange topic, stamped with our
/// version. Sent even when we know no addresses yet: the message still carries our version, which
/// is worth propagating on its own so peers can notice a running-version mismatch (#109) — the
/// previous no-op-on-empty optimization would have withheld it exactly from a freshly started node.
fn broadcast_known_addrs(
    swarm: &mut libp2p::Swarm<HelixBehaviour>,
    topic: &gossipsub::IdentTopic,
    known_addrs: &HashSet<String>,
    tip_height: u64,
    genesis_hash: &str,
) {
    let msg = PeerExchangeMsg {
        peers: known_addrs.iter().cloned().collect(),
        version: OUR_VERSION.to_string(),
        tip_height,
        genesis_hash: genesis_hash.to_string(),
    };
    if let Ok(data) = bincode::serialize(&msg) {
        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
            debug!(err = %e, "Peer-exchange broadcast failed");
        }
    }
}

// ─── Application message handler ─────────────────────────────────────────────

/// What one gossiped application message told us.
#[derive(Debug, Default, PartialEq, Eq)]
struct AppMessageOutcome {
    /// The sender should be charged a misbehavior strike.
    malformed: bool,
    /// A height the *sender* provably holds, for `peer_tips`. `None` when the message says
    /// nothing about its sender's chain (a transaction, a vote, an unknown topic).
    observed_height: Option<u64>,
}

impl AppMessageOutcome {
    fn malformed() -> Self {
        AppMessageOutcome { malformed: true, observed_height: None }
    }

    fn clean(observed_height: Option<u64>) -> Self {
        AppMessageOutcome { malformed: false, observed_height }
    }
}

/// Decode one gossiped message, hand it to the node, and report what it implies about the
/// sender's height.
///
/// The two block topics are read conservatively, each for the strongest claim its message
/// actually supports:
///
/// - A **committed block** at `h` means the sender finalized `h`, so its tip is at least `h`.
/// - A **proposal** for `h` means the sender built on `h - 1`; it is claiming that as its tip,
///   not `h`. Reading it as `h` would have us request a block nobody has committed yet, get a
///   short answer, and cool down a peer for being honest.
///
/// Votes and transactions carry a height but say nothing about what their sender *holds* — a
/// vote for `h` is a claim about the round, and a validator votes on the block it is being
/// asked about. They contribute nothing here.
async fn handle_app_message(
    topic: &str,
    data: &[u8],
    event_tx: &mpsc::Sender<P2PEvent>,
) -> AppMessageOutcome {
    if topic == TOPIC_BLOCKS {
        match bincode::deserialize::<Proposal>(data) {
            Ok(proposal) => {
                debug!(height = proposal.block.height(), round = proposal.round, "Proposal from peer");
                let proposed = proposal.block.height();
                let _ = event_tx.send(P2PEvent::NewProposal(proposal)).await;
                AppMessageOutcome::clean(proposed.checked_sub(1))
            }
            Err(e) => {
                warn!("Invalid proposal from peer: {}", e);
                AppMessageOutcome::malformed()
            }
        }
    } else if topic == TOPIC_TRANSACTIONS {
        match bincode::deserialize::<Transaction>(data) {
            Ok(tx) => {
                let _ = event_tx.send(P2PEvent::NewTransaction(tx)).await;
                AppMessageOutcome::clean(None)
            }
            Err(e) => {
                warn!("Invalid tx from peer: {}", e);
                AppMessageOutcome::malformed()
            }
        }
    } else if topic == TOPIC_VOTES {
        match bincode::deserialize::<Vote>(data) {
            Ok(vote) => {
                let _ = event_tx.send(P2PEvent::NewVote(vote)).await;
                AppMessageOutcome::clean(None)
            }
            Err(e) => {
                warn!("Invalid vote from peer: {}", e);
                AppMessageOutcome::malformed()
            }
        }
    } else if topic == TOPIC_COMMITTED_BLOCKS {
        match bincode::deserialize::<(Block, Vec<Vote>)>(data) {
            Ok((block, commit)) => {
                debug!(height = block.height(), commit_sigs = commit.len(), "Committed block from peer");
                let committed = block.height();
                let _ = event_tx.send(P2PEvent::NewCommittedBlock(block, commit)).await;
                AppMessageOutcome::clean(Some(committed))
            }
            Err(e) => {
                warn!("Invalid committed block from peer: {}", e);
                AppMessageOutcome::malformed()
            }
        }
    } else {
        AppMessageOutcome::clean(None)
    }
}

#[cfg(test)]
mod highest_peer_tip_tests {
    use super::publish_highest_peer_tip;
    use libp2p::PeerId;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn the_highest_claim_wins() {
        let slot = Arc::new(AtomicU64::new(0));
        let mut tips = HashMap::new();
        tips.insert(PeerId::random(), 10u64);
        tips.insert(PeerId::random(), 900);
        tips.insert(PeerId::random(), 42);

        publish_highest_peer_tip(&Some(slot.clone()), &tips);

        assert_eq!(slot.load(Ordering::Relaxed), 900, "the maximum, not the last one seen");
    }

    /// The reason this is recomputed on *every* change to `peer_tips` rather than only on insert:
    /// a peer that leaves must not leave its claim behind. A stale high claim would hold a
    /// caught-up node out of block production forever (#154), and it would look like nothing.
    #[test]
    fn a_departed_peers_claim_does_not_linger() {
        let slot = Arc::new(AtomicU64::new(0));
        let staying = PeerId::random();
        let leaving = PeerId::random();
        let mut tips = HashMap::new();
        tips.insert(staying, 100u64);
        tips.insert(leaving, 5_000);

        publish_highest_peer_tip(&Some(slot.clone()), &tips);
        assert_eq!(slot.load(Ordering::Relaxed), 5_000);

        tips.remove(&leaving);
        publish_highest_peer_tip(&Some(slot.clone()), &tips);
        assert_eq!(slot.load(Ordering::Relaxed), 100, "the claim must leave with the peer");
    }

    /// No peers, no claim — and specifically 0, which the node reads as "nothing to compare
    /// against" and therefore never releases on.
    #[test]
    fn no_peers_publishes_zero() {
        let slot = Arc::new(AtomicU64::new(777));
        publish_highest_peer_tip(&Some(slot.clone()), &HashMap::new());
        assert_eq!(slot.load(Ordering::Relaxed), 0);
    }

    /// Reporting is opt-in; a service without a slot must not panic or otherwise care.
    #[test]
    fn reporting_is_optional() {
        let mut tips = HashMap::new();
        tips.insert(PeerId::random(), 1u64);
        publish_highest_peer_tip(&None, &tips);
    }
}

#[cfg(test)]
mod flap_tracker_tests {
    use super::{FlapTracker, FLAP_THRESHOLD, FLAP_WINDOW};
    use libp2p::PeerId;
    use std::time::{Duration, Instant};

    /// The production case, at the rate it actually occurred: ~10 reconnects an hour, sustained
    /// for 21 hours, and nothing anywhere treated it as remarkable (backlog #149).
    #[test]
    fn a_peer_reconnecting_over_and_over_is_reported() {
        let t0 = Instant::now();
        let mut tracker = FlapTracker::new(t0);
        let peer = PeerId::random();

        for i in 1..FLAP_THRESHOLD {
            assert!(
                !tracker.note_reconnect(peer, t0 + Duration::from_secs(i as u64 * 60)),
                "must not fire before the threshold (reconnect {i})"
            );
        }
        assert!(
            tracker.note_reconnect(peer, t0 + Duration::from_secs(FLAP_THRESHOLD as u64 * 60)),
            "must fire once the threshold is reached"
        );
    }

    /// Once per peer per window. A peer flapping all day is one line an hour, not one per cycle —
    /// otherwise the warning becomes the noise it exists to cut through.
    #[test]
    fn a_peer_already_reported_does_not_warn_again_in_the_same_window() {
        let t0 = Instant::now();
        let mut tracker = FlapTracker::new(t0);
        let peer = PeerId::random();

        let mut fired = 0;
        for i in 1..=(FLAP_THRESHOLD * 4) {
            if tracker.note_reconnect(peer, t0 + Duration::from_secs(u64::from(i) * 10)) {
                fired += 1;
            }
        }
        assert_eq!(fired, 1, "exactly one warning per peer per window");
    }

    /// The control that keeps the threshold honest: ordinary churn must stay silent. A detector
    /// that fires on a peer losing its link once or twice an hour would be turned off within a day.
    #[test]
    fn ordinary_reconnects_are_not_reported() {
        let t0 = Instant::now();
        let mut tracker = FlapTracker::new(t0);
        let peer = PeerId::random();

        // Two reconnects an hour, over four hours — a peer on a flaky link, not a flapping one.
        for hour in 0..4u64 {
            let base = t0 + Duration::from_secs(hour * 3600);
            assert!(!tracker.note_reconnect(peer, base + Duration::from_secs(60)));
            assert!(!tracker.note_reconnect(peer, base + Duration::from_secs(1800)));
        }
    }

    /// Peers are counted apart: one bad peer must not push an innocent one over the line.
    #[test]
    fn peers_are_counted_independently() {
        let t0 = Instant::now();
        let mut tracker = FlapTracker::new(t0);
        let noisy = PeerId::random();
        let quiet = PeerId::random();

        for i in 1..=(FLAP_THRESHOLD + 2) {
            tracker.note_reconnect(noisy, t0 + Duration::from_secs(u64::from(i) * 10));
        }
        assert!(
            !tracker.note_reconnect(quiet, t0 + Duration::from_secs(60)),
            "a peer that reconnected once must not inherit another peer's count"
        );
    }

    /// The window rolls, and rolling is also what bounds memory: without the clear, a peer churning
    /// through fresh PeerIds would grow these maps for the lifetime of the process.
    #[test]
    fn the_window_rolls_and_clears_what_it_counted() {
        let t0 = Instant::now();
        let mut tracker = FlapTracker::new(t0);
        let peer = PeerId::random();

        for i in 1..=FLAP_THRESHOLD {
            tracker.note_reconnect(peer, t0 + Duration::from_secs(u64::from(i)));
        }
        assert!(!tracker.reconnects.is_empty());

        // One reconnect in the next window: counted fresh, and the old bookkeeping is gone.
        let later = t0 + FLAP_WINDOW + Duration::from_secs(1);
        assert!(!tracker.note_reconnect(peer, later), "a new window starts from zero");
        assert_eq!(tracker.reconnects.len(), 1, "old counts must not accumulate");
        assert_eq!(tracker.warned.len(), 0, "and the peer can be reported again if it keeps at it");
    }
}

#[cfg(test)]
mod peer_departure_tests {
    use super::peer_departed;

    /// The production bug (#147), stated directly. A live 2-node run reaches four connections to
    /// one peer, so this is the ordinary case, not an edge case — and treating it as a departure
    /// wiped `peer_tips` and left catch-up with nobody to ask.
    ///
    /// Unit-level on purpose, and the reason is worth recording: the transport test alongside this
    /// proves multiple connections per peer really happen, but it cannot produce a *closure* while
    /// others remain — gossipsub keeps streams on every connection, so the idle timeout never
    /// reaps one, and surplus dials are refused before they are ever established (both measured,
    /// not assumed). An earlier version of this file asserted the teardown behaviour over the wire
    /// and passed just as happily with the fix removed. A vacuous test is worse than none.
    #[test]
    fn a_closure_with_connections_remaining_is_not_a_departure() {
        assert!(!peer_departed(3, true));
        assert!(!peer_departed(1, true));
    }

    #[test]
    fn the_last_connection_closing_is_a_departure() {
        assert!(peer_departed(0, true));
    }

    /// The ban path disconnects without ever announcing the peer. Retracting an announcement that
    /// was never made leaves `PeerConnected`/`PeerDisconnected` unpaired, and the node's
    /// `peer_count` is an `AtomicUsize` — one unpaired decrement is not `-1`, it is `usize::MAX`,
    /// after which every "do we have enough peers for quorum" check passes forever.
    #[test]
    fn a_peer_we_never_announced_is_never_reported_gone() {
        assert!(!peer_departed(0, false));
        assert!(!peer_departed(2, false));
    }
}

#[cfg(test)]
mod multiaddr_ip_tests {
    use super::multiaddr_ip;
    use libp2p::Multiaddr;

    #[test]
    fn extracts_ip4_ignoring_port() {
        let addr: Multiaddr = "/ip4/203.0.113.7/tcp/8546".parse().unwrap();
        assert_eq!(multiaddr_ip(&addr), Some("203.0.113.7".to_string()));
    }

    #[test]
    fn extracts_ip6_ignoring_port() {
        let addr: Multiaddr = "/ip6/::1/tcp/8546".parse().unwrap();
        assert_eq!(multiaddr_ip(&addr), Some("::1".to_string()));
    }

    #[test]
    fn returns_none_without_ip_component() {
        let addr: Multiaddr = "/dns4/example.com/tcp/8546".parse().unwrap();
        assert_eq!(multiaddr_ip(&addr), None);
    }
}

#[cfg(test)]
mod peer_exchange_tests {
    use super::{
        decode_peer_exchange, foreign_chain_warning, foreign_version_warning, peer_chain,
        select_new_addrs, should_serve_catchup, tip_outcome, unreadable_peer_exchange, PeerChain,
        PeerExchangeMsg, PeerExchangeMsgV1, MAX_CATCHUP_SERVE_BLOCKS, MAX_KNOWN_PEER_ADDRS,
        OUR_VERSION, UNREADABLE_PEER_EXCHANGE_TOLERANCE,
    };
    use std::collections::HashSet;

    /// The production incident in one assertion (#137): a validator one block behind the rest of
    /// the set. Before this mechanism existed there was no way for it to ever obtain that block,
    /// and because it was part of the quorum the whole chain stopped with it.
    #[test]
    fn a_peer_one_block_behind_is_served() {
        assert!(should_serve_catchup(26261, 26262));
    }

    /// The direction that must stay silent. When the peer is ahead, *we* are the ones missing
    /// blocks — serving would mean broadcasting blocks it already has, and an off-by-one here
    /// would have every node in a healthy set spraying its tip at every other node forever.
    #[test]
    fn a_peer_ahead_of_us_is_never_served() {
        assert!(!should_serve_catchup(26263, 26262));
    }

    #[test]
    fn a_peer_at_our_own_height_is_never_served() {
        assert!(!should_serve_catchup(26262, 26262));
    }

    /// The anti-amplification bound. `tip_height` arrives unauthenticated over gossip, so the
    /// cheapest lie — "I have nothing, send me everything" — must be the one that gains least.
    #[test]
    fn a_peer_claiming_to_be_hopelessly_behind_is_refused() {
        assert!(
            !should_serve_catchup(0, 26262),
            "a peer claiming height 0 on a long chain must not make us republish the chain"
        );
    }

    #[test]
    fn the_serve_bound_is_inclusive_at_its_edge_and_refuses_beyond_it() {
        let our_tip = 26262;
        assert!(
            should_serve_catchup(our_tip - MAX_CATCHUP_SERVE_BLOCKS, our_tip),
            "exactly at the bound must still be served"
        );
        assert!(
            !should_serve_catchup(our_tip - MAX_CATCHUP_SERVE_BLOCKS - 1, our_tip),
            "one past the bound belongs on the bulk RPC sync path"
        );
    }

    /// A fresh node with an empty store announces 0 and must not be treated as "behind" by another
    /// fresh node — otherwise two empty nodes would serve each other nothing, noisily.
    #[test]
    fn two_nodes_at_genesis_do_not_serve_each_other() {
        assert!(!should_serve_catchup(0, 0));
    }

    // ── Block-sync driver (#138) ──────────────────────────────────────────────

    fn peer(n: u8) -> libp2p::PeerId {
        // Deterministic distinct ids; the bytes themselves are irrelevant to the selection logic.
        libp2p::identity::Keypair::ed25519_from_bytes([n; 32]).unwrap().public().to_peer_id()
    }

    /// No peer is sitting anything out — the default state, and what every test that is not about
    /// the cooldown itself wants.
    fn no_cooldown() -> std::collections::HashMap<libp2p::PeerId, u32> {
        std::collections::HashMap::new()
    }

    /// Backlog #140. Selection is by highest claimed tip and nothing else, so a peer that never
    /// answers — or serves batches we cannot verify — is chosen again on every single tick while a
    /// healthy peer one block lower is never asked. That is not a slow catch-up, it is no catch-up
    /// at all, in exactly the situation directed block sync exists for.
    #[test]
    fn a_peer_on_cooldown_is_skipped_for_the_next_best_one() {
        let mut tips = std::collections::HashMap::new();
        tips.insert(peer(1), 130); // the one that keeps failing us
        tips.insert(peer(2), 129); // healthy, one block lower, previously never asked
        tips.insert(peer(3), 90); // behind us — still must not be picked

        let (chosen, _) = super::best_blocksync_peer(&tips, 100, &no_cooldown(), |_| true).unwrap();
        assert_eq!(chosen, peer(1), "precondition: the highest tip wins when nobody is penalised");

        let cooling: std::collections::HashMap<_, _> = [(peer(1), 5)].into_iter().collect();
        let (chosen, tip) = super::best_blocksync_peer(&tips, 100, &cooling, |_| true).unwrap();
        assert_eq!(chosen, peer(2), "the failing peer must not hold up catch-up");
        assert_eq!(tip, 129);
    }

    /// The cooldown must not become a way to end up asking nobody: if every peer ahead of us is
    /// sitting one out, there is genuinely nothing to do this tick, and the next tick — after the
    /// counters age — has to be able to pick again. Pinned because the alternative failure is
    /// silent (a node that simply stops catching up and logs nothing).
    #[test]
    fn when_everyone_ahead_is_cooling_down_we_ask_nobody_this_tick() {
        let mut tips = std::collections::HashMap::new();
        tips.insert(peer(1), 130);
        tips.insert(peer(2), 129);
        let cooling: std::collections::HashMap<_, _> =
            [(peer(1), 5), (peer(2), 1)].into_iter().collect();

        assert!(super::best_blocksync_peer(&tips, 100, &cooling, |_| true).is_none());

        // One tick later peer(2) has served its penalty — the driver's `retain` drops it at zero.
        let cooling: std::collections::HashMap<_, _> = [(peer(1), 4)].into_iter().collect();
        let (chosen, _) = super::best_blocksync_peer(&tips, 100, &cooling, |_| true).unwrap();
        assert_eq!(chosen, peer(2), "catch-up has to resume on its own, without a reconnect");
    }

    /// Nobody ahead of us is the healthy steady state, and it must produce no request at all —
    /// otherwise every node in a synced network would poll its peers forever.
    #[test]
    fn no_peer_ahead_means_no_request() {
        let mut tips = std::collections::HashMap::new();
        tips.insert(peer(1), 100);
        tips.insert(peer(2), 99);
        assert!(super::best_blocksync_peer(&tips, 100, &no_cooldown(), |_| true).is_none());
    }

    #[test]
    fn the_peer_with_the_highest_tip_is_chosen() {
        let mut tips = std::collections::HashMap::new();
        tips.insert(peer(1), 105);
        tips.insert(peer(2), 130);
        tips.insert(peer(3), 90); // behind us — must not be picked
        let (chosen, tip) = super::best_blocksync_peer(&tips, 100, &no_cooldown(), |_| true).unwrap();
        assert_eq!(chosen, peer(2));
        assert_eq!(tip, 130);
    }

    #[test]
    fn with_no_known_peers_there_is_nobody_to_ask() {
        assert!(super::best_blocksync_peer(&std::collections::HashMap::new(), 0, &no_cooldown(), |_| true).is_none());
    }

    /// The exact production shape: one block behind, so ask for exactly one block.
    #[test]
    fn a_one_block_gap_requests_one_block() {
        assert_eq!(super::blocksync_request_count(26261, 26262), 1);
    }

    /// A long catch-up is capped per request, not truncated to nothing and not asked for in one
    /// enormous batch that would blow the response size limit. From tip 0 the first signing group is
    /// `1..=EPOCH_LENGTH`, which is exactly one full batch.
    #[test]
    fn a_long_gap_is_capped_to_one_batch() {
        assert_eq!(
            super::blocksync_request_count(0, 26_262),
            super::MAX_BLOCKSYNC_BATCH
        );
    }

    /// A request must stop at the validator-set rotation that follows our tip, even when the flat
    /// batch cap would allow more and the peer has far more to give. Getting this wrong is silent:
    /// the batch arrives, is checked against a set that never signed its tip, and honest blocks are
    /// rejected — a node that can never catch up while every individual check looks correct.
    #[test]
    fn a_request_stops_at_the_next_validator_set_rotation() {
        let epoch = helix_consensus::EPOCH_LENGTH;
        // Tip mid-epoch: blocks (200, 300] share one signing set, so from 262 we may ask for 300−262+1.
        let our_tip = 2 * epoch + 62; // 262
        let count = super::blocksync_request_count(our_tip, our_tip + 5_000);
        assert_eq!(u64::from(count), (3 * epoch) - our_tip, "must stop at the boundary at 3·L");
        assert_eq!(our_tip + u64::from(count), 3 * epoch, "last requested block is the boundary itself");
        assert!(u64::from(count) < epoch, "and is therefore shorter than a full batch");
    }

    /// Sitting exactly on a boundary, the next group is a full epoch and may be requested whole —
    /// the boundary rule must not permanently shorten every request.
    #[test]
    fn sitting_on_a_boundary_allows_a_full_batch() {
        let epoch = helix_consensus::EPOCH_LENGTH;
        let count = super::blocksync_request_count(3 * epoch, 10 * epoch);
        assert_eq!(u64::from(count), epoch);
        assert_eq!(3 * epoch + u64::from(count), 4 * epoch);
    }

    /// The production shape once more, now against the boundary rule: one block behind, mid-epoch,
    /// asks for exactly that one block and does not get widened to the boundary.
    #[test]
    fn a_one_block_gap_is_not_widened_by_the_boundary_rule() {
        assert_eq!(super::blocksync_request_count(26_261, 26_262), 1);
    }

    /// Not behind means nothing to ask for. Guards the underflow too: subtracting a larger tip from
    /// a smaller one must not wrap around into a gigantic request.
    #[test]
    fn being_level_or_ahead_requests_nothing() {
        assert_eq!(super::blocksync_request_count(100, 100), 0);
        assert_eq!(super::blocksync_request_count(100, 90), 0);
    }

    /// A peer on a different chain has to be named as such.
    ///
    /// Nothing carried the genesis before, so two nodes on different chains gossiped at each other
    /// and rejected every message one at a time with nobody ever saying why. The operator sees only
    /// that their chain stopped — indistinguishable from every other stall.
    #[test]
    fn a_peer_on_another_chain_is_reported_once() {
        let mut warned = HashSet::new();
        let first = foreign_chain_warning("aaaa", "bbbb", &mut warned);
        assert!(first.expect("a different genesis must be reported").contains("DIFFERENT CHAIN"));
        assert!(
            foreign_chain_warning("aaaa", "bbbb", &mut warned).is_none(),
            "the same mismatch arrives every 30 seconds — it must be logged once",
        );
    }

    #[test]
    fn a_peer_on_our_own_chain_is_not_reported() {
        let mut warned = HashSet::new();
        assert!(foreign_chain_warning("aaaa", "aaaa", &mut warned).is_none());
    }

    /// "Did not say" is not "different". A peer on a build without the field announces nothing, and
    /// a node that has not loaded a genesis yet has nothing to announce — neither is a mismatch, and
    /// treating them as one would put a false alarm in front of every operator during every upgrade.
    #[test]
    fn a_peer_that_announces_no_genesis_is_not_reported() {
        let mut warned = HashSet::new();
        assert!(foreign_chain_warning("", "bbbb", &mut warned).is_none());
        assert!(foreign_chain_warning("aaaa", "", &mut warned).is_none());
    }

    /// A peer-exchange message announcing a tip on a given chain, with nothing else in it.
    fn msg_announcing(tip_height: u64, genesis_hash: &str) -> PeerExchangeMsg {
        PeerExchangeMsg {
            peers: vec![],
            version: OUR_VERSION.to_string(),
            tip_height,
            genesis_hash: genesis_hash.to_string(),
        }
    }

    /// Backlog #175, as the three-way decision it has to be.
    ///
    /// Reversing the `Unknown` arm is invisible in review — both versions compile, both "work" — and
    /// only one of them lets a node keep talking to peers that predate the genesis field.
    #[test]
    fn a_peer_that_did_not_say_which_chain_it_is_on_is_not_treated_as_foreign() {
        assert_eq!(peer_chain("aaaa", "aaaa"), PeerChain::Same);
        assert_eq!(peer_chain("aaaa", "bbbb"), PeerChain::Foreign);
        assert_eq!(peer_chain("", "bbbb"), PeerChain::Unknown, "did not say ≠ different");
        assert_eq!(peer_chain("aaaa", ""), PeerChain::Unknown, "we have no genesis yet");
    }

    /// The behaviour that cost 12 hours of log noise after the 2026-08-07 reset: a node at height 70
    /// took the 36378 claimed by peers still on the *old* chain as evidence it was behind, and
    /// block-synced from them once a second forever, discarding every batch.
    #[test]
    fn a_foreign_chains_tip_is_not_recorded_or_served() {
        let ours = "6860abda";
        let foreign = msg_announcing(36378, "ff271e4a");
        let outcome = tip_outcome(&foreign, 70, ours);
        assert_eq!(outcome.announced_tip, None, "a foreign tip must not drive our sync");
        assert_eq!(outcome.serve_from_tip, None, "nor make us serve blocks it cannot use");
        assert!(!outcome.malformed, "it is a well-formed message from a peer on another chain");

        // Positive control: the identical message from a peer on our chain still counts. Without
        // this, the test above would pass just as well if tips had stopped working altogether.
        let outcome = tip_outcome(&msg_announcing(36378, ours), 70, ours);
        assert_eq!(outcome.announced_tip, Some(36378));
    }

    /// A peer that did not announce a genesis must still be listened to — the case that makes the
    /// `Unknown` arm load-bearing rather than decorative.
    #[test]
    fn a_peer_that_announced_no_genesis_is_still_worth_asking_for_blocks() {
        let outcome = tip_outcome(&msg_announcing(500, ""), 70, "6860abda");
        assert_eq!(outcome.announced_tip, Some(500));
    }

    /// Backlog #166: the first unreadable message explains itself, and does not cost a strike.
    ///
    /// The line it replaces — "Malformed peer-exchange message: io error: unexpected end of file" —
    /// was accurate and sent every reader hunting for an attack or a broken network, when the cause
    /// is someone running a Helix older than 0.9.0.
    #[test]
    fn an_unreadable_peer_exchange_reads_as_an_old_build_before_it_reads_as_abuse() {
        let (message, strike) = unreadable_peer_exchange("12D3KooWpeer", 1);
        let message = message.expect("the first one has to say something");
        assert!(message.contains("older than 0.9.0"), "must name the likely cause: {message}");
        assert!(message.contains("cannot read"), "{message}");
        assert!(
            !message.contains("Malformed"),
            "the word that sent everyone to the wrong place: {message}",
        );
        assert!(!strike, "one unreadable message is not misbehaviour");

        // Silent afterwards — it arrives every 30 s and repeating it says nothing new.
        assert_eq!(unreadable_peer_exchange("12D3KooWpeer", 2).0, None);
    }

    /// And the other half: repetition *is* misbehaviour, or an attacker gets a free channel for
    /// unlimited junk. The tolerance buys diagnosis, it does not buy immunity.
    #[test]
    fn a_peer_that_keeps_sending_unreadable_messages_is_eventually_charged() {
        assert!(!unreadable_peer_exchange("p", 1).1);
        assert!(!unreadable_peer_exchange("p", 2).1);
        assert!(
            unreadable_peer_exchange("p", UNREADABLE_PEER_EXCHANGE_TOLERANCE).1,
            "past the tolerance it is treated as any other misbehaving peer",
        );
        assert!(unreadable_peer_exchange("p", 50).1);
    }

    /// The one that matters most, and the reason this crate now carries two message shapes.
    ///
    /// A peer running the previous release sends the payload without `genesis_hash`. bincode is not
    /// self-describing, so it does not decode as the new struct — and an undecodable peer-exchange
    /// message charges a misbehavior strike, arrives every 30 seconds, and bans the peer after five.
    /// Adding one field would have banned a healthy co-signing validator inside three minutes and
    /// stalled a two-validator chain. No existing test could catch it: none of them runs two
    /// different builds against each other.
    #[test]
    fn a_peer_on_the_previous_release_is_still_understood() {
        let old = PeerExchangeMsgV1 {
            peers: vec!["/ip4/127.0.0.1/tcp/8546".to_string()],
            version: "0.10.0".to_string(),
            tip_height: 4419,
        };
        let bytes = bincode::serialize(&old).expect("serializes");

        let decoded = decode_peer_exchange(&bytes).expect("an older peer is not a malformed one");
        assert_eq!(decoded.version, "0.10.0");
        assert_eq!(decoded.tip_height, 4419);
        assert_eq!(decoded.peers, old.peers);
        assert!(decoded.genesis_hash.is_empty(), "it did not say, and must not appear to have");
    }

    #[test]
    fn a_peer_on_this_release_is_understood_with_its_genesis() {
        let msg = PeerExchangeMsg {
            peers: vec![],
            version: OUR_VERSION.to_string(),
            tip_height: 1,
            genesis_hash: "ff271e4a".to_string(),
        };
        let bytes = bincode::serialize(&msg).expect("serializes");
        assert_eq!(decode_peer_exchange(&bytes).unwrap().genesis_hash, "ff271e4a");
    }

    /// The control that keeps the fallback honest: genuine rubbish must still be malformed, or the
    /// tolerance has quietly disabled the misbehavior accounting it was carved out of.
    #[test]
    fn actual_rubbish_is_still_malformed() {
        assert!(decode_peer_exchange(&[0xff; 8]).is_none());
        assert!(decode_peer_exchange(b"not bincode at all").is_none());
    }

    #[test]
    fn a_matching_version_never_warns() {
        let mut warned = HashSet::new();
        assert!(foreign_version_warning("0.8.13", "0.8.13", &mut warned).is_none());
        assert!(warned.is_empty(), "a match must not even be recorded");
    }

    #[test]
    fn a_differing_version_warns_once_then_stays_quiet() {
        let mut warned = HashSet::new();
        let first = foreign_version_warning("0.9.0", "0.8.13", &mut warned);
        assert!(first.is_some(), "the first sight of a foreign version must warn");
        assert!(first.unwrap().contains("0.9.0"), "the warning names the peer's version");
        // The same mismatch keeps arriving every 30s on the peer-exchange tick — it must not
        // re-warn each time (#109).
        assert!(
            foreign_version_warning("0.9.0", "0.8.13", &mut warned).is_none(),
            "a version already warned about must stay quiet"
        );
    }

    #[test]
    fn each_distinct_foreign_version_warns_separately() {
        let mut warned = HashSet::new();
        assert!(foreign_version_warning("0.9.0", "0.8.13", &mut warned).is_some());
        assert!(
            foreign_version_warning("0.7.0", "0.8.13", &mut warned).is_some(),
            "a different foreign version is a new fact worth its own warning"
        );
    }

    #[test]
    fn returns_only_genuinely_new_addresses() {
        let mut known: HashSet<String> = ["addr-a".to_string()].into_iter().collect();
        let incoming = vec!["addr-a".to_string(), "addr-b".to_string()];

        let new_addrs = select_new_addrs(&mut known, &incoming, None);

        assert_eq!(new_addrs, vec!["addr-b".to_string()]);
        assert!(known.contains("addr-b"));
    }

    #[test]
    fn skips_our_own_address() {
        let mut known = HashSet::new();
        let incoming = vec!["addr-self".to_string(), "addr-other".to_string()];

        let new_addrs = select_new_addrs(&mut known, &incoming, Some("addr-self"));

        assert_eq!(new_addrs, vec!["addr-other".to_string()]);
        assert!(!known.contains("addr-self"));
    }

    #[test]
    fn stops_once_the_cap_is_reached() {
        let mut known: HashSet<String> = (0..MAX_KNOWN_PEER_ADDRS)
            .map(|i| format!("addr-{i}"))
            .collect();
        let incoming = vec!["addr-overflow".to_string()];

        let new_addrs = select_new_addrs(&mut known, &incoming, None);

        assert!(new_addrs.is_empty());
        assert_eq!(known.len(), MAX_KNOWN_PEER_ADDRS);
    }
}


/// Build the libp2p swarm every Helix endpoint uses — the long-lived [`P2PService`] and the
/// one-shot genesis bootstrap in [`crate::genesis_bootstrap`] alike.
///
/// Extracted so those two cannot drift apart. They have to speak the same transports and the
/// same protocols to reach each other at all, and a second copy of this builder is exactly the
/// duplicated invariant that goes stale the first time a transport is added to one of them —
/// silently, and only on the path nobody exercises by hand.
pub(crate) async fn build_swarm(config: &P2PConfig) -> P2PResult<libp2p::Swarm<HelixBehaviour>> {
    let max_msg_size = config.max_message_size;

    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| P2PError::Transport(e.to_string()))?
        .with_dns()
        .map_err(|e| P2PError::Transport(e.to_string()))?
        // Added unconditionally, unlike the `ws_listen_addr` listener below: dialing a
        // `/ws` or `/tls/ws` peer must work for every node, including ones that are not
        // themselves reachable that way. A node that only listens on raw TCP still has to
        // be able to reach a tunnelled peer.
        .with_websocket(
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .await
        .map_err(|e| P2PError::Transport(e.to_string()))?
        .with_behaviour(|key| {
            let message_id_fn = |msg: &gossipsub::Message| {
                let mut hasher = DefaultHasher::new();
                msg.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                // 1s (down from libp2p's 1s default that a prior 10s override had
                // slowed right down): the heartbeat drives both mesh maintenance and
                // the IHAVE/IWANT gossip that recovers messages a peer missed while its
                // mesh was still forming. At 10s, a consensus vote dropped during the
                // first seconds of a round was not re-offered until long after the round
                // had already timed out — so in a multi-validator set some node was
                // always short a prevote or precommit and no round ever reached quorum.
                // At 1s the recovery lands well within a round. Cheap at Helix's small
                // validator-set scale.
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .max_transmit_size(max_msg_size)
                .build()
                .expect("gossipsub config is valid");

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .expect("gossipsub behaviour is valid");

            let mdns: Toggle<mdns::tokio::Behaviour> = if config.enable_mdns {
                Some(
                    mdns::tokio::Behaviour::new(
                        mdns::Config::default(),
                        key.public().to_peer_id(),
                    )
                    .expect("mdns behaviour is valid"),
                )
                .into()
            } else {
                None.into()
            };

            let connection_limits = libp2p::connection_limits::Behaviour::new(
                libp2p::connection_limits::ConnectionLimits::default()
                    .with_max_established(Some(config.max_peers as u32))
                    .with_max_established_incoming(Some(config.max_established_incoming))
                    .with_max_pending_incoming(Some(config.max_pending_incoming))
                    .with_max_established_per_peer(Some(config.max_established_per_peer)),
            );
            let ip_limits = IpConnLimiter::new(config.max_connections_per_ip);

            // `ProtocolSupport::Full` — every node both asks and answers. A node that only
            // asked would be a free-rider on a network whose whole point (#138) is that any
            // peer can bootstrap any other without a central RPC endpoint.
            let blocksync = request_response::Behaviour::with_codec(
                BlockSyncCodec,
                [(BLOCKSYNC_PROTOCOL, request_response::ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30)),
            );

            let genesis_sync = request_response::Behaviour::with_codec(
                GenesisCodec,
                [(GENESIS_PROTOCOL, request_response::ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30)),
            );

            // Short timeout, unlike the two above: this request only has value inside the round
            // that prompted it. An answer that arrives after the round is gone is at best wasted
            // and at worst a stale proposal the engine has to reject, so it is better to give up
            // and ask again next round than to hold the slot open.
            let roundsync = request_response::Behaviour::with_codec(
                RoundSyncCodec,
                [(ROUNDSYNC_PROTOCOL, request_response::ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(5)),
            );

            HelixBehaviour {
                gossipsub,
                mdns,
                connection_limits,
                ip_limits,
                blocksync,
                genesis_sync,
                roundsync,
            }
        })
        .expect("behaviour setup never fails")
        .with_swarm_config(|cfg| {
            // libp2p-swarm defaults this to Duration::ZERO — a connection with no
            // substream open AT THE EXACT INSTANT it's checked is torn down
            // immediately, no grace period. Right after a fresh connection
            // establishes, there's a brief window before gossipsub/mdns have
            // finished negotiating their own substreams; racing that window against
            // a zero-duration idle check flakily kills freshly-established
            // connections before they ever get used — found by running a real
            // multi-node local testnet (a single-node devnet never has a peer to
            // race against, so this never showed up before). Once a connection is
            // actually in use (gossip flowing every ~2s per block), the zero
            // default was never a problem — this only bites the handshake window
            // right at connection setup.
            cfg.with_idle_connection_timeout(Duration::from_secs(60))
        })
        .build();

    Ok(swarm)
}

#[cfg(test)]
mod blocksync_selection_tests {
    use super::{best_blocksync_peer, BLOCKSYNC_PEER_COOLDOWN_TICKS};
    use libp2p::PeerId;
    use std::collections::HashMap;

    fn no_cooldown() -> HashMap<PeerId, u32> {
        HashMap::new()
    }

    /// **The live case this exists for**, as arithmetic rather than a story.
    ///
    /// A node left running on the chain that was reset away on 2026-08-26 claimed height 477,478
    /// while the real chain sat at 41,644. Because it ran a build whose peer exchange predates
    /// `genesis_hash` it was never recognised as foreign, so its tip went into this map — and this
    /// function picks the highest, so it won every choice, over the one peer that could actually
    /// serve blocks. The cooldown paced the damage at one wasted 56-block fetch every ten seconds
    /// and never ended it.
    ///
    /// Dropping such a peer's tip on the evidence of what it served is the fix; this pins the
    /// selection consequence, so the two halves cannot be repaired independently and drift.
    #[test]
    fn a_peer_dropped_for_serving_another_history_stops_winning_the_choice() {
        let zombie = PeerId::random();
        let real = PeerId::random();
        let mut tips = HashMap::new();
        tips.insert(zombie, 477_478);
        tips.insert(real, 41_700);

        let chosen = best_blocksync_peer(&tips, 41_644, &no_cooldown(), |_| true);
        assert_eq!(
            chosen.map(|(p, _)| p),
            Some(zombie),
            "premise: the highest claim wins, which is exactly why a dead chain's claim is harmful"
        );

        // What `BlocksyncPeerOnAnotherChain` does: forget the tip entirely, rather than cool it
        // down and let it win again ten seconds later.
        tips.remove(&zombie);
        assert_eq!(
            best_blocksync_peer(&tips, 41_644, &no_cooldown(), |_| true).map(|(p, _)| p),
            Some(real),
            "with its tip forgotten, catch-up goes to the peer that can actually serve it"
        );
    }

    /// A cooldown alone would not have been enough, and this says why in one assertion: it expires.
    #[test]
    fn a_cooldown_only_postpones_a_peer_that_should_never_be_asked_again() {
        let zombie = PeerId::random();
        let real = PeerId::random();
        let mut tips = HashMap::new();
        tips.insert(zombie, 477_478);
        tips.insert(real, 41_700);

        let mut cooling = HashMap::new();
        cooling.insert(zombie, BLOCKSYNC_PEER_COOLDOWN_TICKS);
        assert_eq!(
            best_blocksync_peer(&tips, 41_644, &cooling, |_| true).map(|(p, _)| p),
            Some(real),
            "while cooling, the real peer is preferred"
        );

        // …and the moment it lapses, the dead chain is back at the front of the queue.
        assert_eq!(
            best_blocksync_peer(&tips, 41_644, &no_cooldown(), |_| true).map(|(p, _)| p),
            Some(zombie),
            "which is the whole reason the tip has to be dropped and not merely delayed"
        );
    }

    /// `peer_tips` is keyed by the validator that *originated* an announcement, which is the
    /// honest attribution but means the map can name peers we hold no connection to. Asking one
    /// of those costs a dial attempt and an `OutboundFailure`, and the cooldown that failure
    /// earns lands on a peer that did nothing wrong.
    #[test]
    fn the_highest_tip_is_skipped_when_we_have_no_connection_to_that_peer() {
        let unreachable = PeerId::random();
        let connected = PeerId::random();
        let mut tips = HashMap::new();
        tips.insert(unreachable, 900);
        tips.insert(connected, 400);

        let (chosen, tip) =
            best_blocksync_peer(&tips, 100, &no_cooldown(), |p| *p == connected).unwrap();

        assert_eq!(chosen, connected, "must ask the peer we can actually reach");
        assert_eq!(tip, 400);
    }

    /// The single-peer case, which is the one a fresh node behind the tunnel is actually in: no
    /// request at all beats a request that can only fail.
    #[test]
    fn nobody_is_asked_when_every_peer_ahead_is_unreachable() {
        let unreachable = PeerId::random();
        let mut tips = HashMap::new();
        tips.insert(unreachable, 900);

        assert!(best_blocksync_peer(&tips, 100, &no_cooldown(), |_| false).is_none());
    }

    /// Connectivity is an additional filter, never a replacement for the cooldown: a connected
    /// peer serving its penalty still must not be picked.
    #[test]
    fn being_connected_does_not_override_a_cooldown() {
        let cooling = PeerId::random();
        let mut tips = HashMap::new();
        tips.insert(cooling, 900);
        let mut cooldown = HashMap::new();
        cooldown.insert(cooling, BLOCKSYNC_PEER_COOLDOWN_TICKS);

        assert!(best_blocksync_peer(&tips, 100, &cooldown, |_| true).is_none());
    }
}

#[cfg(test)]
mod observed_height_tests {
    use super::{handle_app_message, TOPIC_BLOCKS, TOPIC_COMMITTED_BLOCKS, TOPIC_VOTES};
    use helix_consensus::proposal::Proposal;
    use helix_core::block::{genesis_block, Block};
    use helix_crypto::{Address, PublicKey, Signature};
    use tokio::sync::mpsc;

    fn block_at(height: u64) -> Block {
        let pk = PublicKey::from_bytes(vec![7; 32]);
        let mut block = genesis_block(
            Address::from_public_key(&pk),
            pk,
            Signature::from_bytes(vec![9; 32]),
            1_700_000_000_000,
        );
        block.header.height = height;
        block
    }

    /// A committed block is the sender's own finalized history: it holds at least that height.
    #[tokio::test]
    async fn a_committed_block_claims_its_own_height() {
        let (tx, _rx) = mpsc::channel(4);
        let data = bincode::serialize(&(block_at(4_200), Vec::<helix_consensus::vote::Vote>::new()))
            .unwrap();

        let outcome = handle_app_message(TOPIC_COMMITTED_BLOCKS, &data, &tx).await;

        assert!(!outcome.malformed);
        assert_eq!(outcome.observed_height, Some(4_200));
    }

    /// A proposal is a claim about the block *below* it — the proposer built on its own tip and
    /// is asking the set to accept the next one. Reading it as the proposed height would have us
    /// request a block nobody has committed, take a short answer, and cool down an honest peer.
    #[tokio::test]
    async fn a_proposal_claims_only_the_height_below_it() {
        let (tx, _rx) = mpsc::channel(4);
        let data = bincode::serialize(&Proposal::fresh(0, block_at(4_200))).unwrap();

        let outcome = handle_app_message(TOPIC_BLOCKS, &data, &tx).await;

        assert!(!outcome.malformed);
        assert_eq!(outcome.observed_height, Some(4_199));
    }

    /// And a proposal for height 0 claims nothing rather than underflowing.
    #[tokio::test]
    async fn a_proposal_at_the_genesis_height_claims_nothing() {
        let (tx, _rx) = mpsc::channel(4);
        let data = bincode::serialize(&Proposal::fresh(0, block_at(0))).unwrap();

        let outcome = handle_app_message(TOPIC_BLOCKS, &data, &tx).await;

        assert_eq!(outcome.observed_height, None);
    }

    /// A vote carries a height, but it is a claim about the round being decided, not about what
    /// the sender holds — a validator votes on the block it is being asked about.
    #[tokio::test]
    async fn a_malformed_vote_is_a_strike_and_still_claims_no_height() {
        let (tx, _rx) = mpsc::channel(4);

        let outcome = handle_app_message(TOPIC_VOTES, b"not a vote", &tx).await;

        assert!(outcome.malformed);
        assert_eq!(outcome.observed_height, None);
    }
}

#[cfg(test)]
mod peer_tip_gate_tests {
    use super::TipSource;
    use libp2p::PeerId;
    use std::collections::{HashMap, HashSet};

    fn no_cooldown() -> HashMap<PeerId, u32> {
        HashMap::new()
    }

    /// The regression this whole helper exists for. Both doors into `peer_tips` must be shut
    /// against a peer that proved a different history — the gossip door was open, and that turned
    /// a one-time exclusion into a loop that reinstated the peer every round.
    #[test]
    fn a_peer_that_proved_another_history_cannot_walk_back_in_through_either_door() {
        let zombie = PeerId::random();
        let mut tips: HashMap<PeerId, u64> = HashMap::new();
        let mut foreign: HashSet<PeerId> = HashSet::new();
        foreign.insert(zombie);

        assert!(
            !super::record_peer_tip(&mut tips, &foreign, zombie, 280_941, TipSource::PeerExchange),
            "peer exchange from a peer on another history must not set a tip",
        );
        assert!(
            !super::record_peer_tip(&mut tips, &foreign, zombie, 280_941, TipSource::GossipedBlock),
            "a gossiped block is the same claim through a different door — it must not set a tip \
             either, or the exclusion undoes itself on the peer's next proposal",
        );
        assert!(tips.is_empty(), "an excluded peer must leave no tip behind at all");
    }

    /// Live reproduction of the 2026-09-02 loop: exclude, then let the peer gossip. Before the
    /// gate, `best_blocksync_peer` picked the excluded peer straight back out.
    #[test]
    fn an_excluded_peer_does_not_win_the_blocksync_choice_again_after_gossiping() {
        let zombie = PeerId::random();
        let honest = PeerId::random();
        let mut tips: HashMap<PeerId, u64> = HashMap::new();
        let mut foreign: HashSet<PeerId> = HashSet::new();

        // Both peers announce; the zombie claims the far higher tip, so it wins on merit.
        super::record_peer_tip(&mut tips, &foreign, zombie, 280_941, TipSource::PeerExchange);
        super::record_peer_tip(&mut tips, &foreign, honest, 27_960, TipSource::PeerExchange);
        let (chosen, _) =
            super::best_blocksync_peer(&tips, 27_954, &no_cooldown(), |_| true).unwrap();
        assert_eq!(chosen, zombie, "positive control: the highest claimed tip wins");

        // Its batch did not chain. This is what `BlocksyncPeerOnAnotherChain` does.
        foreign.insert(zombie);
        tips.remove(&zombie);

        // Now it proposes a block, exactly as the real one did every couple of minutes.
        super::record_peer_tip(&mut tips, &foreign, zombie, 280_941, TipSource::GossipedBlock);

        let (chosen, _) =
            super::best_blocksync_peer(&tips, 27_954, &no_cooldown(), |_| true).unwrap();
        assert_eq!(
            chosen, honest,
            "after proving another history the peer must stay out, however loudly it gossips",
        );
    }

    /// The gate must not cost the reason the gossip path was added: a peer we have nothing against
    /// still teaches us its height, and raise-only still holds.
    #[test]
    fn an_ordinary_peer_still_teaches_its_tip_and_a_replayed_block_cannot_lower_it() {
        let peer = PeerId::random();
        let mut tips: HashMap<PeerId, u64> = HashMap::new();
        let foreign: HashSet<PeerId> = HashSet::new();

        assert!(super::record_peer_tip(&mut tips, &foreign, peer, 100, TipSource::GossipedBlock));
        assert_eq!(tips.get(&peer), Some(&100));

        super::record_peer_tip(&mut tips, &foreign, peer, 90, TipSource::GossipedBlock);
        assert_eq!(
            tips.get(&peer),
            Some(&100),
            "an old block replayed through the mesh must not move the tip",
        );

        assert!(
            super::record_peer_tip(&mut tips, &foreign, peer, 90, TipSource::PeerExchange),
            "peer exchange is the authority and must still be able to lower a tip (#175)",
        );
        assert_eq!(tips.get(&peer), Some(&90));
    }
}
