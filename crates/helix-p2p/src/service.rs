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
use crate::conn_limits::IpConnLimiter;
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
    /// The node could not verify the block-sync batch this peer served (backlog #140). The service
    /// cannot tell that by itself: from here a batch that fails verification and one that applies
    /// cleanly are both just a non-empty response. Without this the peer keeps being picked — it
    /// is by definition the one claiming the highest tip — and catch-up never moves.
    BlocksyncBatchRejected(String),
}

#[derive(NetworkBehaviour)]
struct HelixBehaviour {
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
    /// Answers inbound block-sync requests (#138). Supplied by the node, which owns the store —
    /// see [`BlockProvider`] for why the dependency points this way.
    block_provider: Arc<dyn BlockProvider>,
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
            P2PService { config, event_tx, command_rx, tip_height, block_provider },
            command_tx,
            event_rx,
        )
    }

    pub async fn run(self) -> P2PResult<()> {
        // Destructure so we can move fields into the loop without borrowing `self`
        let event_tx = self.event_tx;
        let mut command_rx = self.command_rx;
        let config = self.config;
        let tip_height = self.tip_height;
        let block_provider = self.block_provider;

        let max_msg_size = config.max_message_size;

        let mut swarm = SwarmBuilder::with_new_identity()
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

                HelixBehaviour { gossipsub, mdns, connection_limits, ip_limits, blocksync }
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

        for addr in &seed_addrs {
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
        let mut warned_versions: HashSet<String> = HashSet::new();
        // Tip each peer last announced, so the block-sync driver below knows who to ask (#138).
        // Bounded by the connection limit and pruned on disconnect, so it cannot grow unbounded.
        let mut peer_tips: HashMap<PeerId, u64> = HashMap::new();
        // One outstanding request at a time. Without this, every driver tick while a slow batch is
        // in transit would fire another request for the same range — turning our own catch-up into
        // a flood. Cleared on a response and on any failure, so a peer that never answers costs one
        // request and one timeout, not a wedged sync.
        let mut blocksync_in_flight = false;
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
                                    config.public_addr.as_deref(),
                                    &mut swarm,
                                    &mut warned_versions,
                                    tip_height.load(Ordering::Relaxed),
                                );
                                if let Some(tip) = outcome.announced_tip {
                                    peer_tips.insert(propagation_source, tip);
                                }
                                if let Some(peer_tip) = outcome.serve_from_tip {
                                    let _ = event_tx
                                        .send(P2PEvent::PeerBehind { peer_tip })
                                        .await;
                                }
                                outcome.malformed
                            } else {
                                handle_app_message(topic, &message.data, &event_tx).await
                            };

                            if malformed && reputation.record_infraction(&peer_str) {
                                warn!(peer = %peer_str, "peer exceeded misbehavior threshold — disconnecting");
                                let _ = swarm.disconnect_peer_id(propagation_source);
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

                            info!(peer = %peer_id, "Peer connected");

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
                            );

                            let _ = event_tx.send(P2PEvent::PeerConnected(peer_str)).await;
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            // `info!`, matching "Peer connected" above — the asymmetry this
                            // replaces (connect at `info!`, disconnect at `debug!`) is not
                            // cosmetic. On 2026-07-29 a dropped link to one validator cost 14.5
                            // hours of production downtime, and the disconnect that started it was
                            // invisible: the outage had to be reconstructed backwards from the
                            // *reconnect* lines, which were the only trace at the default log
                            // level. A lost peer is exactly as newsworthy as a gained one.
                            info!(peer = %peer_id, "Peer disconnected");
                            peer_tips.remove(&peer_id);
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
                    if !blocksync_in_flight {
                        let our_tip = tip_height.load(Ordering::Relaxed);
                        if let Some((peer, peer_tip)) =
                            best_blocksync_peer(&peer_tips, our_tip, &blocksync_cooldown)
                        {
                            let count = blocksync_request_count(our_tip, peer_tip);
                            if count > 0 {
                                debug!(
                                    peer = %peer,
                                    from = our_tip + 1,
                                    count,
                                    peer_tip,
                                    "Requesting missing blocks from a peer that is ahead"
                                );
                                swarm.behaviour_mut().blocksync.send_request(
                                    &peer,
                                    BlockSyncRequest { from_height: our_tip + 1, count },
                                );
                                blocksync_in_flight = true;
                            }
                        }
                    }
                }

                _ = peer_exchange_interval.tick() => {
                    broadcast_known_addrs(
                        &mut swarm,
                        &peer_exchange_topic,
                        &known_addrs,
                        tip_height.load(Ordering::Relaxed),
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
                                    debug!("Proposal broadcast: {}", e);
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
                                    debug!("Committed block broadcast: {}", e);
                                }
                            }
                        }
                        P2PCommand::ConnectPeer(addr) => {
                            let _ = swarm.dial(addr);
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

/// Returns what the caller must act on: whether the sender misbehaved, and whether it is behind us
/// and should be served the blocks it is missing.
fn handle_peer_exchange_message(
    data: &[u8],
    known_addrs: &mut HashSet<String>,
    self_addr: Option<&str>,
    swarm: &mut libp2p::Swarm<HelixBehaviour>,
    warned_versions: &mut HashSet<String>,
    our_tip: u64,
) -> PeerExchangeOutcome {
    let msg = match bincode::deserialize::<PeerExchangeMsg>(data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Malformed peer-exchange message: {}", e);
            return PeerExchangeOutcome {
                malformed: true,
                announced_tip: None,
                serve_from_tip: None,
            };
        }
    };

    // Catch a peer that upgraded (or downgraded) while we keep running — the gap join-time
    // `peer_version_warning` cannot see (#109).
    if let Some(warning) = foreign_version_warning(&msg.version, OUR_VERSION, warned_versions) {
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

fn best_blocksync_peer(
    peer_tips: &HashMap<PeerId, u64>,
    our_tip: u64,
    cooldown: &HashMap<PeerId, u32>,
) -> Option<(PeerId, u64)> {
    peer_tips
        .iter()
        .filter(|(peer, &tip)| tip > our_tip && !cooldown.contains_key(*peer))
        .max_by_key(|(_, &tip)| tip)
        .map(|(peer, &tip)| (*peer, tip))
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
) {
    let msg = PeerExchangeMsg {
        peers: known_addrs.iter().cloned().collect(),
        version: OUR_VERSION.to_string(),
        tip_height,
    };
    if let Ok(data) = bincode::serialize(&msg) {
        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
            debug!(err = %e, "Peer-exchange broadcast failed");
        }
    }
}

// ─── Application message handler ─────────────────────────────────────────────

/// Returns `true` if the message was malformed (i.e. the sender should be
/// charged a misbehavior strike).
async fn handle_app_message(topic: &str, data: &[u8], event_tx: &mpsc::Sender<P2PEvent>) -> bool {
    if topic == TOPIC_BLOCKS {
        match bincode::deserialize::<Proposal>(data) {
            Ok(proposal) => {
                debug!(height = proposal.block.height(), round = proposal.round, "Proposal from peer");
                let _ = event_tx.send(P2PEvent::NewProposal(proposal)).await;
                false
            }
            Err(e) => {
                warn!("Invalid proposal from peer: {}", e);
                true
            }
        }
    } else if topic == TOPIC_TRANSACTIONS {
        match bincode::deserialize::<Transaction>(data) {
            Ok(tx) => {
                let _ = event_tx.send(P2PEvent::NewTransaction(tx)).await;
                false
            }
            Err(e) => {
                warn!("Invalid tx from peer: {}", e);
                true
            }
        }
    } else if topic == TOPIC_VOTES {
        match bincode::deserialize::<Vote>(data) {
            Ok(vote) => {
                let _ = event_tx.send(P2PEvent::NewVote(vote)).await;
                false
            }
            Err(e) => {
                warn!("Invalid vote from peer: {}", e);
                true
            }
        }
    } else if topic == TOPIC_COMMITTED_BLOCKS {
        match bincode::deserialize::<(Block, Vec<Vote>)>(data) {
            Ok((block, commit)) => {
                debug!(height = block.height(), commit_sigs = commit.len(), "Committed block from peer");
                let _ = event_tx.send(P2PEvent::NewCommittedBlock(block, commit)).await;
                false
            }
            Err(e) => {
                warn!("Invalid committed block from peer: {}", e);
                true
            }
        }
    } else {
        false
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
        foreign_version_warning, select_new_addrs, should_serve_catchup, MAX_CATCHUP_SERVE_BLOCKS,
        MAX_KNOWN_PEER_ADDRS,
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

        let (chosen, _) = super::best_blocksync_peer(&tips, 100, &no_cooldown()).unwrap();
        assert_eq!(chosen, peer(1), "precondition: the highest tip wins when nobody is penalised");

        let cooling: std::collections::HashMap<_, _> = [(peer(1), 5)].into_iter().collect();
        let (chosen, tip) = super::best_blocksync_peer(&tips, 100, &cooling).unwrap();
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

        assert!(super::best_blocksync_peer(&tips, 100, &cooling).is_none());

        // One tick later peer(2) has served its penalty — the driver's `retain` drops it at zero.
        let cooling: std::collections::HashMap<_, _> = [(peer(1), 4)].into_iter().collect();
        let (chosen, _) = super::best_blocksync_peer(&tips, 100, &cooling).unwrap();
        assert_eq!(chosen, peer(2), "catch-up has to resume on its own, without a reconnect");
    }

    /// Nobody ahead of us is the healthy steady state, and it must produce no request at all —
    /// otherwise every node in a synced network would poll its peers forever.
    #[test]
    fn no_peer_ahead_means_no_request() {
        let mut tips = std::collections::HashMap::new();
        tips.insert(peer(1), 100);
        tips.insert(peer(2), 99);
        assert!(super::best_blocksync_peer(&tips, 100, &no_cooldown()).is_none());
    }

    #[test]
    fn the_peer_with_the_highest_tip_is_chosen() {
        let mut tips = std::collections::HashMap::new();
        tips.insert(peer(1), 105);
        tips.insert(peer(2), 130);
        tips.insert(peer(3), 90); // behind us — must not be picked
        let (chosen, tip) = super::best_blocksync_peer(&tips, 100, &no_cooldown()).unwrap();
        assert_eq!(chosen, peer(2));
        assert_eq!(tip, 130);
    }

    #[test]
    fn with_no_known_peers_there_is_nobody_to_ask() {
        assert!(super::best_blocksync_peer(&std::collections::HashMap::new(), 0, &no_cooldown()).is_none());
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
