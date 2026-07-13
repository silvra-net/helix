use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use libp2p::{
    futures::StreamExt,
    gossipsub, mdns,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, SwarmBuilder,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use helix_consensus::{Proposal, Vote};
use helix_core::{Block, Transaction};

use crate::config::P2PConfig;
use crate::conn_limits::IpConnLimiter;
use crate::reputation::PeerReputation;
use crate::session::{HandshakeMsg, SessionManager};
use crate::{P2PError, P2PResult, TOPIC_BLOCKS, TOPIC_COMMITTED_BLOCKS, TOPIC_SESSION, TOPIC_TRANSACTIONS, TOPIC_VOTES};

/// Events received FROM the P2P network → node
#[derive(Debug)]
pub enum P2PEvent {
    NewProposal(Proposal),
    NewTransaction(Transaction),
    NewVote(Vote),
    /// A peer broadcast a committed block (already past BFT quorum).
    /// The receiving node can apply it directly after verifying the proposer signature.
    NewCommittedBlock(Block),
    PeerConnected(String),
    PeerDisconnected(String),
}

/// Commands sent TO the P2P network FROM the node
#[derive(Debug)]
pub enum P2PCommand {
    BroadcastProposal(Proposal),
    BroadcastTransaction(Transaction),
    BroadcastVote(Vote),
    /// Broadcast a committed block to help lagging peers catch up.
    BroadcastBlock(Block),
    ConnectPeer(Multiaddr),
}

#[derive(NetworkBehaviour)]
struct HelixBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    /// Global/pending/per-peer connection caps (backlog #44) — a connection flood
    /// (real or Sybil, distinct `PeerId` per socket) can't grow the swarm's
    /// established/pending connection tables past these bounds.
    connection_limits: libp2p::connection_limits::Behaviour,
    /// Per-source-IP connection cap (backlog #44) — `connection_limits` above has
    /// no notion of IP, so a Sybil attacker presenting a fresh `PeerId` per socket
    /// isn't bounded by it; this closes that gap.
    ip_limits: IpConnLimiter,
}

pub struct P2PService {
    config: P2PConfig,
    event_tx: mpsc::Sender<P2PEvent>,
    command_rx: mpsc::Receiver<P2PCommand>,
}

impl P2PService {
    pub fn new(config: P2PConfig) -> (Self, mpsc::Sender<P2PCommand>, mpsc::Receiver<P2PEvent>) {
        let (event_tx, event_rx) = mpsc::channel(256);
        let (command_tx, command_rx) = mpsc::channel(256);
        (
            P2PService { config, event_tx, command_rx },
            command_tx,
            event_rx,
        )
    }

    pub async fn run(self) -> P2PResult<()> {
        // Destructure so we can move fields into the loop without borrowing `self`
        let event_tx = self.event_tx;
        let mut command_rx = self.command_rx;
        let config = self.config;

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
            .with_behaviour(|key| {
                let message_id_fn = |msg: &gossipsub::Message| {
                    let mut hasher = DefaultHasher::new();
                    msg.data.hash(&mut hasher);
                    gossipsub::MessageId::from(hasher.finish().to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(10))
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

                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )
                .expect("mdns behaviour is valid");

                let connection_limits = libp2p::connection_limits::Behaviour::new(
                    libp2p::connection_limits::ConnectionLimits::default()
                        .with_max_established(Some(config.max_peers as u32))
                        .with_max_established_incoming(Some(config.max_established_incoming))
                        .with_max_pending_incoming(Some(config.max_pending_incoming))
                        .with_max_established_per_peer(Some(config.max_established_per_peer)),
                );
                let ip_limits = IpConnLimiter::new(config.max_connections_per_ip);

                HelixBehaviour { gossipsub, mdns, connection_limits, ip_limits }
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
        let session_topic = gossipsub::IdentTopic::new(TOPIC_SESSION);

        swarm.behaviour_mut().gossipsub.subscribe(&block_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&tx_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&vote_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&committed_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&session_topic)
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

        for peer_addr in &config.seed_peers {
            if let Ok(addr) = peer_addr.parse::<Multiaddr>() {
                let _ = swarm.dial(addr);
            }
        }

        info!(listen = %config.listen_addr, peer_id = %local_peer_id, "P2P service started");

        // ML-KEM session manager — maintains per-peer post-quantum session keys
        let mut session = SessionManager::new();

        // Misbehavior scoring — disconnects and refuses reconnection for peers
        // that repeatedly send malformed protocol messages.
        let mut reputation = PeerReputation::new();

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

                            let malformed = if topic == TOPIC_SESSION {
                                handle_session_message(
                                    &message.data,
                                    &local_peer_id,
                                    &peer_str,
                                    &mut session,
                                    &mut swarm,
                                    &session_topic,
                                )
                            } else {
                                handle_app_message(topic, &message.data, &event_tx).await
                            };

                            if malformed && reputation.record_infraction(&peer_str) {
                                warn!(peer = %peer_str, "peer exceeded misbehavior threshold — disconnecting");
                                let _ = swarm.disconnect_peer_id(propagation_source);
                            }
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

                            info!(peer = %peer_id, "Peer connected — initiating ML-KEM handshake");

                            // Kick off the ML-KEM session handshake as initiator
                            let ek = session.initiate(&peer_str);
                            let hello = HandshakeMsg::Hello {
                                from: local_peer_id.clone(),
                                to: peer_str.clone(),
                                ek: ek.as_bytes().to_vec(),
                            };
                            if let Ok(data) = bincode::serialize(&hello) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub
                                    .publish(session_topic.clone(), data)
                                {
                                    debug!(peer = %peer_str, err = %e, "ML-KEM Hello publish failed");
                                }
                            }

                            let _ = event_tx.send(P2PEvent::PeerConnected(peer_str)).await;
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            debug!(peer = %peer_id, "Peer disconnected");
                            reputation.on_disconnect(&peer_id.to_string());
                            session.remove(&peer_id.to_string());
                            let _ = event_tx
                                .send(P2PEvent::PeerDisconnected(peer_id.to_string()))
                                .await;
                        }
                        _ => {}
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
                        P2PCommand::BroadcastBlock(block) => {
                            if let Ok(data) = bincode::serialize(&block) {
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

// ─── Session handshake handler ───────────────────────────────────────────────

/// Whether a handshake message's self-reported `from` field can be trusted — i.e. it
/// matches who actually sent it over the gossipsub connection. `from` lives inside the
/// (otherwise unauthenticated) message payload, so without this check a single connected
/// peer could broadcast Hello messages under arbitrarily many fabricated `from` values,
/// each one making `SessionManager::respond` allocate a brand-new session entry for free —
/// unbounded memory growth against consensus-critical P2P infrastructure. Requiring
/// `from == actual_sender` caps it at one handshake-driven entry per real connection.
fn message_sender_is_authentic(msg: &HandshakeMsg, actual_sender: &str) -> bool {
    msg.from_peer() == actual_sender
}

/// Returns `true` if the message was malformed (i.e. the sender should be
/// charged a misbehavior strike).
fn handle_session_message(
    data: &[u8],
    local_peer_id: &str,
    actual_sender: &str,
    session: &mut SessionManager,
    swarm: &mut libp2p::Swarm<HelixBehaviour>,
    session_topic: &gossipsub::IdentTopic,
) -> bool {
    let msg = match bincode::deserialize::<HandshakeMsg>(data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Malformed session message: {}", e);
            return true;
        }
    };

    // Messages are broadcast; only process those addressed to us
    if msg.to_peer() != local_peer_id {
        return false;
    }

    if !message_sender_is_authentic(&msg, actual_sender) {
        warn!(
            claimed = msg.from_peer(),
            actual = actual_sender,
            "Session handshake message's `from` doesn't match the real sender — dropping"
        );
        return true;
    }

    match msg {
        HandshakeMsg::Hello { from, ek, .. } => {
            // We are the responder: encapsulate a shared secret
            if let Some(ct) = session.respond(&from, &ek) {
                let reply = HandshakeMsg::KemCt {
                    from: local_peer_id.to_string(),
                    to: from.clone(),
                    ct: ct.as_bytes().to_vec(),
                };
                if let Ok(encoded) = bincode::serialize(&reply) {
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(session_topic.clone(), encoded)
                    {
                        debug!(peer = %from, err = %e, "ML-KEM KemCt publish failed");
                    } else {
                        info!(peer = %from, "ML-KEM session established (responder)");
                    }
                }
            }
            false
        }
        HandshakeMsg::KemCt { from, ct, .. } => {
            // We are the initiator: complete the handshake
            if session.complete(&from, &ct) {
                info!(peer = %from, "ML-KEM session established (initiator)");
                false
            } else {
                warn!(peer = %from, "ML-KEM KemCt completion failed");
                true
            }
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
        match bincode::deserialize::<Block>(data) {
            Ok(block) => {
                debug!(height = block.height(), "Committed block from peer");
                let _ = event_tx.send(P2PEvent::NewCommittedBlock(block)).await;
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
mod session_auth_tests {
    use super::{message_sender_is_authentic, HandshakeMsg};

    #[test]
    fn accepts_a_hello_whose_from_matches_the_real_sender() {
        let msg = HandshakeMsg::Hello {
            from: "peer-a".to_string(),
            to: "peer-b".to_string(),
            ek: vec![],
        };
        assert!(message_sender_is_authentic(&msg, "peer-a"));
    }

    #[test]
    fn rejects_a_hello_claiming_to_be_from_someone_else() {
        // This is the exact free-fabricated-identity attack the check closes: a real,
        // connected peer ("peer-attacker") broadcasts a Hello claiming to be "peer-victim".
        let msg = HandshakeMsg::Hello {
            from: "peer-victim".to_string(),
            to: "peer-b".to_string(),
            ek: vec![],
        };
        assert!(!message_sender_is_authentic(&msg, "peer-attacker"));
    }

    #[test]
    fn rejects_a_kem_ct_claiming_to_be_from_someone_else() {
        let msg = HandshakeMsg::KemCt {
            from: "peer-victim".to_string(),
            to: "peer-b".to_string(),
            ct: vec![],
        };
        assert!(!message_sender_is_authentic(&msg, "peer-attacker"));
    }
}
