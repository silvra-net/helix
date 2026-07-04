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
use helix_core::Transaction;

use crate::config::P2PConfig;
use crate::session::{HandshakeMsg, SessionManager};
use crate::{P2PError, P2PResult, TOPIC_BLOCKS, TOPIC_SESSION, TOPIC_TRANSACTIONS, TOPIC_VOTES};

/// Events received FROM the P2P network → node
#[derive(Debug)]
pub enum P2PEvent {
    NewProposal(Proposal),
    NewTransaction(Transaction),
    NewVote(Vote),
    PeerConnected(String),
    PeerDisconnected(String),
}

/// Commands sent TO the P2P network FROM the node
#[derive(Debug)]
pub enum P2PCommand {
    BroadcastProposal(Proposal),
    BroadcastTransaction(Transaction),
    BroadcastVote(Vote),
    ConnectPeer(Multiaddr),
}

#[derive(NetworkBehaviour)]
struct HelixBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
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

                HelixBehaviour { gossipsub, mdns }
            })
            .expect("behaviour setup never fails")
            .build();

        let local_peer_id = swarm.local_peer_id().to_string();

        let block_topic = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
        let tx_topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);
        let vote_topic = gossipsub::IdentTopic::new(TOPIC_VOTES);
        let session_topic = gossipsub::IdentTopic::new(TOPIC_SESSION);

        swarm.behaviour_mut().gossipsub.subscribe(&block_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&tx_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&vote_topic)
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

        loop {
            tokio::select! {
                event = swarm.next() => {
                    let Some(event) = event else { break };
                    match event {
                        SwarmEvent::Behaviour(HelixBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { message, .. }
                        )) => {
                            let topic = message.topic.as_str();

                            if topic == TOPIC_SESSION {
                                handle_session_message(
                                    &message.data,
                                    &local_peer_id,
                                    &mut session,
                                    &mut swarm,
                                    &session_topic,
                                );
                            } else {
                                handle_app_message(topic, &message.data, &event_tx).await;
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
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            info!(peer = %peer_id, "Peer connected — initiating ML-KEM handshake");
                            let peer_str = peer_id.to_string();

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

// ─── Session handshake handler ───────────────────────────────────────────────

fn handle_session_message(
    data: &[u8],
    local_peer_id: &str,
    session: &mut SessionManager,
    swarm: &mut libp2p::Swarm<HelixBehaviour>,
    session_topic: &gossipsub::IdentTopic,
) {
    let msg = match bincode::deserialize::<HandshakeMsg>(data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Malformed session message: {}", e);
            return;
        }
    };

    // Messages are broadcast; only process those addressed to us
    if msg.to_peer() != local_peer_id {
        return;
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
        }
        HandshakeMsg::KemCt { from, ct, .. } => {
            // We are the initiator: complete the handshake
            if session.complete(&from, &ct) {
                info!(peer = %from, "ML-KEM session established (initiator)");
            } else {
                warn!(peer = %from, "ML-KEM KemCt completion failed");
            }
        }
    }
}

// ─── Application message handler ─────────────────────────────────────────────

async fn handle_app_message(topic: &str, data: &[u8], event_tx: &mpsc::Sender<P2PEvent>) {
    if topic == TOPIC_BLOCKS {
        match bincode::deserialize::<Proposal>(data) {
            Ok(proposal) => {
                debug!(height = proposal.block.height(), round = proposal.round, "Proposal from peer");
                let _ = event_tx.send(P2PEvent::NewProposal(proposal)).await;
            }
            Err(e) => warn!("Invalid proposal from peer: {}", e),
        }
    } else if topic == TOPIC_TRANSACTIONS {
        match bincode::deserialize::<Transaction>(data) {
            Ok(tx) => {
                let _ = event_tx.send(P2PEvent::NewTransaction(tx)).await;
            }
            Err(e) => warn!("Invalid tx from peer: {}", e),
        }
    } else if topic == TOPIC_VOTES {
        match bincode::deserialize::<Vote>(data) {
            Ok(vote) => {
                let _ = event_tx.send(P2PEvent::NewVote(vote)).await;
            }
            Err(e) => warn!("Invalid vote from peer: {}", e),
        }
    }
}
