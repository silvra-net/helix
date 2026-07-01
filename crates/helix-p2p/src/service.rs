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

use helix_core::{Block, Transaction};

use crate::config::P2PConfig;
use crate::{P2PError, P2PResult, TOPIC_BLOCKS, TOPIC_TRANSACTIONS};

/// Events received FROM the P2P network → node
#[derive(Debug)]
pub enum P2PEvent {
    NewBlock(Block),
    NewTransaction(Transaction),
    PeerConnected(String),
    PeerDisconnected(String),
}

/// Commands sent TO the P2P network FROM the node
#[derive(Debug)]
pub enum P2PCommand {
    BroadcastBlock(Block),
    BroadcastTransaction(Transaction),
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

    pub async fn run(mut self) -> P2PResult<()> {
        let max_msg_size = self.config.max_message_size;

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

                // Return behaviour directly — identity TryInto makes with_behaviour infallible
                HelixBehaviour { gossipsub, mdns }
            })
            .expect("behaviour setup never fails")
            .build();

        let block_topic = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
        let tx_topic = gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS);
        swarm.behaviour_mut().gossipsub.subscribe(&block_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;
        swarm.behaviour_mut().gossipsub.subscribe(&tx_topic)
            .map_err(|e| P2PError::Gossipsub(e.to_string()))?;

        let listen_addr: Multiaddr = format!(
            "/ip4/{}/tcp/{}",
            self.config.listen_addr.ip(),
            self.config.listen_addr.port()
        )
        .parse()
        .map_err(|e: libp2p::multiaddr::Error| P2PError::Transport(e.to_string()))?;

        swarm.listen_on(listen_addr)
            .map_err(|e| P2PError::Transport(e.to_string()))?;

        for peer_addr in &self.config.seed_peers {
            if let Ok(addr) = peer_addr.parse::<Multiaddr>() {
                let _ = swarm.dial(addr);
            }
        }

        info!(listen = %self.config.listen_addr, "P2P service started");

        loop {
            tokio::select! {
                event = swarm.next() => {
                    let Some(event) = event else { break };
                    match event {
                        SwarmEvent::Behaviour(HelixBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { message, .. }
                        )) => {
                            self.handle_gossipsub_message(message).await;
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
                            info!(peer = %peer_id, "Peer connected");
                            let _ = self.event_tx.send(P2PEvent::PeerConnected(peer_id.to_string())).await;
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            debug!(peer = %peer_id, "Peer disconnected");
                            let _ = self.event_tx.send(P2PEvent::PeerDisconnected(peer_id.to_string())).await;
                        }
                        _ => {}
                    }
                }

                Some(cmd) = self.command_rx.recv() => {
                    match cmd {
                        P2PCommand::BroadcastBlock(block) => {
                            if let Ok(data) = bincode::serialize(&block) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub
                                    .publish(block_topic.clone(), data)
                                {
                                    debug!("Block broadcast: {}", e);
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
                        P2PCommand::ConnectPeer(addr) => {
                            let _ = swarm.dial(addr);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_gossipsub_message(&self, message: gossipsub::Message) {
        let topic = message.topic.as_str();
        if topic == TOPIC_BLOCKS {
            match bincode::deserialize::<Block>(&message.data) {
                Ok(block) => {
                    debug!(height = block.height(), "Block from peer");
                    let _ = self.event_tx.send(P2PEvent::NewBlock(block)).await;
                }
                Err(e) => warn!("Invalid block from peer: {}", e),
            }
        } else if topic == TOPIC_TRANSACTIONS {
            match bincode::deserialize::<Transaction>(&message.data) {
                Ok(tx) => {
                    let _ = self.event_tx.send(P2PEvent::NewTransaction(tx)).await;
                }
                Err(e) => warn!("Invalid tx from peer: {}", e),
            }
        }
    }
}
