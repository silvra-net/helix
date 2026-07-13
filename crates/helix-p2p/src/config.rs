use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct P2PConfig {
    /// Address to listen on for incoming P2P connections
    pub listen_addr: SocketAddr,
    /// Optional seed peers to connect to on startup
    pub seed_peers: Vec<String>,
    /// Maximum number of established connections (incoming + outgoing combined).
    /// Enforced at the transport layer via `libp2p::connection_limits` — was
    /// previously declared but never wired up (see `helix-p2p::service`).
    pub max_peers: usize,
    /// Gossipsub message size limit (bytes)
    pub max_message_size: usize,
    /// Maximum established *incoming* connections. Kept below `max_peers` so a
    /// flood of inbound dials can't crowd out the node's own outbound peer
    /// connections (see the libp2p connection_limits eclipse-attack note).
    pub max_established_incoming: u32,
    /// Maximum concurrent connections still mid-handshake (dialed but not yet
    /// authenticated). Bounds resource use from connection floods that never
    /// complete the handshake, independent of the established-connection caps.
    pub max_pending_incoming: u32,
    /// Maximum established connections to a single peer ID.
    pub max_established_per_peer: u32,
    /// Maximum concurrent connections (pending + established) from a single
    /// remote IP address, regardless of how many distinct peer IDs it presents.
    /// `libp2p::connection_limits` has no per-IP notion — enforced by our own
    /// `conn_limits::IpConnLimiter` behaviour instead.
    pub max_connections_per_ip: u32,
}

impl Default for P2PConfig {
    fn default() -> Self {
        P2PConfig {
            listen_addr: "0.0.0.0:8546".parse().unwrap(),
            seed_peers: vec![],
            max_peers: 50,
            max_message_size: 4 * 1024 * 1024, // 4 MB — fits a full block
            max_established_incoming: 40,
            max_pending_incoming: 64,
            max_established_per_peer: 4,
            max_connections_per_ip: 8,
        }
    }
}
