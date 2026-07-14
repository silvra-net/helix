use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct P2PConfig {
    /// Address to listen on for incoming P2P connections
    pub listen_addr: SocketAddr,
    /// Optional seed peers to connect to on startup
    pub seed_peers: Vec<String>,
    /// This node's own externally-dialable multiaddr (e.g.
    /// `/dns4/helix.silvra.net/tcp/8546`), if known — announced to peers via peer
    /// exchange (`crate::service`'s `TOPIC_PEER_EXCHANGE`) so a node connecting only to
    /// this one can still be told about, and directly dial, every other peer this node
    /// knows about. `None` when this node has no known-public address (e.g. behind NAT
    /// with no port forwarding, or a pure follower with no configured public host) —
    /// it still relays addresses it learns from others, it just never announces itself.
    pub public_addr: Option<String>,
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
    /// Whether to run mDNS LAN peer auto-discovery. On by default (zero-config peering
    /// for nodes on the same network). Turn it OFF for deterministic peering that relies
    /// only on `seed_peers` + peer exchange — required when two *independent* Helix
    /// networks share a LAN (e.g. a local integration test running alongside a live
    /// production node), where mDNS would otherwise cross-wire them: each network's nodes
    /// would discover the other's, gossip incompatible-height proposals/votes/committed
    /// blocks at each other, and trigger endless futile catch-up-sync churn.
    pub enable_mdns: bool,
}

impl Default for P2PConfig {
    fn default() -> Self {
        P2PConfig {
            listen_addr: "0.0.0.0:8546".parse().unwrap(),
            seed_peers: vec![],
            public_addr: None,
            max_peers: 50,
            max_message_size: 4 * 1024 * 1024, // 4 MB — fits a full block
            max_established_incoming: 40,
            max_pending_incoming: 64,
            max_established_per_peer: 4,
            max_connections_per_ip: 8,
            enable_mdns: true,
        }
    }
}
