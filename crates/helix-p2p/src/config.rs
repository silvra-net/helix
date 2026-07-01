use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct P2PConfig {
    /// Address to listen on for incoming P2P connections
    pub listen_addr: SocketAddr,
    /// Optional seed peers to connect to on startup
    pub seed_peers: Vec<String>,
    /// Maximum number of connected peers
    pub max_peers: usize,
    /// Gossipsub message size limit (bytes)
    pub max_message_size: usize,
}

impl Default for P2PConfig {
    fn default() -> Self {
        P2PConfig {
            listen_addr: "0.0.0.0:8546".parse().unwrap(),
            seed_peers: vec![],
            max_peers: 50,
            max_message_size: 4 * 1024 * 1024, // 4 MB — fits a full block
        }
    }
}
