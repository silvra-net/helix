//! `helix mesh` — the Mesh (formerly Rosetta) Data API, served in front of a node.

use std::net::SocketAddr;

/// Serve the Mesh (Rosetta) Data API in front of a node.
#[derive(clap::Args)]
pub struct Args {
    /// Where to serve the Mesh API.
    #[arg(long, env = "HELIX_MESH_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,
    /// The network name in every network identifier (the blockchain is "Helix").
    #[arg(long, env = "HELIX_MESH_NETWORK", default_value = "testnet")]
    pub network: String,
}

/// Serve until the process ends, reading the node at `node_url` — one that executed every block
/// itself with 0.20.2 or later (see the crate documentation).
pub async fn serve(node_url: &str, args: Args) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(listen = %args.listen, node = %node_url, network = %args.network, "Serving the Mesh Data API");
    axum::serve(listener, crate::router(node_url, &args.network)).await?;
    Ok(())
}
