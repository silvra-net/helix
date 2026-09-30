use std::net::SocketAddr;

use clap::Parser;

/// Mesh (formerly Rosetta) Data API for Helix, reading a node's REST API.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// The Helix node to read. It must have executed the chain from genesis with a build that
    /// records balance changes — see the crate documentation.
    #[arg(long, env = "HELIX_MESH_NODE", default_value = "http://127.0.0.1:8545")]
    node: String,
    /// Where to serve the Mesh API.
    #[arg(long, env = "HELIX_MESH_LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
    /// The network name in every network identifier (the blockchain is "Helix").
    #[arg(long, env = "HELIX_MESH_NETWORK", default_value = "testnet")]
    network: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(listen = %args.listen, node = %args.node, network = %args.network, "Serving the Mesh Data API");
    axum::serve(listener, helix_mesh::router(&args.node, &args.network)).await?;
    Ok(())
}
