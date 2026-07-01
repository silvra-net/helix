use anyhow::Result;
use tracing::info;

mod node;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("helix=info".parse()?),
        )
        .init();

    info!("╔══════════════════════════════════════════╗");
    info!("║       Helix Node v{}                 ║", env!("CARGO_PKG_VERSION"));
    info!("║   Quantum-Secure Blockchain  •  HLX      ║");
    info!("║   Crypto: ML-DSA (NIST PQC Dilithium3)   ║");
    info!("╚══════════════════════════════════════════╝");

    let node = node::HelixNode::new().await?;
    node.run().await
}
