use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

mod config;
mod node;

/// Helix — one binary for everything. `helix start` runs the node daemon; every other
/// subcommand (`wallet`, `tx`, `chain`, …) is a thin RPC client against a node, defaulting
/// to the public network so a freshly downloaded binary works out of the box.
#[derive(Parser)]
#[command(
    name = "helix",
    about = "Helix — quantum-secure blockchain node and client",
    version,
    long_about = "Helix (HLX) — a quantum-secure Layer-1 blockchain.\n\n\
                  Run `helix start` to operate a node. Use `helix wallet`, `helix tx`, \
                  `helix chain`, etc. to manage keys and interact with the chain over RPC."
)]
struct Cli {
    /// Node RPC endpoint for client subcommands. Defaults to the public Helix network, so a
    /// freshly downloaded binary works against the live chain out of the box. Point it at
    /// `http://127.0.0.1:8545` (or set `HELIX_NODE`) to talk to your own local node instead.
    /// Ignored by `helix start`, which configures itself from the environment / `helix.toml`.
    #[arg(long, global = true, env = "HELIX_NODE", default_value = "https://helix.silvra.net")]
    node: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the node daemon (block production, P2P, RPC server)
    Start,
    /// Client subcommands (wallet, tx, chain, …) — flattened in at the top level
    #[command(flatten)]
    Client(helix_cli::Commands),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Start => run_node().await,
        Command::Client(command) => {
            let node = cli.node.trim_end_matches('/').to_string();
            helix_cli::run(&node, command).await
        }
    }
}

/// Boot and run the node daemon. Only this path initialises tracing and reads the node's
/// environment/`helix.toml` config — client subcommands print plain output and never open
/// the chain database.
async fn run_node() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("helix=info".parse()?),
        )
        .init();

    info!("╔══════════════════════════════════════════╗");
    info!("║       Helix Node v{}                 ║", env!("CARGO_PKG_VERSION"));
    info!("║   Quantum-Secure Blockchain  •  HLX      ║");
    info!("║   Crypto: ML-DSA-65 (NIST FIPS 204)      ║");
    info!("╚══════════════════════════════════════════╝");

    let node = node::HelixNode::new().await?;
    node.run().await
}
