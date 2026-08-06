use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

mod config;
mod local_node;
mod node;
mod run_record;
mod signing_guard;

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
    /// Node RPC endpoint for client subcommands. Unset, a node running on this machine is used if
    /// one answers, and the public Helix network otherwise — so a freshly downloaded binary works
    /// against the live chain out of the box, and running your own node is enough to be asked.
    /// Ignored by `helix start`, which configures itself from the environment / `helix.toml`.
    ///
    /// No `default_value` on purpose: with one, "the operator asked for the public network" and
    /// "the operator asked for nothing" are the same string, and their own node could never be
    /// preferred without overriding a choice they might have made deliberately.
    #[arg(long, global = true, env = "HELIX_NODE")]
    node: Option<String>,

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
            let chosen = resolve_client_node(cli.node.as_deref()).await;
            helix_cli::run(chosen.url(), command).await
        }
    }
}

/// Pick the node a client subcommand talks to, and say so when it is not the obvious one.
///
/// Probes only when the operator named nothing, so nobody pays for a lookup they already answered.
/// The note goes to stderr: stdout is what gets piped into `jq`, and telling someone which node
/// replied must not change what their script parses.
async fn resolve_client_node(explicit: Option<&str>) -> local_node::Chosen {
    if let Some(url) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return local_node::choose(Some(url), None);
    }

    // The same address the node itself binds, so the two agree on where "your node" is even when an
    // operator moved it — asking a hardcoded port would find nothing and quietly use ours instead.
    // A malformed helix.toml must not stop a wallet command — fall back to the default port and
    // let the daemon be the one that complains about its own config.
    let local_url = config::load_node_config()
        .map(|cfg| local_rpc_url(&cfg))
        .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());

    match local_node::probe(&local_url).await {
        Some(status) => {
            eprintln!("Using your local node at {local_url}");
            if let Some(note) = local_node::local_note(&status) {
                eprintln!("{note}");
            }
            local_node::choose(None, Some(&local_url))
        }
        None => local_node::choose(None, None),
    }
}

/// Where a node on this machine would be listening, from the same config the daemon reads.
///
/// A bind address of `0.0.0.0` means "every interface", which is not an address to connect *to* —
/// loopback is the one that always reaches a locally bound socket.
fn local_rpc_url(cfg: &config::NodeConfig) -> String {
    let port = config::resolve("HELIX_RPC_BIND", &cfg.rpc_bind)
        .and_then(|s| s.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()))
        .unwrap_or(8545);
    format!("http://127.0.0.1:{port}")
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
