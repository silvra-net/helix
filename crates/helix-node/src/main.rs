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
    /// Run the node daemon (block production, P2P, RPC server). With `HELIX_WALLET_RPC` set it
    /// also serves a Bitcoin-Core-style wallet RPC for exchanges, in the same process.
    Start,
    /// A Bitcoin-Core-style wallet RPC for exchanges, as its own process against a node — or,
    /// simpler, inside the node itself (`HELIX_WALLET_RPC=127.0.0.1:8547 helix start`)
    #[command(name = "wallet-rpc", subcommand)]
    WalletRpc(helix_walletd::cli::Command),
    /// The Mesh (Rosetta) Data API, in front of a node
    Mesh(helix_mesh::cli::Args),
    /// Call the wallet RPC as bitcoin-cli calls Bitcoin Core (`helix rpc getbalance`). The same
    /// binary under the name `helix-cli` — a link to it — is this command.
    #[command(disable_help_flag = true)]
    Rpc {
        /// bitcoin-cli's options (-rpcport=…, -datadir=…, -named, -stdin …), the method, its
        /// parameters. `helix rpc -help` lists them.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<String>,
    },
    /// Client subcommands (wallet, tx, chain, …) — flattened in at the top level
    #[command(flatten)]
    Client(helix_cli::Commands),
}

/// Whether this binary was started as `helix-cli` — a link to it, as bitcoin-cli is to scripts
/// that call it by that name.
fn invoked_as_helix_cli() -> bool {
    std::env::args_os()
        .next()
        .and_then(|program| std::path::Path::new(&program).file_stem().map(|s| s == "helix-cli"))
        .unwrap_or(false)
}

#[tokio::main]
async fn main() -> Result<()> {
    if invoked_as_helix_cli() {
        std::process::exit(helix_walletd::client::main(std::env::args().skip(1).collect()).await);
    }
    let cli = Cli::parse();
    match cli.command {
        Command::Start => run_node().await,
        Command::Rpc { args } => std::process::exit(helix_walletd::client::main(args).await),
        // A service for an exchange's own node: never the public network as a fallback — a
        // hot wallet quietly running against someone else's node is not a default.
        Command::WalletRpc(command) => {
            init_service_logging()?;
            helix_walletd::cli::run(&own_node_url(cli.node.as_deref()), command).await
        }
        Command::Mesh(args) => {
            init_service_logging()?;
            helix_mesh::cli::serve(&own_node_url(cli.node.as_deref()), args).await
        }
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

/// The node a service subcommand reads: `--node`, else this machine's node — never the public
/// network, which is the client subcommands' fallback and the wrong one for a wallet.
fn own_node_url(explicit: Option<&str>) -> String {
    match explicit.map(str::trim).filter(|s| !s.is_empty()) {
        Some(url) => url.to_string(),
        None => config::load_node_config()
            .map(|cfg| local_rpc_url(&cfg))
            .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string()),
    }
}

fn init_service_logging() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A wallet or Mesh service named no node: it reads this machine's, never the public network —
    /// the client subcommands' fallback, and the wrong one for an exchange's hot wallet.
    #[test]
    fn a_service_without_a_node_named_reads_this_machines_node() {
        assert_eq!(own_node_url(Some(" http://10.0.0.5:8545 ")), "http://10.0.0.5:8545");
        for unnamed in [None, Some(""), Some("  ")] {
            let url = own_node_url(unnamed);
            assert!(url.starts_with("http://127.0.0.1:"), "{unnamed:?} gave {url}");
            assert!(!url.contains(helix_core::DEFAULT_SEED_PEER.trim_start_matches("https://")), "{url}");
        }
    }
}
