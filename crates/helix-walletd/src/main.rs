use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use helix_walletd::daemon::{Daemon, Options};
use helix_walletd::keys::Keys;
use helix_walletd::node::Node;
use helix_walletd::server::{router, Auth};

/// A wallet with Bitcoin Core's JSON-RPC interface, in front of a Helix node — for exchanges.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// The Helix node to read and submit through: your own, running 0.20.2 or later.
    #[arg(long, env = "HELIX_WALLETD_NODE", default_value = "http://127.0.0.1:8545", global = true)]
    node: String,
    /// The wallet's directory: keys, the issued-address log, the ledger.
    #[arg(long, env = "HELIX_WALLETD_DIR", default_value = "helix-wallet", global = true)]
    wallet_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make a new wallet. It starts at the node's current height.
    Init {
        /// Encrypt every key under the passphrase in this file (one trailing newline is ignored).
        /// Without it the keys are stored unencrypted, readable by their owner only.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// `main` or `test`: what getblockchaininfo reports as the chain.
        #[arg(long, default_value = "test")]
        network: String,
        /// The genesis hash of the chain to sign for. Defaults to the public network's, compiled
        /// into this release; the node must be on the same chain.
        #[arg(long, env = "HELIX_CHAIN_ID")]
        chain_id: Option<String>,
    },
    /// Serve the RPC.
    Serve {
        #[arg(long, env = "HELIX_WALLETD_LISTEN", default_value = "127.0.0.1:8547")]
        listen: SocketAddr,
        /// A user for Basic authentication, with --rpcpassword-file. A cookie (`.cookie` in the
        /// wallet directory, as Bitcoin Core writes it) is accepted either way.
        #[arg(long, env = "HELIX_WALLETD_RPCUSER", requires = "rpcpassword_file")]
        rpcuser: Option<String>,
        #[arg(long, requires = "rpcuser")]
        rpcpassword_file: Option<PathBuf>,
        /// Sweep a deposit address to the hot address once it holds at least this many HLX.
        #[arg(long, default_value = "0.0001")]
        sweep_min: String,
        /// Addresses an encrypted wallet makes ahead, to hand out while it is locked.
        #[arg(long, default_value_t = 100)]
        keypool: usize,
    },
}

/// A secret from a file: its contents, less one trailing newline. Never an argument, which
/// would stand in the shell history and in every process listing (#227).
fn read_secret(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path).with_context(|| format!("could not read {}", path.display()))?;
    let text = text.strip_suffix('\n').map(|t| t.strip_suffix('\r').unwrap_or(t)).unwrap_or(&text).to_string();
    if text.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(text)
}

fn write_cookie(dir: &Path) -> Result<String> {
    let secret: [u8; 32] = rand::random();
    let pair = format!("__cookie__:{}", hex::encode(secret));
    let path = dir.join(".cookie");
    let _ = std::fs::remove_file(&path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    use std::io::Write;
    options.open(&path)?.write_all(pair.as_bytes())?;
    Ok(pair)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    match args.command {
        Command::Init { passphrase_file, network, chain_id } => {
            let node = Node::new(&args.node);
            let genesis = node.header(0).await.context("could not read the node's genesis block")?.hash;
            let expected = chain_id.unwrap_or_else(|| helix_core::DEFAULT_GENESIS_HASH.to_string());
            if genesis != expected {
                bail!(
                    "the node at {} is on the chain with genesis {genesis}, not {expected} — pass \
                     --chain-id {genesis} if that is the chain this wallet is for",
                    args.node
                );
            }
            let status = node.status().await?;
            let passphrase = passphrase_file.as_deref().map(read_secret).transpose()?;
            let keys = Keys::create(&args.wallet_dir, &network, &genesis, status.height, passphrase.as_deref())?;
            println!("Wallet made in {}", args.wallet_dir.display());
            println!("  Chain       : {genesis}");
            println!("  Starts at   : block {}", status.height);
            println!("  Hot address : {}", keys.meta.hot_address);
            println!("  Encrypted   : {}", if keys.meta.encrypted { "yes" } else { "no" });
            println!("Back up the whole directory, or call backupwallet after handing out addresses.");
            Ok(())
        }
        Command::Serve { listen, rpcuser, rpcpassword_file, sweep_min, keypool } => {
            let sweep_min = helix_core::fee::parse_hlx(&sweep_min).map_err(|e| anyhow::anyhow!("--sweep-min: {e}"))?;
            let opts = Options { sweep_min, keypool, ..Options::default() };
            let daemon = Arc::new(Daemon::open(&args.wallet_dir, &args.node, opts).await?);
            let mut pairs = vec![write_cookie(&args.wallet_dir)?];
            if let (Some(user), Some(file)) = (rpcuser, rpcpassword_file) {
                pairs.push(format!("{user}:{}", read_secret(&file)?));
            }
            let background = daemon.clone();
            tokio::spawn(async move {
                loop {
                    background.tick().await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });
            let listener = tokio::net::TcpListener::bind(listen).await?;
            tracing::info!(%listen, node = %args.node, hot = %daemon.hot_address(), "serving the wallet RPC");
            axum::serve(listener, router(daemon, Auth::new(pairs))).await?;
            Ok(())
        }
    }
}
