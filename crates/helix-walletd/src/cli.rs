//! How the wallet RPC runs: inside the node (`helix start` with `HELIX_WALLET_RPC`, the simple
//! way — one process, like `bitcoind`), or on its own against a node (`helix wallet-rpc`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::daemon::{Daemon, Options};
use crate::keys::Keys;
use crate::node::Node;
use crate::server::{router, Auth};

/// `helix wallet-rpc …` — the wallet RPC as its own process, against a node elsewhere.
#[derive(clap::Subcommand)]
pub enum Command {
    /// Make a new wallet. It starts at the node's current height.
    Init {
        /// The wallet's directory: keys, the issued-address log, the ledger.
        #[arg(long, env = "HELIX_WALLET_DIR", default_value = "helix-wallet")]
        wallet_dir: PathBuf,
        /// Encrypt every key under the passphrase in this file (one trailing newline is ignored).
        /// Without it the keys are stored unencrypted, readable by their owner only.
        #[arg(long, env = "HELIX_WALLET_PASSPHRASE_FILE")]
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
        #[arg(long, env = "HELIX_WALLET_DIR", default_value = "helix-wallet")]
        wallet_dir: PathBuf,
        #[arg(long, env = "HELIX_WALLET_RPC", default_value = "127.0.0.1:8547")]
        listen: SocketAddr,
        /// A user for Basic authentication, with --rpcpassword-file. The cookie in
        /// `<wallet-dir>/.cookie`, written at every start as Bitcoin Core does, works either way.
        #[arg(long, env = "HELIX_WALLET_RPC_USER", requires = "rpcpassword_file")]
        rpcuser: Option<String>,
        #[arg(long, env = "HELIX_WALLET_RPC_PASSWORD_FILE", requires = "rpcuser")]
        rpcpassword_file: Option<PathBuf>,
        /// Sweep a deposit address to the hot address once it holds at least this many HLX.
        #[arg(long, default_value = "0.0001")]
        sweep_min: String,
        /// Addresses an encrypted wallet makes ahead, to hand out while it is locked.
        #[arg(long, default_value_t = 100)]
        keypool: usize,
    },
}

/// Everything the wallet RPC needs to run, read and checked before anything starts.
#[derive(Clone)]
pub struct Settings {
    pub listen: SocketAddr,
    pub wallet_dir: PathBuf,
    /// `user:password` for Basic authentication, besides the cookie.
    pub credentials: Option<String>,
    /// Encrypts a wallet made on first start; unused once the wallet exists.
    pub passphrase: Option<String>,
    pub network: String,
    pub options: Options,
}

/// A secret from a file: its contents, less one trailing newline. Never an argument or a variable,
/// which stand in the shell history and in process listings (#227).
pub fn read_secret(path: &Path) -> Result<String> {
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

/// Serve the wallet RPC over `node` until the process ends.
async fn serve(node: Node, settings: Settings) -> Result<()> {
    let daemon = Arc::new(Daemon::open(&settings.wallet_dir, node, settings.options.clone()).await?);
    let mut pairs = vec![write_cookie(&settings.wallet_dir)?];
    pairs.extend(settings.credentials.clone());
    let background = daemon.clone();
    tokio::spawn(async move {
        loop {
            background.tick().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    let listener = tokio::net::TcpListener::bind(settings.listen)
        .await
        .with_context(|| format!("the wallet RPC could not listen on {}", settings.listen))?;
    if !settings.listen.ip().is_loopback() {
        tracing::warn!(listen = %settings.listen, "the wallet RPC listens beyond this machine — keep it behind a firewall");
    }
    tracing::info!(listen = %settings.listen, hot = %daemon.hot_address(), dir = %settings.wallet_dir.display(), "Wallet RPC ready");
    axum::serve(listener, router(daemon, Auth::new(pairs))).await?;
    Ok(())
}

/// The wallet RPC inside the node: `routes` are this node's own RPC routes, called in-process.
/// A wallet is made on the first start (encrypted if a passphrase was given), at the node's
/// current height, for the chain this node is on.
pub async fn serve_in_process(routes: axum::Router, settings: Settings) -> Result<()> {
    let node = Node::in_process(routes);
    if !settings.wallet_dir.join("wallet.json").exists() {
        let genesis = node.header(0).await.context("reading this node's genesis block")?.hash;
        let height = node.status().await?.height;
        let keys = Keys::create(&settings.wallet_dir, &settings.network, &genesis, height, settings.passphrase.as_deref())?;
        tracing::info!(
            dir = %settings.wallet_dir.display(),
            hot = %keys.meta.hot_address,
            encrypted = keys.meta.encrypted,
            starts_at = height,
            "Made a new wallet for the wallet RPC — back up its directory"
        );
        if !keys.meta.encrypted {
            tracing::warn!("the wallet's keys are not encrypted — set HELIX_WALLET_PASSPHRASE_FILE when making a wallet that holds real funds");
        }
    }
    serve(node, settings).await
}

/// `helix wallet-rpc …` against the node at `node_url`.
pub async fn run(node_url: &str, command: Command) -> Result<()> {
    match command {
        Command::Init { wallet_dir, passphrase_file, network, chain_id } => {
            let node = Node::new(node_url);
            let genesis = node.header(0).await.context("could not read the node's genesis block")?.hash;
            let expected = chain_id.unwrap_or_else(|| helix_core::DEFAULT_GENESIS_HASH.to_string());
            if genesis != expected {
                bail!(
                    "the node at {node_url} is on the chain with genesis {genesis}, not {expected} — \
                     pass --chain-id {genesis} if that is the chain this wallet is for"
                );
            }
            let height = node.status().await?.height;
            let passphrase = passphrase_file.as_deref().map(read_secret).transpose()?;
            let keys = Keys::create(&wallet_dir, &network, &genesis, height, passphrase.as_deref())?;
            println!("Wallet made in {}", wallet_dir.display());
            println!("  Chain       : {genesis}");
            println!("  Starts at   : block {height}");
            println!("  Hot address : {}", keys.meta.hot_address);
            println!("  Encrypted   : {}", if keys.meta.encrypted { "yes" } else { "no" });
            println!("Back up the whole directory, or call backupwallet after handing out addresses.");
            Ok(())
        }
        Command::Serve { wallet_dir, listen, rpcuser, rpcpassword_file, sweep_min, keypool } => {
            let sweep_min = helix_core::fee::parse_hlx(&sweep_min).map_err(|e| anyhow::anyhow!("--sweep-min: {e}"))?;
            let credentials = match (rpcuser, rpcpassword_file) {
                (Some(user), Some(file)) => Some(format!("{user}:{}", read_secret(&file)?)),
                _ => None,
            };
            let settings = Settings {
                listen,
                wallet_dir,
                credentials,
                passphrase: None,
                network: "test".into(),
                options: Options { sweep_min, keypool, ..Options::default() },
            };
            serve(Node::new(node_url), settings).await
        }
    }
}
