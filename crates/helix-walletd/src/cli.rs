//! How the wallet RPC runs: inside the node (`helix start` with `server=1` in the wallet's
//! `helix.conf`, or `HELIX_WALLET_RPC` — the simple way, one process, like `bitcoind`), or on its
//! own against a node (`helix wallet-rpc`).
//!
//! **Settings come from two places, and never both for the same thing.** The node's environment
//! or `helix.toml` (`HELIX_WALLET_*`), as every other node setting; and `helix.conf` in the wallet's
//! directory, in `bitcoin.conf`'s format, where a Bitcoin-family integration writes them. A setting
//! given in both stops the start with both named: which one wins is not something an operator
//! should have to guess.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;

use crate::conf::{Conf, RpcAuth};
use crate::daemon::{Daemon, Options};
use crate::keys::Keys;
use crate::node::Node;
use crate::server::{router, Auth};

/// The network this release serves: what `getblockchaininfo` calls the chain, and which section of
/// `helix.conf` applies. The public chain is a testnet; this becomes `main` with the mainnet.
pub const NETWORK: &str = "test";

/// The wallet RPC's port when nothing names one.
pub const DEFAULT_PORT: u16 = 8547;

/// `helix wallet-rpc …` — the wallet RPC as its own process, against a node elsewhere.
#[derive(clap::Subcommand)]
pub enum Command {
    /// Make a new wallet. It starts at the node's current height.
    Init {
        /// The wallet's directory: keys, the issued-address log, the ledger, `helix.conf`.
        #[arg(long, env = "HELIX_WALLET_DIR", default_value = "helix-wallet")]
        wallet_dir: PathBuf,
        /// Encrypt every key under the passphrase in this file (one trailing newline is ignored).
        /// Without it the keys are stored unencrypted, readable by their owner only.
        #[arg(long, env = "HELIX_WALLET_PASSPHRASE_FILE")]
        passphrase_file: Option<PathBuf>,
        /// `main` or `test`: what getblockchaininfo reports as the chain.
        #[arg(long, default_value = NETWORK)]
        network: String,
        /// The genesis hash of the chain to sign for. Defaults to the public network's, compiled
        /// into this release; the node must be on the same chain.
        #[arg(long, env = "HELIX_CHAIN_ID")]
        chain_id: Option<String>,
    },
    /// Serve the RPC. Reads `helix.conf` in the wallet directory, as the node does.
    Serve {
        #[arg(long, env = "HELIX_WALLET_DIR", default_value = "helix-wallet")]
        wallet_dir: PathBuf,
        /// Where to listen. Unset: `rpcbind`/`rpcport` in helix.conf, else 127.0.0.1:8547.
        #[arg(long, env = "HELIX_WALLET_RPC")]
        listen: Option<SocketAddr>,
        /// A user for Basic authentication, with --rpcpassword-file. The cookie in
        /// `<wallet-dir>/.cookie`, written at every start as Bitcoin Core does, works either way.
        #[arg(long, env = "HELIX_WALLET_RPC_USER", requires = "rpcpassword_file")]
        rpcuser: Option<String>,
        #[arg(long, env = "HELIX_WALLET_RPC_PASSWORD_FILE", requires = "rpcuser")]
        rpcpassword_file: Option<PathBuf>,
        /// Sweep a deposit address to the hot address once it holds at least this many HLX.
        #[arg(long, default_value = "0.0001")]
        sweep_min: String,
        /// Addresses an encrypted wallet makes ahead, to hand out while it is locked (or `keypool`
        /// in helix.conf).
        #[arg(long)]
        keypool: Option<usize>,
    },
}

/// Everything the wallet RPC needs to run, read and checked before anything starts.
#[derive(Clone)]
pub struct Settings {
    pub listen: SocketAddr,
    pub wallet_dir: PathBuf,
    /// `user:password` pairs for Basic authentication, besides the cookie.
    pub credentials: Vec<String>,
    pub rpcauth: Vec<RpcAuth>,
    /// Who may connect besides this machine (`rpcallowip`).
    pub allow: Vec<IpNet>,
    pub cookie_file: PathBuf,
    /// Encrypts a wallet made on first start; unused once the wallet exists.
    pub passphrase: Option<String>,
    pub network: String,
    pub options: Options,
    /// `helix.conf`, if one was read, and the Bitcoin options in it that mean nothing here.
    pub conf: Option<PathBuf>,
    pub ignored: Vec<String>,
}

/// What the node's environment or `helix.toml` set — or `serve`'s flags.
#[derive(Debug, Default, Clone)]
pub struct Explicit {
    pub listen: Option<SocketAddr>,
    /// `user:password`.
    pub credentials: Option<String>,
    pub passphrase: Option<String>,
    pub sweep_min: Option<u64>,
    pub keypool: Option<usize>,
}

/// `rpcbind` and `rpcport` as an address to listen on.
fn bind_address(rpcbind: Option<&str>, rpcport: Option<u16>) -> Result<SocketAddr> {
    let Some(bind) = rpcbind.map(str::trim) else {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpcport.unwrap_or(DEFAULT_PORT)));
    };
    if let Ok(with_port) = bind.parse::<SocketAddr>() {
        if rpcport.is_some_and(|p| p != with_port.port()) {
            bail!("rpcbind={bind} names port {} and rpcport another — name it once", with_port.port());
        }
        return Ok(with_port);
    }
    let ip: IpAddr = bind
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .map_err(|_| anyhow::anyhow!("rpcbind={bind} is not an address to listen on"))?;
    Ok(SocketAddr::new(ip, rpcport.unwrap_or(DEFAULT_PORT)))
}

/// Settle the wallet RPC's settings: `None` when nothing asks for it. `serving` is `helix
/// wallet-rpc serve`, which serves whatever the files say.
pub fn resolve(wallet_dir: PathBuf, explicit: Explicit, network: &str, serving: bool) -> Result<Option<Settings>> {
    let conf = Conf::read(&wallet_dir, network)?;
    let enabled = serving || explicit.listen.is_some() || conf.as_ref().is_some_and(|c| c.server == Some(true));
    if !enabled {
        if let Some(c) = &conf {
            tracing::info!(path = %c.path.display(), "found, but it does not say server=1 — the wallet RPC stays off");
        }
        return Ok(None);
    }
    let conf = conf.unwrap_or_default();
    let named = || conf.path.display().to_string();

    let conf_listens = conf.rpcbind.is_some() || conf.rpcport.is_some() || (!serving && conf.server.is_some());
    let listen = match explicit.listen {
        Some(listen) if conf_listens => bail!(
            "the wallet RPC's address is set twice — HELIX_WALLET_RPC (or --listen) says {listen}, and {} sets \
             server/rpcbind/rpcport. Keep one",
            named()
        ),
        Some(listen) => listen,
        None => bind_address(conf.rpcbind.as_deref(), conf.rpcport).with_context(named)?,
    };
    if !listen.ip().is_loopback() && conf.rpcallowip.is_empty() {
        bail!(
            "the wallet RPC would listen on {listen}, beyond this machine, and nothing names who may connect — \
             add rpcallowip=<address or network> to {} (as Bitcoin Core requires), or listen on 127.0.0.1",
            wallet_dir.join(crate::conf::FILE).display()
        );
    }

    let mut credentials = Vec::new();
    match (explicit.credentials, conf.rpcuser.clone(), conf.rpcpassword.clone()) {
        (Some(_), Some(_), _) => bail!(
            "a wallet RPC user is set twice — HELIX_WALLET_RPC_USER (or --rpcuser) and rpcuser in {}. Keep one",
            named()
        ),
        (Some(pair), None, _) => credentials.push(pair),
        (None, Some(user), Some(password)) => credentials.push(format!("{user}:{password}")),
        _ => {}
    }

    let keypool = match (explicit.keypool, conf.keypool) {
        (Some(_), Some(_)) => bail!("keypool is set twice — --keypool and keypool in {}. Keep one", named()),
        (a, b) => a.or(b),
    };
    let defaults = Options::default();
    let max_fee = conf.maxtxfee.unwrap_or(defaults.max_fee);
    if max_fee == 0 {
        bail!("maxtxfee=0 in {} would refuse every send", named());
    }
    if conf.paytxfee.is_some_and(|rate| rate > max_fee) {
        bail!("paytxfee in {} is above maxtxfee — no send could pay it", named());
    }
    let options = Options {
        sweep_min: explicit.sweep_min.unwrap_or(defaults.sweep_min),
        keypool: keypool.unwrap_or(defaults.keypool),
        walletnotify: conf.walletnotify.clone(),
        blocknotify: conf.blocknotify.clone(),
        paytxfee: conf.paytxfee,
        max_fee,
        decimals: conf.amountdecimals.unwrap_or_default(),
        ..defaults
    };
    let cookie_file = match &conf.rpccookiefile {
        Some(file) if Path::new(file).is_absolute() => PathBuf::from(file),
        Some(file) => wallet_dir.join(file),
        None => wallet_dir.join(".cookie"),
    };
    Ok(Some(Settings {
        listen,
        credentials,
        rpcauth: conf.rpcauth.clone(),
        allow: conf.rpcallowip.clone(),
        cookie_file,
        passphrase: explicit.passphrase,
        network: network.to_string(),
        options,
        conf: (!conf.path.as_os_str().is_empty()).then(|| conf.path.clone()),
        ignored: conf.ignored.clone(),
        wallet_dir,
    }))
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

fn write_cookie(path: &Path) -> Result<String> {
    let secret: [u8; 32] = rand::random();
    let pair = format!("__cookie__:{}", hex::encode(secret));
    let _ = std::fs::remove_file(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    use std::io::Write;
    options
        .open(path)
        .with_context(|| format!("could not write the cookie to {}", path.display()))?
        .write_all(pair.as_bytes())?;
    Ok(pair)
}

/// Serve the wallet RPC over `node` until the process ends.
async fn serve(node: Node, settings: Settings) -> Result<()> {
    let daemon = Arc::new(Daemon::open(&settings.wallet_dir, node, settings.options.clone()).await?);
    let mut pairs = vec![write_cookie(&settings.cookie_file)?];
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
    if let Some(conf) = &settings.conf {
        if settings.ignored.is_empty() {
            tracing::info!(path = %conf.display(), "read");
        } else {
            tracing::info!(path = %conf.display(), ignored = %settings.ignored.join(", "), "read — these Bitcoin options mean nothing for a Helix wallet and were passed over");
        }
    }
    if !settings.listen.ip().is_loopback() {
        let allowed: Vec<String> = settings.allow.iter().map(|n| n.to_string()).collect();
        tracing::warn!(listen = %settings.listen, allowed = %allowed.join(", "), "the wallet RPC listens beyond this machine — keep it behind a firewall");
    }
    tracing::info!(listen = %settings.listen, hot = %daemon.hot_address(), dir = %settings.wallet_dir.display(), "Wallet RPC ready");
    let app = router(daemon, Auth::new(pairs, settings.rpcauth.clone()), settings.allow.clone());
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
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
            let explicit = Explicit { listen, credentials, passphrase: None, sweep_min: Some(sweep_min), keypool };
            let settings = resolve(wallet_dir, explicit, NETWORK, true)?.expect("serving always serves");
            serve(Node::new(node_url), settings).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(conf: Option<&str>) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("helix-walletd-cli-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(text) = conf {
            std::fs::write(dir.join(crate::conf::FILE), text).unwrap();
        }
        dir
    }

    fn err(dir: PathBuf, explicit: Explicit) -> String {
        format!("{:#}", resolve(dir, explicit, NETWORK, false).err().expect("must refuse"))
    }

    #[test]
    fn nothing_asks_for_a_wallet_unless_someone_did() {
        assert!(resolve(dir_with(None), Explicit::default(), NETWORK, false).unwrap().is_none());
        assert!(resolve(dir_with(Some("rpcport=9000\n")), Explicit::default(), NETWORK, false).unwrap().is_none(), "no server=1");
        assert!(resolve(dir_with(Some("server=0\n")), Explicit::default(), NETWORK, false).unwrap().is_none());
    }

    /// The exchange's bitcoin.conf, read into the wallet: the address, who may connect, users,
    /// notifications, fees and decimals.
    #[test]
    fn a_helix_conf_with_server_1_configures_the_wallet() {
        let dir = dir_with(Some(
            "server=1\nrpcbind=0.0.0.0\nrpcport=18547\nrpcallowip=172.16.0.0/12\nrpcuser=x\nrpcpassword=y\n\
             walletnotify=/n %s\nblocknotify=/b %s\npaytxfee=0.0001\nmaxtxfee=0.5\namountdecimals=8\ntxindex=1\n",
        ));
        let s = resolve(dir.clone(), Explicit::default(), NETWORK, false).unwrap().unwrap();
        assert_eq!(s.listen, "0.0.0.0:18547".parse().unwrap());
        assert_eq!((s.allow.len(), s.credentials.clone()), (1, vec!["x:y".to_string()]));
        assert_eq!(s.options.walletnotify.as_deref(), Some("/n %s"));
        assert_eq!((s.options.paytxfee, s.options.max_fee), (Some(100_000), 500_000_000));
        assert_eq!(s.options.decimals, crate::amount::Decimals::Eight);
        assert_eq!(s.cookie_file, dir.join(".cookie"));
        assert_eq!(s.ignored, vec!["txindex"]);
        let plain = resolve(dir_with(Some("server=1\n")), Explicit::default(), NETWORK, false).unwrap().unwrap();
        assert_eq!(plain.listen, "127.0.0.1:8547".parse().unwrap(), "Bitcoin Core's default: this machine only");
    }

    /// The #240 rule for two sources: a setting in both is not a setting anyone can predict.
    #[test]
    fn a_setting_in_both_places_or_one_that_exposes_the_wallet_stops_the_start() {
        let listen = Some("127.0.0.1:8547".parse().unwrap());
        for (conf, explicit, says) in [
            ("server=1\nrpcport=1\n", Explicit { listen, ..Default::default() }, "set twice"),
            ("server=1\nrpcuser=a\nrpcpassword=b\n", Explicit { credentials: Some("c:d".into()), ..Default::default() }, "set twice"),
            ("server=1\nrpcbind=0.0.0.0\n", Explicit::default(), "rpcallowip"),
            ("server=1\nrpcbind=10.0.0.1:1\nrpcport=2\n", Explicit::default(), "name it once"),
            ("server=1\nmaxtxfee=0\n", Explicit::default(), "refuse every send"),
            ("server=1\npaytxfee=2\n", Explicit::default(), "above maxtxfee"),
        ] {
            let said = err(dir_with(Some(conf)), explicit);
            assert!(said.contains(says), "{conf:?}: {said}");
        }
        let exposed = Explicit { listen: Some("0.0.0.0:8547".parse().unwrap()), ..Default::default() };
        assert!(err(dir_with(None), exposed).contains("rpcallowip"), "HELIX_WALLET_RPC=0.0.0.0 alone exposes it too");
    }
}
