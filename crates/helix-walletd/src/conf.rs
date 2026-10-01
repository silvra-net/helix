//! `helix.conf` — the wallet RPC's settings in Bitcoin Core's `bitcoin.conf` format, in the wallet's
//! directory (Bitcoin's datadir), where an exchange's Bitcoin-family tooling writes them: `server=1`,
//! `rpcport`, `rpcallowip`, `rpcuser`/`rpcpassword` or `rpcauth`, `walletnotify`, `blocknotify`.
//!
//! **A key this service does not know stops it, with the reason** (#240): a setting that silently
//! does nothing is worse than a node that does not start. Bitcoin options that mean nothing for a
//! Helix wallet (`txindex`, `dbcache`, `printtoconsole` …) are accepted and named once in the log,
//! so a `bitcoin.conf` copied over still works; an option an exchange might *rely on* — ZMQ, a
//! negated option — is refused, because ignoring it would leave them waiting for something that
//! never comes.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;

use crate::amount::Decimals;

/// The file's name in the wallet directory.
pub const FILE: &str = "helix.conf";

/// A user with a salted HMAC-SHA256 of their password, as Bitcoin Core's `rpcauth` (written by its
/// `share/rpcauth/rpcauth.py`): `user:salt$hash`, hash = HMAC-SHA256(key = salt, message = password).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcAuth {
    pub user: String,
    pub salt: String,
    pub hash: Vec<u8>,
}

impl RpcAuth {
    pub fn parse(value: &str) -> Result<RpcAuth, String> {
        let (user, rest) = value.split_once(':').ok_or("expected user:salt$hash")?;
        let (salt, hash) = rest.split_once('$').ok_or("expected user:salt$hash")?;
        if user.is_empty() || salt.is_empty() {
            return Err("expected user:salt$hash".into());
        }
        let hash = hex::decode(hash).map_err(|_| "the hash is not hex".to_string())?;
        if hash.len() != 32 {
            return Err("the hash is not 32 bytes (HMAC-SHA256)".into());
        }
        Ok(RpcAuth { user: user.to_string(), salt: salt.to_string(), hash })
    }

    /// Whether `password` is this user's, compared in constant time.
    pub fn accepts(&self, password: &str) -> bool {
        use hmac::{Hmac, KeyInit, Mac};
        use subtle::ConstantTimeEq;
        let Ok(mut mac) = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(self.salt.as_bytes()) else {
            return false;
        };
        mac.update(password.as_bytes());
        let computed = mac.finalize().into_bytes();
        bool::from(computed.as_slice().ct_eq(&self.hash))
    }
}

/// Who may connect, besides this machine (which always may): an address or a network, written as
/// Bitcoin Core takes it — `10.0.0.5`, `10.0.0.0/8`, `10.0.0.0/255.0.0.0`, `fd00::/8`.
pub fn parse_allow(value: &str) -> Result<IpNet, String> {
    let value = value.trim();
    if let Some((addr, mask)) = value.split_once('/') {
        let addr: IpAddr = addr.parse().map_err(|_| format!("{addr:?} is not an IP address"))?;
        let prefix = match mask.parse::<u8>() {
            Ok(p) => p,
            Err(_) => {
                let mask: IpAddr = mask.parse().map_err(|_| format!("{mask:?} is neither a prefix length nor a netmask"))?;
                let bits = match mask {
                    IpAddr::V4(m) => u32::from(m) as u128,
                    IpAddr::V6(m) => u128::from(m),
                };
                let width = if mask.is_ipv4() { 32 } else { 128 };
                let ones = if width == 32 { (bits as u32).leading_ones() } else { bits.leading_ones() };
                let contiguous = if width == 32 { (bits as u32).count_ones() == ones } else { bits.count_ones() == ones };
                if !contiguous {
                    return Err(format!("{mask} is not a netmask"));
                }
                ones as u8
            }
        };
        return IpNet::new(addr, prefix).map(|n| n.trunc()).map_err(|_| format!("/{prefix} is too long for {addr}"));
    }
    let addr: IpAddr = value.parse().map_err(|_| format!("{value:?} is not an IP address or network"))?;
    Ok(IpNet::from(addr))
}

/// Whether a client at `ip` may use the wallet RPC: this machine always, others when listed.
pub fn allowed(ip: IpAddr, allow: &[IpNet]) -> bool {
    let ip = ip.to_canonical();
    ip.is_loopback() || allow.iter().any(|net| net.contains(&ip))
}

#[derive(Debug, Clone, Default)]
pub struct Conf {
    pub path: PathBuf,
    pub server: Option<bool>,
    pub rpcbind: Option<String>,
    pub rpcport: Option<u16>,
    pub rpcallowip: Vec<IpNet>,
    pub rpcuser: Option<String>,
    pub rpcpassword: Option<String>,
    pub rpcauth: Vec<RpcAuth>,
    /// Where `helix-cli` connects (`bitcoin-cli`'s option; the service ignores it).
    pub rpcconnect: Option<String>,
    pub rpccookiefile: Option<String>,
    pub walletnotify: Option<String>,
    pub blocknotify: Option<String>,
    /// Nano-HLX per kB.
    pub paytxfee: Option<u64>,
    /// Nano-HLX.
    pub maxtxfee: Option<u64>,
    pub keypool: Option<usize>,
    pub amountdecimals: Option<Decimals>,
    /// Bitcoin options that mean nothing here and were passed over.
    pub ignored: Vec<String>,
}

/// Bitcoin Core options a copied `bitcoin.conf` may hold that mean nothing for a Helix wallet —
/// they configure Bitcoin's node, its peers, its database or its logging.
const IGNORED: &[&str] = &[
    "addnode", "assumevalid", "bind", "blocksonly", "chain", "checkblocks", "checklevel", "connect",
    "daemon", "daemonwait", "datadir", "dbcache", "debug", "debugexclude", "deprecatedrpc", "discover",
    "dns", "dnsseed", "externalip", "fallbackfee", "listen", "listenonion", "logips", "logthreadnames",
    "logtimestamps", "maxconnections", "maxmempool", "maxuploadtarget", "mempoolexpiry", "mintxfee",
    "natpmp", "onlynet", "par", "persistmempool", "port", "printtoconsole", "proxy", "prune",
    "regtest", "rest", "rpcservertimeout", "rpcthreads", "rpcworkqueue", "seednode", "shrinkdebugfile",
    "signet", "testnet", "timeout", "txindex", "uacomment", "upnp", "wallet", "walletdir",
    "whitebind", "whitelist",
];

const SUPPORTED: &[&str] = &[
    "server", "rpcbind", "rpcport", "rpcallowip", "rpcuser", "rpcpassword", "rpcauth", "rpcconnect",
    "rpccookiefile", "walletnotify", "blocknotify", "paytxfee", "maxtxfee", "keypool", "amountdecimals",
];

const SECTIONS: &[&str] = &["main", "test", "testnet4", "signet", "regtest"];

impl Conf {
    /// The file in `dir`, or `None` if there is none.
    pub fn read(dir: &Path, network: &str) -> Result<Option<Conf>> {
        Conf::read_file(&dir.join(FILE), network)
    }

    /// The file at `path`, or `None` if there is none.
    pub fn read_file(path: &Path, network: &str) -> Result<Option<Conf>> {
        let path = path.to_path_buf();
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };
        let mut conf = Conf::parse(&text, network).with_context(|| format!("{}", path.display()))?;
        conf.path = path.clone();
        #[cfg(unix)]
        if conf.rpcpassword.is_some() {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&path) {
                if meta.permissions().mode() & 0o077 != 0 {
                    tracing::warn!(path = %path.display(), "holds rpcpassword and others on this machine can read it — chmod 600 it, or use rpcauth");
                }
            }
        }
        Ok(Some(conf))
    }

    pub fn parse(text: &str, network: &str) -> Result<Conf> {
        let mut conf = Conf::default();
        let mut section: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let at = number + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                let name = name.trim();
                if !SECTIONS.contains(&name) {
                    bail!("line {at}: [{name}] is not a section (they are {})", SECTIONS.join(", "));
                }
                section = Some(name.to_string());
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                bail!("line {at}: {line:?} is not key=value");
            };
            let key = key.trim();
            let mut value = value.trim().to_string();
            if let Some(hash) = value.find('#') {
                if key == "rpcpassword" {
                    bail!("line {at}: rpcpassword holds a '#', which starts a comment — use a password without one, or rpcauth");
                }
                value = value[..hash].trim().to_string();
            }
            if let Some(s) = &section {
                if s != network {
                    continue;
                }
            }
            if key.starts_with("zmqpub") {
                bail!(
                    "line {at}: {key} — Helix does not publish over ZMQ. Use walletnotify and blocknotify, \
                     which run a command for every wallet transaction and every block"
                );
            }
            if IGNORED.contains(&key) {
                conf.ignored.push(key.to_string());
                continue;
            }
            if !SUPPORTED.contains(&key) {
                bail!("line {at}: {key} is not a setting of the Helix wallet RPC (it takes {})", SUPPORTED.join(", "));
            }
            let repeatable = matches!(key, "rpcallowip" | "rpcauth");
            if !repeatable && seen.iter().any(|k| k == key) {
                bail!("line {at}: {key} is set twice");
            }
            seen.push(key.to_string());
            let bad = |why: String| anyhow::anyhow!("line {at}: {key}={value}: {why}");
            match key {
                "server" => {
                    conf.server = Some(match value.as_str() {
                        "1" => true,
                        "0" => false,
                        _ => return Err(bad("write 1 or 0".into())),
                    })
                }
                "rpcbind" => conf.rpcbind = Some(value.clone()),
                "rpcport" => conf.rpcport = Some(value.parse().map_err(|_| bad("not a port".into()))?),
                "rpcallowip" => conf.rpcallowip.push(parse_allow(&value).map_err(bad)?),
                "rpcuser" => conf.rpcuser = Some(value.clone()),
                "rpcpassword" => conf.rpcpassword = Some(value.clone()),
                "rpcauth" => conf.rpcauth.push(RpcAuth::parse(&value).map_err(bad)?),
                "rpcconnect" => conf.rpcconnect = Some(value.clone()),
                "rpccookiefile" => conf.rpccookiefile = Some(value.clone()),
                "walletnotify" => conf.walletnotify = Some(value.clone()).filter(|v| !v.is_empty()),
                "blocknotify" => conf.blocknotify = Some(value.clone()).filter(|v| !v.is_empty()),
                "paytxfee" => conf.paytxfee = Some(helix_core::fee::parse_hlx(&value).map_err(|e| bad(e.to_string()))?),
                "maxtxfee" => conf.maxtxfee = Some(helix_core::fee::parse_hlx(&value).map_err(|e| bad(e.to_string()))?),
                "keypool" => conf.keypool = Some(value.parse().map_err(|_| bad("not a number".into()))?),
                "amountdecimals" => conf.amountdecimals = Some(Decimals::parse(&value).map_err(bad)?),
                _ => unreachable!("every supported key is matched"),
            }
        }
        if conf.rpcuser.is_some() != conf.rpcpassword.is_some() {
            bail!("rpcuser and rpcpassword go together — set both, or use rpcauth or the cookie");
        }
        Ok(conf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bitcoin_conf_an_exchange_writes_is_read() {
        let conf = Conf::parse(
            "# wallet RPC\nserver=1\nrpcport=18547\nrpcbind=0.0.0.0\nrpcallowip=10.0.0.0/8\nrpcallowip=192.168.1.7\n\
             rpcuser=exchange\nrpcpassword=s3cret\nwalletnotify=/opt/notify.sh %s\nblocknotify=curl -s http://x/%s # ping\n\
             txindex=1\ndbcache=450\npaytxfee=0.00001\nkeypool=500\namountdecimals=8\n",
            "test",
        )
        .unwrap();
        assert_eq!(conf.server, Some(true));
        assert_eq!((conf.rpcport, conf.rpcbind.as_deref()), (Some(18547), Some("0.0.0.0")));
        assert_eq!(conf.rpcallowip.len(), 2);
        assert_eq!((conf.rpcuser.as_deref(), conf.rpcpassword.as_deref()), (Some("exchange"), Some("s3cret")));
        assert_eq!(conf.walletnotify.as_deref(), Some("/opt/notify.sh %s"));
        assert_eq!(conf.blocknotify.as_deref(), Some("curl -s http://x/%s"), "an inline comment is cut");
        assert_eq!(conf.ignored, vec!["txindex", "dbcache"]);
        assert_eq!((conf.paytxfee, conf.keypool, conf.amountdecimals), (Some(10_000), Some(500), Some(Decimals::Eight)));
    }

    /// A setting nobody acts on must not look like one that works — the #240 rule.
    #[test]
    fn what_helix_cannot_do_stops_it_with_the_reason() {
        for (text, says) in [
            ("rpcpasword=x", "not a setting"),
            ("zmqpubrawtx=tcp://127.0.0.1:28332", "ZMQ"),
            ("noserver=1", "not a setting"),
            ("server=yes", "1 or 0"),
            ("rpcport=99999", "not a port"),
            ("rpcuser=a", "go together"),
            ("rpcpassword=ab#c\nrpcuser=u", "comment"),
            ("rpcport=1\nrpcport=2", "set twice"),
            ("[testnet3]\nserver=1", "not a section"),
            ("server", "key=value"),
            ("rpcallowip=10.0.0.0/255.0.255.0", "not a netmask"),
            ("rpcauth=u:salt$abcd", "32 bytes"),
            ("amountdecimals=6", "8 or 9"),
            ("paytxfee=1e-5", "paytxfee"),
        ] {
            let err = format!("{:#}", Conf::parse(text, "test").unwrap_err());
            assert!(err.contains(says), "{text:?} said {err:?}, not {says:?}");
        }
    }

    #[test]
    fn a_section_applies_only_on_its_network() {
        let text = "rpcport=1\n[main]\nrpcport=2\n[test]\nkeypool=7\n";
        let test = Conf::parse(text, "test").unwrap();
        assert_eq!((test.rpcport, test.keypool), (Some(1), Some(7)));
        let main = Conf::parse("[main]\nrpcport=2\n[test]\nkeypool=7\n", "main").unwrap();
        assert_eq!((main.rpcport, main.keypool), (Some(2), None));
    }

    /// The vector from Bitcoin Core's own test (`test/functional/rpc_users.py`), checked against
    /// Python's `hmac` before it went in here — not computed by the code it tests.
    #[test]
    fn rpcauth_accepts_the_password_bitcoin_core_accepts() {
        let auth = RpcAuth::parse("rt:93648e835a54c573682c2eb19f882535$7681e9c5b74bdd85e78166031d2058e1069b3ed7ed967c93fc63abba06f31144").unwrap();
        assert_eq!(auth.user, "rt");
        assert!(auth.accepts("cA773lm788buwYe4g4WT+05pKyNruVKjQ25x3n0DQcM="));
        assert!(!auth.accepts("cA773lm788buwYe4g4WT+05pKyNruVKjQ25x3n0DQcM"));
        assert!(!auth.accepts(""));
    }

    #[test]
    fn rpcallowip_reads_every_form_bitcoin_core_takes_and_this_machine_is_always_allowed() {
        let allow: Vec<IpNet> = ["10.0.0.0/8", "192.168.1.0/255.255.255.0", "172.17.0.2", "fd00::/8"]
            .iter()
            .map(|v| parse_allow(v).unwrap())
            .collect();
        for (ip, ok) in [
            ("10.200.3.4", true),
            ("11.0.0.1", false),
            ("192.168.1.77", true),
            ("192.168.2.1", false),
            ("172.17.0.2", true),
            ("172.17.0.3", false),
            ("fd12::1", true),
            ("::ffff:10.1.2.3", true),
            ("127.0.0.1", true),
            ("::1", true),
            ("8.8.8.8", false),
        ] {
            assert_eq!(allowed(ip.parse().unwrap(), &allow), ok, "{ip}");
        }
        assert!(!allowed("10.0.0.1".parse().unwrap(), &[]), "nobody but this machine without rpcallowip");
    }
}
