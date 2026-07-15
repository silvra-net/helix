use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Optional `helix.toml` file (path overridable via `HELIX_CONFIG`) bundling the
/// node parameters that used to be scattered across single-purpose env vars.
/// Every field stays optional: an absent file, or an absent field within it, is
/// not an error — it just falls through to the env var (if set) and then the
/// built-in default, so existing env-var-only deployments keep working unchanged.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub rpc_bind: Option<String>,
    pub p2p_listen_addr: Option<String>,
    pub reward_address: Option<String>,
    pub sync_peer: Option<String>,
    /// Set truthy (`1`/`true`/`yes`/`on`) to start/run a **standalone chain** instead of
    /// auto-joining the public Helix network. When neither `sync_peer` nor `HELIX_SYNC_PEER`
    /// is set, a node defaults to seeding from the built-in production endpoint
    /// (`node::DEFAULT_SEED_PEER`) — a freshly downloaded release joins the live chain out of
    /// the box. This flag opts out of that: the node self-signs its own genesis and runs its
    /// own network. Set it for the production origin node itself and for any local devnet.
    /// Overridable via `HELIX_NEW_CHAIN`. Ignored if a sync peer is explicitly configured.
    pub new_chain: Option<String>,
    /// Path to this node's validator key file (the unified KeyFile JSON format `hlx wallet`
    /// also produces). Defaults to `validator-key.json` in the working directory. Overridable
    /// via `HELIX_VALIDATOR_KEY`.
    pub validator_key_path: Option<String>,
    pub validator_crypto_scheme: Option<String>,
    pub mempool_tx_ttl_secs: Option<u64>,
    /// Comma-separated hex-encoded public keys of the network's personhood-issuing
    /// authorities — see `ChainState::personhood_authorities`. `ProvePersonhood` accepts a
    /// signature from any ONE of these. Only read at genesis (fresh chain, no block 0 yet);
    /// once persisted, changing this has no effect without a chain reset. Every node must be
    /// configured with the same value, since it becomes part of consensus-checked state —
    /// this is an operator convention, not cryptographically enforced.
    pub personhood_authorities: Option<String>,
    /// This node's own externally-dialable host (e.g. `helix.silvra.net` or a public IP,
    /// no scheme/port) — used to build the multiaddr this node announces to peers via peer
    /// exchange (`P2PConfig::public_addr`, see its doc comment for why). Absent for pure
    /// followers / nodes behind NAT with no forwarded port: they still relay addresses they
    /// learn from others, they just never announce themselves.
    pub p2p_public_addr: Option<String>,
    /// Comma-separated `address:stake_hlx` pairs — validators to pre-stake directly at
    /// genesis beyond the one bootstrap validator every chain has always had, e.g.
    /// `hlx1abc...:100000,hlx1def...:100000`. See `GenesisConfig::extra_validators`'s doc
    /// comment for why this exists (organic staking is far too slow to bootstrap a
    /// genuinely multi-validator network). Only takes effect for a fresh chain — see
    /// `personhood_authorities`'s doc comment above for the same caveat.
    pub genesis_extra_validators: Option<String>,
    /// Set truthy (`1`/`true`/`yes`/`on`) to turn OFF mDNS LAN peer auto-discovery, leaving
    /// only `seed_peers` + peer exchange for connectivity. Needed when two independent Helix
    /// networks share a LAN (mDNS would otherwise cross-wire them) — see
    /// `helix_p2p::P2PConfig::enable_mdns`. Absent/false keeps mDNS on (the default).
    pub p2p_disable_mdns: Option<String>,
    /// Comma-separated list of additional P2P peers to dial directly, as libp2p
    /// multiaddrs (e.g. `/ip4/1.2.3.4/tcp/8546,/dns4/peer.example/tcp/8546`). Unlike
    /// `sync_peer` (one HTTP peer for history + its single derived P2P seed), this hard-wires
    /// several direct P2P peers at once — important for a validator set, where every
    /// validator should peer with every other rather than hub-and-spoke through one node: a
    /// hub outage otherwise partitions the rest, and relaying consensus votes through a single
    /// hub is fragile. Peer exchange still discovers further peers on top of these.
    pub p2p_seed_peers: Option<String>,
}

const CONFIG_PATH_ENV: &str = "HELIX_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "helix.toml";

/// Load the node config file. Looks at `HELIX_CONFIG` for a custom path, else
/// `./helix.toml`. A missing file resolves to an all-`None` config (not an
/// error); a present-but-malformed file is.
pub fn load_node_config() -> Result<NodeConfig> {
    let path = std::env::var(CONFIG_PATH_ENV).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    load_node_config_from(Path::new(&path))
}

fn load_node_config_from(path: &Path) -> Result<NodeConfig> {
    if !path.exists() {
        return Ok(NodeConfig::default());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("failed to parse config file {}", path.display()))
}

/// Resolve a single setting: env var (if set) takes precedence over the config
/// file field, which takes precedence over the caller's default.
pub fn resolve(env_var: &str, config_val: &Option<String>) -> Option<String> {
    std::env::var(env_var).ok().or_else(|| config_val.clone())
}

/// Same precedence as `resolve` (env var > config file > caller default), but for a
/// `u64` setting. An env var present but not parseable as `u64` is ignored (falls
/// through to the config file value) rather than erroring — keeps this consistent
/// with `resolve`'s "never fail on optional settings" behavior.
pub fn resolve_u64(env_var: &str, config_val: Option<u64>) -> Option<u64> {
    std::env::var(env_var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .or(config_val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_yields_default_config() {
        let path = std::env::temp_dir().join(format!("helix-test-missing-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_eq!(load_node_config_from(&path).unwrap(), NodeConfig::default());
    }

    #[test]
    fn parses_a_partial_config_file() {
        let path = std::env::temp_dir().join(format!("helix-test-partial-{}.toml", std::process::id()));
        std::fs::write(&path, "rpc_bind = \"0.0.0.0:8545\"\nsync_peer = \"http://seed:8545\"\n").unwrap();

        let cfg = load_node_config_from(&path).unwrap();
        assert_eq!(cfg.rpc_bind.as_deref(), Some("0.0.0.0:8545"));
        assert_eq!(cfg.sync_peer.as_deref(), Some("http://seed:8545"));
        assert_eq!(cfg.p2p_listen_addr, None);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rejects_unknown_fields() {
        let path = std::env::temp_dir().join(format!("helix-test-unknown-{}.toml", std::process::id()));
        std::fs::write(&path, "not_a_real_field = \"x\"\n").unwrap();

        assert!(load_node_config_from(&path).is_err());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn resolve_prefers_env_over_config_file() {
        let env_var = "HELIX_TEST_RESOLVE_PRECEDENCE";
        std::env::set_var(env_var, "from-env");
        assert_eq!(resolve(env_var, &Some("from-file".to_string())), Some("from-env".to_string()));
        std::env::remove_var(env_var);
    }

    #[test]
    fn resolve_falls_back_to_config_file() {
        let env_var = "HELIX_TEST_RESOLVE_FALLBACK";
        std::env::remove_var(env_var);
        assert_eq!(resolve(env_var, &Some("from-file".to_string())), Some("from-file".to_string()));
    }

    #[test]
    fn resolve_u64_prefers_env_over_config_file() {
        let env_var = "HELIX_TEST_RESOLVE_U64_PRECEDENCE";
        std::env::set_var(env_var, "42");
        assert_eq!(resolve_u64(env_var, Some(7)), Some(42));
        std::env::remove_var(env_var);
    }

    #[test]
    fn resolve_u64_falls_back_to_config_file_on_unparseable_env() {
        let env_var = "HELIX_TEST_RESOLVE_U64_UNPARSEABLE";
        std::env::set_var(env_var, "not-a-number");
        assert_eq!(resolve_u64(env_var, Some(7)), Some(7));
        std::env::remove_var(env_var);
    }

    #[test]
    fn resolve_u64_falls_back_to_default_when_unset() {
        let env_var = "HELIX_TEST_RESOLVE_U64_UNSET";
        std::env::remove_var(env_var);
        assert_eq!(resolve_u64(env_var, None), None);
    }
}
