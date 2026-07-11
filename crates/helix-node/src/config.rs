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
    pub validator_crypto_scheme: Option<String>,
    pub mempool_tx_ttl_secs: Option<u64>,
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
