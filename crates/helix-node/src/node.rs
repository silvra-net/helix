use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use helix_consensus::{BftEngine, ConsensusError, DoubleSignEvidence, Proposal, Validator, ValidatorSet};
use helix_core::{genesis_block, Block, Transaction, TxType};
use helix_crypto::{Address, CryptoScheme, KeyFile, KeyPair, PublicKey, Signature};
use helix_executor::{
    execute_block,
    genesis::{GenesisConfig, NANO_PER_HLX, TOTAL_SUPPLY_HLX, VALIDATOR_GENESIS_STAKE_HLX},
    state::ChainState,
    GovernanceParams,
};
use helix_mempool::Mempool;
use helix_p2p::{
    config::P2PConfig,
    service::{P2PCommand, P2PEvent, P2PService},
};
use helix_rpc::server::{start_rpc_server, AppState};
use helix_storage::{db::HelixDb, BlockStore};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::config::{self, NodeConfig};

/// Load the validator keypair from disk, or generate + persist a new one for
/// `scheme_for_new` (the scheme to use only if no key file exists yet).
///
/// File format is the unified KeyFile JSON format shared with `hlx wallet` (see
/// `helix_crypto::keyfile`). A validator migrates to a new PQC scheme (see
/// `helix_crypto::CryptoScheme`) by setting `HELIX_VALIDATOR_CRYPTO_SCHEME=sphincs-plus`
/// and regenerating the key — blocks/votes it already signed under the old scheme stay
/// verifiable forever since each one carries its own `crypto_version` tag.
///
/// Support for the pre-2026-07-05 raw-bytes format (`[scheme tag][secret][public]`,
/// or untagged legacy ML-DSA `secret || public`) was removed once no known key file
/// still used it — convert an old file first with `hlx wallet import-node-key`.
///
/// Passphrase used to decrypt an encrypted validator key file (KeyFile format with
/// `encryption = "aes256gcm-argon2id"`, e.g. produced by `hlx wallet encrypt`). There
/// is no interactive prompt at node startup, so this is the only way to unlock one.
const VALIDATOR_KEY_PASSPHRASE_ENV: &str = "HELIX_VALIDATOR_KEY_PASSPHRASE";

/// Unified validator key filename. It's the exact same KeyFile JSON format `hlx wallet`
/// produces — a validator key *is* a wallet, usable directly with `hlx --key`, with no
/// conversion step. Overridable via `HELIX_VALIDATOR_KEY` / `validator_key_path`.
const DEFAULT_VALIDATOR_KEY_FILE: &str = "validator-key.json";


/// The public production network's RPC endpoint. When a node has no local chain and no
/// `sync_peer`/`HELIX_SYNC_PEER` configured, it seeds from here by default — so a freshly
/// downloaded release joins the live Helix chain out of the box, with no manual peer setup.
/// This one HTTPS endpoint supplies everything a joiner needs: the real genesis block, the
/// full historical block download, an attempted direct P2P dial, and the target of the
/// periodic RPC catch-up ([`rpc_sync_loop`]) that keeps a follower current even when the raw
/// P2P port isn't publicly reachable (it runs behind a Cloudflare HTTPS tunnel). Opt out with
/// `HELIX_NEW_CHAIN=1` to run a standalone chain instead (the production origin node and any
/// local devnet do this). Override the endpoint itself with `HELIX_SYNC_PEER`.
pub const DEFAULT_SEED_PEER: &str = "https://helix.silvra.net";

/// Interval between periodic RPC catch-up polls of the sync peer (see [`rpc_sync_loop`]).
const RPC_SYNC_POLL_SECS: u64 = 4;

/// True for the truthy env/config spellings `1`/`true`/`yes`/`on` (case-insensitive) — the
/// same set already accepted for `HELIX_P2P_DISABLE_MDNS`, factored out so the new
/// `HELIX_NEW_CHAIN` flag reads identically.
fn flag_is_truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// The file the validator keypair lives in: an explicit `HELIX_VALIDATOR_KEY` /
/// `validator_key_path` override, otherwise the unified `validator-key.json`. Everything uses
/// the one KeyFile JSON format `hlx wallet` produces — there is no separate legacy format.
fn resolve_validator_key_path(cfg: &config::NodeConfig) -> PathBuf {
    match config::resolve("HELIX_VALIDATOR_KEY", &cfg.validator_key_path) {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(DEFAULT_VALIDATOR_KEY_FILE),
    }
}

fn load_or_create_keypair(path: &PathBuf, scheme_for_new: CryptoScheme) -> Result<KeyPair> {
    load_or_create_keypair_with(path, scheme_for_new, std::env::var(VALIDATOR_KEY_PASSPHRASE_ENV).ok())
}

fn load_or_create_keypair_with(
    path: &PathBuf,
    scheme_for_new: CryptoScheme,
    passphrase: Option<String>,
) -> Result<KeyPair> {
    if path.exists() {
        let data = std::fs::read(path)?;

        let text = std::str::from_utf8(&data).map_err(|_| {
            anyhow::anyhow!(
                "Validator key file {} is not valid KeyFile JSON (old raw-format key files are no longer supported — convert with `hlx wallet import-node-key --from {} --output {}`)",
                path.display(), path.display(), path.display()
            )
        })?;
        let kf = KeyFile::from_json_str(text).map_err(|e| {
            anyhow::anyhow!("Invalid key file {}: {}", path.display(), e)
        })?;
        let kp = kf
            .to_keypair(passphrase.as_deref())
            .map_err(|e| anyhow::anyhow!("Invalid key in {}: {}", path.display(), e))?;
        info!("Loaded persistent validator keypair ({:?}) from {} (KeyFile format)", kp.scheme, path.display());
        Ok(kp)
    } else {
        let kp = KeyPair::generate_for(scheme_for_new);
        // Neue Keys im vereinheitlichten KeyFile-JSON-Format speichern — Node und CLI
        // teilen sich ab jetzt ein Format, kein Konvertierungsschritt mehr nötig.
        let kf = KeyFile::from_keypair_plain(&kp);
        kf.save(path)?;
        info!("Generated new validator keypair ({:?}) → saved to {} (KeyFile format)", scheme_for_new, path.display());
        Ok(kp)
    }
}

#[cfg(test)]
mod keypair_file_tests {
    use super::*;

    #[test]
    fn generates_and_reloads_a_tagged_keypair() {
        let path = std::env::temp_dir().join(format!("helix-test-key-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let generated = load_or_create_keypair(&path, CryptoScheme::SphincsPlus).unwrap();
        assert_eq!(generated.scheme, CryptoScheme::SphincsPlus);

        // Loading again must reconstruct the same key from the tagged file,
        // regardless of what scheme_for_new is passed (the file already exists).
        let reloaded = load_or_create_keypair(&path, CryptoScheme::MlDsa).unwrap();
        assert_eq!(reloaded.scheme, CryptoScheme::SphincsPlus);
        assert_eq!(reloaded.public.as_bytes(), generated.public.as_bytes());
        assert_eq!(reloaded.secret.as_bytes(), generated.secret.as_bytes());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rejects_a_raw_non_json_key_file_with_a_helpful_error() {
        let path = std::env::temp_dir().join(format!("helix-test-raw-key-{}.json", std::process::id()));
        let kp = KeyPair::generate();
        // Old raw format: no longer accepted — must be converted first.
        let mut data = kp.secret.as_bytes().to_vec();
        data.extend_from_slice(kp.public.as_bytes());
        std::fs::write(&path, &data).unwrap();

        match load_or_create_keypair(&path, CryptoScheme::SphincsPlus) {
            Err(e) => assert!(e.to_string().contains("import-node-key"), "error should point at the migration path: {e}"),
            Ok(_) => panic!("expected loading a raw non-JSON key file to fail"),
        }

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn loads_passphrase_encrypted_keyfile_when_passphrase_given() {
        let path = std::env::temp_dir().join(format!("helix-test-encrypted-key-{}.json", std::process::id()));
        let kp = KeyPair::generate();
        let kf = KeyFile::from_keypair_encrypted(&kp, "correct horse battery staple").unwrap();
        kf.save(&path).unwrap();

        match load_or_create_keypair_with(&path, CryptoScheme::MlDsa, None) {
            Err(e) => assert!(e.to_string().contains("Passphrase required")),
            Ok(_) => panic!("expected loading an encrypted key without a passphrase to fail"),
        }

        let loaded = load_or_create_keypair_with(
            &path,
            CryptoScheme::MlDsa,
            Some("correct horse battery staple".to_string()),
        )
        .unwrap();
        assert_eq!(loaded.public.as_bytes(), kp.public.as_bytes());
        assert_eq!(loaded.secret.as_bytes(), kp.secret.as_bytes());

        std::fs::remove_file(&path).unwrap();
    }
}

const BLOCK_TIME_MS: u64 = 2_000;
/// Block-production ticks to wait (after enough validators have connected) for the
/// gossip mesh to finish forming before producing the first block, in a
/// multi-validator set. See the startup gate in `block_production_loop`.
const MESH_SETTLE_TICKS: u32 = 5;
const MAX_TXS_PER_BLOCK: usize = 1_000;
const RPC_BIND_DEFAULT: &str = "127.0.0.1:8545";

/// Fee for the node-generated `SubmitDoubleSignEvidence` transaction — well above
/// `helix_mempool`'s `DEFAULT_MIN_FEE` (1,000 nano-HLX), which isn't itself
/// importable here (private to that crate). Found the hard way: this tx used to
/// carry `fee: 0`, so `Mempool::add()` rejected it with `FeeTooLow` on *every*
/// node, including the reporter's own — evidence was detected and logged, but the
/// slash it should have triggered silently never made it anywhere close to a
/// block. Unit tests exercise `execute_submit_double_sign_evidence` directly, which
/// bypasses the mempool entirely, so this was never caught until an actual
/// double-sign was triggered on a real multi-node network and the resulting
/// "evidence detected" log was checked against what the chain actually did with it.
const DOUBLE_SIGN_EVIDENCE_FEE_NANO: u64 = 10_000;

/// RPC bind address — defaults to `RPC_BIND_DEFAULT`, overridable via `helix.toml`'s
/// `rpc_bind` field or (taking precedence) the `HELIX_RPC_BIND` env var (e.g.
/// `HELIX_RPC_BIND=0.0.0.0:8545` for non-standard topologies where the node isn't
/// reached through a local reverse proxy / tunnel).
fn resolve_rpc_bind(cfg: &NodeConfig) -> Result<SocketAddr> {
    resolve_rpc_bind_from(config::resolve("HELIX_RPC_BIND", &cfg.rpc_bind))
}

fn resolve_rpc_bind_from(override_val: Option<String>) -> Result<SocketAddr> {
    match override_val {
        Some(s) => s
            .parse()
            .with_context(|| format!("HELIX_RPC_BIND is set but not a valid address: {}", s)),
        None => Ok(RPC_BIND_DEFAULT.parse().expect("valid default RPC bind addr")),
    }
}

#[cfg(test)]
mod rpc_bind_tests {
    use super::*;

    #[test]
    fn defaults_when_unset() {
        assert_eq!(
            resolve_rpc_bind_from(None).unwrap(),
            RPC_BIND_DEFAULT.parse().unwrap()
        );
    }

    #[test]
    fn honors_valid_override() {
        assert_eq!(
            resolve_rpc_bind_from(Some("0.0.0.0:9999".to_string())).unwrap(),
            "0.0.0.0:9999".parse().unwrap()
        );
    }

    #[test]
    fn rejects_invalid_override() {
        assert!(resolve_rpc_bind_from(Some("not-an-address".to_string())).is_err());
    }
}

pub struct HelixNode {
    keypair: Arc<KeyPair>,
    address: Address,
    /// Where the validator's 50 % fee share lands.  Defaults to `address` when unset.
    /// Configure via `reward_address` in `helix.toml` or the HELIX_REWARD_ADDRESS env var.
    reward_address: Option<Address>,
    /// Resolved once at startup (env > `helix.toml` > unset) via `config::resolve`,
    /// then reused for both the startup sync and the runtime gap-fill fallback in
    /// `handle_p2p_event` — so a `sync_peer` set only in the config file also
    /// covers the runtime path, not just startup.
    sync_peer: Option<String>,
    store: Arc<RwLock<HelixDb>>,
    mempool: Arc<RwLock<Mempool>>,
    chain_state: Arc<RwLock<ChainState>>,
    p2p_command_tx: mpsc::Sender<P2PCommand>,
    p2p_event_rx: mpsc::Receiver<P2PEvent>,
    p2p_service: Option<P2PService>,
    /// This node's own libp2p listen port — surfaced to RPC (`GET /status`) so a peer that
    /// syncs from this node can derive a dialable seed address, see
    /// `resolve_seed_peer_multiaddr`.
    p2p_port: u16,
    /// This node's announced public P2P multiaddr (`HELIX_P2P_PUBLIC_ADDR`), if any — also
    /// surfaced to RPC (`GET /status`) so a syncing peer dials it directly rather than the
    /// raw-TCP address derived from `p2p_port`, which is unreachable for a tunnelled node.
    p2p_public_addr: Option<String>,
    rpc_bind: SocketAddr,
}

impl HelixNode {
    pub async fn new() -> Result<Self> {
        // `helix.toml` (path overridable via HELIX_CONFIG) bundles the node
        // params below; env vars still take precedence over the file, see
        // `config::resolve`.
        let cfg = config::load_node_config()?;

        let key_path = resolve_validator_key_path(&cfg);
        let scheme_for_new = match config::resolve("HELIX_VALIDATOR_CRYPTO_SCHEME", &cfg.validator_crypto_scheme).as_deref() {
            Some("sphincs-plus") | Some("sphincsplus") => CryptoScheme::SphincsPlus,
            _ => CryptoScheme::MlDsa,
        };
        let keypair = load_or_create_keypair(&key_path, scheme_for_new)?;
        let address = Address::from_public_key(&keypair.public);

        // Optional reward address — fees land here instead of the validator address.
        let reward_address = config::resolve("HELIX_REWARD_ADDRESS", &cfg.reward_address).and_then(|s| {
            match Address::from_str(&s) {
                Ok(addr) => {
                    info!("Fee reward address : {} (HELIX_REWARD_ADDRESS / helix.toml)", addr);
                    Some(addr)
                }
                Err(_) => {
                    warn!("reward_address is set but invalid — fees go to validator address");
                    None
                }
            }
        });

        info!("Validator address : {}", address);
        info!("PK fingerprint    : {}", keypair.public.fingerprint());

        // Persistent redb-backed store — blocks + chain state survive restarts.
        let db_path = PathBuf::from("helix-data.redb");
        let mut store = HelixDb::open(&db_path)?;

        // Personhood authorities — only takes effect for a fresh chain (see below); an
        // existing chain's authorities (if any) were already persisted at its own genesis.
        let personhood_authorities: Vec<helix_crypto::PublicKey> =
            config::resolve("HELIX_PERSONHOOD_AUTHORITIES", &cfg.personhood_authorities)
                .map(|raw| {
                    raw.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .filter_map(|hex| match helix_crypto::PublicKey::from_hex(hex) {
                            Ok(pk) => Some(pk),
                            Err(e) => {
                                warn!(err = %e, key = hex, "HELIX_PERSONHOOD_AUTHORITIES / helix.toml contains an invalid public key — skipping it");
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
        if personhood_authorities.is_empty() {
            info!("No personhood authorities configured — ProvePersonhood transactions will be rejected");
        }

        // Extra genesis validators — only takes effect for a fresh chain, same caveat as
        // personhood_authorities above. See `GenesisConfig::extra_validators`'s doc comment.
        let extra_validators: Vec<(Address, u64)> =
            config::resolve("HELIX_GENESIS_EXTRA_VALIDATORS", &cfg.genesis_extra_validators)
                .map(|raw| {
                    raw.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .filter_map(|entry| {
                            let (addr_str, stake_str) = entry.split_once(':')?;
                            let address = match Address::from_str(addr_str) {
                                Ok(a) => a,
                                Err(e) => {
                                    warn!(err = %e, addr = addr_str, "HELIX_GENESIS_EXTRA_VALIDATORS / helix.toml contains an invalid address — skipping it");
                                    return None;
                                }
                            };
                            let stake_hlx: u64 = match stake_str.parse() {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(err = %e, stake = stake_str, "HELIX_GENESIS_EXTRA_VALIDATORS / helix.toml has a non-numeric stake — skipping it");
                                    return None;
                                }
                            };
                            Some((address, stake_hlx * NANO_PER_HLX))
                        })
                        .collect()
                })
                .unwrap_or_default();

        let mut genesis_cfg = GenesisConfig::devnet_with_personhood_authority(address.clone(), personhood_authorities);
        genesis_cfg.extra_validators = extra_validators;

        // `sync_peer = "http://seed:8545"` in helix.toml, or HELIX_SYNC_PEER — resolved here
        // (rather than after genesis, as before) because a node with no local chain yet needs
        // it to decide *which* genesis it starts from.
        //
        // Default seed: if no sync peer is configured, fall back to the public production
        // endpoint (DEFAULT_SEED_PEER) so a freshly downloaded release joins the live chain
        // with zero configuration. Opt out with HELIX_NEW_CHAIN=1 (or `new_chain` in the
        // config) to run a standalone chain — the production origin node and every local devnet
        // set this, so they self-sign their own genesis instead of trying to seed from
        // (potentially themselves) the public network.
        let new_chain = config::resolve("HELIX_NEW_CHAIN", &cfg.new_chain)
            .as_deref()
            .map(flag_is_truthy)
            .unwrap_or(false);
        let sync_peer = config::resolve("HELIX_SYNC_PEER", &cfg.sync_peer).or_else(|| {
            if new_chain {
                None
            } else {
                info!(
                    seed = DEFAULT_SEED_PEER,
                    "No sync peer configured — joining the public Helix network by default \
                     (set HELIX_NEW_CHAIN=1 to run a standalone chain instead)"
                );
                Some(DEFAULT_SEED_PEER.to_string())
            }
        });

        let mut chain_state = if store.get_block_by_height(0).is_ok() {
            info!("Loaded existing chain state from {}", db_path.display());
            store.load_chain_state(TOTAL_SUPPLY_HLX * NANO_PER_HLX)?
        } else if let Some(peer_url) = &sync_peer {
            // Adopt the peer's real genesis instead of self-signing one. Every node used to
            // sign its own height-0 block with its own key — deterministic in every field
            // except `validator`/`public_key`/`signature`, so two independently-bootstrapped
            // nodes always produced two distinct, mutually incompatible genesis hashes. That
            // meant `sync_blocks_from_peer` could never succeed for a genuinely fresh node:
            // block 1 either failed the validator-membership check (this node's own genesis
            // only ever pre-stakes itself, never the peer's real validator) or, had that
            // passed, the prev_hash continuity check right after it (block 1's prev_hash
            // names the peer's genesis hash, not this node's self-signed one) — found by
            // actually wiping a node's data and watching it fail to rejoin the network it
            // just left, then re-derive its own solo chain instead. Every prior node in this
            // fleet was in fact bootstrapped by copying an already-populated database file,
            // never through this path — this is the first time it's been exercised for real.
            info!("No local chain yet — fetching genesis from sync peer {}", peer_url);
            let peer_genesis = fetch_genesis_from_peer(peer_url).await?;
            let genesis = peer_genesis.block.clone();

            // Rebuild through the same function the peer hashed, taking every field from the
            // peer rather than from this binary's own defaults — they describe a chain this node
            // isn't joining. `allocations` in particular is replaced, never merged: adding a
            // local prefund on top would mint HLX the real chain never issued.
            let state = helix_executor::genesis::rebuild_genesis_state(
                genesis.header.validator.clone(),
                peer_genesis.personhood_authorities.clone(),
                peer_genesis.extra_validators.clone(),
                peer_genesis.validator_stake,
                peer_genesis.allocations.clone(),
                peer_genesis.governance_params.clone(),
            );

            // Before anything is written. A wrong genesis persisted is a wrong chain that then
            // applies every subsequent block perfectly on top of it.
            verify_genesis_reconstruction(&peer_genesis, &state)?;

            store.put_block(genesis.clone())?;
            info!(validator = %genesis.header.validator, "Adopted peer's genesis block (height 0)");
            store.save_chain_state(&state)?;
            state
        } else {
            let sig = keypair.sign(b"helix-genesis-v1")?;
            let genesis = genesis_block(address.clone(), keypair.public.clone(), sig);
            store.put_block(genesis)?;
            info!("Genesis block created (height 0)");

            let state = genesis_cfg.build_state();
            store.save_chain_state(&state)?;
            info!("Genesis: no liquid pre-mine — validator earns via 50/50 fee split plus the halving block reward");
            state
        };

        // Block sync — download historical blocks from a trusted peer if configured.
        // Fetches all blocks this node is missing (from height 1 on — genesis, height 0, was
        // either loaded above or adopted from this same peer just above).
        if let Some(peer_url) = &sync_peer {
            let local_tip = store.latest_height();
            info!("Syncing blocks from {} (local tip: {})", peer_url, local_tip);
            match sync_blocks_from_peer(peer_url, local_tip, &mut store, &mut chain_state).await {
                Ok(synced) => info!("Block sync complete — applied {} new blocks", synced),
                Err(e) => warn!("Block sync failed (continuing anyway): {}", e),
            }
        }

        // P2P setup — `p2p_listen_addr` in helix.toml (or HELIX_P2P_LISTEN) overrides
        // the default listen address; unset means keep P2PConfig::default().
        let mut p2p_config = P2PConfig::default();
        if let Some(addr) = config::resolve("HELIX_P2P_LISTEN", &cfg.p2p_listen_addr) {
            p2p_config.listen_addr = addr
                .parse()
                .with_context(|| format!("invalid P2P listen address: {}", addr))?;
        }
        if let Some(addr) = config::resolve("HELIX_P2P_WS_LISTEN", &cfg.p2p_ws_listen_addr) {
            p2p_config.ws_listen_addr = Some(
                addr.parse()
                    .with_context(|| format!("invalid P2P WebSocket listen address: {}", addr))?,
            );
        }

        // Explicit seed peer — `sync_peer` gets this node its historical blocks over plain
        // HTTP, but on its own it left gossipsub with nothing but mDNS for live connectivity.
        // mDNS only ever finds peers in the same local multicast segment, so a `sync_peer`
        // reachable only over a real network (the exact "join an existing network" case the
        // README documents) would sync its history once at startup and then never receive a
        // single new block again — found by this same failure mode reproducing in CI, where
        // mDNS doesn't work at all inside the runner's network sandbox, not just on the open
        // internet. Resolves the peer's own P2P port via `GET /status` (added for this) and
        // dials it directly; best-effort, mDNS remains a second, independent discovery path.
        if let Some(peer_url) = &sync_peer {
            match resolve_seed_peer_multiaddr(peer_url).await {
                Ok(addr) => {
                    info!(peer = %peer_url, multiaddr = %addr, "Resolved sync peer's P2P address — will dial directly");
                    p2p_config.seed_peers.push(addr);
                }
                Err(e) => warn!(peer = %peer_url, error = %e, "Could not resolve sync peer's P2P address — falling back to mDNS-only discovery"),
            }
        }

        // Our own externally-dialable address (if configured) — announced to peers via peer
        // exchange (`P2PConfig::public_addr`'s doc comment has the full picture: without this,
        // followers connected only to a single hub have no path to each other if that hub goes
        // down). Optional — a node behind NAT or with no public host set still participates in
        // peer exchange, it just never announces itself, and relays what it learns from others.
        if let Some(value) = config::resolve("HELIX_P2P_PUBLIC_ADDR", &cfg.p2p_public_addr) {
            // A value starting with `/` is already a full multiaddr — used verbatim. This is how
            // a node behind an HTTPS proxy / Cloudflare tunnel announces a WebSocket address
            // (`/dns4/host/tcp/443/tls/ws`), whose transport and port the plain host+raw-TCP-port
            // form below cannot express. Anything else is treated as a bare host, with this
            // node's raw TCP P2P port appended — the original, still-common case.
            let addr = if value.starts_with('/') {
                value
            } else {
                format!("/{}/{value}/tcp/{}", multiaddr_kind(&value), p2p_config.listen_addr.port())
            };
            info!(multiaddr = %addr, "Announcing our own P2P address via peer exchange");
            p2p_config.public_addr = Some(addr);
        }

        // Additional explicit P2P seed peers (comma-separated multiaddrs) to dial directly,
        // on top of the one derived from `sync_peer`. Lets an operator wire a validator set
        // into a full mesh (every validator dials every other) rather than hub-and-spoke,
        // which both survives any single node's outage and gives consensus vote gossip more
        // than one relay path. Malformed entries are dialed-and-ignored by the P2P layer.
        if let Some(seeds) = config::resolve("HELIX_P2P_SEED_PEERS", &cfg.p2p_seed_peers) {
            for s in seeds.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                p2p_config.seed_peers.push(s.to_string());
            }
        }

        // mDNS LAN auto-discovery is on by default (zero-config peering). Disable it for
        // deterministic seed-peer-only peering — required when another independent Helix
        // network shares this LAN (e.g. the multi-node integration test running next to a
        // live production node), where mDNS would otherwise cross-wire the two and drown
        // each in the other's incompatible-height gossip. See `P2PConfig::enable_mdns`.
        if let Some(v) = config::resolve("HELIX_P2P_DISABLE_MDNS", &cfg.p2p_disable_mdns) {
            if flag_is_truthy(&v) {
                info!("mDNS LAN discovery disabled — relying on seed peers + peer exchange only");
                p2p_config.enable_mdns = false;
            }
        }

        let p2p_port = p2p_config.listen_addr.port();
        // Captured before `p2p_config` is moved into the service — surfaced via `/status` so
        // syncing peers dial this announced address directly (see `resolve_seed_peer_multiaddr`).
        let p2p_public_addr = p2p_config.public_addr.clone();
        let (p2p_service, p2p_command_tx, p2p_event_rx) = P2PService::new(p2p_config);

        let rpc_bind = resolve_rpc_bind(&cfg)?;

        // Mempool TTL — `mempool_tx_ttl_secs` in helix.toml, or HELIX_MEMPOOL_TX_TTL_SECS;
        // unset means keep Mempool's built-in DEFAULT_TTL.
        let mempool = match config::resolve_u64("HELIX_MEMPOOL_TX_TTL_SECS", cfg.mempool_tx_ttl_secs) {
            Some(secs) => Mempool::with_ttl(std::time::Duration::from_secs(secs)),
            None => Mempool::new(),
        };

        Ok(HelixNode {
            keypair: Arc::new(keypair),
            address,
            reward_address,
            sync_peer,
            store: Arc::new(RwLock::new(store)),
            mempool: Arc::new(RwLock::new(mempool)),
            chain_state: Arc::new(RwLock::new(chain_state)),
            p2p_command_tx,
            p2p_event_rx,
            p2p_service: Some(p2p_service),
            p2p_port,
            p2p_public_addr,
            rpc_bind,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        // Shared peer count for RPC status
        let peer_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let rpc_state = AppState {
            store: self.store.clone(),
            mempool: self.mempool.clone(),
            chain_state: self.chain_state.clone(),
            node_address: self.address.to_string(),
            peer_count: peer_count.clone(),
            p2p_port: self.p2p_port,
            p2p_public_addr: self.p2p_public_addr.clone(),
            p2p_command_tx: self.p2p_command_tx.clone(),
        };

        // Spawn RPC server
        let rpc_bind: SocketAddr = self.rpc_bind;
        info!("RPC bind address  : {}", rpc_bind);
        tokio::spawn(async move {
            start_rpc_server(rpc_state, rpc_bind).await;
        });

        // Spawn P2P service
        let p2p_service = self.p2p_service.take().unwrap();
        tokio::spawn(async move {
            if let Err(e) = p2p_service.run().await {
                error!("P2P service error: {}", e);
            }
        });

        // BFT engine, shared between the block production loop (which drives
        // its own proposals) and the P2P event handler (which folds in votes
        // arriving from other validators against that same active round).
        //
        // Rebuilt from persisted chain state rather than hardcoded, so a restart
        // resumes with the same validator set and epoch the chain already
        // rotated to — not epoch 0 with only this node as validator.
        let genesis_height = self.store.read().await.latest_height();
        let validator_set = {
            let state_guard = self.chain_state.read().await;
            let validators: Vec<Validator> = state_guard
                .stakers()
                .into_iter()
                .map(|(addr, stake)| {
                    let has_personhood = state_guard.has_personhood(&addr);
                    Validator::new(addr, stake, has_personhood)
                })
                .collect();
            drop(state_guard);
            let epoch = genesis_height / helix_consensus::EPOCH_LENGTH;
            if validators.is_empty() {
                // No qualifying stakers recorded yet — fall back to self as sole
                // validator so the chain can still produce blocks.
                let total_stake = 1_000_000_000_000_000u64;
                ValidatorSet::new(vec![Validator::new(self.address.clone(), total_stake, true)], epoch)
            } else {
                ValidatorSet::new(validators, epoch)
            }
        };
        let engine = Arc::new(RwLock::new(BftEngine::new(
            validator_set,
            self.address.clone(),
            genesis_height,
        )));
        // Seed the engine's chain-continuity check with the real tip hash — without
        // this, `validate_block`'s prev_hash check stays silently disabled until this
        // engine's own first `finalize()`, the exact restart window a diverged
        // proposal is most likely to slip through in.
        {
            let tip_hash = self.store.read().await.latest_hash();
            engine.write().await.seed_last_committed(tip_hash);
        }
        // Seed the EIP-1559 base fee the next block must carry, deterministically derived from
        // the persisted chain tip — otherwise a restart resumes at `INITIAL_BASE_FEE_PER_BYTE`
        // and would stamp/expect the wrong base fee for its first produced/validated block,
        // diverging from peers that never restarted. The engine keeps this value out of its own
        // consensus state; the node (which holds the blocks) is the source of truth for it.
        if let Ok(tip) = self.store.read().await.get_block_by_height(genesis_height) {
            publish_base_fee(&engine, &self.mempool, base_fee_for_next_block(&tip)).await;
        }

        // Guards against a genuine race between this node's two independent block-ingestion
        // paths — its own BFT engine reaching quorum (NewProposal/NewVote, in the P2P event
        // task) versus a `NewCommittedBlock` gossip arrival for the *same* height (also in
        // the P2P event task, but interleaved with block_production_loop's separate tokio
        // task) — both of which call `apply_finalized_block`. Each path's own pre-check used
        // a different piece of state (the engine's `current_height` vs. `store.latest_height()`),
        // read *before* actually calling `apply_finalized_block`, with no shared lock held
        // across the gap to the eventual state mutation — so both could observe "not yet
        // applied" and both proceed, double-executing the same block (unconditionally
        // double-minting its block reward, since that mint isn't gated by transaction nonces
        // the way the block's actual transactions mostly are). `apply_finalized_block` now
        // claims a height atomically against this single shared mutex as its first action,
        // regardless of which path called it — see its doc comment.
        let last_applied_height = Arc::new(Mutex::new(genesis_height));

        // Spawn P2P event handler
        let mempool_for_p2p = self.mempool.clone();
        let peer_count_for_p2p = peer_count.clone();
        let store_for_p2p = self.store.clone();
        let chain_state_for_p2p = self.chain_state.clone();
        let engine_for_p2p = engine.clone();
        let keypair_for_p2p = self.keypair.clone();
        let p2p_tx_for_p2p = self.p2p_command_tx.clone();
        let sync_peer_for_p2p = self.sync_peer.clone();
        let last_applied_height_for_p2p = last_applied_height.clone();
        let mut p2p_event_rx = self.p2p_event_rx;
        tokio::spawn(async move {
            while let Some(event) = p2p_event_rx.recv().await {
                handle_p2p_event(
                    event,
                    &mempool_for_p2p,
                    &peer_count_for_p2p,
                    &store_for_p2p,
                    &chain_state_for_p2p,
                    &engine_for_p2p,
                    &keypair_for_p2p,
                    &p2p_tx_for_p2p,
                    &sync_peer_for_p2p,
                    &last_applied_height_for_p2p,
                )
                .await;
            }
        });

        // Periodic RPC catch-up loop — keeps a follower current over the sync peer's HTTP RPC
        // even when the peer's raw P2P port isn't publicly reachable (production runs behind a
        // Cloudflare HTTPS tunnel that only exposes RPC). No-op for a standalone chain (no sync
        // peer) or when P2P already keeps us current (each tick is then just a cheap probe).
        tokio::spawn(rpc_sync_loop(
            self.sync_peer.clone(),
            self.store.clone(),
            self.chain_state.clone(),
            engine.clone(),
            self.mempool.clone(),
            last_applied_height.clone(),
        ));

        // Block production loop
        let block_loop = tokio::spawn(block_production_loop(
            self.store.clone(),
            self.mempool.clone(),
            self.chain_state.clone(),
            self.keypair.clone(),
            engine,
            last_applied_height,
            self.p2p_command_tx.clone(),
            self.reward_address.map(Arc::new),
            peer_count.clone(),
        ));

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received.");
            }
            res = block_loop => {
                if let Err(e) = res { error!("Block loop panicked: {}", e); }
            }
        }

        info!("Helix node stopped.");
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_p2p_event(
    event: P2PEvent,
    mempool: &Arc<RwLock<Mempool>>,
    peer_count: &Arc<std::sync::atomic::AtomicUsize>,
    store: &Arc<RwLock<HelixDb>>,
    chain_state: &Arc<RwLock<ChainState>>,
    engine: &Arc<RwLock<BftEngine>>,
    keypair: &KeyPair,
    p2p_tx: &mpsc::Sender<P2PCommand>,
    sync_peer: &Option<String>,
    last_applied_height: &Arc<Mutex<u64>>,
) {
    match event {
        P2PEvent::NewTransaction(tx) => {
            let (recovery_key, can_pay) = {
                let chain = chain_state.read().await;
                (
                    chain.recovery_key(&tx.from).cloned(),
                    helix_executor::can_pay_fee(&chain, &tx),
                )
            };
            // The same gate the RPC submit path applies. Without it here, the RPC's rate limiter
            // would be the only thing between an unfunded fee claim and the pool — and a peer
            // reaches this path without ever touching the RPC. See `helix_executor::can_pay_fee`.
            if !can_pay {
                warn!(from = %tx.from, fee = tx.fee, "Rejected peer tx: sender cannot pay the declared fee");
                return;
            }
            let mut pool = mempool.write().await;
            match pool.add_with_recovery_key(tx, recovery_key.as_ref()) {
                Ok(()) => {}
                Err(e) => warn!("Rejected peer tx: {}", e),
            }
        }
        P2PEvent::NewProposal(proposal) => {
            let result = { engine.write().await.receive_proposal(keypair, proposal) };

            // receive_proposal() may have cast our prevote (and possibly a
            // follow-up precommit) for the received proposal — broadcast
            // those regardless of outcome, same as the NewVote arm below.
            let outbound = { engine.write().await.take_outbound_votes() };
            for v in outbound {
                let _ = p2p_tx.try_send(P2PCommand::BroadcastVote(v));
            }
            // Report any double-sign evidence this vote processing turned up — see
            // report_double_sign_evidence's doc comment for why this can't just slash
            // directly here.
            let evidence = { engine.write().await.take_evidence() };
            for ev in evidence {
                report_double_sign_evidence(ev, keypair, chain_state, mempool, p2p_tx).await;
            }

            match result {
                Ok(Some(block)) => {
                    info!(height = block.height(), "Block finalized via peer proposal");
                    // `None`, not our own configured reward_address: this block was
                    // proposed by whichever validator's turn it was (see receive_proposal),
                    // not necessarily us. Passing our local override here would redirect
                    // that validator's reward to our own address, and — since reward_address
                    // is a per-node config, not part of the block — make every node compute
                    // a different balance for the same block. `None` lets execute_block fall
                    // back to `block.header.validator`, which is identical on every node.
                    apply_finalized_block(block, true, store, mempool, chain_state, engine, p2p_tx, None, last_applied_height).await;
                }
                Ok(None) => {}
                Err(ConsensusError::UnknownValidator(_)) => {
                    // We're not a validator in the current set — nothing to vote with.
                }
                Err(e) => warn!("Rejected peer proposal: {}", e),
            }
        }
        P2PEvent::NewVote(vote) => {
            let result = { engine.write().await.add_vote(keypair, vote) };

            // add_vote() may itself have cast our own follow-up precommit
            // (see its doc comment) — broadcast that regardless of outcome.
            let outbound = { engine.write().await.take_outbound_votes() };
            for v in outbound {
                let _ = p2p_tx.try_send(P2PCommand::BroadcastVote(v));
            }
            let evidence = { engine.write().await.take_evidence() };
            for ev in evidence {
                report_double_sign_evidence(ev, keypair, chain_state, mempool, p2p_tx).await;
            }

            match result {
                Ok(Some(block)) => {
                    info!(height = block.height(), "Block finalized via peer votes");
                    // Same reasoning as the NewProposal arm above: this block's proposer
                    // isn't necessarily us, so `None` — not our local reward_address.
                    apply_finalized_block(block, true, store, mempool, chain_state, engine, p2p_tx, None, last_applied_height).await;
                }
                Ok(None) => {}
                Err(ConsensusError::NoActiveRound) => {
                    // We're not currently proposing/awaiting votes for any round —
                    // expected whenever this node isn't the proposer this height.
                    debug!("Vote received with no active round — ignored");
                }
                Err(e) => warn!("Rejected peer vote: {}", e),
            }
        }
        P2PEvent::NewCommittedBlock(block) => {
            let our_height = store.read().await.latest_height();
            let block_height = block.height();

            if block_height <= our_height {
                // Already have it — duplicate from gossip, ignore.
                return;
            }

            if block_height > our_height + 1 {
                // Gap detected — we're missing blocks between our_height+1 and block_height-1.
                // Attempt to fill the gap from the configured sync peer (using the RPC sync
                // endpoint on the same host; resolved once at startup from HELIX_SYNC_PEER or
                // helix.toml's `sync_peer` via `config::resolve`, same source as the startup
                // sync in `HelixNode::new`). If unset, we can't fill the gap and will stay
                // behind until the next block arrives.
                warn!(our_height, block_height, "Block gap detected — attempting catch-up sync");
                if let Some(peer_url) = sync_peer {
                    // Hold `last_applied_height` for the whole sync, exactly like
                    // `rpc_sync_loop` does — without it, this path calls `execute_block`
                    // (via `sync_blocks_from_peer`) completely outside the guard that
                    // `apply_finalized_block` checks, so a concurrent BFT-finalize or
                    // another gossip event for the same height(s) can double-mint the
                    // block reward. `sync_blocks_from_peer` itself never touches this
                    // lock, so the re-check under it (`base`) is required, not redundant:
                    // another path may have already caught us up while we waited for it.
                    let mut last = last_applied_height.lock().await;
                    let base = store.read().await.latest_height();
                    if block_height <= base {
                        return; // another path already applied this in the meantime
                    }
                    let result = {
                        let mut s = store.write().await;
                        let mut cs = chain_state.write().await;
                        sync_blocks_from_peer(peer_url, base, &mut s, &mut cs)
                            .await
                            .map(|n| (n, s.latest_height(), s.latest_hash()))
                    };
                    match result {
                        Ok((n, new_height, new_hash)) if n > 0 => {
                            *last = new_height;
                            // This apply bypassed receive_proposal/add_vote and
                            // apply_finalized_block entirely — keep the engine's height
                            // tracking and EIP-1559 base fee in step, same as
                            // rpc_sync_loop does after its own sync_blocks_from_peer call.
                            engine.write().await.sync_to_externally_finalized_block(new_height, new_hash);
                            if let Ok(tip) = store.read().await.get_block_by_height(new_height) {
                                publish_base_fee(engine, mempool, base_fee_for_next_block(&tip)).await;
                            }
                            info!("Gap filled: applied {} blocks", n);
                        }
                        Ok(_) => {}
                        Err(e) => warn!("Gap sync failed: {}", e),
                    }
                }
                return;
            }

            // block_height == our_height + 1: verify proposer sig, then that the
            // signer is actually a member of the current validator set — a
            // self-consistent signature alone only proves the embedded public key
            // matches the declared `validator` address, not that this address holds
            // any stake. Without this check, anyone can generate a free throwaway
            // keypair, self-sign a block for our next height, and gossip it on the
            // public TOPIC_COMMITTED_BLOCKS topic to have it applied here — bypassing
            // BFT quorum entirely and forking us off the real chain.
            match block.header.verify_signature() {
                Ok(()) => {
                    let is_known_validator = {
                        engine.read().await.validator_set().get(&block.header.validator).is_some()
                    };
                    if !is_known_validator {
                        warn!(
                            height = block_height,
                            validator = %block.header.validator,
                            "Committed block from peer signed by an address outside the current validator set — dropping"
                        );
                        return;
                    }
                    // Chain continuity: a validly-signed block from a real validator can
                    // still fail to build on our actual tip (stale round, a validator
                    // building on a different branch, etc.) — applying it anyway would
                    // silently corrupt our chain state instead of just missing a block.
                    let our_tip_hash = store.read().await.latest_hash();
                    if block.header.prev_hash != our_tip_hash {
                        warn!(
                            height = block_height,
                            expected_prev = %our_tip_hash,
                            got_prev = %block.header.prev_hash,
                            "Committed block from peer does not chain from our tip — dropping"
                        );
                        return;
                    }
                    info!(height = block_height, "Applying committed block from peer");
                    // `None`, same reasoning as the NewProposal/NewVote arms above: this
                    // block came from a peer, not our own block_production_loop, so our
                    // local reward_address override must not apply to it.
                    apply_finalized_block(block, false, store, mempool, chain_state, engine, p2p_tx, None, last_applied_height).await;
                }
                Err(e) => {
                    warn!(height = block_height, err = %e, "Committed block from peer failed signature check — dropping");
                }
            }
        }
        P2PEvent::PeerConnected(_) => {
            peer_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        P2PEvent::PeerDisconnected(_) => {
            peer_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Turns locally-detected double-sign evidence into a signed `SubmitDoubleSignEvidence`
/// transaction, adds it to our own mempool, and broadcasts it — so the slash it carries gets
/// applied deterministically once included in a block, through the same transaction-execution
/// path every node already runs identically for every other tx. See that `TxType` variant's
/// doc comment for why detection (node-local, asymmetric — fine) must stay separate from
/// slashing (must be deterministic across all nodes).
///
/// Evidence is self-verifying (both votes carry their own signatures), so submitting it as our
/// own transaction — rather than, say, relaying it verbatim — is just the simplest way to get
/// it into the mempool; any node could equally report evidence anyone else produced.
async fn report_double_sign_evidence(
    evidence: DoubleSignEvidence,
    keypair: &KeyPair,
    chain_state: &Arc<RwLock<ChainState>>,
    mempool: &Arc<RwLock<Mempool>>,
    p2p_tx: &mpsc::Sender<P2PCommand>,
) {
    let self_address = Address::from_public_key(&keypair.public);
    let nonce = {
        let state = chain_state.read().await;
        state.get(&self_address).map(|acc| acc.nonce).unwrap_or(0)
    };

    let data = match bincode::serialize(&evidence) {
        Ok(d) => d,
        Err(e) => {
            warn!(err = %e, "Failed to serialize double-sign evidence — dropping");
            return;
        }
    };

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::SubmitDoubleSignEvidence,
        from: self_address,
        to: None,
        amount: 0,
        fee: DOUBLE_SIGN_EVIDENCE_FEE_NANO,
        nonce,
        data,
        crypto_version: keypair.scheme,
        signature: Signature::from_bytes(vec![]),
        public_key: keypair.public.clone(),
    };
    tx.signature = match keypair.sign(tx.signing_hash().as_bytes()) {
        Ok(sig) => sig,
        Err(e) => {
            warn!(err = %e, "Failed to sign double-sign evidence tx — dropping");
            return;
        }
    };

    warn!(
        validator = %evidence.validator,
        height = evidence.height,
        round = evidence.round,
        "Double-sign evidence detected — reporting on-chain"
    );

    if let Err(e) = mempool.write().await.add(tx.clone()) {
        // Most likely a peer's report of the same incident already made it into our
        // mempool first (same evidence, different reporter) — not an error.
        debug!(err = %e, "Local mempool rejected our own evidence tx");
    }
    let _ = p2p_tx.try_send(P2PCommand::BroadcastTransaction(tx));
}

/// Execute, rotate, broadcast, and persist a block that just reached BFT finality —
/// whether that happened locally (this node cast the deciding vote itself in
/// `block_production_loop`) or via a peer's vote arriving through P2P
/// (`handle_p2p_event`). Both paths must apply identical side effects exactly once.
///
/// `should_broadcast`: set to `true` when this node was part of the consensus round
/// (it knows the correct committed round). Set to `false` when applying a block
/// received via `NewCommittedBlock` — the block has already been broadcast by the
/// proposer, and re-broadcasting with a wrong round tag would confuse other nodes.
/// Deterministically compute the EIP-1559 base fee (nano-HLX per tx byte) the block *after*
/// `block` must carry, from that block's own base fee and total serialized transaction bytes.
/// The floor is `fee::INITIAL_BASE_FEE_PER_BYTE` — empty blocks decay the base fee back down to
/// it. Pure integer arithmetic (see `helix_core::fee::next_base_fee_per_byte`), so every node
/// derives the identical value from the same tip.
fn base_fee_for_next_block(block: &Block) -> u64 {
    let bytes_used: u64 = block.transactions.iter().map(|t| t.size_bytes()).sum();
    helix_core::fee::next_base_fee_per_byte(
        block.header.base_fee_per_byte,
        bytes_used,
        helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
    )
}

/// Publish the next block's base fee to both components that need it: the engine, which stamps
/// it into blocks it proposes and rejects blocks carrying anything else, and the mempool, which
/// refuses transactions that cannot afford it.
///
/// One function rather than two calls at each of the three sites that learn a new base fee
/// (startup from the persisted tip, every commit, RPC catch-up). If the two ever drift apart the
/// pool starts lying about what it will accept — admitting transactions doomed to fail at
/// execution, or turning away ones that would have worked. Keeping them adjacent makes adding a
/// fourth site that updates only one of them the harder thing to do by accident.
async fn publish_base_fee(
    engine: &Arc<RwLock<BftEngine>>,
    mempool: &Arc<RwLock<Mempool>>,
    base_fee_per_byte: u64,
) {
    engine.write().await.set_base_fee_per_byte(base_fee_per_byte);
    mempool.write().await.set_base_fee_per_byte(base_fee_per_byte);
}

#[allow(clippy::too_many_arguments)]
async fn apply_finalized_block(
    block: Block,
    should_broadcast: bool,
    store: &Arc<RwLock<HelixDb>>,
    mempool: &Arc<RwLock<Mempool>>,
    chain_state: &Arc<RwLock<ChainState>>,
    engine: &Arc<RwLock<BftEngine>>,
    p2p_tx: &mpsc::Sender<P2PCommand>,
    reward_address: Option<Arc<Address>>,
    last_applied_height: &Arc<Mutex<u64>>,
) {
    let tx_hashes: Vec<_> = block.transactions.iter().map(|t| t.hash()).collect();
    let height = block.height();
    let tx_count = block.tx_count();
    // EIP-1559: the base fee the *next* block must carry, derived from this one's fullness.
    // Captured here while `block` is still owned (it's moved into `put_block` below); applied to
    // the engine only after the block actually persists, so a failed persist never advances it.
    let next_base_fee = base_fee_for_next_block(&block);

    // Atomically claim this height before doing anything else. This node's own BFT engine
    // reaching quorum (NewProposal/NewVote) and a `NewCommittedBlock` gossip arrival for the
    // *same* height run as genuinely concurrent tokio tasks, and each call site's own
    // pre-check reads different state (the engine's `current_height` vs.
    // `store.latest_height()`) *before* ever calling this function — with no lock held across
    // that gap to the actual state mutation below, both could observe "not yet applied" and
    // both proceed. Without this guard that race double-executes the block.
    //
    // Its transactions survive that: each one in an applied block has moved its sender's nonce —
    // success and charged failure alike — so `execute_transaction`'s intrinsic gate refuses every
    // one of them before dispatch, charging nothing. That is a property of the fee semantics
    // rather than of this guard, and it only became true once a failing transaction started
    // paying; before that the nonce stayed put and a replay could genuinely re-run it, with
    // `execute_call_contract` re-charging its fee as the sharpest case. The executor test
    // `re_executing_a_block_replays_no_transaction_but_does_mint_again` pins this down.
    //
    // The block reward is why the guard has to exist regardless: nothing gates it — no nonce, no
    // sender — so a second application mints it again and silently inflates supply beyond what
    // the schedule intends. Found by noticing a small, fixed (non-growing) `circulating_supply`
    // divergence between two nodes that otherwise agreed on every block hash — same symptom
    // `ChainState::state_hash()` exists to surface, but this particular cause is a
    // P2P/executor-boundary race, not a state-machine bug, so the fix belongs here rather than
    // in `helix-executor`.
    {
        let mut last = last_applied_height.lock().await;
        if height <= *last {
            debug!(height, "Skipping duplicate finalized-block application (already applied via a concurrent path)");
            return;
        }
        *last = height;
    }

    // `should_broadcast == false` means this block arrived already fully committed
    // (the NewCommittedBlock gossip topic) rather than through this node's own
    // receive_proposal/add_vote — those already advanced the engine's current_height
    // internally via finalize() before returning Ok(Some(block)), so only the
    // committed-block fast path needs this explicit sync. See
    // sync_to_externally_finalized_block's doc comment for why skipping this
    // silently desyncs the engine from the actual chain tip.
    if !should_broadcast {
        engine.write().await.sync_to_externally_finalized_block(height, block.hash());
    }

    // Execute transactions. The per-tx receipts are kept and persisted below: they are the only
    // record of whether a committed transaction did anything, and warning about the count in the
    // log while dropping them left `hlx tx status`, the explorer and Spark all reporting a
    // rejected transfer as `confirmed`.
    let tx_receipts = {
        let mut state = chain_state.write().await;
        let receipt = execute_block(&mut state, &block, reward_address.as_deref());
        if receipt.failed_txs() > 0 {
            warn!(height, failed = receipt.failed_txs(), "Tx execution failures");
        }
        // Not a protocol-level state root (not in BlockHeader, not signed, doesn't gate
        // consensus) — a diagnostic escape hatch. If two nodes' logs ever show different
        // state_hash values at the same height, something has silently diverged; grep for
        // it. Also served live via GET /status (NodeStatus::state_hash) for tooling that
        // wants to compare running nodes without trawling logs. See ChainState::state_hash's
        // doc comment for exactly what this is and isn't.
        debug!(height, state_hash = %state.state_hash().to_hex(), "Block applied");
        receipt.tx_receipts
    };

    // Double-sign slashing does NOT happen here. It used to: this function unconditionally
    // drained engine.take_evidence() and slashed directly. But pending_evidence is per-node,
    // local, live-BFT-vote-processing state — a node that only received this block passively
    // (P2P gossip or sync, see the NewCommittedBlock arm below and sync_blocks_from_peer) never
    // accumulates it, so some validators slashed while others silently didn't: a state fork,
    // undetectable by anything CONSENSUS-LEVEL, since BlockHeader still carries no state_root
    // (ChainState::state_hash above is an operator-facing diagnostic, not a protocol check).
    // Evidence is now reported via a `SubmitDoubleSignEvidence` transaction (see
    // `report_double_sign_evidence`, called wherever the engine can produce evidence) and
    // slashed inside `execute_block` above, through the same transaction-execution path
    // every node already runs identically.

    // Immediately jail any validator whose double-sign slash just landed in this block,
    // instead of leaving them at full, stale voting power until the next epoch rotation
    // (up to EPOCH_LENGTH blocks / ~3.3 min away at BLOCK_TIME_MS). Scans the block's own transactions —
    // rather than engine.take_evidence(), which is per-node/asymmetric — so every node
    // reaches the identical jailing decision, matching the deterministic slash itself:
    // membership in `slashed_double_sign_incidents` is only ever true after the incident
    // was independently signature-verified inside execute_submit_double_sign_evidence, so
    // a forged evidence tx naming an innocent validator can't trigger a jail here either.
    {
        let state = chain_state.read().await;
        for tx in &block.transactions {
            if tx.tx_type != TxType::SubmitDoubleSignEvidence {
                continue;
            }
            let Ok(evidence) = bincode::deserialize::<DoubleSignEvidence>(&tx.data) else {
                continue;
            };
            let incident_key = format!("{}:{}:{}", evidence.validator, evidence.height, evidence.round);
            if state.slashed_double_sign_incidents.contains(&incident_key)
                && engine.write().await.validator_set.remove(&evidence.validator)
            {
                warn!(
                    validator = %evidence.validator,
                    height,
                    "Validator jailed immediately after double-sign slash — excluded from BFT rounds from here on, not just at the next epoch rotation"
                );
            }
        }
    }

    // Epoch boundary: rebuild the validator set from current stake.
    // Personhood is read from chain state: ZK-STARK ProvePersonhood txs set
    // PersonhoodStatus::Verified, which unlocks the 1% voting-power cap
    // (instead of the 0.5% cap for unverified validators).
    if height % helix_consensus::EPOCH_LENGTH == 0 {
        let previously_active: std::collections::HashSet<Address> = {
            engine.read().await.validator_set().validators.iter().map(|v| v.address.clone()).collect()
        };
        let mut state_guard = chain_state.write().await;
        // A `Stake` tx alone would otherwise be enough to become quorum-critical the moment
        // this rotation hits, with no online-check and no warning — see
        // `pending_validators`' doc comment. New entrants sit out this rotation instead of
        // joining `validators` below; still-current members are never delayed.
        let activated = state_guard.stakers_after_delayed_activation(&previously_active);
        let deferred: Vec<Address> = state_guard.pending_validators.iter().cloned().collect();
        let validators: Vec<Validator> = activated
            .into_iter()
            .map(|(addr, stake)| {
                let has_personhood = state_guard.has_personhood(&addr);
                Validator::new(addr, stake, has_personhood)
            })
            .collect();
        drop(state_guard);
        for addr in &deferred {
            warn!(
                height,
                validator = %addr,
                "New stake crossed the validator threshold — held out of the active set until \
                 the next epoch rotation (~{} blocks) instead of becoming quorum-critical \
                 immediately; make sure this validator's node is actually running and \
                 connected before then",
                helix_consensus::EPOCH_LENGTH
            );
        }
        let had = validators.len();
        let mut eng = engine.write().await;
        eng.rotate_validator_set(validators);
        if had > 0 {
            info!(height, epoch = eng.validator_set().epoch, validators = had, "Validator set rotated");
        } else {
            // rotate_validator_set() is a deliberate no-op on an empty candidate list —
            // switching to zero validators would halt block production entirely, so the
            // previous (stale) validator set stays active instead. That keeps the chain
            // alive but means every validator that fully unstaked and claimed still holds
            // their pre-exit voting power indefinitely, with nothing else in the system
            // ever surfacing that fact. This is the only place that can detect it, so warn
            // loudly instead of the previous silence.
            warn!(
                height,
                epoch = eng.validator_set().epoch,
                "Epoch rotation skipped — no accounts meet min_validator_stake; \
                 the previous validator set (and its now-stale voting power) remains active"
            );
        }
    }

    // Only the node that participated in consensus knows the correct committed round
    // and can broadcast a semantically correct Proposal. Nodes that received the block
    // via NewCommittedBlock skip re-broadcasting to avoid flooding with wrong round tags.
    if should_broadcast {
        let round = engine.read().await.last_committed_round().unwrap_or(0);
        let _ = p2p_tx.try_send(P2PCommand::BroadcastProposal(Proposal::fresh(round, block.clone())));
        let _ = p2p_tx.try_send(P2PCommand::BroadcastBlock(block.clone()));
    }

    // Persist block + chain state to the same redb file, under one write lock.
    {
        let mut s = store.write().await;
        if let Err(e) = s.put_block(block) {
            error!("Failed to store block {}: {}", height, e);
            return;
        }
        // A block whose receipts failed to write is still a valid block — the chain is not held
        // up for it. Their absence reads as `unknown` at the RPC, never as success.
        if let Err(e) = s.put_receipts(&tx_receipts) {
            error!("Failed to store receipts for block {}: {}", height, e);
        }
        let state = chain_state.read().await;
        if let Err(e) = s.save_chain_state(&state) {
            error!("Failed to persist chain state at height {}: {}", height, e);
        }
    }

    // Advance the EIP-1559 base fee now that this block is committed: the next block produced
    // or validated by this node must carry `next_base_fee`. Both ingestion paths funnel through
    // here, so the engine's expected base fee stays in lockstep with the persisted tip.
    publish_base_fee(engine, mempool, next_base_fee).await;

    { mempool.write().await.remove_committed(&tx_hashes); }

    if tx_count > 0 {
        info!(height, tx_count, "Block committed");
    }
}

#[allow(clippy::too_many_arguments)]
async fn block_production_loop(
    store: Arc<RwLock<HelixDb>>,
    mempool: Arc<RwLock<Mempool>>,
    chain_state: Arc<RwLock<ChainState>>,
    keypair: Arc<KeyPair>,
    engine: Arc<RwLock<BftEngine>>,
    last_applied_height: Arc<Mutex<u64>>,
    p2p_tx: mpsc::Sender<P2PCommand>,
    reward_address: Option<Arc<Address>>,
    peer_count: Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(BLOCK_TIME_MS));

    // One-time startup gate: in a multi-validator set, don't produce the very first
    // block until enough peers are connected AND the gossip mesh has had a few ticks
    // to finish grafting + exchanging topic subscriptions. A proposal or vote
    // published into a half-formed mesh is silently dropped by the peers it hasn't
    // meshed with yet — and gossipsub won't re-publish an identical (already-seen)
    // message, so those first-round votes are simply lost forever and round 0 never
    // reaches quorum. Waiting out the mesh makes the first round's delivery as
    // reliable as every later round's. Single-validator sets need 0 peers, so this
    // passes through immediately and the live devnet is unaffected.
    let mut mesh_ready = false;
    let mut settle_ticks_left: u32 = MESH_SETTLE_TICKS;

    loop {
        interval.tick().await;

        if !mesh_ready {
            let needed = engine.read().await.peers_needed_for_quorum();
            if needed == 0 {
                mesh_ready = true;
            } else if peer_count.load(std::sync::atomic::Ordering::Relaxed) < needed {
                if !engine.write().await.note_peer_wait_tick() {
                    continue; // still waiting for enough validators to connect
                }
                // Past PEER_WAIT_TIMEOUT_TICKS — a validator that never connects at all
                // would otherwise hold this node here forever (this gate runs before the
                // has_active_round loop's own peer-wait checks even see a tick). Nothing to
                // settle for a mesh that was never formed, so skip the settle-tick wait too.
                mesh_ready = true;
            } else {
                engine.write().await.reset_peer_wait();
                if settle_ticks_left > 0 {
                    settle_ticks_left -= 1;
                    continue; // peers here — let the mesh settle before first use
                } else {
                    mesh_ready = true;
                }
            }
        }

        // A round from a previous tick is still awaiting peer votes — don't
        // clobber it with a brand-new proposal (different timestamp/hash) for
        // the same height, which would orphan any votes peers already cast
        // against the original proposal. Give it a few more ticks before
        // concluding it's stalled (e.g. the proposer went offline, or its
        // block failed validation for enough peers that quorum can never be
        // reached) and forcing it to the next round via `advance_round`.
        let stalled = if engine.read().await.has_active_round() {
            // Re-broadcast our pending proposal every tick so a validator that
            // connected *after* we first proposed can still receive and vote on
            // it. Critical at cold start, where the round's proposer is up and
            // proposing before the other validators have finished joining —
            // without this they'd never see the one proposal that was sent once,
            // before they connected. Idempotent: a peer already tracking this
            // round ignores the duplicate (see `receive_proposal`).
            let pending = { engine.read().await.pending_proposal_envelope() };
            if let Some(proposal) = pending {
                let _ = p2p_tx.try_send(P2PCommand::BroadcastProposal(proposal));
            }

            // Hold the round instead of advancing while fewer than a quorum's
            // worth of other validators are connected. Burning through rounds
            // while under-connected just runs this node ahead of validators that
            // will (re)join at round 0, into a round they'll never reach back —
            // the exact cold-start desync that otherwise stalls a multi-validator
            // chain at height 1 forever. A single-validator set needs 0 peers, so
            // this never gates production on the live devnet.
            //
            // Bounded, not indefinite: a validator that never (re)connects at all —
            // no P2P peer, so `note_round_tick`'s own timeout/liveness-jail machinery
            // never even runs — would otherwise hold this node here forever. Past
            // `PEER_WAIT_TIMEOUT_TICKS`, stop waiting and tick anyway; see
            // `note_peer_wait_tick`'s doc comment.
            if peer_count.load(std::sync::atomic::Ordering::Relaxed)
                < engine.read().await.peers_needed_for_quorum()
            {
                if !engine.write().await.note_peer_wait_tick() {
                    continue;
                }
            } else {
                engine.write().await.reset_peer_wait();
            }

            let timed_out = { engine.write().await.note_round_tick(&keypair) };
            // This tick may have cast a nil prevote (`PROPOSAL_TIMEOUT_TICKS`). Send it now:
            // the drain at the end of the loop body is unreachable from the `continue` below,
            // and a nil prevote that never leaves this node can't be tallied by anyone, so
            // nil quorum — the whole point of casting it — could never form.
            broadcast_outbound_votes(&engine, &p2p_tx).await;
            if !timed_out {
                continue;
            }
            true
        } else {
            // No active round: either we're this round's proposer (produce_block below makes
            // the round) or we're a non-proposer waiting for someone else's proposal. In the
            // latter case nothing else runs the round clock — so if that round's proposer is
            // dead/offline the height would stall forever. Run the timeout here too and, when
            // it fires, advance to the next round (a different, hopefully live proposer). Only
            // meaningful in a multi-validator set; a sole validator (peers_needed == 0) always
            // proposes and never waits, so it skips this and produce_block finalizes as before.
            let needed = engine.read().await.peers_needed_for_quorum();
            let under_connected =
                peer_count.load(std::sync::atomic::Ordering::Relaxed) < needed;
            if needed == 0 {
                false
            } else if under_connected && !engine.write().await.note_peer_wait_tick() {
                // Under-connected — don't burn rounds getting ahead of validators still
                // joining at round 0 (the same guard the active-round branch applies).
                // Bounded the same way: see `note_peer_wait_tick`'s doc comment.
                continue;
            } else {
                if !under_connected {
                    engine.write().await.reset_peer_wait();
                }
                let timed_out = { engine.write().await.note_round_tick(&keypair) };
                // Same reason as the active-round branch: a nil prevote cast here has to go
                // out this tick. (This branch falls through to the end-of-body drain rather
                // than `continue`ing, but draining twice is free — the second is empty.)
                broadcast_outbound_votes(&engine, &p2p_tx).await;
                timed_out
            }
        };

        let txs = { mempool.write().await.take(MAX_TXS_PER_BLOCK) };
        let prev_hash = store.read().await.latest_hash();

        let produced = if stalled {
            engine.write().await.advance_round(&keypair, prev_hash, txs)
        } else {
            engine.write().await.produce_block(&keypair, prev_hash, txs)
        };
        match produced {
            Ok(block) => {
                apply_finalized_block(block, true, &store, &mempool, &chain_state, &engine, &p2p_tx, reward_address.clone(), &last_applied_height)
                    .await;
            }
            Err(ConsensusError::AwaitingVotes { .. }) => {
                // Multi-validator: our proposal + own votes are cast, round is
                // stored in the engine. Broadcast the proposal itself so
                // peers can validate it and cast their own votes — the votes
                // below only cover this node's own prevote/precommit.
                let proposal = { engine.read().await.pending_proposal_envelope() };
                if let Some(proposal) = proposal {
                    let _ = p2p_tx.try_send(P2PCommand::BroadcastProposal(proposal));
                }
            }
            Err(ConsensusError::NotProposer { .. }) => {
                // Expected every tick for non-proposer validators, and for a
                // deferring validator right after a round timeout — wait for
                // the actual proposer's Proposal to arrive over P2P instead.
            }
            Err(ConsensusError::NoActiveRound) => {
                // Benign race: a peer vote arriving via handle_p2p_event
                // finalized the stalled round between our timeout check and
                // this call. The height already advanced normally.
            }
            Err(e) => warn!("Block production failed: {}", e),
        }

        // Broadcast any votes this node cast this tick (own prevote/precommit
        // from produce_block) so other validators can fold them into their
        // VoteSets.
        broadcast_outbound_votes(&engine, &p2p_tx).await;
        // Report any double-sign evidence this tick's produce_block/advance_round
        // turned up (e.g. a stalled round's accumulated evidence).
        let evidence = { engine.write().await.take_evidence() };
        for ev in evidence {
            report_double_sign_evidence(ev, &keypair, &chain_state, &mempool, &p2p_tx).await;
        }
    }
}

/// Drain the votes this node has cast but not yet sent, and gossip them to the other
/// validators. Safe to call more than once per tick — the second call finds an empty queue.
async fn broadcast_outbound_votes(
    engine: &Arc<RwLock<BftEngine>>,
    p2p_tx: &mpsc::Sender<P2PCommand>,
) {
    let outbound = { engine.write().await.take_outbound_votes() };
    for vote in outbound {
        let _ = p2p_tx.try_send(P2PCommand::BroadcastVote(vote));
    }
}

/// Download and apply all blocks from a peer node that this node is missing.
///
/// Fetches blocks in batches of 200 from `peer_url/sync/blocks?from=X&count=200`,
/// verifies each block's proposer signature (same check as the P2P committed-block
/// path in `handle_p2p_event`), applies it through `execute_block`, and persists it
/// to `store`.
///
/// `sync_peer` is operator-configured and generally trusted, but since Docker
/// deployments let external validator operators point it at a peer outside their
/// own trust domain, a compromised or misconfigured peer could otherwise feed in
/// unsigned or forged blocks. On the first block that fails signature verification,
/// sync stops immediately — blocks applied before it stay applied and persisted
/// (chain state is saved before returning), nothing already-valid is rolled back,
/// but nothing after the bad block is trusted either.
///
/// Fetch `peer_url`'s actual genesis block (height 0), the `personhood_authorities` it was
/// built with, and its current `governance_params`, so a fresh node can adopt them verbatim
/// instead of self-signing its own incompatible genesis (see the call site in
/// `HelixNode::new` for why that matters) or assuming today's hardcoded compile-time
/// defaults, which can silently drift from what this specific chain's real genesis actually
/// used (e.g. `MIN_VALIDATOR_STAKE` changing in source code after a long-running testnet's
/// genesis already locked in a different value) — found the same way as the genesis-adoption
/// gap itself: a freshly re-synced node rejecting real historical blocks as coming from an
/// "unstaked" validator that has, in fact, been staked above the true (lower) threshold since
/// block 106.
/// Everything a peer's `GET /genesis` tells us about the chain it launched, i.e. everything
/// needed to rebuild that exact genesis state locally. Every field here is one that cannot be
/// re-derived from the genesis block alone, and — just as importantly — must not be taken from
/// this node's own compile-time defaults, which describe how a *new* chain would launch today,
/// not how *this* chain launched.
struct PeerGenesis {
    block: Block,
    personhood_authorities: Vec<PublicKey>,
    governance_params: GovernanceParams,
    extra_validators: Vec<(Address, u64)>,
    validator_stake: u64,
    allocations: Vec<(Address, u64)>,
    /// The hash the peer's genesis state has. `None` from a peer too old to report it — see
    /// `verify_genesis_reconstruction`.
    state_hash: Option<String>,
}

async fn fetch_genesis_from_peer(peer_url: &str) -> Result<PeerGenesis> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let resp: serde_json::Value = client
        .get(format!("{}/genesis", peer_url.trim_end_matches('/')))
        .send()
        .await?
        .json()
        .await?;
    let block: Block = serde_json::from_value(
        resp.get("block")
            .cloned()
            .context("peer's /genesis response is missing \"block\"")?,
    )
    .context("peer's /genesis \"block\" did not deserialize as a Block")?;
    let personhood_authorities = resp
        .get("personhood_authorities")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|hex| PublicKey::from_hex(hex).ok())
                .collect()
        })
        .unwrap_or_default();
    let governance_params: GovernanceParams = match resp.get("governance_params").cloned() {
        Some(v) => serde_json::from_value(v)
            .context("peer's /genesis \"governance_params\" did not deserialize")?,
        None => GovernanceParams::default(),
    };
    let extra_validators = resp
        .get("extra_validators")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    let address = Address::from_str(entry.get("address")?.as_str()?).ok()?;
                    let stake = entry.get("stake_nano")?.as_u64()?;
                    Some((address, stake))
                })
                .collect()
        })
        .unwrap_or_default();
    // A peer too old to report this leaves us no better source than our own default — the same
    // position every node was in before this field existed. Falling back keeps such a peer
    // syncable instead of refusing to join it; it is only correct as long as that chain did
    // launch on the default, which is exactly the case for every chain predating this field.
    let validator_stake = resp
        .get("validator_stake_nano")
        .and_then(|v| v.as_u64())
        .unwrap_or(VALIDATOR_GENESIS_STAKE_HLX * NANO_PER_HLX);
    // A peer too old to report these is one whose chain launched before the field existed, and
    // `GENESIS_PREFUND` has been empty for far longer than that — so an absent list really does
    // mean "no liquid genesis balances", not "unknown".
    let allocations = resp
        .get("allocations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    let address = Address::from_str(entry.get("address")?.as_str()?).ok()?;
                    let balance = entry.get("balance_nano")?.as_u64()?;
                    Some((address, balance))
                })
                .collect()
        })
        .unwrap_or_default();
    let state_hash = resp.get("state_hash").and_then(|v| v.as_str()).map(str::to_string);
    Ok(PeerGenesis {
        block,
        personhood_authorities,
        governance_params,
        extra_validators,
        validator_stake,
        allocations,
        state_hash,
    })
}

/// Refuse to join a chain whose genesis this node cannot reproduce.
///
/// Everything genesis needs that isn't in the genesis block travels over `GET /genesis` — but
/// only the fields anyone thought to send. Whatever the peer *doesn't* mention, this node fills
/// in from its own constants: `TOTAL_SUPPLY_HLX`, and any field genesis grows in the future. A
/// binary that disagrees about one of those builds a different ledger from the same blocks and
/// has no way to notice.
///
/// It is not a theoretical concern. Syncing the live chain on 2026-07-16, the published v1.4.0
/// binary — which predates the genesis stake being transmitted at all — rebuilt genesis from its
/// own `VALIDATOR_GENESIS_STAKE_HLX = 1_000_000` against a chain that launched with 100_000. It
/// applied all 2,253 blocks without an error and then reported 1,002,252 HLX in circulation
/// where 202,252 exist: 800,000 HLX conjured, served over RPC as fact.
///
/// Comparing hashes turns that into a refusal to start. A peer too old to send one leaves us
/// where we were before it existed — no check possible — so we warn rather than refuse, since
/// refusing would make a new node unable to join a chain of older ones.
fn verify_genesis_reconstruction(peer_genesis: &PeerGenesis, local: &ChainState) -> Result<()> {
    let Some(expected) = peer_genesis.state_hash.as_deref() else {
        warn!(
            "Sync peer did not report a genesis state hash — it predates the check. Cannot verify \
             that this node rebuilt the same genesis; a mismatch would go unnoticed."
        );
        return Ok(());
    };
    let ours = local.state_hash().to_hex();
    if ours == expected {
        info!(genesis_state_hash = %ours, "Genesis reconstruction matches the peer's");
        return Ok(());
    }
    bail!(
        "refusing to join: this node rebuilt a different genesis than the chain it is joining \
         (ours {ours}, peer's {expected}). Every block would apply cleanly on top of the wrong \
         ledger and every balance this node reports would be wrong, silently. This build \
         disagrees with the chain about something genesis depends on — most likely it is older \
         than the chain's format. Use a build matching the network."
    )
}

/// Resolves a `sync_peer` HTTP URL (e.g. `http://seed:8545`) to a dialable libp2p multiaddr
/// for that same peer, by asking it (via `GET /status`) which port it listens on for P2P —
/// see the call site in `HelixNode::new` for why this exists instead of relying on mDNS
/// alone. Best-effort by design: every caller treats a failure here as "fall back to
/// mDNS-only", never as fatal, since a peer running an older build without `p2p_port` in its
/// `/status` response should still be syncable, just without this extra connectivity path.
async fn resolve_seed_peer_multiaddr(peer_url: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(peer_url)
        .with_context(|| format!("invalid sync peer URL: {}", peer_url))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("sync peer URL has no host: {}", peer_url))?
        .to_string();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let status: serde_json::Value = client
        .get(format!("{}/status", peer_url.trim_end_matches('/')))
        .send()
        .await?
        .json()
        .await?;

    seed_multiaddr_from_status(&status, &host)
}

/// Pure `/status` → dialable multiaddr mapping, split out so it can be unit-tested without a
/// live HTTP peer (see `resolve_seed_peer_multiaddr` for the fetch around it).
///
/// Prefers the peer's *announced* public multiaddr (`p2p_public_addr`) if it has one. A node
/// behind an HTTPS proxy / Cloudflare tunnel is reachable only over a WebSocket on a different
/// host+port than its raw TCP `p2p_port` (e.g. `/dns4/p2p.silvra.net/tcp/443/tls/ws` while its
/// RPC host is `helix.silvra.net`) — a fact the raw-TCP derivation below cannot reconstruct,
/// since it reuses the RPC host and the raw port. Dialing the derived raw-TCP address for such
/// a peer just burns a ~20 s connection timeout on every (re)connect before the WebSocket seed
/// is tried. Using the announced address avoids that and needs no separate seed config. Trust
/// is unchanged: this peer already serves our genesis + history, and the P2P Noise handshake
/// authenticates whoever we reach regardless of the address we dial. Falls back to the raw-TCP
/// form for a peer that announces nothing (the common open-node case) or runs an older build
/// whose `/status` has no `p2p_public_addr` field at all.
fn seed_multiaddr_from_status(status: &serde_json::Value, host: &str) -> Result<String> {
    if let Some(public_addr) = status
        .get("p2p_public_addr")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        return Ok(public_addr.to_string());
    }

    let p2p_port = status
        .get("p2p_port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("peer's /status has no p2p_port field (older version?)"))?;

    Ok(format!("/{}/{host}/tcp/{p2p_port}", multiaddr_kind(host)))
}

/// Ask a peer (`GET /status`) for its current chain height. Cheap, lock-free probe used by
/// [`rpc_sync_loop`] to decide whether the peer is ahead before taking any write locks.
async fn fetch_peer_height(client: &reqwest::Client, peer_url: &str) -> Result<u64> {
    let status: serde_json::Value = client
        .get(format!("{}/status", peer_url.trim_end_matches('/')))
        .send()
        .await?
        .json()
        .await?;
    status
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("peer's /status has no height field"))
}

/// Periodic RPC catch-up: pull any blocks the sync peer has beyond our tip over plain HTTP,
/// on a fixed interval, independent of P2P gossip.
///
/// libp2p gossip is the primary way a node stays current, but it needs the peer's raw P2P
/// port to be reachable. The production node is served through a Cloudflare HTTPS tunnel that
/// only exposes its RPC (not the raw libp2p TCP port), so a freshly downloaded follower would
/// otherwise fetch history once at startup and then never see another block. This loop closes
/// that gap over the one channel that *is* publicly reachable — the same RPC endpoint used for
/// startup sync — so "download a node → it follows the live chain" holds even with no P2P
/// connectivity at all. When P2P *is* reachable, gossip keeps the node current between polls
/// and each tick is just one cheap height probe that finds nothing new.
///
/// Race-safe with the P2P/BFT apply path: it claims the shared `last_applied_height` guard
/// (the same one `apply_finalized_block` uses) across the whole apply, so the two never
/// double-apply a height — see `apply_finalized_block`'s doc comment for that race.
async fn rpc_sync_loop(
    sync_peer: Option<String>,
    store: Arc<RwLock<HelixDb>>,
    chain_state: Arc<RwLock<ChainState>>,
    engine: Arc<RwLock<BftEngine>>,
    mempool: Arc<RwLock<Mempool>>,
    last_applied_height: Arc<Mutex<u64>>,
) {
    let Some(peer_url) = sync_peer else {
        return; // standalone chain (HELIX_NEW_CHAIN) — nothing to catch up from
    };
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Could not build RPC sync client — periodic catch-up disabled: {e}");
            return;
        }
    };

    let mut ticker = tokio::time::interval(Duration::from_secs(RPC_SYNC_POLL_SECS));
    // The first tick fires immediately; skip missed ticks rather than bursting to catch up.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        // Lock-free pre-check: is the peer actually ahead of us? When caught up (the common
        // case) this is the only work a tick does — no locks taken, no state touched.
        let peer_height = match fetch_peer_height(&client, &peer_url).await {
            Ok(h) => h,
            Err(e) => {
                debug!("Periodic RPC sync: peer height probe failed: {e}");
                continue;
            }
        };
        if peer_height <= store.read().await.latest_height() {
            continue;
        }

        // Peer is ahead — apply under the shared height guard so a concurrent P2P/BFT apply
        // for the same height can't double-execute it.
        let mut last = last_applied_height.lock().await;
        let base = store.read().await.latest_height();
        if peer_height <= base {
            continue; // another path already caught us up while we waited for the lock
        }

        let result = {
            let mut s = store.write().await;
            let mut cs = chain_state.write().await;
            sync_blocks_from_peer(&peer_url, base, &mut s, &mut cs)
                .await
                .map(|n| (n, s.latest_height(), s.latest_hash()))
        };
        match result {
            Ok((applied, new_height, new_hash)) if applied > 0 => {
                *last = new_height;
                // Keep the BFT engine's own height tracking in step — this apply bypassed
                // receive_proposal/add_vote, exactly like the NewCommittedBlock fast path.
                engine
                    .write()
                    .await
                    .sync_to_externally_finalized_block(new_height, new_hash);
                // Refresh the EIP-1559 base fee from the freshly-synced tip too — this apply
                // bypassed apply_finalized_block, so without this the engine would keep a stale
                // base fee and stamp/validate the wrong value for its next block.
                if let Ok(tip) = store.read().await.get_block_by_height(new_height) {
                    publish_base_fee(&engine, &mempool, base_fee_for_next_block(&tip)).await;
                }
                info!(
                    applied,
                    height = new_height,
                    "Periodic RPC catch-up: pulled new blocks from the sync peer"
                );
            }
            Ok(_) => {}
            Err(e) => warn!("Periodic RPC catch-up failed: {e}"),
        }
    }
}

/// Distinguishes literal IPs from hostnames/domains so a `sync_peer` set to a real domain
/// (not just an IP or "localhost") still produces a multiaddr libp2p can dial and resolve.
fn multiaddr_kind(host: &str) -> &'static str {
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        "ip4"
    } else if host.parse::<std::net::Ipv6Addr>().is_ok() {
        "ip6"
    } else {
        "dns4"
    }
}

/// Skips genesis (height 0) — either loaded from this node's own existing data or, for a
/// genuinely fresh node, adopted from this same peer via `fetch_genesis_from_peer` before
/// this function is ever called.
/// Returns the number of blocks successfully applied.
async fn sync_blocks_from_peer(
    peer_url: &str,
    local_tip: u64,
    store: &mut HelixDb,
    chain_state: &mut ChainState,
) -> Result<u64> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut from = local_tip + 1;
    let mut total_applied = 0u64;
    // Tracks the hash each next block must chain from — starts at our current tip
    // and advances to the just-applied block's own hash after each iteration.
    let mut expected_prev_hash = store.latest_hash();

    loop {
        let url = format!("{}/sync/blocks?from={}&count=200", peer_url.trim_end_matches('/'), from);
        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("peer returned HTTP {}", resp.status());
        }
        let blocks: Vec<Block> = resp.json().await?;
        if blocks.is_empty() {
            break; // caught up
        }
        for block in &blocks {
            let h = block.height();
            if let Err(e) = block.header.verify_signature() {
                store.save_chain_state(chain_state)?;
                anyhow::bail!(
                    "block {} from sync peer failed signature verification ({}) — \
                     aborting sync, {} block(s) already applied",
                    h,
                    e,
                    total_applied
                );
            }
            // A self-consistent signature only proves the embedded public key matches
            // the declared `validator` address, not that this address held any stake
            // at the time. Check it against the stakers recorded in `chain_state` as
            // of the block directly before this one (i.e. right after the previous
            // iteration's `execute_block` applied any staking txs) — same gap as the
            // one just closed in `handle_p2p_event`'s `NewCommittedBlock` arm, but
            // reachable via a compromised/MITM'd sync peer instead of public gossip.
            //
            // `chain_state.stakers().is_empty()` mirrors the exact bootstrap fallback
            // every node's own BFT engine already applies before anyone has ever staked
            // (see `HelixNode::run`'s "no qualifying stakers yet — fall back to self as
            // sole validator" branch): that fallback validator never appears in
            // `chain_state.stakers()`, since it was never established via an on-chain
            // `Stake` tx, so without this the *very first* synced block (and every one
            // before the network's first `Stake` tx) would always fail this check —
            // sync could never get past block 1, for any node, ever. Found by actually
            // wiping a node's data and trying to resync it from scratch: it re-derived
            // its own solo genesis fallback instead, forking itself off the real chain
            // block by block. Once real stake exists, this reduces to the strict
            // membership check exactly as before.
            let is_known_validator = chain_state.stakers().is_empty()
                || chain_state
                    .stakers()
                    .iter()
                    .any(|(addr, _)| addr == &block.header.validator);
            if !is_known_validator {
                store.save_chain_state(chain_state)?;
                anyhow::bail!(
                    "block {} from sync peer signed by an address outside the current \
                     validator set — aborting sync, {} block(s) already applied",
                    h,
                    total_applied
                );
            }
            // Chain continuity: a validly-signed block from a real validator can still
            // fail to build on the block we just applied (peer serving a different
            // branch, a stale/reordered batch, etc.) — applying it anyway would splice
            // an unrelated block into our chain instead of just failing the sync.
            if block.header.prev_hash != expected_prev_hash {
                store.save_chain_state(chain_state)?;
                anyhow::bail!(
                    "block {} from sync peer does not chain from the previous block \
                     (expected prev_hash {}, got {}) — aborting sync, {} block(s) already applied",
                    h,
                    expected_prev_hash,
                    block.header.prev_hash,
                    total_applied
                );
            }
            execute_block(chain_state, block, None);
            store.put_block(block.clone())?;
            expected_prev_hash = block.hash();
            if h % 1000 == 0 {
                info!("Synced block {}", h);
            }
        }
        total_applied += blocks.len() as u64;
        from += blocks.len() as u64;
        if blocks.len() < 200 {
            break; // last batch — we're at the peer tip
        }
    }

    store.save_chain_state(chain_state)?;
    Ok(total_applied)
}

#[cfg(test)]
mod sync_blocks_from_peer_tests {
    use super::*;
    use axum::{extract::Query, routing::get, Json, Router};
    use helix_core::genesis_block;
    use helix_crypto::{Hash, KeyPair, Signature as Sig};
    use std::collections::HashMap;

    fn signed_block(kp: &KeyPair, height: u64, prev_hash: Hash) -> Block {
        let mut block = genesis_block(
            Address::from_public_key(&kp.public),
            kp.public.clone(),
            Sig::from_bytes(vec![]),
        );
        block.header.height = height;
        block.header.prev_hash = prev_hash;
        let sig = kp.sign(block.header.signing_hash().as_bytes()).unwrap();
        block.header.signature = sig;
        block
    }

    /// Builds `heights.len()` blocks that properly chain from `Hash::ZERO` (a
    /// fresh store's initial tip) through each other in order.
    fn chained_blocks(kp: &KeyPair, heights: &[u64]) -> Vec<Block> {
        let mut prev_hash = Hash::ZERO;
        heights
            .iter()
            .map(|&h| {
                let block = signed_block(kp, h, prev_hash);
                prev_hash = block.hash();
                block
            })
            .collect()
    }

    async fn serve_blocks(blocks: Vec<Block>) -> String {
        let blocks = Arc::new(blocks);
        let app = Router::new().route(
            "/sync/blocks",
            get(move |Query(params): Query<HashMap<String, String>>| {
                let blocks = blocks.clone();
                async move {
                    let from: u64 = params.get("from").and_then(|s| s.parse().ok()).unwrap_or(0);
                    let count: usize = params.get("count").and_then(|s| s.parse().ok()).unwrap_or(200);
                    let page: Vec<Block> = blocks
                        .iter()
                        .filter(|b| b.height() >= from)
                        .take(count)
                        .cloned()
                        .collect();
                    Json(page)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", addr)
    }

    fn fresh_store() -> HelixDb {
        let path = std::env::temp_dir().join(format!(
            "helix-test-sync-store-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        HelixDb::open(&path).unwrap()
    }

    /// Registers `kp`'s address as a staked validator in `chain_state`, so blocks
    /// it signs pass the validator-set membership check in `sync_blocks_from_peer`.
    fn stake_validator(chain_state: &mut ChainState, kp: &KeyPair) {
        let addr = Address::from_public_key(&kp.public);
        let min_stake = chain_state.governance_params.min_validator_stake;
        let mut acc = helix_executor::AccountState::new(&addr);
        acc.staked = min_stake;
        chain_state.accounts.insert(addr.to_string(), acc);
    }

    #[tokio::test]
    async fn applies_all_validly_signed_blocks() {
        let kp = KeyPair::generate();
        let blocks = chained_blocks(&kp, &[1, 2, 3]);
        let peer_url = serve_blocks(blocks).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
        stake_validator(&mut chain_state, &kp);
        let applied = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state).await.unwrap();

        assert_eq!(applied, 3);
        assert_eq!(store.latest_height(), 3);
    }

    #[tokio::test]
    async fn rejects_tampered_block_and_aborts_cleanly() {
        let kp = KeyPair::generate();
        let mut blocks = chained_blocks(&kp, &[1, 2, 3]);
        blocks[1].header.height = 99; // invalidates the signature without re-signing
        let peer_url = serve_blocks(blocks).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
        stake_validator(&mut chain_state, &kp);
        let result = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state).await;

        // Sync aborts with an error instead of panicking/crashing ...
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature verification"));
        // ... but the one valid block seen before the bad one stays applied.
        assert_eq!(store.latest_height(), 1);
        // The forged/height-99 and any block after it must never be persisted.
        assert!(store.get_block_by_height(99).is_err());
        assert!(store.get_block_by_height(3).is_err());
    }

    #[tokio::test]
    async fn accepts_unstaked_validator_for_the_very_first_block_when_no_stakers_exist_yet() {
        // A block signed by a not-yet-staked address, synced against a chain_state with
        // literally no stakers registered, is indistinguishable from every real node's own
        // legitimate bootstrap block — every node's BFT engine falls back to "no qualifying
        // stakers yet, accept self as sole validator" before anyone has ever submitted a
        // real on-chain Stake tx (see `HelixNode::run`), and that fallback validator is never
        // reflected in `chain_state.stakers()` since it was never established via a Stake tx.
        // Before this fix, sync could never get past this very first block for any node —
        // found by wiping a node's data and watching it fail to resync from a live peer.
        let kp = KeyPair::generate();
        let blocks = vec![signed_block(&kp, 1, Hash::ZERO)];
        let peer_url = serve_blocks(blocks).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0); // no stakers registered
        let result = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state).await;

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(store.latest_height(), 1);
    }

    #[tokio::test]
    async fn rejects_validly_signed_block_from_unstaked_address_once_real_stake_exists() {
        // Once a real staker exists in chain_state, an unrelated free, throwaway keypair
        // with no stake must still be rejected — the bootstrap fallback above only ever
        // applies while stakers() is genuinely empty, not as a general bypass.
        let real_kp = KeyPair::generate();
        let block1 = signed_block(&real_kp, 1, Hash::ZERO);
        let attacker_kp = KeyPair::generate();
        let block2 = signed_block(&attacker_kp, 2, block1.hash());
        let peer_url = serve_blocks(vec![block1, block2]).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
        stake_validator(&mut chain_state, &real_kp);
        let result = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("outside the current validator set"));
        // Block 1 (the real staker) stays applied, block 2 (the impersonator) does not.
        assert_eq!(store.latest_height(), 1);
        assert!(store.get_block_by_height(2).is_err());
    }

    #[tokio::test]
    async fn rejects_block_that_does_not_chain_from_previous_block() {
        // Both blocks are validly signed by a real staker, but block 2's prev_hash
        // doesn't match block 1's actual hash (e.g. peer serving a different branch).
        let kp = KeyPair::generate();
        let block1 = signed_block(&kp, 1, Hash::ZERO);
        let non_chaining_block2 = signed_block(&kp, 2, Hash::ZERO); // should be block1.hash()
        let blocks = vec![block1, non_chaining_block2];
        let peer_url = serve_blocks(blocks).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
        stake_validator(&mut chain_state, &kp);
        let result = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not chain"));
        // Block 1 stays applied, block 2 (the non-chaining one) is never persisted.
        assert_eq!(store.latest_height(), 1);
        assert!(store.get_block_by_height(2).is_err());
    }
}

#[cfg(test)]
mod multiaddr_kind_tests {
    use super::*;

    #[test]
    fn recognizes_ipv4() {
        assert_eq!(multiaddr_kind("127.0.0.1"), "ip4");
        assert_eq!(multiaddr_kind("203.0.113.7"), "ip4");
    }

    #[test]
    fn recognizes_ipv6() {
        assert_eq!(multiaddr_kind("::1"), "ip6");
    }

    #[test]
    fn falls_back_to_dns4_for_hostnames() {
        assert_eq!(multiaddr_kind("localhost"), "dns4");
        assert_eq!(multiaddr_kind("helix.silvra.net"), "dns4");
    }
}

#[cfg(test)]
mod resolve_seed_peer_multiaddr_tests {
    use super::*;
    use axum::{routing::get, Json, Router};

    /// Spins up a real HTTP server on a free local port that serves a fixed `/status`
    /// JSON body — same pattern as `sync_blocks_from_peer_tests::serve_blocks`, so this
    /// exercises the real HTTP + JSON-parsing path, not just the string formatting.
    async fn serve_status(body: serde_json::Value) -> String {
        let app = Router::new().route("/status", get(move || async move { Json(body) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn resolves_to_a_dialable_multiaddr_using_the_peers_own_p2p_port() {
        let peer_url = serve_status(serde_json::json!({ "p2p_port": 9999 })).await;

        let addr = resolve_seed_peer_multiaddr(&peer_url).await.unwrap();

        assert_eq!(addr, "/ip4/127.0.0.1/tcp/9999");
    }

    #[tokio::test]
    async fn errors_when_the_peer_omits_p2p_port() {
        // An older node's /status response, before this field existed — must be treated
        // as "no seed peer available", not crash node startup.
        let peer_url = serve_status(serde_json::json!({ "height": 5 })).await;

        let result = resolve_seed_peer_multiaddr(&peer_url).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("p2p_port"));
    }

    #[tokio::test]
    async fn errors_on_unreachable_peer() {
        let result = resolve_seed_peer_multiaddr("http://127.0.0.1:1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn prefers_the_announced_public_multiaddr_over_the_derived_raw_tcp_one() {
        // A peer behind an HTTPS proxy / Cloudflare tunnel: its RPC host (this URL) is NOT
        // where its P2P lives — the announced WebSocket address is on a different host and port,
        // and the raw-TCP derivation (`/ip4/127.0.0.1/tcp/8546`) would be an unreachable dial
        // that just burns a ~20 s timeout. The announced address must win. Regression guard for
        // backlog #104.
        let peer_url = serve_status(serde_json::json!({
            "p2p_port": 8546,
            "p2p_public_addr": "/dns4/p2p.silvra.net/tcp/443/tls/ws",
        }))
        .await;

        let addr = resolve_seed_peer_multiaddr(&peer_url).await.unwrap();

        assert_eq!(addr, "/dns4/p2p.silvra.net/tcp/443/tls/ws");
    }

    #[tokio::test]
    async fn falls_back_to_raw_tcp_when_the_announced_addr_is_empty_or_absent() {
        // An open node that announces nothing (empty string) — and, separately, one whose build
        // predates the field entirely — must both keep the original raw-TCP-from-p2p_port
        // behaviour, not error.
        let empty = serve_status(serde_json::json!({
            "p2p_port": 9999,
            "p2p_public_addr": "",
        }))
        .await;
        assert_eq!(
            resolve_seed_peer_multiaddr(&empty).await.unwrap(),
            "/ip4/127.0.0.1/tcp/9999"
        );

        let absent = serve_status(serde_json::json!({ "p2p_port": 9999 })).await;
        assert_eq!(
            resolve_seed_peer_multiaddr(&absent).await.unwrap(),
            "/ip4/127.0.0.1/tcp/9999"
        );
    }
}

#[cfg(test)]
mod handle_p2p_event_tests {
    use super::*;
    use helix_core::genesis_block;
    use helix_crypto::{Hash, KeyPair, Signature as Sig};
    use std::sync::atomic::AtomicUsize;

    fn fresh_store() -> HelixDb {
        let path = std::env::temp_dir().join(format!(
            "helix-test-p2p-event-store-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        HelixDb::open(&path).unwrap()
    }

    fn signed_block(kp: &KeyPair, height: u64, prev_hash: Hash) -> Block {
        let mut block = genesis_block(
            Address::from_public_key(&kp.public),
            kp.public.clone(),
            Sig::from_bytes(vec![]),
        );
        block.header.height = height;
        block.header.prev_hash = prev_hash;
        let sig = kp.sign(block.header.signing_hash().as_bytes()).unwrap();
        block.header.signature = sig;
        block
    }

    /// The free-throwaway-keypair attack this fix closes: a validly self-signed
    /// block from an address that holds no stake and isn't in the validator set
    /// must be dropped by the `NewCommittedBlock` P2P event handler, not applied.
    #[tokio::test]
    async fn new_committed_block_from_unstaked_signer_is_dropped() {
        let attacker_kp = KeyPair::generate();
        let block = signed_block(&attacker_kp, 1, Hash::ZERO);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let peer_count = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(0)));

        // Validator set contains only a legitimate, unrelated validator — not the attacker.
        let real_kp = KeyPair::generate();
        let real_addr = Address::from_public_key(&real_kp.public);
        let validator_set = ValidatorSet::new(vec![Validator::new(real_addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, real_addr, 0)));

        let own_kp = KeyPair::generate();
        let (p2p_tx, mut p2p_rx) = mpsc::channel(8);

        handle_p2p_event(
            P2PEvent::NewCommittedBlock(block),
            &mempool,
            &peer_count,
            &store,
            &chain_state,
            &engine,
            &own_kp,
            &p2p_tx,
            &None,
            &Arc::new(Mutex::new(0)),
        )
        .await;

        // Dropped: never applied (height unchanged), nothing broadcast.
        assert_eq!(store.read().await.latest_height(), 0);
        assert!(p2p_rx.try_recv().is_err());
    }

    /// Regression test: a block finalized via a peer's proposal/votes/gossip must mint
    /// its block reward to the block's own `header.validator`, never to this node's
    /// locally configured `reward_address`. Before this fix, `handle_p2p_event` threaded
    /// its own `reward_address` into every `apply_finalized_block` call, including these
    /// peer-driven ones — a node with `HELIX_REWARD_ADDRESS` set would redirect every
    /// other validator's block reward to itself, and any two nodes with different
    /// configs would diverge on the resulting chain state.
    #[tokio::test]
    async fn new_committed_block_from_peer_mints_reward_to_block_validator_not_to_local_override() {
        let validator_kp = KeyPair::generate();
        let validator_addr = Address::from_public_key(&validator_kp.public);
        let block = signed_block(&validator_kp, 1, Hash::ZERO);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let peer_count = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));

        let validator_set = ValidatorSet::new(vec![Validator::new(validator_addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, validator_addr.clone(), 0)));

        let own_kp = KeyPair::generate();
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);

        handle_p2p_event(
            P2PEvent::NewCommittedBlock(block),
            &mempool,
            &peer_count,
            &store,
            &chain_state,
            &engine,
            &own_kp,
            &p2p_tx,
            &None,
            &Arc::new(Mutex::new(0)),
        )
        .await;

        let state = chain_state.read().await;
        assert!(state.get(&validator_addr).unwrap().balance > 0, "block reward must land on the actual block validator");
        assert!(state.get(&Address::from_public_key(&own_kp.public)).is_none(), "our own address never participated and must not receive anything");
    }

    /// A block from a real, staked validator with a signature that checks out is
    /// still dropped if it doesn't build on our actual tip — otherwise applying it
    /// would silently splice an unrelated block into our chain state.
    #[tokio::test]
    async fn new_committed_block_with_wrong_prev_hash_is_dropped() {
        let validator_kp = KeyPair::generate();
        let validator_addr = Address::from_public_key(&validator_kp.public);
        // Fresh store's tip hash is Hash::ZERO — deliberately build the block on a
        // different, non-zero "previous" hash so it doesn't chain.
        let wrong_prev_hash = Hash::digest(b"not our actual tip");
        let block = signed_block(&validator_kp, 1, wrong_prev_hash);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let peer_count = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(0)));

        let validator_set = ValidatorSet::new(vec![Validator::new(validator_addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, validator_addr, 0)));

        let own_kp = KeyPair::generate();
        let (p2p_tx, mut p2p_rx) = mpsc::channel(8);

        handle_p2p_event(
            P2PEvent::NewCommittedBlock(block),
            &mempool,
            &peer_count,
            &store,
            &chain_state,
            &engine,
            &own_kp,
            &p2p_tx,
            &None,
            &Arc::new(Mutex::new(0)),
        )
        .await;

        assert_eq!(store.read().await.latest_height(), 0);
        assert!(p2p_rx.try_recv().is_err());
    }

    fn signed_vote(
        kp: &KeyPair,
        validator: &Address,
        vote_type: helix_consensus::VoteType,
        height: u64,
        round: u32,
        block_hash: Hash,
    ) -> helix_consensus::Vote {
        let mut vote = helix_consensus::Vote {
            vote_type,
            height,
            round,
            block_hash,
            validator: validator.clone(),
            public_key: kp.public.clone(),
            crypto_version: kp.scheme,
            signature: Sig::from_bytes(vec![]),
        };
        vote.signature = kp.sign(&vote.signing_bytes()).unwrap();
        vote
    }

    /// Regression test for a security-critical bug found by actually triggering a real
    /// double-sign on a multi-node local testnet: `report_double_sign_evidence` used to
    /// build its `SubmitDoubleSignEvidence` transaction with `fee: 0`. Evidence detection
    /// itself worked and got logged ("Double-sign evidence detected — reporting on-chain"),
    /// but the transaction was rejected by `Mempool::add()`'s minimum-fee check on *every*
    /// node, including the reporter's own — silently, since the rejection is only logged at
    /// debug level. The slash this was supposed to trigger never came anywhere near a block.
    /// Existing tests only ever exercised `execute_submit_double_sign_evidence` directly,
    /// bypassing the mempool entirely, so this was invisible until a real double-sign
    /// actually happened over a real network and the resulting chain state was checked.
    #[tokio::test]
    async fn report_double_sign_evidence_produces_a_transaction_the_mempool_actually_accepts() {
        let bad_kp = KeyPair::generate();
        let bad_addr = Address::from_public_key(&bad_kp.public);
        let vote_a = signed_vote(&bad_kp, &bad_addr, helix_consensus::VoteType::Prevote, 5, 0, Hash::digest(b"a"));
        let vote_b = signed_vote(&bad_kp, &bad_addr, helix_consensus::VoteType::Prevote, 5, 0, Hash::digest(b"b"));
        let evidence = DoubleSignEvidence { validator: bad_addr, height: 5, round: 0, vote_a, vote_b };

        let reporter_kp = KeyPair::generate();
        let chain_state = Arc::new(RwLock::new(ChainState::new(0)));
        // Uses Mempool::new()'s real default min-fee — the same one a live node runs
        // with — not a relaxed test double, since the whole point is proving this
        // clears the bar a real node's mempool actually enforces.
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);

        report_double_sign_evidence(evidence, &reporter_kp, &chain_state, &mempool, &p2p_tx).await;

        assert_eq!(
            mempool.read().await.len(),
            1,
            "the evidence tx must actually clear the mempool's fee floor, not just get logged"
        );
    }

    /// A block that includes a valid `SubmitDoubleSignEvidence` transaction must not just
    /// apply the slash (already covered at the executor level) but also immediately remove
    /// the slashed validator from the live `BftEngine`'s validator set — not wait for the
    /// next epoch rotation, which could be `EPOCH_LENGTH` blocks away.
    #[tokio::test]
    async fn apply_finalized_block_jails_validator_immediately_after_slash() {
        let bad_validator_kp = KeyPair::generate();
        let bad_validator_addr = Address::from_public_key(&bad_validator_kp.public);
        let reporter_kp = KeyPair::generate();
        let reporter_addr = Address::from_public_key(&reporter_kp.public);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(0)));
        {
            let mut state = chain_state.write().await;
            state.update_account(&bad_validator_addr, |acc| acc.staked = 1_000_000);
            state.update_account(&reporter_addr, |acc| acc.balance = 1_000_000);
        }

        let validator_set =
            ValidatorSet::new(vec![Validator::new(bad_validator_addr.clone(), 1_000_000, true)], 0);
        let engine =
            Arc::new(RwLock::new(BftEngine::new(validator_set, bad_validator_addr.clone(), 0)));

        let vote_a = signed_vote(
            &bad_validator_kp,
            &bad_validator_addr,
            helix_consensus::VoteType::Precommit,
            10,
            0,
            Hash::digest(b"block-a"),
        );
        let vote_b = signed_vote(
            &bad_validator_kp,
            &bad_validator_addr,
            helix_consensus::VoteType::Precommit,
            10,
            0,
            Hash::digest(b"block-b"),
        );
        let evidence = DoubleSignEvidence {
            validator: bad_validator_addr.clone(),
            height: 10,
            round: 0,
            vote_a,
            vote_b,
        };

        let mut evidence_tx = Transaction {
            version: 1,
            tx_type: TxType::SubmitDoubleSignEvidence,
            from: reporter_addr.clone(),
            to: None,
            amount: 0,
            fee: 0,
            nonce: 0,
            data: bincode::serialize(&evidence).unwrap(),
            crypto_version: reporter_kp.scheme,
            signature: Sig::from_bytes(vec![]),
            public_key: reporter_kp.public.clone(),
        };
        evidence_tx.signature = reporter_kp.sign(evidence_tx.signing_hash().as_bytes()).unwrap();

        let mut block = signed_block(&bad_validator_kp, 1, Hash::ZERO);
        block.transactions = vec![evidence_tx];

        let (p2p_tx, _p2p_rx) = mpsc::channel(8);
        let last_applied_height = Arc::new(Mutex::new(0));
        apply_finalized_block(block, false, &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height).await;

        assert!(
            engine.read().await.validator_set.get(&bad_validator_addr).is_none(),
            "slashed validator must be jailed immediately, not just at the next epoch rotation"
        );
        assert!(
            chain_state.read().await.get(&bad_validator_addr).unwrap().staked < 1_000_000,
            "slash itself must still have applied"
        );
    }

    /// Regression test for a real race: this node's own BFT engine reaching quorum
    /// (NewProposal/NewVote) and a `NewCommittedBlock` gossip arrival for the *same* height
    /// run as independent tokio tasks, each deciding whether to proceed from different state
    /// (the engine's `current_height` vs. `store.latest_height()`) read *before* either ever
    /// calls `apply_finalized_block` — with no lock held across that gap, both could observe
    /// "not yet applied" and both call it. Without the shared `last_applied_height` guard,
    /// this double-executes the block: harmless for most of its own transactions (rejected
    /// the second time on stale nonces), but the block reward mint isn't nonce-gated at all,
    /// so it mints twice regardless — silently inflating supply. Found in practice as a
    /// small, fixed `circulating_supply` divergence between two otherwise-identical nodes.
    /// Simulates the race by calling `apply_finalized_block` twice for the identical block
    /// Applying a block must leave behind a record of what its transactions actually did.
    /// The chain executed them, warned about the failures in its own log, and threw the
    /// receipts away — so a transaction the executor rejected was indistinguishable, from
    /// outside the node, from one that moved money. Uses the real case that exposed it: a
    /// zero-amount transfer, which is committed, charged, and refused.
    #[tokio::test]
    async fn apply_finalized_block_persists_why_a_transaction_failed() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let sender_kp = KeyPair::generate();
        let sender = Address::from_public_key(&sender_kp.public);

        let mut rejected = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: sender.clone(),
            to: Some(addr.clone()),
            amount: 0, // execute_transfer refuses this, after the block is already committed
            fee: 10_000,
            nonce: 0,
            data: vec![],
            crypto_version: sender_kp.scheme,
            signature: Sig::from_bytes(vec![]),
            public_key: sender_kp.public.clone(),
        };
        rejected.signature = sender_kp.sign(rejected.signing_hash().as_bytes()).unwrap();
        let tx_hash = rejected.hash();

        let mut block = signed_block(&kp, 1, Hash::ZERO);
        block.transactions = vec![rejected];
        block.header.signature = kp.sign(block.header.signing_hash().as_bytes()).unwrap();

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut state = chain_state.write().await;
            state.update_account(&sender, |acc| acc.balance = 1_000_000);
        }
        let validator_set = ValidatorSet::new(vec![Validator::new(addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, addr, 0)));
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);
        let last_applied_height = Arc::new(Mutex::new(0));

        apply_finalized_block(block, false, &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height).await;

        let receipt = store
            .read()
            .await
            .get_receipt(&tx_hash)
            .unwrap()
            .expect("the block was applied, so its receipt must have been written");
        assert!(!receipt.success, "a rejected transfer must not be recorded as successful");
        assert!(
            receipt.error.as_deref().is_some_and(|e| e.contains("greater than zero")),
            "the reason has to survive to the caller, not just the log: {:?}",
            receipt.error
        );
    }

    /// against the same `last_applied_height` — the second call must be a complete no-op.
    #[tokio::test]
    async fn apply_finalized_block_does_not_double_mint_a_racing_duplicate_for_the_same_height() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let block = signed_block(&kp, 1, Hash::ZERO);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        let validator_set = ValidatorSet::new(vec![Validator::new(addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, addr, 0)));
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);
        let last_applied_height = Arc::new(Mutex::new(0));

        apply_finalized_block(block.clone(), false, &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height).await;
        let issued_after_first = chain_state.read().await.total_issued;
        assert!(issued_after_first > 0, "the first application must mint the scheduled block reward");

        // A second application of the *same* block/height — as a racing duplicate ingestion
        // path would produce — must change nothing further.
        apply_finalized_block(block, false, &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height).await;
        let issued_after_second = chain_state.read().await.total_issued;
        assert_eq!(issued_after_second, issued_after_first, "the block reward must not be minted twice for the same height");
        assert_eq!(store.read().await.latest_height(), 1, "the duplicate must not re-touch storage either");
    }

    /// The bug this closes: `NewCommittedBlock`'s gap-fill branch called
    /// `sync_blocks_from_peer` — which mints block rewards via `execute_block` — entirely
    /// outside `last_applied_height`. A concurrent BFT-finalize or gossip apply for a height
    /// inside the just-synced range would see a guard that still read its pre-sync value and
    /// double-mint. Reproduces the real race end-to-end: gap-fill via `handle_p2p_event`,
    /// then a racing `apply_finalized_block` for one of the heights it just applied.
    #[tokio::test]
    async fn gap_fill_sync_is_covered_by_the_shared_height_guard() {
        use axum::{extract::Query, routing::get, Json, Router};
        use std::collections::HashMap;

        let kp = KeyPair::generate();
        let mut prev_hash = Hash::ZERO;
        let chained: Vec<Block> = (1u64..=3)
            .map(|h| {
                let b = signed_block(&kp, h, prev_hash);
                prev_hash = b.hash();
                b
            })
            .collect();

        let served = Arc::new(chained.clone());
        let app = Router::new().route(
            "/sync/blocks",
            get(move |Query(params): Query<HashMap<String, String>>| {
                let served = served.clone();
                async move {
                    let from: u64 = params.get("from").and_then(|s| s.parse().ok()).unwrap_or(0);
                    let count: usize = params.get("count").and_then(|s| s.parse().ok()).unwrap_or(200);
                    let page: Vec<Block> =
                        served.iter().filter(|b| b.height() >= from).take(count).cloned().collect();
                    Json(page)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let peer_count = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        // Empty validator set — mirrors the same bootstrap fallback `sync_blocks_from_peer`
        // already relies on (`chain_state.stakers().is_empty()`), same as its own test suite.
        let validator_set = ValidatorSet::new(vec![], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, Address::from_public_key(&kp.public), 0)));
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);
        let last_applied_height = Arc::new(Mutex::new(0u64));

        // A gossiped block far ahead of our tip — triggers the gap-fill branch. Its own
        // content is irrelevant; it's never applied directly, only used to detect the gap.
        let far_ahead = signed_block(&kp, 5, Hash::ZERO);
        handle_p2p_event(
            P2PEvent::NewCommittedBlock(far_ahead),
            &mempool,
            &peer_count,
            &store,
            &chain_state,
            &engine,
            &kp,
            &p2p_tx,
            &Some(peer_url),
            &last_applied_height,
        )
        .await;

        assert_eq!(store.read().await.latest_height(), 3, "all three blocks from the peer must be applied");
        assert_eq!(
            *last_applied_height.lock().await,
            3,
            "gap-fill must advance the shared guard to the new tip — before this fix it never \
             touched it at all, leaving it at its pre-sync value"
        );
        let issued_after_gap_fill = chain_state.read().await.total_issued;
        assert!(issued_after_gap_fill > 0, "gap-fill must have minted the block rewards for heights 1-3");

        // Now the actual race: some other ingestion path (BFT-finalize, direct gossip)
        // finalizes one of the heights the gap-fill just applied. Before this fix, this
        // would see `last_applied_height` still at its pre-sync value and double-mint.
        let racing_duplicate = chained[2].clone(); // height 3, same block gap-fill already applied
        apply_finalized_block(
            racing_duplicate,
            false,
            &store,
            &mempool,
            &chain_state,
            &engine,
            &p2p_tx,
            None,
            &last_applied_height,
        )
        .await;

        assert_eq!(
            chain_state.read().await.total_issued,
            issued_after_gap_fill,
            "the racing duplicate must not mint the block reward a second time"
        );
        assert_eq!(store.read().await.latest_height(), 3, "the racing duplicate must not re-touch storage either");
    }

    /// Wiring-level regression test for the new-entrant delay in epoch rotation — the pure
    /// promotion logic itself (`ChainState::stakers_after_delayed_activation`) has exhaustive
    /// unit coverage in `helix_executor::state`; this proves `apply_finalized_block`'s rotation
    /// block actually threads `engine.validator_set()` through as `previously_active` and holds
    /// a brand-new staker out of the active set for one full epoch. Closes the gap found live
    /// on 2026-07-20: a `Stake` tx alone made a second validator quorum-critical the moment the
    /// epoch rotated, with no online-check and no warning, freezing the chain for hours because
    /// their node wasn't actually connected yet.
    #[tokio::test]
    async fn epoch_rotation_defers_a_brand_new_staker_by_one_epoch() {
        let genesis_kp = KeyPair::generate();
        let genesis_addr = Address::from_public_key(&genesis_kp.public);
        let new_staker_addr = Address::from_public_key(&KeyPair::generate().public);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut cs = chain_state.write().await;
            cs.governance_params.min_validator_stake = 1;
            cs.update_account(&genesis_addr, |acc| acc.staked = 1_000_000);
            // Staked directly rather than via a `Stake` tx — the rotation only cares about
            // `stakers()`, and this keeps the test focused on the rotation wiring itself.
            cs.update_account(&new_staker_addr, |acc| acc.staked = 1_000_000);
        }
        let validator_set = ValidatorSet::new(vec![Validator::new(genesis_addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, genesis_addr.clone(), 0)));
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);
        let last_applied_height = Arc::new(Mutex::new(0u64));

        // First epoch boundary: both accounts already qualify, but new_staker_addr was never
        // part of the active set before — it must not appear in the rotated set yet.
        let block_at_epoch = signed_block(&genesis_kp, helix_consensus::EPOCH_LENGTH, Hash::ZERO);
        apply_finalized_block(
            block_at_epoch, false, &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height,
        )
        .await;

        assert!(
            engine.read().await.validator_set().get(&genesis_addr).is_some(),
            "the already-active validator must remain active"
        );
        assert!(
            engine.read().await.validator_set().get(&new_staker_addr).is_none(),
            "a brand-new staker must not become quorum-critical on the very rotation it first qualifies"
        );

        // Second epoch boundary, one full epoch later: the new staker must now be promoted.
        let block_at_second_epoch = signed_block(&genesis_kp, helix_consensus::EPOCH_LENGTH * 2, Hash::ZERO);
        apply_finalized_block(
            block_at_second_epoch, false, &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height,
        )
        .await;

        assert!(
            engine.read().await.validator_set().get(&new_staker_addr).is_some(),
            "the staker must be promoted at the next epoch rotation"
        );
    }
}

#[cfg(test)]
mod genesis_verification_tests {
    use super::*;
    use helix_core::genesis_block;
    use helix_crypto::{KeyPair, Signature};

    fn peer_genesis_with(validator_stake: u64, state_hash: Option<String>) -> PeerGenesis {
        let kp = KeyPair::generate();
        let validator = Address::from_public_key(&kp.public);
        PeerGenesis {
            block: genesis_block(
                validator,
                kp.public.clone(),
                Signature::from_bytes(vec![0u8; 8]),
            ),
            personhood_authorities: vec![],
            governance_params: GovernanceParams::default(),
            extra_validators: vec![],
            validator_stake,
            allocations: vec![],
            state_hash,
        }
    }

    fn rebuilt(pg: &PeerGenesis) -> ChainState {
        helix_executor::genesis::rebuild_genesis_state(
            pg.block.header.validator.clone(),
            pg.personhood_authorities.clone(),
            pg.extra_validators.clone(),
            pg.validator_stake,
            pg.allocations.clone(),
            pg.governance_params.clone(),
        )
    }

    #[test]
    fn a_matching_reconstruction_is_accepted() {
        let mut pg = peer_genesis_with(100_000 * NANO_PER_HLX, None);
        let state = rebuilt(&pg);
        pg.state_hash = Some(state.state_hash().to_hex());
        assert!(verify_genesis_reconstruction(&pg, &state).is_ok());
    }

    /// The real case, reproduced: the published v1.4.0 binary rebuilt genesis with its own
    /// `VALIDATOR_GENESIS_STAKE_HLX = 1_000_000` against a chain that launched with 100_000,
    /// synced every block without complaint, and reported 800,000 HLX that do not exist. Any
    /// disagreement about genesis produces exactly this shape — a state that is wrong from
    /// block 0 and stays internally consistent forever after.
    #[test]
    fn a_node_that_rebuilds_a_different_genesis_refuses_to_join() {
        let peer = peer_genesis_with(100_000 * NANO_PER_HLX, None);
        let peer_state = rebuilt(&peer);

        // What an older build produces from the same peer response.
        let mut stale = peer_genesis_with(100_000 * NANO_PER_HLX, None);
        stale.block = peer.block.clone();
        stale.validator_stake = 1_000_000 * NANO_PER_HLX;
        let stale_state = rebuilt(&stale);

        assert_ne!(peer_state.state_hash(), stale_state.state_hash(), "premise");

        let mut pg = peer;
        pg.state_hash = Some(peer_state.state_hash().to_hex());
        let err = verify_genesis_reconstruction(&pg, &stale_state).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("refusing to join"), "{msg}");
        assert!(msg.contains("silently"), "the message must say why it matters: {msg}");
    }

    /// A peer older than the check cannot send a hash. Refusing would strand a new node against
    /// a chain of older ones — so we are back where we were before the check existed, and say so,
    /// rather than pretending the absence of a mismatch is a match.
    #[test]
    fn a_peer_too_old_to_report_a_hash_is_allowed_through() {
        let pg = peer_genesis_with(100_000 * NANO_PER_HLX, None);
        let state = rebuilt(&pg);
        assert!(verify_genesis_reconstruction(&pg, &state).is_ok());
    }
}
