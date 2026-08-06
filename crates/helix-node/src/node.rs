use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use helix_consensus::{
    BftEngine, ConsensusError, DoubleSignEvidence, Proposal, Validator, ValidatorSet, Vote, VoteType,
};
use helix_core::{genesis_block, Block, CommitSig, Transaction, TxType};
use helix_crypto::{Address, CryptoScheme, Hash, KeyFile, KeyPair, PublicKey, Signature};
use helix_executor::{
    execute_block,
    genesis::{GenesisConfig, NANO_PER_HLX, TOTAL_SUPPLY_HLX, VALIDATOR_GENESIS_STAKE_HLX},
    state::ChainState,
    GovernanceParams,
};
use helix_mempool::Mempool;
use helix_p2p::{
    blocksync::BlockSyncResponse,
    config::P2PConfig,
    service::{P2PCommand, P2PEvent, P2PService, MAX_CATCHUP_SERVE_BLOCKS},
};
use helix_rpc::server::{start_rpc_server, AppState};
use helix_rpc::TipCertificate;
use helix_storage::{db::HelixDb, BlockStore};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::config::{self, NodeConfig};
use crate::signing_guard::{Decision, SigningGuard};

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
/// The chain database's filename, in the working directory. Named because the run record sits
/// beside it and both paths have to agree.
const CHAIN_DB_FILE: &str = "helix-data.redb";

pub const DEFAULT_SEED_PEER: &str = "https://helix.silvra.net";

/// The genesis hash of the public Helix chain, compiled in so joining it is verified by default.
///
/// Bitcoin puts its genesis block in the source and asserts the hash (`chainparams.cpp`), so a node
/// cannot be talked onto another chain and nobody configures anything. This is the same idea with
/// one deliberate softening: it is the *default* value of the checkpoint, not a law. A Helix devnet
/// reset produces a new genesis, and a hard-coded hash that outlived a reset would lock every
/// operator out of the network until a release shipped — trading a real outage for a hypothetical
/// impersonation. `HELIX_GENESIS_HASH` still overrides it, so after a reset an operator is told
/// clearly what happened and has a way through rather than being stranded.
///
/// Only applies when joining the default seed. An operator who named their own `sync_peer` is
/// joining a network this constant knows nothing about, and silently checking ours against theirs
/// would refuse a perfectly good join.
///
/// **Update this together with any chain reset**, in the release that accompanies it.
pub const DEFAULT_GENESIS_HASH: &str =
    "ff271e4a9e4d61f769a8d7dc543facca7dc17a3968398a730c5863a93f2d030b";

/// The genesis hash this node should insist on: the operator's if they set one, otherwise the
/// compiled-in default — but only when joining the public chain the default describes.
///
/// Split out as a pure function because the "only for the default seed" condition is the whole
/// safety argument, and it is one `&&` away from silently refusing every private network.
fn expected_genesis_hash(configured: Option<String>, sync_peer: Option<&str>) -> Option<String> {
    if let Some(explicit) = configured.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        return Some(explicit);
    }
    match sync_peer {
        Some(peer) if peer == DEFAULT_SEED_PEER => Some(DEFAULT_GENESIS_HASH.to_string()),
        _ => None,
    }
}

/// Interval between periodic RPC catch-up polls of the sync peer (see [`rpc_sync_loop`]).
const RPC_SYNC_POLL_SECS: u64 = 4;

/// How far behind the sync peer this node must be before the periodic RPC catch-up is allowed
/// to interrupt a consensus round it is currently driving (see [`rpc_sync_loop`]).
///
/// Applying a block through the catch-up path calls
/// [`BftEngine::sync_to_externally_finalized_block`], which drops the active round, its
/// buffered votes and the collected `last_commit` — correct for a follower that was never in
/// the round, ruinous for a validator that was. A validator waiting on precommits is *by
/// definition* one height behind the proposer, so with no threshold at all the catch-up fires
/// on essentially every poll and tears the round down before it can ever finish.
///
/// Measured on the live chain 2026-07-22: the second validator logged "Periodic RPC catch-up …
/// applied=2" every few seconds for hours. It never emitted a single precommit, so validator 1
/// liveness-jailed it, committed alone, and its address appeared in no block's `last_commit` —
/// 150 missed blocks later it was downtime-jailed, over and over, through eight full cycles.
/// The node was healthy and well-connected the entire time; it was being reset by its own
/// catch-up loop. Any validator joining through the default seed hits this, which is why the
/// network never had a working second validator.
///
/// Above this gap the round is genuinely stale (the chain moved on without us) and catching up
/// is the right call — that is the follower case this loop exists for, and it still applies
/// immediately when no round is in flight.
const RPC_CATCHUP_ROUND_GRACE_BLOCKS: u64 = 3;

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

/// How many block-production ticks between probation heartbeats (see
/// `send_probation_heartbeat_if_due`). Ten gives a probationer about ten attempts across its
/// 100-block epoch, so no single dropped transaction costs it the epoch, while staying far below
/// the noise of one per block.
const HEARTBEAT_TICK_INTERVAL: u32 = 10;
/// Block-production ticks to wait (after enough validators have connected) for the
/// gossip mesh to finish forming before producing the first block, in a
/// multi-validator set. See the startup gate in `block_production_loop`.
const MESH_SETTLE_TICKS: u32 = 5;
const MAX_TXS_PER_BLOCK: usize = 1_000;
const RPC_BIND_DEFAULT: &str = "127.0.0.1:8545";
/// Validator health heartbeat cadence and thresholds (see `validator_health_loop`).
const VALIDATOR_HEALTH_SECS: u64 = 60;
/// How many recent blocks the signing check looks across. A healthy validator is legitimately
/// absent from a large fraction of individual commit certificates (the gossip fast-path drops
/// precommits it already had), so "not in the last block" is noise — "not in any of the last
/// `HEALTH_SIGN_WINDOW`" is the real signal.
const HEALTH_SIGN_WINDOW: u64 = 20;
/// Height must be frozen at least this long before the heartbeat calls the chain stalled.
const HEALTH_STALL_WARN_SECS: u64 = 15;
/// Grace period after startup before the heartbeat is allowed to warn — avoids crying wolf while
/// the node still has too little history or is settling into its first rounds.
const HEALTH_START_GRACE_SECS: u64 = 90;

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
    /// Set while the startup catch-up runs, cleared when it finishes. Shared with the RPC
    /// server (so `GET /status` can report it) and with `block_production_loop`, which must
    /// not propose anything until it clears — see `run`.
    syncing: Arc<std::sync::atomic::AtomicBool>,
    /// Tip the startup sync is working towards, 0 when unknown. Purely informational.
    sync_target_height: Arc<std::sync::atomic::AtomicU64>,
    /// The committed tip height this node announces on the peer-exchange gossip, so peers can see
    /// they are behind us and be served the blocks they are missing (#137). Shared with
    /// [`P2PService`], which reads it on every announcement; written here at startup, after the
    /// initial sync, and by `publish_tip_certificate` at every commit.
    announced_tip_height: Arc<std::sync::atomic::AtomicU64>,
    /// Highest tip any connected peer claims, published by [`P2PService`] (backlog #154).
    ///
    /// Untrusted, and used only in the safe direction: to decide that a node held back after a
    /// failed startup sync (#152) has caught up with what the network is offering. A peer claiming
    /// too low cannot release us early (this is a maximum, so an honest higher claim wins); one
    /// claiming too high can only keep holding us, which costs this node its own liveness and
    /// nothing else — and only while the RPC catch-up, the independent second release path, is
    /// also unavailable.
    highest_peer_tip: Arc<std::sync::atomic::AtomicU64>,
    /// Live commit certificate for the current tip — served at `/sync/tip-certificate` (#133) and
    /// used to certify a block handed to a peer over block sync (#138). Created in the constructor
    /// rather than in `run()` because [`StoreBlockProvider`] needs to share the very same cell.
    tip_certificate: Arc<RwLock<TipCertificate>>,
    /// Where this node's double-sign high-water mark lives — next to `validator-key.json`. Loaded
    /// into a [`SigningGuard`] in `run()`. See `signing_guard` for why the protection sits on the
    /// broadcast path rather than in the consensus engine.
    signing_state_path: PathBuf,
}

impl HelixNode {
    pub async fn new() -> Result<Self> {
        // `helix.toml` (path overridable via HELIX_CONFIG) bundles the node
        // params below; env vars still take precedence over the file, see
        // `config::resolve`.
        let cfg = config::load_node_config()?;

        let key_path = resolve_validator_key_path(&cfg);
        // Double-sign state lives beside the key it protects: validator-key.json ->
        // validator-key.signing-state.json. See `signing_guard`.
        let signing_state_path = key_path.with_extension("signing-state.json");
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
        let db_path = PathBuf::from(CHAIN_DB_FILE);
        let mut store = HelixDb::open(&db_path)?;

        // How the last run ended, before anything else can overwrite the evidence.
        //
        // A node that stops answering is the most common thing an operator has to diagnose, and
        // until now nothing distinguished a clean stop from a crash, an OOM kill or a hard
        // `kill -9` — the log simply ended. That made "why does my node keep dying?" genuinely
        // unanswerable, including for us when a validator's absence stalls the chain.
        let run_record_path = crate::run_record::path_beside(&db_path);
        {
            let previous = crate::run_record::begin_run(
                &run_record_path,
                env!("CARGO_PKG_VERSION"),
                store.latest_height(),
            );
            crate::run_record::report_previous_run(previous.as_ref());
        }

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

        let genesis_cfg = GenesisConfig::devnet_with_personhood_authority(address.clone(), personhood_authorities);

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

        let chain_state = if store.get_block_by_height(0).is_ok() {
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

            // Before the block is rebuilt, hashed against the peer's own claim, or written
            // (backlog #139). This is the one check in the join path that does not originate with
            // the peer being trusted.
            let expected_genesis = expected_genesis_hash(
                config::resolve("HELIX_GENESIS_HASH", &cfg.genesis_hash),
                Some(peer_url.as_str()),
            );
            verify_genesis_checkpoint(expected_genesis.as_deref(), &genesis)?;

            // Rebuild through the same function the peer hashed, taking every field from the
            // peer rather than from this binary's own defaults — they describe a chain this node
            // isn't joining. `allocations` in particular is replaced, never merged: adding a
            // local prefund on top would mint HLX the real chain never issued.
            let state = helix_executor::genesis::rebuild_genesis_state(
                genesis.header.validator.clone(),
                peer_genesis.personhood_authorities.clone(),
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
        } else if joins_over_p2p(new_chain, &configured_seed_peers(&cfg)) {
            // No local chain and no RPC `sync_peer`, but the operator named P2P peers — join from
            // those alone (#139). Until this branch existed, adopting a genesis was possible only
            // through `GET /genesis`, so joining the network required somebody to run a reachable
            // HTTP server; in practice that somebody was us, and it was the last hard dependency on
            // one machine left in the join path.
            //
            // Ordered *after* the `sync_peer` branch on purpose: an operator who configured an RPC
            // peer named a specific source, and silently preferring a different one would answer a
            // question they had already answered.
            //
            // Gated on `!new_chain` for the same reason, and that gate is not decoration. Seed peers
            // and "start a standalone chain" are routinely set together — every local devnet and the
            // production origin node do exactly that, because the seed list is how a validator set
            // is wired into a mesh, not a statement about where the chain came from. Without the
            // gate those nodes stop self-signing, spend the fetch timeout asking peers that do not
            // exist yet, and then fail to start at all. Caught by the multi-node integration tests
            // after the unit suite was entirely green.
            let peers = configured_seed_peers(&cfg);
            info!(peers = peers.len(), "No local chain and no sync peer — fetching genesis over P2P");
            let payload =
                helix_p2p::fetch_genesis_over_p2p(&peers, helix_p2p::GENESIS_FETCH_TIMEOUT).await?;
            let genesis = payload.block.clone();

            // The same checkpoint the RPC path applies, and for a stronger reason here: over P2P
            // the answer comes from whichever peer replied first, not from a source the operator
            // named. Compared against a locally recomputed `Block::hash()` — never against anything
            // the peer says about the block — and before anything is rebuilt or written.
            let expected_genesis = config::resolve("HELIX_GENESIS_HASH", &cfg.genesis_hash);
            verify_genesis_checkpoint(expected_genesis.as_deref(), &genesis)?;

            let state = helix_executor::genesis::rebuild_genesis_state(
                genesis.header.validator.clone(),
                payload.personhood_authorities.clone(),
                payload.validator_stake,
                payload.allocations.clone(),
                helix_executor::GovernanceParams {
                    min_validator_stake: payload.min_validator_stake,
                    fuel_per_fee_unit: payload.fuel_per_fee_unit,
                },
            );

            // Same self-certifying caveat as over RPC: both halves came from the same peer, so this
            // catches an inconsistent answer, never a coherently false one. The checkpoint above is
            // the check that does not originate with the peer.
            if let Some(claimed) = &payload.state_hash {
                let ours = state.state_hash().to_hex();
                if &ours != claimed {
                    anyhow::bail!(
                        "rebuilt genesis state does not match the peer's: ours {ours}, theirs {claimed}"
                    );
                }
            }

            store.put_block(genesis.clone())?;
            info!(validator = %genesis.header.validator, "Adopted genesis received over P2P (height 0)");
            store.save_chain_state(&state)?;
            state
        } else {
            let sig = keypair.sign(b"helix-genesis-v1")?;
            // Wall-clock timestamp, not the historical hardcoded 0: it makes this genesis hash
            // — and hence the chain_id the signing guard uses to tell chains apart — unique to
            // this reset. Without it every reset that reused the validator key produced a
            // byte-identical genesis (all other fields are deterministic, ML-DSA signing
            // included), so a returning validator's stale double-sign high-water mark was never
            // recognised as belonging to a dead chain and gagged it into silence. Joining nodes
            // adopt this block verbatim (the sync_peer branch above), so all nodes on this chain
            // still share one chain_id.
            let genesis_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let genesis = genesis_block(address.clone(), keypair.public.clone(), sig, genesis_ts);
            store.put_block(genesis)?;
            info!("Genesis block created (height 0)");

            let state = genesis_cfg.build_state();
            store.save_chain_state(&state)?;
            info!("Genesis: no liquid pre-mine — validator earns via 50/50 fee split plus the halving block reward");
            state
        };

        // NOTE: the historical catch-up does NOT happen here any more — it runs in `run`,
        // after the RPC server is listening. Downloading it from inside the constructor meant
        // the node answered nothing at all until it finished: no RPC, no P2P, no status. On the
        // live chain that was 36 minutes (measured 2026-07-21) in which a healthy node and a
        // broken one looked exactly alike, and the wallet had no way to tell it was making
        // progress. Bitcoin Core serves its RPC from the first second and reports the sync as
        // progress; this now does the same.

        // P2P setup — `p2p_listen_addr` in helix.toml (or HELIX_P2P_LISTEN) overrides
        // the default listen address; unset means keep P2PConfig::default().
        let mut p2p_config = P2PConfig {
            // Remember peers across restarts, beside the chain database rather than inside it.
            //
            // Without this a node came back knowing only its configured seeds — in practice the
            // one built-in endpoint — no matter how much of the network it had met while running.
            // Beside the database on purpose: deleting chain data is something operators do (and
            // were told to do, wrongly, by our own health line before #150), and that is exactly
            // the moment a node most needs to still know who to ask.
            peer_store_path: Some(db_path.with_file_name("helix-peers.txt")),
            ..P2PConfig::default()
        };
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
        p2p_config.seed_peers.extend(configured_seed_peers(&cfg));

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
        // Seeded from the store's real tip, not 0 (#137). A restart must announce the height it
        // actually holds from its very first peer-exchange broadcast — a node that announced 0
        // until its first commit would be written off as "hopelessly behind" and refused a serve
        // by `should_serve_catchup`, which is exactly the node that needs one: a stalled validator
        // never reaches a commit to correct the number.
        let announced_tip_height =
            Arc::new(std::sync::atomic::AtomicU64::new(store.latest_height()));
        // Wrapped here rather than in `run()` because the service is constructed here and needs the
        // provider up front. Both handles are shared with the node, so what the provider serves is
        // always the node's live store and live tip certificate, never a snapshot.
        let shared_store = Arc::new(RwLock::new(store));
        // Shared before the P2P service is built, because the genesis provider (#139) needs it and
        // the service is constructed above the point where the node struct is assembled.
        let shared_chain_state = Arc::new(RwLock::new(chain_state));
        let shared_tip_certificate = Arc::new(RwLock::new(TipCertificate::default()));
        let block_provider: Arc<dyn helix_p2p::BlockProvider> = Arc::new(StoreBlockProvider {
            store: shared_store.clone(),
            tip_certificate: shared_tip_certificate.clone(),
        });
        let highest_peer_tip = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (p2p_service, p2p_command_tx, p2p_event_rx) = P2PService::new(
            p2p_config,
            announced_tip_height.clone(),
            block_provider,
        );
        // Which chain this node is on, announced to peers so one on a different chain is named
        // rather than silently rejecting everything we send it (#164). Read from the store, which
        // by this point holds the genesis whether it was loaded, adopted or self-signed.
        let our_genesis_hash = shared_store
            .read()
            .await
            .get_block_by_height(0)
            .map(|b| b.hash().to_hex())
            .unwrap_or_default();

        let p2p_service = p2p_service
            .announcing_genesis(our_genesis_hash)
            .with_peer_tip_reporting(highest_peer_tip.clone())
            // Every node serves its own genesis, so joining never depends on one particular
            // machine being up — the point of #139.
            .with_genesis_provider(Arc::new(StoreGenesisProvider {
                store: shared_store.clone(),
                chain_state: shared_chain_state.clone(),
            }));

        let rpc_bind = resolve_rpc_bind(&cfg)?;

        // Mempool TTL — `mempool_tx_ttl_secs` in helix.toml, or HELIX_MEMPOOL_TX_TTL_SECS;
        // unset means keep Mempool's built-in DEFAULT_TTL.
        let mempool = match config::resolve_u64("HELIX_MEMPOOL_TX_TTL_SECS", cfg.mempool_tx_ttl_secs) {
            Some(secs) => Mempool::with_ttl(std::time::Duration::from_secs(secs)),
            None => Mempool::new(),
        };

        let has_sync_peer = sync_peer.is_some();

        Ok(HelixNode {
            keypair: Arc::new(keypair),
            address,
            reward_address,
            sync_peer,
            store: shared_store,
            mempool: Arc::new(RwLock::new(mempool)),
            chain_state: shared_chain_state,
            p2p_command_tx,
            p2p_event_rx,
            p2p_service: Some(p2p_service),
            p2p_port,
            p2p_public_addr,
            rpc_bind,
            // Starts true whenever there is a peer to catch up from: `run` clears it once the
            // sync finishes (or immediately, if there is nothing to sync from). Claiming
            // "synced" before checking would be the same lie the old hardcoded `false` told.
            syncing: Arc::new(std::sync::atomic::AtomicBool::new(has_sync_peer)),
            sync_target_height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            announced_tip_height,
            highest_peer_tip,
            tip_certificate: shared_tip_certificate,
            signing_state_path,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        // Shared peer count for RPC status
        let peer_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Live commit certificate for the current tip — served at `/sync/tip-certificate` (#133).
        // Updated by every path that commits a block (all funnel through `apply_finalized_block`),
        // plus the RPC catch-up loop once it seeds one. Starts empty: this node has no tip
        // certificate to offer until it has committed (or adopted) its first block.
        // The cell itself is created in the constructor, so `StoreBlockProvider` — handed to the
        // P2P service there — shares it rather than watching a second, always-empty copy (#138).
        let tip_certificate = self.tip_certificate.clone();
        // Reload the last persisted tip certificate so a restart serves the real tip immediately
        // rather than `height: 0` for the block-interval it takes to commit again (#134).
        load_persisted_tip_certificate(&self.store, &tip_certificate).await;

        let rpc_state = AppState {
            store: self.store.clone(),
            mempool: self.mempool.clone(),
            chain_state: self.chain_state.clone(),
            node_address: self.address.to_string(),
            peer_count: peer_count.clone(),
            syncing: self.syncing.clone(),
            sync_target_height: self.sync_target_height.clone(),
            p2p_port: self.p2p_port,
            p2p_public_addr: self.p2p_public_addr.clone(),
            p2p_command_tx: self.p2p_command_tx.clone(),
            // `None` unless this operator set HELIX_FAUCET_KEY. The node's own address goes in
            // so the faucet can refuse to be the validator key — see `helix_rpc::faucet`.
            faucet: helix_rpc::faucet::Faucet::from_env(&self.address.to_string()),
            tip_certificate: tip_certificate.clone(),
        };

        // Spawn RPC server — first, before any catch-up, so `GET /status` answers from the
        // very first second and can report the sync as progress instead of the node being a
        // black box until it finishes.
        let rpc_bind: SocketAddr = self.rpc_bind;
        info!("RPC bind address  : {}", rpc_bind);
        tokio::spawn(async move {
            start_rpc_server(rpc_state, rpc_bind).await;
        });

        // Historical catch-up, now that the RPC is up (spawned just above, so `GET /status`
        // keeps answering — reporting `is_syncing` — throughout the wait below; that is the
        // whole point of #107 and is preserved).
        //
        // Awaited to completion HERE, *before* the BFT engine is constructed, rather than being
        // spawned to run alongside it. The engine is seeded entirely from the persisted chain
        // tip a few lines down — height, tip hash, base fee, and the validator set. When this
        // sync was a detached task, a genuinely fresh node built that engine from its height-0
        // genesis while the sync was still fetching: it would then rotate `active_validators` in
        // *chain state* as it applied blocks, but nothing mirrors a sync-path rotation into the
        // live engine (only the finalize path calls `rotate_validator_set`). The result was a
        // freshly-synced validator running a stale height-0 validator set — it disagreed with the
        // rest of the network on the round-robin proposer schedule and silently stalled the chain
        // the instant it was expected to co-sign. Structurally invisible on a single-validator
        // network (a one-element set has only one order) and it only bites when the joining node
        // crosses its own activation rotation *during sync* rather than while live — the exact
        // post-reset onboarding case. See backlog #129. Awaiting here makes a fresh sync seed the
        // engine from the true tip, exactly as an ordinary restart (whose DB is already current)
        // already does. Consensus additionally waits on `syncing` in `block_production_loop`; a
        // node that proposes while still missing history would fork off a chain it hasn't seen.
        if let Some(peer_url) = self.sync_peer.clone() {
            // Best-effort: the target is only for the progress display, so an old or
            // unreachable peer just leaves it at 0 (reported as `null`) rather than
            // holding up the sync itself.
            if let Ok(client) = peer_http_client(Duration::from_secs(10)) {
                if let Ok(tip) = fetch_peer_height(&client, &peer_url).await {
                    self.sync_target_height.store(tip, std::sync::atomic::Ordering::Relaxed);
                }
            }
            let local_tip = self.store.read().await.latest_height();
            info!(peer = %peer_url, local_tip, "Syncing blocks from peer");
            let result = {
                let mut s = self.store.write().await;
                let mut cs = self.chain_state.write().await;
                sync_blocks_from_peer(&peer_url, local_tip, &mut s, &mut cs).await
            };
            let failed = result.is_err();
            match result {
                Ok(synced) => info!(applied = synced, "Block sync complete"),
                // Same tolerance as before this moved out of the constructor: an
                // unreachable peer must not stop the node, it just starts from what it has.
                Err(e) => warn!(error = %e, "Block sync failed (continuing anyway)"),
            }

            // Clearing this unconditionally — as this used to — lets a node that failed to sync
            // start producing and voting on whatever height it happens to hold (backlog #152).
            //
            // For a follower "carry on with what you have" is right, and is what the tolerance
            // above is for. For a validator with no chain it is the worst available outcome: it
            // votes at height 1, every peer rejects those votes ("vote is for height=1/round=N,
            // expected …"), and it is simply absent from the quorum. On a small set that stops the
            // chain — and the node cannot recover through this gate, because `syncing` is never
            // set back to true anywhere.
            //
            // The condition is deliberately *not* "the sync failed". A validator whose chain is
            // complete and whose peer is briefly unreachable must keep validating; refusing that
            // would turn every transient network blip into an outage — the opposite mistake, and a
            // worse one. What actually disqualifies a node is having meant to join an existing
            // chain and holding none of it: `sync_peer` configured, and nothing above genesis.
            //
            // Released again by the periodic RPC catch-up once it has drawn level (see
            // `rpc_sync_loop`), which is the same peer this just failed against — so a peer that
            // was merely down for a moment costs one poll interval, not the session.
            let have_no_chain = self.store.read().await.latest_height() == 0;
            if hold_production_after_failed_sync(failed, have_no_chain) {
                warn!(
                    peer = %peer_url,
                    "Holding block production: this node has no chain yet and could not sync from \
                     its peer. It will not propose or vote until it has caught up — a validator \
                     voting at height 0 is invisible to the network and only removes itself from \
                     the quorum. Retrying in the background; check that the sync peer is reachable."
                );
            } else {
                self.syncing.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Keep the tip height announced to peers (#137) in step with the store.
        //
        // On a timer reading the store, deliberately, rather than pushed from each of the paths
        // that commit a block. Those are three (the `apply_finalized_block` funnel, the P2P
        // gap-fill, the RPC catch-up loop) plus the bulk startup sync, and a copy of this
        // assignment in each is a copy that can be forgotten when a fourth path appears — the
        // duplicated-invariant trap, where the omission looks like nothing at all until a node
        // silently announces a stale height and is refused the blocks it needs. Reading the store
        // cannot drift from the store no matter who wrote to it.
        //
        // Well below the 30-second announcement interval, so the value a peer receives is never
        // meaningfully behind; one cheap height read per tick.
        tokio::spawn({
            let store = self.store.clone();
            let announced_tip_height = self.announced_tip_height.clone();
            let highest_peer_tip = self.highest_peer_tip.clone();
            let syncing = self.syncing.clone();
            async move {
                let mut tick = tokio::time::interval(Duration::from_secs(5));
                loop {
                    tick.tick().await;
                    let tip = store.read().await.latest_height();
                    announced_tip_height.store(tip, std::sync::atomic::Ordering::Relaxed);

                    // Second release path for production held after a failed startup sync
                    // (backlog #154). #152 releases via the RPC catch-up, which ties resuming to
                    // the one central dependency the P2P block sync exists to remove: a node that
                    // catches up purely over P2P would otherwise stay mute until the RPC peer
                    // happened to answer.
                    //
                    // Safe because the claim is only ever used to *stop* holding, never to hold
                    // longer or to skip ahead: releasing needs our own verified height to have
                    // reached the highest claim, so a peer claiming too low cannot release us
                    // early (an honest higher claim wins the maximum), and one claiming too high
                    // merely keeps this node quiet — its own liveness, nobody else's, and only
                    // while the RPC path is also down. Both paths are ORed, never ANDed.
                    if syncing.load(std::sync::atomic::Ordering::Relaxed) {
                        let claimed = highest_peer_tip.load(std::sync::atomic::Ordering::Relaxed);
                        if claimed > 0 && tip >= claimed {
                            syncing.store(false, std::sync::atomic::Ordering::Relaxed);
                            info!(
                                height = tip,
                                claimed,
                                "Caught up with what peers are announcing — resuming block \
                                 production"
                            );
                        }
                    }
                }
            }
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
        // rotated to — not epoch 0 with only this node as validator. Built from
        // `engine_validator_set()` (the rotation's own truth, `active_validators`),
        // not raw `stakers()`, so a node that synced up to the tip runs exactly the
        // set every live node rotated to — including honouring the one-epoch activation
        // delay for a staker that has not been rotated in yet. See backlog #129.
        let genesis_height = self.store.read().await.latest_height();
        let validator_set = {
            let state_guard = self.chain_state.read().await;
            let validators = validators_from_state(&state_guard);
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
        // Double-sign protection: every outbound vote is checked against a durable high-water
        // mark before it is gossiped, so a restart or a stray second instance can't equivocate
        // and get this validator slashed. Seeded with the persisted tip so it never re-signs an
        // already-committed height even on a first run with no state file. See `signing_guard`.
        // The chain this signing state belongs to — the genesis block's hash. A reset to a new
        // genesis (a different chain that happens to reuse this validator key) must not inherit the
        // old chain's high-water mark: the old chain reached far higher heights, so every vote on
        // the fresh chain would look like a regression and the validator would sit bonded-but-silent
        // forever (diagnosed live 2026-07-26). Same genesis across a restart keeps its mark, so the
        // double-sign protection is unchanged within a chain.
        let chain_id = self
            .store
            .read()
            .await
            .get_block_by_height(0)
            .map(|b| b.hash())
            .unwrap_or(helix_crypto::Hash::ZERO);
        let signing_guard = Arc::new(std::sync::Mutex::new(SigningGuard::load(
            self.signing_state_path.clone(),
            genesis_height,
            chain_id,
        )));
        // Seed the engine's chain-continuity check with the real tip hash — without
        // this, `validate_block`'s prev_hash check stays silently disabled until this
        // engine's own first `finalize()`, the exact restart window a diverged
        // proposal is most likely to slip through in.
        {
            let tip_hash = self.store.read().await.latest_hash();
            engine.write().await.seed_last_committed(tip_hash);
        }

        // Resume above the round this key already signed, instead of rejoining wherever the
        // network happens to be (backlog #165).
        //
        // A round number lives only in memory. A restarting validator therefore rejoins at whatever
        // round its peers are on, which can be *below* the round it had already climbed to — and
        // its own double-sign guard then correctly refuses every vote at a round it has already
        // signed. The node is mute until the network works its way back up, one round timeout at a
        // time, and the longer the stall that prompted the restart, the longer the silence
        // afterwards. Live on 2026-08-05: reached round 10, restarted into round 7, withheld its
        // votes for three and a half minutes with the chain stopped throughout, because a
        // two-validator set needs both of them.
        //
        // `+ 1` because the guard's own round is burned: it holds a value signed there already.
        if let Some((signed_height, signed_round)) = signing_guard
            .lock()
            .map(|g| g.last_signed())
            .unwrap_or(None)
        {
            let resume_round = signed_round.saturating_add(1);
            let mut e = engine.write().await;
            e.resume_at_round(signed_height, resume_round);
            if e.pending_round() == resume_round {
                info!(
                    height = signed_height,
                    round = resume_round,
                    "Resuming above the last round this key signed — rejoining below it would gag \
                     this validator until the network caught back up"
                );
            }
        }
        // Seed the EIP-1559 base fee the next block must carry, deterministically derived from
        // the persisted chain tip — otherwise a restart resumes at `INITIAL_BASE_FEE_PER_BYTE`
        // and would stamp/expect the wrong base fee for its first produced/validated block,
        // diverging from peers that never restarted. The engine keeps this value out of its own
        // consensus state; the node (which holds the blocks) is the source of truth for it.
        if let Ok(tip) = self.store.read().await.get_block_by_height(genesis_height) {
            publish_base_fee(&engine, &self.mempool, base_fee_for_next_block(&tip)).await;
        }
        // Same reasoning one field over: a node restarting mid-probation would otherwise hold an
        // empty exemption set until its first applied block, and refuse its own heartbeat in the
        // window where it most wants to send one.
        publish_fee_exempt_probationers(&self.chain_state, &self.mempool).await;

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
        let signing_guard_for_p2p = signing_guard.clone();
        let tip_certificate_for_p2p = tip_certificate.clone();
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
                    &signing_guard_for_p2p,
                    &tip_certificate_for_p2p,
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
            tip_certificate.clone(),
            self.syncing.clone(),
        ));

        // Validator health heartbeat — logs "am I actually validating?" on its own timer, so an
        // operator watching the console sees the truth even when the consensus loop has silently
        // stalled. Independent of block production and purely observational.
        // One shared truth for "is the chain held up by missing validators?", so the health
        // heartbeat and the production loop cannot contradict each other about it (#150).
        let quorum_peers_missing = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // How many other validators' votes are not reaching us, published by
        // `block_production_loop` for the health loop. Same lock-free reasoning as above:
        // the health loop must keep talking exactly when the consensus path is wedged.
        let silent_peer_validators = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // Proof of life for the production loop, watched by the health heartbeat (#151).
        let production_ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));

        tokio::spawn(validator_health_loop(
            self.store.clone(),
            self.chain_state.clone(),
            self.address.clone(),
            peer_count.clone(),
            self.syncing.clone(),
            quorum_peers_missing.clone(),
            silent_peer_validators.clone(),
            production_ticks.clone(),
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
            self.syncing.clone(),
            signing_guard,
            tip_certificate,
            quorum_peers_missing,
            silent_peer_validators,
            production_ticks,
        ));

        // SIGTERM as well as SIGINT. `ctrl_c()` alone catches only SIGINT, which pm2 sends —
        // but systemd and Docker send SIGTERM, so on those the orderly stop would have looked
        // exactly like a crash in the run record below. A "your node was killed" warning that
        // fires on every planned restart is worse than no warning: it is the kind of false alarm
        // that teaches operators to ignore the line, and this line has to be believed the one
        // time it is real.
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .ok();
        let terminate = async {
            match sigterm.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                // No SIGTERM handler (non-Unix, or the handler could not be installed): fall back
                // to never firing, so SIGINT still works and nothing else changes.
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received (SIGINT).");
                // Only this path is an orderly stop. A panic in the block loop below is not, and
                // must stay indistinguishable from a kill in the record — otherwise the next
                // start would report a crash as a clean shutdown, which is the one lie this
                // mechanism must not tell.
                crate::run_record::mark_clean(
                    &crate::run_record::path_beside(std::path::Path::new(CHAIN_DB_FILE)),
                    self.store.read().await.latest_height(),
                );
            }
            _ = terminate => {
                info!("Shutdown signal received (SIGTERM).");
                crate::run_record::mark_clean(
                    &crate::run_record::path_beside(std::path::Path::new(CHAIN_DB_FILE)),
                    self.store.read().await.latest_height(),
                );
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
    signing_guard: &Arc<std::sync::Mutex<SigningGuard>>,
    tip_certificate: &Arc<RwLock<TipCertificate>>,
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
            broadcast_outbound_votes(engine, p2p_tx, signing_guard).await;
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
                    apply_finalized_block(block, true, vec![], store, mempool, chain_state, engine, p2p_tx, None, last_applied_height, tip_certificate).await;
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
            broadcast_outbound_votes(engine, p2p_tx, signing_guard).await;
            let evidence = { engine.write().await.take_evidence() };
            for ev in evidence {
                report_double_sign_evidence(ev, keypair, chain_state, mempool, p2p_tx).await;
            }

            match result {
                Ok(Some(block)) => {
                    info!(height = block.height(), "Block finalized via peer votes");
                    // Same reasoning as the NewProposal arm above: this block's proposer
                    // isn't necessarily us, so `None` — not our local reward_address.
                    apply_finalized_block(block, true, vec![], store, mempool, chain_state, engine, p2p_tx, None, last_applied_height, tip_certificate).await;
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
        P2PEvent::NewCommittedBlock(block, commit_certificate) => {
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
                    // Whatever the outcome, the guard must not be left behind the store: a sync
                    // that applied blocks and then aborted returns `Err`, and the arm below would
                    // never run (#145).
                    settle_applied_height(&mut last, store).await;
                    match result {
                        Ok((n, new_height, new_hash)) if n > 0 => {
                            *last = new_height;
                            // This apply bypassed receive_proposal/add_vote and
                            // apply_finalized_block entirely — keep the engine's height
                            // tracking and EIP-1559 base fee in step, same as
                            // rpc_sync_loop does after its own sync_blocks_from_peer call.
                            // Gap-filled over the RPC /sync/blocks path, which carries no
                            // certificate in-band. Fetch the peer's tip certificate for exactly the
                            // block we stopped on and adopt it, so — if this node later proposes —
                            // its next block stamps a real last_commit rather than an empty one
                            // (#133, closing #114 for the RPC path). Empty on any failure, i.e. the
                            // unchanged pre-#133 behaviour; the engine re-verifies it regardless.
                            let cert = fetch_tip_certificate(peer_url, new_height, new_hash).await;
                            engine.write().await.sync_to_externally_finalized_block(new_height, new_hash, cert);
                            // Mirror any validator rotation those synced blocks applied in chain
                            // state into the live engine — the finalize path that normally does
                            // this was skipped. Without it, a validator that crossed its own
                            // activation while filling this gap keeps a stale set and never votes,
                            // stalling the chain while reporting itself bonded-but-silent.
                            reconcile_engine_validator_set(engine, chain_state, new_height).await;
                            if let Ok(tip) = store.read().await.get_block_by_height(new_height) {
                                publish_base_fee(engine, mempool, base_fee_for_next_block(&tip)).await;
                            }
                            // Surface the certificate we just adopted (if any) so a follower syncing
                            // from *this* node can obtain the tip's too (#133).
                            publish_tip_certificate(engine, tip_certificate, store, new_height, new_hash).await;
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
                    // BFT quorum gate (audit A1). The three checks above prove the block is
                    // well-formed, authored by an in-set validator, and builds on our tip — none of
                    // them proves 2/3 of the set actually finalized it. `TOPIC_COMMITTED_BLOCKS` is
                    // public, so without this a single Byzantine validator could self-sign a block
                    // it alone stands behind, gossip it here, and fork every receiver off the real
                    // chain — the exact guarantee BFT is supposed to hold at f < N/3. Require the
                    // accompanying certificate to carry precommits summing to quorum for *this*
                    // block before adopting it. The certificate is untrusted wire data; every
                    // signature in it is re-verified against the current set (`precommits_reach_quorum`).
                    let has_quorum = {
                        let eng = engine.read().await;
                        let set = eng.validator_set();
                        // Bootstrap window: before the network's first `Stake` tx there is no staked
                        // power to form a quorum from — the only producer is the genesis/self-fallback
                        // validator, and the `is_known_validator` check above is the only gate that
                        // can apply. Once real stake exists this reduces to the strict quorum check.
                        // Same window `sync_blocks_from_peer` handles via `stakers().is_empty()`.
                        set.total_voting_power() == 0
                            || set.precommits_reach_quorum(&commit_certificate, block_height, &block.hash())
                    };
                    if !has_quorum {
                        warn!(
                            height = block_height,
                            validator = %block.header.validator,
                            "Committed block from peer carries no quorum certificate — dropping (not proven final)"
                        );
                        return;
                    }
                    info!(height = block_height, "Applying committed block from peer");
                    // `None`, same reasoning as the NewProposal/NewVote arms above: this
                    // block came from a peer, not our own block_production_loop, so our
                    // local reward_address override must not apply to it.
                    apply_finalized_block(block, false, commit_certificate, store, mempool, chain_state, engine, p2p_tx, None, last_applied_height, tip_certificate).await;

                    // Say out loud that we adopted it (#141). On a busy chain this path — not
                    // proposal/vote — is how a validator sees most blocks, and a node that only
                    // ever adopts appears in no `last_commit`, so nothing in the protocol records
                    // that it is running. Goes out through the same signing guard as every other
                    // vote, which is what makes it safe to sign a value we did not vote on live.
                    engine.write().await.attest_adopted_block(keypair);
                    broadcast_outbound_votes(engine, p2p_tx, signing_guard).await;
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
            // Saturating, not wrapping. The service now pairs these events strictly (#147), but
            // this counter gates block production via `peers >= needed` — and on an `AtomicUsize`
            // one unpaired decrement does not read as "-1", it reads as `usize::MAX`, which makes
            // every quorum-peer check pass forever. Cheap insurance against a future caller.
            let _ = peer_count.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| Some(n.saturating_sub(1)),
            );
        }
        P2PEvent::PeerBehind { peer_tip } => {
            serve_catchup_blocks(peer_tip, store, tip_certificate, p2p_tx).await;
        }
        P2PEvent::BlocksSynced(batch, peer) => {
            apply_synced_batch(batch, peer, store, chain_state, engine, mempool, last_applied_height, tip_certificate, p2p_tx).await;
        }
    }
}

/// Raise the applied-height guard to whatever the store actually holds (backlog #145).
///
/// Every catch-up path can end in a *partial* apply: some blocks written, then an abort — a
/// tampered block, an unreachable peer mid-batch, a storage error. Those paths return `Err`, and
/// their callers only advance the guard in the `Ok` arm, so the guard silently falls behind the
/// store.
///
/// That gap is not cosmetic, because the guard is the *only* thing standing between two ingest
/// paths and executing the same block twice: `apply_finalized_block` compares the incoming height
/// against it and nothing else — there is no check that the block chains from the current tip. A
/// height the aborted sync already applied therefore passes straight through and is executed
/// again, minting its block reward a second time. Measured 2026-07-31: two nodes agreeing on
/// `ba6128de…` at height 310 while a third sat on `c0771c6b…`, which is #142's failure exactly,
/// reached through a different door.
///
/// The store is the authority here, not the return value: it knows what was persisted regardless
/// of how the call ended. Only ever raises the guard — lowering it would reintroduce the very
/// window it exists to close.
async fn settle_applied_height(last: &mut u64, store: &Arc<RwLock<HelixDb>>) {
    let stored = store.read().await.latest_height();
    if *last < stored {
        debug!(guard = *last, stored, "Catch-up ended part-way — raising the applied-height guard");
        *last = stored;
    }
}

/// Verify and apply a block batch a peer sent in answer to our block-sync request (#138).
///
/// Structured exactly like the RPC gap-fill branch above — hold `last_applied_height` across the
/// whole apply, re-check the tip under that lock, then bring the engine back in step afterwards —
/// with one difference that matters: nothing is written until [`verify_block_batch`] has passed on
/// the batch as a whole, so a peer that lies costs a round trip rather than a corrupted store.
#[allow(clippy::too_many_arguments)]
async fn apply_synced_batch(
    batch: BlockSyncResponse,
    peer: String,
    store: &Arc<RwLock<HelixDb>>,
    chain_state: &Arc<RwLock<ChainState>>,
    engine: &Arc<RwLock<BftEngine>>,
    mempool: &Arc<RwLock<Mempool>>,
    last_applied_height: &Arc<Mutex<u64>>,
    tip_certificate: &Arc<RwLock<TipCertificate>>,
    p2p_tx: &mpsc::Sender<P2PCommand>,
) {
    if batch.blocks.is_empty() {
        return;
    }

    // Held for the whole operation, like the gap-fill path: `execute_block` below runs outside the
    // guard `apply_finalized_block` checks, so without this a concurrent BFT-finalize or gossip
    // event for the same height could mint the block reward twice.
    let mut last = last_applied_height.lock().await;
    let (base, base_hash) = {
        let s = store.read().await;
        (s.latest_height(), s.latest_hash())
    };
    // Another path may have caught us up while we waited for the lock — this is a re-check under
    // it, not a redundant one.
    if batch.blocks.last().map(|b| b.height()).unwrap_or(0) <= base {
        return;
    }

    let validator_set = {
        let cs = chain_state.read().await;
        ValidatorSet::new(
            validators_from_state(&cs),
            base / helix_consensus::EPOCH_LENGTH,
        )
    };

    {
        let cs = chain_state.read().await;
        if let Err(e) = verify_block_batch(
            &batch.blocks,
            &batch.tip_certificate,
            base + 1,
            base_hash,
            &cs,
            &validator_set,
        ) {
            warn!(peer = %peer, err = %e, "Rejected a block-sync batch from a peer — nothing applied");
            // Tell the P2P service, or it will ask this same peer again on the very next tick:
            // it picks by highest claimed tip, and from its side a batch we threw away looks
            // exactly like one that applied cleanly (backlog #140). Nothing here trusts the peer
            // any less — the batch is already discarded — this only stops it from monopolising
            // catch-up while a healthy peer sits one block lower, unasked.
            let _ = p2p_tx.try_send(P2PCommand::BlocksyncBatchRejected(peer));
            return;
        }
    }

    let (new_height, new_hash) = {
        let mut s = store.write().await;
        let mut cs = chain_state.write().await;
        for block in &batch.blocks {
            execute_block(&mut cs, block, None);
            cs.applied_height = block.height();
            if let Err(e) = s.put_block(block.clone()) {
                // The batch verified, so this is a local storage failure, not a bad peer. Stop here
                // and keep what did persist: the next request resumes from the new tip.
                error!(height = block.height(), err = %e, "Failed to store a synced block");
                break;
            }
        }
        if let Err(e) = s.save_chain_state(&cs) {
            fatal_storage_failure("chain state", cs.applied_height, &e);
        }
        (s.latest_height(), s.latest_hash())
    };

    if new_height <= base {
        return; // nothing actually persisted
    }
    *last = new_height;

    // The batch carried its tip's certificate in-band, so unlike the RPC path there is nothing to
    // fetch — hand it straight to the engine, which verifies it again on its own terms (#114/#133).
    let tip_votes = if batch.blocks.last().map(|b| b.height()) == Some(new_height) {
        batch.tip_certificate.clone()
    } else {
        Vec::new()
    };
    engine.write().await.sync_to_externally_finalized_block(new_height, new_hash, tip_votes);
    // A rotation inside this batch has to reach the live engine, or a validator that crossed its own
    // activation while catching up runs a stale set and sits silent (#129/#130).
    reconcile_engine_validator_set(engine, chain_state, new_height).await;
    if let Ok(tip) = store.read().await.get_block_by_height(new_height) {
        publish_base_fee(engine, mempool, base_fee_for_next_block(&tip)).await;
    }
    publish_tip_certificate(engine, tip_certificate, store, new_height, new_hash).await;
    info!(
        applied = new_height - base,
        new_height, "Caught up over P2P block sync"
    );
}

/// Re-broadcast the committed blocks a peer that announced `peer_tip` is missing, each with the
/// commit certificate that finalized it, so it can adopt them through the ordinary
/// committed-blocks fast path (#137).
///
/// Why this exists at all: `BroadcastBlock` fires exactly once, at the moment of commit. A peer
/// whose link is down in that instant never hears of the block again — there is no request
/// protocol to ask for it, and the `NewCommittedBlock` gap-fill branch needs both a gap of two or
/// more *and* an operator-configured `sync_peer`. A validator one block behind therefore had no
/// route back at all, and being part of the quorum it took the whole chain down with it: it could
/// not advance without the block, and the block could not be superseded without its vote. That is
/// the 14.5-hour production stall of 2026-07-29, and the reason it survived a restart and full
/// reconnection of every peer.
///
/// Safe against a lying `peer_tip` by construction. The height only ever selects which of *our own
/// already-committed* blocks we upload; the receiver re-verifies each one from scratch (proposer
/// signature, known validator, `prev_hash`, and the certificate's quorum), so nothing here can put
/// a block into anyone's chain that the fast path would not have accepted anyway. The volume is
/// bounded twice — by `should_serve_catchup` before the event is emitted, and by
/// [`MAX_CATCHUP_SERVE_BLOCKS`] again here.
async fn serve_catchup_blocks(
    peer_tip: u64,
    store: &Arc<RwLock<HelixDb>>,
    tip_certificate: &Arc<RwLock<TipCertificate>>,
    p2p_tx: &mpsc::Sender<P2PCommand>,
) {
    let our_tip = store.read().await.latest_height();
    if peer_tip >= our_tip {
        return; // caught up (or ahead) since the announcement — nothing to serve
    }
    let last = our_tip.min(peer_tip + MAX_CATCHUP_SERVE_BLOCKS);

    for height in (peer_tip + 1)..=last {
        let block = match store.read().await.get_block_by_height(height) {
            Ok(b) => b,
            Err(e) => {
                warn!(height, err = %e, "Cannot serve catch-up block — not in our store");
                return;
            }
        };
        let certificate = catchup_certificate(&block, our_tip, store, tip_certificate).await;
        // Stop at the first block we cannot certify rather than skipping it. The receiver applies
        // the fast path strictly in sequence (anything above `our_height + 1` is a gap it cannot
        // fill without a `sync_peer`), so a hole makes every block after it useless — and sending
        // an uncertified block would just have it dropped by the receiver's quorum gate, which is
        // exactly the check that keeps this path from becoming a fork vector.
        if certificate.is_empty() {
            debug!(
                height,
                "No commit certificate available for this block — ending catch-up serve here"
            );
            return;
        }
        if p2p_tx.send(P2PCommand::BroadcastBlock(block, certificate)).await.is_err() {
            return; // P2P service gone; the node is shutting down
        }
        info!(height, peer_tip, "Serving a peer the committed block it is missing");
    }
}

/// Verify a batch of blocks offered by a peer *before* a single one of them is written (#138).
///
/// The whole batch rests on one proof: a BFT quorum certificate for its **last** block. Given an
/// unbroken `prev_hash` chain from our own tip up to a block that provably carries a quorum, every
/// block in between is an ancestor of a finalized block — so finality transfers backwards across the
/// batch and a peer cannot fabricate any part of it without forging a quorum for the tip. This is
/// why the caller must buffer the batch and only apply it after this returns `Ok`: verifying as you
/// write means a forged batch is already on disk by the time its tip fails.
///
/// `validator_set` must be derived from state we already trust — the caller's **pre-batch** state.
/// Deriving it by applying the batch first would be self-certifying: whoever supplies the blocks
/// would supply the set that validates them. That is also why a batch may not straddle a
/// validator-set rotation; `blocksync_request_count` in helix-p2p keeps requests inside one set.
///
/// The bootstrap window is exempt from the quorum requirement for the same reason every other
/// ingest path exempts it: before anyone has staked there is no set to reach a quorum in, and
/// without the exemption no node could ever sync its first blocks.
fn verify_block_batch(
    blocks: &[Block],
    tip_certificate: &[Vote],
    expected_first_height: u64,
    expected_prev_hash: Hash,
    chain_state: &ChainState,
    validator_set: &ValidatorSet,
) -> std::result::Result<(), String> {
    // Structure first, cryptography second: a peer must not be able to make us verify signatures
    // over a batch that is already provably not ours.
    let Some(first) = blocks.first() else {
        return Err("empty batch".into());
    };
    if first.height() != expected_first_height {
        return Err(format!(
            "batch starts at height {} but we need {}",
            first.height(),
            expected_first_height
        ));
    }

    let mut expected_prev = expected_prev_hash;
    for (i, block) in blocks.iter().enumerate() {
        let expected_height = expected_first_height + i as u64;
        if block.height() != expected_height {
            return Err(format!(
                "batch is not contiguous: expected height {} at position {}, got {}",
                expected_height,
                i,
                block.height()
            ));
        }
        if block.header.prev_hash != expected_prev {
            return Err(format!(
                "block {} does not chain from the previous block (expected prev_hash {}, got {})",
                block.height(),
                expected_prev,
                block.header.prev_hash
            ));
        }
        if block.exceeds_size_limit() {
            return Err(format!(
                "block {} carries {} transaction bytes, over the {}-byte limit",
                block.height(),
                block.transaction_bytes(),
                helix_core::fee::MAX_BLOCK_BYTES
            ));
        }
        expected_prev = block.hash();
    }

    // The proof that carries the batch. Checked before the per-block signatures below because it is
    // the cheaper of the two (one certificate versus one signature per block) and the one that a
    // forged batch fails.
    let tip = blocks.last().expect("non-empty, checked above");
    let bootstrapping = validator_set.total_voting_power() == 0;
    if !bootstrapping
        && !validator_set.precommits_reach_quorum(tip_certificate, tip.height(), &tip.hash())
    {
        return Err(format!(
            "the certificate for the batch tip (height {}) does not reach a BFT quorum — \
             refusing the whole batch",
            tip.height()
        ));
    }

    // Per-block proposer checks. Strictly implied by the quorum-certified tip plus the hash chain
    // above, kept because they are cheap relative to being wrong and because every other ingest
    // path applies them — a batch that passes here passes the same bar as one that arrived over
    // gossip or RPC.
    for block in blocks {
        if let Err(e) = block.header.verify_signature() {
            return Err(format!("block {} failed signature verification: {}", block.height(), e));
        }
        // Same bootstrap fallback as `sync_blocks_from_peer`: before the network's first `Stake`
        // tx, every node's own genesis fallback validator is absent from `stakers()`, so without
        // this no node could sync past block 1.
        let is_known_validator = chain_state.stakers().is_empty()
            || chain_state
                .stakers()
                .iter()
                .any(|(addr, _)| addr == &block.header.validator);
        if !is_known_validator {
            return Err(format!(
                "block {} is signed by an address outside the current validator set",
                block.height()
            ));
        }
    }

    Ok(())
}

/// Answers inbound block-sync requests from our own store (#138).
///
/// The counterpart to [`serve_catchup_blocks`]: that one pushes blocks at a peer we happened to
/// notice was behind, this one answers a peer that asked. Same certificate sourcing, same refusal
/// to hand over anything we cannot prove.
struct StoreBlockProvider {
    store: Arc<RwLock<HelixDb>>,
    tip_certificate: Arc<RwLock<TipCertificate>>,
}

/// Serves this node's genesis to peers joining over P2P (#139).
///
/// The fields are the same ones `GET /genesis` reports, assembled a second time here because the
/// two answers cross different boundaries — JSON out of `helix-rpc`, bincode out of `helix-p2p` —
/// and neither crate can own the other's type. **Both must be updated together when a genesis field
/// is added.**
///
/// What keeps that from being a silent trap: `state_hash` is computed by `rebuild_genesis_state`
/// from the very fields being sent, so a field left out here produces a hash that disagrees with
/// the joining node's own rebuild, and the join is refused rather than quietly landing on a subtly
/// different chain.
struct StoreGenesisProvider {
    store: Arc<RwLock<HelixDb>>,
    chain_state: Arc<RwLock<ChainState>>,
}

impl helix_p2p::GenesisProvider for StoreGenesisProvider {
    fn genesis<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = helix_p2p::GenesisResponse> + Send + 'a>>
    {
        Box::pin(async move {
            // No height 0 means this node has no chain to describe — a node still bootstrapping.
            // Answering honestly beats silence: a requester cannot tell silence from unreachable.
            let block = match self.store.read().await.get_block_by_height(0) {
                Ok(b) => b,
                Err(_) => return helix_p2p::GenesisResponse::empty(),
            };
            let cs = self.chain_state.read().await;

            // Rebuilt through the same function the joining node runs, so this answers "what should
            // your reconstruction come out as" rather than "what does my chain look like now",
            // which has moved on since height 0.
            let state_hash = helix_executor::genesis::rebuild_genesis_state(
                block.header.validator.clone(),
                cs.personhood_authorities.clone(),
                cs.genesis_validator_stake,
                cs.genesis_allocations.clone(),
                cs.governance_params.clone(),
            )
            .state_hash()
            .to_hex();

            helix_p2p::GenesisResponse {
                genesis: Some(helix_p2p::GenesisPayload {
                    block,
                    personhood_authorities: cs.personhood_authorities.clone(),
                    validator_stake: cs.genesis_validator_stake,
                    allocations: cs.genesis_allocations.clone(),
                    // This node's *current* governance params, not necessarily its genesis-time
                    // ones — the same caveat `GET /genesis` carries. A param changed by a proposal
                    // since genesis is applied retroactively from height 0 by a joining node. Both
                    // paths share the limitation; neither should grow it silently.
                    min_validator_stake: cs.governance_params.min_validator_stake,
                    fuel_per_fee_unit: cs.governance_params.fuel_per_fee_unit,
                    state_hash: Some(state_hash),
                }),
            }
        })
    }
}

impl helix_p2p::BlockProvider for StoreBlockProvider {
    fn blocks<'a>(
        &'a self,
        from_height: u64,
        count: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = BlockSyncResponse> + Send + 'a>> {
        Box::pin(async move {
            let our_tip = self.store.read().await.latest_height();
            if count == 0 || from_height == 0 || from_height > our_tip {
                return BlockSyncResponse::empty();
            }
            let last = our_tip.min(from_height + u64::from(count) - 1);

            let mut blocks = Vec::new();
            for height in from_height..=last {
                match self.store.read().await.get_block_by_height(height) {
                    Ok(block) => blocks.push(block),
                    // A hole in our own store — serve the contiguous prefix, nothing past it.
                    Err(_) => break,
                }
            }

            // Serve the longest prefix whose last block we can actually certify, shrinking from the
            // end rather than giving up outright. A block whose successor carries an empty
            // `last_commit` cannot be proven by us (the #113 legacy: blocks committed before the
            // certificate travelled with them), and refusing the whole range on account of the last
            // one would leave a requester permanently stuck at that height. Everything below it is
            // still provable and still useful.
            while let Some(tip) = blocks.last() {
                let certificate =
                    catchup_certificate(tip, our_tip, &self.store, &self.tip_certificate).await;
                if !certificate.is_empty() {
                    return BlockSyncResponse { blocks, tip_certificate: certificate };
                }
                blocks.pop();
            }
            BlockSyncResponse::empty()
        })
    }
}

/// The commit certificate for one of our stored blocks, as precommit votes, or empty when we hold
/// none for it.
///
/// Two sources, because a chain stores the certificate for block `h` in block `h + 1`'s header:
/// every block below our tip is certified by its successor's `last_commit`, while the tip itself
/// has no successor yet and is certified only by the live cell that #133/#134 maintain. The tip is
/// the interesting case — it is the block a peer one behind actually needs.
async fn catchup_certificate(
    block: &Block,
    our_tip: u64,
    store: &Arc<RwLock<HelixDb>>,
    tip_certificate: &Arc<RwLock<TipCertificate>>,
) -> Vec<Vote> {
    let height = block.height();
    let block_hash = block.hash();

    if height < our_tip {
        return match store.read().await.get_block_by_height(height + 1) {
            Ok(successor) => {
                commit_sigs_to_votes(successor.header.last_commit.clone(), height, block_hash)
            }
            Err(_) => Vec::new(),
        };
    }

    // The tip: only the live cell can certify it. Match on both height and hash — a certificate
    // for a different block is worse than none, and the receiver would reject it anyway.
    let cert = tip_certificate.read().await;
    if cert.height == height && cert.block_hash == block_hash.to_hex() {
        commit_sigs_to_votes(cert.signatures.clone(), height, block_hash)
    } else {
        Vec::new()
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

/// Send this node's probation heartbeat, if it is serving probation and has not yet proved
/// itself live this epoch (backlog #132/#141). No-op otherwise, which is the common case — an
/// active validator never sends one.
///
/// This is what turns "a node is running for this key" into a fact the chain can act on. It is a
/// transaction rather than anything in the consensus stream because a probationer holds zero
/// voting power and cannot be relied on to hold the tip: it may be catching up, and every
/// consensus-side signal has a delivery window it can miss. A transaction has none — it waits in
/// the mempool until some block includes it, and it works exactly when the node is behind, which
/// is the case all three earlier designs failed on.
///
/// Fee 0: the exemption in `execute_transaction` covers precisely this transaction from precisely
/// this sender, because an operator who staked their whole balance has nothing to pay with.
async fn send_probation_heartbeat_if_due(
    keypair: &KeyPair,
    chain_state: &Arc<RwLock<ChainState>>,
    mempool: &Arc<RwLock<Mempool>>,
    p2p_tx: &mpsc::Sender<P2PCommand>,
) {
    let self_address = Address::from_public_key(&keypair.public);
    let (nonce, applied_height) = {
        let state = chain_state.read().await;
        if !state.probation_proof_outstanding(&self_address) {
            return;
        }
        (
            state.get(&self_address).map(|acc| acc.nonce).unwrap_or(0),
            state.applied_height,
        )
    };

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::ProbationHeartbeat,
        from: self_address,
        to: None,
        amount: 0,
        fee: 0,
        nonce,
        // The height this attempt was made at, and the reason retries work at all.
        //
        // Without it every attempt is byte-identical — ML-DSA signs deterministically, and the
        // nonce cannot change — so gossipsub drops each repeat as "already been published" and
        // the local mempool rejects it as a pending nonce. The result was one delivery attempt
        // per epoch dressed up as ten: measured 2026-07-31, each joiner logged exactly one
        // heartbeat, and losing that single message cost the whole epoch (one four-validator run
        // in five). Varying the payload makes each retry a genuinely new message that peers have
        // not seen, which is the entire point of retrying.
        //
        // Only one of them can ever execute — they share a nonce — so the extras cost a rejected
        // transaction each and nothing else. Never read by the executor: the *signature* is the
        // proof, not this.
        data: applied_height.to_le_bytes().to_vec(),
        crypto_version: keypair.scheme,
        signature: Signature::from_bytes(vec![]),
        public_key: keypair.public.clone(),
    };
    tx.signature = match keypair.sign(tx.signing_hash().as_bytes()) {
        Ok(sig) => sig,
        Err(e) => {
            warn!(err = %e, "Failed to sign the probation heartbeat — will retry next tick");
            return;
        }
    };

    // The pool rejects every attempt after the first (same nonce still pending) — expected, and
    // not a reason to skip the broadcast: it is the *peers'* pools that decide whether this ever
    // reaches a block, and each retry is a distinct message to them.
    let first_attempt = mempool.write().await.add(tx.clone()).is_ok();
    if first_attempt {
        info!(height = applied_height, "Proving this node is live so the validator can leave probation");
    } else {
        debug!(height = applied_height, "Re-sending the probation heartbeat");
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

/// Mirror into the mempool which validators may currently send a fee-free probation heartbeat
/// (backlog #141). Without this the pool's set stays empty, every heartbeat is charged a fee its
/// sender may not have, and the promotion gate becomes unpassable again — the failure the whole
/// design exists to avoid, reintroduced one layer below where anyone would look for it.
///
/// Deliberately a separate function from `publish_base_fee` despite the identical shape: this one
/// reads chain state, and the sites that learn a new base fee are not all sites where the
/// probation cohort can change. Called from the commit funnel, which every applied block passes
/// through exactly once.
async fn publish_fee_exempt_probationers(
    chain_state: &Arc<RwLock<ChainState>>,
    mempool: &Arc<RwLock<Mempool>>,
) {
    let exempt: std::collections::HashSet<Address> = {
        let state = chain_state.read().await;
        state
            .probationary_validators
            .iter()
            .filter(|a| !state.probation_seen.contains(*a))
            .cloned()
            .collect()
    };
    mempool.write().await.set_fee_exempt_probationers(exempt);
}

/// Build the live BFT validator inputs from chain state — the set every node must run to agree
/// on the round-robin proposer schedule and the quorum denominator. Reads `engine_validator_set()`
/// (the post-rotation `active_validators`, or `stakers()` during the genesis window before the
/// first rotation) and pairs each address with its current personhood so the 1% / 0.5%
/// voting-power cap is applied. Shared by the startup engine build and both catch-up paths, so a
/// synced validator can never construct a different set from the same state than a live one does.
fn validators_from_state(state: &ChainState) -> Vec<Validator> {
    state
        .engine_validator_set()
        .into_iter()
        .map(|(addr, stake, probationary)| {
            let has_personhood = state.has_personhood(&addr);
            if probationary {
                // In the set to sign (so its liveness is provable via `last_commit`) but with no
                // voting power and no proposer turn — see `Validator::probationary` / backlog #132.
                Validator::new_probationary(addr, stake, has_personhood)
            } else {
                Validator::new(addr, stake, has_personhood)
            }
        })
        .collect()
}

/// Mirror a just-synced chain-state validator rotation into the live BFT engine.
///
/// The catch-up paths (`sync_blocks_from_peer`, via the P2P gap-fill and the periodic
/// `rpc_sync_loop`) apply blocks — so `execute_block` rotates `active_validators` in chain state
/// — but bypass the finalize path that normally calls `rotate_validator_set`. Without this a
/// validator that crossed its *own* activation rotation while catching up keeps the stale set it
/// built at startup: it never sees itself in the set, so it never proposes or votes, and a small
/// chain that now counts it toward quorum stalls with the node reporting itself "bonded" (from
/// chain state) yet silent (never co-signing). See [`BftEngine::set_validator_set`].
///
/// `height` is the freshly-synced tip; the epoch is derived from it exactly as the startup engine
/// build does. Safe to call every catch-up: it only rebuilds the set when membership changed, and
/// logs solely in that case.
async fn reconcile_engine_validator_set(
    engine: &Arc<RwLock<BftEngine>>,
    chain_state: &Arc<RwLock<ChainState>>,
    height: u64,
) {
    let validators = {
        let cs = chain_state.read().await;
        validators_from_state(&cs)
    };
    let epoch = height / helix_consensus::EPOCH_LENGTH;
    let changed = engine.write().await.set_validator_set(validators, epoch);
    if changed {
        let eng = engine.read().await;
        info!(
            height,
            epoch = eng.validator_set().epoch,
            validators = eng.validator_set().len(),
            "Live validator set reconciled from synced state — a validator that crossed its \
             activation rotation while catching up now runs the same set as the rest of the \
             network, so it can propose and vote instead of sitting silent"
        );
    }
}

/// Rebuild precommit `Vote`s from a `CommitSig` certificate (the shape a block carries in its
/// `last_commit`, and the shape `/sync/tip-certificate` serves). A `CommitSig` is a precommit with
/// the `(height, block_hash)` it attests factored out — those are shared across the whole
/// certificate — so restoring them yields votes the engine verifies byte-for-byte the same way it
/// verifies a certificate carried in a gossiped block: `precommit_signing_bytes` backs both (see
/// `Vote::signing_bytes`). The engine re-verifies every signature in `verified_commit_certificate`,
/// so forged or mismatched entries from a lying peer are dropped there regardless of this rebuild.
fn commit_sigs_to_votes(sigs: Vec<CommitSig>, height: u64, block_hash: Hash) -> Vec<Vote> {
    sigs.into_iter()
        .map(|s| Vote {
            vote_type: VoteType::Precommit,
            height,
            round: s.round,
            block_hash,
            validator: s.validator,
            public_key: s.public_key,
            crypto_version: s.crypto_version,
            signature: s.signature,
        })
        .collect()
}

/// Snapshot the engine's current commit certificate — its `last_commit`, the precommits that
/// finalized the tip — into the cell the RPC serves at `/sync/tip-certificate` (#133). The tip's
/// certificate lives only in the live engine until block tip+1 is produced (that block's header is
/// where it would otherwise persist), so this is the one certificate an RPC-only follower cannot
/// reconstruct from stored blocks. Publishing an empty certificate — a pure follower that salvaged
/// nothing — is fine: it honestly says "I hold no certificate for this tip", which a consumer
/// treats exactly as it treats the endpoint returning a non-matching height (falls back to empty).
async fn publish_tip_certificate(
    engine: &Arc<RwLock<BftEngine>>,
    cell: &Arc<RwLock<TipCertificate>>,
    store: &Arc<RwLock<HelixDb>>,
    height: u64,
    block_hash: Hash,
) {
    let signatures: Vec<CommitSig> = engine
        .read()
        .await
        .commit_certificate()
        .iter()
        .map(|v| CommitSig {
            validator: v.validator.clone(),
            public_key: v.public_key.clone(),
            crypto_version: v.crypto_version,
            round: v.round,
            signature: v.signature.clone(),
        })
        .collect();
    let cert = TipCertificate { height, block_hash: block_hash.to_hex(), signatures };
    // Mirror the tip certificate to redb so a restart can reload it instead of serving `height: 0`
    // from `/sync/tip-certificate` for the one block-interval it takes to commit again (#134).
    // Best-effort: a failed persist only loses that startup convenience — the live cell below still
    // reflects the true tip, and a consumer treats a stale/empty on-disk certificate exactly like
    // the endpoint returning a non-matching height (falls back to empty, no regression).
    match bincode::serialize(&cert) {
        Ok(bytes) => {
            if let Err(e) = store.read().await.save_tip_certificate(&bytes) {
                warn!("Could not persist tip certificate at height {height}: {e}");
            }
        }
        Err(e) => warn!("Could not serialize tip certificate at height {height}: {e}"),
    }
    *cell.write().await = cert;
}

/// Reload the persisted tip certificate (#134) into the in-memory cell at startup, so a freshly
/// restarted node serves the real tip's certificate at `/sync/tip-certificate` immediately rather
/// than `height: 0`. Missing or malformed bytes leave the cell at its empty default — exactly the
/// pre-#134 startup state, no regression.
async fn load_persisted_tip_certificate(
    store: &Arc<RwLock<HelixDb>>,
    cell: &Arc<RwLock<TipCertificate>>,
) {
    let bytes = match store.read().await.load_tip_certificate() {
        Ok(Some(b)) => b,
        Ok(None) => return,
        Err(e) => {
            warn!("Could not read persisted tip certificate: {e}");
            return;
        }
    };
    match bincode::deserialize::<TipCertificate>(&bytes) {
        Ok(cert) => {
            // Only if it actually attests the tip we hold (#135). The certificate and the block are
            // written in separate redb transactions, so a crash in the window between them leaves a
            // certificate for tip−1 on disk while the store is already at tip. Serving that would
            // hand a syncing follower a certificate for a block it did not ask about; it discards
            // it on the hash mismatch, so nothing breaks — but it discards it after a round trip,
            // and only because it happens to re-check. Checking here costs one read and keeps the
            // stale certificate out of circulation entirely.
            //
            // Dropping it is the correct fallback, not a loss: an empty cell is exactly the
            // pre-#134 startup state, and the next commit republishes a real certificate.
            let (tip_height, tip_hash) = {
                let s = store.read().await;
                (s.latest_height(), s.latest_hash())
            };
            if cert.height != tip_height || cert.block_hash != tip_hash.to_hex() {
                warn!(
                    cert_height = cert.height,
                    tip_height,
                    "Ignoring a persisted tip certificate that does not attest our tip — most \
                     likely a crash between storing the block and its certificate"
                );
                return;
            }
            info!("Loaded persisted tip certificate for height {}", cert.height);
            *cell.write().await = cert;
        }
        Err(e) => warn!("Ignoring malformed persisted tip certificate: {e}"),
    }
}

/// Fetch a sync peer's tip certificate for exactly `(expected_height, expected_hash)` (#133), for
/// the RPC catch-up paths that just applied blocks up to that tip. Returns the certificate as
/// precommit votes ready for [`BftEngine::sync_to_externally_finalized_block`], or an empty vec on
/// any failure: an unreachable peer, a malformed response, or a certificate that attests a
/// *different* tip (the peer advanced past `expected_height` between our `/sync/blocks` fetch and
/// this call). An empty result is exactly the pre-#133 behaviour, so nothing regresses — the
/// engine's `last_commit` stays empty for this tip, as it always did over RPC, and the next
/// catch-up pass picks the certificate up once the peer's tip stops moving. The engine re-verifies
/// every returned signature, so a lying peer buys nothing here.
async fn fetch_tip_certificate(peer_url: &str, expected_height: u64, expected_hash: Hash) -> Vec<Vote> {
    let client = match peer_http_client(Duration::from_secs(10)) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let url = format!("{}/sync/tip-certificate", peer_url.trim_end_matches('/'));
    let cert: TipCertificate = match fetch_json(&client, &url).await {
        Ok(c) => c,
        Err(e) => {
            debug!("Could not fetch tip certificate from {peer_url}: {e}");
            return Vec::new();
        }
    };
    if cert.height != expected_height || cert.block_hash != expected_hash.to_hex() {
        return Vec::new();
    }
    commit_sigs_to_votes(cert.signatures, expected_height, expected_hash)
}

#[allow(clippy::too_many_arguments)]
async fn apply_finalized_block(
    block: Block,
    should_broadcast: bool,
    commit_certificate: Vec<Vote>,
    store: &Arc<RwLock<HelixDb>>,
    mempool: &Arc<RwLock<Mempool>>,
    chain_state: &Arc<RwLock<ChainState>>,
    engine: &Arc<RwLock<BftEngine>>,
    p2p_tx: &mpsc::Sender<P2PCommand>,
    reward_address: Option<Arc<Address>>,
    last_applied_height: &Arc<Mutex<u64>>,
    tip_certificate: &Arc<RwLock<TipCertificate>>,
) {
    let tx_hashes: Vec<_> = block.transactions.iter().map(|t| t.hash()).collect();
    let height = block.height();
    let block_hash = block.hash();
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
    // Held until this block is on disk, not just until the claim is made. Releasing it here — as
    // this used to — leaves a window in which `*last` already says `height` while the block store
    // still ends at `height - 1`, and the catch-up paths take their starting point from the
    // *store*, not from this counter: `NewCommittedBlock`'s gap-fill branch and `apply_synced_batch`
    // both read `store.latest_height()` after acquiring this very lock. Sampled inside the window
    // they see `height - 1`, conclude they are behind, fetch block `height` from a peer and execute
    // it a second time — the block reward is minted twice and that node's `total_issued` is
    // permanently one reward ahead of everyone else's.
    //
    // Measured, not theorised: the three-validator integration test failed roughly every other run
    // with node A one block reward *below* the two nodes that have a `sync_peer` (and therefore run
    // the gap-fill path at all) — `circulating_supply` differing by exactly 1 HLX with identical
    // block hashes and identical `total_burned`. Both other paths already hold this lock across
    // their whole apply; this one is now consistent with them.
    let mut applied_guard = last_applied_height.lock().await;
    if height <= *applied_guard {
        debug!(height, "Skipping duplicate finalized-block application (already applied via a concurrent path)");
        return;
    }

    // Second, independent gate: the block must actually build on what we have (backlog #146).
    //
    // Every caller already guarantees this — the two engine paths only return a block whose
    // `prev_hash` `validate_block` checked, the gossip fast path checks it explicitly, and our own
    // production builds on `store.latest_hash()` by construction. That is precisely why this is
    // worth restating here: it is a guarantee made by *callers*, and this function exists because
    // there are several of them.
    //
    // The height guard above cannot stand in for it. It compares a number, so it is only as good
    // as whoever keeps it current — and when a partially-applied catch-up left it behind the store
    // (backlog #145), a block that had already been executed sailed through and minted its reward
    // a second time. A chain check would have refused that block on its own, whatever the guard
    // said. Refusing costs nothing: a node that drops a block it cannot chain is simply behind,
    // and the catch-up paths bring it back.
    let expected_prev = store.read().await.latest_hash();
    if block.header.prev_hash != expected_prev {
        warn!(
            height,
            expected_prev = %expected_prev,
            got_prev = %block.header.prev_hash,
            "Refusing a finalized block that does not chain from our tip"
        );
        return;
    }

    // Same argument as the chain check above, for the block size rule: every caller checks it, and
    // this function exists because there are several of them. Independent of those checks rather
    // than a restatement of them — it reads the block in front of it, not a number somebody else
    // maintained.
    if block.exceeds_size_limit() {
        warn!(
            height,
            bytes = block.transaction_bytes(),
            limit = helix_core::fee::MAX_BLOCK_BYTES,
            "Refusing a finalized block larger than the network will carry"
        );
        return;
    }

    *applied_guard = height;

    // `should_broadcast == false` means this block arrived already fully committed
    // (the NewCommittedBlock gossip topic) rather than through this node's own
    // receive_proposal/add_vote — those already advanced the engine's current_height
    // internally via finalize() before returning Ok(Some(block)), so only the
    // committed-block fast path needs this explicit sync. See
    // sync_to_externally_finalized_block's doc comment for why skipping this
    // silently desyncs the engine from the actual chain tip.
    if !should_broadcast {
        // The certificate gossiped with the block (#114): the engine adopts it as its own
        // `last_commit` because a fast-path receiver never collected these precommits itself. The
        // live-finalize path leaves it empty here — it already holds the real votes via finalize().
        engine.write().await.sync_to_externally_finalized_block(height, block.hash(), commit_certificate);
    }

    // Execute transactions. The per-tx receipts are kept and persisted below: they are the only
    // record of whether a committed transaction did anything, and warning about the count in the
    // log while dropping them left `hlx tx status`, the explorer and Spark all reporting a
    // rejected transfer as `confirmed`.
    let (tx_receipts, newly_jailed_for_downtime, rotated_validators) = {
        let mut state = chain_state.write().await;
        let receipt = execute_block(&mut state, &block, reward_address.as_deref());
        if receipt.failed_txs() > 0 {
            warn!(height, failed = receipt.failed_txs(), "Tx execution failures");
        }
        // Stamp the state with the height that produced it, while still holding the write lock
        // that produced it. This is what lets `GET /status` report a `state_hash` and the height
        // it belongs to as a pair — see `ChainState::applied_height`. Any reader taking the read
        // lock now sees both or neither; there is no moment where they disagree.
        state.applied_height = height;
        // Not a protocol-level state root (not in BlockHeader, not signed, doesn't gate
        // consensus) — a diagnostic escape hatch. If two nodes' logs ever show different
        // state_hash values at the same height, something has silently diverged; grep for
        // it. Also served live via GET /status (NodeStatus::state_hash) for tooling that
        // wants to compare running nodes without trawling logs. See ChainState::state_hash's
        // doc comment for exactly what this is and isn't.
        debug!(height, state_hash = %state.state_hash().to_hex(), "Block applied");
        (receipt.tx_receipts, receipt.newly_jailed, receipt.rotated_validators)
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

    // Same immediate-jail treatment for downtime — `execute_block` (via
    // `ChainState::record_block_participation`) already decided who crossed
    // `DOWNTIME_JAIL_THRESHOLD_BLOCKS` deterministically (every node that applies this block
    // reaches the same list from the same verified `last_commit` data), this just keeps the
    // live `BftEngine`'s quorum math in sync with it immediately rather than waiting up to
    // `EPOCH_LENGTH` blocks for the next rotation to notice `stakers()` shrank.
    for addr in &newly_jailed_for_downtime {
        if engine.write().await.validator_set.remove(addr) {
            warn!(
                validator = %addr,
                height,
                "Validator downtime-jailed — excluded from BFT rounds until it submits Unjail"
            );
        }
    }

    // Epoch boundary: mirror the freshly rotated set into the live BFT engine.
    // Personhood is read from chain state: ZK-STARK ProvePersonhood txs set
    // PersonhoodStatus::Verified, which unlocks the 1% voting-power cap
    // (instead of the 0.5% cap for unverified validators).
    if let Some(activated) = rotated_validators {
        // The rotation itself already happened inside `execute_block` — it mutates consensus
        // state (`active_validators`/`pending_validators`, both in `state_hash`) and so has to
        // run on every path that applies a block, including `sync_blocks_from_peer`, which
        // never reaches this function. All that is left here is mirroring the decision into
        // the live `BftEngine` and telling the operator about it.
        let state_guard = chain_state.read().await;
        let deferred: Vec<Address> = state_guard.pending_validators.iter().cloned().collect();
        let validators: Vec<Validator> = activated
            .into_iter()
            .map(|(addr, stake, probationary)| {
                let has_personhood = state_guard.has_personhood(&addr);
                if probationary {
                    Validator::new_probationary(addr, stake, has_personhood)
                } else {
                    Validator::new(addr, stake, has_personhood)
                }
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
        } else if !deferred.is_empty() {
            // Everyone who qualifies is still serving the one-epoch activation delay — the
            // normal state on the first rotation after an upgrade, when `active_validators`
            // starts empty and even a long-running validator is treated as a new entrant once
            // (see `ChainState::rotate_active_validators`). Nothing is wrong and nothing needs
            // doing: the sitting set keeps its seats because the rotation is a no-op, and the
            // candidates are promoted at the next one.
            //
            // Worth distinguishing, because the message below used to cover this case too and
            // said the opposite of the truth — observed live during the 0.8.1 deploy at height
            // 38900, claiming no account met min_validator_stake while the running validator
            // met it comfortably. An operator reading that goes looking for a problem that
            // does not exist.
            info!(
                height,
                epoch = eng.validator_set().epoch,
                waiting = deferred.len(),
                "Epoch rotation deferred — every candidate is still serving its activation \
                 epoch; the current set keeps its seats and they join at the next rotation"
            );
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
        // Read both under one lock. `commit_certificate()` is this node's `last_commit`, which
        // `finalize` just set to the precommits that carried exactly this block (a following block
        // cannot finalize before this one is persisted below, so no later certificate can race in
        // here) — send it with the block so a fast-path receiver can adopt it as its own
        // `last_commit` instead of an empty one (#114).
        let (round, certificate) = {
            let eng = engine.read().await;
            (eng.last_committed_round().unwrap_or(0), eng.commit_certificate())
        };
        let _ = p2p_tx.try_send(P2PCommand::BroadcastProposal(Proposal::fresh(round, block.clone())));
        let _ = p2p_tx.try_send(P2PCommand::BroadcastBlock(block.clone(), certificate));
    }

    // Persist block + chain state to the same redb file, under one write lock.
    {
        let mut s = store.write().await;
        if let Err(e) = s.put_block(block) {
            fatal_storage_failure("block", height, &e);
        }
        // A block whose receipts failed to write is still a valid block — the chain is not held
        // up for it. Their absence reads as `unknown` at the RPC, never as success.
        if let Err(e) = s.put_receipts(&tx_receipts) {
            error!("Failed to store receipts for block {}: {}", height, e);
        }
        let state = chain_state.read().await;
        if let Err(e) = s.save_chain_state(&state) {
            // Worse than a lost block, because it leaves no gap to notice: the block is on disk
            // and the state that belongs to it is not, so a restart loads a state that silently
            // disagrees with the chain height above it.
            fatal_storage_failure("chain state", height, &e);
        }
    }

    // The store now agrees with the claim, so a catch-up path that starts from `latest_height()`
    // can no longer conclude it is missing this block. Everything below is bookkeeping on state
    // that is already committed, and holding the lock through it would serialise block application
    // against every catch-up attempt for no benefit.
    drop(applied_guard);

    // Advance the EIP-1559 base fee now that this block is committed: the next block produced
    // or validated by this node must carry `next_base_fee`. Both ingestion paths funnel through
    // here, so the engine's expected base fee stays in lockstep with the persisted tip.
    publish_base_fee(engine, mempool, next_base_fee).await;
    publish_fee_exempt_probationers(chain_state, mempool).await;

    // Surface this tip's commit certificate for RPC-only followers (#133). Both ingestion paths
    // funnel through here with the engine's `last_commit` already settled — set by `finalize` on
    // the produce path, adopted from the gossiped certificate on the fast path (see the
    // `sync_to_externally_finalized_block` call above) — so `commit_certificate()` now holds the
    // precommits that carried exactly this block. This is the one certificate `/sync/blocks` cannot
    // serve, since the block that would embed it (tip+1) does not exist yet.
    publish_tip_certificate(engine, tip_certificate, store, height, block_hash).await;

    { mempool.write().await.remove_committed(&tx_hashes); }

    if tx_count > 0 {
        info!(height, tx_count, "Block committed");
    }
}

/// Abort the process after a write to the chain database failed.
///
/// Logging and carrying on is what this used to do, and it is the worse option by a distance.
/// Seen live on 2026-07-20 when the disk filled up: `Failed to store block 4108: No space left
/// on device`, after which the consensus engine kept running while **nothing** was persisted.
/// The node sat there for 7 minutes looking alive — RPC answering, no further errors — and did
/// not recover on its own once space was free again. A `pm2 restart` fixed it instantly, which
/// is the whole point: restarting *was* the working recovery, the node just refused to do it.
///
/// So do that deliberately. Exiting is louder than a log line nobody is watching, and every
/// supervisor (pm2, systemd, Docker) restarts from here, which re-runs the startup sync and
/// repairs whatever the failed write left behind. If the underlying cause persists the node
/// restart-loops — visible, diagnosable, and still better than a process that claims to be
/// producing blocks it is quietly dropping.
///
/// `std::process::exit` rather than `panic!`: this runs inside a Tokio task, and a panic there
/// unwinds that task alone. The RPC server, P2P service and block production loop would all
/// keep running — reproducing the exact failure this exists to prevent.
fn fatal_storage_failure(what: &str, height: u64, e: &dyn std::fmt::Display) -> ! {
    error!(
        height,
        error = %e,
        "Failed to persist {what} — exiting so the supervisor restarts this node. Continuing \
         would keep consensus running while the chain on disk silently stops advancing."
    );
    std::process::exit(1)
}

/// The decision the health heartbeat reports, factored out of the async loop so it can be
/// unit-tested against the very failure it exists to catch — an active validator gone silent.
#[derive(Debug, PartialEq)]
enum HealthVerdict {
    Following,
    Jailed(u64),
    WaitingActivation,
    Validating { last_signed: u64, age: u64 },
    NotValidating { last_signed: Option<u64>, stalled_secs: Option<u64> },
    Settling,
}

/// Pure verdict for the health heartbeat. `last_signed` is `Some((height, age_secs))` if this node
/// co-signed any block in the recent window; `stalled` is whether the chain height has been frozen
/// past the warn threshold; `past_grace` gates warnings until there is enough history to trust one.
fn health_verdict(
    staked: bool,
    in_active: bool,
    jailed_until: Option<u64>,
    last_signed: Option<(u64, u64)>,
    stalled: bool,
    stalled_secs: u64,
    past_grace: bool,
) -> HealthVerdict {
    if !staked {
        return HealthVerdict::Following;
    }
    if let Some(until) = jailed_until {
        return HealthVerdict::Jailed(until);
    }
    if !in_active {
        return HealthVerdict::WaitingActivation;
    }
    match (last_signed, stalled) {
        // Co-signed recently and the chain is moving — the one healthy state.
        (Some((h, age)), false) => HealthVerdict::Validating { last_signed: h, age },
        // Active but silent (or the chain is stalled while we're active): the failure to shout
        // about — but only once there's enough history that it isn't just startup settling.
        (ls, _) if past_grace => HealthVerdict::NotValidating {
            last_signed: ls.map(|(h, _)| h),
            stalled_secs: if stalled { Some(stalled_secs) } else { None },
        },
        _ => HealthVerdict::Settling,
    }
}

/// Whether a failed startup sync must hold block production (backlog #152).
///
/// `sync_peer` being configured at all means this node set out to join an existing chain. If the
/// sync then failed *and* it holds nothing above genesis, it has no chain to validate — and a
/// validator voting at height 0 is not merely useless: every peer rejects those votes as being for
/// the wrong height, so it is absent from the quorum while appearing to run. On a small set that
/// stops the chain, and nothing sets `syncing` back to true, so it never recovers on its own.
///
/// Note what is deliberately *not* a reason to hold: a sync that failed while this node already
/// has a chain. That node is very likely current, or close to it, and its peer was merely
/// unreachable for a moment — holding there would convert every transient network blip into an
/// outage, which is the same class of harm in the other direction and a good deal more common.
///
/// The realistic path into the held state is not an unreachable peer (genesis is fetched from the
/// same peer moments earlier and fails the startup outright), but a block sync that begins and
/// then breaks — which, pulling six figures of blocks over RPC, is entirely ordinary.
fn hold_production_after_failed_sync(sync_failed: bool, no_chain_above_genesis: bool) -> bool {
    sync_failed && no_chain_above_genesis
}

/// Consecutive health beats the block production loop may show no progress before it is reported
/// as dead (backlog #151).
///
/// At the production 2 s cadence and a 60 s health beat, one beat is ~30 loop ticks, so two beats
/// means the loop has missed sixty in a row — far outside any normal pause, including a slow
/// storage write or a peer wait (which keeps ticking; the counter sits ahead of every `continue`).
/// Erring generous on purpose: a false "this node is dead" is worse than a late true one, because
/// it teaches operators to ignore the line — and this warning exists for the case where they must
/// not.
const PRODUCTION_STALL_BEATS: u32 = 2;

/// Folds one health-beat observation of the production loop's tick counter into a run length of
/// beats without progress. `0` means it moved.
fn production_stall_beats(current_ticks: u64, previous_ticks: u64, beats_so_far: u32) -> u32 {
    if current_ticks == previous_ticks {
        beats_so_far.saturating_add(1)
    } else {
        0
    }
}

/// What to tell an operator whose node is active but not co-signing (backlog #150).
///
/// Separated out and tested because operators act on this sentence, and for months it said the
/// same thing regardless of cause: "restarting the node re-establishes its round." That is right
/// when this node alone is stuck, and wrong when the chain is waiting for *other* validators —
/// where a restart achieves nothing. The block production loop reports that case correctly, so the
/// two contradicted each other a minute apart in the same log.
///
/// On 2026-08-04 an operator followed the actionable half. The restart was survivable; starting
/// again with an empty chain database was not — it pinned that node at height 1 and turned a
/// recoverable outage into a 21-hour stall (#147). Hence the explicit line about the data
/// directory: the mistake that actually cost the time was not the restart.
fn not_validating_advice(quorum_peers_missing: bool, silent_peer_validators: usize) -> &'static str {
    if quorum_peers_missing {
        "This node is healthy — the chain is waiting for other validators to reconnect, and \
         restarting will not speed that up. Do NOT delete this node's chain data: a node that \
         starts with an empty database has to sync from scratch and cannot vote until it does."
    } else if silent_peer_validators > 0 {
        // The gap #150 left open, found the hard way on 2026-08-06: peers *connected* but not
        // voting. The quorum-peers check only counts connections, so this case fell through to
        // the "restart" branch — and the restart provably changed nothing, because the node
        // being restarted was not the one that had stopped.
        //
        // Phrased as "not seeing their votes" on purpose. This node cannot tell an absent peer
        // from a broken link to a healthy one, and saying otherwise sends the operator to blame
        // somebody whose node is fine (R2 — it happened, 596 times in one outage).
        "This node is healthy and connected, but the round cannot close because votes from at \
         least one other validator are not arriving here — see the 'Validator silent' lines above \
         for which. Restarting THIS node will not help, and do NOT delete its chain data. If you \
         run one of the other validators, check that it is up and co-signing."
    } else {
        "The process is up but not participating in consensus; restarting the node re-establishes \
         its round."
    }
}

/// Heartbeat that answers "am I actually validating right now?" in the node's own log.
///
/// An operator watching the console — the GUI Node tab streams exactly this stdout — otherwise
/// has no way to tell a healthy validator from one whose process is up but has silently stopped
/// participating in consensus. That second state is what halts a small network until someone
/// restarts the stuck node, and it was reported from the field as "it said it was still running,
/// but it wasn't." This loop runs on its own timer, independent of the consensus loop, so it
/// keeps reporting even when that loop has stalled.
///
/// Purely observational: it reads state and logs, never mutates consensus or the chain.
#[allow(clippy::too_many_arguments)]
async fn validator_health_loop(
    store: Arc<RwLock<HelixDb>>,
    chain_state: Arc<RwLock<ChainState>>,
    address: Address,
    peer_count: Arc<std::sync::atomic::AtomicUsize>,
    syncing: Arc<std::sync::atomic::AtomicBool>,
    // Whether block production is currently held up by validators being below quorum, published
    // by `block_production_loop`. Read, never written, and never via a lock: this loop has to
    // keep talking precisely when the consensus path is stuck (backlog #150).
    quorum_peers_missing: Arc<std::sync::atomic::AtomicBool>,
    silent_peer_validators: Arc<std::sync::atomic::AtomicUsize>,
    // Monotonic tick counter of the block production loop (backlog #151). Its *movement* is the
    // only local evidence that the loop is alive at all; its value means nothing on its own.
    production_ticks: Arc<std::sync::atomic::AtomicU64>,
) {
    use std::sync::atomic::Ordering;
    let started = std::time::Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(VALIDATOR_HEALTH_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_height = 0u64;
    let mut last_height_change = std::time::Instant::now();
    // Production-loop liveness tracking (#151).
    let mut last_production_ticks = production_ticks.load(Ordering::Relaxed);
    let mut stall_beats = 0u32;
    let mut reported_dead = false;

    loop {
        ticker.tick().await;
        // Still catching up — "am I validating?" isn't a meaningful question until we're current.
        if syncing.load(Ordering::Relaxed) {
            continue;
        }

        let height = { store.read().await.latest_height() };
        if height != last_height {
            last_height = height;
            last_height_change = std::time::Instant::now();
        }
        let stalled_secs = last_height_change.elapsed().as_secs();
        let peers = peer_count.load(Ordering::Relaxed);
        let addr_str = address.to_string();

        let (staked, in_active, jailed_until) = {
            let cs = chain_state.read().await;
            let staked = cs.stakers().iter().any(|(a, _)| a == &address);
            // An empty `active_validators` means the chain has never rotated yet (genesis /
            // bootstrap), and in that state every staker is active — so don't read it as
            // "waiting for activation". Once rotation has run, membership is explicit.
            let in_active =
                cs.active_validators.is_empty() || cs.active_validators.contains(&address);
            let jailed = cs.jailed_until.get(&addr_str).copied().filter(|&h| h > height);
            (staked, in_active, jailed)
        };

        // Scan the recent window for my own co-signature only when I'm an active validator —
        // that's the only verdict that depends on it. last_commit in block h carries the precommits
        // that finalized block h-1, so my address there means I signed h-1.
        let scan_active = staked && in_active && jailed_until.is_none();
        let last_signed: Option<(u64, u64)> = if scan_active {
            let s = store.read().await;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let lo = height.saturating_sub(HEALTH_SIGN_WINDOW);
            let mut found = None;
            let mut h = height;
            while h > lo {
                if let Ok(block) = s.get_block_by_height(h) {
                    if block.header.last_commit.iter().any(|c| c.validator == address) {
                        let age = now_ms.saturating_sub(block.header.timestamp) / 1000;
                        found = Some((h.saturating_sub(1), age));
                        break;
                    }
                }
                h -= 1;
            }
            found
        } else {
            None
        };

        let stalled = stalled_secs >= HEALTH_STALL_WARN_SECS;
        // Enough history and past the startup settle before we're allowed to warn.
        let past_grace =
            started.elapsed().as_secs() >= HEALTH_START_GRACE_SECS && height > HEALTH_SIGN_WINDOW;

        // Keep the run record's "last seen" moving, so a run that is killed can still say when
        // it was last alive — the timestamp that lines up against `dmesg`/journalctl. Written from
        // here rather than the consensus path because this loop keeps running when that one is
        // wedged, which is exactly the run whose ending needs explaining.
        crate::run_record::touch(
            &crate::run_record::path_beside(std::path::Path::new(CHAIN_DB_FILE)),
            height,
        );

        let quorum_missing = quorum_peers_missing.load(Ordering::Relaxed);
        let silent_peers = silent_peer_validators.load(Ordering::Relaxed);

        // Is the loop that produces blocks still running at all (#151)? Reported separately from
        // the verdict below, and before it, because if that loop is dead every other line here is
        // misleading: this node can still look "validating" from a block it co-signed minutes ago,
        // and the advice would send the operator looking at the network instead of at this node.
        {
            let ticks = production_ticks.load(Ordering::Relaxed);
            stall_beats = production_stall_beats(ticks, last_production_ticks, stall_beats);
            last_production_ticks = ticks;
            if stall_beats >= PRODUCTION_STALL_BEATS {
                // Once per stall, not once per beat: this does not resolve on its own, and
                // repeating it every minute would bury the surrounding context an operator needs.
                if !reported_dead {
                    reported_dead = true;
                    warn!(
                        beats = stall_beats,
                        "Health: ⛔ block production loop has STOPPED — it has not run for at \
                         least {}s while this process kept going. The chain cannot advance from \
                         this node regardless of the network. Restart the node; keep its chain \
                         data and validator key.",
                        u64::from(PRODUCTION_STALL_BEATS) * VALIDATOR_HEALTH_SECS
                    );
                }
            } else if reported_dead {
                reported_dead = false;
                info!("Health: block production loop is running again");
            }
        }

        match health_verdict(staked, in_active, jailed_until, last_signed, stalled, stalled_secs, past_grace) {
            HealthVerdict::Following => {
                info!("Health: following the chain · height {} · peers {}", height, peers);
            }
            HealthVerdict::Jailed(until) => {
                warn!(
                    "Health: validator JAILED until #{} — submit an Unjail transaction to rejoin (height {}, peers {})",
                    until, height, peers
                );
            }
            HealthVerdict::WaitingActivation => {
                info!(
                    "Health: staked, waiting for activation — not yet in the active set (height {}, peers {})",
                    height, peers
                );
            }
            HealthVerdict::Validating { last_signed: signed_h, age } => {
                info!(
                    "Health: ✓ validating · last co-signed #{} ({}s ago) · height {} · peers {}",
                    signed_h, age, height, peers
                );
            }
            HealthVerdict::NotValidating { last_signed: ls, stalled_secs: st } => {
                let last = match ls {
                    Some(signed_h) => format!("last co-signed #{}", signed_h),
                    None => format!("no block co-signed in the last {}", HEALTH_SIGN_WINDOW),
                };
                let chain = match st {
                    Some(secs) => format!("chain STALLED at #{} for {}s", height, secs),
                    None => format!("height {}", height),
                };
                // The advice has to match the cause, because operators act on it. This warning
                // used to end with "restarting the node re-establishes its round" no matter what
                // — including when this node is fine and the chain is held up by *other*
                // validators being absent, where a restart does nothing. The block production
                // loop says so correctly in that case ("restarting this node does not speed it
                // up"), so the two contradicted each other a minute apart in the same log.
                //
                // That is not cosmetic: on 2026-08-04 an operator followed the actionable half and
                // restarted with an empty chain database, pinning that node at height 1 and
                // turning a recoverable outage into a 21-hour stall (#147/#150). Hence also the
                // explicit warning about the data directory — the restart itself was survivable,
                // wiping the chain was not.
                let advice = not_validating_advice(quorum_missing, silent_peers);
                warn!(
                    "Health: ⚠ NOT validating — this node is an active validator but is not \
                     co-signing ({}, {}, peers {}). {}",
                    last, chain, peers, advice
                );
            }
            HealthVerdict::Settling => {
                info!("Health: validating (settling in) · height {} · peers {}", height, peers);
            }
        }
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
    syncing: Arc<std::sync::atomic::AtomicBool>,
    signing_guard: Arc<std::sync::Mutex<SigningGuard>>,
    tip_certificate: Arc<RwLock<TipCertificate>>,
    // Set whenever the chain is waiting on validators rather than on this node — read by the
    // health heartbeat so its advice matches what this loop already reports (backlog #150).
    quorum_peers_missing: Arc<std::sync::atomic::AtomicBool>,
    silent_peer_validators: Arc<std::sync::atomic::AtomicUsize>,
    // Incremented on every iteration, ahead of every gate — the health heartbeat watches it move
    // to tell a running loop from a dead one (backlog #151).
    production_ticks: Arc<std::sync::atomic::AtomicU64>,
) {
    // Pure production cadence — it enters no hash, no signature and not the proposer schedule
    // (`proposer_for_round` is `(height+round) % len`, timestamp-free), so overriding it cannot
    // fork a chain the way a consensus constant like `EPOCH_LENGTH` would. Overridable via
    // `HELIX_BLOCK_TIME_MS` purely so the multi-node integration tests can march a joiner across
    // its (fixed, 100-block) activation epochs in seconds instead of minutes; unset in production,
    // where it stays `BLOCK_TIME_MS`.
    let block_time_ms = config::resolve_u64("HELIX_BLOCK_TIME_MS", None).unwrap_or(BLOCK_TIME_MS);
    let mut interval = tokio::time::interval(Duration::from_millis(block_time_ms));

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

    // Logged once rather than every tick — a full catch-up is thousands of ticks long.
    let mut announced_wait = false;
    // Ticks spent held at the sync gate, so the reason can be repeated at a steady cadence rather
    // than announced once (#152 made this state long-lived).
    let mut sync_wait_ticks: u64 = 0;
    // One minute's worth of production ticks, whatever the configured block time.
    let ticks_per_minute = (60_000 / block_time_ms).max(1);
    // Ticks spent waiting for peers, for the periodic "this is why nothing is happening" line.
    let mut waited_ticks: u32 = 0;
    // Ticks between probation heartbeats. Not every tick: the transaction is only useful once per
    // epoch, and re-broadcasting it constantly would be pure gossip noise. Not once per epoch
    // either — a single attempt that lands in a moment of packet loss would cost a whole epoch,
    // and the whole point of this design is that it does not depend on catching one moment.
    let mut heartbeat_ticks: u32 = 0;

    loop {
        interval.tick().await;

        // Proof of life for the health heartbeat (backlog #151). Deliberately the very first thing
        // after the tick, ahead of every gate and every `continue` below: this counter answers
        // "is this loop still running?", not "is it producing blocks". A loop legitimately parked
        // in the sync gate or a peer wait is alive and must keep counting, or the health loop would
        // report every normal wait as a crash — the false positive that would get the warning
        // ignored, and with it the true positive it exists for.
        //
        // Which is the case that matters: "the process is up" has now twice been the observation
        // that misled us (#137's 14.5 hours, and 2026-08-04's 21). A dead production task and a
        // healthy one look identical from outside — same process, same RPC, same logs from every
        // other loop. This is the difference, and it costs one relaxed store per tick.
        production_ticks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Nothing gets proposed while history is still downloading. The startup sync moved out
        // of the constructor so the RPC can answer during it (see `run`), which means this loop
        // now starts while the chain may still be at height 0 — and a validator proposing there
        // would build its own fork of the network it is trying to join. On a single-validator
        // set nothing else would stop it: `peers_needed_for_quorum` is 0, so the mesh gate
        // below passes straight through.
        if syncing.load(std::sync::atomic::Ordering::Relaxed) {
            // Repeated once a minute, not announced once and then silent.
            //
            // Saying it once was fine while this state lasted seconds — the initial sync and no
            // more. Since #152 it can last indefinitely: a node whose startup sync failed with no
            // chain is held here until it catches up, which needs a peer to answer. An operator
            // would otherwise see one line at startup and nothing further while their validator
            // sat out the chain for hours, which is precisely the silence #121 and #150 exist to
            // remove.
            if !announced_wait || sync_wait_ticks.is_multiple_of(ticks_per_minute) {
                let held_at = store.read().await.latest_height();
                info!(
                    height = held_at,
                    "Block production held until this node has caught up — it will not propose or \
                     vote until then. Waiting for its sync peer or for peers to announce a tip it \
                     can reach."
                );
                announced_wait = true;
            }
            sync_wait_ticks = sync_wait_ticks.wrapping_add(1);
            continue;
        }
        sync_wait_ticks = 0;

        // Prove liveness while on probation (#132/#141). Placed here, before every gate below,
        // deliberately: a probationer is at its least healthy exactly when it most needs to be
        // counted — catching up, below quorum, waiting on peers — and none of those states should
        // silence the one signal that gets it out of probation. Cheap when it does not apply: an
        // active validator's check is a single read of the chain state.
        heartbeat_ticks = heartbeat_ticks.saturating_add(1);
        if heartbeat_ticks % HEARTBEAT_TICK_INTERVAL == 1 {
            send_probation_heartbeat_if_due(&keypair, &chain_state, &mempool, &p2p_tx).await;
        }

        // Publish, for the health heartbeat, whether the chain is held up by missing validators
        // rather than by anything wrong with this node (backlog #150).
        //
        // Every branch below already knows this and says so correctly — "restarting this node does
        // not speed it up". The health loop is the one voice that did not know, and it appended
        // "restarting the node re-establishes its round" unconditionally, including in exactly the
        // case where a restart is useless. The two ran a minute apart in production and an
        // operator, reading the actionable one, restarted with an empty chain database on
        // 2026-08-04 — turning a recoverable outage into a 21-hour stall (#147).
        //
        // An atomic rather than letting the health loop ask the engine: that loop exists to keep
        // reporting when the consensus loop is wedged, so it must never block on a lock the wedged
        // path holds. A slightly stale value is harmless here — `peers_needed_for_quorum` only
        // moves on set rotation, unlike the height.
        {
            let needed = engine.read().await.peers_needed_for_quorum();
            let have = peer_count.load(std::sync::atomic::Ordering::Relaxed);
            quorum_peers_missing
                .store(needed > 0 && have < needed, std::sync::atomic::Ordering::Relaxed);
            silent_peer_validators.store(
                engine.read().await.silent_peer_validators(),
                std::sync::atomic::Ordering::Relaxed,
            );
        }

        if !mesh_ready {
            let needed = engine.read().await.peers_needed_for_quorum();
            if needed == 0 {
                mesh_ready = true;
            } else if peer_count.load(std::sync::atomic::Ordering::Relaxed) < needed {
                let have = peer_count.load(std::sync::atomic::Ordering::Relaxed);
                if !engine.write().await.note_peer_wait_tick() {
                    // Say what is happening. A stalled chain with a silent log is what makes an
                    // operator restart the node — which resets this counter and so lengthens
                    // exactly the outage they were trying to end. Once a minute is enough to be
                    // visible without flooding.
                    waited_ticks += 1;
                    if waited_ticks % 30 == 1 {
                        info!(
                            peers = have,
                            needed,
                            "Waiting for validators to connect before producing — the chain does \
                             not advance until quorum is reachable. Restarting the node does not \
                             speed this up; it starts the wait over."
                        );
                    }
                    continue; // still waiting for enough validators to connect
                }
                // This used to promise that "the missing validators are excluded by the liveness
                // jail, then the chain advances without them". That jail was removed on
                // 2026-07-22 (it forked the chain), so the sentence became a lie — and precisely
                // the lie an operator reads while staring at a stalled node, which then sends
                // them looking for a fault that does not exist. Seen in production the same day.
                warn!(
                    peers = have,
                    needed,
                    "Not enough validators connected after the grace period — starting rounds \
                     anyway, but they cannot finalize without the missing validators. The chain \
                     stays where it is until they reconnect; each round now names who is \
                     missing. Nothing on this node can shorten that wait."
                );
                // Past PEER_WAIT_TIMEOUT_TICKS — a validator that never connects at all
                // would otherwise hold this node here forever (this gate runs before the
                // has_active_round loop's own peer-wait checks even see a tick). Nothing to
                // settle for a mesh that was never formed, so skip the settle-tick wait too.
                mesh_ready = true;
            } else {
                engine.write().await.reset_peer_wait();
                waited_ticks = 0;
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
            let needed = engine.read().await.peers_needed_for_quorum();
            if peer_count.load(std::sync::atomic::Ordering::Relaxed) < needed {
                if !engine.write().await.note_peer_wait_tick() {
                    // Same silence #121 fixes in the mesh phase, one step later: a round is
                    // already open but validators dropped below quorum, so we hold it and say
                    // nothing until the wait expires and `record_round_liveness` starts naming
                    // names. Those are the minutes an operator decides whether to restart (which
                    // resets the counter and lengthens the very outage they meant to end). Once a
                    // minute is enough to be visible without flooding.
                    waited_ticks += 1;
                    if waited_ticks % 30 == 1 {
                        let have = peer_count.load(std::sync::atomic::Ordering::Relaxed);
                        info!(
                            peers = have,
                            needed,
                            "Holding the open round — validators dropped below quorum. The chain \
                             stays here until they reconnect; restarting this node does not speed \
                             it up."
                        );
                    }
                    continue;
                }
            } else {
                engine.write().await.reset_peer_wait();
                waited_ticks = 0;
            }

            let timed_out = { engine.write().await.note_round_tick(&keypair) };
            // This tick may have cast a nil prevote (`PROPOSAL_TIMEOUT_TICKS`). Send it now:
            // the drain at the end of the loop body is unreachable from the `continue` below,
            // and a nil prevote that never leaves this node can't be tallied by anyone, so
            // nil quorum — the whole point of casting it — could never form.
            broadcast_outbound_votes(&engine, &p2p_tx, &signing_guard).await;
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
            // `needed == 0` alone used to skip the round clock entirely, on the reasoning that a
            // sole validator "always proposes and never waits". The first half of that is what
            // actually matters, and it is not implied by the second: a node whose own power meets
            // quorum can still be sitting out a round that belongs to someone else — the other
            // validator only has to be small enough (below the 1 % cap) not to be needed. Then
            // nothing ran the clock, nothing advanced the round, and the height stopped for good.
            // Measured on a three-node devnet 2026-07-30, twice out of twice: one proposal
            // rejected as "prev_hash mismatch", then ten minutes of nothing (backlog #143). The
            // proposer being *behind* rather than *silent* is incidental — from this node's side
            // both are the same no-active-round wait, and the engine recovers from either once
            // the clock is allowed to run.
            let our_turn = engine.read().await.is_our_turn();
            if needed == 0 && our_turn {
                false
            } else if under_connected && !engine.write().await.note_peer_wait_tick() {
                // Under-connected — don't burn rounds getting ahead of validators still
                // joining at round 0 (the same guard the active-round branch applies).
                // Bounded the same way: see `note_peer_wait_tick`'s doc comment.
                // And, per #121, don't do it silently: this is the no-active-round twin of the
                // hold above — a non-proposer waiting for a proposal that cannot come while
                // quorum is unreachable. Once a minute, say so.
                waited_ticks += 1;
                if waited_ticks % 30 == 1 {
                    let have = peer_count.load(std::sync::atomic::Ordering::Relaxed);
                    info!(
                        peers = have,
                        needed,
                        "Waiting for a proposal — validators are below quorum, so the round \
                         cannot start. The chain stays here until they reconnect; restarting \
                         this node does not speed it up."
                    );
                }
                continue;
            } else {
                if !under_connected {
                    engine.write().await.reset_peer_wait();
                    waited_ticks = 0;
                }
                let timed_out = { engine.write().await.note_round_tick(&keypair) };
                // Same reason as the active-round branch: a nil prevote cast here has to go
                // out this tick. (This branch falls through to the end-of-body drain rather
                // than `continue`ing, but draining twice is free — the second is empty.)
                broadcast_outbound_votes(&engine, &p2p_tx, &signing_guard).await;
                timed_out
            }
        };

        // Bounded by bytes as well as count. Counting alone bounded nothing that matters: at
        // ~5.4 KB per transfer, 1000 transactions is a 5.2 MB block, past what gossipsub will
        // transmit — so it would never reach a peer, never collect a vote, and be rebuilt
        // identically by the next proposer out of the same mempool.
        let txs = {
            mempool
                .write()
                .await
                .take_within(MAX_TXS_PER_BLOCK, helix_core::fee::MAX_BLOCK_BYTES)
        };
        let prev_hash = store.read().await.latest_hash();

        let produced = if stalled {
            engine.write().await.advance_round(&keypair, prev_hash, txs)
        } else {
            engine.write().await.produce_block(&keypair, prev_hash, txs)
        };
        match produced {
            Ok(block) => {
                apply_finalized_block(block, true, vec![], &store, &mempool, &chain_state, &engine, &p2p_tx, reward_address.clone(), &last_applied_height, &tip_certificate)
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
        broadcast_outbound_votes(&engine, &p2p_tx, &signing_guard).await;
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
///
/// This is the single point where every own vote leaves the node, so it is also where the
/// double-sign guard runs: a vote that would equivocate at a height/round this validator already
/// signed (typically after a restart, or from a stray second instance sharing the key) is dropped
/// here rather than gossiped, so it can never become slashable evidence. See `signing_guard`.
async fn broadcast_outbound_votes(
    engine: &Arc<RwLock<BftEngine>>,
    p2p_tx: &mpsc::Sender<P2PCommand>,
    signing_guard: &Arc<std::sync::Mutex<SigningGuard>>,
) {
    let outbound = { engine.write().await.take_outbound_votes() };
    for vote in outbound {
        let decision = {
            // Short, synchronous critical section (a small fsync on advance) — no await held.
            signing_guard.lock().unwrap().check(&vote)
        };
        match decision {
            Decision::Allow => {
                let _ = p2p_tx.try_send(P2PCommand::BroadcastVote(vote));
            }
            Decision::Refuse => {
                warn!(
                    height = vote.height,
                    round = vote.round,
                    vote_type = ?vote.vote_type,
                    "Double-sign guard withheld a vote: this key already signed a different value \
                     at this height/round (most likely a restart). Not equivocating — this node \
                     will resync instead. If this repeats, a second node may be running with a \
                     copy of this validator key."
                );
            }
        }
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
    validator_stake: u64,
    allocations: Vec<(Address, u64)>,
    /// The hash the peer's genesis state has. `None` from a peer too old to report it — see
    /// `verify_genesis_reconstruction`.
    state_hash: Option<String>,
}

/// Whether a node with no local chain and no RPC `sync_peer` should fetch its genesis from the
/// configured P2P seed peers (#139).
///
/// `new_chain` is the operator saying "self-sign, do not join anything", and it has to win. Seed
/// peers and that flag are routinely set together — every local devnet and the production origin
/// node do, because the seed list wires a validator set into a mesh and says nothing about where
/// the chain came from. Reading the seed list alone as an instruction to join stops those nodes
/// self-signing and leaves them failing to start.
fn joins_over_p2p(new_chain: bool, seed_peers: &[String]) -> bool {
    !new_chain && !seed_peers.is_empty()
}

/// The explicit P2P seed peers an operator configured, as multiaddr strings.
///
/// Read through one function because two callers need it at different moments: the P2P config
/// built during startup, and — before any of that exists — the genesis bootstrap, which has only a
/// peer address to work with and no chain to put it in context (#139). Two copies of this parsing
/// would be the duplicated invariant that drifts the first time the format changes.
fn configured_seed_peers(cfg: &config::NodeConfig) -> Vec<String> {
    config::resolve("HELIX_P2P_SEED_PEERS", &cfg.p2p_seed_peers)
        .map(|seeds| {
            seeds
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// The HTTP client every outbound peer request uses.
///
/// Carries an honest `User-Agent` (`helix/<version>`). reqwest sends none at all by default, and
/// a request with no user agent is exactly what bot-protection heuristics treat as suspicious —
/// so this both identifies our traffic to a seed operator reading their logs and makes it less
/// likely to be lumped in with anonymous scrapers.
fn peer_http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("helix/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("could not build the HTTP client for peer requests")
}

/// Say what a peer actually sent when it wasn't the JSON we asked for.
///
/// Returns a diagnosis to append to an error, not just the bytes: the raw body is usually a
/// full HTML document, and pasting that into a terminal tells an operator nothing.
fn diagnose_non_json(body: &str) -> String {
    let lower = body.to_lowercase();
    if lower.contains("just a moment")
        || lower.contains("cf-mitigated")
        || lower.contains("cdn-cgi/challenge-platform")
        || (lower.contains("cloudflare") && lower.contains("challenge"))
    {
        return " — the peer answered with a Cloudflare bot challenge instead of data. That \
                challenge can only be passed by a real browser running JavaScript, so no node \
                can sync through it. This is a setting on the *peer's* side: its operator has to \
                exempt the API paths (/status, /genesis, /sync/blocks, /blocks/*) from the \
                WAF/bot protection, or serve them unproxied. Until then, point HELIX_SYNC_PEER \
                at a different node."
            .to_string();
    }
    if lower.trim_start().starts_with("<!doctype") || lower.trim_start().starts_with("<html") {
        let snippet: String = body.chars().filter(|c| *c != '\n' && *c != '\r').take(160).collect();
        return format!(
            " — the peer answered with an HTML page, not JSON, so something is intercepting the \
             request (a proxy, a captive portal, or an error page from a reverse proxy in front \
             of the node). First bytes: {snippet}"
        );
    }
    let snippet: String = body.chars().filter(|c| *c != '\n' && *c != '\r').take(160).collect();
    if snippet.is_empty() {
        " — the peer answered with an empty body".to_string()
    } else {
        format!(" — the peer answered with: {snippet}")
    }
}

/// `GET url` and decode it as JSON, failing with something an operator can act on.
///
/// The obvious spelling — `client.get(url).send().await?.json().await?` — throws away both the
/// HTTP status and the body, so anything that isn't JSON surfaces as serde's
/// `expected value at line 1 column 1`. That is what a joining node reported on 2026-07-22:
/// `helix.silvra.net` sat behind a Cloudflare bot challenge that answers datacenter IPs with a
/// 403 HTML page, and the node's only output was `Error: error decoding response body`. The
/// operator had to run `curl -v` themselves to discover the seed was fine and the WAF was not.
/// Reproduced independently from an outside datacenter address: 403 there, 200 from the host
/// itself — which is exactly why the seed's own operator could not see it.
///
/// So: check the status, look at what actually came back, and name the likely cause.
async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("could not reach {url}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("could not read {url}'s response body"))?;

    if !status.is_success() {
        bail!("{url} answered HTTP {status}{}", diagnose_non_json(&body));
    }
    serde_json::from_str(&body)
        .with_context(|| format!("{url} did not answer with valid JSON{}", diagnose_non_json(&body)))
}

async fn fetch_genesis_from_peer(peer_url: &str) -> Result<PeerGenesis> {
    let client = peer_http_client(Duration::from_secs(30))?;
    let resp: serde_json::Value =
        fetch_json(&client, &format!("{}/genesis", peer_url.trim_end_matches('/'))).await?;
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
/// Checks a peer-supplied genesis block against an operator-configured checkpoint hash, before any
/// of it is adopted (backlog #139).
///
/// Why this is the join path's only real anchor: a node with no chain yet has nothing to judge an
/// offered genesis by — no state, no validator set, no chain_id. `verify_genesis_reconstruction`
/// looks like it covers this and does not: it compares our rebuild against a `state_hash` that
/// arrived in the same response, so a peer serving an internally consistent fake satisfies it
/// completely. Both halves come from whoever we are asking. That is the same self-certifying shape
/// #138 had to design around, and here it decides which chain the node spends its life on.
///
/// The hash is the whole trust anchor, so it must be compared against the block's *own* hash
/// rather than anything the peer says about it — `Block::hash()`, recomputed locally.
///
/// Unconfigured stays permitted: it is what every existing deployment does, and refusing would
/// lock operators out on upgrade. It warns, because "I trust this endpoint completely" should be a
/// visible choice rather than a default nobody noticed making.
fn verify_genesis_checkpoint(expected_hex: Option<&str>, genesis: &Block) -> Result<()> {
    let actual = genesis.hash().to_hex();

    let Some(expected) = expected_hex.map(str::trim).filter(|s| !s.is_empty()) else {
        warn!(
            genesis_hash = %actual,
            "No expected genesis hash configured — adopting whatever this sync peer serves. A \
             compromised or impersonated peer could hand this node a different chain and every \
             balance it reports would be wrong. Set genesis_hash (or HELIX_GENESIS_HASH) to the \
             network's published genesis hash to make joining verifiable."
        );
        return Ok(());
    };

    // Case-insensitive: operators copy this out of logs, release notes and block explorers, which
    // do not agree on casing. Nothing else about the comparison is lenient.
    if actual.eq_ignore_ascii_case(expected) {
        info!(genesis_hash = %actual, "Genesis matches the configured checkpoint");
        return Ok(());
    }

    bail!(
        "refusing to join: this sync peer serves genesis {actual}, but this node is configured to \
         join the chain whose genesis is {expected}. Either the peer is on a different chain (a \
         reset creates a new genesis — check for a published new hash), or it is not the peer it \
         claims to be. Nothing has been written."
    )
}

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

    let client = peer_http_client(Duration::from_secs(10))?;
    let status: serde_json::Value =
        fetch_json(&client, &format!("{}/status", peer_url.trim_end_matches('/'))).await?;

    if let Some(warning) = peer_version_warning(&status, env!("CARGO_PKG_VERSION")) {
        warn!(peer = %peer_url, "{warning}");
    }

    seed_multiaddr_from_status(&status, &host)
}

/// Compares our build against the sync peer's reported one, returning a warning when they
/// differ. Pure so it can be tested without a live peer.
///
/// The P2P layer warns on a version mismatch but never refuses one, so two nodes running
/// different consensus rules will peer happily and then disagree in silence. That is not
/// hypothetical: the downtime-accounting fix
/// in 0.8.1 changes which validators are scored for missed blocks, so an un-upgraded node jails
/// a validator that an upgraded one considers fine and stops voting with it — while both keep
/// producing perfectly valid-looking blocks. 0.8.5 raises the stakes again: a node still running
/// the old local liveness exclusion will finalize blocks alone that an upgraded peer refuses to,
/// which is how the chain split at height 66918.
///
/// This catches the mismatch at join time, which is where it usually starts (an operator brings
/// up a node against an already-upgraded network). The complementary case — a peer that upgrades
/// while we keep running — is now caught by the running P2P layer: every peer-exchange broadcast
/// carries the sender's version, and `service::foreign_version_warning` logs a mismatch once
/// (#109). Warning rather than refusing is deliberate in both places: most version differences are
/// harmless, and a node that refuses to start because a peer is one patch ahead would be worse
/// than one that says so loudly.
fn peer_version_warning(status: &serde_json::Value, ours: &str) -> Option<String> {
    let theirs = status.get("version")?.as_str()?;
    if theirs == ours {
        return None;
    }
    Some(format!(
        "Sync peer runs Helix {theirs}, this node runs {ours}. Nothing enforces a match, and a \
         consensus-rule difference between them shows up as silent disagreement — mismatched \
         jailing, votes that never count, a chain that stalls without an error. Run the same \
         version as the network you are joining."
    ))
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
    let status: serde_json::Value =
        fetch_json(client, &format!("{}/status", peer_url.trim_end_matches('/'))).await?;
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
/// Should the periodic RPC catch-up leave this poll alone and let consensus finish?
///
/// Split out of [`rpc_sync_loop`] so the rule can be tested without a peer, a store or a clock —
/// the bug it fixes was a single missing condition that no test could reach while it lived
/// inline in a network loop.
fn catchup_defers_to_consensus(our_height: u64, peer_height: u64, round_in_flight: bool) -> bool {
    round_in_flight && peer_height.saturating_sub(our_height) <= RPC_CATCHUP_ROUND_GRACE_BLOCKS
}

#[allow(clippy::too_many_arguments)]
async fn rpc_sync_loop(
    sync_peer: Option<String>,
    store: Arc<RwLock<HelixDb>>,
    chain_state: Arc<RwLock<ChainState>>,
    engine: Arc<RwLock<BftEngine>>,
    mempool: Arc<RwLock<Mempool>>,
    last_applied_height: Arc<Mutex<u64>>,
    tip_certificate: Arc<RwLock<TipCertificate>>,
    // Cleared once this loop finds we have drawn level with the peer. A startup sync that failed
    // with no chain leaves it set, which holds block production until then (backlog #152).
    syncing: Arc<std::sync::atomic::AtomicBool>,
) {
    let Some(peer_url) = sync_peer else {
        return; // standalone chain (HELIX_NEW_CHAIN) — nothing to catch up from
    };
    let client = match peer_http_client(Duration::from_secs(15)) {
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
        let our_height = store.read().await.latest_height();
        if peer_height <= our_height {
            // Level with the peer. If a failed startup sync left production held (#152), this is
            // the moment it is safe to release: we have what the peer has. Ordinary ticks reach
            // here constantly and the store is a no-op after the first, so this costs nothing.
            if syncing.swap(false, std::sync::atomic::Ordering::Relaxed) {
                info!(
                    height = our_height,
                    "Caught up with the sync peer — resuming block production"
                );
            }
            continue;
        }

        // Don't tear down a consensus round this node is in the middle of driving over a gap
        // that round is about to close by itself — see `RPC_CATCHUP_ROUND_GRACE_BLOCKS` for the
        // live incident this caused. A follower (no round in flight) is unaffected and still
        // catches up on the very next poll.
        if catchup_defers_to_consensus(our_height, peer_height, engine.read().await.has_active_round())
        {
            debug!(
                our_height,
                peer_height, "Periodic RPC catch-up: deferring to the consensus round in flight"
            );
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
        // Same as the gap-fill path: a partial apply returns `Err` and must still move the guard,
        // or the next ingest path re-executes what this one already wrote (#145).
        settle_applied_height(&mut last, &store).await;
        match result {
            Ok((applied, new_height, new_hash)) if applied > 0 => {
                *last = new_height;
                // Keep the BFT engine's own height tracking in step — this apply bypassed
                // receive_proposal/add_vote, exactly like the NewCommittedBlock fast path.
                //
                // /sync/blocks carries no certificate in-band, so fetch the peer's tip certificate
                // for exactly the block we stopped on and adopt it (#133). This is what lets a node
                // that activates and then catches up purely over RPC stamp a real last_commit on
                // its first proposal instead of dropping the tip's participation record. Empty on
                // any failure — the unchanged pre-#133 behaviour — and the engine re-verifies it.
                let cert = fetch_tip_certificate(&peer_url, new_height, new_hash).await;
                engine
                    .write()
                    .await
                    .sync_to_externally_finalized_block(new_height, new_hash, cert);
                // Same reconciliation as the P2P gap-fill path: this apply bypassed the finalize
                // path, so mirror any validator rotation it made into the live engine — otherwise
                // a validator that activates while this loop is catching it up runs a stale set
                // and never participates. See `reconcile_engine_validator_set`.
                reconcile_engine_validator_set(&engine, &chain_state, new_height).await;
                // Refresh the EIP-1559 base fee from the freshly-synced tip too — this apply
                // bypassed apply_finalized_block, so without this the engine would keep a stale
                // base fee and stamp/validate the wrong value for its next block.
                if let Ok(tip) = store.read().await.get_block_by_height(new_height) {
                    publish_base_fee(&engine, &mempool, base_fee_for_next_block(&tip)).await;
                }
                // Surface the adopted certificate (if any) so a follower syncing from this node can
                // obtain the tip's certificate too (#133).
                publish_tip_certificate(&engine, &tip_certificate, &store, new_height, new_hash).await;
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
    let client = peer_http_client(Duration::from_secs(30))?;

    let mut from = local_tip + 1;
    // Incremented per block, not per batch (backlog #160). The abort messages below quote this
    // number, and quoting a per-batch counter meant an abort five blocks into a 200-block batch
    // reported "0 block(s) already applied" while four were persisted — the one number somebody
    // reads when deciding whether an interrupted sync left the node clean.
    let mut total_applied = 0u64;
    // Tracks the hash each next block must chain from — starts at our current tip
    // and advances to the just-applied block's own hash after each iteration.
    let mut expected_prev_hash = store.latest_hash();

    loop {
        let url = format!("{}/sync/blocks?from={}&count=200", peer_url.trim_end_matches('/'), from);
        let blocks: Vec<Block> = fetch_json(&client, &url).await?;
        if blocks.is_empty() {
            break; // caught up
        }
        // A full batch means the peer has more: hold its last block back rather than applying it
        // uncertified, and let the next batch — which begins with it and carries its successor —
        // prove it (backlog #158). Costs one re-fetched block per batch and closes the gap for
        // every block except the chain tip itself.
        let peer_has_more = blocks.len() >= 200;
        let apply_count = if peer_has_more { blocks.len() - 1 } else { blocks.len() };

        for (idx, block) in blocks.iter().take(apply_count).enumerate() {
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
            if block.exceeds_size_limit() {
                store.save_chain_state(chain_state)?;
                anyhow::bail!(
                    "block {} from sync peer carries {} transaction bytes, over the {}-byte \
                     limit — aborting sync, {} block(s) already applied",
                    h,
                    block.transaction_bytes(),
                    helix_core::fee::MAX_BLOCK_BYTES,
                    total_applied
                );
            }
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
            // Quorum proof, the check this path never had (backlog #136).
            //
            // Signature + set membership + prev_hash together still allow one byzantine validator
            // — or anyone holding a validator key who can answer as this node's `sync_peer` — to
            // serve a self-signed branch that satisfies all three. That is the hole audit item A1
            // closed on the gossip fast path, left open here.
            //
            // The proof is already in the stream: a block's successor carries, in its
            // `last_commit`, the precommits that finalized it — `BftEngine` fills that field from
            // `precommits.quorum_votes()`, so it is a quorum by construction. Checking against the
            // *next* block rather than fetching a certificate per block is what makes this
            // workable at all; the 2026-07-31 attempt tried to obtain one per segment, could not
            // for any segment not ending exactly on the peer tip, and broke catch-up outright.
            //
            // Verified against the set as of *before* this block: `chain_state` has had every
            // earlier block applied and nothing later, and a rotation happens while executing the
            // block whose height is a multiple of EPOCH_LENGTH — so this is the set that signed
            // the certificate. Deriving it from the batch instead would be self-certifying.
            {
                let set = ValidatorSet::new(validators_from_state(chain_state), h);
                // Bootstrap, mirroring the `stakers().is_empty()` fallback above: before anyone
                // has staked there is no set to weigh a certificate against, and every node's own
                // engine falls back to itself as sole validator. Demanding a quorum here would
                // make the first blocks of any chain unsyncable, for everyone, forever. As soon as
                // a set exists this check applies with no exception.
                if set.total_voting_power() > 0 {
                // The successor's `last_commit` where there is one; for the chain tip — the only
                // block with no successor anywhere — the peer's `/sync/tip-certificate` (#133),
                // which exists for exactly this and is already used by the other catch-up paths.
                let certificate = match blocks.get(idx + 1) {
                    Some(successor) => commit_sigs_to_votes(
                        successor.header.last_commit.clone(),
                        h,
                        block.hash(),
                    ),
                    None => fetch_tip_certificate(peer_url, h, block.hash()).await,
                };
                if certificate.is_empty() {
                    // No certificate obtainable — an older peer, or one that just restarted with
                    // an empty tip-certificate cell. Applied on the pre-#136 terms rather than
                    // refused: holding the tip back would leave this node one block short, and a
                    // validator one block short of a small set stops the chain outright (#137).
                    // That failure has happened and cost 14.5 hours; this one is hypothetical and
                    // requires the operator's own sync peer to be hostile.
                    warn!(
                        height = h,
                        peer = %peer_url,
                        "Applying the chain tip without a quorum certificate — this peer served \
                         none. The block is signed by a set member and chains correctly, but its \
                         finality is unproven until a successor arrives."
                    );
                } else if !set.precommits_reach_quorum(&certificate, h, &block.hash()) {
                    store.save_chain_state(chain_state)?;
                    anyhow::bail!(
                        "block {} from sync peer is not backed by a BFT quorum — its successor's \
                         commit certificate does not reach the threshold for the validator set of \
                         that height. Aborting sync, {} block(s) already applied",
                        h,
                        total_applied
                    );
                }
                }
            }
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
            execute_block(chain_state, block, None);
            // Same stamp as the consensus path in `apply_finalized_block` — a node catching up
            // over RPC serves `/status` throughout, and a state height frozen at whatever it was
            // before the sync started would be worse than none at all. This function owns
            // `chain_state` exclusively (`&mut`), so the pair is consistent here too.
            chain_state.applied_height = h;
            store.put_block(block.clone())?;
            expected_prev_hash = block.hash();
            total_applied += 1;
            if h % 1000 == 0 {
                info!("Synced block {}", h);
            }
        }
        from += apply_count as u64;
        if !peer_has_more {
            break; // last batch — we're at the peer tip
        }
    }

    store.save_chain_state(chain_state)?;
    Ok(total_applied)
}

#[cfg(test)]
mod genesis_join_tests {
    use super::{expected_genesis_hash, joins_over_p2p, DEFAULT_GENESIS_HASH, DEFAULT_SEED_PEER};

    /// Joining the public chain is verified without the operator configuring anything — Bitcoin's
    /// model, where the genesis is compiled in and nobody is asked. Before this, the default was to
    /// adopt whatever the peer served and the safe path took manual work, which is backwards.
    #[test]
    fn joining_the_public_chain_checks_the_compiled_in_genesis_by_default() {
        assert_eq!(
            expected_genesis_hash(None, Some(DEFAULT_SEED_PEER)).as_deref(),
            Some(DEFAULT_GENESIS_HASH),
        );
    }

    /// The condition the whole safety argument rests on. An operator who named their own peer is
    /// joining a network this binary knows nothing about; checking our hash against theirs would
    /// refuse every private network and every devnet, including our own integration tests.
    #[test]
    fn joining_someone_elses_network_does_not_check_our_hash() {
        assert_eq!(expected_genesis_hash(None, Some("http://some-other-host:8545")), None);
        assert_eq!(expected_genesis_hash(None, None), None);
    }

    /// An explicit setting always wins — that is what keeps a reset from stranding anyone: the
    /// compiled-in hash goes stale the moment the chain is reset, and this is the way through.
    #[test]
    fn an_explicit_setting_overrides_the_compiled_in_default() {
        assert_eq!(
            expected_genesis_hash(Some("abc123".into()), Some(DEFAULT_SEED_PEER)).as_deref(),
            Some("abc123"),
        );
    }

    /// An empty or whitespace value is an unset environment variable, not a hash. Treating it as
    /// one would abort every start with a mismatch against the empty string.
    #[test]
    fn a_blank_setting_falls_through_to_the_default() {
        assert_eq!(
            expected_genesis_hash(Some("   ".into()), Some(DEFAULT_SEED_PEER)).as_deref(),
            Some(DEFAULT_GENESIS_HASH),
        );
    }


    fn seeds() -> Vec<String> {
        vec!["/ip4/127.0.0.1/tcp/8546".to_string()]
    }

    #[test]
    fn a_node_with_seed_peers_and_no_chain_of_its_own_joins_over_p2p() {
        assert!(joins_over_p2p(false, &seeds()));
    }

    /// The regression this exists for. `HELIX_NEW_CHAIN` and seed peers are set together by every
    /// local devnet and by the production origin node — the seed list wires a mesh, it does not say
    /// where the chain came from. Reading it as an instruction to join left those nodes waiting out
    /// the fetch timeout and then failing to start at all, which the unit suite did not notice and
    /// the multi-node integration tests did.
    #[test]
    fn a_node_starting_its_own_chain_never_joins_however_many_peers_it_lists() {
        assert!(!joins_over_p2p(true, &seeds()));
    }

    #[test]
    fn a_node_with_no_peers_has_nowhere_to_join_from() {
        assert!(!joins_over_p2p(false, &[]));
    }
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
            0,
        );
        block.header.height = height;
        block.header.prev_hash = prev_hash;
        let sig = kp.sign(block.header.signing_hash().as_bytes()).unwrap();
        block.header.signature = sig;
        block
    }

    /// A precommit by `kp` for `(height, block_hash)`, in the form a block header carries it.
    ///
    /// Real blocks carry these: `BftEngine` fills `last_commit` from the precommits that finalized
    /// the parent. The test helpers below build them too, because since #136 the sync path checks
    /// them — a block whose successor carries no quorum is exactly what an attacker serves.
    fn commit_sig_for(kp: &KeyPair, height: u64, block_hash: &Hash) -> CommitSig {
        let bytes = helix_core::block::precommit_signing_bytes(
            height,
            0,
            block_hash,
            helix_core::CryptoVersion::MlDsa,
        );
        CommitSig {
            validator: Address::from_public_key(&kp.public),
            public_key: kp.public.clone(),
            crypto_version: helix_core::CryptoVersion::MlDsa,
            round: 0,
            signature: kp.sign(&bytes).unwrap(),
        }
    }

    /// Builds `heights.len()` blocks that properly chain from `Hash::ZERO` (a
    /// fresh store's initial tip) through each other in order.
    ///
    /// Each block carries a commit certificate for its predecessor, as a real chain does — the
    /// sync path verifies a block's quorum from its successor's `last_commit` (#136), so blocks
    /// without one describe a chain that could never have been produced.
    fn chained_blocks(kp: &KeyPair, heights: &[u64]) -> Vec<Block> {
        chained_blocks_certified_by(kp, &[kp], heights)
    }

    /// Like `chained_blocks`, but the commit certificates are signed by `certifiers` — needed
    /// wherever the state has more than one active validator, since one precommit out of two is
    /// short of a quorum and the sync path now checks that (#136).
    fn chained_blocks_certified_by(
        proposer: &KeyPair,
        certifiers: &[&KeyPair],
        heights: &[u64],
    ) -> Vec<Block> {
        let mut prev_hash = Hash::ZERO;
        let mut prev_height: Option<u64> = None;
        heights
            .iter()
            .map(|&h| {
                let mut block = signed_block(proposer, h, prev_hash);
                if let Some(ph) = prev_height {
                    block.header.last_commit = certifiers
                        .iter()
                        .map(|c| commit_sig_for(c, ph, &prev_hash))
                        .collect();
                    // Re-sign: the certificate is folded into the header's signing hash.
                    block.header.signature =
                        proposer.sign(block.header.signing_hash().as_bytes()).unwrap();
                }
                prev_hash = block.hash();
                prev_height = Some(h);
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

    /// A peer that reports a fixed committed height on `/status` — the one field
    /// `fetch_peer_height` reads.
    async fn serve_height(height: u64) -> String {
        let app = Router::new().route(
            "/status",
            get(move || async move { Json(serde_json::json!({ "height": height })) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", addr)
    }

    /// Backlog #152, and the half that decides whether the fix is an improvement or a new outage:
    /// production held after a failed startup sync **must** be released once this node is level
    /// with its peer. Get this wrong and a node that was briefly unable to sync never validates
    /// again — worse than the bug it replaces, and silent.
    ///
    /// Against a real HTTP peer rather than by calling the predicate: what matters is that the
    /// running loop reaches the release, and its path there (build a client, probe /status, compare
    /// heights) is exactly the part a direct call would skip.
    #[tokio::test]
    async fn catching_up_with_the_peer_releases_held_block_production() {
        // Peer reports height 0; our store is a fresh one, also 0 — level, so nothing to fetch.
        let peer_url = serve_height(0).await;

        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        let addr = Address::from_public_key(&KeyPair::generate().public);
        let vset = ValidatorSet::new(vec![Validator::new(addr.clone(), 1, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(vset, addr, 0)));
        // Held, as a failed startup sync with no chain would leave it.
        let syncing = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let handle = tokio::spawn(rpc_sync_loop(
            Some(peer_url),
            store.clone(),
            chain_state.clone(),
            engine.clone(),
            Arc::new(RwLock::new(Mempool::new())),
            Arc::new(Mutex::new(0u64)),
            Arc::new(RwLock::new(TipCertificate::default())),
            syncing.clone(),
        ));

        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < deadline
            && syncing.load(std::sync::atomic::Ordering::Relaxed)
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        handle.abort();

        assert!(
            !syncing.load(std::sync::atomic::Ordering::Relaxed),
            "a node level with its peer must be released to produce again — otherwise a node that \
             failed one startup sync stays mute for the life of the process"
        );
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

    /// End-to-end reproduction of the join-stall, and the fix for it. A second operator stakes to
    /// become a validator and their node catches up over the **sync path** — the one that applies
    /// blocks (rotating `active_validators` in chain state) but skips the finalize path's
    /// `rotate_validator_set`. Their activation rotation lands mid-sync.
    ///
    /// Before the fix (#129), the live engine kept the stale set it built at startup, so the joiner
    /// was never in its own validator set: it never proposed or voted, and the node reported itself
    /// bonded-but-silent. After the fix, reconciling the live engine from the freshly-synced chain
    /// state puts the joiner in its own set, so it participates.
    ///
    /// Layered on top (#132): because the joiner only *synced* and its own signature never reached
    /// a committed `last_commit`, it enters the reconciled set as a zero-power **probationer** — in
    /// the set to sign, but not yet carrying quorum weight — so the chain keeps finalizing on the
    /// incumbent alone and an unproven (possibly phantom) joiner can never freeze it.
    #[tokio::test]
    async fn a_validator_that_activates_while_syncing_ends_up_in_its_own_live_set() {
        let genesis_kp = KeyPair::generate();
        let genesis_addr = Address::from_public_key(&genesis_kp.public);
        let joiner_kp = KeyPair::generate();
        let joiner_addr = Address::from_public_key(&joiner_kp.public);

        // The peer serves a fresh single-validator chain across two epoch boundaries — the
        // genesis window defers everyone once, then a real rotation promotes the joiner. Every
        // block is produced by the genesis validator, exactly as a real solo chain looks right up
        // to the joiner's activation.
        let heights: Vec<u64> = (1..=helix_consensus::EPOCH_LENGTH * 2).collect();
        let blocks = chained_blocks(&genesis_kp, &heights);
        let peer_url = serve_blocks(blocks).await;

        // The joiner's node state: both validators are staked (the joiner's `Stake` tx is already
        // part of the chain it is about to sync). The genesis validator has been active since
        // block 0 (`Genesis::apply` seeds `active_validators`), so it holds its seat across the
        // rotations while the joiner walks the tiers.
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = {
            let mut cs = ChainState::new(0);
            stake_validator(&mut cs, &genesis_kp);
            stake_validator(&mut cs, &joiner_kp);
            cs.active_validators.insert(genesis_addr.clone());
            Arc::new(RwLock::new(cs))
        };

        // The engine the joiner built at startup, before it was ever active: the bootstrap
        // fallback set (just the genesis validator it syncs behind), with itself as its identity.
        let stale =
            ValidatorSet::new(vec![Validator::new(genesis_addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(stale, joiner_addr.clone(), 0)));
        assert!(
            engine.read().await.validator_set().get(&joiner_addr).is_none(),
            "precondition: the joiner is not yet in its own live set (the bonded-but-silent trap)"
        );

        // Catch up across the activation rotation over the sync path.
        let new_height = {
            let mut s = store.write().await;
            let mut cs = chain_state.write().await;
            let applied = sync_blocks_from_peer(&peer_url, 0, &mut s, &mut cs).await.unwrap();
            assert_eq!(applied, helix_consensus::EPOCH_LENGTH * 2);
            s.latest_height()
        };

        // Chain state rotated the joiner into PROBATION — the synced blocks carry no `last_commit`
        // signed by the joiner (a solo producer's chain), so it never proved liveness and is held
        // at zero power rather than handed full membership. That is #132's protection: a node that
        // only synced, and might be a phantom, cannot become quorum-critical until it signs.
        {
            let cs = chain_state.read().await;
            assert!(
                cs.probationary_validators.contains(&joiner_addr),
                "the joiner is in probation after crossing its activation epoch — in the set, no power yet"
            );
            assert!(
                !cs.active_validators.contains(&joiner_addr),
                "…and specifically NOT active: it has not proved a live node behind it"
            );
            assert!(
                cs.active_validators.contains(&genesis_addr),
                "the genesis validator was active from block 0 and stays active"
            );
        }

        // The fix (#129/#130): reconcile mirrors that rotation into the live engine.
        reconcile_engine_validator_set(&engine, &chain_state, new_height).await;

        let eng = engine.read().await;
        let joiner = eng.validator_set().get(&joiner_addr).cloned();
        assert!(
            joiner.is_some(),
            "after reconciling, the joiner is in its own live set so it can sign — no longer silent"
        );
        assert_eq!(
            joiner.unwrap().voting_power,
            0,
            "but as a zero-power probationer: it participates without the chain depending on it"
        );
        let genesis = eng.validator_set().get(&genesis_addr).cloned();
        assert!(genesis.is_some(), "the genesis validator stays in the set");
        assert!(
            genesis.unwrap().voting_power > 0,
            "and carries all the voting power — the chain still finalizes on it alone, no stall"
        );
    }

    /// The **2→3** case of the join-over-sync stall — the one that actually halted the live chain
    /// when a third operator tried to join a running two-validator network, and the case the
    /// existing 1→2 test above does not reach. It is the harder shape in two ways a single joiner
    /// never exercises: C first syncs across a rotation that already happened *for validators it is
    /// not part of* (A and B activating at height 200), and only then crosses its **own** activation
    /// (at 400) — both over the sync path, which applies blocks (rotating `active_validators` in
    /// chain state) but never travels the finalize path that mirrors a rotation into the live engine.
    ///
    /// Sequencing is the whole point and is why this is a distinct test: A and B activate first, and
    /// C stakes only *afterwards*, so its activation lands a full epoch later against an already-
    /// larger set. If C computed even a slightly different membership or proposer order than the
    /// incumbents at either boundary, the chain stalls. The assertion is that C, purely from
    /// syncing, arrives at the identical set every other node builds — the full incumbents {A,B} in
    /// canonical address order plus C — so every node agrees on the round-robin schedule, and that
    /// reconciling is what makes it so.
    ///
    /// And (#132) because C only synced and never signed a committed `last_commit`, it lands as a
    /// zero-power **probationer**: present so it can start signing, but carrying no quorum weight, so
    /// the incumbents keep finalizing and an unproven C cannot freeze the set it just joined.
    #[tokio::test]
    async fn a_third_validator_joining_over_sync_matches_the_incumbents_set_and_schedule() {
        let genesis_kp = KeyPair::generate(); // A
        let kp_b = KeyPair::generate();
        let kp_c = KeyPair::generate();
        let addr_a = Address::from_public_key(&genesis_kp.public);
        let addr_b = Address::from_public_key(&kp_b.public);
        let addr_c = Address::from_public_key(&kp_c.public);
        let joiner_addr = addr_c.clone();

        // A signs every block, exactly as `/sync/blocks` looks to a catching-up node: the endpoint
        // enforces validator-set membership, not per-height proposer identity, so a solo producer's
        // blocks are valid to apply right across both the incumbents' and the joiner's activation.
        let heights: Vec<u64> = (1..=helix_consensus::EPOCH_LENGTH * 4).collect();
        // Certified by both sitting validators: with A and B equally weighted, one precommit is
        // half the power and short of quorum — a real chain's `last_commit` carries both.
        let certifiers = [&genesis_kp, &kp_b];
        let (phase1, phase2): (Vec<Block>, Vec<Block>) =
            chained_blocks_certified_by(&genesis_kp, &certifiers, &heights)
            .into_iter()
            .partition(|b| b.height() <= helix_consensus::EPOCH_LENGTH * 2);
        let peer1 = serve_blocks(phase1).await;
        let peer2 = serve_blocks(phase2).await;

        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = {
            let mut cs = ChainState::new(0);
            stake_validator(&mut cs, &genesis_kp); // A
            stake_validator(&mut cs, &kp_b); // B — C is deliberately NOT staked yet
            // A and B are the sitting validators, active since block 0 (`Genesis::apply` seeds
            // `active_validators`) — the realistic state a third operator joins into.
            cs.active_validators.insert(addr_a.clone());
            cs.active_validators.insert(addr_b.clone());
            Arc::new(RwLock::new(cs))
        };
        // C's engine at startup: the bootstrap fallback set (just the validator it syncs behind),
        // with its own identity. C is a plain follower so far, in nobody's set.
        let stale = ValidatorSet::new(vec![Validator::new(addr_a.clone(), 1_000_000, false)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(stale, joiner_addr.clone(), 0)));

        // Phase 1: C follows the chain across A and B's activation at height 200 — a rotation it is
        // not part of — over the sync path.
        let h1 = {
            let mut s = store.write().await;
            let mut cs = chain_state.write().await;
            sync_blocks_from_peer(&peer1, 0, &mut s, &mut cs).await.unwrap();
            s.latest_height()
        };
        assert_eq!(h1, helix_consensus::EPOCH_LENGTH * 2);
        reconcile_engine_validator_set(&engine, &chain_state, h1).await;
        {
            let cs = chain_state.read().await;
            assert!(
                cs.active_validators.contains(&addr_a) && cs.active_validators.contains(&addr_b),
                "A and B must be active after their rotation at height {h1}"
            );
            assert!(!cs.active_validators.contains(&addr_c), "C has not staked yet — it must not be active");
        }
        assert!(
            engine.read().await.validator_set().get(&joiner_addr).is_none(),
            "C is only a follower through phase 1 — correctly not in the set"
        );

        // C now stakes: its `Stake` tx lands on the chain. Modelled as the stake taking effect in
        // chain state, which is exactly what `execute_block` does when C's tx is included.
        stake_validator(&mut *chain_state.write().await, &kp_c);

        // Phase 2: C keeps syncing across ITS OWN activation rotation at height 400 — still the sync
        // path, never the finalize path.
        let h2 = {
            let mut s = store.write().await;
            let mut cs = chain_state.write().await;
            sync_blocks_from_peer(&peer2, helix_consensus::EPOCH_LENGTH * 2, &mut s, &mut cs).await.unwrap();
            s.latest_height()
        };
        assert_eq!(h2, helix_consensus::EPOCH_LENGTH * 4);
        {
            let cs = chain_state.read().await;
            assert!(
                cs.probationary_validators.contains(&addr_c),
                "C is in probation after crossing its activation epoch at {h2} — the synced blocks carry \
                 no `last_commit` signed by C, so it has not yet proved a live node and stays zero-power"
            );
            assert!(
                !cs.active_validators.contains(&addr_c),
                "…and NOT active: probation is exactly what stops an unproven C from freezing the 3-set (#132)"
            );
        }

        // Positive control: without reconciling, C's live engine keeps the stale phase-1 set and
        // never learns it is even in the set — the exact bonded-but-silent stall the operators hit.
        assert!(
            engine.read().await.validator_set().get(&joiner_addr).is_none(),
            "before reconcile C is in state but absent from its own live set — the stall"
        );

        // The fix: mirror the synced rotation into the live engine.
        reconcile_engine_validator_set(&engine, &chain_state, h2).await;

        let eng = engine.read().await;
        for (label, a) in [("A", &addr_a), ("B", &addr_b), ("C", &addr_c)] {
            assert!(
                eng.validator_set().get(a).is_some(),
                "after reconcile, member {label} must be in C's live set — same membership on every node"
            );
        }
        // A and B carry the voting power; C is a zero-power probationer until it signs — so the
        // live chain finalizes on the incumbents and C's arrival cannot stall it (#132).
        assert!(
            eng.validator_set().get(&addr_a).unwrap().voting_power > 0
                && eng.validator_set().get(&addr_b).unwrap().voting_power > 0,
            "the incumbents keep their voting power"
        );
        assert_eq!(
            eng.validator_set().get(&addr_c).unwrap().voting_power,
            0,
            "C participates in the set but carries no quorum weight until it proves liveness"
        );
        // The proposer schedule is what a divergent set silently breaks (a node proposes out of
        // turn / expects the wrong proposer = the 2→3 stall). It runs over the FULL members only
        // (`full_members()`; probationers take no proposer turn), address-sorted, and every path
        // that builds the set — live finalize, sync/reconcile, genesis — funnels through
        // `tagged_engine_set` which emits `[active-address-sorted, probationary-address-sorted]`,
        // a pure function of committed state. Pin that C computes exactly that: the two full
        // incumbents in canonical address order, then C as a trailing zero-power probationer. A
        // divergence here is a fork.
        let vs = eng.validator_set();
        let full_actual: Vec<Address> =
            vs.validators.iter().filter(|v| !v.probationary).map(|v| v.address.clone()).collect();
        let mut full_expected = vec![addr_a.clone(), addr_b.clone()];
        full_expected.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(full_actual, full_expected, "C's full-member proposer schedule diverges — the 2→3 stall");
        let prob_actual: Vec<Address> =
            vs.validators.iter().filter(|v| v.probationary).map(|v| v.address.clone()).collect();
        assert_eq!(prob_actual, vec![addr_c.clone()], "C must be the sole probationary member, held after the full set");
        assert_eq!(
            eng.peers_needed_for_quorum(),
            2,
            "C carries no power, so from its seat it needs both full incumbents' votes to reach quorum"
        );
    }

    /// Backlog #145. A catch-up that applies some blocks and *then* fails returns `Err` — and its
    /// callers only advance `last_applied_height` in the `Ok` arm. The guard is therefore left
    /// behind the store, and the guard is the only thing standing between two ingest paths and a
    /// double execution: `apply_finalized_block` compares against it and nothing else — there is
    /// no check that the block chains from the current tip.
    ///
    /// So a block already applied by the partial sync sails straight through and is executed a
    /// second time, minting its reward twice. That is the divergence measured on 2026-07-31 (two
    /// nodes on `ba6128de…`, one on `c0771c6b…` at height 310), and it is the #142 failure again
    /// through a different door.
    ///
    /// Written as the caller sequence rather than against the guard directly, because the bug is
    /// not in either function: each is correct on its own, and only the handover between them
    /// loses the height.
    #[tokio::test]
    async fn a_partially_applied_sync_does_not_leave_a_block_open_to_double_execution() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        // Block 2 is tampered with, so the sync applies block 1 and then aborts.
        let mut blocks = chained_blocks(&kp, &[1, 2]);
        blocks[1].header.height = 99;
        let peer_url = serve_blocks(blocks.clone()).await;

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut cs = chain_state.write().await;
            let min_stake = cs.governance_params.min_validator_stake;
            let mut acc = helix_executor::AccountState::new(&addr);
            acc.staked = min_stake;
            cs.accounts.insert(addr.to_string(), acc);
        }
        let validator_set = ValidatorSet::new(vec![Validator::new(addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, addr.clone(), 0)));
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);
        let last_applied_height = Arc::new(Mutex::new(0u64));

        // The caller sequence, exactly as gap-fill and rpc_sync_loop run it.
        let (applied_height, issued_after_sync) = {
            let mut last = last_applied_height.lock().await;
            let mut s = store.write().await;
            let mut cs = chain_state.write().await;
            let result = sync_blocks_from_peer(&peer_url, 0, &mut s, &mut cs).await;
            assert!(result.is_err(), "precondition: the tampered block must abort the sync");
            // Exactly what the callers do: advance the guard only on success — and then settle it
            // against the store regardless, which is the fix.
            if let Ok(n) = result {
                if n > 0 {
                    *last = s.latest_height();
                }
            }
            drop(s);
            settle_applied_height(&mut last, &store).await;
            let s = store.read().await;
            (s.latest_height(), cs.total_issued)
        };
        assert_eq!(applied_height, 1, "precondition: block 1 was applied before the abort");
        assert!(issued_after_sync > 0, "precondition: applying block 1 minted its reward");

        // Block 1 now arrives again through the other ingest path — gossip, a peer re-serving it,
        // a racing gap-fill. Nothing about it is malformed; it is simply a height we already have.
        apply_finalized_block(
            blocks[0].clone(), false, vec![], &store, &mempool, &chain_state, &engine, &p2p_tx,
            None, &last_applied_height, &Arc::new(RwLock::new(TipCertificate::default())),
        )
        .await;

        assert_eq!(
            chain_state.read().await.total_issued,
            issued_after_sync,
            "block 1 was already applied by the aborted sync — executing it again mints its reward \
             twice and puts this node on a different state than its peers",
        );
    }

    /// Like `serve_blocks`, but also serves `/sync/tip-certificate` for the last block — what a
    /// current peer does. Lets a syncing node prove the chain tip, which has no successor to
    /// certify it (backlog #158).
    async fn serve_blocks_with_tip_certificate(blocks: Vec<Block>, certifiers: &[&KeyPair]) -> String {
        let tip = blocks.last().expect("need at least one block").clone();
        let cert = TipCertificate {
            height: tip.height(),
            block_hash: tip.hash().to_hex(),
            signatures: certifiers
                .iter()
                .map(|c| commit_sig_for(c, tip.height(), &tip.hash()))
                .collect(),
        };
        let blocks = Arc::new(blocks);
        let app = Router::new()
            .route(
                "/sync/blocks",
                get(move |Query(params): Query<HashMap<String, String>>| {
                    let blocks = blocks.clone();
                    async move {
                        let from: u64 =
                            params.get("from").and_then(|s| s.parse().ok()).unwrap_or(0);
                        let count: usize =
                            params.get("count").and_then(|s| s.parse().ok()).unwrap_or(200);
                        let page: Vec<Block> = blocks
                            .iter()
                            .filter(|b| b.height() >= from)
                            .take(count)
                            .cloned()
                            .collect();
                        Json(page)
                    }
                }),
            )
            .route("/sync/tip-certificate", get(move || {
                let cert = cert.clone();
                async move { Json(cert) }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{}", addr)
    }

    /// Backlog #160: the number an abort message quotes has to be the number of blocks actually
    /// persisted. It was incremented once per batch, so an abort partway through reported zero
    /// while blocks were already on disk — read by whoever decides, after an interrupted sync,
    /// whether the node needs cleaning up. Same class as #150: a diagnostic that invites the wrong
    /// action.
    #[tokio::test]
    async fn an_aborted_sync_reports_how_many_blocks_it_really_applied() {
        let kp = KeyPair::generate();
        let mut blocks = chained_blocks(&kp, &[1, 2, 3, 4]);
        // Block 4 is signed by nobody in the set — the sync must stop there, having applied 1-3.
        let stranger = KeyPair::generate();
        blocks[3] = signed_block(&stranger, 4, blocks[2].hash());
        blocks[3].header.last_commit = vec![commit_sig_for(&kp, 3, &blocks[2].hash())];
        blocks[3].header.signature =
            stranger.sign(blocks[3].header.signing_hash().as_bytes()).unwrap();
        let peer_url = serve_blocks(blocks).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
        stake_validator(&mut chain_state, &kp);

        let err = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state)
            .await
            .expect_err("a block from outside the set must abort the sync");

        assert_eq!(store.latest_height(), 3, "precondition: three blocks really were applied");
        assert!(
            err.to_string().contains("3 block(s) already applied"),
            "the message must say how many are on disk, not zero: {err}"
        );
    }

    /// Backlog #158: the chain tip is the one block with no successor to certify it, and before
    /// this it was applied on nothing but a signature. A peer's `/sync/tip-certificate` (#133) is
    /// exactly that missing proof, and it was already being served — just never consulted here.
    #[tokio::test]
    async fn the_chain_tip_is_certified_from_the_peers_tip_certificate() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let blocks = chained_blocks_certified_by(&a, &[&a, &b], &[1, 2, 3]);
        let peer_url = serve_blocks_with_tip_certificate(blocks, &[&a, &b]).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
        stake_validator(&mut chain_state, &a);
        stake_validator(&mut chain_state, &b);

        let applied = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state)
            .await
            .expect("a chain whose tip is certified must sync in full");

        assert_eq!(applied, 3, "including the tip");
        assert_eq!(store.latest_height(), 3);
    }

    /// And the tip must be refused when the certificate the peer serves does not carry a quorum —
    /// otherwise consulting it proves nothing. Here the tip is certified by one of two validators.
    #[tokio::test]
    async fn a_tip_whose_certificate_is_short_of_quorum_is_refused() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let blocks = chained_blocks_certified_by(&a, &[&a, &b], &[1, 2, 3]);
        // Tip certificate signed by A alone — half the power, short of the threshold.
        let peer_url = serve_blocks_with_tip_certificate(blocks, &[&a]).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
        stake_validator(&mut chain_state, &a);
        stake_validator(&mut chain_state, &b);

        let err = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state)
            .await
            .expect_err("a tip certificate short of quorum must not pass");
        assert!(err.to_string().contains("not backed by a BFT quorum"), "{err}");
        assert_eq!(store.latest_height(), 2, "the certified blocks below it stay applied");
    }

    /// Backlog #136, the hole this path had since it was written: signature + set membership +
    /// prev_hash are all satisfiable by a single validator serving a branch it alone signed.
    ///
    /// The attacker here is exactly that — a real, staked validator (so membership passes),
    /// signing well-formed blocks that chain properly (so continuity passes), on a chain where the
    /// set is large enough that one signature is not a quorum. Before this check the node adopted
    /// the branch outright; audit item A1 closed the same hole on the gossip fast path and left
    /// this one open, reachable through a compromised or impersonated `sync_peer`.
    #[tokio::test]
    async fn rejects_a_branch_one_validator_signed_alone() {
        let attacker = KeyPair::generate();
        let honest = KeyPair::generate();

        // Well-formed blocks, correctly chained, signed by a genuine set member — but certified
        // only by itself.
        let blocks = chained_blocks_certified_by(&attacker, &[&attacker], &[1, 2, 3]);
        let peer_url = serve_blocks(blocks).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
        stake_validator(&mut chain_state, &attacker);
        stake_validator(&mut chain_state, &honest);

        let result = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state).await;

        let err = result.expect_err("a branch without a quorum must not be adopted").to_string();
        assert!(err.contains("not backed by a BFT quorum"), "{err}");
        assert_eq!(
            store.latest_height(),
            0,
            "and nothing from that branch may be persisted — a single applied block from it puts \
             this node on a fork the rest of the network will never extend",
        );
    }

    /// The control, and the one that decides whether this is a fix or an outage: an honest chain
    /// must still sync. The 2026-07-31 attempt at #136 failed exactly here — it demanded a
    /// certificate per segment, could not obtain one for any segment not ending on the peer tip,
    /// and broke catch-up for everyone.
    #[tokio::test]
    async fn an_honestly_certified_chain_still_syncs() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let blocks = chained_blocks_certified_by(&a, &[&a, &b], &[1, 2, 3, 4, 5]);
        let peer_url = serve_blocks(blocks).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
        stake_validator(&mut chain_state, &a);
        stake_validator(&mut chain_state, &b);

        let applied = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state)
            .await
            .expect("a properly certified chain must sync");

        assert_eq!(applied, 5);
        // The last block has no successor in the stream, so it carries no proof yet — it is
        // applied on the same terms as before this check, and certified on the next poll.
        assert_eq!(store.latest_height(), 5);
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
        let mut block2 = signed_block(&attacker_kp, 2, block1.hash());
        // Block 2 certifies block 1 honestly — otherwise block 1 is rejected for want of a quorum
        // and this test never reaches the membership check it exists for (#136).
        block2.header.last_commit = vec![commit_sig_for(&real_kp, 1, &block1.hash())];
        block2.header.signature =
            attacker_kp.sign(block2.header.signing_hash().as_bytes()).unwrap();
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
        let mut non_chaining_block2 = signed_block(&kp, 2, Hash::ZERO); // should be block1.hash()
        // Certifies block 1, so this test reaches the continuity check rather than stopping at
        // block 1 for want of a quorum (#136).
        non_chaining_block2.header.last_commit = vec![commit_sig_for(&kp, 1, &block1.hash())];
        non_chaining_block2.header.signature =
            kp.sign(non_chaining_block2.header.signing_hash().as_bytes()).unwrap();
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
mod validator_health_tests {
    use super::*;

    // Positive control: the verdict must actually flag the failure this heartbeat exists for —
    // an active, un-jailed validator that co-signed nothing in the window (a node "still running"
    // but not participating). Without this, a green run only proves the healthy path.
    #[test]
    fn flags_a_silent_active_validator() {
        let v = health_verdict(true, true, None, None, false, 0, true);
        assert_eq!(v, HealthVerdict::NotValidating { last_signed: None, stalled_secs: None });
    }

    #[test]
    fn flags_a_stall_while_active_even_if_it_once_signed() {
        let v = health_verdict(true, true, None, Some((100, 5)), true, 40, true);
        assert_eq!(v, HealthVerdict::NotValidating { last_signed: Some(100), stalled_secs: Some(40) });
    }

    #[test]
    fn healthy_when_signed_recently_and_moving() {
        let v = health_verdict(true, true, None, Some((100, 2)), false, 0, true);
        assert_eq!(v, HealthVerdict::Validating { last_signed: 100, age: 2 });
    }

    #[test]
    fn stays_quiet_within_the_startup_grace() {
        // Same silent inputs as the warn case, but before grace elapses → no warning yet.
        let v = health_verdict(true, true, None, None, false, 0, false);
        assert_eq!(v, HealthVerdict::Settling);
    }

    #[test]
    fn jailed_and_waiting_and_follower_take_precedence() {
        assert_eq!(health_verdict(true, true, Some(500), None, true, 99, true), HealthVerdict::Jailed(500));
        assert_eq!(health_verdict(true, false, None, None, true, 99, true), HealthVerdict::WaitingActivation);
        assert_eq!(health_verdict(false, false, None, None, true, 99, true), HealthVerdict::Following);
    }

    /// Backlog #150. The advice attached to "NOT validating" is the one line an operator acts on,
    /// and it used to be the same regardless of cause — telling someone to restart a node that is
    /// perfectly fine while the chain waits for absent validators.
    #[test]
    fn a_node_held_up_by_missing_validators_is_not_told_to_restart() {
        let advice = not_validating_advice(true, 0);
        assert!(
            advice.contains("will not speed that up"),
            "must say plainly that restarting does not help: {advice}"
        );
        assert!(
            !advice.contains("re-establishes its round"),
            "must not also carry the opposite recommendation: {advice}"
        );
    }

    /// The line that actually cost the time on 2026-08-04: the operator restarted *and* wiped the
    /// chain database, which pinned that node at height 1 (#147). The restart was survivable.
    #[test]
    fn the_waiting_advice_warns_against_deleting_chain_data() {
        let advice = not_validating_advice(true, 0);
        assert!(
            advice.contains("Do NOT delete"),
            "must warn against wiping the data directory: {advice}"
        );
    }

    /// Backlog #152, the failure this exists for: a validator that meant to join a chain, could
    /// not sync it, and holds nothing — it must not vote. Its votes are for height 0/1, every peer
    /// rejects them as being for the wrong height, and it is simply missing from the quorum while
    /// looking alive. That is how a node sat at height 1 for 21 hours through the outage of
    /// 2026-08-04 while the chain it was supposed to be validating stood still.
    #[test]
    fn a_validator_that_failed_to_sync_and_has_no_chain_must_not_produce() {
        assert!(hold_production_after_failed_sync(true, true));
    }

    /// The control, and the more important half: a node whose chain is already there must keep
    /// validating when its peer is briefly unreachable. Holding *that* would turn every transient
    /// network blip into an outage — the same harm in the other direction, and far more frequent.
    /// A fix that simply held on any failed sync would pass the test above and cause this.
    #[test]
    fn a_node_that_already_has_a_chain_keeps_producing_when_a_sync_fails() {
        assert!(!hold_production_after_failed_sync(true, false));
    }

    /// And a successful sync never holds, whatever the height — including the legitimate case of
    /// joining a chain that is genuinely still at genesis.
    #[test]
    fn a_successful_sync_never_holds_production() {
        assert!(!hold_production_after_failed_sync(false, true));
        assert!(!hold_production_after_failed_sync(false, false));
    }

    /// Backlog #151. A production loop that keeps ticking must never be reported dead — a normal
    /// peer wait or sync gate ticks the counter (it sits ahead of every `continue`), and a warning
    /// that cries wolf on those is a warning operators learn to scroll past.
    #[test]
    fn a_loop_that_keeps_ticking_is_never_reported_dead() {
        let mut beats = 0u32;
        let mut previous = 0u64;
        for tick in 1..=100u64 {
            beats = production_stall_beats(tick, previous, beats);
            previous = tick;
            assert_eq!(beats, 0, "a moving counter must never accumulate stall beats");
        }
    }

    /// The case this exists for: the process is up, every other loop still logs, but the one that
    /// drives consensus is gone. "The process is up" has twice been the observation that misled
    /// us — #137's 14.5 hours and the 21-hour stall of 2026-08-04.
    #[test]
    fn a_frozen_counter_is_reported_once_the_threshold_is_reached() {
        let frozen = 4_242u64;
        let mut beats = 0u32;
        for beat in 1..=PRODUCTION_STALL_BEATS {
            beats = production_stall_beats(frozen, frozen, beats);
            assert_eq!(beats, beat);
        }
        assert!(beats >= PRODUCTION_STALL_BEATS, "must trip once the threshold is reached");
    }

    /// One slow beat is not death. The threshold is deliberately more than one so a single delayed
    /// tick — a slow storage write, a busy machine — does not produce a false alarm.
    #[test]
    fn a_single_missed_beat_is_not_enough_to_declare_it_dead() {
        let beats = production_stall_beats(7, 7, 0);
        assert_eq!(beats, 1);
        assert!(beats < PRODUCTION_STALL_BEATS, "one quiet beat must not trip the warning");
    }

    /// And it has to recover: a loop that starts moving again resets the run, so a node that was
    /// briefly wedged is not reported dead forever.
    #[test]
    fn progress_after_a_stall_clears_the_run() {
        let mut beats = production_stall_beats(7, 7, 0);
        beats = production_stall_beats(7, 7, beats);
        assert!(beats >= PRODUCTION_STALL_BEATS);
        beats = production_stall_beats(8, 7, beats);
        assert_eq!(beats, 0, "movement must clear the stall run");
    }

    /// The control: when this node really is the stuck one, restarting is the right advice and has
    /// to survive. A fix that simply removed the recommendation everywhere would pass the tests
    /// above and leave a genuinely wedged validator with nothing to do.
    #[test]
    fn a_node_that_is_itself_stuck_is_still_told_to_restart() {
        let advice = not_validating_advice(false, 0);
        assert!(
            advice.contains("re-establishes its round"),
            "a genuinely stuck node must still be told to restart: {advice}"
        );
        assert!(!advice.contains("Do NOT delete"));
    }

    /// The gap #150 left, found live on 2026-08-06 and confirmed by acting on it.
    ///
    /// The quorum-peers check counts *connections*. When the peers are connected but one of them
    /// has stopped voting, that check is false and the advice fell through to "restart this node"
    /// — so a healthy validator is told to restart while the chain waits for somebody else. It
    /// was followed: the restart changed nothing, because the node being restarted was not the
    /// one that had stopped.
    #[test]
    fn a_node_waiting_on_a_silent_peer_is_not_told_to_restart_either() {
        let advice = not_validating_advice(false, 1);
        assert!(
            advice.contains("will not help"),
            "must say plainly that restarting this node is not the answer: {advice}"
        );
        assert!(
            !advice.contains("re-establishes its round"),
            "must not also carry the opposite recommendation: {advice}"
        );
        assert!(
            advice.contains("do NOT delete its chain data"),
            "the restart was survivable on 2026-08-04; wiping the chain was not: {advice}"
        );
    }

    /// R2, written into the test so a later rewording cannot quietly break it: this node cannot
    /// distinguish a validator that is down from a healthy one whose votes are not reaching us.
    /// Saying "they are offline" sends the operator to blame somebody whose node is fine — which
    /// happened 596 times in one outage on 2026-07-29.
    #[test]
    fn the_advice_does_not_claim_the_other_validator_is_down() {
        let advice = not_validating_advice(false, 2).to_lowercase();
        assert!(
            advice.contains("not arriving here"),
            "must describe what this node observes, not what the peer is doing: {advice}"
        );
        for forbidden in ["is offline", "is down", "has crashed", "has failed"] {
            assert!(
                !advice.contains(forbidden),
                "must not assert a state this node cannot observe ({forbidden}): {advice}"
            );
        }
    }

    /// Precedence. Missing peers is the more specific diagnosis and keeps its own wording — a
    /// disconnected validator is also a silent one, so both flags are set at once and the order
    /// decides which line an operator reads.
    #[test]
    fn disconnected_peers_keep_their_own_more_specific_advice() {
        let advice = not_validating_advice(true, 3);
        assert!(advice.contains("waiting for other validators to reconnect"), "{advice}");
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

    /// The store's current tip hash — what a block must chain from to be accepted (#146).
    async fn tip_of(store: &Arc<RwLock<HelixDb>>) -> Hash {
        store.read().await.latest_hash()
    }
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
            0,
        );
        block.header.height = height;
        block.header.prev_hash = prev_hash;
        let sig = kp.sign(block.header.signing_hash().as_bytes()).unwrap();
        block.header.signature = sig;
        block
    }

    /// A block proposed by `kp` that carries a `last_commit` — the parent height's precommits —
    /// signed by `signers`. That certificate is what `execute_block` verifies into the `signers`
    /// set it hands `record_probation_liveness`, so this is how a test makes a probationer's
    /// signature "seen" (mirrors `helix_executor`'s `block_with_commit`).
    fn signed_block_with_commit(
        kp: &KeyPair,
        height: u64,
        prev_hash: Hash,
        signers: &[&KeyPair],
    ) -> Block {
        let mut block = signed_block(kp, height, prev_hash);
        block.header.last_commit = signers
            .iter()
            .map(|s| {
                let bytes = helix_core::precommit_signing_bytes(
                    height.saturating_sub(1),
                    0,
                    &block.header.prev_hash,
                    helix_core::CryptoVersion::MlDsa,
                );
                helix_core::CommitSig {
                    validator: Address::from_public_key(&s.public),
                    public_key: s.public.clone(),
                    crypto_version: helix_core::CryptoVersion::MlDsa,
                    round: 0,
                    signature: s.sign(&bytes).unwrap(),
                }
            })
            .collect();
        // The header signature must cover the last_commit we just set.
        block.header.signature = kp.sign(block.header.signing_hash().as_bytes()).unwrap();
        block
    }

    /// Precommit `CommitSig`s for `(height, block_hash)` at round 0, signed by each of `signers` —
    /// the shape a serving node's live tip certificate takes on the wire (`/sync/tip-certificate`).
    fn tip_commit_sigs(height: u64, block_hash: Hash, signers: &[&KeyPair]) -> Vec<CommitSig> {
        signers
            .iter()
            .map(|s| {
                let bytes = helix_core::precommit_signing_bytes(
                    height,
                    0,
                    &block_hash,
                    helix_core::CryptoVersion::MlDsa,
                );
                CommitSig {
                    validator: Address::from_public_key(&s.public),
                    public_key: s.public.clone(),
                    crypto_version: helix_core::CryptoVersion::MlDsa,
                    round: 0,
                    signature: s.sign(&bytes).unwrap(),
                }
            })
            .collect()
    }

    /// #133, positive control with a built-in red run. The one certificate `/sync/blocks` cannot
    /// carry is the tip's — the block that would embed it (tip+1) does not exist yet — so an
    /// RPC-only follower fetches it from `/sync/tip-certificate`. This proves that certificate
    /// survives the JSON hop *and* the `CommitSig`→`Vote` reconstruction the follower does, so the
    /// engine adopts it and holds a real `last_commit`: that is what lets the follower's *next*
    /// proposal record who finalized the tip instead of stamping an empty certificate (#113's hole,
    /// reopened over the RPC path until now). The red run — the same signatures reconstructed
    /// against a different tip hash — must be rejected, proving the engine verifies the
    /// round-tripped certificate rather than trusting whatever a peer serves.
    #[test]
    fn an_rpc_synced_engine_adopts_a_round_tripped_tip_certificate() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let tip_height = 5u64;
        let tip_hash = Hash::digest(b"tip-block-5");

        // The serving node's live tip certificate as `publish_tip_certificate` would snapshot it,
        // serialized to JSON and back exactly as it crosses `/sync/tip-certificate`.
        let served = TipCertificate {
            height: tip_height,
            block_hash: tip_hash.to_hex(),
            signatures: tip_commit_sigs(tip_height, tip_hash, &[&a, &b]),
        };
        let wire = serde_json::to_string(&served).unwrap();
        let received: TipCertificate = serde_json::from_str(&wire).unwrap();
        assert_eq!(received.height, tip_height);
        assert_eq!(received.block_hash, tip_hash.to_hex());

        let set = ValidatorSet::new(
            vec![
                Validator::new(Address::from_public_key(&a.public), 1_000_000, true),
                Validator::new(Address::from_public_key(&b.public), 1_000_000, true),
            ],
            0,
        );

        // The follower converts the CommitSigs back to precommit votes for the tip it just synced
        // to and hands them to the engine, exactly as the RPC catch-up paths now do.
        let votes = commit_sigs_to_votes(received.signatures.clone(), tip_height, tip_hash);
        let mut follower = BftEngine::new(set.clone(), Address::from_public_key(&a.public), 0);
        follower.sync_to_externally_finalized_block(tip_height, tip_hash, votes);
        assert_eq!(
            follower.commit_certificate().len(),
            2,
            "both genuine tip precommits survive the JSON + CommitSig↔Vote round-trip and are adopted"
        );

        // Red run: the same signatures reconstructed against the WRONG tip hash must be dropped —
        // their signatures were made over the real tip, so they fail verification against another
        // block. A certificate that does not attest the synced tip can never seed a bogus
        // last_commit.
        let other = Hash::digest(b"not-the-tip");
        let wrong = commit_sigs_to_votes(received.signatures, tip_height, other);
        let mut follower2 = BftEngine::new(set, Address::from_public_key(&a.public), 0);
        follower2.sync_to_externally_finalized_block(tip_height, other, wrong);
        assert!(
            follower2.commit_certificate().is_empty(),
            "signatures that do not attest the synced tip are verified out, never adopted"
        );
    }

    /// #134, positive control with a built-in negative case. The tip-certificate cell is in-memory
    /// (#133), so a restart would serve `height: 0` from `/sync/tip-certificate` for the one
    /// block-interval it takes to commit again — unless the last certificate was persisted and
    /// reloaded. This proves the reload path: a certificate written to redb (as `publish_tip_certificate`
    /// now does on every commit) repopulates the cell at startup, byte-for-byte, so the node serves the
    /// real tip immediately. The negative case — a fresh store with nothing persisted — must leave the
    /// cell empty, proving the reload is what filled it, not some default.
    #[tokio::test]
    async fn a_restart_reloads_the_persisted_tip_certificate_into_the_cell() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let tip_height = 7u64;

        // Negative case first: a fresh store holds nothing, so the reload must leave the cell empty
        // — exactly the pre-#134 startup state, no false positive from a stray default.
        let store = Arc::new(RwLock::new(fresh_store()));
        let cell = Arc::new(RwLock::new(TipCertificate::default()));
        load_persisted_tip_certificate(&store, &cell).await;
        assert_eq!(cell.read().await.height, 0, "a fresh store leaves the cell at its empty default");
        assert!(cell.read().await.signatures.is_empty(), "no signatures reload from an empty store");

        // A real tip in the store, because the reload now checks the certificate against it (#135).
        let tip_block = signed_block(&a, tip_height, Hash::digest(b"parent-of-7"));
        let tip_hash = tip_block.hash();
        store.write().await.put_block(tip_block).unwrap();

        // Persist a real tip certificate the way `publish_tip_certificate` serializes it, then reload.
        let cert = TipCertificate {
            height: tip_height,
            block_hash: tip_hash.to_hex(),
            signatures: tip_commit_sigs(tip_height, tip_hash, &[&a, &b]),
        };
        let bytes = bincode::serialize(&cert).unwrap();
        store.read().await.save_tip_certificate(&bytes).unwrap();

        // A fresh cell (the restarted process) reloaded from the same store must hold the real tip.
        let reloaded = Arc::new(RwLock::new(TipCertificate::default()));
        load_persisted_tip_certificate(&store, &reloaded).await;
        let got = reloaded.read().await;
        assert_eq!(got.height, tip_height, "the reloaded cell serves the real tip height, not 0");
        assert_eq!(got.block_hash, tip_hash.to_hex(), "the reloaded tip hash matches what was persisted");
        assert_eq!(got.signatures.len(), 2, "both persisted precommits reload with the certificate");
    }

    /// Backlog #135: the block and its certificate are written in separate redb transactions, so a
    /// crash between them leaves a certificate for tip−1 on disk while the store already holds tip.
    /// Reloading that would put a certificate for the wrong block into `/sync/tip-certificate`.
    ///
    /// A follower does re-check and discards it on the hash mismatch, so this was never a consensus
    /// regression — but it is a stale certificate handed out for a round trip, and the node has
    /// everything it needs to notice locally. Dropping it restores exactly the pre-#134 startup
    /// state, and the next commit republishes a real one.
    #[tokio::test]
    async fn a_persisted_certificate_for_the_wrong_block_is_not_reloaded() {
        let kp = KeyPair::generate();
        let store = Arc::new(RwLock::new(fresh_store()));

        // The store advanced to height 8 …
        let older = signed_block(&kp, 7, Hash::digest(b"parent-of-7"));
        let older_hash = older.hash();
        store.write().await.put_block(older).unwrap();
        let tip = signed_block(&kp, 8, older_hash);
        store.write().await.put_block(tip).unwrap();

        // … but the certificate on disk still attests height 7: the crash window.
        let stale = TipCertificate {
            height: 7,
            block_hash: older_hash.to_hex(),
            signatures: tip_commit_sigs(7, older_hash, &[&kp]),
        };
        store
            .read()
            .await
            .save_tip_certificate(&bincode::serialize(&stale).unwrap())
            .unwrap();

        let cell = Arc::new(RwLock::new(TipCertificate::default()));
        load_persisted_tip_certificate(&store, &cell).await;

        let got = cell.read().await;
        assert_eq!(got.height, 0, "a certificate for a block that is not our tip must not load");
        assert!(got.signatures.is_empty(), "and it must not leak its signatures into the cell either");
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
            P2PEvent::NewCommittedBlock(block, vec![]),
            &mempool,
            &peer_count,
            &store,
            &chain_state,
            &engine,
            &own_kp,
            &p2p_tx,
            &None,
            &Arc::new(Mutex::new(0)),
            &Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            &Arc::new(RwLock::new(TipCertificate::default())),
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
        // Quorum gate (audit A1): the block is adopted only with a certificate proving quorum.
        // A single-validator set reaches quorum on that validator's own precommit.
        let block_hash = block.hash();
        let cert = commit_sigs_to_votes(tip_commit_sigs(1, block_hash, &[&validator_kp]), 1, block_hash);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let peer_count = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));

        let validator_set = ValidatorSet::new(vec![Validator::new(validator_addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, validator_addr.clone(), 0)));

        let own_kp = KeyPair::generate();
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);

        handle_p2p_event(
            P2PEvent::NewCommittedBlock(block, cert),
            &mempool,
            &peer_count,
            &store,
            &chain_state,
            &engine,
            &own_kp,
            &p2p_tx,
            &None,
            &Arc::new(Mutex::new(0)),
            &Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            &Arc::new(RwLock::new(TipCertificate::default())),
        )
        .await;

        let state = chain_state.read().await;
        assert!(state.get(&validator_addr).unwrap().balance > 0, "block reward must land on the actual block validator");
        assert!(state.get(&Address::from_public_key(&own_kp.public)).is_none(), "our own address never participated and must not receive anything");
    }

    /// Audit A1: a committed block from a real in-set validator, correctly signed, building on our
    /// tip is STILL dropped if its accompanying certificate does not prove quorum. This is the fork
    /// defense — `TOPIC_COMMITTED_BLOCKS` is public, so a single Byzantine validator must not be
    /// able to gossip a block it alone stands behind and have receivers adopt it. Two-validator set,
    /// certificate carrying only one of the two precommits (below the 2/3 threshold): must not apply.
    #[tokio::test]
    async fn new_committed_block_without_quorum_certificate_is_dropped() {
        let proposer_kp = KeyPair::generate();
        let proposer_addr = Address::from_public_key(&proposer_kp.public);
        let other_kp = KeyPair::generate();
        let other_addr = Address::from_public_key(&other_kp.public);

        // Block built by an in-set validator on the fresh store's tip (Hash::ZERO) — passes the
        // signature, membership, and prev_hash checks, so only the quorum gate can stop it.
        let block = signed_block(&proposer_kp, 1, Hash::ZERO);
        let block_hash = block.hash();
        // Certificate with only the proposer's own precommit: 1 of 2, below quorum.
        let lone_cert = commit_sigs_to_votes(tip_commit_sigs(1, block_hash, &[&proposer_kp]), 1, block_hash);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let peer_count = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));

        // Two equal-stake validators, so a lone precommit is genuinely below the 2/3 threshold.
        let validator_set = ValidatorSet::new(
            vec![
                Validator::new(proposer_addr.clone(), 1_000_000, true),
                Validator::new(other_addr, 1_000_000, true),
            ],
            0,
        );
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, proposer_addr.clone(), 0)));
        let own_kp = KeyPair::generate();
        let (p2p_tx, mut p2p_rx) = mpsc::channel(8);

        handle_p2p_event(
            P2PEvent::NewCommittedBlock(block, lone_cert),
            &mempool,
            &peer_count,
            &store,
            &chain_state,
            &engine,
            &own_kp,
            &p2p_tx,
            &None,
            &Arc::new(Mutex::new(0)),
            &Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            &Arc::new(RwLock::new(TipCertificate::default())),
        )
        .await;

        // Dropped: no quorum, so never applied (height unchanged) and nothing broadcast.
        assert_eq!(store.read().await.latest_height(), 0, "a block without a quorum certificate must not be adopted");
        assert!(chain_state.read().await.get(&proposer_addr).is_none(), "no reward minted for an unproven block");
        assert!(p2p_rx.try_recv().is_err());
    }

    /// Blocks that properly chain from `Hash::ZERO` (a fresh store's tip) through each other.
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

    /// Puts `blocks` into a fresh store and returns it alongside a tip-certificate cell holding a
    /// quorum certificate for the last one — the state a node is in after committing them.
    async fn store_with_chain(
        kp: &KeyPair,
        blocks: &[Block],
    ) -> (Arc<RwLock<HelixDb>>, Arc<RwLock<TipCertificate>>) {
        let store = Arc::new(RwLock::new(fresh_store()));
        for b in blocks {
            store.write().await.put_block(b.clone()).unwrap();
        }
        let tip = blocks.last().unwrap();
        let cell = Arc::new(RwLock::new(TipCertificate {
            height: tip.height(),
            block_hash: tip.hash().to_hex(),
            signatures: tip_commit_sigs(tip.height(), tip.hash(), &[kp]),
        }));
        (store, cell)
    }

    /// Drives a `PeerBehind` event through `handle_p2p_event` and collects whatever it broadcast.
    async fn blocks_served_to_peer_at(
        peer_tip: u64,
        store: &Arc<RwLock<HelixDb>>,
        tip_certificate: &Arc<RwLock<TipCertificate>>,
    ) -> Vec<(u64, usize)> {
        let (p2p_tx, mut p2p_rx) = mpsc::channel(64);
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let engine = Arc::new(RwLock::new(BftEngine::new(
            ValidatorSet::new(vec![Validator::new(addr.clone(), 1_000_000, true)], 0),
            addr,
            0,
        )));

        handle_p2p_event(
            P2PEvent::PeerBehind { peer_tip },
            &Arc::new(RwLock::new(Mempool::new())),
            &Arc::new(AtomicUsize::new(0)),
            store,
            &Arc::new(RwLock::new(ChainState::new(0))),
            &engine,
            &kp,
            &p2p_tx,
            &None,
            &Arc::new(Mutex::new(0)),
            &Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            tip_certificate,
        )
        .await;

        let mut served = Vec::new();
        while let Ok(cmd) = p2p_rx.try_recv() {
            if let P2PCommand::BroadcastBlock(b, cert) = cmd {
                served.push((b.height(), cert.len()));
            }
        }
        served
    }

    /// The production incident of 2026-07-29, as a test (#137). A peer sits exactly one block
    /// behind us; that block is our tip, so its certificate exists *only* in the live cell (no
    /// successor block carries it yet). Before this path existed the peer had no way to obtain it —
    /// the one-shot commit broadcast was long gone, gap-fill needs a gap of two and a `sync_peer` —
    /// and since it was part of the quorum, the chain stopped with it for 14.5 hours.
    #[tokio::test]
    async fn a_peer_one_block_behind_is_served_our_tip_with_its_certificate() {
        let kp = KeyPair::generate();
        let blocks = chained_blocks(&kp, &[1]);
        let (store, cell) = store_with_chain(&kp, &blocks).await;

        let served = blocks_served_to_peer_at(0, &store, &cell).await;

        assert_eq!(
            served,
            vec![(1, 1)],
            "the tip must be served, carrying the certificate from the live cell"
        );
    }

    /// Negative control for the certificate sourcing, so the test above cannot pass vacuously: with
    /// the cell empty we hold no certificate for our tip, and serving an uncertified block would
    /// only get it dropped by the receiver's quorum gate. Nothing must go out.
    #[tokio::test]
    async fn a_tip_we_hold_no_certificate_for_is_not_served() {
        let kp = KeyPair::generate();
        let blocks = chained_blocks(&kp, &[1]);
        let (store, _) = store_with_chain(&kp, &blocks).await;
        let empty_cell = Arc::new(RwLock::new(TipCertificate::default()));

        let served = blocks_served_to_peer_at(0, &store, &empty_cell).await;

        assert!(served.is_empty(), "without a certificate there is nothing worth sending");
    }

    /// A certificate for a *different* block than our tip must not be attached to it. The cell is
    /// updated at every commit, so a mismatch means it is stale — treat it as absent rather than
    /// pairing a block with someone else's proof.
    #[tokio::test]
    async fn a_stale_tip_certificate_is_not_attached_to_the_tip() {
        let kp = KeyPair::generate();
        let blocks = chained_blocks(&kp, &[1]);
        let (store, _) = store_with_chain(&kp, &blocks).await;
        let wrong_hash = Hash::digest(b"some other block");
        let stale = Arc::new(RwLock::new(TipCertificate {
            height: 1,
            block_hash: wrong_hash.to_hex(),
            signatures: tip_commit_sigs(1, wrong_hash, &[&kp]),
        }));

        let served = blocks_served_to_peer_at(0, &store, &stale).await;

        assert!(served.is_empty(), "a certificate for another block must not be served as ours");
    }

    /// Blocks below the tip are certified by their successor's `last_commit`, not by the live cell —
    /// so a peer several blocks behind gets each of them with the right proof. Proves both
    /// certificate sources work in one sweep, and that they are served oldest-first (the receiver's
    /// fast path only accepts `our_height + 1`, so order is not cosmetic).
    #[tokio::test]
    async fn blocks_below_the_tip_are_served_with_the_certificate_from_their_successor() {
        let kp = KeyPair::generate();
        let mut blocks = chained_blocks(&kp, &[1, 2, 3]);
        // Stamp each block with the certificate for its predecessor, exactly as a real proposer
        // does — this is what makes a stored block below the tip certifiable at all.
        for i in 1..blocks.len() {
            let prev_height = blocks[i - 1].height();
            let prev_hash = blocks[i - 1].hash();
            blocks[i].header.last_commit = tip_commit_sigs(prev_height, prev_hash, &[&kp]);
        }
        let (store, cell) = store_with_chain(&kp, &blocks).await;

        let served = blocks_served_to_peer_at(0, &store, &cell).await;

        assert_eq!(
            served,
            vec![(1, 1), (2, 1), (3, 1)],
            "every missing block, oldest first, each with a non-empty certificate"
        );
    }

    /// The serve stops at the first block it cannot certify instead of skipping it. The receiver
    /// applies the fast path strictly in sequence, so a hole makes everything after it unusable —
    /// and here block 2 carries no `last_commit`, leaving block 1 uncertifiable.
    #[tokio::test]
    async fn the_serve_stops_at_the_first_block_it_cannot_certify() {
        let kp = KeyPair::generate();
        let blocks = chained_blocks(&kp, &[1, 2]);
        let (store, cell) = store_with_chain(&kp, &blocks).await;

        let served = blocks_served_to_peer_at(0, &store, &cell).await;

        assert!(
            served.is_empty(),
            "block 1 has no certificate (block 2 carries no last_commit), so the serve must stop \
             there rather than skipping ahead to the certifiable tip"
        );
    }

    /// A peer that is ahead of us, or level with us, has nothing to receive. Guards the direction of
    /// the comparison at the handler level, where a slip would have every healthy node broadcasting
    /// its tip at every other node forever.
    #[tokio::test]
    async fn a_peer_that_is_not_behind_is_served_nothing() {
        let kp = KeyPair::generate();
        let blocks = chained_blocks(&kp, &[1]);
        let (store, cell) = store_with_chain(&kp, &blocks).await;

        assert!(blocks_served_to_peer_at(1, &store, &cell).await.is_empty(), "level: nothing to send");
        assert!(blocks_served_to_peer_at(9, &store, &cell).await.is_empty(), "ahead: nothing to send");
    }

    // ── P2P block sync (#138) ─────────────────────────────────────────────────

    /// Registers `kp` as a staked validator, so `validators_from_state` yields a set with real
    /// voting power and a quorum can actually be reached.
    fn stake_in_state(chain_state: &mut ChainState, kp: &KeyPair) {
        let addr = Address::from_public_key(&kp.public);
        let min_stake = chain_state.governance_params.min_validator_stake;
        let mut acc = helix_executor::AccountState::new(&addr);
        acc.staked = min_stake;
        chain_state.accounts.insert(addr.to_string(), acc);
    }

    /// A store at genesis, chain state with `kp` staked, and an engine — the state of a node about
    /// to receive its first block-sync batch.
    async fn blocksync_fixture(
        kp: &KeyPair,
    ) -> (
        Arc<RwLock<HelixDb>>,
        Arc<RwLock<ChainState>>,
        Arc<RwLock<BftEngine>>,
        Arc<RwLock<TipCertificate>>,
    ) {
        let store = Arc::new(RwLock::new(fresh_store()));
        let mut cs = ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX);
        stake_in_state(&mut cs, kp);
        let addr = Address::from_public_key(&kp.public);
        let engine = Arc::new(RwLock::new(BftEngine::new(
            ValidatorSet::new(vec![Validator::new(addr.clone(), 1_000_000, true)], 0),
            addr,
            0,
        )));
        (
            store,
            Arc::new(RwLock::new(cs)),
            engine,
            Arc::new(RwLock::new(TipCertificate::default())),
        )
    }

    async fn deliver_batch(
        batch: BlockSyncResponse,
        store: &Arc<RwLock<HelixDb>>,
        chain_state: &Arc<RwLock<ChainState>>,
        engine: &Arc<RwLock<BftEngine>>,
        tip_certificate: &Arc<RwLock<TipCertificate>>,
    ) {
        let (p2p_tx, _rx) = mpsc::channel(8);
        handle_p2p_event(
            P2PEvent::BlocksSynced(batch, "12D3KooWtest".to_string()),
            &Arc::new(RwLock::new(Mempool::new())),
            &Arc::new(AtomicUsize::new(0)),
            store,
            chain_state,
            engine,
            &KeyPair::generate(),
            &p2p_tx,
            &None,
            &Arc::new(Mutex::new(0)),
            &Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            tip_certificate,
        )
        .await;
    }

    /// The whole point of #138: a node that is behind asks a peer, receives a verifiable batch, and
    /// catches up — with no RPC `sync_peer` involved anywhere. This is the capability whose absence
    /// left the origin node structurally unable to recover on 2026-07-29.
    #[tokio::test]
    async fn a_verifiable_batch_is_applied_and_advances_our_tip() {
        let kp = KeyPair::generate();
        let (store, chain_state, engine, cell) = blocksync_fixture(&kp).await;
        let blocks = chained_blocks(&kp, &[1, 2, 3]);
        let tip = blocks.last().unwrap();
        let batch = BlockSyncResponse {
            tip_certificate: commit_sigs_to_votes(
                tip_commit_sigs(tip.height(), tip.hash(), &[&kp]),
                tip.height(),
                tip.hash(),
            ),
            blocks: blocks.clone(),
        };

        deliver_batch(batch, &store, &chain_state, &engine, &cell).await;

        assert_eq!(store.read().await.latest_height(), 3, "the whole batch must be applied");
        assert_eq!(store.read().await.latest_hash(), blocks[2].hash());
    }

    /// The security property the batch rests on. Everything else about these blocks is impeccable —
    /// real staked signer, valid signatures, unbroken chain from our tip — and they must still be
    /// refused, because nothing proves the network ever finalized them. Without this a single peer
    /// could hand us any history it liked.
    #[tokio::test]
    async fn a_batch_whose_tip_certificate_lacks_quorum_is_refused_entirely() {
        let kp = KeyPair::generate();
        let other = KeyPair::generate();
        let (store, chain_state, engine, cell) = blocksync_fixture(&kp).await;
        // A second staker, so one signature is genuinely short of the 2/3 threshold.
        stake_in_state(&mut *chain_state.write().await, &other);

        let blocks = chained_blocks(&kp, &[1, 2, 3]);
        let tip = blocks.last().unwrap();
        let batch = BlockSyncResponse {
            tip_certificate: commit_sigs_to_votes(
                tip_commit_sigs(tip.height(), tip.hash(), &[&kp]),
                tip.height(),
                tip.hash(),
            ),
            blocks,
        };

        deliver_batch(batch, &store, &chain_state, &engine, &cell).await;

        assert_eq!(
            store.read().await.latest_height(),
            0,
            "an unproven batch must not be applied — not even its first block"
        );
    }

    /// A certificate for a block that is not the batch tip must not carry the batch. Otherwise a
    /// peer could append arbitrary blocks after a genuinely finalized one and have them adopted.
    #[tokio::test]
    async fn a_certificate_for_the_wrong_block_does_not_carry_the_batch() {
        let kp = KeyPair::generate();
        let (store, chain_state, engine, cell) = blocksync_fixture(&kp).await;
        let blocks = chained_blocks(&kp, &[1, 2, 3]);
        // Certificate for block 2 while the batch tip is block 3.
        let wrong = &blocks[1];
        let batch = BlockSyncResponse {
            tip_certificate: commit_sigs_to_votes(
                tip_commit_sigs(wrong.height(), wrong.hash(), &[&kp]),
                wrong.height(),
                wrong.hash(),
            ),
            blocks: blocks.clone(),
        };

        deliver_batch(batch, &store, &chain_state, &engine, &cell).await;

        assert_eq!(store.read().await.latest_height(), 0);
    }

    /// A batch that does not chain from our own tip is refused — even fully certified. Applying it
    /// would splice an unrelated history onto ours.
    #[tokio::test]
    async fn a_batch_that_does_not_chain_from_our_tip_is_refused() {
        let kp = KeyPair::generate();
        let (store, chain_state, engine, cell) = blocksync_fixture(&kp).await;
        // Built on a foreign ancestor instead of the fresh store's Hash::ZERO tip.
        let mut prev = Hash::digest(b"a different chain");
        let mut blocks = Vec::new();
        for h in 1..=3u64 {
            let b = signed_block(&kp, h, prev);
            prev = b.hash();
            blocks.push(b);
        }
        let tip = blocks.last().unwrap();
        let batch = BlockSyncResponse {
            tip_certificate: commit_sigs_to_votes(
                tip_commit_sigs(tip.height(), tip.hash(), &[&kp]),
                tip.height(),
                tip.hash(),
            ),
            blocks: blocks.clone(),
        };

        deliver_batch(batch, &store, &chain_state, &engine, &cell).await;

        assert_eq!(store.read().await.latest_height(), 0);
    }

    /// A gap inside the batch is refused rather than applied up to the hole, which would leave the
    /// store's height and its contents disagreeing.
    #[tokio::test]
    async fn a_non_contiguous_batch_is_refused() {
        let kp = KeyPair::generate();
        let (store, chain_state, engine, cell) = blocksync_fixture(&kp).await;
        let all = chained_blocks(&kp, &[1, 2, 3]);
        // Drop block 2, keeping 1 and 3 — heights jump and the chain breaks.
        let blocks = vec![all[0].clone(), all[2].clone()];
        let tip = blocks.last().unwrap();
        let batch = BlockSyncResponse {
            tip_certificate: commit_sigs_to_votes(
                tip_commit_sigs(tip.height(), tip.hash(), &[&kp]),
                tip.height(),
                tip.hash(),
            ),
            blocks,
        };

        deliver_batch(batch, &store, &chain_state, &engine, &cell).await;

        assert_eq!(store.read().await.latest_height(), 0);
    }

    /// An oversized block must not ride in over block sync.
    ///
    /// This is the door that actually matters for the size rule. Gossip cannot deliver such a block
    /// at all — it is past the transmit limit, which is the whole problem — but block sync will
    /// carry up to 8 MB, so without a check here a peer could hand us a block that our own proposer
    /// would never build and that no other node would accept. That is a fork, not a nuisance: a size
    /// limit some nodes enforce and others do not is two different chains.
    #[tokio::test]
    async fn a_batch_containing_an_oversized_block_is_refused() {
        let kp = KeyPair::generate();
        let (store, chain_state, engine, cell) = blocksync_fixture(&kp).await;

        let mut b1 = signed_block(&kp, 1, Hash::ZERO);
        let mut fat = helix_core::Transaction {
            version: 1,
            tx_type: helix_core::transaction::TxType::Transfer,
            from: Address::from_public_key(&kp.public),
            to: Some(Address::from_public_key(&kp.public)),
            amount: 1,
            fee: 1,
            nonce: 0,
            data: vec![0u8; helix_core::fee::MAX_BLOCK_BYTES as usize + 1],
            crypto_version: kp.scheme,
            signature: Sig::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        fat.signature = kp.sign(fat.signing_hash().as_bytes()).unwrap();
        b1.transactions = vec![fat];
        // Merkle root and proposer signature made correct, so size is the only thing left to
        // refuse it on — otherwise this would pass for the wrong reason.
        let tx_hashes: Vec<_> = b1.transactions.iter().map(|t| t.hash()).collect();
        b1.header.merkle_root = helix_crypto::merkle_root(&tx_hashes);
        b1.header.signature = kp.sign(b1.header.signing_hash().as_bytes()).unwrap();

        let batch = BlockSyncResponse {
            tip_certificate: commit_sigs_to_votes(
                tip_commit_sigs(1, b1.hash(), &[&kp]),
                1,
                b1.hash(),
            ),
            blocks: vec![b1],
        };

        deliver_batch(batch, &store, &chain_state, &engine, &cell).await;

        assert_eq!(
            store.read().await.latest_height(),
            0,
            "an oversized block must not be spliced into the chain"
        );
    }

    /// A block signed by someone outside the validator set is refused even when the batch tip
    /// carries a real quorum — the impersonated block would otherwise ride in on its neighbour.
    #[tokio::test]
    async fn a_batch_containing_a_block_from_a_non_validator_is_refused() {
        let kp = KeyPair::generate();
        let impostor = KeyPair::generate(); // never staked
        let (store, chain_state, engine, cell) = blocksync_fixture(&kp).await;

        let b1 = signed_block(&kp, 1, Hash::ZERO);
        let b2 = signed_block(&impostor, 2, b1.hash());
        let batch = BlockSyncResponse {
            tip_certificate: commit_sigs_to_votes(
                tip_commit_sigs(2, b2.hash(), &[&kp]),
                2,
                b2.hash(),
            ),
            blocks: vec![b1, b2],
        };

        deliver_batch(batch, &store, &chain_state, &engine, &cell).await;

        assert_eq!(store.read().await.latest_height(), 0);
    }

    /// A tampered block must fail signature verification. Proves the per-block check is live and not
    /// shadowed by the tip certificate.
    #[tokio::test]
    async fn a_batch_containing_a_tampered_block_is_refused() {
        let kp = KeyPair::generate();
        let (store, chain_state, engine, cell) = blocksync_fixture(&kp).await;
        let mut blocks = chained_blocks(&kp, &[1, 2]);
        // Re-point the validator field after signing: the signature no longer matches the header.
        blocks[0].header.validator = Address::from_public_key(&KeyPair::generate().public);
        let tip = blocks.last().unwrap().clone();
        let batch = BlockSyncResponse {
            tip_certificate: commit_sigs_to_votes(
                tip_commit_sigs(tip.height(), tip.hash(), &[&kp]),
                tip.height(),
                tip.hash(),
            ),
            blocks,
        };

        deliver_batch(batch, &store, &chain_state, &engine, &cell).await;

        assert_eq!(store.read().await.latest_height(), 0);
    }

    /// An empty answer changes nothing and must not panic — a peer legitimately says "I have
    /// nothing for you" when it has been pruned or is itself behind.
    #[tokio::test]
    async fn an_empty_batch_is_a_no_op() {
        let kp = KeyPair::generate();
        let (store, chain_state, engine, cell) = blocksync_fixture(&kp).await;
        deliver_batch(BlockSyncResponse::empty(), &store, &chain_state, &engine, &cell).await;
        assert_eq!(store.read().await.latest_height(), 0);
    }

    /// Before anyone has staked there is no set to reach a quorum in, so the bootstrap window must
    /// stay open — otherwise a genuinely fresh node could never sync its first blocks, which is the
    /// failure that once had nodes re-derive their own solo genesis and fork off block by block.
    #[tokio::test]
    async fn the_bootstrap_window_syncs_without_a_quorum_certificate() {
        let kp = KeyPair::generate();
        let store = Arc::new(RwLock::new(fresh_store()));
        // No stakers at all — `validators_from_state` yields an empty set.
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        let addr = Address::from_public_key(&kp.public);
        let engine = Arc::new(RwLock::new(BftEngine::new(
            ValidatorSet::new(vec![Validator::new(addr.clone(), 1_000_000, true)], 0),
            addr,
            0,
        )));
        let cell = Arc::new(RwLock::new(TipCertificate::default()));
        let blocks = chained_blocks(&kp, &[1, 2]);

        deliver_batch(
            BlockSyncResponse { blocks, tip_certificate: vec![] },
            &store,
            &chain_state,
            &engine,
            &cell,
        )
        .await;

        assert_eq!(
            store.read().await.latest_height(),
            2,
            "with no validator set yet, a batch must still be adoptable"
        );
    }

    /// The serving side: a peer asks for a range and gets it, with a certificate for the last block
    /// it is given.
    #[tokio::test]
    async fn the_block_provider_serves_a_requested_range_with_a_certificate() {
        use helix_p2p::BlockProvider;
        let kp = KeyPair::generate();
        let blocks = chained_blocks(&kp, &[1, 2, 3]);
        let (store, cell) = store_with_chain(&kp, &blocks).await;
        let provider = StoreBlockProvider { store, tip_certificate: cell };

        let served = provider.blocks(1, 3).await;

        assert_eq!(
            served.blocks.iter().map(|b| b.height()).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(!served.tip_certificate.is_empty(), "the served tip must carry its proof");
    }

    /// Asked for more than we hold, we serve what we have — clamped to our own tip rather than
    /// erroring or padding.
    #[tokio::test]
    async fn the_block_provider_clamps_a_request_to_its_own_tip() {
        use helix_p2p::BlockProvider;
        let kp = KeyPair::generate();
        let blocks = chained_blocks(&kp, &[1, 2]);
        let (store, cell) = store_with_chain(&kp, &blocks).await;
        let provider = StoreBlockProvider { store, tip_certificate: cell };

        let served = provider.blocks(1, 50).await;

        assert_eq!(served.blocks.len(), 2);
    }

    /// A range we do not hold gets an honest empty answer, never a partial or fabricated one.
    #[tokio::test]
    async fn the_block_provider_serves_nothing_beyond_its_tip() {
        use helix_p2p::BlockProvider;
        let kp = KeyPair::generate();
        let blocks = chained_blocks(&kp, &[1]);
        let (store, cell) = store_with_chain(&kp, &blocks).await;
        let provider = StoreBlockProvider { store, tip_certificate: cell };

        let served = provider.blocks(9, 10).await;

        assert!(served.blocks.is_empty() && served.tip_certificate.is_empty());
    }

    /// A block whose successor carries no `last_commit` cannot be certified by us, so the provider
    /// serves the certifiable prefix instead of refusing the range outright — a requester must not
    /// get permanently stuck behind one such block.
    #[tokio::test]
    async fn the_block_provider_shrinks_to_the_certifiable_prefix() {
        use helix_p2p::BlockProvider;
        let kp = KeyPair::generate();
        let mut blocks = chained_blocks(&kp, &[1, 2, 3]);
        // Block 2 certifies block 1; block 3 certifies nothing (empty last_commit).
        let b1_height = blocks[0].height();
        let b1_hash = blocks[0].hash();
        blocks[1].header.last_commit = tip_commit_sigs(b1_height, b1_hash, &[&kp]);
        let (store, _) = store_with_chain(&kp, &blocks).await;
        // Empty cell, so the tip (block 3) is uncertifiable too.
        let empty_cell = Arc::new(RwLock::new(TipCertificate::default()));
        let provider = StoreBlockProvider { store, tip_certificate: empty_cell };

        let served = provider.blocks(1, 3).await;

        assert_eq!(
            served.blocks.iter().map(|b| b.height()).collect::<Vec<_>>(),
            vec![1],
            "only block 1 is provable here, so only block 1 is served"
        );
        assert!(!served.tip_certificate.is_empty());
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
            P2PEvent::NewCommittedBlock(block, vec![]),
            &mempool,
            &peer_count,
            &store,
            &chain_state,
            &engine,
            &own_kp,
            &p2p_tx,
            &None,
            &Arc::new(Mutex::new(0)),
            &Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            &Arc::new(RwLock::new(TipCertificate::default())),
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
        apply_finalized_block(block, false, vec![], &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height, &Arc::new(RwLock::new(TipCertificate::default()))).await;

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

        apply_finalized_block(block, false, vec![], &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height, &Arc::new(RwLock::new(TipCertificate::default()))).await;

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

        apply_finalized_block(block.clone(), false, vec![], &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height, &Arc::new(RwLock::new(TipCertificate::default()))).await;
        let issued_after_first = chain_state.read().await.total_issued;
        assert!(issued_after_first > 0, "the first application must mint the scheduled block reward");

        // A second application of the *same* block/height — as a racing duplicate ingestion
        // path would produce — must change nothing further.
        apply_finalized_block(block, false, vec![], &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height, &Arc::new(RwLock::new(TipCertificate::default()))).await;
        let issued_after_second = chain_state.read().await.total_issued;
        assert_eq!(issued_after_second, issued_after_first, "the block reward must not be minted twice for the same height");
        assert_eq!(store.read().await.latest_height(), 1, "the duplicate must not re-touch storage either");
    }

    /// Backlog #146: the chain check is an *independent* second gate, not a restatement of the
    /// height guard. Here the guard is entirely correct — the incoming height is genuinely new —
    /// and the block is still refused, because it does not build on our tip.
    ///
    /// That independence is the whole point. #145 was a case where the guard had gone stale and
    /// was the only thing between two ingest paths and a double execution; with this gate the
    /// block would have been refused whatever the guard said. Both are cheap, and they fail for
    /// different reasons.
    #[tokio::test]
    async fn a_finalized_block_that_does_not_chain_from_our_tip_is_refused() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let first = signed_block(&kp, 1, Hash::ZERO);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        let validator_set = ValidatorSet::new(vec![Validator::new(addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, addr, 0)));
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);
        let last_applied_height = Arc::new(Mutex::new(0u64));
        let cert = Arc::new(RwLock::new(TipCertificate::default()));

        apply_finalized_block(first, false, vec![], &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height, &cert).await;
        assert_eq!(store.read().await.latest_height(), 1, "precondition: block 1 applied");
        let issued = chain_state.read().await.total_issued;

        // Height 2 — new, so the height guard is satisfied — but built on a parent we never had.
        let orphan = signed_block(&kp, 2, Hash::digest(b"a tip from some other branch"));
        apply_finalized_block(orphan, false, vec![], &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height, &cert).await;

        assert_eq!(
            store.read().await.latest_height(),
            1,
            "a block that does not chain from our tip must not be spliced into the chain",
        );
        assert_eq!(
            chain_state.read().await.total_issued,
            issued,
            "and it must not have been executed either — no reward, no state change",
        );
        assert_eq!(
            *last_applied_height.lock().await,
            1,
            "the guard must not be advanced by a block that was refused",
        );
    }

    /// The other direction of the same race, and the one that actually bit production code: the
    /// guard used to be *released* the moment the height was claimed, long before the block
    /// reached the store. Every catch-up path takes its starting point from
    /// `store.latest_height()` *after* acquiring this lock — so one that ran inside that window
    /// saw the store still one block short, concluded it was behind, re-fetched the block from a
    /// peer and executed it a second time, minting the block reward twice.
    ///
    /// Asserted as an invariant rather than by trying to hit the window: no observer holding the
    /// guard may ever see it claim a height the store does not have yet. The observer polls under
    /// the real lock while a real `apply_finalized_block` runs, so with the fix reverted it
    /// catches the violation on the first `.await` inside the apply.
    /// Multi-threaded on purpose: on the single-threaded test runtime the observer would only get
    /// a turn where `apply_finalized_block` actually pends, and its uncontended lock acquisitions
    /// never do — the observer would sit at zero observations and the assertion would be vacuous
    /// (which is exactly what the first version of this test did).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_height_guard_is_held_until_the_block_is_actually_stored() {
        let kp = KeyPair::generate();
        let block = signed_block(&kp, 1, Hash::ZERO);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        let engine = Arc::new(RwLock::new(BftEngine::new(
            ValidatorSet::new(vec![], 0),
            Address::from_public_key(&kp.public),
            0,
        )));
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);
        let last_applied_height = Arc::new(Mutex::new(0u64));

        let violations = Arc::new(AtomicUsize::new(0));
        let observations = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let observer = tokio::spawn({
            let (guard, store, violations, observations, stop) = (
                last_applied_height.clone(),
                store.clone(),
                violations.clone(),
                observations.clone(),
                stop.clone(),
            );
            async move {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    observations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // `try_lock`, not `lock().await`: blocking on the guard would make this
                    // observer trivially quiet once the fix holds it, and a quiet observer proves
                    // nothing. Failing to acquire *is* the fix working; acquiring mid-apply is the
                    // bug, and is exactly what a catch-up path would do with the lock it got.
                    if let Ok(claimed) = guard.try_lock() {
                        let stored = store.read().await.latest_height();
                        if *claimed > stored {
                            violations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    tokio::task::yield_now().await;
                }
            }
        });

        apply_finalized_block(
            block,
            false,
            vec![],
            &store,
            &mempool,
            &chain_state,
            &engine,
            &p2p_tx,
            None,
            &last_applied_height,
            &Arc::new(RwLock::new(TipCertificate::default())),
        )
        .await;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        observer.await.unwrap();

        assert!(
            observations.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "the observer never got a turn — it would report zero violations no matter what"
        );
        assert_eq!(
            store.read().await.latest_height(),
            1,
            "precondition: the block really was applied, so the window existed to be observed"
        );
        assert_eq!(
            violations.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a catch-up path holding the guard saw a claimed height the store did not have yet — \
             it would fetch that block from a peer and execute it again, minting the reward twice"
        );
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
            P2PEvent::NewCommittedBlock(far_ahead, vec![]),
            &mempool,
            &peer_count,
            &store,
            &chain_state,
            &engine,
            &kp,
            &p2p_tx,
            &Some(peer_url),
            &last_applied_height,
            &Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            &Arc::new(RwLock::new(TipCertificate::default())),
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
            vec![],
            &store,
            &mempool,
            &chain_state,
            &engine,
            &p2p_tx,
            None,
            &last_applied_height,
            &Arc::new(RwLock::new(TipCertificate::default())),
        )
        .await;

        assert_eq!(
            chain_state.read().await.total_issued,
            issued_after_gap_fill,
            "the racing duplicate must not mint the block reward a second time"
        );
        assert_eq!(store.read().await.latest_height(), 3, "the racing duplicate must not re-touch storage either");
    }

    /// Wiring-level regression test that `apply_finalized_block`'s epoch-rotation block threads
    /// `execute_block`'s three-tier decision (backlog #132) into the live `BftEngine` — the pure
    /// promotion logic itself has exhaustive unit coverage in `helix_executor::state`. It walks a
    /// brand-new staker through the full lifecycle at the node level:
    ///
    ///   pending (1 epoch, absent from the set) → probation (in the set, **zero voting power**,
    ///   no proposer turn) → full active membership.
    ///
    /// Closes the gap found live on 2026-07-20: a `Stake` tx alone made a second validator
    /// quorum-critical the moment the epoch rotated, freezing the chain because its node wasn't
    /// actually connected. Two epochs of no voting power is the answer to that.
    ///
    /// It does **not** close the phantom case of 2026-07-28 (#132). The `last_commit` this fixture
    /// feeds in makes the staker's signature visible, but nothing depends on it any more — the
    /// silent staker in the companion test below reaches the same full membership. See #141.
    #[tokio::test]
    async fn epoch_rotation_walks_a_new_staker_through_probation_to_full_power() {
        let genesis_kp = KeyPair::generate();
        let genesis_addr = Address::from_public_key(&genesis_kp.public);
        let new_staker_kp = KeyPair::generate();
        let new_staker_addr = Address::from_public_key(&new_staker_kp.public);

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
            // Genesis seeds `active_validators` at block 0 (see `Genesis::apply`), so the
            // incumbent holds its seat across rotations while newcomers walk the tiers. Modelling
            // that here is what makes this a fresh-genesis chain rather than the one-time
            // pre-`active_validators` upgrade window (in which everyone runs full via the
            // `stakers()` fallback and probation offers no gate — covered separately in executor).
            cs.active_validators.insert(genesis_addr.clone());
        }
        let validator_set = ValidatorSet::new(vec![Validator::new(genesis_addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, genesis_addr.clone(), 0)));
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);
        let last_applied_height = Arc::new(Mutex::new(0u64));

        // Each rotation block below is chained from the store's current tip (`tip_of(&store)`),
        // because `apply_finalized_block` refuses blocks that do not chain (#146). The heights
        // still jump a whole epoch at a time — this test is about what a rotation does, not about
        // contiguity — but the hash chain is real, which is what the ingest path requires.
        let apply = |block: Block, store: &Arc<RwLock<HelixDb>>, engine: &Arc<RwLock<BftEngine>>| {
            let (store, engine, mempool, chain_state, p2p_tx, last_applied_height) = (
                store.clone(), engine.clone(), mempool.clone(), chain_state.clone(),
                p2p_tx.clone(), last_applied_height.clone(),
            );
            async move {
                apply_finalized_block(
                    block, false, vec![], &store, &mempool, &chain_state, &engine, &p2p_tx, None, &last_applied_height,
                    &Arc::new(RwLock::new(TipCertificate::default())),
                )
                .await;
            }
        };

        // First epoch boundary: both accounts qualify, but the new staker was never active before,
        // so it enters the one-epoch pending delay — absent from the live set entirely.
        apply(signed_block(&genesis_kp, helix_consensus::EPOCH_LENGTH, tip_of(&store).await), &store, &engine).await;
        assert!(
            engine.read().await.validator_set().get(&genesis_addr).is_some(),
            "the already-active validator must remain active"
        );
        assert!(
            engine.read().await.validator_set().get(&new_staker_addr).is_none(),
            "a brand-new staker must not enter the set on the very rotation it first qualifies"
        );

        // Second epoch boundary: the new staker enters PROBATION — now in the signing set so its
        // liveness is provable, but with zero voting power and no proposer turn, so it cannot make
        // the chain depend on it before it has shown a node is actually running.
        apply(signed_block(&genesis_kp, helix_consensus::EPOCH_LENGTH * 2, tip_of(&store).await), &store, &engine).await;
        {
            let eng = engine.read().await;
            let v = eng.validator_set().get(&new_staker_addr).cloned();
            assert!(v.is_some(), "the staker must enter the set at the second rotation (probation)");
            assert_eq!(v.unwrap().voting_power, 0, "…but as a zero-power probationer, not a full voter");
        }
        assert!(
            chain_state.read().await.probationary_validators.contains(&new_staker_addr),
            "chain state records it as probationary, not active"
        );

        // During the probation epoch its node signs a block's `last_commit` — the proof of a live
        // node the promotion gate requires.
        apply(
            signed_block_with_commit(
                &genesis_kp, helix_consensus::EPOCH_LENGTH * 2 + 1, tip_of(&store).await, &[&new_staker_kp],
            ),
            &store, &engine,
        )
        .await;

        // Third epoch boundary: having served the probation epoch, the probationer is promoted to
        // full active membership with real voting power.
        apply(signed_block(&genesis_kp, helix_consensus::EPOCH_LENGTH * 3, tip_of(&store).await), &store, &engine).await;
        {
            let eng = engine.read().await;
            let v = eng.validator_set().get(&new_staker_addr).cloned();
            assert!(v.is_some(), "it stays in the set");
            assert!(v.unwrap().voting_power > 0, "and now carries real voting power — full member");
        }
        assert!(
            chain_state.read().await.active_validators.contains(&new_staker_addr),
            "chain state now records it as active — the full lifecycle completed",
        );
    }

    /// Companion to the promotion path above, run end-to-end through the node: a staker whose node
    /// never sends a heartbeat crosses the same epoch boundaries as one that does — and does *not*
    /// reach the same place. It waits its pending epoch outside the signing set, spends its
    /// probation epoch in the set at zero voting power, and is then held there rather than
    /// promoted (#132/#141).
    ///
    /// The node-level path matters on its own: the executor decides, but it is the node that has
    /// to carry that decision into the live `ValidatorSet` the engine actually votes with.
    #[tokio::test]
    async fn epoch_rotation_never_gives_a_phantom_staker_voting_power() {
        let genesis_kp = KeyPair::generate();
        let genesis_addr = Address::from_public_key(&genesis_kp.public);
        let phantom_addr = Address::from_public_key(&KeyPair::generate().public);

        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let store = Arc::new(RwLock::new(fresh_store()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut cs = chain_state.write().await;
            cs.governance_params.min_validator_stake = 1;
            cs.update_account(&genesis_addr, |acc| acc.staked = 1_000_000);
            cs.update_account(&phantom_addr, |acc| acc.staked = 1_000_000);
            cs.active_validators.insert(genesis_addr.clone());
        }
        let validator_set = ValidatorSet::new(vec![Validator::new(genesis_addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(validator_set, genesis_addr.clone(), 0)));
        let (p2p_tx, _p2p_rx) = mpsc::channel(8);
        let last_applied_height = Arc::new(Mutex::new(0u64));

        // The phantom never signs a single `last_commit` at any point below.
        // Chained from the current tip for the same reason as the sibling test above (#146).
        let boundary = async |epoch: u64| {
            signed_block(&genesis_kp, helix_consensus::EPOCH_LENGTH * epoch, tip_of(&store).await)
        };
        let apply_one = async |block, last: &Arc<Mutex<u64>>| {
            apply_finalized_block(
                block, false, vec![], &store, &mempool, &chain_state, &engine, &p2p_tx, None, last,
                &Arc::new(RwLock::new(TipCertificate::default())),
            )
            .await;
        };

        // First boundary: picked up as pending — not in the signing set at all.
        apply_one(boundary(1).await, &last_applied_height).await;
        assert!(
            engine.read().await.validator_set().get(&phantom_addr).is_none(),
            "a brand-new staker waits out its pending epoch outside the signing set"
        );

        // Second boundary: enters probation — in the set, but powerless, so quorum does not
        // depend on it and a node that isn't really running cannot stall anything yet.
        apply_one(boundary(2).await, &last_applied_height).await;
        {
            let eng = engine.read().await;
            let v = eng.validator_set().get(&phantom_addr).cloned();
            assert!(v.is_some(), "the probationer is in the signing set");
            assert_eq!(v.unwrap().voting_power, 0, "…but carries no voting power during probation");
        }
        assert!(
            !chain_state.read().await.active_validators.contains(&phantom_addr),
            "and is not active yet"
        );

        // Third boundary: NOT promoted, having produced nothing at all — and, decisively, still
        // carrying no voting power in the set the engine actually votes with. Serving the epoch is
        // not the requirement; proving a node is running is.
        apply_one(boundary(3).await, &last_applied_height).await;
        assert!(
            !chain_state.read().await.active_validators.contains(&phantom_addr),
            "a staker with no running node behind it must never become quorum-critical"
        );
        {
            let eng = engine.read().await;
            let power = eng.validator_set().get(&phantom_addr).map(|v| v.voting_power);
            assert!(
                matches!(power, None | Some(0)),
                "and the live set must not hand it power either — got {power:?}"
            );
        }

        // Two more boundaries: it cycles and never gets in. The point is that this is stable,
        // not that it is delayed by one more epoch.
        apply_one(boundary(4).await, &last_applied_height).await;
        apply_one(boundary(5).await, &last_applied_height).await;
        assert!(
            !chain_state.read().await.active_validators.contains(&phantom_addr),
            "and it stays out for as long as nobody runs the node it staked for"
        );
    }

    /// End to end through the node's own machinery: a validator on probation with **zero liquid
    /// balance** must produce a heartbeat that its own mempool actually accepts. Both halves have
    /// bitten before — a transaction the node happily signs and the pool silently drops is
    /// indistinguishable from one that was never sent, and it would put the promotion gate right
    /// back to unpassable (#141), one layer below where anyone would look.
    ///
    /// The mirrored exemption set is published here the same way the node does it, so this also
    /// pins that `publish_fee_exempt_probationers` is what makes the pool agree with the executor.
    #[tokio::test]
    async fn a_broke_probationer_sends_a_heartbeat_its_own_mempool_accepts() {
        let kp = Arc::new(KeyPair::generate());
        let addr = Address::from_public_key(&kp.public);
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut cs = chain_state.write().await;
            cs.update_account(&addr, |acc| acc.staked = 100_000);
            cs.probationary_validators.insert(addr.clone());
            assert_eq!(cs.get(&addr).unwrap().balance, 0, "precondition: nothing liquid");
        }
        let (p2p_tx, mut p2p_rx) = mpsc::channel(8);

        publish_fee_exempt_probationers(&chain_state, &mempool).await;
        send_probation_heartbeat_if_due(&kp, &chain_state, &mempool, &p2p_tx).await;

        let pending = mempool.write().await.take(10);
        assert_eq!(pending.len(), 1, "the heartbeat must reach this node's own pool");
        assert_eq!(pending[0].tx_type, TxType::ProbationHeartbeat);
        assert_eq!(pending[0].from, addr);
        assert_eq!(pending[0].fee, 0, "an operator who staked everything has nothing to pay with");

        assert!(
            matches!(p2p_rx.try_recv(), Ok(P2PCommand::BroadcastTransaction(_))),
            "and it must be gossiped — a heartbeat only this node knows about proves nothing",
        );
    }

    /// Retries have to be *distinct messages*, or they are not retries.
    ///
    /// This is the trap the design walked into once already: ML-DSA signs deterministically and
    /// the nonce cannot change, so two attempts built from the same state are byte-identical —
    /// gossipsub drops the repeat as "already been published" and the local pool rejects it as a
    /// pending nonce. What looked like ten attempts per epoch was one, and losing that single
    /// message cost the joiner a whole epoch (one four-validator run in five, 2026-07-31).
    ///
    /// Asserted on the hash rather than on the payload, because what matters is not that some
    /// field differs but that the network sees something it has not seen before.
    #[tokio::test]
    async fn each_heartbeat_retry_is_a_message_the_network_has_not_seen() {
        let kp = Arc::new(KeyPair::generate());
        let addr = Address::from_public_key(&kp.public);
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut cs = chain_state.write().await;
            cs.update_account(&addr, |acc| acc.staked = 100_000);
            cs.probationary_validators.insert(addr.clone());
            cs.applied_height = 210;
        }
        let (p2p_tx, mut p2p_rx) = mpsc::channel(8);
        publish_fee_exempt_probationers(&chain_state, &mempool).await;

        send_probation_heartbeat_if_due(&kp, &chain_state, &mempool, &p2p_tx).await;
        // A later tick, same epoch, same nonce — only the chain has moved on.
        chain_state.write().await.applied_height = 220;
        send_probation_heartbeat_if_due(&kp, &chain_state, &mempool, &p2p_tx).await;

        let mut hashes = Vec::new();
        while let Ok(P2PCommand::BroadcastTransaction(tx)) = p2p_rx.try_recv() {
            assert_eq!(tx.tx_type, TxType::ProbationHeartbeat);
            assert_eq!(tx.nonce, 0, "retries keep the nonce — only one of them may ever execute");
            hashes.push(tx.hash().to_hex());
        }
        assert_eq!(hashes.len(), 2, "both attempts must be gossiped, not just the first");
        assert_ne!(
            hashes[0], hashes[1],
            "a retry identical to the original is silently dropped by gossipsub and reaches nobody",
        );
    }

    /// The other direction, so the test above cannot pass by simply always sending: an active
    /// validator, and a probationer that has already proved itself, send nothing at all. Without
    /// this the node would gossip a useless transaction every ten ticks forever.
    #[tokio::test]
    async fn nobody_else_sends_a_probation_heartbeat() {
        let kp = Arc::new(KeyPair::generate());
        let addr = Address::from_public_key(&kp.public);
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut cs = chain_state.write().await;
            cs.update_account(&addr, |acc| acc.staked = 100_000);
            cs.active_validators.insert(addr.clone());
        }
        let (p2p_tx, _rx) = mpsc::channel(8);

        send_probation_heartbeat_if_due(&kp, &chain_state, &mempool, &p2p_tx).await;
        assert_eq!(mempool.read().await.len(), 0, "an active validator sends none");

        // Now on probation, but the proof is already recorded: still nothing to say.
        {
            let mut cs = chain_state.write().await;
            cs.active_validators.clear();
            cs.probationary_validators.insert(addr.clone());
            cs.probation_seen.insert(addr.clone());
        }
        send_probation_heartbeat_if_due(&kp, &chain_state, &mempool, &p2p_tx).await;
        assert_eq!(
            mempool.read().await.len(),
            0,
            "and one that has already proved itself does not keep repeating it",
        );
    }

    /// The startup sync moved out of the constructor so the RPC can serve during it, which
    /// means block production now starts while the chain may still be empty. A validator that
    /// proposes there builds its own fork of the network it is trying to join — and on a
    /// single-validator set nothing else stops it, since `peers_needed_for_quorum()` is 0 and
    /// the mesh gate passes straight through.
    ///
    /// This pins that the sync flag alone holds it: with the flag set, the loop must not
    /// advance the chain; with it cleared, it must.
    /// Backlog #151, and the half the unit tests cannot reach: that the counter the health loop
    /// watches is actually driven by the real loop, and driven *ahead of the gates*.
    ///
    /// A node held in the sync gate takes the earliest `continue` there is. It is alive and must
    /// keep counting — if the counter sat after any gate, this parked-but-healthy node would be
    /// reported dead, which is the false alarm that would get the warning ignored. Testing the
    /// pure fold alone would have passed happily with the increment placed anywhere, or nowhere.
    #[tokio::test]
    async fn a_loop_parked_in_the_sync_gate_still_proves_it_is_alive() {
        let kp = Arc::new(KeyPair::generate());
        let addr = Address::from_public_key(&kp.public);
        let store = Arc::new(RwLock::new(fresh_store()));
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut cs = chain_state.write().await;
            cs.governance_params.min_validator_stake = 1;
            cs.update_account(&addr, |acc| acc.staked = 1_000_000);
        }
        let vset = ValidatorSet::new(vec![Validator::new(addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(vset, addr.clone(), 0)));
        let (p2p_tx, _rx) = mpsc::channel(64);
        let ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        // Held in the sync gate for the whole test.
        let syncing = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let loop_handle = tokio::spawn(block_production_loop(
            store.clone(),
            mempool.clone(),
            chain_state.clone(),
            kp.clone(),
            engine.clone(),
            Arc::new(Mutex::new(0u64)),
            p2p_tx.clone(),
            None,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            syncing.clone(),
            Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            Arc::new(RwLock::new(TipCertificate::default())),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            ticks.clone(),
        ));

        tokio::time::sleep(Duration::from_millis(BLOCK_TIME_MS * 4)).await;
        loop_handle.abort();

        assert_eq!(
            store.read().await.latest_height(),
            0,
            "precondition: the node really was parked, not producing"
        );
        assert!(
            ticks.load(std::sync::atomic::Ordering::Relaxed) >= 2,
            "a loop parked in the sync gate must still prove it is alive — got {}",
            ticks.load(std::sync::atomic::Ordering::Relaxed)
        );
    }

    #[tokio::test]
    async fn block_production_waits_for_the_initial_sync() {
        let kp = Arc::new(KeyPair::generate());
        let addr = Address::from_public_key(&kp.public);
        let store = Arc::new(RwLock::new(fresh_store()));
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut cs = chain_state.write().await;
            cs.governance_params.min_validator_stake = 1;
            cs.update_account(&addr, |acc| acc.staked = 1_000_000);
        }
        let vset = ValidatorSet::new(vec![Validator::new(addr.clone(), 1_000_000, true)], 0);
        let engine = Arc::new(RwLock::new(BftEngine::new(vset, addr.clone(), 0)));
        let (p2p_tx, _rx) = mpsc::channel(64);
        let last_applied = Arc::new(Mutex::new(0u64));
        let peer_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let syncing = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let loop_handle = tokio::spawn(block_production_loop(
            store.clone(),
            mempool.clone(),
            chain_state.clone(),
            kp.clone(),
            engine.clone(),
            last_applied.clone(),
            p2p_tx.clone(),
            None,
            peer_count.clone(),
            syncing.clone(),
            Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            Arc::new(RwLock::new(TipCertificate::default())),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ));

        // Well past several block intervals: nothing may be produced while syncing.
        tokio::time::sleep(Duration::from_millis(BLOCK_TIME_MS * 4)).await;
        assert_eq!(
            store.read().await.latest_height(),
            0,
            "a syncing node must not propose — it would fork off the chain it is still fetching"
        );

        // Sync finishes: the same loop, unchanged otherwise, must now make progress.
        syncing.store(false, std::sync::atomic::Ordering::Relaxed);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while store.read().await.latest_height() == 0 {
            assert!(std::time::Instant::now() < deadline, "production did not resume after sync");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        loop_handle.abort();
    }

    /// Backlog #143. This node's own power meets quorum (`peers_needed_for_quorum() == 0`), but
    /// the round it is on belongs to a *different* validator — one small enough to be below the
    /// 1 % cap, so it is not needed for quorum, yet still takes its proposer turns. That other
    /// validator produces nothing this node will accept: offline, or (the live case) behind and
    /// proposing on a `prev_hash` we reject. Either way this node sits in the no-active-round
    /// wait.
    ///
    /// The bug: `needed == 0` skipped the round clock outright, so the timeout never fired, the
    /// round never advanced, and the height stopped for good — measured on a three-node devnet
    /// 2026-07-30, twice out of twice, ten minutes with no progress. The chain has to reach the
    /// The wiring, not the rule. `not_validating_advice` is a pure function and stays green
    /// whether or not anything ever fills `silent_peer_validators` — and an advice branch that is
    /// never reached is exactly as useless as the wrong advice it replaced. This is the same gap
    /// that hid in #147's teardown and #151's tick counter, so it gets a test that runs the real
    /// loop.
    ///
    /// The engine is driven to the point where it already considers the other validator silent
    /// (rounds time out on tick counts, not wall-clock, which is what makes this affordable), then
    /// the production loop is started and must publish that number for the health loop to read.
    #[tokio::test]
    async fn the_production_loop_publishes_how_many_validators_have_gone_silent() {
        let kp = Arc::new(KeyPair::generate());
        let addr = Address::from_public_key(&kp.public);
        let absent = Address::from_public_key(&KeyPair::generate().public);

        let store = Arc::new(RwLock::new(fresh_store()));
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut cs = chain_state.write().await;
            cs.governance_params.min_validator_stake = 1;
            cs.update_account(&addr, |acc| acc.staked = 10_000_000);
            cs.update_account(&absent, |acc| acc.staked = 10_000_000);
        }

        let vset = ValidatorSet::new(
            vec![
                Validator::new(addr.clone(), 10_000_000, true),
                Validator::new(absent.clone(), 10_000_000, true),
            ],
            0,
        );
        let engine = Arc::new(RwLock::new(BftEngine::new(vset, addr.clone(), 0)));

        // Time out a few rounds with the other validator never voting, which is what the engine
        // counts as silence.
        {
            let mut eng = engine.write().await;
            for _ in 0..4 {
                while !eng.note_round_tick(&kp) {}
                eng.take_outbound_votes();
                let _ = eng.advance_round(&kp, Hash::digest(b"genesis"), vec![]);
                eng.take_outbound_votes();
            }
            assert!(
                eng.silent_peer_validators() > 0,
                "precondition: the engine must already regard the other validator as silent"
            );
        }

        let silent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (p2p_tx, _rx) = mpsc::channel(64);
        let loop_handle = tokio::spawn(block_production_loop(
            store.clone(),
            mempool.clone(),
            chain_state.clone(),
            kp.clone(),
            engine.clone(),
            Arc::new(Mutex::new(0u64)),
            p2p_tx.clone(),
            None,
            Arc::new(std::sync::atomic::AtomicUsize::new(2)),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            Arc::new(RwLock::new(TipCertificate::default())),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            silent.clone(),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ));

        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while silent.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the production loop never published the silent-validator count, so the health \
                 loop can never tell 'this node is stuck' from 'this node is waiting on someone \
                 else' — and goes on advising a restart that does not help"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        loop_handle.abort();
    }

    /// next round on its own and produce there.
    ///
    /// `block_production_waits_for_the_initial_sync` above is the control for the other half:
    /// a sole validator, where `needed == 0` *and* it is our turn, must still produce as before.
    #[tokio::test]
    async fn a_proposer_this_node_does_not_need_cannot_stop_the_height() {
        let kp = Arc::new(KeyPair::generate());
        let addr = Address::from_public_key(&kp.public);
        let absent = Address::from_public_key(&KeyPair::generate().public);

        let store = Arc::new(RwLock::new(fresh_store()));
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let chain_state = Arc::new(RwLock::new(ChainState::new(TOTAL_SUPPLY_HLX * NANO_PER_HLX)));
        {
            let mut cs = chain_state.write().await;
            cs.governance_params.min_validator_stake = 1;
            cs.update_account(&addr, |acc| acc.staked = 10_000_000);
            cs.update_account(&absent, |acc| acc.staked = 100);
        }

        // Order matters: `proposer_for_round` is `(height + round) % len`, so at height 1 round 0
        // the turn belongs to index 1 — the absent validator — and only at round 1 to us.
        let vset = ValidatorSet::new(
            vec![
                Validator::new(addr.clone(), 10_000_000, true),
                Validator::new(absent.clone(), 100, true),
            ],
            0,
        );
        let engine = Arc::new(RwLock::new(BftEngine::new(vset, addr.clone(), 0)));
        {
            let eng = engine.read().await;
            assert_eq!(
                eng.peers_needed_for_quorum(),
                0,
                "precondition: our power alone meets quorum, which is what used to skip the clock"
            );
            assert!(
                !eng.is_our_turn(),
                "precondition: round 0 of height 1 belongs to the absent validator"
            );
        }

        let (p2p_tx, _rx) = mpsc::channel(64);
        let loop_handle = tokio::spawn(block_production_loop(
            store.clone(),
            mempool.clone(),
            chain_state.clone(),
            kp.clone(),
            engine.clone(),
            Arc::new(Mutex::new(0u64)),
            p2p_tx.clone(),
            None,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(std::sync::Mutex::new(SigningGuard::unguarded())),
            Arc::new(RwLock::new(TipCertificate::default())),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ));

        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while store.read().await.latest_height() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the height never moved: a proposer we do not need for quorum still held the \
                 chain, because the round clock never ran (#143)"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        loop_handle.abort();
    }
}

#[cfg(test)]
mod genesis_verification_tests {
    use super::*;
    use helix_core::genesis_block;
    use helix_crypto::{KeyPair, Signature};

    fn some_genesis(ts: u64) -> Block {
        let kp = KeyPair::generate();
        genesis_block(
            Address::from_public_key(&kp.public),
            kp.public.clone(),
            Signature::from_bytes(vec![0u8; 8]),
            ts,
        )
    }

    /// The gap #139 is about, stated as a test: a peer that serves a *different chain's* genesis
    /// must not get this node to adopt it. Nothing else in the join path catches this — the peer
    /// supplies both the genesis and the `state_hash` it is checked against.
    #[test]
    fn a_genesis_that_is_not_the_configured_one_is_refused() {
        let genesis = some_genesis(1);
        let other = some_genesis(2);
        assert_ne!(genesis.hash(), other.hash(), "the two must actually differ");

        let err = verify_genesis_checkpoint(Some(&other.hash().to_hex()), &genesis)
            .expect_err("a genesis that is not the configured one must be refused");
        // The operator has to be able to tell the two apart from the message alone.
        let msg = err.to_string();
        assert!(msg.contains(&genesis.hash().to_hex()), "must name what was served");
        assert!(msg.contains(&other.hash().to_hex()), "must name what was expected");
    }

    #[test]
    fn the_configured_genesis_is_accepted() {
        let genesis = some_genesis(1);
        assert!(verify_genesis_checkpoint(Some(&genesis.hash().to_hex()), &genesis).is_ok());
    }

    /// Operators copy this hash out of logs, release notes and explorers, which disagree on casing.
    #[test]
    fn the_checkpoint_comparison_ignores_hex_casing_and_whitespace() {
        let genesis = some_genesis(1);
        let hex = genesis.hash().to_hex();
        assert!(verify_genesis_checkpoint(Some(&hex.to_uppercase()), &genesis).is_ok());
        assert!(verify_genesis_checkpoint(Some(&format!("  {hex}  ")), &genesis).is_ok());
    }

    /// No regression for existing deployments: unconfigured must still join, or every operator is
    /// locked out by the upgrade itself. An empty string counts as unconfigured — that is what a
    /// blank env var or an unfilled config line produces, and treating it as a hash to match would
    /// fail every start with a baffling message.
    #[test]
    fn an_unconfigured_checkpoint_still_joins() {
        let genesis = some_genesis(1);
        assert!(verify_genesis_checkpoint(None, &genesis).is_ok());
        assert!(verify_genesis_checkpoint(Some(""), &genesis).is_ok());
        assert!(verify_genesis_checkpoint(Some("   "), &genesis).is_ok());
    }

    fn peer_genesis_with(validator_stake: u64, state_hash: Option<String>) -> PeerGenesis {
        let kp = KeyPair::generate();
        let validator = Address::from_public_key(&kp.public);
        PeerGenesis {
            block: genesis_block(
                validator,
                kp.public.clone(),
                Signature::from_bytes(vec![0u8; 8]),
                0,
            ),
            personhood_authorities: vec![],
            governance_params: GovernanceParams::default(),
            validator_stake,
            allocations: vec![],
            state_hash,
        }
    }

    fn rebuilt(pg: &PeerGenesis) -> ChainState {
        helix_executor::genesis::rebuild_genesis_state(
            pg.block.header.validator.clone(),
            pg.personhood_authorities.clone(),
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

    /// Joining a network that runs different consensus rules has to be *said*, since nothing
    /// prevents it — see `peer_version_warning`'s doc comment for what the silence costs.
    #[test]
    fn a_sync_peer_on_a_different_version_produces_a_warning() {
        let status = serde_json::json!({ "version": "0.8.1", "height": 5 });

        assert!(
            peer_version_warning(&status, "0.8.1").is_none(),
            "matching versions must stay quiet"
        );

        let warning = peer_version_warning(&status, "0.8.0")
            .expect("a version difference must be reported");
        assert!(warning.contains("0.8.1") && warning.contains("0.8.0"), "name both versions: {warning}");

        // A peer too old to report a version leaves us no worse off than before the check —
        // same reasoning as the genesis hash above, so no false alarm either.
        assert!(peer_version_warning(&serde_json::json!({ "height": 5 }), "0.8.1").is_none());
    }

    /// The real incident, kept as a test: an operator on a Hetzner VPS could not start a node
    /// because the seed answered their datacenter IP with a Cloudflare challenge, and all the
    /// node said was `error decoding response body: expected value at line 1 column 1`. Whatever
    /// else changes, that body must never again produce an error that points at our JSON.
    #[test]
    fn a_bot_challenge_is_named_instead_of_surfacing_as_a_json_error() {
        let challenge = "<!DOCTYPE html><html lang=\"en-US\"><head><title>Just a moment...</title>\
                         <script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page\">\
                         </script></head><body>Enable JavaScript and cookies to continue</body></html>";

        let d = diagnose_non_json(challenge);
        assert!(d.contains("bot challenge"), "the cause has to be named: {d}");
        assert!(
            d.contains("/genesis") && d.contains("/sync/blocks"),
            "an operator needs the concrete paths to exempt: {d}"
        );
        assert!(
            d.contains("HELIX_SYNC_PEER"),
            "and a way to get running now, since the fix is on someone else's server: {d}"
        );
        assert!(
            !d.contains("cdn-cgi/challenge-platform"),
            "the raw challenge markup helps nobody and buries the message: {d}"
        );
    }

    /// A plain error page is a different situation from a bot challenge — a proxy in the way,
    /// not a policy — so it must not be reported as the latter, and it must still show enough
    /// of the body to recognise what answered.
    #[test]
    fn an_ordinary_html_error_page_is_distinguished_from_a_challenge() {
        let d = diagnose_non_json("<html><head><title>502 Bad Gateway</title></head><body>nginx</body></html>");
        assert!(!d.contains("bot challenge"), "not every HTML page is a challenge: {d}");
        assert!(d.contains("HTML page"), "say what it was: {d}");
        assert!(d.contains("502"), "show enough of it to identify the responder: {d}");
    }

    /// An empty body used to be indistinguishable from a short one at the end of a truncated
    /// message; both are reported, neither panics on slicing a multi-byte boundary.
    #[test]
    fn an_empty_or_odd_body_is_still_described() {
        assert!(diagnose_non_json("").contains("empty body"));
        let unicode = "Fehler: Verbindung wurde zurückgesetzt — Grüße vom Proxy ✂".repeat(10);
        let d = diagnose_non_json(&unicode);
        assert!(d.contains("answered with"), "{d}");
    }
}

#[cfg(test)]
mod catchup_tests {
    use super::*;

    /// The 2026-07-22 incident, as a rule rather than a story: a validator driving a round is
    /// always a block or two behind the proposer it is voting for, so an unconditional catch-up
    /// fires on essentially every poll and calls `sync_to_externally_finalized_block`, which
    /// drops the round, its buffered votes and the `last_commit` collected so far. The validator
    /// then never precommits, gets liveness-jailed by its peers, appears in no certificate, and
    /// is downtime-jailed 150 blocks later — while looking perfectly healthy in its own logs.
    #[test]
    fn the_catch_up_never_interrupts_a_round_over_a_gap_consensus_is_about_to_close() {
        // Normal validator lag while a round is in flight: hands off.
        for gap in 1..=RPC_CATCHUP_ROUND_GRACE_BLOCKS {
            assert!(
                catchup_defers_to_consensus(100, 100 + gap, true),
                "a {gap}-block gap with a round in flight must defer to consensus"
            );
        }

        // Genuinely left behind — the round is stale, catching up is the whole point.
        assert!(
            !catchup_defers_to_consensus(100, 100 + RPC_CATCHUP_ROUND_GRACE_BLOCKS + 1, true),
            "past the grace window the round cannot close the gap and must not block the sync"
        );

        // A follower has no round to protect and must keep syncing exactly as before — this is
        // the case the loop was built for (P2P unreachable behind the HTTPS tunnel).
        for gap in 1..=(RPC_CATCHUP_ROUND_GRACE_BLOCKS + 5) {
            assert!(
                !catchup_defers_to_consensus(100, 100 + gap, false),
                "a follower must never defer — nothing else will bring it the blocks"
            );
        }
    }
}
