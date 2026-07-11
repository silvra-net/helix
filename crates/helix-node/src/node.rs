use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use helix_consensus::{BftEngine, ConsensusError, Proposal, Validator, ValidatorSet};
use helix_core::{genesis_block, Block};
use helix_crypto::{Address, CryptoScheme, KeyFile, KeyPair};
use helix_executor::{
    execute_block,
    genesis::{GenesisConfig, NANO_PER_HLX, TOTAL_SUPPLY_HLX},
    state::ChainState,
};
use helix_mempool::Mempool;
use helix_p2p::{
    config::P2PConfig,
    service::{P2PCommand, P2PEvent, P2PService},
};
use helix_rpc::server::{start_rpc_server, AppState};
use helix_storage::{db::HelixDb, BlockStore};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::config::{self, NodeConfig};

/// Load the validator keypair from disk, or generate + persist a new one for
/// `scheme_for_new` (the scheme to use only if no key file exists yet).
///
/// File format is `[scheme tag: 1 byte][secret key][public key]`, which lets a
/// validator migrate to a new PQC scheme (see `helix_crypto::CryptoScheme`) by
/// setting `HELIX_VALIDATOR_CRYPTO_SCHEME=sphincs-plus` and regenerating the key —
/// blocks/votes it already signed under the old scheme stay verifiable forever
/// since each one carries its own `crypto_version` tag.
///
/// Pre-migration key files (raw ML-DSA `secret key || public key`, no tag byte)
/// are still read correctly: their length exactly matches the untagged legacy
/// size, which no valid tagged file can produce.
/// Passphrase used to decrypt an encrypted `validator-key.bin` (KeyFile format with
/// `encryption = "aes256gcm-argon2id"`, e.g. produced by `hlx wallet encrypt`). There
/// is no interactive prompt at node startup, so this is the only way to unlock one.
const VALIDATOR_KEY_PASSPHRASE_ENV: &str = "HELIX_VALIDATOR_KEY_PASSPHRASE";

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

        // Bevorzugt: vereinheitlichtes KeyFile-JSON-Format (seit 2026-07-05, dasselbe
        // Format wie `hlx wallet` — kein separates Node-Rohformat mehr nötig, siehe
        // helix-crypto::keyfile). Fallback darunter: legacy Rohformat für bereits
        // bestehende validator-key.bin-Dateien, die noch im alten Format sind.
        if let Ok(text) = std::str::from_utf8(&data) {
            if let Ok(kf) = KeyFile::from_json_str(text) {
                let kp = kf
                    .to_keypair(passphrase.as_deref())
                    .map_err(|e| anyhow::anyhow!("Invalid key in {}: {}", path.display(), e))?;
                info!("Loaded persistent validator keypair ({:?}) from {} (KeyFile format)", kp.scheme, path.display());
                return Ok(kp);
            }
        }

        let legacy_len = CryptoScheme::MlDsa.secret_key_len() + CryptoScheme::MlDsa.public_key_len();
        let (scheme, sk_bytes, pk_bytes) = if data.len() == legacy_len {
            let sk_len = CryptoScheme::MlDsa.secret_key_len();
            (CryptoScheme::MlDsa, data[..sk_len].to_vec(), data[sk_len..].to_vec())
        } else {
            if data.is_empty() {
                anyhow::bail!("Validator key file is empty");
            }
            let scheme = CryptoScheme::from_tag(data[0])
                .map_err(|e| anyhow::anyhow!("Validator key file: {e}"))?;
            let sk_len = scheme.secret_key_len();
            let pk_len = scheme.public_key_len();
            if data.len() != 1 + sk_len + pk_len {
                anyhow::bail!(
                    "Validator key file has unexpected size ({} bytes, expected {})",
                    data.len(), 1 + sk_len + pk_len
                );
            }
            (scheme, data[1..1 + sk_len].to_vec(), data[1 + sk_len..].to_vec())
        };

        let kp = KeyPair::from_raw(scheme, sk_bytes, pk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid key in validator key file: {e}"))?;
        info!("Loaded persistent validator keypair ({:?}) from {} (legacy raw format)", scheme, path.display());
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
        let path = std::env::temp_dir().join(format!("helix-test-key-{}.bin", std::process::id()));
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
    fn reads_pre_migration_legacy_format_as_ml_dsa() {
        let path = std::env::temp_dir().join(format!("helix-test-legacy-key-{}.bin", std::process::id()));
        let kp = KeyPair::generate();
        // Legacy format: no scheme tag byte, just sk || pk.
        let mut data = kp.secret.as_bytes().to_vec();
        data.extend_from_slice(kp.public.as_bytes());
        std::fs::write(&path, &data).unwrap();

        let loaded = load_or_create_keypair(&path, CryptoScheme::SphincsPlus).unwrap();
        assert_eq!(loaded.scheme, CryptoScheme::MlDsa);
        assert_eq!(loaded.public.as_bytes(), kp.public.as_bytes());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn loads_passphrase_encrypted_keyfile_when_passphrase_given() {
        let path = std::env::temp_dir().join(format!("helix-test-encrypted-key-{}.bin", std::process::id()));
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
const MAX_TXS_PER_BLOCK: usize = 1_000;
const RPC_BIND_DEFAULT: &str = "127.0.0.1:8545";

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
    rpc_bind: SocketAddr,
}

impl HelixNode {
    pub async fn new() -> Result<Self> {
        // `helix.toml` (path overridable via HELIX_CONFIG) bundles the node
        // params below; env vars still take precedence over the file, see
        // `config::resolve`.
        let cfg = config::load_node_config()?;

        let key_path = PathBuf::from("validator-key.bin");
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

        let genesis_cfg = GenesisConfig::devnet(address.clone());
        let mut chain_state = if store.get_block_by_height(0).is_ok() {
            info!("Loaded existing chain state from {}", db_path.display());
            store.load_chain_state(TOTAL_SUPPLY_HLX * NANO_PER_HLX)?
        } else {
            let sig = keypair.sign(b"helix-genesis-v1")?;
            let genesis = genesis_block(address.clone(), keypair.public.clone(), sig);
            store.put_block(genesis)?;
            info!("Genesis block created (height 0)");

            let state = genesis_cfg.build_state();
            store.save_chain_state(&state)?;
            info!("Genesis: no validator pre-mine — earnings via 50/50 fee split only");
            state
        };

        // Block sync — download historical blocks from a trusted peer if configured.
        // `sync_peer = "http://seed:8545"` in helix.toml, or HELIX_SYNC_PEER — fetches
        // all blocks this node is missing.
        let sync_peer = config::resolve("HELIX_SYNC_PEER", &cfg.sync_peer);
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
        let (p2p_service, p2p_command_tx, p2p_event_rx) = P2PService::new(p2p_config);

        let rpc_bind = resolve_rpc_bind(&cfg)?;

        Ok(HelixNode {
            keypair: Arc::new(keypair),
            address,
            reward_address,
            sync_peer,
            store: Arc::new(RwLock::new(store)),
            mempool: Arc::new(RwLock::new(Mempool::new())),
            chain_state: Arc::new(RwLock::new(chain_state)),
            p2p_command_tx,
            p2p_event_rx,
            p2p_service: Some(p2p_service),
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

        // Spawn P2P event handler
        let mempool_for_p2p = self.mempool.clone();
        let peer_count_for_p2p = peer_count.clone();
        let store_for_p2p = self.store.clone();
        let chain_state_for_p2p = self.chain_state.clone();
        let engine_for_p2p = engine.clone();
        let keypair_for_p2p = self.keypair.clone();
        let p2p_tx_for_p2p = self.p2p_command_tx.clone();
        let reward_for_p2p = self.reward_address.as_ref().map(|a| Arc::new(a.clone()));
        let sync_peer_for_p2p = self.sync_peer.clone();
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
                    reward_for_p2p.clone(),
                    &sync_peer_for_p2p,
                )
                .await;
            }
        });

        // Block production loop
        let block_loop = tokio::spawn(block_production_loop(
            self.store.clone(),
            self.mempool.clone(),
            self.chain_state.clone(),
            self.keypair.clone(),
            engine,
            self.p2p_command_tx.clone(),
            self.reward_address.map(Arc::new),
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
    reward_address: Option<Arc<Address>>,
    sync_peer: &Option<String>,
) {
    match event {
        P2PEvent::NewTransaction(tx) => {
            let mut pool = mempool.write().await;
            match pool.add(tx) {
                Ok(()) => {}
                Err(e) => warn!("Rejected peer tx: {}", e),
            }
        }
        P2PEvent::NewProposal(proposal) => {
            let result = { engine.write().await.receive_proposal(keypair, proposal.round, proposal.block) };

            // receive_proposal() may have cast our prevote (and possibly a
            // follow-up precommit) for the received proposal — broadcast
            // those regardless of outcome, same as the NewVote arm below.
            let outbound = { engine.write().await.take_outbound_votes() };
            for v in outbound {
                let _ = p2p_tx.try_send(P2PCommand::BroadcastVote(v));
            }

            match result {
                Ok(Some(block)) => {
                    info!(height = block.height(), "Block finalized via peer proposal");
                    apply_finalized_block(block, true, store, mempool, chain_state, engine, p2p_tx, reward_address.clone()).await;
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

            match result {
                Ok(Some(block)) => {
                    info!(height = block.height(), "Block finalized via peer votes");
                    apply_finalized_block(block, true, store, mempool, chain_state, engine, p2p_tx, reward_address.clone()).await;
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
                    let mut s = store.write().await;
                    let mut cs = chain_state.write().await;
                    match sync_blocks_from_peer(peer_url, our_height, &mut s, &mut cs).await {
                        Ok(n) => info!("Gap filled: applied {} blocks", n),
                        Err(e) => warn!("Gap sync failed: {}", e),
                    }
                }
                return;
            }

            // block_height == our_height + 1: verify proposer sig, then apply.
            match block.header.verify_signature() {
                Ok(()) => {
                    info!(height = block_height, "Applying committed block from peer");
                    apply_finalized_block(block, false, store, mempool, chain_state, engine, p2p_tx, reward_address).await;
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

/// Execute, slash, rotate, broadcast, and persist a block that just reached BFT
/// finality — whether that happened locally (this node cast the deciding vote
/// itself in `block_production_loop`) or via a peer's vote arriving through P2P
/// (`handle_p2p_event`). Both paths must apply identical side effects exactly once.
///
/// `should_broadcast`: set to `true` when this node was part of the consensus round
/// (it knows the correct committed round). Set to `false` when applying a block
/// received via `NewCommittedBlock` — the block has already been broadcast by the
/// proposer, and re-broadcasting with a wrong round tag would confuse other nodes.
async fn apply_finalized_block(
    block: Block,
    should_broadcast: bool,
    store: &Arc<RwLock<HelixDb>>,
    mempool: &Arc<RwLock<Mempool>>,
    chain_state: &Arc<RwLock<ChainState>>,
    engine: &Arc<RwLock<BftEngine>>,
    p2p_tx: &mpsc::Sender<P2PCommand>,
    reward_address: Option<Arc<Address>>,
) {
    let tx_hashes: Vec<_> = block.transactions.iter().map(|t| t.hash()).collect();
    let height = block.height();
    let tx_count = block.tx_count();

    // Execute transactions
    {
        let mut state = chain_state.write().await;
        let receipt = execute_block(&mut state, &block, reward_address.as_deref());
        if receipt.failed_txs() > 0 {
            warn!(height, failed = receipt.failed_txs(), "Tx execution failures");
        }
    }

    // Slash any validator caught double-signing during this round. Detected
    // in helix-consensus::VoteSet (conflicting votes, same validator/height/
    // round/type, different block hash) — the signature on both votes is
    // already verified there, so this evidence is trustworthy.
    for ev in engine.write().await.take_evidence() {
        if !ev.is_valid() {
            continue;
        }
        let slashed = {
            let mut state = chain_state.write().await;
            state.slash(&ev.validator, helix_consensus::SLASH_FRACTION_BPS)
        };
        warn!(
            validator = %ev.validator,
            height = ev.height,
            round = ev.round,
            slashed_nano = slashed,
            "Double-sign evidence confirmed — validator slashed"
        );
    }

    // Epoch boundary: rebuild the validator set from current stake.
    // Personhood is read from chain state: ZK-STARK ProvePersonhood txs set
    // PersonhoodStatus::Verified, which unlocks the 1% voting-power cap
    // (instead of the 0.5% cap for unverified validators).
    if height % helix_consensus::EPOCH_LENGTH == 0 {
        let state_guard = chain_state.read().await;
        let stakers = state_guard.stakers();
        let validators: Vec<Validator> = stakers
            .into_iter()
            .map(|(addr, stake)| {
                let has_personhood = state_guard.has_personhood(&addr);
                Validator::new(addr, stake, has_personhood)
            })
            .collect();
        drop(state_guard);
        let had = validators.len();
        let mut eng = engine.write().await;
        eng.rotate_validator_set(validators);
        if had > 0 {
            info!(height, epoch = eng.validator_set().epoch, validators = had, "Validator set rotated");
        }
    }

    // Only the node that participated in consensus knows the correct committed round
    // and can broadcast a semantically correct Proposal. Nodes that received the block
    // via NewCommittedBlock skip re-broadcasting to avoid flooding with wrong round tags.
    if should_broadcast {
        let round = engine.read().await.last_committed_round().unwrap_or(0);
        let _ = p2p_tx.try_send(P2PCommand::BroadcastProposal(Proposal { round, block: block.clone() }));
        let _ = p2p_tx.try_send(P2PCommand::BroadcastBlock(block.clone()));
    }

    // Persist block + chain state to the same redb file, under one write lock.
    {
        let mut s = store.write().await;
        if let Err(e) = s.put_block(block) {
            error!("Failed to store block {}: {}", height, e);
            return;
        }
        let state = chain_state.read().await;
        if let Err(e) = s.save_chain_state(&state) {
            error!("Failed to persist chain state at height {}: {}", height, e);
        }
    }

    { mempool.write().await.remove_committed(&tx_hashes); }

    if tx_count > 0 {
        info!(height, tx_count, "Block committed");
    }
}

async fn block_production_loop(
    store: Arc<RwLock<HelixDb>>,
    mempool: Arc<RwLock<Mempool>>,
    chain_state: Arc<RwLock<ChainState>>,
    keypair: Arc<KeyPair>,
    engine: Arc<RwLock<BftEngine>>,
    p2p_tx: mpsc::Sender<P2PCommand>,
    reward_address: Option<Arc<Address>>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(BLOCK_TIME_MS));

    loop {
        interval.tick().await;

        // A round from a previous tick is still awaiting peer votes — don't
        // clobber it with a brand-new proposal (different timestamp/hash) for
        // the same height, which would orphan any votes peers already cast
        // against the original proposal. Give it a few more ticks before
        // concluding it's stalled (e.g. the proposer went offline, or its
        // block failed validation for enough peers that quorum can never be
        // reached) and forcing it to the next round via `advance_round`.
        let stalled = if engine.read().await.has_active_round() {
            let timed_out = { engine.write().await.note_round_tick() };
            if !timed_out {
                continue;
            }
            true
        } else {
            false
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
                apply_finalized_block(block, true, &store, &mempool, &chain_state, &engine, &p2p_tx, reward_address.clone())
                    .await;
            }
            Err(ConsensusError::AwaitingVotes { round, .. }) => {
                // Multi-validator: our proposal + own votes are cast, round is
                // stored in the engine. Broadcast the proposal itself so
                // peers can validate it and cast their own votes — the votes
                // below only cover this node's own prevote/precommit.
                let block = { engine.read().await.pending_proposal().cloned() };
                if let Some(block) = block {
                    let _ = p2p_tx.try_send(P2PCommand::BroadcastProposal(Proposal { round, block }));
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
        let outbound = { engine.write().await.take_outbound_votes() };
        for vote in outbound {
            let _ = p2p_tx.try_send(P2PCommand::BroadcastVote(vote));
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
/// Skips genesis (height 0) — every node generates it locally.
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
            execute_block(chain_state, block, None);
            store.put_block(block.clone())?;
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
    use helix_crypto::{KeyPair, Signature as Sig};
    use std::collections::HashMap;

    fn signed_block(kp: &KeyPair, height: u64) -> Block {
        let mut block = genesis_block(
            Address::from_public_key(&kp.public),
            kp.public.clone(),
            Sig::from_bytes(vec![]),
        );
        block.header.height = height;
        let sig = kp.sign(block.header.signing_hash().as_bytes()).unwrap();
        block.header.signature = sig;
        block
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

    #[tokio::test]
    async fn applies_all_validly_signed_blocks() {
        let kp = KeyPair::generate();
        let blocks = vec![signed_block(&kp, 1), signed_block(&kp, 2), signed_block(&kp, 3)];
        let peer_url = serve_blocks(blocks).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
        let applied = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state).await.unwrap();

        assert_eq!(applied, 3);
        assert_eq!(store.latest_height(), 3);
    }

    #[tokio::test]
    async fn rejects_tampered_block_and_aborts_cleanly() {
        let kp = KeyPair::generate();
        let mut tampered = signed_block(&kp, 2);
        tampered.header.height = 99; // invalidates the signature without re-signing
        let blocks = vec![signed_block(&kp, 1), tampered, signed_block(&kp, 3)];
        let peer_url = serve_blocks(blocks).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0);
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
}
