use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use helix_consensus::{BftEngine, ConsensusError, DoubleSignEvidence, Proposal, Validator, ValidatorSet};
use helix_core::{genesis_block, Block, Transaction, TxType};
use helix_crypto::{Address, CryptoScheme, KeyFile, KeyPair, Signature};
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
    fn rejects_a_raw_non_json_key_file_with_a_helpful_error() {
        let path = std::env::temp_dir().join(format!("helix-test-raw-key-{}.bin", std::process::id()));
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
            info!("Genesis: no liquid pre-mine — validator earns via 50/50 fee split plus the halving block reward");
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

        // Spawn P2P event handler
        let mempool_for_p2p = self.mempool.clone();
        let peer_count_for_p2p = peer_count.clone();
        let store_for_p2p = self.store.clone();
        let chain_state_for_p2p = self.chain_state.clone();
        let engine_for_p2p = engine.clone();
        let keypair_for_p2p = self.keypair.clone();
        let p2p_tx_for_p2p = self.p2p_command_tx.clone();
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
                    apply_finalized_block(block, true, store, mempool, chain_state, engine, p2p_tx, None).await;
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
                    apply_finalized_block(block, true, store, mempool, chain_state, engine, p2p_tx, None).await;
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
                    apply_finalized_block(block, false, store, mempool, chain_state, engine, p2p_tx, None).await;
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
        fee: 0,
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
        // Not a protocol-level state root (not in BlockHeader, not signed, doesn't gate
        // consensus) — a diagnostic escape hatch. If two nodes' logs ever show different
        // state_hash values at the same height, something has silently diverged; grep for
        // it. Also served live via GET /status (NodeStatus::state_hash) for tooling that
        // wants to compare running nodes without trawling logs. See ChainState::state_hash's
        // doc comment for exactly what this is and isn't.
        debug!(height, state_hash = %state.state_hash().to_hex(), "Block applied");
    }

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
    // (up to EPOCH_LENGTH blocks / ~20 min away). Scans the block's own transactions —
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
        // Report any double-sign evidence this tick's produce_block/advance_round
        // turned up (e.g. a stalled round's accumulated evidence).
        let evidence = { engine.write().await.take_evidence() };
        for ev in evidence {
            report_double_sign_evidence(ev, &keypair, &chain_state, &mempool, &p2p_tx).await;
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
            let is_known_validator = chain_state
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
    async fn rejects_validly_signed_block_from_unstaked_address() {
        // Signature is perfectly valid, but `kp` was never registered as a staker —
        // simulates an attacker with a free, throwaway keypair and no stake.
        let kp = KeyPair::generate();
        let blocks = vec![signed_block(&kp, 1, Hash::ZERO)];
        let peer_url = serve_blocks(blocks).await;

        let mut store = fresh_store();
        let mut chain_state = ChainState::new(0); // no stakers registered
        let result = sync_blocks_from_peer(&peer_url, 0, &mut store, &mut chain_state).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("outside the current validator set"));
        assert_eq!(store.latest_height(), 0);
        assert!(store.get_block_by_height(1).is_err());
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
        apply_finalized_block(block, false, &store, &mempool, &chain_state, &engine, &p2p_tx, None).await;

        assert!(
            engine.read().await.validator_set.get(&bad_validator_addr).is_none(),
            "slashed validator must be jailed immediately, not just at the next epoch rotation"
        );
        assert!(
            chain_state.read().await.get(&bad_validator_addr).unwrap().staked < 1_000_000,
            "slash itself must still have applied"
        );
    }
}
