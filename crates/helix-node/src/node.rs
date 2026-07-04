use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use helix_consensus::{BftEngine, ConsensusError, Proposal, Validator, ValidatorSet};
use helix_core::{genesis_block, Block};
use helix_crypto::{Address, CryptoScheme, KeyPair};
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
fn load_or_create_keypair(path: &PathBuf, scheme_for_new: CryptoScheme) -> Result<KeyPair> {
    let legacy_len = CryptoScheme::MlDsa.secret_key_len() + CryptoScheme::MlDsa.public_key_len();

    if path.exists() {
        let data = std::fs::read(path)?;

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
        info!("Loaded persistent validator keypair ({:?}) from {}", scheme, path.display());
        Ok(kp)
    } else {
        let kp = KeyPair::generate_for(scheme_for_new);
        // Persist as scheme_tag || sk_bytes || pk_bytes
        let mut data = vec![scheme_for_new as u8];
        data.extend_from_slice(kp.secret.as_bytes());
        data.extend_from_slice(kp.public.as_bytes());
        std::fs::write(path, &data)?;
        info!("Generated new validator keypair ({:?}) → saved to {}", scheme_for_new, path.display());
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
}

const BLOCK_TIME_MS: u64 = 2_000;
const MAX_TXS_PER_BLOCK: usize = 1_000;
const RPC_BIND: &str = "127.0.0.1:8545";

pub struct HelixNode {
    keypair: Arc<KeyPair>,
    address: Address,
    /// Where the validator's 50 % fee share lands.  Defaults to `address` when unset.
    /// Configure via HELIX_REWARD_ADDRESS env var.
    reward_address: Option<Address>,
    store: Arc<RwLock<HelixDb>>,
    mempool: Arc<RwLock<Mempool>>,
    chain_state: Arc<RwLock<ChainState>>,
    p2p_command_tx: mpsc::Sender<P2PCommand>,
    p2p_event_rx: mpsc::Receiver<P2PEvent>,
    p2p_service: Option<P2PService>,
}

impl HelixNode {
    pub async fn new() -> Result<Self> {
        let key_path = PathBuf::from("validator-key.bin");
        let scheme_for_new = match std::env::var("HELIX_VALIDATOR_CRYPTO_SCHEME").as_deref() {
            Ok("sphincs-plus") | Ok("sphincsplus") => CryptoScheme::SphincsPlus,
            _ => CryptoScheme::MlDsa,
        };
        let keypair = load_or_create_keypair(&key_path, scheme_for_new)?;
        let address = Address::from_public_key(&keypair.public);

        // Optional reward address — fees land here instead of the validator address.
        let reward_address = std::env::var("HELIX_REWARD_ADDRESS").ok().and_then(|s| {
            match Address::from_str(&s) {
                Ok(addr) => {
                    info!("Fee reward address : {} (HELIX_REWARD_ADDRESS)", addr);
                    Some(addr)
                }
                Err(_) => {
                    warn!("HELIX_REWARD_ADDRESS is set but invalid — fees go to validator address");
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
        let chain_state = if store.get_block_by_height(0).is_ok() {
            info!("Loaded existing chain state from {}", db_path.display());
            store.load_chain_state(TOTAL_SUPPLY_HLX * NANO_PER_HLX)?
        } else {
            let sig = keypair.sign(b"helix-genesis-v1")?;
            let genesis = genesis_block(address.clone(), sig);
            store.put_block(genesis)?;
            info!("Genesis block created (height 0)");

            let state = genesis_cfg.build_state();
            store.save_chain_state(&state)?;
            info!("Genesis: no validator pre-mine — earnings via 50/50 fee split only");
            state
        };

        // P2P setup
        let p2p_config = P2PConfig::default();
        let (p2p_service, p2p_command_tx, p2p_event_rx) = P2PService::new(p2p_config);

        Ok(HelixNode {
            keypair: Arc::new(keypair),
            address,
            reward_address,
            store: Arc::new(RwLock::new(store)),
            mempool: Arc::new(RwLock::new(Mempool::new())),
            chain_state: Arc::new(RwLock::new(chain_state)),
            p2p_command_tx,
            p2p_event_rx,
            p2p_service: Some(p2p_service),
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
        let rpc_bind: SocketAddr = RPC_BIND.parse()?;
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
        let total_stake = 1_000_000_000_000_000u64;
        let validator = Validator::new(self.address.clone(), total_stake, true);
        let validator_set = ValidatorSet::new(vec![validator], 0);
        let genesis_height = self.store.read().await.latest_height();
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
                    apply_finalized_block(block, store, mempool, chain_state, engine, p2p_tx, reward_address.clone()).await;
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
                    apply_finalized_block(block, store, mempool, chain_state, engine, p2p_tx, reward_address.clone()).await;
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
async fn apply_finalized_block(
    block: Block,
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
    // Personhood attestation isn't wired up yet (Phase 6), so rotated-in
    // validators start uncapped-by-personhood (i.e. capped at 0.5%) until then.
    if height % helix_consensus::EPOCH_LENGTH == 0 {
        let stakers = chain_state.read().await.stakers();
        let validators: Vec<Validator> = stakers
            .into_iter()
            .map(|(addr, stake)| Validator::new(addr, stake, false))
            .collect();
        let had = validators.len();
        let mut eng = engine.write().await;
        eng.rotate_validator_set(validators);
        if had > 0 {
            info!(height, epoch = eng.validator_set().epoch, validators = had, "Validator set rotated");
        }
    }

    // Broadcast to peers before storing (peers can validate against prev_hash).
    // Tagged with the round it actually committed in, so a peer that's
    // exactly one block behind can validate the proposer against the right
    // round instead of assuming round 0.
    let round = engine.read().await.last_committed_round().unwrap_or(0);
    let _ = p2p_tx.try_send(P2PCommand::BroadcastProposal(Proposal { round, block: block.clone() }));

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

        let txs = { mempool.read().await.take(MAX_TXS_PER_BLOCK) };
        let prev_hash = store.read().await.latest_hash();

        let produced = if stalled {
            engine.write().await.advance_round(&keypair, prev_hash, txs)
        } else {
            engine.write().await.produce_block(&keypair, prev_hash, txs)
        };
        match produced {
            Ok(block) => {
                apply_finalized_block(block, &store, &mempool, &chain_state, &engine, &p2p_tx, reward_address.clone())
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
