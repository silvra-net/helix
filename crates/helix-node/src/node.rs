use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use helix_consensus::{BftEngine, ConsensusError, Validator, ValidatorSet};
use helix_core::{genesis_block, Block};
use helix_crypto::{Address, KeyPair};
use helix_executor::{execute_block, genesis::GenesisConfig, state::ChainState};
use helix_mempool::Mempool;
use helix_p2p::{
    config::P2PConfig,
    service::{P2PCommand, P2PEvent, P2PService},
};
use helix_rpc::server::{start_rpc_server, AppState};
use helix_storage::{mem::MemBlockStore, BlockStore};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

const BLOCK_TIME_MS: u64 = 2_000;
const MAX_TXS_PER_BLOCK: usize = 1_000;
const RPC_BIND: &str = "127.0.0.1:8545";

pub struct HelixNode {
    keypair: Arc<KeyPair>,
    address: Address,
    store: Arc<RwLock<MemBlockStore>>,
    mempool: Arc<RwLock<Mempool>>,
    chain_state: Arc<RwLock<ChainState>>,
    p2p_command_tx: mpsc::Sender<P2PCommand>,
    p2p_event_rx: mpsc::Receiver<P2PEvent>,
    p2p_service: Option<P2PService>,
}

impl HelixNode {
    pub async fn new() -> Result<Self> {
        let keypair = KeyPair::generate();
        let address = Address::from_public_key(&keypair.public);

        info!("Validator address : {}", address);
        info!("PK fingerprint    : {}", keypair.public.fingerprint());

        // Genesis block
        let mut store = MemBlockStore::new();
        let sig = keypair.sign(b"helix-genesis-v1")?;
        let genesis = genesis_block(address.clone(), sig);
        store.put_block(genesis)?;
        info!("Genesis block created (height 0)");

        // Genesis state
        let genesis_cfg = GenesisConfig::devnet(address.clone());
        let chain_state = genesis_cfg.build_state();
        info!(
            "Genesis: {}M HLX allocated to validator",
            helix_executor::genesis::GENESIS_VALIDATOR_ALLOCATION_HLX / 1_000_000
        );

        // P2P setup
        let p2p_config = P2PConfig::default();
        let (p2p_service, p2p_command_tx, p2p_event_rx) = P2PService::new(p2p_config);

        Ok(HelixNode {
            keypair: Arc::new(keypair),
            address,
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
    store: &Arc<RwLock<MemBlockStore>>,
    chain_state: &Arc<RwLock<ChainState>>,
    engine: &Arc<RwLock<BftEngine>>,
    keypair: &KeyPair,
    p2p_tx: &mpsc::Sender<P2PCommand>,
) {
    match event {
        P2PEvent::NewTransaction(tx) => {
            let mut pool = mempool.write().await;
            match pool.add(tx) {
                Ok(()) => {}
                Err(e) => warn!("Rejected peer tx: {}", e),
            }
        }
        P2PEvent::NewBlock(_block) => {
            // Non-proposer validators joining an in-progress round on receipt
            // of a proposal is not wired up yet — only the block's own
            // proposer currently drives a round (see block_production_loop).
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
                    apply_finalized_block(block, store, mempool, chain_state, engine, p2p_tx).await;
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
    store: &Arc<RwLock<MemBlockStore>>,
    mempool: &Arc<RwLock<Mempool>>,
    chain_state: &Arc<RwLock<ChainState>>,
    engine: &Arc<RwLock<BftEngine>>,
    p2p_tx: &mpsc::Sender<P2PCommand>,
) {
    let tx_hashes: Vec<_> = block.transactions.iter().map(|t| t.hash()).collect();
    let height = block.height();
    let tx_count = block.tx_count();

    // Execute transactions
    {
        let mut state = chain_state.write().await;
        let receipt = execute_block(&mut state, &block);
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

    // Broadcast to peers before storing (peers can validate against prev_hash)
    let _ = p2p_tx.try_send(P2PCommand::BroadcastBlock(block.clone()));

    // Persist
    {
        let mut s = store.write().await;
        if let Err(e) = s.put_block(block) {
            error!("Failed to store block {}: {}", height, e);
            return;
        }
    }

    { mempool.write().await.remove_committed(&tx_hashes); }

    if tx_count > 0 {
        info!(height, tx_count, "Block committed");
    }
}

async fn block_production_loop(
    store: Arc<RwLock<MemBlockStore>>,
    mempool: Arc<RwLock<Mempool>>,
    chain_state: Arc<RwLock<ChainState>>,
    keypair: Arc<KeyPair>,
    engine: Arc<RwLock<BftEngine>>,
    p2p_tx: mpsc::Sender<P2PCommand>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(BLOCK_TIME_MS));

    loop {
        interval.tick().await;

        let txs = { mempool.read().await.take(MAX_TXS_PER_BLOCK) };
        let prev_hash = store.read().await.latest_hash();

        let produced = { engine.write().await.produce_block(&keypair, prev_hash, txs) };
        match produced {
            Ok(block) => {
                apply_finalized_block(block, &store, &mempool, &chain_state, &engine, &p2p_tx)
                    .await;
            }
            Err(ConsensusError::AwaitingVotes { .. }) => {
                // Multi-validator: our proposal + own votes are cast, round is
                // stored in the engine — broadcast the votes below and wait for
                // peers' votes to arrive via handle_p2p_event.
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
