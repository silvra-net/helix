use std::net::SocketAddr;
use std::sync::{atomic::Ordering, Arc};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use helix_core::{Block, Transaction};
use helix_crypto::{Address, Hash};
use helix_executor::state::ChainState;
use helix_mempool::Mempool;
use helix_storage::{db::HelixDb, BlockStore};
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::{
    AccountResponse, BlockResponse, GovernanceParamsResponse, GovernanceProposalResponse,
    GuardianResponse, HeaderResponse, NameResponse, NodeStatus, PersonhoodResponse,
    ProofStepResponse, RecoveryStatusResponse, TxHistoryEntry, TxProofResponse,
};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<RwLock<HelixDb>>,
    pub mempool: Arc<RwLock<Mempool>>,
    pub chain_state: Arc<RwLock<ChainState>>,
    pub node_address: String,
    pub peer_count: Arc<std::sync::atomic::AtomicUsize>,
}

pub async fn start_rpc_server(state: AppState, bind: SocketAddr) {
    let app = Router::new()
        .route("/", get(root))
        .route("/status", get(get_status))
        .route("/blocks/latest", get(get_latest_block))
        .route("/blocks/height/:n", get(get_block_by_height))
        .route("/blocks/height/:n/header", get(get_block_header))
        .route("/blocks/height/:n/proof/:tx_hash", get(get_tx_proof))
        .route("/blocks/hash/:hash", get(get_block_by_hash))
        .route("/blocks/range", get(get_blocks_range))
        .route("/accounts/:address", get(get_account))
        .route("/accounts/:address/name", get(get_account_name))
        .route("/accounts/:address/personhood", get(get_account_personhood))
        .route("/accounts/:address/guardians", get(get_account_guardians))
        .route("/accounts/:address/recovery", get(get_account_recovery))
        .route(
            "/accounts/:address/transactions",
            get(get_account_transactions),
        )
        .route("/names/:name", get(resolve_name))
        .route("/governance/params", get(get_governance_params))
        .route("/governance/proposals", get(get_governance_proposals))
        .route("/governance/proposals/:id", get(get_governance_proposal))
        .route("/mempool", get(get_mempool_info))
        .route("/sync/blocks", get(get_sync_blocks))
        .route("/transactions", post(submit_transaction))
        .layer(CorsLayer::permissive())
        .with_state(state);

    info!("RPC server listening on http://{}", bind);
    let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> Json<Value> {
    Json(json!({
        "name": "Helix Node",
        "version": env!("CARGO_PKG_VERSION"),
        "token": "HLX",
        "crypto": "ML-DSA (Dilithium3) — NIST PQC",
        "endpoints": [
            "GET  /status",
            "GET  /blocks/latest",
            "GET  /blocks/height/{n}",
            "GET  /blocks/height/{n}/header",
            "GET  /blocks/height/{n}/proof/{tx_hash}",
            "GET  /blocks/hash/{hash}",
            "GET  /accounts/{address}",
            "GET  /accounts/{address}/name",
            "GET  /accounts/{address}/personhood",
            "GET  /accounts/{address}/guardians",
            "GET  /accounts/{address}/recovery",
            "GET  /accounts/{address}/transactions",
            "GET  /names/{name}",
            "GET  /governance/params",
            "GET  /governance/proposals",
            "GET  /governance/proposals/{id}",
            "GET  /mempool",
            "POST /transactions"
        ]
    }))
}

async fn get_status(State(state): State<AppState>) -> Json<NodeStatus> {
    let store = state.store.read().await;
    let mempool = state.mempool.read().await;
    let chain = state.chain_state.read().await;
    Json(NodeStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        height: store.latest_height(),
        best_hash: store.latest_hash().to_hex(),
        peer_count: state.peer_count.load(Ordering::Relaxed),
        is_syncing: false,
        mempool_size: mempool.len(),
        total_accounts: chain.account_count(),
        circulating_supply_hlx: chain.circulating_supply() as f64 / 1_000_000_000.0,
        total_burned_hlx: chain.total_burned as f64 / 1_000_000_000.0,
    })
}

async fn get_latest_block(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    let height = store.latest_height();
    match store.get_block_by_height(height) {
        Ok(block) => (StatusCode::OK, Json(json!(BlockResponse::from(block)))),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}

async fn get_block_by_height(
    State(state): State<AppState>,
    Path(n): Path<u64>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    match store.get_block_by_height(n) {
        Ok(block) => (StatusCode::OK, Json(json!(BlockResponse::from(block)))),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}

async fn get_block_by_hash(
    State(state): State<AppState>,
    Path(hash_hex): Path<String>,
) -> impl IntoResponse {
    let hash = match Hash::from_hex(&hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid hash format" })),
            )
        }
    };
    let store = state.store.read().await;
    match store.get_block_by_hash(&hash) {
        Ok(block) => (StatusCode::OK, Json(json!(BlockResponse::from(block)))),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}

/// Batch block download for node sync.
///
/// `GET /blocks/range?from=<height>&count=<n>` — returns up to 500 full blocks
/// starting at `from`.  Used by new nodes bootstrapping from a known peer.
async fn get_blocks_range(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, u64>>,
) -> impl IntoResponse {
    let from = params.get("from").copied().unwrap_or(0);
    let count = params.get("count").copied().unwrap_or(100).min(500);
    let store = state.store.read().await;
    let mut blocks = Vec::with_capacity(count as usize);
    for h in from..from + count {
        match store.get_block_by_height(h) {
            Ok(block) => blocks.push(BlockResponse::from(block)),
            Err(_) => break, // reached tip — stop silently
        }
    }
    (StatusCode::OK, Json(json!(blocks)))
}

/// Full block download for node sync — returns raw `Block` structs as JSON.
///
/// `GET /sync/blocks?from=<height>&count=<n>` — up to 200 blocks per request.
/// Unlike `/blocks/range` (which returns the lossy `BlockResponse` display view),
/// this endpoint returns the full `Block` including signatures and public keys, so
/// a syncing node can replay execution and store blocks in its local database.
async fn get_sync_blocks(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, u64>>,
) -> impl IntoResponse {
    let from = params.get("from").copied().unwrap_or(1);
    let count = params.get("count").copied().unwrap_or(200).min(200);
    let store = state.store.read().await;
    let mut blocks: Vec<Block> = Vec::with_capacity(count as usize);
    for h in from..from + count {
        match store.get_block_by_height(h) {
            Ok(block) => blocks.push(block),
            Err(_) => break,
        }
    }
    (StatusCode::OK, Json(json!(blocks)))
}

/// Header-only view of a block — for light clients that sync the chain of
/// headers without paying the bandwidth cost of every block's full tx list.
async fn get_block_header(
    State(state): State<AppState>,
    Path(n): Path<u64>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    match store.get_block_by_height(n) {
        Ok(block) => (StatusCode::OK, Json(json!(HeaderResponse::from(&block)))),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}

/// Merkle inclusion proof for one transaction in a block. A light client that
/// already trusts the block's `merkle_root` (e.g. from `/blocks/height/{n}/header`)
/// can replay this proof to confirm the transaction was included, without
/// downloading the block's other transactions.
async fn get_tx_proof(
    State(state): State<AppState>,
    Path((height, tx_hash_hex)): Path<(u64, String)>,
) -> impl IntoResponse {
    let tx_hash = match Hash::from_hex(&tx_hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid tx hash format" })),
            )
        }
    };
    let store = state.store.read().await;
    let block = match store.get_block_by_height(height) {
        Ok(b) => b,
        Err(e) => return (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    };
    let index = match block.transactions.iter().position(|tx| tx.hash() == tx_hash) {
        Some(i) => i,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("tx {} not found in block {}", tx_hash_hex, height) })),
            )
        }
    };
    let proof = block
        .merkle_proof_for(index)
        .expect("index came from position() over this block's own transactions, so it's in bounds");
    (
        StatusCode::OK,
        Json(json!(TxProofResponse {
            tx_hash: tx_hash_hex,
            block_height: block.height(),
            block_hash: block.hash().to_hex(),
            merkle_root: block.header.merkle_root.to_hex(),
            leaf_index: index,
            proof: proof.iter().map(ProofStepResponse::from).collect(),
        })),
    )
}

async fn get_account(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    if Address::from_str(&address).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid address format: {}", address) })),
        );
    }
    let chain = state.chain_state.read().await;
    match chain.accounts.get(&address) {
        Some(acc) => (
            StatusCode::OK,
            Json(json!(AccountResponse {
                address: acc.address.clone(),
                balance_hlx: acc.balance_hlx(),
                staked_hlx: acc.staked_hlx(),
                unbonding_stake_hlx: acc.unbonding_stake as f64 / 1_000_000_000.0,
                unbonding_unlock_height: acc.unbonding_unlock_height,
                nonce: acc.nonce,
                has_code: acc.code.is_some(),
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("account {} not found", address) })),
        ),
    }
}

async fn resolve_name(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let name = name.trim_end_matches(".hlx");
    let chain = state.chain_state.read().await;
    match chain.resolve_name(name) {
        Some(address) => (
            StatusCode::OK,
            Json(json!(NameResponse {
                name: name.to_string(),
                address: address.to_string(),
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("name {} not registered", name) })),
        ),
    }
}

async fn get_governance_params(State(state): State<AppState>) -> Json<Value> {
    let chain = state.chain_state.read().await;
    Json(json!(GovernanceParamsResponse {
        min_validator_stake_hlx: chain.governance_params.min_validator_stake as f64 / 1_000_000_000.0,
        fuel_per_fee_unit: chain.governance_params.fuel_per_fee_unit,
    }))
}

async fn get_governance_proposals(State(state): State<AppState>) -> Json<Value> {
    let chain = state.chain_state.read().await;
    let mut proposals: Vec<GovernanceProposalResponse> =
        chain.proposals.values().map(GovernanceProposalResponse::from).collect();
    proposals.sort_by_key(|p| p.id);
    Json(json!({ "proposals": proposals }))
}

async fn get_governance_proposal(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    let chain = state.chain_state.read().await;
    match chain.proposal(id) {
        Some(p) => (StatusCode::OK, Json(json!(GovernanceProposalResponse::from(p)))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("proposal {} not found", id) })),
        ),
    }
}

async fn get_account_name(
    State(state): State<AppState>,
    Path(address_str): Path<String>,
) -> impl IntoResponse {
    let address = match Address::from_str(&address_str) {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid address format" })),
            )
        }
    };
    let chain = state.chain_state.read().await;
    match chain.name_of(&address) {
        Some(name) => (
            StatusCode::OK,
            Json(json!(NameResponse {
                name: name.to_string(),
                address: address_str,
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("no name registered for {}", address_str) })),
        ),
    }
}

async fn get_account_personhood(
    State(state): State<AppState>,
    Path(address_str): Path<String>,
) -> impl IntoResponse {
    let address = match Address::from_str(&address_str) {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid address format" })),
            )
        }
    };
    let chain = state.chain_state.read().await;
    let status = chain.personhood_status(&address);
    (
        StatusCode::OK,
        Json(json!(PersonhoodResponse {
            address: address_str,
            status,
        })),
    )
}

async fn get_account_guardians(
    State(state): State<AppState>,
    Path(address_str): Path<String>,
) -> impl IntoResponse {
    let address = match Address::from_str(&address_str) {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid address format" })),
            )
        }
    };
    let chain = state.chain_state.read().await;
    match chain.guardians(&address) {
        Some(set) => (
            StatusCode::OK,
            Json(json!(GuardianResponse {
                address: address_str,
                guardians: set.guardians.iter().map(|g| g.to_string()).collect(),
                threshold: set.threshold(),
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("no guardians registered for {}", address_str) })),
        ),
    }
}

async fn get_account_recovery(
    State(state): State<AppState>,
    Path(address_str): Path<String>,
) -> impl IntoResponse {
    let address = match Address::from_str(&address_str) {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid address format" })),
            )
        }
    };
    let chain = state.chain_state.read().await;
    let recovered_key_fingerprint = chain.recovery_key(&address).map(|k| k.fingerprint());
    let (pending_approvals, threshold) = match chain.recovery_request(&address) {
        Some(req) => (
            Some(req.approvals.len()),
            chain.guardians(&address).map(|g| g.threshold()),
        ),
        None => (None, None),
    };
    (
        StatusCode::OK,
        Json(json!(RecoveryStatusResponse {
            address: address_str,
            recovered_key_fingerprint,
            pending_approvals,
            threshold,
        })),
    )
}

/// Extracts every transaction touching `address` (as sender or recipient) from `blocks`,
/// newest first. Pure and store-agnostic so it can be unit-tested without a `HelixDb`.
fn extract_tx_history(blocks: &[helix_core::Block], address: &str) -> Vec<TxHistoryEntry> {
    let mut history = Vec::new();
    for block in blocks {
        for tx in &block.transactions {
            let is_sender = tx.from.to_string() == address;
            let is_recipient = tx.to.as_ref().map(|a| a.to_string()).as_deref() == Some(address);
            if is_sender || is_recipient {
                history.push(TxHistoryEntry {
                    hash: tx.hash().to_hex(),
                    from: tx.from.to_string(),
                    to: tx.to.as_ref().map(|a| a.to_string()),
                    amount_hlx: tx.amount as f64 / 1_000_000_000.0,
                    fee_hlx: tx.fee as f64 / 1_000_000_000.0,
                    tx_type: format!("{:?}", tx.tx_type),
                    nonce: tx.nonce,
                    block_height: block.height(),
                    block_hash: block.hash().to_hex(),
                    timestamp: block.header.timestamp,
                });
            }
        }
    }
    history.reverse();
    history
}

async fn get_account_transactions(
    State(state): State<AppState>,
    Path(address_str): Path<String>,
) -> impl IntoResponse {
    if Address::from_str(&address_str).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid address format: {}", address_str) })),
        );
    }
    let store = state.store.read().await;
    let latest = store.latest_height();
    let blocks: Vec<_> = (0..=latest)
        .filter_map(|h| store.get_block_by_height(h).ok())
        .collect();
    let history = extract_tx_history(&blocks, &address_str);
    (
        StatusCode::OK,
        Json(json!({ "address": address_str, "transactions": history })),
    )
}

async fn get_mempool_info(State(state): State<AppState>) -> Json<Value> {
    let mempool = state.mempool.read().await;
    Json(json!({
        "pending_count": mempool.len(),
        "is_empty": mempool.is_empty(),
    }))
}

async fn submit_transaction(
    State(state): State<AppState>,
    Json(tx): Json<Transaction>,
) -> impl IntoResponse {
    let tx_hash = tx.hash().to_hex();
    let mut mempool = state.mempool.write().await;
    match mempool.add(tx) {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(json!({ "tx_hash": tx_hash, "status": "accepted" })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_core::{Block, BlockHeader, CryptoVersion, TxType};
    use helix_crypto::{Hash, PublicKey, Signature};

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&PublicKey::from_bytes(vec![seed; 8]))
    }

    fn tx(from: &Address, to: &Address, amount: u64, nonce: u64) -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: from.clone(),
            to: Some(to.clone()),
            amount,
            fee: 100,
            nonce,
            data: vec![],
            crypto_version: Default::default(),

            signature: Signature::from_bytes(vec![]),
            public_key: PublicKey::from_bytes(vec![]),
        }
    }

    fn block(height: u64, validator: &Address, transactions: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                height,
                timestamp: 1_000 + height,
                prev_hash: Hash::ZERO,
                merkle_root: Hash::ZERO,
                validator: validator.clone(),
                public_key: helix_crypto::PublicKey::from_bytes(vec![]),
                crypto_version: CryptoVersion::MlDsa,
                signature: Signature::from_bytes(vec![]),
            },
            transactions,
        }
    }

    #[test]
    fn extract_tx_history_finds_sent_and_received_newest_first() {
        let alice = addr(1);
        let bob = addr(2);
        let carol = addr(3);

        let block0 = block(0, &alice, vec![tx(&alice, &bob, 10, 0)]);
        let block1 = block(1, &alice, vec![tx(&bob, &alice, 5, 0), tx(&carol, &bob, 1, 0)]);

        let history = extract_tx_history(&[block0, block1], alice.to_string().as_str());

        assert_eq!(history.len(), 2);
        // newest block first
        assert_eq!(history[0].block_height, 1);
        assert_eq!(history[0].from, bob.to_string());
        assert_eq!(history[0].to.as_deref(), Some(alice.to_string().as_str()));
        assert_eq!(history[1].block_height, 0);
        assert_eq!(history[1].from, alice.to_string());
    }

    #[test]
    fn extract_tx_history_ignores_unrelated_transactions() {
        let alice = addr(1);
        let bob = addr(2);
        let carol = addr(3);

        let block0 = block(0, &alice, vec![tx(&bob, &carol, 10, 0)]);

        let history = extract_tx_history(&[block0], alice.to_string().as_str());
        assert!(history.is_empty());
    }
}
