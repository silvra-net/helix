//! The Mesh Data API endpoints: network, block, account, mempool.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde_json::{json, Value};

use crate::map::{self, MapError, SUCCESS};
use crate::node::{Node, NodeError};
use crate::types::{
    AccountBalanceRequest, BlockRequest, BlockTransactionRequest, Currency, MempoolTransactionRequest,
    MeshError, NetworkIdentifier, NetworkRequest, PartialBlockIdentifier,
};

/// The blockchain name in every network identifier.
pub const BLOCKCHAIN: &str = "Helix";
/// The Mesh specification version this service implements.
pub const ROSETTA_VERSION: &str = "1.4.13";

#[derive(Clone)]
struct AppState {
    node: Arc<Node>,
    network: NetworkIdentifier,
}

type Reply = Result<Json<Value>, (StatusCode, Json<MeshError>)>;

fn error(code: u32, message: &str, retriable: bool) -> MeshError {
    MeshError { code, message: message.to_string(), retriable, description: None }
}

fn unavailable() -> MeshError {
    error(1, "The Helix node is unavailable", true)
}
fn unsupported_network() -> MeshError {
    error(2, "This service serves another network", false)
}
fn block_not_found() -> MeshError {
    error(3, "Block not found", true)
}
fn transaction_not_found() -> MeshError {
    error(4, "Transaction not found", false)
}
fn no_record() -> MeshError {
    error(5, "The node has no record of this block's balance changes", false)
}
fn invalid_address() -> MeshError {
    error(6, "Invalid address", false)
}
fn no_history() -> MeshError {
    error(7, "Balances are available at the current block only", false)
}
fn malformed() -> MeshError {
    error(8, "The node answered something this service does not understand", false)
}
fn not_in_mempool() -> MeshError {
    error(9, "Transaction not in the mempool", false)
}
fn rate_limited() -> MeshError {
    let mut e = error(10, "The Helix node is rate-limiting this service", true);
    e.description = Some(
        "the node limits requests per client address, and this service asks for every block — \
         start the node with a higher HELIX_RPC_RATE_LIMIT (burst,refill per second)"
            .into(),
    );
    e
}

/// Every error this service can return — `/network/options` lists them, as the specification asks.
pub fn all_errors() -> Vec<MeshError> {
    vec![
        unavailable(),
        unsupported_network(),
        block_not_found(),
        transaction_not_found(),
        no_record(),
        invalid_address(),
        no_history(),
        malformed(),
        not_in_mempool(),
        rate_limited(),
    ]
}

fn fail(e: MeshError) -> (StatusCode, Json<MeshError>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(e))
}

/// A node failure as a Mesh error; `not_found` says what a 404 means for this request.
fn node_failure(e: NodeError, not_found: MeshError) -> (StatusCode, Json<MeshError>) {
    fail(match e {
        NodeError::Unavailable(err) => {
            tracing::warn!(err = %err, "request to the node failed");
            unavailable()
        }
        NodeError::NotFound => not_found,
        NodeError::Invalid(_) => invalid_address(),
        NodeError::RateLimited => {
            // Once: while it lasts, every request would say it again.
            static SAID: AtomicBool = AtomicBool::new(false);
            if !SAID.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "The node is rate-limiting this service — raise HELIX_RPC_RATE_LIMIT on the node \
                     (e.g. 5000,1000); requests are answered as retriable until then"
                );
            }
            rate_limited()
        }
    })
}

fn map_failure(e: MapError) -> (StatusCode, Json<MeshError>) {
    match e {
        MapError::NoRecord(height) => {
            let mut e = no_record();
            e.description = Some(format!(
                "block {height} was executed by this node without the record (a build before #260) \
                 or has been pruned — serve Mesh from a node that ran the chain from genesis"
            ));
            fail(e)
        }
        MapError::Malformed(why) => {
            tracing::warn!(%why, "malformed answer from the node");
            fail(malformed())
        }
    }
}

fn check_network(state: &AppState, requested: &NetworkIdentifier) -> Result<(), (StatusCode, Json<MeshError>)> {
    if requested == &state.network {
        Ok(())
    } else {
        Err(fail(unsupported_network()))
    }
}

/// The router: every endpoint of the Data API, reading the node at `node_url`.
pub fn router(node_url: &str, network: &str) -> Router {
    let state = AppState {
        node: Arc::new(Node::new(node_url)),
        network: NetworkIdentifier { blockchain: BLOCKCHAIN.into(), network: network.into() },
    };
    Router::new()
        .route("/network/list", post(network_list))
        .route("/network/options", post(network_options))
        .route("/network/status", post(network_status))
        .route("/block", post(block))
        .route("/block/transaction", post(block_transaction))
        .route("/account/balance", post(account_balance))
        .route("/mempool", post(mempool))
        .route("/mempool/transaction", post(mempool_transaction))
        .with_state(state)
}

async fn network_list(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "network_identifiers": [state.network] }))
}

async fn network_options(State(state): State<AppState>, Json(req): Json<NetworkRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let status = state.node.status().await.map_err(|e| node_failure(e, unavailable()))?;
    Ok(Json(json!({
        "version": {
            "rosetta_version": ROSETTA_VERSION,
            "node_version": status.version,
            "middleware_version": env!("CARGO_PKG_VERSION"),
        },
        "allow": {
            "operation_statuses": [{ "status": SUCCESS, "successful": true }],
            "operation_types": map::operation_types(),
            "errors": all_errors(),
            "historical_balance_lookup": false,
            "call_methods": [],
            "balance_exemptions": [],
            "mempool_coins": false,
        },
    })))
}

async fn network_status(State(state): State<AppState>, Json(req): Json<NetworkRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let node = &state.node;
    let status = node.status().await.map_err(|e| node_failure(e, unavailable()))?;
    let current = node.header(status.height).await.map_err(|e| node_failure(e, unavailable()))?;
    let genesis = node.header(0).await.map_err(|e| node_failure(e, unavailable()))?;
    let mut sync = json!({ "current_index": status.height, "synced": !status.is_syncing });
    if let Some(target) = status.sync_target_height {
        sync["target_index"] = json!(target.max(status.height));
    }
    Ok(Json(json!({
        "current_block_identifier": { "index": current.height, "hash": current.hash },
        "current_block_timestamp": current.timestamp,
        "genesis_block_identifier": { "index": 0, "hash": genesis.hash },
        "sync_status": sync,
        "peers": [],
    })))
}

/// The block a partial identifier names: by height, by hash, or the current one. When both are
/// given they must name the same block.
async fn fetch_block(node: &Node, id: &PartialBlockIdentifier) -> Result<crate::types::Block, (StatusCode, Json<MeshError>)> {
    let height = match (id.index, &id.hash) {
        (Some(index), _) => index,
        (None, Some(hash)) => {
            let b = node.block_by_hash(hash).await.map_err(|e| node_failure(e, block_not_found()))?;
            if b.height != 0 {
                return map::block(&b).map_err(map_failure);
            }
            0
        }
        (None, None) => node.status().await.map_err(|e| node_failure(e, unavailable()))?.height,
    };
    let block = if height == 0 {
        let header = node.header(0).await.map_err(|e| node_failure(e, block_not_found()))?;
        let genesis = node.genesis().await.map_err(|e| node_failure(e, unavailable()))?;
        map::genesis_block(&header, &genesis)
    } else {
        let b = node.block_at(height).await.map_err(|e| node_failure(e, block_not_found()))?;
        map::block(&b).map_err(map_failure)?
    };
    if let Some(hash) = &id.hash {
        if &block.block_identifier.hash != hash {
            return Err(fail(block_not_found()));
        }
    }
    Ok(block)
}

async fn block(State(state): State<AppState>, Json(req): Json<BlockRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let block = fetch_block(&state.node, &req.block_identifier).await?;
    Ok(Json(json!({ "block": block })))
}

async fn block_transaction(State(state): State<AppState>, Json(req): Json<BlockTransactionRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let id = PartialBlockIdentifier {
        index: Some(req.block_identifier.index),
        hash: Some(req.block_identifier.hash.clone()),
    };
    let block = fetch_block(&state.node, &id).await?;
    let tx = block
        .transactions
        .into_iter()
        .find(|t| t.transaction_identifier == req.transaction_identifier)
        .ok_or_else(|| fail(transaction_not_found()))?;
    Ok(Json(json!({ "transaction": tx })))
}

/// A balance as of the block the node's state is at. Asked for another block, it says so rather
/// than answer for the wrong one — this node keeps no past states.
async fn account_balance(State(state): State<AppState>, Json(req): Json<AccountBalanceRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    if req.account_identifier.sub_account.is_some() {
        return Err(fail(invalid_address()));
    }
    let node = &state.node;
    let balance = node
        .balance(&req.account_identifier.address)
        .await
        .map_err(|e| node_failure(e, invalid_address()))?;
    // The node applies a block's state a moment before it stores the block itself; the header
    // for the state's height can lag it by that moment.
    let mut header = None;
    for _ in 0..20 {
        match node.header(balance.state_height).await {
            Ok(h) => {
                header = Some(h);
                break;
            }
            Err(NodeError::NotFound) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(e) => return Err(node_failure(e, block_not_found())),
        }
    }
    let header = header.ok_or_else(|| fail(block_not_found()))?;
    if let Some(requested) = &req.block_identifier {
        let other_height = requested.index.is_some_and(|i| i != header.height);
        let other_hash = requested.hash.as_ref().is_some_and(|h| h != &header.hash);
        if other_height || other_hash {
            return Err(fail(no_history()));
        }
    }
    Ok(Json(json!({
        "block_identifier": { "index": header.height, "hash": header.hash },
        "balances": [{ "value": balance.nano.to_string(), "currency": Currency::hlx() }],
    })))
}

async fn mempool(State(state): State<AppState>, Json(req): Json<NetworkRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let hashes = state.node.mempool().await.map_err(|e| node_failure(e, unavailable()))?;
    let ids: Vec<Value> = hashes.into_iter().map(|hash| json!({ "hash": hash })).collect();
    Ok(Json(json!({ "transaction_identifiers": ids })))
}

async fn mempool_transaction(State(state): State<AppState>, Json(req): Json<MempoolTransactionRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let pending = state
        .node
        .pending(&req.transaction_identifier.hash)
        .await
        .map_err(|e| node_failure(e, not_in_mempool()))?;
    let tx = map::pending(&pending).map_err(map_failure)?;
    Ok(Json(json!({ "transaction": tx })))
}
