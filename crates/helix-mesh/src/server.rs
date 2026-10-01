//! The Mesh endpoints: the Data API (network, block, account, mempool) and the Construction API.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde_json::{json, Value};

use crate::construction::{self, ML_DSA_65};
use crate::map::{self, MapError, SUCCESS};
use crate::node::{Node, NodeError, Submitted};
use crate::types::{
    AccountBalanceRequest, BlockRequest, BlockTransactionRequest, ConstructionCombineRequest,
    ConstructionDeriveRequest, ConstructionMetadataRequest, ConstructionParseRequest, ConstructionPayloadsRequest,
    ConstructionPreprocessRequest, Currency, MempoolTransactionRequest, MeshError, NetworkIdentifier, NetworkRequest,
    PartialBlockIdentifier, SignedTransactionRequest,
};

/// The blockchain name in every network identifier.
pub const BLOCKCHAIN: &str = "Helix";
/// The Mesh specification version this service implements.
pub const ROSETTA_VERSION: &str = "1.4.13";

#[derive(Clone)]
struct AppState {
    /// `None` offline: only what needs no node is served.
    node: Option<Arc<Node>>,
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
fn not_a_transfer(why: String) -> MeshError {
    let mut e = error(11, "Only a transfer of HLX between two accounts can be constructed", false);
    e.description = Some(why);
    e
}
fn refused(why: String) -> MeshError {
    let mut e = error(12, "The node refused the transaction", false);
    e.description = Some(why);
    e
}
fn offline() -> MeshError {
    error(13, "This service runs offline and does not ask a node", false)
}
fn invalid_transaction(why: String) -> MeshError {
    let mut e = error(14, "The transaction, key or signature is not valid", false);
    e.description = Some(why);
    e
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
        not_a_transfer(String::new()),
        refused(String::new()),
        offline(),
        invalid_transaction(String::new()),
    ]
    .into_iter()
    .map(|mut e| {
        if e.description.as_deref() == Some("") {
            e.description = None;
        }
        e
    })
    .collect()
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

/// The node, when this service has one.
fn online(state: &AppState) -> Result<&Node, (StatusCode, Json<MeshError>)> {
    state.node.as_deref().ok_or_else(|| fail(offline()))
}

/// The router: every endpoint, reading the node at `node_url`.
pub fn router(node_url: &str, network: &str) -> Router {
    routes(AppState {
        node: Some(Arc::new(Node::new(node_url))),
        network: NetworkIdentifier { blockchain: BLOCKCHAIN.into(), network: network.into() },
    })
}

/// The same endpoints with no node behind them, for the machine that signs: `/network/list`,
/// `/network/options` and the construction steps that need no live data (derive, preprocess,
/// payloads, combine, parse, hash). Everything else answers error 13.
pub fn offline_router(network: &str) -> Router {
    routes(AppState { node: None, network: NetworkIdentifier { blockchain: BLOCKCHAIN.into(), network: network.into() } })
}

fn routes(state: AppState) -> Router {
    Router::new()
        .route("/network/list", post(network_list))
        .route("/network/options", post(network_options))
        .route("/network/status", post(network_status))
        .route("/block", post(block))
        .route("/block/transaction", post(block_transaction))
        .route("/account/balance", post(account_balance))
        .route("/mempool", post(mempool))
        .route("/mempool/transaction", post(mempool_transaction))
        .route("/construction/derive", post(construction_derive))
        .route("/construction/preprocess", post(construction_preprocess))
        .route("/construction/metadata", post(construction_metadata))
        .route("/construction/payloads", post(construction_payloads))
        .route("/construction/combine", post(construction_combine))
        .route("/construction/parse", post(construction_parse))
        .route("/construction/hash", post(construction_hash))
        .route("/construction/submit", post(construction_submit))
        .with_state(state)
}

async fn network_list(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "network_identifiers": [state.network] }))
}

async fn network_options(State(state): State<AppState>, Json(req): Json<NetworkRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let node_version = match &state.node {
        Some(node) => node.status().await.map_err(|e| node_failure(e, unavailable()))?.version,
        None => "offline".to_string(),
    };
    Ok(Json(json!({
        "version": {
            "rosetta_version": ROSETTA_VERSION,
            "node_version": node_version,
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
    let node = online(&state)?;
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
    let block = fetch_block(online(&state)?, &req.block_identifier).await?;
    Ok(Json(json!({ "block": block })))
}

async fn block_transaction(State(state): State<AppState>, Json(req): Json<BlockTransactionRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let id = PartialBlockIdentifier {
        index: Some(req.block_identifier.index),
        hash: Some(req.block_identifier.hash.clone()),
    };
    let block = fetch_block(online(&state)?, &id).await?;
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
    let node = online(&state)?;
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
    let hashes = online(&state)?.mempool().await.map_err(|e| node_failure(e, unavailable()))?;
    let ids: Vec<Value> = hashes.into_iter().map(|hash| json!({ "hash": hash })).collect();
    Ok(Json(json!({ "transaction_identifiers": ids })))
}

async fn mempool_transaction(State(state): State<AppState>, Json(req): Json<MempoolTransactionRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let pending = online(&state)?
        .pending(&req.transaction_identifier.hash)
        .await
        .map_err(|e| node_failure(e, not_in_mempool()))?;
    let tx = map::pending(&pending).map_err(map_failure)?;
    Ok(Json(json!({ "transaction": tx })))
}

// ---------- construction ----------

fn account(address: &str) -> Value {
    json!({ "address": address })
}

/// The account a public key controls: its address is a hash of the key.
async fn construction_derive(State(state): State<AppState>, Json(req): Json<ConstructionDeriveRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let key = construction::public_key(&req.public_key).map_err(|e| fail(invalid_transaction(e)))?;
    let address = helix_crypto::Address::from_public_key(&key).to_string();
    Ok(Json(json!({ "account_identifier": account(&address), "address": address })))
}

/// What `/construction/metadata` needs: the sender (for its nonce), the memo (it changes the size,
/// so the fee), and a nonce the caller chose, if any — to build several transactions from one
/// account before the first is in a block. The sender's public key is required: an account's first
/// transaction carries it.
async fn construction_preprocess(State(state): State<AppState>, Json(req): Json<ConstructionPreprocessRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let intent = construction::intent(&req.operations).map_err(|e| fail(not_a_transfer(e)))?;
    let memo = construction::memo(req.metadata.as_ref()).map_err(|e| fail(not_a_transfer(e)))?;
    let mut options = json!({ "from": intent.from.to_string() });
    if let Some(memo) = memo {
        options["memo"] = json!(memo);
    }
    match req.metadata.as_ref().and_then(|m| m.get("nonce")) {
        None | Some(Value::Null) => {}
        Some(n) => {
            let n = n.as_u64().ok_or_else(|| fail(not_a_transfer("the nonce must be a whole number".into())))?;
            options["nonce"] = json!(n);
        }
    }
    Ok(Json(json!({ "options": options, "required_public_keys": [account(&intent.from.to_string())] })))
}

/// The live data: the sender's next nonce (unless the caller chose one), the chain to sign for,
/// and the fee — by the wallets' rule, on the signed size, refused above 1 HLX.
async fn construction_metadata(State(state): State<AppState>, Json(req): Json<ConstructionMetadataRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let node = online(&state)?;
    let options = req.options.unwrap_or(Value::Null);
    let from = options["from"].as_str().ok_or_else(|| fail(not_a_transfer("options.from is missing — pass on what /construction/preprocess returned".into())))?;
    let memo = construction::memo(Some(&options)).map_err(|e| fail(not_a_transfer(e)))?;
    let nonce = match options["nonce"].as_u64() {
        Some(n) => n,
        None => node.nonce(from).await.map_err(|e| node_failure(e, invalid_address()))?,
    };
    let status = node.status().await.map_err(|e| node_failure(e, unavailable()))?;
    let chain_id = node.header(0).await.map_err(|e| node_failure(e, unavailable()))?.hash;
    let fee = construction::fee(status.base_fee_per_byte, nonce, memo.as_deref()).map_err(|e| fail(refused(e)))?;
    let mut metadata = json!({ "nonce": nonce, "chain_id": chain_id, "fee_nano": fee.to_string() });
    if let Some(memo) = memo {
        metadata["memo"] = json!(memo);
    }
    Ok(Json(json!({
        "metadata": metadata,
        "suggested_fee": [{ "value": fee.to_string(), "currency": Currency::hlx() }],
    })))
}

/// The unsigned transaction and what to sign.
async fn construction_payloads(State(state): State<AppState>, Json(req): Json<ConstructionPayloadsRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let intent = construction::intent(&req.operations).map_err(|e| fail(not_a_transfer(e)))?;
    let metadata = req.metadata.unwrap_or(Value::Null);
    let bad = |why: &str| fail(not_a_transfer(format!("metadata.{why} — pass on what /construction/metadata returned")));
    let nonce = metadata["nonce"].as_u64().ok_or_else(|| bad("nonce is missing"))?;
    let chain_id = metadata["chain_id"]
        .as_str()
        .and_then(|h| helix_crypto::Hash::from_hex(h).ok())
        .ok_or_else(|| bad("chain_id is missing or not a block hash"))?;
    let fee: u64 = metadata["fee_nano"].as_str().and_then(|f| f.parse().ok()).ok_or_else(|| bad("fee_nano is missing"))?;
    if fee > helix_core::fee::WALLET_AUTO_FEE_CEILING_NANO {
        return Err(fail(not_a_transfer("a fee above 1 HLX is not built — no wallet pays one on its own".into())));
    }
    let memo = construction::memo(Some(&metadata)).map_err(|e| fail(not_a_transfer(e)))?;
    let key = req
        .public_keys
        .unwrap_or_default()
        .iter()
        .filter_map(|k| construction::public_key(k).ok())
        .find(|k| helix_crypto::Address::from_public_key(k) == intent.from)
        .ok_or_else(|| {
            fail(invalid_transaction(format!(
                "no {ML_DSA_65} public key for the sender {} in public_keys — /construction/preprocess asks for it",
                intent.from
            )))
        })?;
    let tx = construction::unsigned(&intent, nonce, fee, chain_id, key, memo.as_deref());
    let from = intent.from.to_string();
    Ok(Json(json!({
        "unsigned_transaction": construction::encode(&tx),
        "payloads": [{
            "address": from,
            "account_identifier": account(&from),
            "hex_bytes": construction::signing_payload(&tx),
            "signature_type": ML_DSA_65,
        }],
    })))
}

async fn construction_combine(State(state): State<AppState>, Json(req): Json<ConstructionCombineRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let tx = construction::decode(&req.unsigned_transaction).map_err(|e| fail(invalid_transaction(e)))?;
    let [signature] = req.signatures.as_slice() else {
        return Err(fail(invalid_transaction(format!("a transfer takes one signature, not {}", req.signatures.len()))));
    };
    let signed = construction::combine(tx, signature).map_err(|e| fail(invalid_transaction(e)))?;
    Ok(Json(json!({ "signed_transaction": construction::encode(&signed) })))
}

async fn construction_parse(State(state): State<AppState>, Json(req): Json<ConstructionParseRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let tx = if req.signed {
        construction::signed(&req.transaction)
    } else {
        construction::decode(&req.transaction)
    }
    .map_err(|e| fail(invalid_transaction(e)))?;
    let operations = construction::operations(&tx).map_err(|e| fail(not_a_transfer(e)))?;
    let signers: Vec<String> = if req.signed { vec![tx.from.to_string()] } else { Vec::new() };
    Ok(Json(json!({
        "operations": operations,
        "account_identifier_signers": signers.iter().map(|a| account(a)).collect::<Vec<_>>(),
        "signers": signers,
        "metadata": construction::parse_metadata(&tx),
    })))
}

async fn construction_hash(State(state): State<AppState>, Json(req): Json<SignedTransactionRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let tx = construction::signed(&req.signed_transaction).map_err(|e| fail(invalid_transaction(e)))?;
    Ok(Json(json!({ "transaction_identifier": { "hash": tx.hash().to_hex() } })))
}

/// Hand the signed transaction to the node. The same one again is not an error (a submission
/// whose answer was lost is retried); anything the node refuses is error 12 with its reason.
async fn construction_submit(State(state): State<AppState>, Json(req): Json<SignedTransactionRequest>) -> Reply {
    check_network(&state, &req.network_identifier)?;
    let node = online(&state)?;
    let tx = construction::signed(&req.signed_transaction).map_err(|e| fail(invalid_transaction(e)))?;
    match node.submit(&tx).await {
        Ok(Submitted) => Ok(Json(json!({ "transaction_identifier": { "hash": tx.hash().to_hex() } }))),
        Err(NodeError::Invalid(reason)) => Err(fail(refused(reason))),
        Err(e) => Err(node_failure(e, unavailable())),
    }
}
