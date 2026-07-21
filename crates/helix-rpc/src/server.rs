use std::net::SocketAddr;
use std::sync::{atomic::Ordering, Arc};

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use helix_core::{Block, Transaction};
use helix_crypto::{Address, Hash};
use helix_executor::state::ChainState;
use helix_mempool::Mempool;
use helix_p2p::P2PCommand;
use helix_storage::{db::HelixDb, BlockStore};
use serde_json::{json, Value};
use tokio::sync::{mpsc, RwLock};
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::rate_limit::{rate_limit_middleware, RateLimiter};
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
    /// This node's own libp2p listen port — surfaced via `GET /status` so a joining peer
    /// can derive a dialable seed address without needing mDNS. See `NodeStatus::p2p_port`.
    pub p2p_port: u16,
    /// This node's announced public P2P multiaddr (`HELIX_P2P_PUBLIC_ADDR`), if any — surfaced
    /// via `GET /status` so a joining peer dials this directly instead of deriving a raw-TCP
    /// address from `p2p_port` that, for a tunnelled node, is unreachable. See
    /// `NodeStatus::p2p_public_addr`.
    pub p2p_public_addr: Option<String>,
    /// Used to gossip an RPC-submitted transaction to the rest of the network. Without
    /// this, a transaction submitted to a node that never proposes a block itself (any
    /// non-genesis validator, or a pure full node) would sit in that node's local
    /// mempool forever — found by actually running a multi-node local testnet, not by
    /// any single-node unit/integration test, since a lone node is always its own
    /// proposer and never needed this path.
    pub p2p_command_tx: mpsc::Sender<P2PCommand>,
}

/// Explicit request-body cap for `POST /transactions`, well above any plausible signed
/// transaction, chosen to bound memory pressure from oversized payloads on this
/// publicly reachable endpoint rather than relying on axum's implicit 2 MB default.
const TX_SUBMIT_BODY_LIMIT_BYTES: usize = 64 * 1024;

pub async fn start_rpc_server(state: AppState, bind: SocketAddr) {
    // Burst of 30 requests per IP, sustained refill of 10/sec — generous enough
    // for normal wallet/explorer use, tight enough to blunt a single-source flood
    // against the publicly reachable RPC endpoint.
    let limiter = Arc::new(RateLimiter::new(30.0, 10.0));

    let app = Router::new()
        .route("/", get(root))
        .route("/logo.png", get(logo))
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
        .route("/accounts/:address/delegations", get(get_account_delegations))
        .route("/accounts/:address/storage/:key_hex", get(get_contract_storage))
        .route("/validators/:address/pool", get(get_validator_pool))
        .route(
            "/accounts/:address/transactions",
            get(get_account_transactions),
        )
        .route("/names/:name", get(resolve_name))
        .route("/governance/params", get(get_governance_params))
        .route("/governance/proposals", get(get_governance_proposals))
        .route("/governance/proposals/:id", get(get_governance_proposal))
        .route("/mempool", get(get_mempool_info))
        .route("/genesis", get(get_genesis))
        .route("/sync/blocks", get(get_sync_blocks))
        .route(
            "/transactions",
            post(submit_transaction).layer(DefaultBodyLimit::max(TX_SUBMIT_BODY_LIMIT_BYTES)),
        )
        .route("/transactions/:hash", get(get_transaction_status))
        .layer(CorsLayer::permissive())
        // Compress responses for any client that asks (`Accept-Encoding: gzip`). The chain's
        // bulk payloads are dominated by ML-DSA signatures and public keys, which serde renders
        // as JSON arrays of decimal numbers — `[56, 87, 212, …]`. A 3,309-byte signature becomes
        // ~13,000 characters that way, so an *empty* block costs ~38 KB on the wire. Measured
        // 2026-07-21: 200 empty blocks = 7.6 MB uncompressed, 2.0 MB gzipped — a 3.8x cut on
        // every historical sync, which is the single largest thing this node serves.
        //
        // Until now that saving only existed for nodes sitting behind a CDN that compresses for
        // them (ours does; a self-hosted one does not), which is exactly backwards: the operator
        // without a proxy is the one paying for their own bandwidth. Doing it here makes it
        // uniform. gzip is HTTP content negotiation, so a client that does not ask, or an older
        // one that cannot decode it, still gets plain JSON.
        .layer(CompressionLayer::new())
        .layer(middleware::from_fn_with_state(limiter, rate_limit_middleware))
        .with_state(state);

    info!("RPC server listening on http://{}", bind);
    let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

/// The explorer, compiled into the binary. Not read from disk and not fetched from anywhere:
/// a node must work on a machine that cannot reach a CDN, and shipping it as a file would mean
/// a node whose explorer silently disappears if the file isn't deployed alongside it.
const EXPLORER_HTML: &str = include_str!("explorer.html");

/// The Helix logo (512×512 PNG), compiled into the binary and served at a stable URL.
///
/// The explorer embeds its own copy as a base64 data URI so it stays self-contained; this route
/// exists for the opposite need — a real, fetchable URL (`https://<node>/logo.png`) that a
/// listing directory, a chat, or anyone asking "where's the logo?" can point at directly.
const LOGO_PNG: &[u8] = include_bytes!("logo.png");

/// `GET /logo.png` — the project logo at a stable, shareable URL. Cached for a day since the
/// bytes only ever change with a new binary.
async fn logo() -> impl IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/png"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        LOGO_PNG,
    )
}

/// `GET /` answers a browser with the explorer and everything else with the API index.
///
/// Same URL, because it is the one people are handed: `helix.silvra.net` in a browser used to
/// return raw JSON, which is a poor way to meet a project. Content negotiation rather than a
/// separate `/explorer` path keeps the link that gets shared and the link that gets curl'd the
/// same one. Anything that doesn't ask for HTML — curl, a wallet, another node — is unaffected.
async fn root(headers: axum::http::HeaderMap) -> axum::response::Response {
    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"));
    if wants_html {
        return (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            EXPLORER_HTML,
        )
            .into_response();
    }
    api_index().into_response()
}

fn api_index() -> Json<Value> {
    Json(json!({
        "name": "Helix Node",
        "version": env!("CARGO_PKG_VERSION"),
        "token": "HLX",
        "crypto": "ML-DSA-65 — NIST FIPS 204",
        "endpoints": [
            "GET  /logo.png",
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
            "GET  /accounts/{address}/delegations",
            "GET  /accounts/{address}/storage/{key_hex}",
            "GET  /validators/{address}/pool",
            "GET  /names/{name}",
            "GET  /governance/params",
            "GET  /governance/proposals",
            "GET  /governance/proposals/{id}",
            "GET  /mempool",
            "GET  /genesis",
            "POST /transactions",
            "GET  /transactions/{hash}"
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
        state_hash: chain.state_hash().to_hex(),
        p2p_port: state.p2p_port,
        p2p_public_addr: state.p2p_public_addr.clone(),
        // Read off the mempool, which the node keeps in lockstep with the consensus engine
        // (`publish_base_fee`) — the same value admission here charges, so a client that prices
        // against it gets a transaction this node will actually accept.
        base_fee_per_byte: mempool.base_fee_per_byte(),
    })
}

async fn get_latest_block(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    let height = store.latest_height();
    match store.get_block_by_height(height) {
        Ok(block) => (StatusCode::OK, Json(json!(block_response(&block, &store)))),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}

async fn get_block_by_height(
    State(state): State<AppState>,
    Path(n): Path<u64>,
) -> impl IntoResponse {
    let store = state.store.read().await;
    match store.get_block_by_height(n) {
        Ok(block) => (StatusCode::OK, Json(json!(block_response(&block, &store)))),
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
        Ok(block) => (StatusCode::OK, Json(json!(block_response(&block, &store)))),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}

/// Batch block listing for clients (explorers, wallets).
///
/// `GET /blocks/range?from=<height>&count=<n>` — returns up to 500 blocks in the
/// `BlockResponse` display view, starting at `from`.
///
/// Not the sync path, despite what this comment claimed until 2026-07-17: a node bootstrapping
/// from a peer uses `/sync/blocks`, which carries the full `Block` including signatures. This
/// view drops those, so no node could ever have synced from it.
async fn get_blocks_range(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, u64>>,
) -> impl IntoResponse {
    let from = params.get("from").copied().unwrap_or(0);
    let count = params.get("count").copied().unwrap_or(100).min(500);
    let store = state.store.read().await;
    let mut blocks = Vec::with_capacity(count as usize);
    for h in from..from.saturating_add(count) {
        match store.get_block_by_height(h) {
            Ok(block) => blocks.push(block_response(&block, &store)),
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
/// `GET /genesis` — everything a node bootstrapping fresh against this one as its
/// `sync_peer` needs to reconstruct an identical genesis, instead of self-signing its own
/// (see `HelixNode::new`'s doc comment on why that produces a distinct, incompatible
/// height-0 block per node).
///
/// The genesis block identifies *who* got the bootstrap stake; everything else here is a
/// per-deployment choice that cannot be re-derived from the block: `personhood_authorities`,
/// the governance params, the bootstrap `validator_stake_nano`, any `extra_validators`, and any
/// liquid `allocations`. Each is served from chain state rather than from this node's own
/// compile-time defaults, which describe how a *new* chain would launch on today's build — not
/// how this one launched. Together they let a joining node rebuild the exact same initial
/// `ChainState` this chain started from, whatever build it happens to be running.
async fn get_genesis(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().await;
    let block = match store.get_block_by_height(0) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))),
    };
    drop(store);
    let cs = state.chain_state.read().await;
    let personhood_authorities: Vec<String> =
        cs.personhood_authorities.iter().map(|pk| pk.to_hex()).collect();
    // Additional validators pre-staked at genesis beyond this block's own `validator` — see
    // `ChainState::genesis_extra_validators`'s doc comment for why this can't just be
    // re-derived from current stakers().
    let extra_validators: Vec<serde_json::Value> = cs
        .genesis_extra_validators
        .iter()
        .map(|(addr, stake)| json!({ "address": addr.as_str(), "stake_nano": stake }))
        .collect();
    let allocations: Vec<serde_json::Value> = cs
        .genesis_allocations
        .iter()
        .map(|(addr, balance)| json!({ "address": addr.as_str(), "balance_nano": balance }))
        .collect();
    // Rebuilt from the very fields served above, through the same function a joining node uses —
    // so this hash answers "what should your reconstruction come out as", not "what does my
    // chain look like now" (which has moved on since height 0).
    let genesis_state_hash = helix_executor::genesis::rebuild_genesis_state(
        block.header.validator.clone(),
        cs.personhood_authorities.clone(),
        cs.genesis_extra_validators.clone(),
        cs.genesis_validator_stake,
        cs.genesis_allocations.clone(),
        cs.governance_params.clone(),
    )
    .state_hash()
    .to_hex();
    // This node's *current* governance_params, not necessarily its genesis-time ones — if a
    // proposal changed a param since genesis, a node adopting this as its starting value will
    // (mis)apply the current value retroactively from height 0, rather than the true original
    // value up to the proposal's real execution height. Narrower and strictly better than the
    // alternative this replaces (a hardcoded compile-time default that can silently drift from
    // what this chain's real genesis actually used, as MIN_VALIDATOR_STAKE already has here),
    // but not a full historical-params replay — accept the gap rather than build that.
    let governance_params = cs.governance_params.clone();
    (
        StatusCode::OK,
        Json(json!({
            "block": block,
            "personhood_authorities": personhood_authorities,
            "governance_params": governance_params,
            "extra_validators": extra_validators,
            // What the genesis validator was actually staked at height 0. Served for the same
            // reason as `extra_validators`, and it must come from chain state rather than
            // `VALIDATOR_GENESIS_STAKE_HLX`: the constant is a default for *new* chains and may
            // since have been retuned, whereas this chain's genesis is fixed forever.
            "validator_stake_nano": cs.genesis_validator_stake,
            // Liquid genesis balances (faucet, treasury, …). Served for the same reason as the
            // two above: `GENESIS_PREFUND` is a compile-time default for new chains, not a
            // description of what this one handed out at height 0.
            "allocations": allocations,
            // The hash of the genesis state these fields rebuild to, so a joining node can check
            // that its own reconstruction landed on the same ledger rather than assuming it did.
            //
            // Transmitting the inputs is not enough on its own: a node whose binary disagrees
            // about anything the fields *don't* carry — `TOTAL_SUPPLY_HLX`, or any field added
            // to genesis after that node was built — silently constructs a different chain and
            // reports it as fact. That is not hypothetical: the published v1.4.0 binary, syncing
            // this chain on 2026-07-16, produced a ledger with 800,000 HLX that does not exist,
            // without erroring. This turns that into a refusal to start.
            "state_hash": genesis_state_hash,
        })),
    )
}

async fn get_sync_blocks(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, u64>>,
) -> impl IntoResponse {
    let from = params.get("from").copied().unwrap_or(1);
    let count = params.get("count").copied().unwrap_or(200).min(200);
    let store = state.store.read().await;
    let mut blocks: Vec<Block> = Vec::with_capacity(count as usize);
    for h in from..from.saturating_add(count) {
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
                unbonding_source: acc.unbonding_source.clone(),
                nonce: acc.nonce,
                has_code: acc.code.is_some(),
                jailed_until: chain.jailed_until.get(&address).copied(),
                missed_blocks: chain.missed_blocks.get(&address).copied(),
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

const DEFAULT_PROPOSALS_LIMIT: u64 = 50;
const MAX_PROPOSALS_LIMIT: u64 = 200;

/// `GET /governance/proposals?limit=<n>&offset=<n>` — proposals are never pruned
/// (they're the permanent governance record, like blocks), so without pagination
/// this response grows unbounded as proposals accumulate over the chain's
/// lifetime. Same `limit`/`offset` convention as `/accounts/{address}/transactions`.
async fn get_governance_proposals(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, u64>>,
) -> Json<Value> {
    let limit = params.get("limit").copied().unwrap_or(DEFAULT_PROPOSALS_LIMIT).min(MAX_PROPOSALS_LIMIT);
    let offset = params.get("offset").copied().unwrap_or(0);

    let chain = state.chain_state.read().await;
    let mut proposals: Vec<GovernanceProposalResponse> =
        chain.proposals.values().map(GovernanceProposalResponse::from).collect();
    proposals.sort_by_key(|p| p.id);
    let page: Vec<GovernanceProposalResponse> =
        proposals.into_iter().skip(offset as usize).take(limit as usize).collect();
    Json(json!({ "proposals": page }))
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

/// `GET /validators/:address/pool` — a validator's delegation pool: how much delegated
/// stake it currently has backing it, at what commission rate, plus its own self-stake and
/// the effective total (self + delegated) that actually counts for validator-set eligibility
/// and BFT voting weight (see `ChainState::effective_stake`). `has_pool: false` with the
/// rest zeroed means nobody has ever delegated to this address — not an error, since any
/// address can in principle receive a delegation once it self-stakes.
async fn get_validator_pool(
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
    let self_staked = chain.get(&address).map(|a| a.staked).unwrap_or(0);
    let pool = chain.validator_pools.get(&address_str);
    (
        StatusCode::OK,
        Json(json!({
            "address": address_str,
            "has_pool": pool.is_some(),
            "self_staked_hlx": self_staked as f64 / 1_000_000_000.0,
            "delegated_stake_hlx": pool.map(|p| p.total_delegated_stake).unwrap_or(0) as f64 / 1_000_000_000.0,
            "effective_stake_hlx": chain.effective_stake(&address) as f64 / 1_000_000_000.0,
            "total_shares": pool.map(|p| p.total_shares).unwrap_or(0),
            "commission_bps": pool.map(|p| p.commission_bps),
        })),
    )
}

/// `GET /accounts/:address/delegations` — every validator this address currently has an
/// active delegation to, with the current redeemable HLX value of each (principal plus any
/// auto-compounded rewards, minus any slashing since delegating — see
/// `ChainState::delegation_value`). Scans `validator_pools` (bounded by validator count, not
/// delegator count) rather than requiring a reverse index, since looking up "my own
/// delegations" is an infrequent, operator-facing query, not a consensus-critical hot path.
async fn get_account_delegations(
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
    let delegations: Vec<Value> = chain
        .delegator_shares
        .iter()
        .filter_map(|(validator_addr, delegators)| {
            let shares = *delegators.get(&address_str)?;
            let validator = Address::from_str(validator_addr).ok()?;
            let value = chain.delegation_value(&validator, &address)?;
            Some(json!({
                "validator": validator_addr,
                "shares": shares,
                "value_hlx": value as f64 / 1_000_000_000.0,
            }))
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "address": address_str, "delegations": delegations })),
    )
}

/// `GET /accounts/:address/storage/:key_hex` — reads one key out of a deployed contract's
/// own storage (see `ChainState.contract_storage`'s doc comment). Debugging/exploration
/// endpoint, not something a wallet needs — a contract's storage schema is entirely up to
/// its own bytecode, so this just exposes the raw key/value bytes hex-encoded rather than
/// trying to guess a structure. The key is hex rather than a literal path segment because
/// storage keys are arbitrary bytes (up to `helix_vm::MAX_KEY_LEN`), not necessarily valid
/// UTF-8 or URL-safe text.
async fn get_contract_storage(
    State(state): State<AppState>,
    Path((address_str, key_hex)): Path<(String, String)>,
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
    let key = match hex::decode(&key_hex) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "key must be hex-encoded" })),
            )
        }
    };
    let chain = state.chain_state.read().await;
    match chain.contract_storage_read(&address, &key) {
        Some(value) => (
            StatusCode::OK,
            Json(json!({
                "address": address_str,
                "key_hex": key_hex,
                "value_hex": hex::encode(&value),
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no contract storage entry for this address/key" })),
        ),
    }
}

/// Builds the RPC-facing history entry for one transaction from the block it's in.
fn tx_history_entry(
    block: &helix_core::Block,
    tx: &Transaction,
    outcome: (String, Option<String>),
) -> TxHistoryEntry {
    let (status, error) = outcome;
    TxHistoryEntry {
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
        status,
        error,
    }
}

/// What the stored receipt says happened to `tx_hash`, as (status, error).
///
/// A missing receipt is `unknown`, never success: the block may predate receipt storage, or
/// the write may have failed. Both endpoints that report an outcome go through here so they
/// cannot drift into telling callers different stories about the same transaction.
fn receipt_outcome(store: &HelixDb, tx_hash: &Hash) -> (String, Option<String>) {
    match store.get_receipt(tx_hash) {
        Ok(Some(r)) if r.success => ("applied".to_string(), None),
        Ok(Some(r)) => ("failed".to_string(), r.error),
        Ok(None) | Err(_) => ("unknown".to_string(), None),
    }
}

/// The one way a block reaches a client. Routes every transaction's status through
/// `receipt_outcome`, the same helper the single-transaction and history endpoints use, so a
/// block listing and a transaction detail view can never disagree about whether a transfer
/// went through.
fn block_response(block: &Block, store: &HelixDb) -> BlockResponse {
    BlockResponse::new(block, |tx_hash| receipt_outcome(store, tx_hash))
}

/// Extracts every transaction touching `address` (as sender or recipient) from `blocks`,
/// newest first. Pure and store-agnostic so it can be unit-tested without a `HelixDb`.
/// Full-scan reference implementation — kept for tests as a ground truth to check the
/// indexed lookup in `get_account_transactions` against; not used on the live request path.
#[cfg(test)]
fn extract_tx_history(blocks: &[helix_core::Block], address: &str) -> Vec<TxHistoryEntry> {
    let mut history = Vec::new();
    for block in blocks {
        for tx in &block.transactions {
            let is_sender = tx.from.to_string() == address;
            let is_recipient = tx.to.as_ref().map(|a| a.to_string()).as_deref() == Some(address);
            if is_sender || is_recipient {
                // No store here by design (this is the pure ground truth for the indexed
                // lookup), so no receipt either — the outcome is not what it checks.
                history.push(tx_history_entry(block, tx, ("unknown".to_string(), None)));
            }
        }
    }
    history.reverse();
    history
}

const DEFAULT_ACCOUNT_TX_LIMIT: u64 = 50;
const MAX_ACCOUNT_TX_LIMIT: u64 = 200;

/// `GET /accounts/:address/transactions?limit=<n>&offset=<m>` — newest first.
///
/// Backed by `HelixDb::address_transactions`, an index maintained incrementally on
/// every `put_block` rather than a scan of every block in the chain: cost is
/// proportional to how many transactions actually touched this address, not to
/// chain height, and stays bounded per request via `limit`/`offset`.
async fn get_account_transactions(
    State(state): State<AppState>,
    Path(address_str): Path<String>,
    Query(params): Query<std::collections::HashMap<String, u64>>,
) -> impl IntoResponse {
    if Address::from_str(&address_str).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid address format: {}", address_str) })),
        );
    }
    let limit = params.get("limit").copied().unwrap_or(DEFAULT_ACCOUNT_TX_LIMIT).min(MAX_ACCOUNT_TX_LIMIT);
    let offset = params.get("offset").copied().unwrap_or(0);

    let store = state.store.read().await;
    let refs = match store.address_transactions(&address_str, limit as usize, offset as usize) {
        Ok(refs) => refs,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("failed to read transaction index: {e}") })),
            );
        }
    };

    let mut history = Vec::with_capacity(refs.len());
    for (height, tx_index) in refs {
        let Ok(block) = store.get_block_by_height(height) else { continue };
        let Some(tx) = block.transactions.get(tx_index as usize) else { continue };
        let outcome = receipt_outcome(&store, &tx.hash());
        history.push(tx_history_entry(&block, tx, outcome));
    }

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
    let (recovery_key, can_pay) = {
        let chain = state.chain_state.read().await;
        (
            chain.recovery_key(&tx.from).cloned(),
            helix_executor::can_pay_fee(&chain, &tx),
        )
    };
    // The pool ranks on a fee the sender only claims, and cannot check the claim itself — it has
    // no chain state. Asking here, where the state is already open for the recovery key, is what
    // stops an empty wallet from outbidding paying users for pool space with a fee it could never
    // pay. See `helix_executor::can_pay_fee`.
    if !can_pay {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "sender cannot pay the declared fee" })),
        );
    }
    let mut mempool = state.mempool.write().await;
    let result = mempool.add_with_recovery_key(tx.clone(), recovery_key.as_ref());
    drop(mempool);
    match result {
        Ok(()) => {
            // Gossip to the rest of the network — this node may never propose a block
            // itself (see AppState::p2p_command_tx's doc comment). Best-effort: a full
            // outbound command channel shouldn't fail the client's submission, since the
            // tx is already safely in our own mempool either way.
            let _ = state.p2p_command_tx.try_send(P2PCommand::BroadcastTransaction(tx));
            (
                StatusCode::ACCEPTED,
                Json(json!({ "tx_hash": tx_hash, "status": "accepted" })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

/// `GET /transactions/:hash` — was routed to by `hlx tx status` from the very first
/// version of the CLI, but this endpoint never actually existed server-side (only
/// `POST /transactions` was registered), so every call 404'd with an empty body,
/// which the CLI's JSON parser then failed on with an opaque "EOF while parsing a
/// value" instead of a clear error. Found while using `hlx tx status` for real during
/// a multi-node testnet session — nobody had actually called it since it was written.
async fn get_transaction_status(
    State(state): State<AppState>,
    Path(hash_hex): Path<String>,
) -> impl IntoResponse {
    let tx_hash = match Hash::from_hex(&hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid hash format" })),
            )
        }
    };

    let store = state.store.read().await;
    let location = store.tx_location(&tx_hash);
    match location {
        Ok(Some((height, tx_index))) => {
            let Ok(block) = store.get_block_by_height(height) else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "indexed block missing from store" })),
                );
            };
            let Some(tx) = block.transactions.get(tx_index as usize) else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "indexed tx position out of range" })),
                );
            };
            // Being in a block is not the same as having worked: the executor rejects
            // transactions for a bad nonce, insufficient balance or a zero amount, and they are
            // committed and charged the fee exactly like any other. This answered `confirmed`
            // to all of them, which is the difference between "your money arrived" and "it
            // didn't". The receipt is the only thing that knows.
            let mut entry = json!(tx_history_entry(&block, tx, receipt_outcome(&store, &tx_hash)));
            // The burn split is in the receipt anyway, and it is the only place a caller can
            // see what the fee actually did — how much EIP-1559 burned, how much the validator
            // earned.
            if let Ok(Some(r)) = store.get_receipt(&tx_hash) {
                entry["fee_burned_hlx"] = json!(r.fee_burned as f64 / 1_000_000_000.0);
                entry["fee_to_validator_hlx"] = json!(r.fee_to_validator as f64 / 1_000_000_000.0);
            }
            (StatusCode::OK, Json(entry))
        }
        Ok(None) => {
            drop(store);
            if state.mempool.read().await.contains(&tx_hash) {
                (
                    StatusCode::OK,
                    Json(json!({ "hash": hash_hex, "status": "pending" })),
                )
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": format!("transaction {} not found", hash_hex) })),
                )
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to read transaction index: {e}") })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_core::{Block, BlockHeader, CryptoVersion, TxType};
    use helix_crypto::{Hash, KeyPair, PublicKey, Signature};
    use helix_executor::receipt::Receipt;

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
                base_fee_per_byte: helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
                last_commit: vec![],
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

    fn fresh_app_state() -> (AppState, std::path::PathBuf) {
        // Unique by construction, per process and within it. The path used to end in a wall-clock
        // nanosecond, which is not a uniqueness guarantee: the eighteen tests on this fixture run
        // as parallel threads of one process, and any two that read the same nanosecond get the
        // same file — redb refuses the second with "Database already open. Cannot acquire lock."
        // Rare enough to pass locally every time and still fail in CI, where the clock is coarser.
        // A counter cannot tie; the pid keeps concurrent `cargo test` runs apart.
        static NEXT_DB: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "helix-rpc-account-tx-test-{}-{}.redb",
            std::process::id(),
            NEXT_DB.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        let store = HelixDb::open(&path).unwrap();
        let (p2p_command_tx, _p2p_command_rx) = mpsc::channel(8);
        let state = AppState {
            store: Arc::new(RwLock::new(store)),
            mempool: Arc::new(RwLock::new(Mempool::new())),
            chain_state: Arc::new(RwLock::new(ChainState::new(0))),
            node_address: String::new(),
            peer_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            p2p_port: 0,
            p2p_public_addr: None,
            p2p_command_tx,
        };
        (state, path)
    }

    /// The attack this gate closes, proven end to end at the door it comes through.
    ///
    /// A wallet with no funds signs a valid transfer and simply *claims* an enormous fee. The
    /// pool cannot check that claim — it holds no chain state — but it ranks and evicts by it, so
    /// the claim alone used to buy pool space ahead of paying users, a front-of-block slot, and
    /// then cost nothing at execution, because an empty account has nothing to take.
    #[tokio::test]
    async fn an_unfunded_fee_claim_is_refused_at_the_door() {
        let (state, path) = fresh_app_state();
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let to = Address::from_public_key(&KeyPair::generate().public);

        // Sender's balance is never set: this account has nothing, and claims u64::MAX/2.
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from,
            to: Some(to),
            amount: 1_000,
            fee: u64::MAX / 2,
            nonce: 0,
            data: vec![],
            crypto_version: CryptoVersion::MlDsa,
            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();

        let response = submit_transaction(State(state.clone()), Json(tx)).await.into_response();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "a fee the sender cannot pay must not buy a place in the pool"
        );
        assert!(
            state.mempool.read().await.is_empty(),
            "the pool must stay empty — an admitted claim is what evicts honest transactions"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The counterweight: the gate must not turn away someone who can actually pay.
    #[tokio::test]
    async fn a_funded_sender_is_still_admitted() {
        let (state, path) = fresh_app_state();
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let to = Address::from_public_key(&KeyPair::generate().public);
        state
            .chain_state
            .write()
            .await
            .update_account(&from, |acc| acc.balance = 1_000_000);

        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from,
            to: Some(to),
            amount: 1_000,
            fee: 10_000,
            nonce: 0,
            data: vec![],
            crypto_version: CryptoVersion::MlDsa,
            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();

        let response = submit_transaction(State(state.clone()), Json(tx)).await.into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(!state.mempool.read().await.is_empty());

        let _ = std::fs::remove_file(&path);
    }

    /// Regression test: `GET /transactions/:hash` didn't exist server-side at all
    /// before this fix — `hlx tx status` 404'd against every hash, confirmed or not.
    #[tokio::test]
    async fn get_transaction_status_reports_applied_for_a_transaction_that_executed() {
        let (state, path) = fresh_app_state();
        let alice = addr(1);
        let bob = addr(2);
        let committed = tx(&alice, &bob, 10, 0);
        let hash = committed.hash();
        {
            let mut store = state.store.write().await;
            store.put_block(block(5, &alice, vec![committed])).unwrap();
            store.put_receipts(&[Receipt::success(hash, 40, 60)]).unwrap();
        }

        let response = get_transaction_status(State(state), Path(hash.to_hex()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "applied");
        assert_eq!(parsed["block_height"], 5);

        let _ = std::fs::remove_file(&path);
    }

    /// The bug this whole path exists for. A zero-amount transfer is committed, charged, and
    /// rejected by the executor — and reported as `confirmed` on the live chain, indistinguishable
    /// from one that moved money. The reason has to reach the caller, not just the node's log.
    #[tokio::test]
    async fn a_transaction_the_executor_rejected_reports_failed_and_says_why() {
        let (state, path) = fresh_app_state();
        let alice = addr(1);
        let rejected = tx(&alice, &addr(2), 0, 0);
        let hash = rejected.hash();
        {
            let mut store = state.store.write().await;
            store.put_block(block(5, &alice, vec![rejected])).unwrap();
            store
                .put_receipts(&[Receipt::failure(
                    hash,
                    "transfer amount must be greater than zero",
                    1_082,
                    0,
                )])
                .unwrap();
        }

        let response = get_transaction_status(State(state), Path(hash.to_hex()))
            .await
            .into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "failed", "a rejected tx must not read as a successful one");
        assert_eq!(parsed["error"], "transfer amount must be greater than zero");

        let _ = std::fs::remove_file(&path);
    }

    /// The block view used to be a plain `From<Block>` with no store access, so every
    /// transaction in a block listing looked alike — a rejected transfer sat next to a settled
    /// one with nothing to tell them apart, while the detail view for that same transaction
    /// said `failed`. One block, all three outcomes, checked per transaction.
    #[tokio::test]
    async fn a_block_reports_each_transactions_outcome_not_just_that_it_was_included() {
        let (state, path) = fresh_app_state();
        let alice = addr(1);
        let settled = tx(&alice, &addr(2), 1_000, 0);
        let rejected = tx(&alice, &addr(2), 0, 1);
        let ancient = tx(&alice, &addr(3), 500, 2);
        let (settled_hash, rejected_hash, ancient_hash) =
            (settled.hash(), rejected.hash(), ancient.hash());
        {
            let mut store = state.store.write().await;
            store
                .put_block(block(7, &alice, vec![settled, rejected, ancient]))
                .unwrap();
            // No receipt for `ancient` — it stands in for a block committed before receipts existed.
            store
                .put_receipts(&[
                    Receipt::success(settled_hash, 40, 60),
                    Receipt::failure(
                        rejected_hash,
                        "transfer amount must be greater than zero",
                        1_082,
                        0,
                    ),
                ])
                .unwrap();
        }

        let response = get_block_by_height(State(state), Path(7)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();

        let txs = parsed["transactions"].as_array().unwrap();
        assert_eq!(txs.len(), 3);

        let by_hash = |h: &Hash| {
            txs.iter()
                .find(|t| t["hash"] == h.to_hex())
                .unwrap_or_else(|| panic!("tx {} missing from block response", h.to_hex()))
        };
        assert_eq!(by_hash(&settled_hash)["status"], "applied");
        assert!(by_hash(&settled_hash)["error"].is_null());
        assert_eq!(
            by_hash(&rejected_hash)["status"],
            "failed",
            "a rejected tx must not look like a settled one in a block listing"
        );
        assert_eq!(
            by_hash(&rejected_hash)["error"],
            "transfer amount must be greater than zero"
        );
        assert_eq!(
            by_hash(&ancient_hash)["status"],
            "unknown",
            "no receipt means unknown — never a silent success"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Blocks committed before receipts were stored have none, and the honest answer is that
    /// this node doesn't know — the one thing it must never do is default to success.
    #[tokio::test]
    async fn a_transaction_without_a_stored_receipt_reports_unknown_not_success() {
        let (state, path) = fresh_app_state();
        let alice = addr(1);
        let legacy = tx(&alice, &addr(2), 10, 0);
        let hash = legacy.hash();
        state.store.write().await.put_block(block(5, &alice, vec![legacy])).unwrap();

        let response = get_transaction_status(State(state), Path(hash.to_hex()))
            .await
            .into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "unknown");
        assert!(parsed["error"].is_null(), "no receipt means no claim either way");

        let _ = std::fs::remove_file(&path);
    }

    /// Valid hex of the wrong length used to panic the worker task here, reachable from the
    /// public internet: `Hash::from_hex` fed a 2-byte decode into a 32-byte `copy_from_slice`.
    #[tokio::test]
    async fn a_malformed_hash_is_rejected_instead_of_panicking_the_worker() {
        let (state, path) = fresh_app_state();
        let response = get_transaction_status(State(state), Path("abcd".to_string()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn get_transaction_status_reports_pending_for_a_mempool_only_transaction() {
        let (state, path) = fresh_app_state();
        let keypair = KeyPair::generate();
        let alice = Address::from_public_key(&keypair.public);
        // Clearing the flat min_fee is not enough: a real ML-DSA-signed transfer is ~5.4 KB and
        // owes ~5410 nano at the base-fee floor alone.
        let mut pending = Transaction { fee: 10_000, public_key: keypair.public.clone(), ..tx(&alice, &addr(2), 1, 0) };
        pending.signature = keypair.sign(pending.signing_hash().as_bytes()).unwrap();
        let hash = pending.hash();
        state.mempool.write().await.add(pending).unwrap();

        let response = get_transaction_status(State(state), Path(hash.to_hex()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "pending");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn get_transaction_status_404s_for_an_unknown_hash() {
        let (state, path) = fresh_app_state();
        let unknown = tx(&addr(9), &addr(8), 1, 0).hash();

        let response = get_transaction_status(State(state), Path(unknown.to_hex()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_file(&path);
    }

    /// The indexed lookup behind `get_account_transactions` must return exactly the
    /// same transactions (content and order) as the full-chain-scan reference
    /// implementation (`extract_tx_history`) it replaced.
    #[tokio::test]
    async fn get_account_transactions_matches_full_scan_reference() {
        let (state, path) = fresh_app_state();
        let alice = addr(1);
        let bob = addr(2);
        let carol = addr(3);

        let blocks = vec![
            block(0, &alice, vec![tx(&alice, &bob, 10, 0)]),
            block(1, &alice, vec![tx(&bob, &alice, 5, 0), tx(&carol, &bob, 1, 0)]),
            block(2, &alice, vec![tx(&alice, &carol, 2, 1)]),
        ];
        for b in &blocks {
            state.store.write().await.put_block(b.clone()).unwrap();
        }

        let expected = extract_tx_history(&blocks, alice.to_string().as_str());

        let response = get_account_transactions(
            State(state),
            Path(alice.to_string()),
            Query(std::collections::HashMap::new()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let got = parsed["transactions"].as_array().unwrap();

        assert_eq!(got.len(), expected.len());
        for (entry, want) in got.iter().zip(expected.iter()) {
            assert_eq!(entry["hash"], want.hash);
            assert_eq!(entry["block_height"], want.block_height);
            assert_eq!(entry["from"], want.from);
        }

        let _ = std::fs::remove_file(&path);
    }

    /// Where the bug was actually found: a wallet history. A rejected transfer sat in this list
    /// looking exactly like a payment that went through — same shape, same fields, no outcome
    /// anywhere. Fixing only `/transactions/{hash}` would have left the list, which is what
    /// Spark and the explorer render, still saying nothing.
    #[tokio::test]
    async fn account_history_marks_a_failed_transaction_instead_of_listing_it_like_any_other() {
        let (state, path) = fresh_app_state();
        let alice = addr(1);
        let bob = addr(2);

        let good = tx(&alice, &bob, 10, 0);
        let bad = tx(&alice, &bob, 0, 1);
        let (good_hash, bad_hash) = (good.hash(), bad.hash());
        {
            let mut store = state.store.write().await;
            store.put_block(block(1, &alice, vec![good, bad])).unwrap();
            store
                .put_receipts(&[
                    Receipt::success(good_hash, 40, 60),
                    Receipt::failure(bad_hash, "transfer amount must be greater than zero", 40, 0),
                ])
                .unwrap();
        }

        let response = get_account_transactions(
            State(state),
            Path(alice.to_string()),
            Query(std::collections::HashMap::new()),
        )
        .await
        .into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let got = parsed["transactions"].as_array().unwrap();

        let by_hash = |h: &Hash| {
            got.iter()
                .find(|e| e["hash"] == h.to_hex())
                .unwrap_or_else(|| panic!("history is missing {}", h.to_hex()))
                .clone()
        };
        assert_eq!(by_hash(&good_hash)["status"], "applied");
        assert_eq!(by_hash(&bad_hash)["status"], "failed");
        assert_eq!(by_hash(&bad_hash)["error"], "transfer amount must be greater than zero");
        assert!(
            by_hash(&good_hash)["error"].is_null(),
            "a successful tx carries no error"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn get_account_transactions_honors_limit_query_param() {
        let (state, path) = fresh_app_state();
        let alice = addr(1);
        let bob = addr(2);

        for h in 0..5u64 {
            state
                .store
                .write()
                .await
                .put_block(block(h, &alice, vec![tx(&alice, &bob, 1, h)]))
                .unwrap();
        }

        let mut params = std::collections::HashMap::new();
        params.insert("limit".to_string(), 2u64);
        let response = get_account_transactions(State(state), Path(alice.to_string()), Query(params))
            .await
            .into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let got = parsed["transactions"].as_array().unwrap();

        assert_eq!(got.len(), 2);
        // Newest first: heights 4 then 3.
        assert_eq!(got[0]["block_height"], 4);
        assert_eq!(got[1]["block_height"], 3);

        let _ = std::fs::remove_file(&path);
    }

    /// Exercises the exact route + `DefaultBodyLimit` wiring used for `POST /transactions`
    /// in `start_rpc_server`, without needing a full `AppState` (redb needs a filesystem
    /// path, which isn't worth setting up just to test body-size enforcement).
    fn body_limited_echo_router() -> Router {
        Router::new().route(
            "/transactions",
            post(|body: axum::body::Bytes| async move { body.len().to_string() })
                .layer(DefaultBodyLimit::max(TX_SUBMIT_BODY_LIMIT_BYTES)),
        )
    }

    #[tokio::test]
    async fn submit_transaction_route_accepts_body_within_limit() {
        use tower::ServiceExt;

        let body = vec![b'a'; TX_SUBMIT_BODY_LIMIT_BYTES];
        let response = body_limited_echo_router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/transactions")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn submit_transaction_route_rejects_body_over_limit() {
        use tower::ServiceExt;

        let body = vec![b'a'; TX_SUBMIT_BODY_LIMIT_BYTES + 1];
        let response = body_limited_echo_router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/transactions")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Regression test for a bug found by actually running a multi-node local testnet
    /// (not by any single-node test): `submit_transaction` used to only add the tx to
    /// this node's own local mempool, with no P2P broadcast — fine for a lone node
    /// (always its own proposer) but silently swallows every transaction submitted to
    /// any node that isn't the current block producer on a real multi-validator network.
    #[tokio::test]
    async fn submit_transaction_broadcasts_to_the_p2p_network() {
        // fresh_app_state()'s own receiver is dropped at the end of that function, so
        // this test needs its own channel to actually observe what gets sent.
        let (state, path) = fresh_app_state();
        let (p2p_command_tx, mut p2p_command_rx) = mpsc::channel(8);
        let state = AppState { p2p_command_tx, ..state };

        // Mempool::add() verifies the signature before admitting a tx (see its own doc
        // comment on why that ordering matters) — the addr()/tx() helpers used elsewhere
        // in this file build unsigned fixtures, which is fine for tests that only ever
        // touch storage/state directly, but not here.
        let keypair = KeyPair::generate();
        let alice = Address::from_public_key(&keypair.public);
        let bob = addr(2);
        // Alice must be able to afford the fee she declares, or submission refuses her before the
        // pool ever sees the tx — a claimed fee no longer buys admission (`can_pay_fee`). Same
        // kind of lesson as the base-fee note below: the fixture has to satisfy every rule the
        // real door applies, not just the one under test.
        state.chain_state.write().await.update_account(&alice, |acc| acc.balance = 1_000_000);
        let mut submitted = Transaction {
            // Clears the base fee for its own size, not merely Mempool's flat min_fee — that
            // distinction is what this comment used to get wrong, along with the rest of the suite.
            fee: 10_000,
            public_key: keypair.public.clone(),
            ..tx(&alice, &bob, 1, 0)
        };
        submitted.signature = keypair.sign(submitted.signing_hash().as_bytes()).unwrap();
        let expected_hash = submitted.hash();

        let response = submit_transaction(State(state), Json(submitted)).await.into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        match p2p_command_rx.try_recv() {
            Ok(P2PCommand::BroadcastTransaction(broadcast)) => {
                assert_eq!(broadcast.hash(), expected_hash);
            }
            other => panic!("expected a BroadcastTransaction command, got {other:?}"),
        }

        let _ = std::fs::remove_file(&path);
    }

    fn fresh_test_state() -> AppState {
        let path = std::env::temp_dir().join(format!(
            "helix-rpc-test-store-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let store = HelixDb::open(&path).unwrap();
        let (p2p_command_tx, _p2p_command_rx) = mpsc::channel(8);
        AppState {
            store: Arc::new(RwLock::new(store)),
            mempool: Arc::new(RwLock::new(Mempool::new())),
            chain_state: Arc::new(RwLock::new(ChainState::new(0))),
            node_address: "test-node".to_string(),
            peer_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            p2p_port: 0,
            p2p_public_addr: None,
            p2p_command_tx,
        }
    }

    /// `/genesis` must report the stake *this chain* launched with, taken from chain state —
    /// not `VALIDATOR_GENESIS_STAKE_HLX`, which only describes how a new chain would launch on
    /// today's build. A joining node believes this number, so serving the constant would hand
    /// it a genesis the chain never had the moment the constant is ever retuned.
    #[tokio::test]
    async fn get_genesis_reports_the_chains_own_validator_stake_not_the_binarys_default() {
        let state = fresh_test_state();
        let validator = addr(7);
        state.store.write().await.put_block(block(0, &validator, vec![])).unwrap();

        // Deliberately unlike the compile-time default — a chain launched under another build.
        let launched_with = 330_000 * helix_executor::genesis::NANO_PER_HLX;
        assert_ne!(
            launched_with,
            helix_executor::genesis::VALIDATOR_GENESIS_STAKE_HLX
                * helix_executor::genesis::NANO_PER_HLX
        );
        state.chain_state.write().await.genesis_validator_stake = launched_with;

        let response = get_genesis(State(state)).await.into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["validator_stake_nano"].as_u64(), Some(launched_with));
    }

    /// Liquid genesis balances must reach a joining node over the wire. `GENESIS_PREFUND` is
    /// empty on every build today, so a node that never hears about a treasury silently rebuilds
    /// a genesis without it — and then disagrees about the balance of a real, funded account.
    #[tokio::test]
    async fn get_genesis_reports_the_chains_liquid_allocations() {
        let state = fresh_test_state();
        let validator = addr(7);
        let treasury = addr(8);
        state.store.write().await.put_block(block(0, &validator, vec![])).unwrap();

        let allocated = 100_000 * helix_executor::genesis::NANO_PER_HLX;
        state.chain_state.write().await.genesis_allocations = vec![(treasury.clone(), allocated)];

        let response = get_genesis(State(state)).await.into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let allocations = json["allocations"].as_array().unwrap();
        assert_eq!(allocations.len(), 1);
        assert_eq!(allocations[0]["address"].as_str(), Some(treasury.as_str()));
        assert_eq!(allocations[0]["balance_nano"].as_u64(), Some(allocated));
    }

    /// A browser gets the explorer. Nothing else does — every existing API client, wallet and
    /// node reads `/` expecting the JSON index, and quietly handing them HTML would break them
    /// all at once.
    #[tokio::test]
    async fn root_serves_the_explorer_to_browsers_and_json_to_everything_else() {
        use axum::http::{header, HeaderMap, HeaderValue};

        let mut browser = HeaderMap::new();
        browser.insert(
            header::ACCEPT,
            HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        );
        let response = root(browser).await;
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<title>Helix — the post-quantum blockchain</title>"));
        assert!(
            html.contains("test token"),
            "the hub is the first thing most people see — it has to say honestly what this chain is"
        );

        // curl, wallets, other nodes: no Accept header at all, or a JSON one.
        for headers in [HeaderMap::new(), {
            let mut h = HeaderMap::new();
            h.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
            h
        }] {
            let response = root(headers).await;
            let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).expect("must stay JSON");
            assert_eq!(json["token"], "HLX");
        }
    }

    /// `/logo.png` serves the real image bytes with an image content type — the whole point is a
    /// fetchable URL a listing or a chat can embed, so a broken type or an empty body defeats it.
    #[tokio::test]
    async fn logo_serves_the_png_bytes_with_an_image_content_type() {
        use axum::http::header;

        let response = logo().await.into_response();
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(!body.is_empty(), "the logo must not be empty");
        // PNG magic number — proves we're serving an actual image, not a stray text file.
        assert_eq!(&body[..8], b"\x89PNG\r\n\x1a\n", "must be a real PNG");
    }

    /// The explorer must not reach for anything off the node. A node has to work where there is
    /// no CDN to reach, and an explorer that fetches a font from someone else's server is both a
    /// dependency and a tracker.
    #[test]
    fn the_explorer_makes_no_external_requests() {
        for needle in ["//fonts.", "cdn.", "https://unpkg", "https://cdn", "<script src=", "@import"] {
            assert!(
                !EXPLORER_HTML.contains(needle),
                "explorer must be self-contained, found {needle:?}"
            );
        }
    }

    /// The hash must describe the *genesis* state, not the node's current one. Serving the
    /// latter would make every joining node reject the chain the moment a block was produced —
    /// and worse, would have looked correct in a test against a chain still at height 0.
    #[tokio::test]
    async fn get_genesis_reports_the_genesis_state_hash_not_todays() {
        let state = fresh_test_state();
        let validator = addr(7);
        state.store.write().await.put_block(block(0, &validator, vec![])).unwrap();
        {
            let mut cs = state.chain_state.write().await;
            cs.genesis_validator_stake = 100_000 * helix_executor::genesis::NANO_PER_HLX;
            // Chain state as it looks *now*: someone has since been paid, so it no longer
            // resembles genesis.
            cs.update_account(&addr(9), |a| a.balance = 12_345);
        }
        let live_hash = state.chain_state.read().await.state_hash().to_hex();

        let response = get_genesis(State(state)).await.into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let served = json["state_hash"].as_str().unwrap();

        assert_ne!(served, live_hash, "must not serve the chain's current state hash");

        let expected = helix_executor::genesis::rebuild_genesis_state(
            validator,
            vec![],
            vec![],
            100_000 * helix_executor::genesis::NANO_PER_HLX,
            vec![],
            Default::default(),
        )
        .state_hash()
        .to_hex();
        assert_eq!(served, expected, "must serve what a joining node should rebuild to");
    }

    /// `from` near `u64::MAX` used to be added directly to `count`, which overflows.
    /// Regression test for CTO backlog item 14.
    #[tokio::test]
    async fn get_blocks_range_does_not_overflow_near_u64_max() {
        let state = fresh_test_state();
        let mut params = std::collections::HashMap::new();
        params.insert("from".to_string(), u64::MAX - 1);
        params.insert("count".to_string(), 10);

        let response = get_blocks_range(State(state), Query(params)).await;
        assert_eq!(response.into_response().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_sync_blocks_does_not_overflow_near_u64_max() {
        let state = fresh_test_state();
        let mut params = std::collections::HashMap::new();
        params.insert("from".to_string(), u64::MAX - 1);
        params.insert("count".to_string(), 10);

        let response = get_sync_blocks(State(state), Query(params)).await;
        assert_eq!(response.into_response().status(), StatusCode::OK);
    }

    fn dummy_proposal(id: u64) -> helix_executor::governance::GovernanceProposal {
        helix_executor::governance::GovernanceProposal {
            id,
            proposer: addr(1).to_string(),
            param: helix_executor::governance::GovernanceParam::FuelPerFeeUnit,
            new_value: 2,
            created_at_height: 0,
            voters: Default::default(),
            yes_stake: 0,
            total_staked_at_creation: 0,
            executed: false,
        }
    }

    /// Proposals are never pruned (permanent governance record), so the endpoint
    /// must paginate instead of returning the whole set. Regression test for CTO
    /// backlog item 40.
    #[tokio::test]
    async fn get_governance_proposals_paginates_and_defaults() {
        let state = fresh_test_state();
        {
            let mut chain = state.chain_state.write().await;
            for id in 0..5 {
                chain.set_proposal(dummy_proposal(id));
            }
        }

        let response = get_governance_proposals(State(state.clone()), Query(Default::default())).await;
        let body: Value = serde_json::from_str(
            &String::from_utf8(
                axum::body::to_bytes(response.into_response().into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(body["proposals"].as_array().unwrap().len(), 5);

        let mut params = std::collections::HashMap::new();
        params.insert("limit".to_string(), 2u64);
        params.insert("offset".to_string(), 3u64);
        let response = get_governance_proposals(State(state), Query(params)).await;
        let body: Value = serde_json::from_str(
            &String::from_utf8(
                axum::body::to_bytes(response.into_response().into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let page = body["proposals"].as_array().unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0]["id"], 3);
        assert_eq!(page[1]["id"], 4);
    }

    #[tokio::test]
    async fn get_contract_storage_finds_a_written_key() {
        let (state, path) = fresh_app_state();
        let contract = addr(1);
        {
            let mut chain = state.chain_state.write().await;
            chain.contract_storage_write(&contract, b"greeting".to_vec(), b"hello".to_vec());
        }

        let response = get_contract_storage(
            State(state),
            Path((contract.to_string(), hex::encode(b"greeting"))),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["value_hex"], hex::encode(b"hello"));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn get_contract_storage_404s_for_an_unwritten_key() {
        let (state, path) = fresh_app_state();
        let contract = addr(1);

        let response = get_contract_storage(
            State(state),
            Path((contract.to_string(), hex::encode(b"never-written"))),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn get_contract_storage_rejects_non_hex_key() {
        let (state, path) = fresh_app_state();
        let contract = addr(1);

        let response = get_contract_storage(State(state), Path((contract.to_string(), "not-hex!!".to_string())))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_file(&path);
    }
}
