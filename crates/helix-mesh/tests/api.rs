//! The Mesh endpoints against a stand-in node: the answers `mesh-cli check:data` does not
//! exercise — errors, balances at another block, the mempool.

use axum::{extract::Path, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde_json::{json, Value};

const NET: &str = r#"{"blockchain":"Helix","network":"testnet"}"#;

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// A node at height 7 holding one account and one pending transfer.
async fn stand_in_node() -> String {
    let header = |Path(h): Path<u64>| async move {
        Json(json!({ "hash": format!("h{h}"), "height": h, "timestamp": 1_790_000_000_000u64 + h, "prev_hash": format!("h{}", h.saturating_sub(1)) }))
    };
    let account = |Path(a): Path<String>| async move {
        match a.as_str() {
            "hlxKnown" => (StatusCode::OK, Json(json!({ "balance_nano": "12345678901234567", "state_height": 7 }))).into_response(),
            "hlxFresh" => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found", "state_height": 7 }))).into_response(),
            _ => (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid address format" }))).into_response(),
        }
    };
    let tx = |Path(h): Path<String>| async move {
        if h == "p1" {
            (StatusCode::OK, Json(json!({ "hash": "p1", "status": "pending", "from": "hlxKnown", "to": "hlxFresh",
                "amount_nano": "5", "fee_nano": "3", "tx_type": "Transfer", "nonce": 0 }))).into_response()
        } else {
            (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response()
        }
    };
    let app = Router::new()
        .route("/status", get(|| async { Json(json!({ "version": "0.20.1", "height": 7, "best_hash": "h7", "is_syncing": false })) }))
        .route("/blocks/height/:h/header", get(header))
        .route("/accounts/:a", get(account))
        .route("/mempool/transactions", get(|| async { Json(json!({ "transactions": ["p1"] })) }))
        .route("/transactions/:h", get(tx));
    serve(app).await
}

async fn mesh() -> String {
    serve(helix_mesh::router(&stand_in_node().await, "testnet")).await
}

async fn post(base: &str, path: &str, body: String) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.json().await.unwrap())
}

#[tokio::test]
async fn another_network_is_refused() {
    let base = mesh().await;
    let (status, body) = post(&base, "/network/status", r#"{"network_identifier":{"blockchain":"Helix","network":"mainnet"}}"#.into()).await;
    assert_eq!((status, &body["code"]), (500, &json!(2)), "{body}");
}

#[tokio::test]
async fn options_announce_every_type_and_no_history() {
    let base = mesh().await;
    let (status, body) = post(&base, "/network/options", format!(r#"{{"network_identifier":{NET}}}"#)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["allow"]["historical_balance_lookup"], false);
    assert_eq!(body["allow"]["balance_exemptions"], json!([]));
    let types = body["allow"]["operation_types"].as_array().unwrap();
    assert_eq!(types.len(), helix_mesh::map::operation_types().len());
    assert_eq!(body["version"]["node_version"], "0.20.1");
}

#[tokio::test]
async fn a_balance_comes_with_its_block_and_is_exact() {
    let base = mesh().await;
    let (status, body) = post(&base, "/account/balance", format!(r#"{{"network_identifier":{NET},"account_identifier":{{"address":"hlxKnown"}}}}"#)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["block_identifier"], json!({ "index": 7, "hash": "h7" }));
    assert_eq!(body["balances"][0]["value"], "12345678901234567");
    assert_eq!(body["balances"][0]["currency"], json!({ "symbol": "HLX", "decimals": 9 }));
}

#[tokio::test]
async fn an_address_without_history_has_a_balance_of_zero() {
    let base = mesh().await;
    let (status, body) = post(&base, "/account/balance", format!(r#"{{"network_identifier":{NET},"account_identifier":{{"address":"hlxFresh"}}}}"#)).await;
    assert_eq!((status, &body["balances"][0]["value"]), (200, &json!("0")), "{body}");
}

#[tokio::test]
async fn a_balance_at_another_block_is_refused_not_answered_for_the_wrong_one() {
    let base = mesh().await;
    let (status, body) = post(&base, "/account/balance", format!(r#"{{"network_identifier":{NET},"account_identifier":{{"address":"hlxKnown"}},"block_identifier":{{"index":3}}}}"#)).await;
    assert_eq!((status, &body["code"]), (500, &json!(7)), "{body}");
    let (status, _) = post(&base, "/account/balance", format!(r#"{{"network_identifier":{NET},"account_identifier":{{"address":"hlxKnown"}},"block_identifier":{{"index":7}}}}"#)).await;
    assert_eq!(status, 200, "the current block itself is fine");
}

#[tokio::test]
async fn an_invalid_address_is_named_as_such() {
    let base = mesh().await;
    let (status, body) = post(&base, "/account/balance", format!(r#"{{"network_identifier":{NET},"account_identifier":{{"address":"nonsense"}}}}"#)).await;
    assert_eq!((status, &body["code"]), (500, &json!(6)), "{body}");
}

#[tokio::test]
async fn the_mempool_lists_and_shows_a_pending_transfer() {
    let base = mesh().await;
    let (_, list) = post(&base, "/mempool", format!(r#"{{"network_identifier":{NET}}}"#)).await;
    assert_eq!(list["transaction_identifiers"], json!([{ "hash": "p1" }]));
    let (status, body) = post(&base, "/mempool/transaction", format!(r#"{{"network_identifier":{NET},"transaction_identifier":{{"hash":"p1"}}}}"#)).await;
    assert_eq!(status, 200, "{body}");
    let ops: Vec<(String, String, String)> = body["transaction"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| (o["type"].as_str().unwrap().into(), o["account"]["address"].as_str().unwrap().into(), o["amount"]["value"].as_str().unwrap().into()))
        .collect();
    let s = |a: &str, b: &str, c: &str| (a.to_string(), b.to_string(), c.to_string());
    assert_eq!(ops, vec![s("FEE", "hlxKnown", "-3"), s("TRANSFER", "hlxKnown", "-5"), s("TRANSFER", "hlxFresh", "5")]);
    assert!(body["transaction"]["operations"][0].get("status").is_none(), "nothing has happened yet");
    let (status, body) = post(&base, "/mempool/transaction", format!(r#"{{"network_identifier":{NET},"transaction_identifier":{{"hash":"gone"}}}}"#)).await;
    assert_eq!((status, &body["code"]), (500, &json!(9)), "{body}");
}
