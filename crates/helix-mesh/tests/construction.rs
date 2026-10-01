//! The Construction API over HTTP, against a stand-in node: the whole flow a Mesh client runs, a
//! signature made with this repository's ML-DSA-65, and what the node is handed at the end.

use std::sync::{Arc, Mutex};

use axum::{extract::Path, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use helix_crypto::{Address, KeyPair};
use serde_json::{json, Value};

const NET: &str = r#"{"blockchain":"Helix","network":"testnet"}"#;
const CHAIN: &str = "4dd50c2c53e0be07e09d9af72f537def70e646f5c6b6aaac8e99a5e51d34408f";

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// A node at height 7, base fee 2, every account on nonce 4. `/transactions` keeps what it was
/// handed and answers as the node does: accepted, already in the pool, or refused.
async fn stand_in_node(received: Arc<Mutex<Vec<Value>>>) -> String {
    let header = |Path(h): Path<u64>| async move {
        let hash = if h == 0 { CHAIN.to_string() } else { format!("h{h}") };
        Json(json!({ "hash": hash, "height": h, "timestamp": 1_790_000_000_000u64, "prev_hash": "h" }))
    };
    let account = |Path(_a): Path<String>| async move { Json(json!({ "balance_nano": "1", "nonce": 4, "state_height": 7 })) };
    let submit = move |Json(tx): Json<Value>| {
        let received = received.clone();
        async move {
            let parsed: helix_core::Transaction = serde_json::from_value(tx.clone()).unwrap();
            let mut seen = received.lock().unwrap();
            if parsed.amount == 666 {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Fee below the block base fee: got 1, need at least 9" }))).into_response();
            }
            if seen.contains(&tx) {
                let reason = format!("Transaction {} already in mempool", parsed.hash().to_hex());
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": reason }))).into_response();
            }
            seen.push(tx);
            (StatusCode::OK, Json(json!({ "tx_hash": parsed.hash().to_hex() }))).into_response()
        }
    };
    let app = Router::new()
        .route("/status", get(|| async { Json(json!({ "version": "0.20.2", "height": 7, "best_hash": "h7", "base_fee_per_byte": 2 })) }))
        .route("/blocks/height/:h/header", get(header))
        .route("/accounts/:a", get(account))
        .route("/transactions", post(submit));
    serve(app).await
}

async fn call(base: &str, path: &str, body: Value) -> (u16, Value) {
    let mut body = body;
    body["network_identifier"] = serde_json::from_str(NET).unwrap();
    let response = reqwest::Client::new().post(format!("{base}{path}")).json(&body).send().await.unwrap();
    (response.status().as_u16(), response.json().await.unwrap())
}

fn transfer_ops(from: &str, to: &str, amount: u64) -> Value {
    json!([
        { "operation_identifier": { "index": 0 }, "type": "TRANSFER", "account": { "address": from },
          "amount": { "value": format!("-{amount}"), "currency": { "symbol": "HLX", "decimals": 9 } } },
        { "operation_identifier": { "index": 1 }, "type": "TRANSFER", "account": { "address": to },
          "amount": { "value": amount.to_string(), "currency": { "symbol": "HLX", "decimals": 9 } } },
    ])
}

fn mesh_key(kp: &KeyPair) -> Value {
    json!({ "hex_bytes": hex::encode(kp.public.as_bytes()), "curve_type": "ml_dsa_65" })
}

/// Everything up to the signed transaction, as a Mesh client runs it; returns its blob.
async fn construct(base: &str, kp: &KeyPair, to: &str, amount: u64, memo: Option<&str>) -> (Value, String) {
    let (status, derived) = call(base, "/construction/derive", json!({ "public_key": mesh_key(kp) })).await;
    assert_eq!(status, 200, "{derived}");
    let from = derived["account_identifier"]["address"].as_str().unwrap().to_string();
    assert_eq!(from, Address::from_public_key(&kp.public).to_string());
    let ops = transfer_ops(&from, to, amount);
    let (status, pre) = call(base, "/construction/preprocess", json!({ "operations": ops, "metadata": { "memo": memo } })).await;
    assert_eq!(status, 200, "{pre}");
    assert_eq!(pre["required_public_keys"], json!([{ "address": from }]));
    let (status, meta) = call(base, "/construction/metadata", json!({ "options": pre["options"], "public_keys": [mesh_key(kp)] })).await;
    assert_eq!(status, 200, "{meta}");
    let (status, payloads) = call(base, "/construction/payloads",
        json!({ "operations": ops, "metadata": meta["metadata"], "public_keys": [mesh_key(kp)] })).await;
    assert_eq!(status, 200, "{payloads}");
    let payload = &payloads["payloads"][0];
    assert_eq!((&payload["signature_type"], &payload["account_identifier"]["address"]), (&json!("ml_dsa_65"), &json!(from)));
    let to_sign = hex::decode(payload["hex_bytes"].as_str().unwrap()).unwrap();
    assert_eq!(to_sign.len(), 32, "the signing hash");
    let signature = json!({
        "signing_payload": payload, "public_key": mesh_key(kp), "signature_type": "ml_dsa_65",
        "hex_bytes": hex::encode(kp.sign(&to_sign).unwrap().as_bytes()),
    });
    let unsigned = payloads["unsigned_transaction"].clone();
    let (status, parsed) = call(base, "/construction/parse", json!({ "signed": false, "transaction": unsigned })).await;
    assert_eq!(status, 200, "{parsed}");
    assert_eq!(parsed["operations"], ops, "an unsigned transaction parses back to its intent");
    assert_eq!(parsed["account_identifier_signers"], json!([]));
    let (status, combined) = call(base, "/construction/combine", json!({ "unsigned_transaction": unsigned, "signatures": [signature] })).await;
    assert_eq!(status, 200, "{combined}");
    (meta, combined["signed_transaction"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn a_transfer_is_built_signed_and_handed_to_the_node() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let base = serve(helix_mesh::router(&stand_in_node(received.clone()).await, "testnet")).await;
    let kp = KeyPair::generate();
    let to = Address::from_public_key(&KeyPair::generate().public).to_string();
    let (meta, signed) = construct(&base, &kp, &to, 2_010_000_001, Some("Einzahlung 42")).await;
    assert_eq!(meta["metadata"]["nonce"], 4, "the account's next nonce");
    assert_eq!(meta["metadata"]["chain_id"], CHAIN, "the genesis hash of the node's chain");
    let fee = helix_mesh::construction::fee(2, 4, Some("Einzahlung 42")).unwrap();
    assert_eq!(meta["metadata"]["fee_nano"], fee.to_string());
    assert_eq!(meta["suggested_fee"][0]["value"], fee.to_string());

    let (status, parsed) = call(&base, "/construction/parse", json!({ "signed": true, "transaction": signed })).await;
    assert_eq!(status, 200, "{parsed}");
    let from = Address::from_public_key(&kp.public).to_string();
    assert_eq!(parsed["account_identifier_signers"], json!([{ "address": from }]));
    assert_eq!(parsed["metadata"]["memo"], "Einzahlung 42");
    let (_, hashed) = call(&base, "/construction/hash", json!({ "signed_transaction": signed })).await;
    let (status, submitted) = call(&base, "/construction/submit", json!({ "signed_transaction": signed })).await;
    assert_eq!(status, 200, "{submitted}");
    assert_eq!(submitted["transaction_identifier"], hashed["transaction_identifier"]);

    let handed = received.lock().unwrap().clone();
    assert_eq!(handed.len(), 1);
    let tx: helix_core::Transaction = serde_json::from_value(handed[0].clone()).unwrap();
    tx.verify_signature().expect("the node gets a transaction whose signature verifies");
    assert_eq!((tx.amount, tx.fee, tx.nonce, tx.chain_id.to_hex()), (2_010_000_001, fee, 4, CHAIN.to_string()));
    assert_eq!(tx.hash().to_hex(), hashed["transaction_identifier"]["hash"].as_str().unwrap());
    assert_eq!(tx.memo(), Some("Einzahlung 42"));

    // A submission whose answer was lost is retried; the node says "already in mempool" — not an error.
    let (status, again) = call(&base, "/construction/submit", json!({ "signed_transaction": signed })).await;
    assert_eq!((status, &again["transaction_identifier"]), (200, &hashed["transaction_identifier"]));
}

#[tokio::test]
async fn what_the_node_refuses_is_error_12_with_its_reason() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let base = serve(helix_mesh::router(&stand_in_node(received).await, "testnet")).await;
    let kp = KeyPair::generate();
    let to = Address::from_public_key(&KeyPair::generate().public).to_string();
    let (_, signed) = construct(&base, &kp, &to, 666, None).await;
    let (status, body) = call(&base, "/construction/submit", json!({ "signed_transaction": signed })).await;
    assert_eq!((status, &body["code"], &body["retriable"]), (500, &json!(12), &json!(false)), "{body}");
    assert!(body["description"].as_str().unwrap().contains("base fee"), "{body}");
}

/// The machine that signs never talks to the network: offline, the steps around signing work and
/// the ones that need a node say so.
#[tokio::test]
async fn offline_it_builds_and_combines_and_asks_no_node() {
    let offline = serve(helix_mesh::offline_router("testnet")).await;
    let kp = KeyPair::generate();
    let from = Address::from_public_key(&kp.public).to_string();
    let to = Address::from_public_key(&KeyPair::generate().public).to_string();
    for path in ["/construction/metadata", "/construction/submit", "/network/status", "/account/balance"] {
        let (status, body) = call(&offline, path, json!({ "options": { "from": from }, "signed_transaction": "00",
            "account_identifier": { "address": from } })).await;
        assert_eq!((status, &body["code"]), (500, &json!(13)), "{path}: {body}");
    }
    let (status, opts) = call(&offline, "/network/options", json!({})).await;
    assert_eq!((status, &opts["version"]["node_version"]), (200, &json!("offline")));
    let metadata = json!({ "nonce": 0, "chain_id": CHAIN, "fee_nano": "20000" });
    let ops = transfer_ops(&from, &to, 5);
    let (status, payloads) = call(&offline, "/construction/payloads", json!({ "operations": ops, "metadata": metadata, "public_keys": [mesh_key(&kp)] })).await;
    assert_eq!(status, 200, "{payloads}");
    let to_sign = hex::decode(payloads["payloads"][0]["hex_bytes"].as_str().unwrap()).unwrap();
    let signature = json!({ "signing_payload": payloads["payloads"][0], "public_key": mesh_key(&kp), "signature_type": "ml_dsa_65",
        "hex_bytes": hex::encode(kp.sign(&to_sign).unwrap().as_bytes()) });
    let (status, combined) = call(&offline, "/construction/combine", json!({ "unsigned_transaction": payloads["unsigned_transaction"], "signatures": [signature] })).await;
    assert_eq!(status, 200, "{combined}");
    let (status, hashed) = call(&offline, "/construction/hash", json!({ "signed_transaction": combined["signed_transaction"] })).await;
    assert_eq!(status, 200, "{hashed}");
}

#[tokio::test]
async fn what_cannot_be_built_is_refused_with_the_reason() {
    let offline = serve(helix_mesh::offline_router("testnet")).await;
    let kp = KeyPair::generate();
    let from = Address::from_public_key(&kp.public).to_string();
    let to = Address::from_public_key(&KeyPair::generate().public).to_string();
    let (_, stake) = call(&offline, "/construction/preprocess", json!({ "operations": [
        { "operation_identifier": { "index": 0 }, "type": "STAKE", "account": { "address": from },
          "amount": { "value": "-5", "currency": { "symbol": "HLX", "decimals": 9 } } }] })).await;
    assert_eq!(stake["code"], 11, "{stake}");
    let (_, no_key) = call(&offline, "/construction/payloads", json!({ "operations": transfer_ops(&from, &to, 5),
        "metadata": { "nonce": 0, "chain_id": CHAIN, "fee_nano": "20000" }, "public_keys": [] })).await;
    assert_eq!(no_key["code"], 14, "{no_key}");
    let (_, dear) = call(&offline, "/construction/payloads", json!({ "operations": transfer_ops(&from, &to, 5),
        "metadata": { "nonce": 0, "chain_id": CHAIN, "fee_nano": "1000000001" }, "public_keys": [mesh_key(&kp)] })).await;
    assert_eq!(dear["code"], 11, "a fee above 1 HLX: {dear}");
    let (_, ecdsa) = call(&offline, "/construction/derive", json!({ "public_key": { "hex_bytes": "02ab", "curve_type": "secp256k1" } })).await;
    assert_eq!(ecdsa["code"], 14, "{ecdsa}");
}
