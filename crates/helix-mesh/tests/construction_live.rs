//! The Construction API against a real node — what `mesh-cli check:construction` would do if its
//! SDK could sign ML-DSA-65: build through the offline endpoints, fetch metadata and submit through
//! the online ones, sign with this repository's ML-DSA, and check that the chain applied exactly
//! what the operations said.
//!
//! `#[ignore]`: it needs a running node on a throwaway chain.
//!   HELIX_MESH_LIVE_NODE=http://127.0.0.1:19845 \
//!   HELIX_MESH_LIVE_KEY=<an unencrypted key file holding HLX on that chain> \
//!   cargo test -p helix-mesh --test construction_live -- --ignored --nocapture

use std::time::{Duration, Instant};

use helix_crypto::{Address, KeyPair};
use serde_json::{json, Value};

const NET: &str = r#"{"blockchain":"Helix","network":"testnet"}"#;

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn call(base: &str, path: &str, body: Value) -> Value {
    let mut body = body;
    body["network_identifier"] = serde_json::from_str(NET).unwrap();
    let response = reqwest::Client::new().post(format!("{base}{path}")).json(&body).send().await.unwrap();
    let status = response.status();
    let answer: Value = response.json().await.unwrap();
    assert!(status.is_success(), "{path}: {answer}");
    answer
}

async fn node_get(node: &str, path: &str) -> Value {
    reqwest::get(format!("{node}{path}")).await.unwrap().json().await.unwrap()
}

fn mesh_key(kp: &KeyPair) -> Value {
    json!({ "hex_bytes": hex::encode(kp.public.as_bytes()), "curve_type": "ml_dsa_65" })
}

fn transfer_ops(from: &str, to: &str, amount: u64) -> Value {
    json!([
        { "operation_identifier": { "index": 0 }, "type": "TRANSFER", "account": { "address": from },
          "amount": { "value": format!("-{amount}"), "currency": { "symbol": "HLX", "decimals": 9 } } },
        { "operation_identifier": { "index": 1 }, "type": "TRANSFER", "account": { "address": to },
          "amount": { "value": amount.to_string(), "currency": { "symbol": "HLX", "decimals": 9 } } },
    ])
}

/// One transfer through the Construction API, as a client with its signer offline runs it.
/// Returns (transaction id, fee).
async fn transfer(online: &str, offline: &str, kp: &KeyPair, to: &str, amount: u64, memo: Option<&str>) -> (String, u64) {
    let from = call(offline, "/construction/derive", json!({ "public_key": mesh_key(kp) })).await["account_identifier"]["address"]
        .as_str()
        .unwrap()
        .to_string();
    let ops = transfer_ops(&from, to, amount);
    let pre = call(offline, "/construction/preprocess", json!({ "operations": ops, "metadata": { "memo": memo } })).await;
    let meta = call(online, "/construction/metadata", json!({ "options": pre["options"], "public_keys": [mesh_key(kp)] })).await;
    let payloads = call(offline, "/construction/payloads", json!({ "operations": ops, "metadata": meta["metadata"], "public_keys": [mesh_key(kp)] })).await;
    let unsigned = payloads["unsigned_transaction"].clone();
    assert_eq!(call(offline, "/construction/parse", json!({ "signed": false, "transaction": unsigned })).await["operations"], ops);
    let to_sign = hex::decode(payloads["payloads"][0]["hex_bytes"].as_str().unwrap()).unwrap();
    let signature = json!({ "signing_payload": payloads["payloads"][0], "public_key": mesh_key(kp), "signature_type": "ml_dsa_65",
        "hex_bytes": hex::encode(kp.sign(&to_sign).unwrap().as_bytes()) });
    let signed = call(offline, "/construction/combine", json!({ "unsigned_transaction": unsigned, "signatures": [signature] })).await["signed_transaction"].clone();
    let parsed = call(offline, "/construction/parse", json!({ "signed": true, "transaction": signed })).await;
    assert_eq!(parsed["operations"], ops);
    assert_eq!(parsed["account_identifier_signers"], json!([{ "address": from }]));
    let id = call(offline, "/construction/hash", json!({ "signed_transaction": signed })).await["transaction_identifier"]["hash"].clone();
    let submitted = call(online, "/construction/submit", json!({ "signed_transaction": signed })).await;
    assert_eq!(submitted["transaction_identifier"]["hash"], id, "hash offline = the id the node took it under");
    let fee: u64 = meta["metadata"]["fee_nano"].as_str().unwrap().parse().unwrap();
    (id.as_str().unwrap().to_string(), fee)
}

async fn applied(node: &str, id: &str) -> Value {
    let start = Instant::now();
    loop {
        let tx = node_get(node, &format!("/transactions/{id}")).await;
        match tx["status"].as_str() {
            Some("applied") => return tx,
            Some("failed") => panic!("{id} failed: {tx}"),
            _ if start.elapsed() > Duration::from_secs(60) => panic!("{id} not applied within a minute: {tx}"),
            _ => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
}

async fn balance(node: &str, address: &str) -> u64 {
    node_get(node, &format!("/accounts/{address}")).await["balance_nano"].as_str().unwrap_or("0").parse().unwrap()
}

#[tokio::test]
#[ignore]
async fn transfers_built_through_mesh_are_applied_by_a_real_chain_exactly() {
    let node = std::env::var("HELIX_MESH_LIVE_NODE").expect("HELIX_MESH_LIVE_NODE");
    let key = std::env::var("HELIX_MESH_LIVE_KEY").expect("HELIX_MESH_LIVE_KEY");
    let funder = helix_crypto::keyfile::KeyFile::load(std::path::Path::new(&key)).unwrap().to_keypair(None).unwrap();
    let online = serve(helix_mesh::router(&node, "testnet")).await;
    let offline = serve(helix_mesh::offline_router("testnet")).await;

    // 1. The validator pays a fresh account, with a memo.
    let fresh = KeyPair::generate();
    let fresh_address = Address::from_public_key(&fresh.public).to_string();
    let (id1, fee1) = transfer(&online, &offline, &funder, &fresh_address, 3_210_000_007, Some("Mesh 1")).await;
    let tx1 = applied(&node, &id1).await;
    assert_eq!(tx1["memo"], "Mesh 1");
    assert_eq!(balance(&node, &fresh_address).await, 3_210_000_007, "arrived exactly");
    println!("1. funder -> fresh: {id1}, fee {fee1}, block {}", tx1["block_height"]);

    // 2. The fresh account's very first transaction: nonce 0, its public key carried, priced so.
    let back = Address::from_public_key(&KeyPair::generate().public).to_string();
    let (id2, fee2) = transfer(&online, &offline, &fresh, &back, 1_000_000_000, None).await;
    let tx2 = applied(&node, &id2).await;
    assert_eq!(balance(&node, &back).await, 1_000_000_000);
    assert_eq!(balance(&node, &fresh_address).await, 3_210_000_007 - 1_000_000_000 - fee2, "less exactly the amount and its fee");
    println!("2. fresh -> other (first tx of the account): {id2}, fee {fee2}, block {}", tx2["block_height"]);

    // 3. The Data API shows the applied transfer as the operations it was built from, plus its fee.
    let height = tx2["block_height"].as_u64().unwrap();
    let block = call(&online, "/block", json!({ "block_identifier": { "index": height } })).await;
    let shown = block["block"]["transactions"].as_array().unwrap().iter().find(|t| t["transaction_identifier"]["hash"] == id2).unwrap().clone();
    let ops: Vec<(String, String, String)> = shown["operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["type"] != "REWARD")
        .map(|o| (o["type"].as_str().unwrap().into(), o["account"]["address"].as_str().unwrap().into(), o["amount"]["value"].as_str().unwrap().into()))
        .collect();
    let s = |a: &str, b: &str, c: String| (a.to_string(), b.to_string(), c);
    assert_eq!(ops, vec![
        s("FEE", &fresh_address, format!("-{fee2}")),
        s("TRANSFER", &fresh_address, "-1000000000".into()),
        s("TRANSFER", &back, "1000000000".into()),
    ]);
    println!("3. /block shows FEE, TRANSFER -, TRANSFER + — the intent and its fee");

    // 4. Its second transaction: the chain knows the key now, the block carries the transfer
    //    without it, and the fee is priced on that smaller size (#243) — and still enough.
    let before = balance(&node, &fresh_address).await;
    let (id3, fee3) = transfer(&online, &offline, &fresh, &back, 500_000_000, None).await;
    assert!(fee3 < fee2, "priced without the key: {fee3} against {fee2}");
    let tx3 = applied(&node, &id3).await;
    assert_eq!(balance(&node, &fresh_address).await, before - 500_000_000 - fee3);
    assert_eq!(balance(&node, &back).await, 1_500_000_000);
    println!("4. fresh -> other again (nonce 1, key known): {id3}, fee {fee3} < {fee2}, block {}", tx3["block_height"]);
}
