//! Manual end-to-end check: prints the signed-tx JSON this crate produces, for piping straight
//! into `curl -d @- <node>/transactions` against a real (isolated devnet, never prod) node — the
//! strongest verification available without an actual Android device/emulator attached.
//! Not a `#[test]` because it needs a live node; not shipped, just a debugging aid.
//!
//! Usage: cargo run --example sign_demo -- <to> <amount> <fee> <nonce>
//! Uses the same fixed 0..32 seed as the crate's own unit tests.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let to = args.get(1).cloned();
    let amount: u64 = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(1_000_000_000);
    let fee: u64 = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(10_820);
    let nonce: u64 = args.get(4).map(|s| s.parse().unwrap()).unwrap_or(0);

    let seed: Vec<u8> = (0u8..32).collect();
    let from = helix_mobile::derive_address(seed.clone()).unwrap();
    let signed = helix_mobile::sign_transaction(
        seed,
        helix_mobile::UnsignedTx {
            version: 1,
            tx_type: "Transfer".to_string(),
            from: from.clone(),
            to: to.or(Some(from)),
            amount,
            fee,
            nonce,
            data: vec![],
        },
    )
    .unwrap();

    eprintln!("tx_hash: {}", signed.tx_hash);
    println!("{}", signed.json);
}
