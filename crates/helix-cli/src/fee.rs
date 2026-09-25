//! Pricing a transaction for the chain, in one place.
//!
//! Every command module used to carry its own `const DEFAULT_FEE_NANO: u64 = 10_000` — six
//! copies of one guess, and the guess was wrong in a way none of them could see. A transaction's
//! fee is not flat: the chain charges `base_fee_per_byte × size`, an ML-DSA signature and key
//! alone are ~5.3 KB, and the byte price rises under load. So 10_000 nano covered a plain
//! transfer only while the base fee sat at its floor, and never covered a contract deploy of any
//! real size (the code travels in the transaction; at the 64 KiB limit the true cost is ~71_000).
//!
//! Asking the node what it charges is both correct and self-maintaining.

use anyhow::{bail, Context, Result};
use helix_core::Transaction;
use helix_crypto::KeyPair;

const NANO_PER_HLX_F: f64 = 1_000_000_000.0;

/// Convert a user-typed HLX amount into nano-HLX, rejecting what cannot be an amount.
///
/// `as u64` on an `f64` is a saturating cast that answers *something* for every input, which is
/// how `helix tx send <addr> nan` used to work: NaN becomes 0, so the CLI printed "Sending NaN
/// HLX", signed a zero-value transfer, and the sender paid a fee for a transaction the executor
/// was always going to reject. `inf` became `u64::MAX` — 18 billion HLX — and failed on balance
/// instead. Neither is a typo worth charging someone for.
///
/// Also caps at the supply: no amount above it can exist, and past ~9M HLX an `f64` can no longer
/// represent single nano anyway (53-bit mantissa vs. the 55 bits the cap needs), so a number
/// beyond that is not a precise instruction to begin with.
pub fn hlx_to_nano(amount_hlx: f64) -> Result<u64> {
    if amount_hlx.is_nan() {
        bail!("'{amount_hlx}' is not an amount");
    }
    if amount_hlx.is_infinite() {
        bail!("an amount must be finite, not {amount_hlx}");
    }
    if amount_hlx < 0.0 {
        bail!("an amount cannot be negative ({amount_hlx})");
    }
    let nano = amount_hlx * NANO_PER_HLX_F;
    let max = helix_executor::genesis::TOTAL_SUPPLY_HLX as f64 * NANO_PER_HLX_F;
    if nano > max {
        bail!(
            "{amount_hlx} HLX is more than the entire supply ({} HLX)",
            helix_executor::genesis::TOTAL_SUPPLY_HLX
        );
    }
    Ok(nano as u64)
}

/// What the chain charges per transaction byte right now, straight from the node that will be
/// asked to accept the transaction.
pub async fn fetch_base_fee_per_byte(node: &str) -> Result<u64> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/status", node))
        .send()
        .await
        .with_context(|| format!("could not reach {} to price the fee", node))?;

    // A non-2xx here is the request being refused, not a protocol mismatch — so it must not be
    // reported as "the node is too old". The common case is HTTP 429: this client is being
    // rate-limited (the node caps requests per IP). Blaming the build sent an operator chasing a
    // version problem that did not exist; say what actually happened and how to get past it.
    let http = resp.status();
    if !http.is_success() {
        let body = crate::commands::read_body_capped(resp).await.unwrap_or_default();
        let detail = body.trim();
        bail!(
            "the node refused the fee lookup with HTTP {}{} — the node is not too old, the request \
             was rejected. HTTP 429 means you are being rate-limited: retry, slow down, or pass \
             --fee explicitly to skip the lookup entirely.",
            http.as_u16(),
            if detail.is_empty() { String::new() } else { format!(" ({detail})") },
        );
    }

    let body = crate::commands::read_body_capped(resp).await?;
    let status: serde_json::Value = serde_json::from_str(&body)
        .context("the node's /status was not valid JSON — cannot read the current fee")?;
    status
        .get("base_fee_per_byte")
        .and_then(|v| v.as_u64())
        .context(
            "this node's /status has no base_fee_per_byte field — it is running a build older than \
             the fee market; pass --fee explicitly",
        )
}

/// Sign `tx`, pricing it for the chain unless the caller pinned a fee with `--fee`.
///
/// The fee depends on the transaction's serialized size, and the size depends on the signature —
/// so the transaction is signed once at a placeholder fee purely to obtain a correctly sized
/// signature, measured, priced, and then signed again for real. That is sound because the fee is
/// bincode-encoded as a fixed 8 bytes: the size is identical for a fee of 0 and one of u64::MAX,
/// so pricing cannot change the number it was priced against.
pub async fn price_and_sign(
    tx: &mut Transaction,
    explicit_fee: Option<u64>,
    kp: &KeyPair,
    node: &str,
) -> Result<()> {
    tx.fee = explicit_fee.unwrap_or(0);
    tx.public_key = Some(kp.public.clone());
    tx.signature = kp.sign(tx.signing_hash().as_bytes())?;

    if explicit_fee.is_some() {
        return Ok(());
    }

    let base_fee_per_byte = fetch_base_fee_per_byte(node).await?;
    sign_at_base_fee(tx, base_fee_per_byte, kp)
}

/// The second pass of [`price_and_sign`], apart from the network so it can be tested: price the
/// already-signed `tx` with the one wallet rule (`helix_core::fee::wallet_auto_fee`, headroom
/// and a 1-HLX ceiling) and sign it again. Above the ceiling nothing is signed at that fee — the
/// base fee came from a node, and a node is not someone whose word should spend your money.
fn sign_at_base_fee(tx: &mut Transaction, base_fee_per_byte: u64, kp: &KeyPair) -> Result<()> {
    tx.fee = helix_core::fee::wallet_auto_fee(base_fee_per_byte, tx.size_bytes()).map_err(|e| {
        anyhow::anyhow!(
            "Not sent: {e}. If the fee is real, pass it explicitly with --fee <nano-HLX>."
        )
    })?;
    tx.signature = kp.sign(tx.signing_hash().as_bytes())?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    /// `f64 as u64` is a saturating cast — it answers for every input, including inputs that are
    /// not amounts. Each of these used to produce a signed transaction: NaN a zero-value transfer
    /// the executor always rejects, infinity a claim on 18 billion HLX. The sender paid the fee
    /// either way.
    #[test]
    fn nonsense_is_refused_rather_than_silently_cast_to_a_number() {
        assert!(hlx_to_nano(f64::NAN).is_err(), "NaN as u64 is 0 — a zero-value transfer");
        assert!(hlx_to_nano(f64::INFINITY).is_err(), "inf as u64 is u64::MAX");
        assert!(hlx_to_nano(f64::NEG_INFINITY).is_err());
        assert!(hlx_to_nano(-1.0).is_err(), "negative as u64 is 0");
        assert!(hlx_to_nano(-0.000_000_001).is_err());
    }

    #[test]
    fn an_amount_beyond_the_entire_supply_is_refused() {
        let cap = helix_executor::genesis::TOTAL_SUPPLY_HLX as f64;
        assert!(hlx_to_nano(cap).is_ok(), "the cap itself is representable");
        assert!(hlx_to_nano(cap + 1.0).is_err());
        assert!(hlx_to_nano(f64::MAX).is_err());
    }

    #[test]
    fn ordinary_amounts_convert_exactly() {
        assert_eq!(hlx_to_nano(0.0).unwrap(), 0, "zero is a valid input here — the executor is what rejects a zero transfer, with a message about transfers rather than about parsing");
        assert_eq!(hlx_to_nano(1.0).unwrap(), 1_000_000_000);
        assert_eq!(hlx_to_nano(0.1).unwrap(), 100_000_000);
        assert_eq!(hlx_to_nano(1.5).unwrap(), 1_500_000_000);
        assert_eq!(hlx_to_nano(0.000_000_001).unwrap(), 1, "one nano, the smallest unit");
        assert_eq!(hlx_to_nano(100_000.0).unwrap(), 100_000 * 1_000_000_000);
    }

    fn unsigned_transfer(kp: &KeyPair) -> Transaction {
        Transaction {
            version: 1,
            tx_type: helix_core::TxType::Transfer,
            from: helix_crypto::Address::from_public_key(&kp.public),
            to: Some(helix_crypto::Address::from_public_key(
                &KeyPair::generate().public,
            )),
            amount: 1,
            fee: 0,
            nonce: 0,
            data: vec![],
            crypto_version: kp.scheme,
            chain_id: helix_core::default_chain_id(),
            signature: helix_crypto::Signature::from_bytes(vec![]),
            public_key: Some(kp.public.clone()),
        }
    }

    #[test]
    fn a_node_cannot_make_the_cli_sign_away_the_wallet_in_fees() {
        let kp = KeyPair::generate();
        let mut tx = unsigned_transfer(&kp);
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        let err = sign_at_base_fee(&mut tx, 1_000_000_000_000, &kp)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--fee"), "{err}");
        // The refused fee never reaches the transaction, so no signature over it ever exists.
        assert_eq!(tx.fee, 0);

        // Positive control: the floor price is signed, and the signature covers that fee.
        let mut tx = unsigned_transfer(&kp);
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        sign_at_base_fee(&mut tx, 1, &kp).unwrap();
        assert_eq!(tx.fee, 2 * tx.size_bytes());
        assert!(tx.verify_signature().is_ok());
    }

    /// The same, through a real socket: the path `price_and_sign` takes in production, so the
    /// test covers the wiring and not only the pure function behind it.
    #[tokio::test]
    async fn price_and_sign_refuses_what_a_lying_node_asks_for() {
        use axum::{routing::get, Router};
        let app = Router::new().route(
            "/status",
            get(|| async {
                axum::Json(serde_json::json!({ "base_fee_per_byte": 1_000_000_000_000u64 }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let kp = KeyPair::generate();
        let mut tx = unsigned_transfer(&kp);
        let err = price_and_sign(&mut tx, None, &kp, &node)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Not sent"), "{err}");

        // An explicit fee is the person's own decision and is not second-guessed.
        price_and_sign(&mut tx, Some(5_000_000_000), &kp, &node)
            .await
            .unwrap();
        assert_eq!(tx.fee, 5_000_000_000);
    }
}
