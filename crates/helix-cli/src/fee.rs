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

/// An amount the user typed in HLX, held exactly in nano-HLX.
///
/// Parsed from the digits as written (`helix_core::fee::parse_hlx`), never through an `f64`.
/// It used to be `f64 × 1e9` cast with `as u64`, and that cast truncates: 2.01 × 1e9 is
/// 2_009_999_999.999…, so `helix tx send <addr> 2.01` signed a transfer of **2.009999999** HLX.
/// About one cent in five came out one nano short — invisible in a wallet, and exactly what an
/// exchange reconciling withdrawals to the nano cannot live with.
///
/// Before that, the same cast answered *something* for every input: `nan` signed a zero-value
/// transfer and charged its fee, `inf` became 18 billion HLX. Parsing text refuses both, and
/// anything else that is not an amount, before anything is signed. It also caps at the supply:
/// no larger amount can exist, so a larger number is a typo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hlx(u64);

impl Hlx {
    pub fn nano(self) -> u64 {
        self.0
    }
}

impl std::str::FromStr for Hlx {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let nano = helix_core::fee::parse_hlx(text)?;
        let supply = helix_executor::genesis::TOTAL_SUPPLY_HLX;
        if nano > supply * 1_000_000_000 {
            return Err(format!(
                "{} HLX is more than the entire supply ({supply} HLX)",
                text.trim()
            ));
        }
        Ok(Hlx(nano))
    }
}

impl std::fmt::Display for Hlx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&helix_core::fee::nano_as_hlx(self.0))
    }
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
    let size = helix_core::fee::wallet_priced_size(tx);
    tx.fee = helix_core::fee::wallet_auto_fee(base_fee_per_byte, size).map_err(|e| {
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
    fn hlx(text: &str) -> Result<u64, String> {
        text.parse::<Hlx>().map(Hlx::nano)
    }

    #[test]
    fn nonsense_is_refused_rather_than_silently_cast_to_a_number() {
        for text in ["nan", "NaN", "inf", "-inf", "-1", "-0.000000001", "", "1e3", "ten"] {
            assert!(hlx(text).is_err(), "{text:?} must not become an amount");
        }
    }

    #[test]
    fn an_amount_beyond_the_entire_supply_is_refused() {
        let cap = helix_executor::genesis::TOTAL_SUPPLY_HLX;
        let whole_supply = hlx(&cap.to_string()).unwrap();
        assert_eq!(whole_supply, cap * 1_000_000_000, "the cap itself is an amount");
        assert!(hlx(&format!("{cap}.000000001")).is_err());
        assert!(hlx(&(cap + 1).to_string()).is_err());
        assert!(hlx("18446744073709551616").is_err(), "past u64 is refused, not wrapped");
    }

    #[test]
    fn ordinary_amounts_convert_exactly() {
        assert_eq!(hlx("0").unwrap(), 0, "zero is a valid input here — the executor is what rejects a zero transfer, with a message about transfers rather than about parsing");
        assert_eq!(hlx("1").unwrap(), 1_000_000_000);
        assert_eq!(hlx("0.1").unwrap(), 100_000_000);
        assert_eq!(hlx("1.5").unwrap(), 1_500_000_000);
        assert_eq!(hlx("0.000000001").unwrap(), 1, "one nano, the smallest unit");
        assert_eq!(hlx("100000").unwrap(), 100_000 * 1_000_000_000);
    }

    /// The truncating cast signed 2.01 HLX as 2.009999999. Every cent from 0.01 to 99.99, and the
    /// shape an amount is shown in, must come back as exactly what was typed.
    #[test]
    fn a_typed_amount_is_signed_to_the_nano() {
        assert_eq!(hlx("2.01").unwrap(), 2_010_000_000);
        for cents in 1..10_000u64 {
            let text = format!("{}.{:02}", cents / 100, cents % 100);
            assert_eq!(hlx(&text).unwrap(), cents * 10_000_000, "{text}");
        }
        let shown = Hlx(12_345_678_901).to_string();
        assert_eq!(hlx(&shown).unwrap(), 12_345_678_901, "reads back as shown ({shown})");
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

    /// #243: an account with a transaction behind it pays for the bytes the block carries —
    /// without its key. The wallet still sends the key; the chain just no longer charges for it.
    #[test]
    fn a_later_transaction_is_priced_without_its_key() {
        let kp = KeyPair::generate();
        let mut tx = unsigned_transfer(&kp);
        tx.nonce = 3;
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        sign_at_base_fee(&mut tx, 1, &kp).unwrap();
        let mut carried = tx.clone();
        carried.public_key = None;
        assert_eq!(tx.fee, 2 * carried.size_bytes());
        assert!(tx.public_key.is_some(), "the wallet still sends its key");
        assert!(tx.verify_signature().is_ok(), "and signs the fee it priced");
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
