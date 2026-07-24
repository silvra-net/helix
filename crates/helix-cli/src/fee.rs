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
        let body = resp.text().await.unwrap_or_default();
        let detail = body.trim();
        bail!(
            "the node refused the fee lookup with HTTP {}{} — the node is not too old, the request \
             was rejected. HTTP 429 means you are being rate-limited: retry, slow down, or pass \
             --fee explicitly to skip the lookup entirely.",
            http.as_u16(),
            if detail.is_empty() { String::new() } else { format!(" ({detail})") },
        );
    }

    let status: serde_json::Value = resp
        .json()
        .await
        .context("the node's /status was not valid JSON — cannot read the current fee")?;
    status
        .get("base_fee_per_byte")
        .and_then(|v| v.as_u64())
        .context(
            "this node's /status has no base_fee_per_byte field — it is running a build older than \
             the fee market; pass --fee explicitly",
        )
}

/// Headroom over the bare base fee, as a percentage, when the fee is computed rather than given.
///
/// The base fee moves at most ±12.5% per block, and a transaction is charged the fee of the
/// block that *includes* it, not the one current when it was signed — so pricing at exactly
/// today's rate means anything that waits a few busy blocks gets rejected on arrival. 100% of
/// headroom covers roughly six consecutive rises (1.125⁶ ≈ 2.03). It is not wasted: only
/// `base_fee × size` is burned, the remainder tips the validator and buys priority. At the
/// floor this turns a ~5.4 KB transfer's ~5410 nano into ~10820 — about 0.00001 HLX.
const FEE_HEADROOM_PERCENT: u64 = 100;

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
    tx.public_key = kp.public.clone();
    tx.signature = kp.sign(tx.signing_hash().as_bytes())?;

    if explicit_fee.is_some() {
        return Ok(());
    }

    let base_fee_per_byte = fetch_base_fee_per_byte(node).await?;
    let size = tx.size_bytes();
    let required = base_fee_per_byte.saturating_mul(size);
    tx.fee = required.saturating_add(required.saturating_mul(FEE_HEADROOM_PERCENT) / 100);
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
}
