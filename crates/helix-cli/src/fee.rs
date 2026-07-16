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

use anyhow::{Context, Result};
use helix_core::Transaction;
use helix_crypto::KeyPair;

/// What the chain charges per transaction byte right now, straight from the node that will be
/// asked to accept the transaction.
pub async fn fetch_base_fee_per_byte(node: &str) -> Result<u64> {
    let client = reqwest::Client::new();
    let status: serde_json::Value = client
        .get(format!("{}/status", node))
        .send()
        .await?
        .json()
        .await?;
    status
        .get("base_fee_per_byte")
        .and_then(|v| v.as_u64())
        .context(
            "node did not report base_fee_per_byte — it is running a build older than the fee \
             market; pass --fee explicitly",
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

