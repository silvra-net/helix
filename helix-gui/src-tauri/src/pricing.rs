//! Turning a human HLX amount into nano, and pricing + signing a transaction for the chain.
//!
//! This mirrors `helix-cli`'s `fee.rs` deliberately — the GUI must produce a transaction the
//! node accepts on the same terms the CLI does. It is re-implemented here (rather than depending
//! on `helix-cli`, which pulls clap/rpassword) to keep the backend's dependency graph small, and
//! kept short enough to eyeball against the original.

use helix_core::{Transaction, TxType};
use helix_crypto::{Address, KeyPair, Signature};

pub const NANO_PER_HLX: u64 = 1_000_000_000;

/// The honest supply cap (mirrors `helix_executor::genesis::TOTAL_SUPPLY_HLX`). Used only to
/// reject an amount that cannot exist; not consensus, so a local copy is fine.
const TOTAL_SUPPLY_HLX: u64 = 33_000_000;

/// Headroom over the bare base fee (percent), same rationale as the CLI: the base fee can climb
/// up to 12.5%/block and a tx is charged the fee of the block that includes it. Only
/// `base_fee × size` is burned; the rest tips the validator, so this is not wasted.
const FEE_HEADROOM_PERCENT: u64 = 100;

/// Convert a user-typed HLX amount to nano-HLX, rejecting what cannot be an amount — the exact
/// checks from `helix-cli::fee::hlx_to_nano`. `f64 as u64` is a saturating cast that answers for
/// every input (NaN → 0, inf → u64::MAX), which is how "send NaN HLX" used to sign a zero
/// transfer the sender still paid a fee for.
pub fn hlx_to_nano(amount_hlx: f64) -> Result<u64, String> {
    if amount_hlx.is_nan() {
        return Err(format!("'{amount_hlx}' is not an amount"));
    }
    if amount_hlx.is_infinite() {
        return Err(format!("an amount must be finite, not {amount_hlx}"));
    }
    if amount_hlx < 0.0 {
        return Err(format!("an amount cannot be negative ({amount_hlx})"));
    }
    let nano = amount_hlx * NANO_PER_HLX as f64;
    if nano > TOTAL_SUPPLY_HLX as f64 * NANO_PER_HLX as f64 {
        return Err(format!("{amount_hlx} HLX is more than the entire supply"));
    }
    Ok(nano as u64)
}

/// Assemble a transaction skeleton. The caller then hands it to [`finalize_and_sign`].
pub fn build_tx(tx_type: TxType, from: Address, to: Option<Address>, amount: u64, nonce: u64, data: Vec<u8>, kp: &KeyPair) -> Transaction {
    Transaction {
        version: 1,
        tx_type,
        from,
        to,
        amount,
        fee: 0,
        nonce,
        data,
        crypto_version: kp.scheme,
        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    }
}

/// Price `tx` for the chain and sign it. Synchronous — the caller has already fetched
/// `base_fee_per_byte` (over the network) so this can run entirely under the wallet lock without
/// ever holding it across an `.await`.
///
/// `explicit_fee: Some(f)` pins the fee; `None` prices it as `base_fee × size + headroom`, which
/// needs a two-pass sign: the fee's size depends on the signature, so sign once at fee 0 to get a
/// correctly-sized signature, measure, price, then sign for real. Sound because bincode encodes
/// the fee as a fixed 8 bytes — the size is identical for fee 0 and fee u64::MAX.
pub fn finalize_and_sign(tx: &mut Transaction, explicit_fee: Option<u64>, base_fee_per_byte: u64, kp: &KeyPair) -> Result<(), String> {
    tx.public_key = kp.public.clone();

    if let Some(fee) = explicit_fee {
        tx.fee = fee;
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).map_err(|e| e.to_string())?;
        return Ok(());
    }

    tx.fee = 0;
    tx.signature = kp.sign(tx.signing_hash().as_bytes()).map_err(|e| e.to_string())?;
    let size = tx.size_bytes();
    let required = base_fee_per_byte.saturating_mul(size);
    tx.fee = required.saturating_add(required.saturating_mul(FEE_HEADROOM_PERCENT) / 100);
    tx.signature = kp.sign(tx.signing_hash().as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonsense_amounts_are_refused() {
        assert!(hlx_to_nano(f64::NAN).is_err());
        assert!(hlx_to_nano(f64::INFINITY).is_err());
        assert!(hlx_to_nano(-1.0).is_err());
        assert_eq!(hlx_to_nano(1.5).unwrap(), 1_500_000_000);
    }

    /// The signed transaction the GUI produces must verify under the same check the node runs —
    /// this is the security-critical bit and it uses the real crates, no re-implementation.
    #[test]
    fn a_priced_transfer_verifies() {
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let to = Address::from_public_key(&KeyPair::generate().public);
        let mut tx = build_tx(TxType::Transfer, from, Some(to), 5 * NANO_PER_HLX, 0, vec![], &kp);
        finalize_and_sign(&mut tx, None, 1, &kp).unwrap();
        assert!(tx.fee > 0, "an unpinned fee must be priced above zero");
        assert!(tx.verify_signature().is_ok(), "the node would reject this signature");
    }
}
