//! Turning a human HLX amount into nano, and pricing + signing a transaction for the chain.
//!
//! This mirrors `helix-cli`'s `fee.rs` deliberately — the GUI must produce a transaction the
//! node accepts on the same terms the CLI does. It is re-implemented here (rather than depending
//! on `helix-cli`, which pulls clap/rpassword) to keep the backend's dependency graph small, and
//! kept short enough to eyeball against the original. The pricing rule itself is not mirrored
//! any more: both call `helix_core::fee::wallet_auto_fee`, headroom and ceiling included.

use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Hash, KeyPair, Signature};

pub const NANO_PER_HLX: u64 = 1_000_000_000;

/// The honest supply cap (mirrors `helix_executor::genesis::TOTAL_SUPPLY_HLX`). Used only to
/// reject an amount that cannot exist; not consensus, so a local copy is fine.
const TOTAL_SUPPLY_HLX: u64 = 33_000_000;

/// Read the HLX amount the person typed, exactly, as nano-HLX.
///
/// The webview hands over the text from the input field, and `helix_core::fee::parse_hlx` reads
/// its digits — the same rule as the CLI. It used to arrive as a JavaScript number and be cast
/// with `f64 × 1e9 as u64`, which truncates: 2.01 became 2_009_999_999 nano, so the wallet signed
/// one nano less than it showed for about one cent in five. Text also refuses what a number
/// cannot express honestly (`NaN`, `inf`, more than nine decimals) instead of casting it.
pub fn hlx_to_nano(amount_hlx: &str) -> Result<u64, String> {
    let nano = helix_core::fee::parse_hlx(amount_hlx)?;
    if nano > TOTAL_SUPPLY_HLX * NANO_PER_HLX {
        return Err(format!("{} HLX is more than the entire supply", amount_hlx.trim()));
    }
    Ok(nano)
}

/// Assemble a transaction skeleton. The caller then hands it to [`finalize_and_sign`].
#[allow(clippy::too_many_arguments)]
pub fn build_tx(tx_type: TxType, from: Address, to: Option<Address>, amount: u64, nonce: u64, data: Vec<u8>, chain_id: Hash, kp: &KeyPair) -> Transaction {
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
        // Which chain this is for — see `Transaction::chain_id`. Passed in rather than taken from
        // the compiled-in default here, because a wallet pointed at a devnet must sign for that
        // devnet; `rpc::fetch_chain_id` is where the decision of whom to believe lives.
        chain_id,
        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
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
    tx.public_key = Some(kp.public.clone());

    if let Some(fee) = explicit_fee {
        tx.fee = fee;
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).map_err(|e| e.to_string())?;
        return Ok(());
    }

    tx.fee = 0;
    tx.signature = kp.sign(tx.signing_hash().as_bytes()).map_err(|e| e.to_string())?;
    // The one wallet pricing rule, shared with the CLI — and its 1-HLX ceiling: the base fee
    // came from the node, and this wallet has no fee field, so a node reporting an absurd one
    // would otherwise be the one deciding what the user pays.
    // Priced on the bytes the block will carry: without the key once the account has a
    // transaction behind it (#243).
    let size = helix_core::fee::wallet_priced_size(tx);
    tx.fee = helix_core::fee::wallet_auto_fee(base_fee_per_byte, size).map_err(|e| {
        format!(
            "Not sent: {e}. If the network really is that busy, wait for it to calm down, or \
             send from the command line with an explicit --fee."
        )
    })?;
    tx.signature = kp.sign(tx.signing_hash().as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonsense_amounts_are_refused() {
        for text in ["NaN", "inf", "-1", "", "1e3", "0.0000000001", "33000000.000000001"] {
            assert!(hlx_to_nano(text).is_err(), "{text:?} must not become an amount");
        }
        assert_eq!(hlx_to_nano("1.5").unwrap(), 1_500_000_000);
    }

    /// What the person typed is what is signed — to the nano (the cast signed 2.01 as 2.009999999).
    #[test]
    fn a_typed_amount_is_signed_exactly() {
        assert_eq!(hlx_to_nano("2.01").unwrap(), 2_010_000_000);
        assert_eq!(hlx_to_nano(" 12345678.123456789 ").unwrap(), 12_345_678_123_456_789);
        for cents in 1..10_000u64 {
            let text = format!("{}.{:02}", cents / 100, cents % 100);
            assert_eq!(hlx_to_nano(&text).unwrap(), cents * 10_000_000, "{text}");
        }
    }

    /// The signed transaction the GUI produces must verify under the same check the node runs —
    /// this is the security-critical bit and it uses the real crates, no re-implementation.
    #[test]
    fn a_priced_transfer_verifies() {
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let to = Address::from_public_key(&KeyPair::generate().public);
        let mut tx = build_tx(TxType::Transfer, from, Some(to), 5 * NANO_PER_HLX, 0, vec![], Hash::ZERO, &kp);
        finalize_and_sign(&mut tx, None, 1, &kp).unwrap();
        assert!(tx.fee > 0, "an unpinned fee must be priced above zero");
        assert!(tx.verify_signature().is_ok(), "the node would reject this signature");
    }

    #[test]
    fn a_node_reporting_an_absurd_base_fee_does_not_get_the_wallet_to_sign_it() {
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let to = Address::from_public_key(&KeyPair::generate().public);
        let mut tx = build_tx(
            TxType::Transfer,
            from.clone(),
            Some(to.clone()),
            1,
            0,
            vec![],
            helix_core::default_chain_id(),
            &kp,
        );
        let err = finalize_and_sign(&mut tx, None, 1_000_000_000_000, &kp).unwrap_err();
        assert!(err.contains("Not sent"), "{err}");
        // Positive control: the same transaction at the floor is priced and signed.
        let mut tx = build_tx(
            TxType::Transfer,
            from,
            Some(to),
            1,
            0,
            vec![],
            helix_core::default_chain_id(),
            &kp,
        );
        finalize_and_sign(&mut tx, None, 1, &kp).unwrap();
        assert_eq!(tx.fee, 2 * tx.size_bytes());

        // #243: with a transaction behind it the account pays for the bytes the block carries,
        // which leave the key out.
        let mut later = build_tx(
            TxType::Transfer,
            Address::from_public_key(&kp.public),
            Some(Address::from_public_key(&KeyPair::generate().public)),
            1,
            3,
            vec![],
            helix_core::default_chain_id(),
            &kp,
        );
        finalize_and_sign(&mut later, None, 1, &kp).unwrap();
        let mut carried = later.clone();
        carried.public_key = None;
        assert_eq!(later.fee, 2 * carried.size_bytes());
        assert!(later.verify_signature().is_ok());
    }
}
