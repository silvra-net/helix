//! The Construction API's logic: what a transfer of HLX is in Mesh operations, the transaction it
//! becomes, what the caller signs, and putting the signature in — everything except asking the
//! node, so the offline endpoints never touch one.
//!
//! **What the caller signs.** One payload: the transaction's signing hash — 32 bytes, BLAKE3 over
//! every field but the signature and the public key — with signature type `ml_dsa_65`. Helix
//! verifies it as FIPS 204 ML-DSA-65 with an **empty context string**, over exactly those 32 bytes
//! (the `ml-dsa` crate's `Signer`, as `helix_crypto` uses it). Any conforming signer — randomised
//! or deterministic — produces a signature that verifies. Public keys are `ml_dsa_65`: 1952 bytes,
//! signatures 3309.
//!
//! **Only a transfer.** Two operations of type `TRANSFER`: one taking an amount from the sender, one
//! giving the same amount to the recipient — what the Data API shows of an applied transfer, less
//! its `FEE`, which the transaction states and the chain charges. Anything else is refused, not
//! built approximately.
//!
//! **The blobs** (`unsigned_transaction`, `signed_transaction`) are the transaction's canonical
//! bytes in hex — bincode, the bytes the chain hashes into a block and charges the base fee on —
//! unsigned (no signature) or signed.

use helix_core::{Transaction, TxType, MEMO_MAX_BYTES};
use helix_crypto::{Address, CryptoScheme, Hash, PublicKey, Signature};
use serde_json::{json, Value};

use crate::map::TRANSFER;
use crate::types::{AccountIdentifier, Amount, Currency, Operation, OperationIdentifier};

/// The `curve_type` and `signature_type` of Helix's keys and signatures.
pub const ML_DSA_65: &str = "ml_dsa_65";
/// FIPS 204 ML-DSA-65.
pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SIGNATURE_BYTES: usize = 3309;
/// A blob longer than this is not a transfer: a transfer with the longest memo is ~5.7 KB.
const MAX_BLOB_BYTES: usize = 64 * 1024;

/// A transfer, as the operations describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub from: Address,
    pub to: Address,
    pub amount: u64,
}

fn hlx_amount(op: &Operation) -> Result<i128, String> {
    if op.amount.currency != Currency::hlx() {
        return Err(format!("operation {} is not in HLX (9 decimals)", op.operation_identifier.index));
    }
    op.amount.value.parse::<i128>().map_err(|_| format!("{:?} is not an amount of nano-HLX", op.amount.value))
}

fn address_of(op: &Operation) -> Result<Address, String> {
    if op.account.sub_account.is_some() {
        return Err("Helix accounts have no sub-accounts".into());
    }
    Address::from_str(&op.account.address).map_err(|e| format!("{:?} is not an address: {e}", op.account.address))
}

/// The transfer two operations describe — or why they do not describe one.
pub fn intent(operations: &[Operation]) -> Result<Intent, String> {
    if operations.len() != 2 || operations.iter().any(|op| op.op_type != TRANSFER) {
        return Err("a Helix transaction built here is one transfer: two TRANSFER operations, one taking an \
                    amount from the sender and one giving it to the recipient"
            .into());
    }
    let first = hlx_amount(&operations[0])?;
    hlx_amount(&operations[1])?;
    let (sender, recipient) = if first < 0 { (&operations[0], &operations[1]) } else { (&operations[1], &operations[0]) };
    let (taken, given) = (hlx_amount(sender)?, hlx_amount(recipient)?);
    if taken >= 0 || given <= 0 || taken + given != 0 {
        return Err("the sender's operation must take exactly what the recipient's gives, and more than nothing".into());
    }
    let amount = u64::try_from(given).map_err(|_| "the amount is larger than any balance".to_string())?;
    let (from, to) = (address_of(sender)?, address_of(recipient)?);
    if from == to {
        return Err("a transfer to the sending account itself only costs its fee".into());
    }
    Ok(Intent { from, to, amount })
}

/// A memo as metadata carries it: UTF-8, at most 256 bytes, or none.
pub fn memo(metadata: Option<&Value>) -> Result<Option<String>, String> {
    match metadata.and_then(|m| m.get("memo")) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(m)) if !m.is_empty() && m.len() <= MEMO_MAX_BYTES => Ok(Some(m.clone())),
        Some(Value::String(m)) if m.is_empty() => Err("an empty memo — leave it out".into()),
        Some(Value::String(_)) => Err(format!("a memo is at most {MEMO_MAX_BYTES} bytes")),
        Some(_) => Err("the memo must be a string".into()),
    }
}

/// The public key from a request, checked: `ml_dsa_65`, 1952 bytes, a key that parses.
pub fn public_key(key: &crate::types::PublicKey) -> Result<PublicKey, String> {
    if key.curve_type != ML_DSA_65 {
        return Err(format!("Helix keys are {ML_DSA_65}, not {}", key.curve_type));
    }
    let bytes = hex::decode(&key.hex_bytes).map_err(|_| "the public key is not hex".to_string())?;
    if bytes.len() != PUBLIC_KEY_BYTES {
        return Err(format!("an {ML_DSA_65} public key is {PUBLIC_KEY_BYTES} bytes, this one {}", bytes.len()));
    }
    let key = PublicKey::from_bytes(bytes);
    if !key.is_valid_for(CryptoScheme::MlDsa) {
        return Err("the bytes are not an ML-DSA-65 public key".into());
    }
    Ok(key)
}

/// The transaction for `intent`, unsigned. The public key goes in: the chain needs it for an
/// account's first transaction, and a node drops it from the block when it already knows it (#243).
pub fn unsigned(intent: &Intent, nonce: u64, fee: u64, chain_id: Hash, key: PublicKey, memo: Option<&str>) -> Transaction {
    Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        from: intent.from.clone(),
        to: Some(intent.to.clone()),
        amount: intent.amount,
        fee,
        nonce,
        data: memo.map(|m| m.as_bytes().to_vec()).unwrap_or_default(),
        crypto_version: CryptoScheme::MlDsa,
        chain_id,
        signature: Signature::from_bytes(Vec::new()),
        public_key: Some(key),
    }
}

/// The fee a transfer pays at `base_fee_per_byte`, by the wallets' one rule (headroom over the
/// base fee, refused above 1 HLX) — priced on the size of the **signed** transaction. A signature
/// is 3309 bytes and the base fee is charged per byte; pricing the unsigned one undercharged by
/// exactly that, and the node refused every such transaction (found in #262). Key and signature
/// have fixed lengths, so placeholders of those lengths give the exact size before anyone signs.
pub fn fee(base_fee_per_byte: u64, nonce: u64, memo: Option<&str>) -> Result<u64, String> {
    let placeholder = Address::from_public_key(&PublicKey::from_bytes(vec![0; PUBLIC_KEY_BYTES]));
    let intent = Intent { from: placeholder.clone(), to: placeholder, amount: 0 };
    let mut tx = unsigned(&intent, nonce, 0, Hash::ZERO, PublicKey::from_bytes(vec![0; PUBLIC_KEY_BYTES]), memo);
    tx.signature = Signature::from_bytes(vec![0; SIGNATURE_BYTES]);
    helix_core::fee::wallet_auto_fee(base_fee_per_byte, helix_core::fee::wallet_priced_size(&tx)).map_err(|e| e.to_string())
}

/// A blob: the transaction's canonical bytes, in hex.
pub fn encode(tx: &Transaction) -> String {
    hex::encode(bincode::serialize(tx).expect("serialization is infallible"))
}

pub fn decode(blob: &str) -> Result<Transaction, String> {
    if blob.len() > 2 * MAX_BLOB_BYTES {
        return Err("too long to be a transfer".into());
    }
    let bytes = hex::decode(blob.trim()).map_err(|_| "not hex".to_string())?;
    let tx: Transaction = bincode::deserialize(&bytes).map_err(|e| format!("not a Helix transaction: {e}"))?;
    if bincode::serialize(&tx).expect("serialization is infallible") != bytes {
        return Err("not the canonical bytes of a Helix transaction".into());
    }
    Ok(tx)
}

/// What the caller signs: the signing hash, in hex.
pub fn signing_payload(tx: &Transaction) -> String {
    hex::encode(tx.signing_hash().as_bytes())
}

/// Put `signature` into `tx` and check it: by the key the transaction carries, which must be the
/// sender's (the address is a hash of it), over the signing hash. A signature that does not verify
/// is refused here, before anything reaches a node.
pub fn combine(mut tx: Transaction, signature: &crate::types::Signature) -> Result<Transaction, String> {
    if !tx.signature.as_bytes().is_empty() {
        return Err("the transaction is already signed".into());
    }
    if signature.signature_type != ML_DSA_65 {
        return Err(format!("Helix signatures are {ML_DSA_65}, not {}", signature.signature_type));
    }
    let key = public_key(&signature.public_key)?;
    if tx.public_key.as_ref() != Some(&key) {
        return Err("the signature's public key is not the one the transaction was built with".into());
    }
    if signature.signing_payload.hex_bytes.to_lowercase() != signing_payload(&tx) {
        return Err("the signature is for another payload than this transaction's".into());
    }
    let bytes = hex::decode(&signature.hex_bytes).map_err(|_| "the signature is not hex".to_string())?;
    if bytes.len() != SIGNATURE_BYTES {
        return Err(format!("an {ML_DSA_65} signature is {SIGNATURE_BYTES} bytes, this one {}", bytes.len()));
    }
    tx.signature = Signature::from_bytes(bytes);
    tx.verify_signature().map_err(|e| format!("the signature does not verify: {e}"))?;
    Ok(tx)
}

/// A signed transaction, checked: signed, and by the sender's key.
pub fn signed(blob: &str) -> Result<Transaction, String> {
    let tx = decode(blob)?;
    if tx.signature.as_bytes().is_empty() {
        return Err("the transaction is not signed".into());
    }
    tx.verify_signature().map_err(|e| format!("the signature does not verify: {e}"))?;
    Ok(tx)
}

fn transfer_op(index: u64, address: &Address, delta: i128) -> Operation {
    Operation {
        operation_identifier: OperationIdentifier { index },
        op_type: TRANSFER.to_string(),
        status: None,
        account: AccountIdentifier { address: address.to_string(), sub_account: None },
        amount: Amount { value: delta.to_string(), currency: Currency::hlx() },
    }
}

/// The operations a transaction built here performs — the intent it was built from.
pub fn operations(tx: &Transaction) -> Result<Vec<Operation>, String> {
    let to = match (&tx.tx_type, &tx.to) {
        (TxType::Transfer, Some(to)) => to,
        _ => return Err("not a transfer".into()),
    };
    let amount = tx.amount as i128;
    Ok(vec![transfer_op(0, &tx.from, -amount), transfer_op(1, to, amount)])
}

/// What `/construction/parse` adds about a transaction besides its operations.
pub fn parse_metadata(tx: &Transaction) -> Value {
    json!({
        "nonce": tx.nonce,
        "fee_nano": tx.fee.to_string(),
        "chain_id": tx.chain_id.to_hex(),
        "memo": tx.memo(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::KeyPair;

    fn op(index: u64, address: &str, value: i128) -> Operation {
        Operation {
            operation_identifier: OperationIdentifier { index },
            op_type: TRANSFER.into(),
            status: None,
            account: AccountIdentifier { address: address.into(), sub_account: None },
            amount: Amount { value: value.to_string(), currency: Currency::hlx() },
        }
    }

    fn mesh_key(kp: &KeyPair) -> crate::types::PublicKey {
        crate::types::PublicKey { hex_bytes: hex::encode(kp.public.as_bytes()), curve_type: ML_DSA_65.into() }
    }

    fn mesh_signature(tx: &Transaction, kp: &KeyPair, signed_bytes: &[u8]) -> crate::types::Signature {
        crate::types::Signature {
            signing_payload: crate::types::SigningPayload {
                address: None,
                account_identifier: None,
                hex_bytes: signing_payload(tx),
                signature_type: Some(ML_DSA_65.into()),
            },
            public_key: mesh_key(kp),
            signature_type: ML_DSA_65.into(),
            hex_bytes: hex::encode(kp.sign(signed_bytes).unwrap().as_bytes()),
        }
    }

    /// The lengths the specification states for `ml_dsa_65` are the ones Helix's keys have.
    #[test]
    fn ml_dsa_65_has_the_lengths_the_specification_states() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public.as_bytes().len(), PUBLIC_KEY_BYTES);
        assert_eq!(kp.sign(b"x").unwrap().as_bytes().len(), SIGNATURE_BYTES);
    }

    /// The whole flow, offline: intent → unsigned → payload → signed by a key the way any FIPS 204
    /// signer would → combine → parse gives the intent back → hash is the id the node will use.
    #[test]
    fn a_transfer_goes_from_intent_to_a_signed_transaction_and_back() {
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let to = Address::from_public_key(&KeyPair::generate().public);
        let ops = vec![op(0, &from.to_string(), -2_010_000_001), op(1, &to.to_string(), 2_010_000_001)];
        let intent = intent(&ops).unwrap();
        assert_eq!(intent.amount, 2_010_000_001);
        let chain = Hash::digest(b"some chain");
        let tx = unsigned(&intent, 7, 12_345, chain, public_key(&mesh_key(&kp)).unwrap(), Some("Einzahlung 42"));
        let blob = encode(&tx);
        let back = decode(&blob).unwrap();
        assert_eq!(back, tx);
        assert_eq!(operations(&back).unwrap(), ops, "parse returns the intent");
        let payload = hex::decode(signing_payload(&back)).unwrap();
        assert_eq!(payload.len(), 32);
        let signed_tx = combine(back, &mesh_signature(&tx, &kp, &payload)).unwrap();
        let signed_blob = encode(&signed_tx);
        let parsed = signed(&signed_blob).unwrap();
        assert_eq!(operations(&parsed).unwrap(), ops);
        assert_eq!(parsed.hash(), signed_tx.hash(), "the id the node gives it");
        assert_eq!(parse_metadata(&parsed)["memo"], "Einzahlung 42");
        assert_eq!(parse_metadata(&parsed)["chain_id"], chain.to_hex());
    }

    #[test]
    fn only_a_transfer_between_two_accounts_is_built() {
        let a = Address::from_public_key(&KeyPair::generate().public).to_string();
        let b = Address::from_public_key(&KeyPair::generate().public).to_string();
        let mut other_currency = op(1, &b, 5);
        other_currency.amount.currency.decimals = 8;
        let mut sub = op(1, &b, 5);
        sub.account.sub_account = Some(json!({"address": "x"}));
        let mut stake = op(1, &b, 5);
        stake.op_type = "STAKE".into();
        for (ops, why) in [
            (vec![op(0, &a, -5)], "one operation"),
            (vec![op(0, &a, -5), op(1, &b, 5), op(2, &b, 0)], "three"),
            (vec![op(0, &a, -5), op(1, &b, 4)], "unequal"),
            (vec![op(0, &a, 5), op(1, &b, 5)], "both positive"),
            (vec![op(0, &a, 0), op(1, &b, 0)], "nothing"),
            (vec![op(0, &a, -5), op(1, &a, 5)], "to itself"),
            (vec![op(0, &a, -5), op(1, "hlxNotAnAddress", 5)], "bad address"),
            (vec![op(0, &a, -5), other_currency], "other currency"),
            (vec![op(0, &a, -5), sub], "sub-account"),
            (vec![op(0, &a, -5), stake], "not a transfer"),
        ] {
            assert!(intent(&ops).is_err(), "{why} must be refused");
        }
        assert!(intent(&[op(0, &b, 5), op(1, &a, -5)]).is_ok(), "order does not matter");
    }

    /// A signature that is not the sender's over exactly this payload never makes a signed
    /// transaction.
    #[test]
    fn only_the_senders_signature_over_this_payload_is_combined() {
        let kp = KeyPair::generate();
        let other = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let intent = Intent { from, to: Address::from_public_key(&other.public), amount: 1 };
        let tx = unsigned(&intent, 0, 1, Hash::ZERO, kp.public.clone(), None);
        let payload = hex::decode(signing_payload(&tx)).unwrap();
        assert!(combine(tx.clone(), &mesh_signature(&tx, &kp, &payload)).is_ok(), "control: the right one");
        assert!(combine(tx.clone(), &mesh_signature(&tx, &kp, b"other bytes")).unwrap_err().contains("does not verify"));
        let mut wrong_key = mesh_signature(&tx, &other, &payload);
        assert!(combine(tx.clone(), &wrong_key).unwrap_err().contains("not the one"));
        wrong_key.public_key = mesh_key(&kp);
        assert!(combine(tx.clone(), &wrong_key).unwrap_err().contains("does not verify"), "a key swapped in");
        let mut ecdsa = mesh_signature(&tx, &kp, &payload);
        ecdsa.signature_type = "ecdsa".into();
        assert!(combine(tx.clone(), &ecdsa).is_err());
        // A key that is not the sender's, built in: the address is a hash of the key.
        let forged = unsigned(&intent, 0, 1, Hash::ZERO, other.public.clone(), None);
        let p = hex::decode(signing_payload(&forged)).unwrap();
        assert!(combine(forged.clone(), &mesh_signature(&forged, &other, &p)).unwrap_err().contains("does not verify"));
    }

    /// The fee is priced on the signed size, by the same rule a wallet uses — for a first
    /// transaction (key carried) and a later one, with and without a memo.
    #[test]
    fn the_fee_is_the_wallets_fee_for_the_signed_transaction() {
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let intent = Intent { from, to: Address::from_public_key(&KeyPair::generate().public), amount: 5 };
        let long = "x".repeat(256);
        for (nonce, memo, base) in [(0, None, 1), (0, Some("ref 7"), 3), (9, None, 1), (9, Some(long.as_str()), 2)] {
            let fee = fee(base, nonce, memo).unwrap();
            let mut tx = unsigned(&intent, nonce, fee, Hash::digest(b"c"), kp.public.clone(), memo);
            tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
            let wallet = helix_core::fee::wallet_auto_fee(base, helix_core::fee::wallet_priced_size(&tx)).unwrap();
            assert_eq!(fee, wallet, "nonce {nonce}, memo {memo:?}");
            assert!(fee >= base * helix_core::fee::wallet_priced_size(&tx), "covers the base fee");
        }
        assert!(fee(1_000_000, 0, None).is_err(), "above 1 HLX is refused, as in the wallets");
    }

    #[test]
    fn a_memo_is_utf8_of_at_most_256_bytes() {
        assert_eq!(memo(Some(&json!({"memo": "Einzahlung Ä"}))).unwrap().as_deref(), Some("Einzahlung Ä"));
        assert_eq!(memo(None).unwrap(), None);
        assert_eq!(memo(Some(&json!({}))).unwrap(), None);
        assert!(memo(Some(&json!({"memo": "x".repeat(257)}))).is_err());
        assert!(memo(Some(&json!({"memo": ""}))).is_err());
        assert!(memo(Some(&json!({"memo": 5}))).is_err());
    }

    #[test]
    fn a_blob_must_be_a_transactions_canonical_bytes() {
        assert!(decode("zz").is_err());
        assert!(decode(&hex::encode([1u8, 2, 3])).is_err());
        let kp = KeyPair::generate();
        let tx = unsigned(&Intent { from: Address::from_public_key(&kp.public), to: Address::from_public_key(&KeyPair::generate().public), amount: 1 }, 0, 1, Hash::ZERO, kp.public.clone(), None);
        let mut longer = encode(&tx);
        longer.push_str("00");
        assert!(decode(&longer).is_err(), "trailing bytes");
        assert!(signed(&encode(&tx)).unwrap_err().contains("not signed"));
    }
}
