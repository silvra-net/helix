//! UniFFI bindings exposing Helix's *real* transaction signing to mobile apps — built to replace
//! Spark's hand-maintained TypeScript mirror of `helix_core::Transaction`/`TxPayload`
//! (`client/src/services/helixTx.ts`), which has already drifted silently once (2026-07-20: a
//! same-day domain-separation change in `helix-core` broke Spark's signing until someone
//! manually re-derived it from Rust test vectors — see `spark_helix_signing_drift` in project
//! memory for the full incident).
//!
//! A pinned test that fails loudly on drift (the stopgap this crate replaces) still leaves the
//! actual fix — updating a hand-written TS encoder — as manual work every time. This crate
//! removes that work entirely: Spark calls into the real `Transaction::signing_hash()` and
//! `serde_json::to_string(&Transaction)` through a thin FFI boundary, so there is no second
//! implementation left to drift. Kept deliberately narrow — signing and address derivation only,
//! not a general Helix SDK — because that's the one thing that was actually reimplemented and
//! actually broke; `data` payloads for contract/governance/personhood transactions stay the
//! caller's responsibility exactly as before (opaque bytes, not signature-critical structure).

use helix_core::{Transaction, TxType};
use helix_crypto::{Address, KeyPair, Signature};

#[derive(uniffi::Record)]
pub struct UnsignedTx {
    /// Transaction format version — see `helix_core::Transaction::version`.
    pub version: u32,
    /// One of the `TxType` variant names, e.g. "Transfer", "Delegate", "Unjail" — see
    /// `tx_type_from_str` below for the exhaustive, checked list. Deliberately a string rather
    /// than a generated enum binding: it keeps this FFI surface stable even as `TxType` grows
    /// (20 variants as of this writing, still growing), and an unrecognized name fails loudly
    /// as `MobileError::UnknownTxType` instead of silently mis-mapping.
    pub tx_type: String,
    pub from: String,
    pub to: Option<String>,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub data: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct SignedTx {
    /// The exact JSON body `POST /transactions` expects — `serde_json::to_string(&Transaction)`,
    /// nothing hand-assembled. Submit this verbatim as the request body.
    pub json: String,
    /// Hex tx hash (`Transaction::hash()`), for tracking the submission without re-parsing `json`.
    pub tx_hash: String,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("seed must be exactly 32 bytes (got {0})")]
    InvalidSeedLength(u64),
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("invalid address {0:?}: {1}")]
    InvalidAddress(String, String),
    #[error("unknown tx_type {0:?} — see UnsignedTx::tx_type's doc comment for the valid set")]
    UnknownTxType(String),
    #[error("signing failed: {0}")]
    Signing(String),
}

/// Every `TxType` variant, spelled exactly as `UnsignedTx::tx_type` must spell it. A `match`
/// rather than `format!("{:?}", ..)`/`Debug` on the Rust side deliberately: this way the FFI
/// contract can't silently shift if `TxType`'s `Debug` output ever changes, and adding a variant
/// here without adding it to `TxType` (or vice versa) is a compile error via the exhaustive
/// match in this file's tests, not a runtime surprise on either side of the bridge.
fn tx_type_from_str(s: &str) -> Result<TxType, MobileError> {
    Ok(match s {
        "Transfer" => TxType::Transfer,
        "Stake" => TxType::Stake,
        "Unstake" => TxType::Unstake,
        "RegisterIdentity" => TxType::RegisterIdentity,
        "RegisterName" => TxType::RegisterName,
        "RegisterGuardians" => TxType::RegisterGuardians,
        "ApproveRecovery" => TxType::ApproveRecovery,
        "DeployContract" => TxType::DeployContract,
        "CallContract" => TxType::CallContract,
        "CreateProposal" => TxType::CreateProposal,
        "VoteProposal" => TxType::VoteProposal,
        "ProvePersonhood" => TxType::ProvePersonhood,
        "ClaimUnbonded" => TxType::ClaimUnbonded,
        "CancelRecoveryRequest" => TxType::CancelRecoveryRequest,
        "SubmitDoubleSignEvidence" => TxType::SubmitDoubleSignEvidence,
        "Delegate" => TxType::Delegate,
        "Undelegate" => TxType::Undelegate,
        "Redelegate" => TxType::Redelegate,
        "SetCommission" => TxType::SetCommission,
        "Unjail" => TxType::Unjail,
        other => return Err(MobileError::UnknownTxType(other.to_string())),
    })
}

fn keypair_from_seed(seed: &[u8]) -> Result<KeyPair, MobileError> {
    if seed.len() != 32 {
        return Err(MobileError::InvalidSeedLength(seed.len() as u64));
    }
    KeyPair::from_mldsa_seed(seed).map_err(|e| MobileError::KeyDerivation(e.to_string()))
}

/// The `hlx…` address for a 32-byte ML-DSA seed (the same seed a BIP39 phrase encodes) — so a
/// caller never needs its own keygen/address-derivation just to display "this is your address."
#[uniffi::export]
pub fn derive_address(seed: Vec<u8>) -> Result<String, MobileError> {
    let keypair = keypair_from_seed(&seed)?;
    Ok(Address::from_public_key(&keypair.public).to_string())
}

/// Build and sign a Helix transaction, returning the exact JSON body to `POST /transactions`.
/// This is the whole point of the crate: everything below this line is real `helix-core`/
/// `helix-crypto` code, not a reimplementation — `TxType` parsing aside (see
/// `tx_type_from_str`'s doc comment), there is no logic here that could itself drift from the
/// chain's actual signing format, because it *is* the chain's actual signing format.
#[uniffi::export]
pub fn sign_transaction(seed: Vec<u8>, tx: UnsignedTx) -> Result<SignedTx, MobileError> {
    let keypair = keypair_from_seed(&seed)?;
    let from = Address::from_str(&tx.from)
        .map_err(|e| MobileError::InvalidAddress(tx.from.clone(), e.to_string()))?;
    let to = tx
        .to
        .map(|s| Address::from_str(&s).map_err(|e| MobileError::InvalidAddress(s, e.to_string())))
        .transpose()?;
    let tx_type = tx_type_from_str(&tx.tx_type)?;

    let mut signed = Transaction {
        version: tx.version,
        tx_type,
        from,
        to,
        amount: tx.amount,
        fee: tx.fee,
        nonce: tx.nonce,
        data: tx.data,
        crypto_version: keypair.scheme,
        signature: Signature::from_bytes(vec![]),
        public_key: keypair.public.clone(),
    };
    let hash = signed.signing_hash();
    signed.signature = keypair
        .sign(hash.as_bytes())
        .map_err(|e| MobileError::Signing(e.to_string()))?;

    let tx_hash = signed.hash().to_hex();
    let json = serde_json::to_string(&signed).map_err(|e| MobileError::Signing(e.to_string()))?;
    Ok(SignedTx { json, tx_hash })
}

uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    use super::*;

    /// Same seed as the address-derivation vector already pinned in `helix-cli`
    /// (`phrase_and_key_derivation_match_sparks_javascript_implementation`) — one recognizable
    /// fixture across the codebase instead of a new one per test.
    fn test_seed() -> Vec<u8> {
        (0u8..32).collect()
    }

    #[test]
    fn derive_address_matches_the_pinned_spark_vector() {
        let addr = derive_address(test_seed()).unwrap();
        assert_eq!(addr, "hlxZiWwobcPKCRx8qjZECjeitEufkor2NQ1S");
    }

    #[test]
    fn sign_transaction_produces_a_transaction_that_verifies() {
        let seed = test_seed();
        let from = derive_address(seed.clone()).unwrap();
        let signed = sign_transaction(
            seed,
            UnsignedTx {
                version: 1,
                tx_type: "Transfer".to_string(),
                from: from.clone(),
                to: Some(from),
                amount: 100,
                fee: 1,
                nonce: 0,
                data: vec![],
            },
        )
        .unwrap();

        let tx: Transaction = serde_json::from_str(&signed.json).unwrap();
        assert!(tx.verify_signature().is_ok(), "the FFI-signed tx must verify under the real Rust code");
        assert_eq!(tx.hash().to_hex(), signed.tx_hash);
    }

    #[test]
    fn sign_transaction_covers_every_tx_type_string() {
        // Exhaustiveness guard: if TxType grows a variant, this match won't compile until
        // tx_type_from_str is updated too — the FFI contract can't silently fall behind.
        let all: Vec<TxType> = vec![
            TxType::Transfer, TxType::Stake, TxType::Unstake, TxType::RegisterIdentity,
            TxType::RegisterName, TxType::RegisterGuardians, TxType::ApproveRecovery,
            TxType::DeployContract, TxType::CallContract, TxType::CreateProposal,
            TxType::VoteProposal, TxType::ProvePersonhood, TxType::ClaimUnbonded,
            TxType::CancelRecoveryRequest, TxType::SubmitDoubleSignEvidence, TxType::Delegate,
            TxType::Undelegate, TxType::Redelegate, TxType::SetCommission, TxType::Unjail,
        ];
        for variant in all {
            let name = match &variant {
                TxType::Transfer => "Transfer",
                TxType::Stake => "Stake",
                TxType::Unstake => "Unstake",
                TxType::RegisterIdentity => "RegisterIdentity",
                TxType::RegisterName => "RegisterName",
                TxType::RegisterGuardians => "RegisterGuardians",
                TxType::ApproveRecovery => "ApproveRecovery",
                TxType::DeployContract => "DeployContract",
                TxType::CallContract => "CallContract",
                TxType::CreateProposal => "CreateProposal",
                TxType::VoteProposal => "VoteProposal",
                TxType::ProvePersonhood => "ProvePersonhood",
                TxType::ClaimUnbonded => "ClaimUnbonded",
                TxType::CancelRecoveryRequest => "CancelRecoveryRequest",
                TxType::SubmitDoubleSignEvidence => "SubmitDoubleSignEvidence",
                TxType::Delegate => "Delegate",
                TxType::Undelegate => "Undelegate",
                TxType::Redelegate => "Redelegate",
                TxType::SetCommission => "SetCommission",
                TxType::Unjail => "Unjail",
            };
            assert_eq!(tx_type_from_str(name).unwrap(), variant);
        }
    }

    #[test]
    fn unknown_tx_type_is_a_named_error_not_a_panic() {
        assert!(matches!(
            tx_type_from_str("NotARealType"),
            Err(MobileError::UnknownTxType(_))
        ));
    }

    #[test]
    fn wrong_length_seed_is_rejected() {
        assert!(matches!(
            derive_address(vec![0u8; 31]),
            Err(MobileError::InvalidSeedLength(31))
        ));
    }
}
