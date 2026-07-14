//! ZK-STARK Proof of Personhood for Helix validators.
//!
//! # Protocol
//!
//! The personhood authority issues a credential to a verified human:
//! a `secret` value (128-bit field element). The validator derives:
//!
//!   `commitment = secret^(2^63)  mod p`   (p = 2^128 − 45·2^40 + 1)
//!
//! and registers the `commitment` on-chain via `TxType::RegisterPersonhood`.
//!
//! To claim full personhood voting weight (1% cap instead of 0.5%), the
//! validator submits `TxType::ProvePersonhood` with a STARK proof that they
//! know a `secret` such that `secret^(2^63) = commitment` — without ever
//! revealing `secret`.
//!
//! # Security
//!
//! The squaring chain is a VDF-style one-way function over a 128-bit prime
//! field.  The STARK uses Blake3 hashing and 48 FRI queries, drawing its
//! soundness from the query count (which Grover does not weaken) up to the
//! f128 field's ~128-bit ceiling, rather than from Grover-halvable grinding.
//! The personhood authority's secret prevents validators from self-minting
//! credentials — the STARK proves knowledge of the committed secret.

pub mod air;
pub mod prover;

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, StarkField},
    AcceptableOptions, Proof,
};

use air::{PersonhoodAir, PersonhoodInputs};
use prover::PersonhoodProver;

/// A serialized STARK proof of personhood.
///
/// Produced by [`prove_personhood`], verified by [`verify_personhood`].
/// Safe to store in a `TxType::ProvePersonhood` transaction.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PersonhoodProof(pub Vec<u8>);

impl PersonhoodProof {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        PersonhoodProof(bytes)
    }
}

/// Generate a STARK proof that the prover knows `secret` such that
/// `secret^(2^63) = commitment` in the 128-bit prime field.
///
/// `secret` is a 16-byte little-endian encoding of the field element.
///
/// Returns `(proof, commitment_bytes)` where `commitment_bytes` is the 16-byte
/// encoding of the commitment — submit this alongside the proof in the
/// `ProvePersonhood` transaction.
pub fn prove_personhood(secret_bytes: [u8; 16]) -> (PersonhoodProof, [u8; 16]) {
    let secret = BaseElement::new(u128::from_le_bytes(secret_bytes));
    let prover = PersonhoodProver::new();
    let (stark_proof, commitment) = prover.prove(secret);
    let commitment_bytes = commitment.as_int().to_le_bytes();
    let proof_bytes = stark_proof.to_bytes();
    (PersonhoodProof(proof_bytes), commitment_bytes)
}

/// Verify a personhood proof against a public commitment.
///
/// Returns `true` iff the proof is cryptographically valid and the prover
/// knows `secret` such that `secret^(2^63) = commitment`.
pub fn verify_personhood(proof: &PersonhoodProof, commitment_bytes: [u8; 16]) -> bool {
    let commitment = BaseElement::new(u128::from_le_bytes(commitment_bytes));
    let pub_inputs = PersonhoodInputs { commitment };

    let stark_proof = match Proof::from_bytes(&proof.0) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let acceptable = AcceptableOptions::MinConjecturedSecurity(80);
    winterfell::verify::<
        PersonhoodAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(stark_proof, pub_inputs, &acceptable)
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify_personhood_roundtrip() {
        // A secret credential issued by the personhood authority
        let secret = [42u8; 16];
        let (proof, commitment) = prove_personhood(secret);
        assert!(verify_personhood(&proof, commitment), "proof should verify");
    }

    #[test]
    fn verify_rejects_wrong_commitment() {
        let secret = [1u8; 16];
        let (proof, _commitment) = prove_personhood(secret);
        // Tamper: different commitment
        let wrong_commitment = [2u8; 16];
        assert!(
            !verify_personhood(&proof, wrong_commitment),
            "proof against wrong commitment must fail"
        );
    }

    #[test]
    fn verify_rejects_truncated_proof() {
        let (proof, commitment) = prove_personhood([7u8; 16]);
        let truncated = PersonhoodProof(proof.0[..proof.0.len() / 2].to_vec());
        assert!(
            !verify_personhood(&truncated, commitment),
            "truncated proof must fail"
        );
    }

    #[test]
    fn different_secrets_produce_different_commitments() {
        let (_, c1) = prove_personhood([1u8; 16]);
        let (_, c2) = prove_personhood([2u8; 16]);
        assert_ne!(c1, c2);
    }
}
