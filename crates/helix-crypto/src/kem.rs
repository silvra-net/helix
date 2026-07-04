use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCtTrait, PublicKey as KemPkTrait, SecretKey as KemSkTrait,
    SharedSecret as KemSsTrait,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{CryptoError, CryptoResult};

/// ML-KEM-768 (Kyber-768, NIST FIPS 203 level 3) encapsulation key.
/// Share this with peers so they can encapsulate a shared secret to you.
/// 1184 bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemEncapsulationKey(Vec<u8>);

impl KemEncapsulationKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-KEM-768 ciphertext produced by `kem_encapsulate`. Send to the holder
/// of the matching `KemKeyPair` so they can recover the shared secret.
/// 1088 bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemCiphertext(Vec<u8>);

impl KemCiphertext {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Ephemeral ML-KEM-768 key pair. Generate one per session — never reuse.
/// The decapsulation key (secret key) is zeroed on drop.
pub struct KemKeyPair {
    pub encapsulation_key: KemEncapsulationKey,
    dk: Vec<u8>,
}

impl Drop for KemKeyPair {
    fn drop(&mut self) {
        self.dk.zeroize();
    }
}

impl KemKeyPair {
    /// Generate a fresh ephemeral ML-KEM-768 key pair.
    pub fn generate() -> Self {
        let (pk, sk) = kyber768::keypair();
        KemKeyPair {
            encapsulation_key: KemEncapsulationKey::from_bytes(pk.as_bytes().to_vec()),
            dk: sk.as_bytes().to_vec(),
        }
    }

    /// Decapsulate a ciphertext produced by `kem_encapsulate` against this
    /// key pair's decapsulation key. Returns the 32-byte shared secret.
    /// Fails if the ciphertext is malformed or was encapsulated to a different key.
    pub fn decapsulate(&self, ct: &KemCiphertext) -> CryptoResult<[u8; 32]> {
        let sk = kyber768::SecretKey::from_bytes(&self.dk)
            .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
        let ct_parsed = kyber768::Ciphertext::from_bytes(ct.as_bytes())
            .map_err(|e| CryptoError::InvalidSignature(format!("bad ML-KEM ciphertext: {e}")))?;
        let ss = kyber768::decapsulate(&ct_parsed, &sk);
        let mut out = [0u8; 32];
        out.copy_from_slice(ss.as_bytes());
        Ok(out)
    }
}

/// Encapsulate a fresh shared secret to `ek`. The ciphertext must be sent to
/// the holder of the matching `KemKeyPair` so they can call `decapsulate`.
///
/// Returns `(ciphertext_to_send, shared_secret)`.
/// The shared secret is 32 bytes — suitable for use as an AEAD key or as
/// input to a KDF like `blake3::derive_key`.
pub fn kem_encapsulate(ek: &KemEncapsulationKey) -> CryptoResult<(KemCiphertext, [u8; 32])> {
    let pk = kyber768::PublicKey::from_bytes(ek.as_bytes())
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
    let (ss, ct) = kyber768::encapsulate(&pk);
    let mut shared = [0u8; 32];
    shared.copy_from_slice(ss.as_bytes());
    Ok((KemCiphertext::from_bytes(ct.as_bytes().to_vec()), shared))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip_produces_matching_shared_secrets() {
        let kp = KemKeyPair::generate();
        let (ct, ss_encap) = kem_encapsulate(&kp.encapsulation_key).unwrap();
        let ss_decap = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss_encap, ss_decap);
    }

    #[test]
    fn kem_different_sessions_produce_different_secrets() {
        let kp = KemKeyPair::generate();
        let (ct1, ss1) = kem_encapsulate(&kp.encapsulation_key).unwrap();
        let (ct2, ss2) = kem_encapsulate(&kp.encapsulation_key).unwrap();
        // Same recipient, fresh encapsulation → different ciphertexts and secrets
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn kem_wrong_key_pair_decapsulate_gives_different_secret() {
        let kp1 = KemKeyPair::generate();
        let kp2 = KemKeyPair::generate();
        let (ct, ss1) = kem_encapsulate(&kp1.encapsulation_key).unwrap();
        // Decapsulate with wrong key — KEM is designed to return a pseudo-random
        // (wrong) secret rather than an error, preventing oracle attacks
        let ss2 = kp2.decapsulate(&ct).unwrap();
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn kem_encapsulation_key_sizes_match_ml_kem_768_spec() {
        let kp = KemKeyPair::generate();
        // ML-KEM-768: ek = 1184 bytes, ciphertext = 1088 bytes, shared secret = 32 bytes
        assert_eq!(kp.encapsulation_key.as_bytes().len(), kyber768::public_key_bytes());
        let (ct, ss) = kem_encapsulate(&kp.encapsulation_key).unwrap();
        assert_eq!(ct.as_bytes().len(), kyber768::ciphertext_bytes());
        assert_eq!(ss.len(), 32);
    }
}
