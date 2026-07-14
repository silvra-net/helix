use ml_kem::{
    Ciphertext as MlKemCiphertext, Decapsulate, DecapsulationKey as MlKemDk,
    Encapsulate, EncapsulationKey as MlKemEk, Kem, KeyExport, KeyInit, MlKem768, TryKeyInit,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{CryptoError, CryptoResult};

/// ML-KEM-768 (NIST FIPS 203, security level 3) encapsulation key.
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
        let (dk, ek) = MlKem768::generate_keypair();
        KemKeyPair {
            encapsulation_key: KemEncapsulationKey::from_bytes(KeyExport::to_bytes(&ek).to_vec()),
            dk: KeyExport::to_bytes(&dk).to_vec(),
        }
    }

    /// Decapsulate a ciphertext produced by `kem_encapsulate` against this
    /// key pair's decapsulation key. Returns the 32-byte shared secret.
    /// Fails only if the stored key or ciphertext bytes are malformed —
    /// a *wrong* (mismatched) ciphertext yields a pseudo-random secret by
    /// design (implicit rejection), not an error.
    pub fn decapsulate(&self, ct: &KemCiphertext) -> CryptoResult<[u8; 32]> {
        let dk = MlKemDk::<MlKem768>::new_from_slice(self.dk.as_slice())
            .map_err(|_| CryptoError::InvalidSecretKey("bad ML-KEM decapsulation key".into()))?;
        let ct_arr = MlKemCiphertext::<MlKem768>::try_from(ct.as_bytes())
            .map_err(|_| CryptoError::InvalidSignature("bad ML-KEM ciphertext".into()))?;
        let ss = dk.decapsulate(&ct_arr);
        let mut out = [0u8; 32];
        out.copy_from_slice(&ss);
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
    let ek = MlKemEk::<MlKem768>::new_from_slice(ek.as_bytes())
        .map_err(|_| CryptoError::InvalidPublicKey("bad ML-KEM encapsulation key".into()))?;
    let (ct, ss) = ek.encapsulate();
    let mut shared = [0u8; 32];
    shared.copy_from_slice(&ss);
    Ok((KemCiphertext::from_bytes(ct.to_vec()), shared))
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
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn kem_wrong_key_pair_decapsulate_gives_different_secret() {
        let kp1 = KemKeyPair::generate();
        let kp2 = KemKeyPair::generate();
        let (ct, ss1) = kem_encapsulate(&kp1.encapsulation_key).unwrap();
        // Implicit rejection: decapsulating with the wrong key returns a pseudo-random
        // (wrong) secret rather than an error, preventing chosen-ciphertext oracle attacks.
        let ss2 = kp2.decapsulate(&ct).unwrap();
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn kem_key_and_ciphertext_sizes_match_ml_kem_768_spec() {
        let kp = KemKeyPair::generate();
        // ML-KEM-768: ek = 1184 bytes, ciphertext = 1088 bytes, shared secret = 32 bytes.
        assert_eq!(kp.encapsulation_key.as_bytes().len(), 1184);
        let (ct, ss) = kem_encapsulate(&kp.encapsulation_key).unwrap();
        assert_eq!(ct.as_bytes().len(), 1088);
        assert_eq!(ss.len(), 32);
    }
}
