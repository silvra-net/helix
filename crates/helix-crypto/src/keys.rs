use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

use crate::error::{CryptoError, CryptoResult};
use crate::hash::Hash;

/// ML-DSA (Dilithium3) public key — NIST security level 3
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        PublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        Ok(PublicKey(hex::decode(s)?))
    }

    /// Fingerprint: first 8 bytes of BLAKE3(pubkey) as hex
    pub fn fingerprint(&self) -> String {
        let h = Hash::digest(&self.0);
        hex::encode(&h.as_bytes()[..8])
    }

    /// True if these bytes parse as a structurally valid ML-DSA (Dilithium3) public key.
    pub fn is_valid(&self) -> bool {
        dilithium3::PublicKey::from_bytes(&self.0).is_ok()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}...)", &self.to_hex()[..16])
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

/// ML-DSA (Dilithium3) secret key — zeroed on drop
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        SecretKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-DSA detached signature
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(Vec<u8>);

impl Signature {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Signature(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        Ok(Signature(hex::decode(s)?))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}...)", &self.to_hex()[..16])
    }
}

/// A keypair: public + secret key
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl KeyPair {
    /// Generate a fresh ML-DSA (Dilithium3) keypair
    pub fn generate() -> Self {
        let (pk, sk) = dilithium3::keypair();
        KeyPair {
            public: PublicKey::from_bytes(pk.as_bytes().to_vec()),
            secret: SecretKey::from_bytes(sk.as_bytes().to_vec()),
        }
    }

    /// Sign a message with the secret key (ML-DSA detached signature)
    pub fn sign(&self, message: &[u8]) -> CryptoResult<Signature> {
        let sk = dilithium3::SecretKey::from_bytes(self.secret.as_bytes())
            .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
        let sig = dilithium3::detached_sign(message, &sk);
        Ok(Signature::from_bytes(sig.as_bytes().to_vec()))
    }
}

/// Verify a ML-DSA signature
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> CryptoResult<()> {
    let pk = dilithium3::PublicKey::from_bytes(public_key.as_bytes())
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
    let sig = dilithium3::DetachedSignature::from_bytes(signature.as_bytes())
        .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
    dilithium3::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sign_verify() {
        let kp = KeyPair::generate();
        let msg = b"helix blockchain test message";
        let sig = kp.sign(msg).unwrap();
        assert!(verify(&kp.public, msg, &sig).is_ok());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let kp = KeyPair::generate();
        let sig = kp.sign(b"correct message").unwrap();
        assert!(verify(&kp.public, b"wrong message", &sig).is_err());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let sig = kp1.sign(b"message").unwrap();
        assert!(verify(&kp2.public, b"message", &sig).is_err());
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let kp = KeyPair::generate();
        let hex = kp.public.to_hex();
        let pk2 = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(kp.public, pk2);
    }
}
