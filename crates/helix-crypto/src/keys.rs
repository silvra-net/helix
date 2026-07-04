use pqcrypto_dilithium::dilithium3;
use pqcrypto_sphincsplus::sphincssha2192ssimple as sphincsplus;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

use crate::error::{CryptoError, CryptoResult};
use crate::hash::Hash;

/// Which PQC signature scheme a key or signature belongs to. Each signed
/// artifact (block header, vote) records its own scheme, so the network can
/// migrate to a new algorithm — e.g. if ML-DSA is ever broken or deprecated —
/// without a hard fork: old and new signatures stay independently verifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoScheme {
    /// ML-DSA (Dilithium3) — NIST FIPS 204, initial scheme
    MlDsa = 1,
    /// SLH-DSA (SPHINCS+-SHA2-192s) — NIST FIPS 205, hash-based migration target
    SphincsPlus = 2,
}

impl Default for CryptoScheme {
    fn default() -> Self {
        CryptoScheme::MlDsa
    }
}

impl CryptoScheme {
    pub fn from_tag(tag: u8) -> CryptoResult<Self> {
        match tag {
            1 => Ok(CryptoScheme::MlDsa),
            2 => Ok(CryptoScheme::SphincsPlus),
            other => Err(CryptoError::InvalidPublicKey(format!(
                "unknown crypto scheme tag {other}"
            ))),
        }
    }

    pub fn secret_key_len(self) -> usize {
        match self {
            CryptoScheme::MlDsa => dilithium3::secret_key_bytes(),
            CryptoScheme::SphincsPlus => sphincsplus::secret_key_bytes(),
        }
    }

    pub fn public_key_len(self) -> usize {
        match self {
            CryptoScheme::MlDsa => dilithium3::public_key_bytes(),
            CryptoScheme::SphincsPlus => sphincsplus::public_key_bytes(),
        }
    }
}

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
    /// Only checks the original (default) scheme — callers that need to accept a
    /// migrated SPHINCS+ key should match on an explicit `CryptoScheme` instead.
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

/// A keypair: public + secret key, tagged with the scheme it was generated for
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
    pub scheme: CryptoScheme,
}

impl KeyPair {
    /// Generate a fresh ML-DSA (Dilithium3) keypair — the default scheme
    pub fn generate() -> Self {
        Self::generate_for(CryptoScheme::MlDsa)
    }

    /// Generate a fresh keypair for a specific PQC scheme (used to migrate a
    /// validator or wallet to a new algorithm)
    pub fn generate_for(scheme: CryptoScheme) -> Self {
        match scheme {
            CryptoScheme::MlDsa => {
                let (pk, sk) = dilithium3::keypair();
                KeyPair {
                    public: PublicKey::from_bytes(pk.as_bytes().to_vec()),
                    secret: SecretKey::from_bytes(sk.as_bytes().to_vec()),
                    scheme,
                }
            }
            CryptoScheme::SphincsPlus => {
                let (pk, sk) = sphincsplus::keypair();
                KeyPair {
                    public: PublicKey::from_bytes(pk.as_bytes().to_vec()),
                    secret: SecretKey::from_bytes(sk.as_bytes().to_vec()),
                    scheme,
                }
            }
        }
    }

    /// Reconstruct and structurally validate a keypair from raw bytes previously
    /// produced by `generate_for` (e.g. loaded from a wallet or validator key file).
    pub fn from_raw(scheme: CryptoScheme, secret_bytes: Vec<u8>, public_bytes: Vec<u8>) -> CryptoResult<Self> {
        match scheme {
            CryptoScheme::MlDsa => {
                dilithium3::SecretKey::from_bytes(&secret_bytes)
                    .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
                dilithium3::PublicKey::from_bytes(&public_bytes)
                    .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
            }
            CryptoScheme::SphincsPlus => {
                sphincsplus::SecretKey::from_bytes(&secret_bytes)
                    .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
                sphincsplus::PublicKey::from_bytes(&public_bytes)
                    .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
            }
        }
        Ok(KeyPair {
            public: PublicKey::from_bytes(public_bytes),
            secret: SecretKey::from_bytes(secret_bytes),
            scheme,
        })
    }

    /// Sign a message with the secret key, using this keypair's scheme
    pub fn sign(&self, message: &[u8]) -> CryptoResult<Signature> {
        match self.scheme {
            CryptoScheme::MlDsa => {
                let sk = dilithium3::SecretKey::from_bytes(self.secret.as_bytes())
                    .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
                let sig = dilithium3::detached_sign(message, &sk);
                Ok(Signature::from_bytes(sig.as_bytes().to_vec()))
            }
            CryptoScheme::SphincsPlus => {
                let sk = sphincsplus::SecretKey::from_bytes(self.secret.as_bytes())
                    .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
                let sig = sphincsplus::detached_sign(message, &sk);
                Ok(Signature::from_bytes(sig.as_bytes().to_vec()))
            }
        }
    }
}

/// Verify an ML-DSA signature (the default scheme). For a signature that may have
/// been produced under a migrated scheme, use `verify_with_scheme` instead.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> CryptoResult<()> {
    verify_with_scheme(CryptoScheme::MlDsa, public_key, message, signature)
}

/// Verify a signature under an explicit PQC scheme — lets callers that tag their
/// signed artifacts with a `CryptoScheme` (block headers, votes) verify correctly
/// across a migration, instead of assuming ML-DSA forever.
pub fn verify_with_scheme(
    scheme: CryptoScheme,
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> CryptoResult<()> {
    match scheme {
        CryptoScheme::MlDsa => {
            let pk = dilithium3::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
            let sig = dilithium3::DetachedSignature::from_bytes(signature.as_bytes())
                .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
            dilithium3::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| CryptoError::VerificationFailed)
        }
        CryptoScheme::SphincsPlus => {
            let pk = sphincsplus::PublicKey::from_bytes(public_key.as_bytes())
                .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
            let sig = sphincsplus::DetachedSignature::from_bytes(signature.as_bytes())
                .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
            sphincsplus::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| CryptoError::VerificationFailed)
        }
    }
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

    #[test]
    fn test_sphincsplus_keygen_sign_verify() {
        let kp = KeyPair::generate_for(CryptoScheme::SphincsPlus);
        assert_eq!(kp.scheme, CryptoScheme::SphincsPlus);
        let msg = b"helix migration test message";
        let sig = kp.sign(msg).unwrap();
        assert!(verify_with_scheme(CryptoScheme::SphincsPlus, &kp.public, msg, &sig).is_ok());
    }

    #[test]
    fn test_verify_with_wrong_scheme_fails() {
        // A signature produced under one scheme must not verify under the other,
        // even with the same message and a structurally-parseable key/sig pair.
        let ml_dsa = KeyPair::generate();
        let sphincs = KeyPair::generate_for(CryptoScheme::SphincsPlus);
        let msg = b"cross-scheme message";
        let ml_dsa_sig = ml_dsa.sign(msg).unwrap();
        assert!(verify_with_scheme(CryptoScheme::SphincsPlus, &sphincs.public, msg, &ml_dsa_sig).is_err());
    }

    #[test]
    fn test_keypair_from_raw_roundtrip() {
        let kp = KeyPair::generate_for(CryptoScheme::SphincsPlus);
        let restored = KeyPair::from_raw(
            CryptoScheme::SphincsPlus,
            kp.secret.as_bytes().to_vec(),
            kp.public.as_bytes().to_vec(),
        )
        .unwrap();
        let msg = b"restored keypair still signs correctly";
        let sig = restored.sign(msg).unwrap();
        assert!(verify_with_scheme(CryptoScheme::SphincsPlus, &restored.public, msg, &sig).is_ok());
    }
}
