use core::convert::Infallible;

use ml_dsa::{
    B32, EncodedSignature as MlDsaEncodedSig, EncodedVerifyingKey as MlDsaEncodedVk, Generate,
    KeyExport, KeyInit, Keypair, MlDsa65, Signature as MlDsaSignature, Signer,
    SigningKey as MlDsaSigningKey, Verifier, VerifyingKey as MlDsaVerifyingKey,
};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use slh_dsa::signature::{Signer as SlhSigner, Verifier as SlhVerifier};
use slh_dsa::{
    Sha2_192s, Signature as SlhSignature, SigningKey as SlhSigningKey,
    VerifyingKey as SlhVerifyingKey,
};
use std::fmt;
use zeroize::Zeroize;

use crate::error::{CryptoError, CryptoResult};
use crate::hash::Hash;

/// A `rand_core` 0.10 `CryptoRng` bridged from `rand` 0.8's OS CSPRNG. `slh-dsa`'s key
/// generation is the one primitive here that takes an explicit RNG (ML-DSA and ML-KEM have
/// `getrandom`-backed convenience constructors); this adapter feeds it OS entropy without
/// pulling in a second full `rand` stack. `TryRng<Error = Infallible>` + `TryCryptoRng`
/// blanket-impl into `Rng` + `CryptoRng` in rand_core 0.10.
struct OsCryptoRng;

impl rand_core::TryRng for OsCryptoRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(rand::rngs::OsRng.next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(rand::rngs::OsRng.next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        rand::rngs::OsRng.fill_bytes(dst);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for OsCryptoRng {}

/// Which PQC signature scheme a key or signature belongs to. Each signed
/// artifact (block header, vote) records its own scheme, so the network can
/// migrate to a new algorithm — e.g. if ML-DSA is ever broken or deprecated —
/// without a hard fork: old and new signatures stay independently verifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoScheme {
    /// ML-DSA-65 — NIST FIPS 204, initial scheme
    MlDsa = 1,
    /// SLH-DSA-SHA2-192s — NIST FIPS 205, hash-based migration target
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

    /// Serialized secret-key length in bytes. ML-DSA stores the 32-byte seed (FIPS 204's
    /// "ξ"); the expanded signing key is re-derived from it on load.
    pub fn secret_key_len(self) -> usize {
        match self {
            CryptoScheme::MlDsa => 32,
            // SLH-DSA-SHA2-192s: private key = 4·n = 4·24 bytes (FIPS 205 Table 2).
            CryptoScheme::SphincsPlus => 96,
        }
    }

    pub fn public_key_len(self) -> usize {
        match self {
            // ML-DSA-65 verifying key = 1952 bytes (FIPS 204).
            CryptoScheme::MlDsa => 1952,
            // SLH-DSA-SHA2-192s: public key = 2·n = 2·24 bytes (FIPS 205 Table 2).
            CryptoScheme::SphincsPlus => 48,
        }
    }
}

/// PQC public (verifying) key — opaque scheme-tagged bytes.
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

    /// True if these bytes parse as a structurally valid public key under the given scheme.
    pub fn is_valid_for(&self, scheme: CryptoScheme) -> bool {
        match scheme {
            CryptoScheme::MlDsa => MlDsaEncodedVk::<MlDsa65>::try_from(self.0.as_slice()).is_ok(),
            CryptoScheme::SphincsPlus => {
                SlhVerifyingKey::<Sha2_192s>::try_from(self.0.as_slice()).is_ok()
            }
        }
    }

    /// True if these bytes parse as a structurally valid public key under *any* supported
    /// scheme — so a migrated SPHINCS+ key is accepted just like the default ML-DSA one
    /// (e.g. a social-recovery rotation to the hash-based scheme). Use `is_valid_for` to
    /// require one specific scheme.
    pub fn is_valid(&self) -> bool {
        self.is_valid_for(CryptoScheme::MlDsa) || self.is_valid_for(CryptoScheme::SphincsPlus)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "PublicKey({}...)", &hex[..hex.len().min(16)])
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

/// PQC secret key — zeroed on drop. For ML-DSA this is the 32-byte seed.
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

/// PQC detached signature — opaque scheme-tagged bytes.
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
        let hex = self.to_hex();
        write!(f, "Signature({}...)", &hex[..hex.len().min(16)])
    }
}

/// A keypair: public + secret key, tagged with the scheme it was generated for
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
    pub scheme: CryptoScheme,
}

impl KeyPair {
    /// Generate a fresh ML-DSA-65 keypair — the default scheme
    pub fn generate() -> Self {
        Self::generate_for(CryptoScheme::MlDsa)
    }

    /// Generate a fresh keypair for a specific PQC scheme (used to migrate a
    /// validator or wallet to a new algorithm)
    pub fn generate_for(scheme: CryptoScheme) -> Self {
        match scheme {
            CryptoScheme::MlDsa => {
                let sk = MlDsaSigningKey::<MlDsa65>::generate();
                let vk = sk.verifying_key();
                KeyPair {
                    public: PublicKey::from_bytes(vk.encode().to_vec()),
                    secret: SecretKey::from_bytes(KeyExport::to_bytes(&sk).to_vec()),
                    scheme,
                }
            }
            CryptoScheme::SphincsPlus => {
                let sk = SlhSigningKey::<Sha2_192s>::new(&mut OsCryptoRng);
                let vk = sk.verifying_key();
                KeyPair {
                    public: PublicKey::from_bytes(vk.to_bytes().to_vec()),
                    secret: SecretKey::from_bytes(sk.to_bytes().to_vec()),
                    scheme,
                }
            }
        }
    }

    /// Rebuild an ML-DSA keypair from its 32-byte seed alone — FIPS 204 derives the whole
    /// key deterministically from ξ, so the seed *is* the key.
    ///
    /// This is what makes a 24-word BIP39 backup possible: the seed is exactly the 32 bytes
    /// BIP39 encodes as entropy, so words → seed → keypair → the same address, with no wallet
    /// file involved (see `helix wallet restore`). Only ML-DSA: SLH-DSA's key is not a
    /// re-derivable seed in this way, and callers must keep its file.
    pub fn from_mldsa_seed(seed: &[u8]) -> CryptoResult<Self> {
        let seed = mldsa_seed(seed)?;
        let sk = MlDsaSigningKey::<MlDsa65>::new(&seed);
        let vk = sk.verifying_key();
        Ok(KeyPair {
            public: PublicKey::from_bytes(vk.encode().to_vec()),
            secret: SecretKey::from_bytes(seed.to_vec()),
            scheme: CryptoScheme::MlDsa,
        })
    }

    /// Reconstruct and structurally validate a keypair from raw bytes previously
    /// produced by `generate_for` (e.g. loaded from a wallet or validator key file).
    pub fn from_raw(
        scheme: CryptoScheme,
        secret_bytes: Vec<u8>,
        public_bytes: Vec<u8>,
    ) -> CryptoResult<Self> {
        match scheme {
            CryptoScheme::MlDsa => {
                // Secret is the 32-byte seed; re-derive the verifying key from it and
                // require it to match the stored public key — catches a corrupt/mismatched
                // pair on load rather than at first signature.
                let seed = mldsa_seed(&secret_bytes)?;
                let sk = MlDsaSigningKey::<MlDsa65>::new(&seed);
                let derived = sk.verifying_key().encode().to_vec();
                if derived != public_bytes {
                    return Err(CryptoError::InvalidPublicKey(
                        "ML-DSA public key does not match the secret seed".into(),
                    ));
                }
            }
            CryptoScheme::SphincsPlus => {
                SlhSigningKey::<Sha2_192s>::try_from(secret_bytes.as_slice())
                    .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
                SlhVerifyingKey::<Sha2_192s>::try_from(public_bytes.as_slice())
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
                let seed = mldsa_seed(self.secret.as_bytes())?;
                let sk = MlDsaSigningKey::<MlDsa65>::new(&seed);
                let sig = sk
                    .try_sign(message)
                    .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
                Ok(Signature::from_bytes(sig.encode().to_vec()))
            }
            CryptoScheme::SphincsPlus => {
                let sk = SlhSigningKey::<Sha2_192s>::try_from(self.secret.as_bytes())
                    .map_err(|e| CryptoError::InvalidSecretKey(e.to_string()))?;
                let sig = SlhSigner::try_sign(&sk, message)
                    .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
                Ok(Signature::from_bytes(sig.to_bytes().to_vec()))
            }
        }
    }
}

/// Reconstruct an ML-DSA seed (`B32`) from stored secret bytes.
fn mldsa_seed(bytes: &[u8]) -> CryptoResult<B32> {
    B32::try_from(bytes)
        .map_err(|_| CryptoError::InvalidSecretKey("ML-DSA seed must be 32 bytes".into()))
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
            let enc_vk = MlDsaEncodedVk::<MlDsa65>::try_from(public_key.as_bytes())
                .map_err(|_| CryptoError::InvalidPublicKey("bad ML-DSA public key length".into()))?;
            let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&enc_vk);
            let enc_sig = MlDsaEncodedSig::<MlDsa65>::try_from(signature.as_bytes())
                .map_err(|_| CryptoError::InvalidSignature("bad ML-DSA signature length".into()))?;
            let sig = MlDsaSignature::<MlDsa65>::decode(&enc_sig)
                .ok_or_else(|| CryptoError::InvalidSignature("malformed ML-DSA signature".into()))?;
            vk.verify(message, &sig)
                .map_err(|_| CryptoError::VerificationFailed)
        }
        CryptoScheme::SphincsPlus => {
            let vk = SlhVerifyingKey::<Sha2_192s>::try_from(public_key.as_bytes())
                .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
            let sig = SlhSignature::<Sha2_192s>::try_from(signature.as_bytes())
                .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
            SlhVerifier::verify(&vk, message, &sig).map_err(|_| CryptoError::VerificationFailed)
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
    fn ml_dsa_key_sizes_match_fips_204_level_3() {
        // FIPS 204 ML-DSA-65: verifying key 1952 bytes, signature 3309 bytes, seed 32 bytes.
        let kp = KeyPair::generate();
        assert_eq!(kp.public.as_bytes().len(), 1952);
        assert_eq!(kp.secret.as_bytes().len(), 32);
        let sig = kp.sign(b"x").unwrap();
        assert_eq!(sig.as_bytes().len(), 3309);
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
        // A signature produced under one scheme must not verify under the other.
        let ml_dsa = KeyPair::generate();
        let sphincs = KeyPair::generate_for(CryptoScheme::SphincsPlus);
        let msg = b"cross-scheme message";
        let ml_dsa_sig = ml_dsa.sign(msg).unwrap();
        assert!(
            verify_with_scheme(CryptoScheme::SphincsPlus, &sphincs.public, msg, &ml_dsa_sig).is_err()
        );
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
        assert!(
            verify_with_scheme(CryptoScheme::SphincsPlus, &restored.public, msg, &sig).is_ok()
        );
    }

    #[test]
    fn ml_dsa_from_raw_rejects_mismatched_public() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        // a's seed with b's public key must be rejected.
        let res = KeyPair::from_raw(
            CryptoScheme::MlDsa,
            a.secret.as_bytes().to_vec(),
            b.public.as_bytes().to_vec(),
        );
        assert!(res.is_err());
    }
}
