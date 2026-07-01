use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::{CryptoError, CryptoResult};
use crate::hash::Hash;
use crate::keys::PublicKey;

const ADDRESS_PREFIX: &str = "hlx";
const CHECKSUM_LEN: usize = 4;

/// A Helix address: `hlx1` + base58(blake3(pubkey)[0..20] + checksum)
///
/// Derived from the ML-DSA public key — changing the key algorithm bumps
/// the version byte so old and new addresses can coexist during migration.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(String);

impl Address {
    /// Derive address from a ML-DSA public key (version 1)
    pub fn from_public_key(pk: &PublicKey) -> Self {
        let full_hash = Hash::digest(pk.as_bytes());
        let body = &full_hash.as_bytes()[..20];

        // version byte is included in checksum input so tampering with it is detected
        let mut versioned = Vec::with_capacity(21);
        versioned.push(0x01u8); // version byte — bumped on algo migration
        versioned.extend_from_slice(body);

        let checksum_hash = Hash::digest(&Hash::digest(&versioned).as_bytes()[..]);
        let checksum = &checksum_hash.as_bytes()[..CHECKSUM_LEN];

        let mut data = versioned;
        data.extend_from_slice(checksum);

        Address(format!("{}{}", ADDRESS_PREFIX, bs58::encode(data).into_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_str(s: &str) -> CryptoResult<Self> {
        if !s.starts_with(ADDRESS_PREFIX) {
            return Err(CryptoError::InvalidAddress(format!(
                "missing '{}' prefix",
                ADDRESS_PREFIX
            )));
        }
        let encoded = &s[ADDRESS_PREFIX.len()..];
        let data = bs58::decode(encoded)
            .into_vec()
            .map_err(|e| CryptoError::InvalidAddress(e.to_string()))?;

        if data.len() < 1 + 20 + CHECKSUM_LEN {
            return Err(CryptoError::InvalidAddress("too short".into()));
        }

        let payload = &data[..data.len() - CHECKSUM_LEN];
        let checksum = &data[data.len() - CHECKSUM_LEN..];
        let expected_hash = Hash::digest(&Hash::digest(payload).as_bytes()[..]);
        let expected = &expected_hash.as_bytes()[..CHECKSUM_LEN];

        if checksum != expected {
            return Err(CryptoError::InvalidAddress("checksum mismatch".into()));
        }

        Ok(Address(s.to_string()))
    }

    /// Version byte — determines which signing algorithm this address uses
    pub fn version(&self) -> Option<u8> {
        let encoded = &self.0[ADDRESS_PREFIX.len()..];
        bs58::decode(encoded)
            .into_vec()
            .ok()
            .and_then(|d| d.first().copied())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.0)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_address_from_pubkey() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        assert!(addr.as_str().starts_with("hlx"));
    }

    #[test]
    fn test_address_deterministic() {
        let kp = KeyPair::generate();
        let a1 = Address::from_public_key(&kp.public);
        let a2 = Address::from_public_key(&kp.public);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_address_roundtrip() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let parsed = Address::from_str(addr.as_str()).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_address_version() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        assert_eq!(addr.version(), Some(0x01));
    }

    #[test]
    fn test_invalid_address_rejected() {
        assert!(Address::from_str("invalid").is_err());
        assert!(Address::from_str("hlx1corrupted!!").is_err());
    }
}
