use serde::{Deserialize, Serialize};
use std::fmt;

/// 32-byte BLAKE3 hash — quantum-resistant by design (hash functions are not
/// broken by Grover's algorithm at this output size)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0u8; 32]);

    pub fn digest(data: &[u8]) -> Self {
        Hash(*blake3::hash(data).as_bytes())
    }

    pub fn digest_many(parts: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for part in parts {
            hasher.update(part);
        }
        Hash(*hasher.finalize().as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Hash(arr))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

/// Compute merkle root from a list of hashes using BLAKE3
pub fn merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return Hash::ZERO;
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut current = hashes.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                next.push(Hash::digest_many(&[
                    current[i].as_bytes(),
                    current[i + 1].as_bytes(),
                ]));
            } else {
                // Duplicate last node if odd count
                next.push(Hash::digest_many(&[
                    current[i].as_bytes(),
                    current[i].as_bytes(),
                ]));
            }
            i += 2;
        }
        current = next;
    }
    current[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_digest() {
        let h1 = Hash::digest(b"helix");
        let h2 = Hash::digest(b"helix");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_hex_roundtrip() {
        let h = Hash::digest(b"helix blockchain");
        let hex = h.to_hex();
        let h2 = Hash::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(merkle_root(&[]), Hash::ZERO);
    }

    #[test]
    fn test_merkle_root_single() {
        let h = Hash::digest(b"tx1");
        assert_eq!(merkle_root(&[h]), h);
    }

    #[test]
    fn test_merkle_root_multiple() {
        let hashes: Vec<Hash> = (0..4).map(|i| Hash::digest(&[i])).collect();
        let root = merkle_root(&hashes);
        assert_ne!(root, Hash::ZERO);
    }
}
