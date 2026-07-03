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

/// One step of a Merkle inclusion proof: the sibling hash at a tree level, and
/// whether it sits to the right of the node being proven (needed so
/// `verify_merkle_proof` can hash each pair in the same left-right order
/// `merkle_root` used to build the tree — the pairing isn't commutative).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub sibling: Hash,
    pub sibling_is_right: bool,
}

/// Build an inclusion proof for the leaf at `index`, mirroring the exact
/// pairing/duplication rules `merkle_root` uses to build the tree. A light
/// client that trusts a block's `merkle_root` (e.g. from a header it
/// verified) can use this proof to confirm a specific transaction was
/// included in that block, without downloading the block's full body.
/// Returns `None` if `index` is out of bounds.
pub fn merkle_proof(hashes: &[Hash], index: usize) -> Option<Vec<MerkleProofStep>> {
    if index >= hashes.len() {
        return None;
    }

    let mut proof = Vec::new();
    let mut current = hashes.to_vec();
    let mut idx = index;
    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        let mut i = 0;
        while i < current.len() {
            let left = current[i];
            let right = if i + 1 < current.len() { current[i + 1] } else { current[i] };
            if i == idx {
                proof.push(MerkleProofStep { sibling: right, sibling_is_right: true });
            } else if i + 1 == idx {
                proof.push(MerkleProofStep { sibling: left, sibling_is_right: false });
            }
            next.push(Hash::digest_many(&[left.as_bytes(), right.as_bytes()]));
            i += 2;
        }
        idx /= 2;
        current = next;
    }
    Some(proof)
}

/// Verify that `leaf` is included in the tree that produced `root`, given a
/// proof from `merkle_proof`.
pub fn verify_merkle_proof(leaf: Hash, proof: &[MerkleProofStep], root: Hash) -> bool {
    let mut current = leaf;
    for step in proof {
        current = if step.sibling_is_right {
            Hash::digest_many(&[current.as_bytes(), step.sibling.as_bytes()])
        } else {
            Hash::digest_many(&[step.sibling.as_bytes(), current.as_bytes()])
        };
    }
    current == root
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

    #[test]
    fn merkle_proof_verifies_every_leaf_of_a_power_of_two_tree() {
        let hashes: Vec<Hash> = (0..4).map(|i| Hash::digest(&[i])).collect();
        let root = merkle_root(&hashes);
        for (i, leaf) in hashes.iter().enumerate() {
            let proof = merkle_proof(&hashes, i).unwrap();
            assert!(verify_merkle_proof(*leaf, &proof, root), "leaf {i} failed to verify");
        }
    }

    #[test]
    fn merkle_proof_verifies_every_leaf_of_an_odd_sized_tree() {
        // Odd leaf count exercises the "duplicate last node" branch of merkle_root.
        let hashes: Vec<Hash> = (0..5).map(|i| Hash::digest(&[i])).collect();
        let root = merkle_root(&hashes);
        for (i, leaf) in hashes.iter().enumerate() {
            let proof = merkle_proof(&hashes, i).unwrap();
            assert!(verify_merkle_proof(*leaf, &proof, root), "leaf {i} failed to verify");
        }
    }

    #[test]
    fn merkle_proof_of_single_leaf_tree_is_empty_and_leaf_is_the_root() {
        let h = Hash::digest(b"only tx");
        let proof = merkle_proof(&[h], 0).unwrap();
        assert!(proof.is_empty());
        assert!(verify_merkle_proof(h, &proof, h));
    }

    #[test]
    fn merkle_proof_out_of_bounds_index_returns_none() {
        let hashes: Vec<Hash> = (0..3).map(|i| Hash::digest(&[i])).collect();
        assert!(merkle_proof(&hashes, 3).is_none());
    }

    #[test]
    fn verify_merkle_proof_rejects_tampered_leaf() {
        let hashes: Vec<Hash> = (0..4).map(|i| Hash::digest(&[i])).collect();
        let root = merkle_root(&hashes);
        let proof = merkle_proof(&hashes, 2).unwrap();
        let wrong_leaf = Hash::digest(b"not the real tx");
        assert!(!verify_merkle_proof(wrong_leaf, &proof, root));
    }

    #[test]
    fn verify_merkle_proof_rejects_tampered_sibling() {
        let hashes: Vec<Hash> = (0..4).map(|i| Hash::digest(&[i])).collect();
        let root = merkle_root(&hashes);
        let mut proof = merkle_proof(&hashes, 0).unwrap();
        proof[0].sibling = Hash::digest(b"forged sibling");
        assert!(!verify_merkle_proof(hashes[0], &proof, root));
    }
}
