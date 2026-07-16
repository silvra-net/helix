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

    /// Valid hex of the wrong length is an error, not a panic. `copy_from_slice` asserts on a
    /// length mismatch, and this parses hashes straight out of URLs: `GET /transactions/abcd`
    /// was decoding two bytes into a 32-byte array and taking the worker task down with it,
    /// from anywhere on the internet, no authentication involved.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
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

/// Domain-separation tags for Merkle hashing (RFC 6962 style). A leaf and an
/// internal node are hashed with distinct one-byte prefixes so their preimages
/// can never coincide — without this, an internal node's hash `H(A‖B)` could be
/// presented as if it were a single leaf, letting an attacker forge an inclusion
/// proof for data that was never a real leaf, or build a different tree with the
/// same root. Helix serves SPV inclusion proofs (`/blocks/height/:n/proof/:tx`),
/// so this is a real proof-forgery defense, not just theory.
const MERKLE_LEAF_PREFIX: u8 = 0x00;
const MERKLE_NODE_PREFIX: u8 = 0x01;

/// Hash a leaf value into its domain-separated Merkle leaf node.
fn merkle_leaf_hash(leaf: &Hash) -> Hash {
    Hash::digest_many(&[&[MERKLE_LEAF_PREFIX], leaf.as_bytes()])
}

/// Combine two child hashes into their domain-separated internal Merkle node.
fn merkle_node_hash(left: &Hash, right: &Hash) -> Hash {
    Hash::digest_many(&[&[MERKLE_NODE_PREFIX], left.as_bytes(), right.as_bytes()])
}

/// Compute a domain-separated BLAKE3 Merkle root over a list of leaf hashes.
pub fn merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return Hash::ZERO;
    }

    let mut current: Vec<Hash> = hashes.iter().map(merkle_leaf_hash).collect();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            // Duplicate the last node when the count is odd.
            let right = if i + 1 < current.len() { &current[i + 1] } else { &current[i] };
            next.push(merkle_node_hash(&current[i], right));
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
    let mut current: Vec<Hash> = hashes.iter().map(merkle_leaf_hash).collect();
    let mut idx = index;
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            let left = current[i];
            let right = if i + 1 < current.len() { current[i + 1] } else { current[i] };
            if i == idx {
                proof.push(MerkleProofStep { sibling: right, sibling_is_right: true });
            } else if i + 1 == idx {
                proof.push(MerkleProofStep { sibling: left, sibling_is_right: false });
            }
            next.push(merkle_node_hash(&left, &right));
            i += 2;
        }
        idx /= 2;
        current = next;
    }
    Some(proof)
}

/// Verify that `leaf` is included in the tree that produced `root`, given a
/// proof from `merkle_proof`. `leaf` is the raw leaf value (e.g. a tx hash); it
/// is domain-separated into its leaf node here, mirroring `merkle_root`.
pub fn verify_merkle_proof(leaf: Hash, proof: &[MerkleProofStep], root: Hash) -> bool {
    let mut current = merkle_leaf_hash(&leaf);
    for step in proof {
        current = if step.sibling_is_right {
            merkle_node_hash(&current, &step.sibling)
        } else {
            merkle_node_hash(&step.sibling, &current)
        };
    }
    current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `GET /transactions/abcd` panicked the RPC worker on the live node: valid hex, wrong
    /// length, straight into `copy_from_slice`. Hashes are parsed from URLs, so anyone on the
    /// internet could reach this. Every length that isn't 32 bytes must come back as an error.
    #[test]
    fn hex_of_the_wrong_length_is_an_error_and_not_a_panic() {
        for s in ["abcd", "", "ab", &"00".repeat(31), &"00".repeat(33)] {
            assert!(Hash::from_hex(s).is_err(), "{s:?} must not parse as a hash");
        }
        assert!(Hash::from_hex("zz".repeat(32).as_str()).is_err(), "non-hex must still error");
        assert!(Hash::from_hex(&"00".repeat(32)).is_ok(), "a real 32-byte hash still parses");
    }

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
        // With leaf domain separation the single-leaf root is H(0x00 ‖ leaf), not the
        // raw leaf — but it must still be deterministic and non-trivial.
        let h = Hash::digest(b"tx1");
        let root = merkle_root(&[h]);
        assert_ne!(root, Hash::ZERO);
        assert_ne!(root, h, "domain separation: a leaf must not equal the root verbatim");
        assert_eq!(root, merkle_root(&[h]));
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
    fn merkle_proof_of_single_leaf_tree_is_empty_and_verifies_against_the_root() {
        let h = Hash::digest(b"only tx");
        let root = merkle_root(&[h]);
        let proof = merkle_proof(&[h], 0).unwrap();
        assert!(proof.is_empty());
        assert!(verify_merkle_proof(h, &proof, root));
    }

    #[test]
    fn internal_node_hash_cannot_be_passed_off_as_a_leaf() {
        // Second-preimage defense: take a real 2-leaf tree's internal node (its root)
        // and try to prove *it* is a leaf of that same tree. Domain separation makes the
        // leaf hashing (0x00 prefix) differ from the node hashing (0x01 prefix), so this
        // must fail — without separation, an empty proof would "verify" the root as a leaf.
        let a = Hash::digest(b"tx-a");
        let b = Hash::digest(b"tx-b");
        let root = merkle_root(&[a, b]);
        // An attacker claims `root` is itself a leaf with an empty proof.
        assert!(!verify_merkle_proof(root, &[], root));
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
