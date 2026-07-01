use helix_crypto::{merkle_root, Address, Hash, Signature};
use serde::{Deserialize, Serialize};

use crate::transaction::Transaction;

/// The signing algorithm version used by the block proposer.
/// Bumped during quantum migration to a new PQC scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoVersion {
    /// ML-DSA (Dilithium3) — NIST PQC standard, initial version
    MlDsa = 1,
}

impl Default for CryptoVersion {
    fn default() -> Self {
        CryptoVersion::MlDsa
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Helix protocol version
    pub version: u32,
    /// Block height (genesis = 0)
    pub height: u64,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Hash of the previous block header
    pub prev_hash: Hash,
    /// BLAKE3 merkle root of all transaction hashes
    pub merkle_root: Hash,
    /// Address of the validator that proposed this block
    pub validator: Address,
    /// Which crypto scheme the validator used — supports migration
    pub crypto_version: CryptoVersion,
    /// ML-DSA signature over the canonical header hash
    pub signature: Signature,
}

impl BlockHeader {
    /// Hash of all header fields except the signature (what the validator signs)
    pub fn signing_hash(&self) -> Hash {
        Hash::digest_many(&[
            &self.version.to_le_bytes(),
            &self.height.to_le_bytes(),
            &self.timestamp.to_le_bytes(),
            self.prev_hash.as_bytes(),
            self.merkle_root.as_bytes(),
            self.validator.as_str().as_bytes(),
            &[self.crypto_version as u8],
        ])
    }

    /// Full header hash including the signature — used as block ID
    pub fn hash(&self) -> Hash {
        let payload = bincode::serialize(self).expect("serialization is infallible");
        Hash::digest(&payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Recompute and verify the merkle root matches the header
    pub fn verify_merkle_root(&self) -> bool {
        let tx_hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.hash()).collect();
        merkle_root(&tx_hashes) == self.header.merkle_root
    }

    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
}

/// Genesis block — the first block, height 0, no parent
pub fn genesis_block(validator: Address, signature: Signature) -> Block {
    let header = BlockHeader {
        version: 1,
        height: 0,
        timestamp: 0,
        prev_hash: Hash::ZERO,
        merkle_root: Hash::ZERO,
        validator,
        crypto_version: CryptoVersion::MlDsa,
        signature,
    };
    Block {
        header,
        transactions: vec![],
    }
}
