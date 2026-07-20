use helix_crypto::{merkle_proof, merkle_root, Address, Hash, MerkleProofStep, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::transaction::Transaction;

/// The signing algorithm used by the block proposer for this header.
/// Bumped during quantum migration to a new PQC scheme — see `helix_crypto::CryptoScheme`
/// for the schemes themselves and how verification dispatches on this tag.
pub use helix_crypto::CryptoScheme as CryptoVersion;

/// The exact bytes a **precommit** vote signs, given the (height, round, block_hash,
/// crypto_version) it committed to. Lives here — not in `helix-consensus`, where the real
/// `Vote` type and its `signing_bytes()` live — because `CommitSig` (below) needs it and
/// `helix-core` cannot depend back on `helix-consensus` (the dependency already runs the other
/// way). `helix-consensus::Vote::signing_bytes()`'s `Precommit` arm calls this directly so the
/// two can never drift apart into two different "what a precommit signs" definitions.
pub fn precommit_signing_bytes(
    height: u64,
    round: u32,
    block_hash: &Hash,
    crypto_version: CryptoVersion,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"helix-vote-v1:");
    bytes.extend_from_slice(b"precommit:");
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&round.to_le_bytes());
    bytes.extend_from_slice(block_hash.as_bytes());
    bytes.push(crypto_version as u8);
    bytes
}

/// One validator's precommit signature, carried in the *next* block's header as proof that
/// this validator participated in finalizing the block this header's `prev_hash` points to.
/// Self-verifying (like a `Vote`, which this is a trimmed copy of) — `height`/`block_hash`
/// aren't stored here because they're always the parent block's, known to the verifier from
/// context, not from the signer's say-so.
///
/// This is the data downtime-jailing counts from: `helix-executor::ChainState` walks a new
/// block's `last_commit`, and any current validator whose address is absent gets a miss
/// recorded against it. A proposer can only ever hurt an honest validator's count by omitting
/// a real signature it holds — it can't fabricate one, `verify()` below is the reason why —
/// and round-robin proposer rotation means that omission can't persist past the next honest
/// proposer's turn, which will include the real signature and reset the count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitSig {
    pub validator: Address,
    /// Travels with the signature for the same reason `Vote::public_key`/
    /// `BlockHeader::public_key` do — `Address` is one-way.
    pub public_key: PublicKey,
    pub crypto_version: CryptoVersion,
    /// The round (within the parent height) this precommit was cast in.
    pub round: u32,
    pub signature: Signature,
}

impl CommitSig {
    /// Verify this signature is a genuine precommit for `(height, block_hash)` — i.e. that
    /// `public_key` derives `validator` and really signed this exact commitment. Doesn't check
    /// that `validator` was actually a validator at that height, or that enough `CommitSig`s
    /// together reach quorum — callers with access to the validator set check membership
    /// themselves (same accepted-approximation pattern as proof-of-lock verification: the
    /// *current* validator set is used, not a historical snapshot, since Helix doesn't keep
    /// one — see `verify_pol`'s doc comment). `last_commit` exists to feed the downtime
    /// counter, not to re-prove the parent block's finality (that's already established by
    /// `prev_hash` chaining and the engine's own live quorum tracking).
    pub fn verify(&self, height: u64, block_hash: &Hash) -> helix_crypto::CryptoResult<()> {
        if Address::from_public_key(&self.public_key) != self.validator {
            return Err(helix_crypto::CryptoError::InvalidPublicKey(
                "commit sig public key does not derive declared validator address".into(),
            ));
        }
        let bytes = precommit_signing_bytes(height, self.round, block_hash, self.crypto_version);
        helix_crypto::verify_with_scheme(self.crypto_version, &self.public_key, &bytes, &self.signature)
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
    /// Public key of the proposing validator. `Address` is one-way so the key
    /// must travel with the header for `signature` to be self-verifiable —
    /// same pattern as `Vote::public_key`.
    pub public_key: PublicKey,
    /// Which crypto scheme the validator used — supports migration
    pub crypto_version: CryptoVersion,
    /// EIP-1559-style base fee for this block, in nano-HLX **per transaction byte**. Every
    /// transaction in the block must pay at least `base_fee_per_byte × its_serialized_size`,
    /// and exactly that portion of its fee is burned (the remainder is the validator's tip).
    /// Deterministically derived from the parent block's fullness (`fee::next_base_fee_per_byte`)
    /// so every node computes the same value — it is part of the signed header and re-checked
    /// on validation, not something the proposer may pick freely.
    pub base_fee_per_byte: u64,
    /// The precommit signatures that finalized the *parent* block (`prev_hash`) — proof of
    /// who actually participated, carried one block late because a block can't contain its
    /// own not-yet-formed commit. Empty for genesis (no parent to attest) and, in practice,
    /// for any single-validator height (a lone validator's own precommit is enough for
    /// quorum without needing to prove it to anyone). Feeds downtime-jailing in
    /// `helix-executor::ChainState` — see `CommitSig`'s doc comment for the trust model.
    pub last_commit: Vec<CommitSig>,
    /// Signature over the canonical signing hash (excludes `signature` itself)
    pub signature: Signature,
}

impl BlockHeader {
    /// Hash of all header fields except the signature (what the validator signs)
    pub fn signing_hash(&self) -> Hash {
        // The leading domain tag separates a block-header signature from a vote or
        // transaction signature (each has its own tag). The field layout stays
        // unambiguous — every field is fixed-length except `validator`, which is the
        // only variable-length field and is followed only by fixed-length fields
        // (crypto_version byte + base_fee_per_byte + the last_commit hash below), so the
        // concatenation has a single possible parse. `last_commit` itself is variable-length
        // (a `Vec<CommitSig>`) — rather than extend that "only one variable field" argument to
        // a second field, it's folded in as its own fixed-size (32-byte) digest, exactly like
        // `merkle_root` already stands in for the variable-length transaction list.
        let last_commit_bytes = bincode::serialize(&self.last_commit)
            .expect("CommitSig vec serialization is infallible");
        let last_commit_hash = Hash::digest(&last_commit_bytes);
        Hash::digest_many(&[
            b"helix-block-header-v1:",
            &self.version.to_le_bytes(),
            &self.height.to_le_bytes(),
            &self.timestamp.to_le_bytes(),
            self.prev_hash.as_bytes(),
            self.merkle_root.as_bytes(),
            self.validator.as_str().as_bytes(),
            &[self.crypto_version as u8],
            &self.base_fee_per_byte.to_le_bytes(),
            last_commit_hash.as_bytes(),
        ])
    }

    /// Verify that `public_key` derives `validator` and that `signature` is
    /// valid under this header's declared `crypto_version`. Returns an error
    /// if either check fails — callers should reject the block.
    pub fn verify_signature(&self) -> helix_crypto::CryptoResult<()> {
        if Address::from_public_key(&self.public_key) != self.validator {
            return Err(helix_crypto::CryptoError::InvalidPublicKey(
                "block proposer public key does not derive declared validator address".into(),
            ));
        }
        helix_crypto::verify_with_scheme(
            self.crypto_version,
            &self.public_key,
            self.signing_hash().as_bytes(),
            &self.signature,
        )
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

    /// Build a Merkle inclusion proof for the transaction at `index`. A light
    /// client that trusts this block's header (and hence its `merkle_root`)
    /// can use the proof to confirm the transaction was included, without
    /// downloading the block's full transaction list.
    pub fn merkle_proof_for(&self, index: usize) -> Option<Vec<MerkleProofStep>> {
        let tx_hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.hash()).collect();
        merkle_proof(&tx_hashes, index)
    }
}

/// Genesis block — the first block, height 0, no parent
pub fn genesis_block(validator: Address, public_key: PublicKey, signature: Signature) -> Block {
    let header = BlockHeader {
        version: 1,
        height: 0,
        timestamp: 0,
        prev_hash: Hash::ZERO,
        merkle_root: Hash::ZERO,
        validator,
        public_key,
        crypto_version: CryptoVersion::MlDsa,
        base_fee_per_byte: crate::fee::INITIAL_BASE_FEE_PER_BYTE,
        last_commit: vec![],
        signature,
    };
    Block {
        header,
        transactions: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Transaction, TxType};
    use helix_crypto::{PublicKey, Signature as Sig};

    fn tx(nonce: u64) -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: Address::from_public_key(&PublicKey::from_bytes(vec![1, 2, 3])),
            to: Some(Address::from_public_key(&PublicKey::from_bytes(vec![4, 5, 6]))),
            amount: 10,
            fee: 1,
            nonce,
            data: vec![],
            crypto_version: Default::default(),
            signature: Sig::from_bytes(vec![]),
            public_key: PublicKey::from_bytes(vec![]),
        }
    }

    /// A light client holding only a block's header can verify a specific
    /// transaction was included in that block via `merkle_proof_for`, without
    /// ever seeing the block's other transactions.
    #[test]
    fn merkle_proof_for_matches_block_header_merkle_root() {
        let transactions: Vec<Transaction> = (0..5).map(tx).collect();
        let tx_hashes: Vec<Hash> = transactions.iter().map(|t| t.hash()).collect();
        let root = merkle_root(&tx_hashes);

        let block = Block {
            header: BlockHeader {
                version: 1,
                height: 1,
                timestamp: 0,
                prev_hash: Hash::ZERO,
                merkle_root: root,
                validator: Address::from_public_key(&PublicKey::from_bytes(vec![9])),
                public_key: PublicKey::from_bytes(vec![9]),
                crypto_version: CryptoVersion::MlDsa,
                base_fee_per_byte: crate::fee::INITIAL_BASE_FEE_PER_BYTE,
                last_commit: vec![],
                signature: Sig::from_bytes(vec![]),
            },
            transactions,
        };

        for (i, leaf) in tx_hashes.iter().enumerate() {
            let proof = block.merkle_proof_for(i).unwrap();
            assert!(helix_crypto::verify_merkle_proof(*leaf, &proof, block.header.merkle_root));
        }
    }

    fn signed_test_block(kp: &helix_crypto::KeyPair) -> Block {
        let addr = Address::from_public_key(&kp.public);
        let mut block = genesis_block(addr, kp.public.clone(), Sig::from_bytes(vec![]));
        let sig = kp.sign(block.header.signing_hash().as_bytes()).unwrap();
        block.header.signature = sig;
        block
    }

    #[test]
    fn verify_signature_accepts_valid_proposer_signature() {
        use helix_crypto::KeyPair;
        let kp = KeyPair::generate();
        let block = signed_test_block(&kp);
        assert!(block.header.verify_signature().is_ok());
    }

    #[test]
    fn verify_signature_rejects_wrong_public_key() {
        use helix_crypto::KeyPair;
        let kp = KeyPair::generate();
        let other = KeyPair::generate();
        let mut block = signed_test_block(&kp);
        // Swap in a different public key — address won't match
        block.header.public_key = other.public.clone();
        assert!(block.header.verify_signature().is_err());
    }

    #[test]
    fn verify_signature_rejects_tampered_content() {
        use helix_crypto::KeyPair;
        let kp = KeyPair::generate();
        let mut block = signed_test_block(&kp);
        // Tamper with the block height after signing — signing_hash changes
        block.header.height = 99;
        assert!(block.header.verify_signature().is_err());
    }

    #[test]
    fn merkle_proof_for_out_of_bounds_index_is_none() {
        let pk = PublicKey::from_bytes(vec![1]);
        let block = genesis_block(
            Address::from_public_key(&pk),
            pk,
            Sig::from_bytes(vec![]),
        );
        assert!(block.merkle_proof_for(0).is_none());
    }
}
