//! Blocks on the gossip wire without the transactions the receiver already holds (#235).
//!
//! Every transaction is gossiped on its own lane when it is submitted, so by the time a block
//! that carries it is proposed, nearly every node already holds it in its pool. Sending it again
//! inside the proposal — and again inside the committed block every validator publishes after
//! finality — made each transaction cross each link up to three times. Measured under a flood
//! (#235): the links carried ~200 MB for ~22 MB of transactions, a validator's uplink was full,
//! and block time was bound by it.
//!
//! A compact block is the header plus one reference per transaction: its id
//! ([`Transaction::hash`], which is the same whether or not the sender's key travels with it) and
//! whether the block's copy carries that key. The flag is not optional detail: since #243 one
//! transaction is two different byte strings, and the header's Merkle root commits to exactly one
//! of them. The receiver rebuilds the block from its own pool and checks the result against that
//! root. The header is signed and its hash is the block's hash, so a rebuilt block that passes the
//! check *is* the block, byte for byte — consensus and execution see exactly what they saw when
//! the whole block travelled.
//!
//! A receiver that lacks a transaction does not guess. For a proposal it asks a peer for the whole
//! thing over round sync, which still carries full blocks; for a committed block it catches up over
//! block sync. Nothing here is trusted: a reference to a transaction nobody gossiped fails the
//! lookup, and a wrong key flag — or anything else that does not match — fails the root check.

use helix_consensus::{Proposal, Vote};
use helix_core::{Block, BlockHeader, Transaction};
use helix_crypto::Hash;
use serde::{Deserialize, Serialize};

/// One transaction of a compact block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxRef {
    /// [`Transaction::hash`] — the id wallets and pools know it by.
    pub id: Hash,
    /// Whether the block's copy carries the sender's public key (#243).
    pub carries_key: bool,
}

/// A block as it travels on the gossip wire: its header, and which transactions it carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactBlock {
    pub header: BlockHeader,
    pub transactions: Vec<TxRef>,
}

/// A [`Proposal`] as it travels on the gossip wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactProposal {
    pub round: u32,
    pub valid_round: Option<u32>,
    pub block: CompactBlock,
    pub pol: Vec<Vote>,
}

/// Why a compact block could not be turned back into the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebuildError {
    /// This many of its transactions are not held here.
    Missing(usize),
    /// This many of its transactions are held here only without the key the block carries —
    /// stripped on arrival because this node's chain already knew the key. A key cannot be put
    /// back from the id alone.
    KeyNotHeld(usize),
    /// Every transaction was found, and together they are not what the header commits to.
    RootMismatch,
}

impl std::fmt::Display for RebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RebuildError::Missing(n) => {
                write!(f, "{n} of its transactions are not in this node's pool")
            }
            RebuildError::KeyNotHeld(n) => write!(
                f,
                "{n} of its transactions are held here only without the key the block carries"
            ),
            RebuildError::RootMismatch => {
                write!(
                    f,
                    "its transactions do not match the Merkle root its header commits to"
                )
            }
        }
    }
}

impl CompactBlock {
    pub fn of(block: &Block) -> Self {
        CompactBlock {
            header: block.header.clone(),
            transactions: block
                .transactions
                .iter()
                .map(|tx| TxRef {
                    id: tx.hash(),
                    carries_key: tx.public_key.is_some(),
                })
                .collect(),
        }
    }

    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// The hash of the block this stands for — the header's, as for any block.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// The block, from transactions `lookup` finds by id.
    ///
    /// `lookup` may hand back either form of a transaction; the key is dropped where the block
    /// carries none. Every missing transaction is counted before giving up, so a caller can say how
    /// far off this node was, not only that it was.
    pub fn rebuild(
        &self,
        mut lookup: impl FnMut(&Hash) -> Option<Transaction>,
    ) -> Result<Block, RebuildError> {
        let mut transactions = Vec::with_capacity(self.transactions.len());
        let (mut missing, mut key_not_held) = (0, 0);
        for reference in &self.transactions {
            match lookup(&reference.id) {
                None => missing += 1,
                Some(mut tx) => {
                    if !reference.carries_key {
                        tx.public_key = None;
                    } else if tx.public_key.is_none() {
                        key_not_held += 1;
                        continue;
                    }
                    transactions.push(tx);
                }
            }
        }
        if missing > 0 {
            return Err(RebuildError::Missing(missing));
        }
        if key_not_held > 0 {
            return Err(RebuildError::KeyNotHeld(key_not_held));
        }
        let block = Block {
            header: self.header.clone(),
            transactions,
        };
        if !block.verify_merkle_root() {
            return Err(RebuildError::RootMismatch);
        }
        Ok(block)
    }
}

impl CompactProposal {
    pub fn of(proposal: &Proposal) -> Self {
        CompactProposal {
            round: proposal.round,
            valid_round: proposal.valid_round,
            block: CompactBlock::of(&proposal.block),
            pol: proposal.pol.clone(),
        }
    }

    pub fn height(&self) -> u64 {
        self.block.height()
    }

    /// The proposal, rebuilt as [`CompactBlock::rebuild`] rebuilds its block.
    pub fn rebuild(
        &self,
        lookup: impl FnMut(&Hash) -> Option<Transaction>,
    ) -> Result<Proposal, RebuildError> {
        Ok(Proposal {
            round: self.round,
            valid_round: self.valid_round,
            block: self.block.rebuild(lookup)?,
            pol: self.pol.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_core::block::genesis_block;
    use helix_core::{transactions_root, CryptoVersion, TxType};
    use helix_crypto::{Address, PublicKey, Signature};
    use std::collections::HashMap;

    fn key() -> PublicKey {
        PublicKey::from_bytes(vec![7; 1952])
    }

    fn transfer(nonce: u64, with_key: bool) -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: Address::from_public_key(&key()),
            to: Some(Address::from_public_key(&PublicKey::from_bytes(vec![
                2;
                32
            ]))),
            amount: 1,
            fee: 1,
            nonce,
            data: vec![],
            crypto_version: CryptoVersion::MlDsa,
            chain_id: Hash::digest(b"chain"),
            signature: Signature::from_bytes(vec![nonce as u8; 3309]),
            public_key: with_key.then(key),
        }
    }

    /// A block over `transactions`, with the header committing to them as a proposer's would.
    fn block_of(transactions: Vec<Transaction>) -> Block {
        let mut block = genesis_block(
            Address::from_public_key(&key()),
            key(),
            Signature::from_bytes(vec![9; 16]),
            1_700_000_000_000,
        );
        block.header.height = 7;
        block.header.merkle_root = transactions_root(&transactions);
        block.transactions = transactions;
        block
    }

    fn pool_of(transactions: &[Transaction]) -> HashMap<Hash, Transaction> {
        transactions
            .iter()
            .map(|tx| (tx.hash(), tx.clone()))
            .collect()
    }

    #[test]
    fn a_block_whose_transactions_are_all_held_rebuilds_byte_for_byte() {
        let txs = vec![transfer(0, true), transfer(1, false), transfer(2, false)];
        let block = block_of(txs.clone());
        let pool = pool_of(&txs);
        let rebuilt = CompactBlock::of(&block)
            .rebuild(|id| pool.get(id).cloned())
            .unwrap();
        assert_eq!(
            bincode::serialize(&rebuilt).unwrap(),
            bincode::serialize(&block).unwrap()
        );
        assert_eq!(rebuilt.hash(), block.hash());
    }

    #[test]
    fn a_pool_that_kept_a_key_the_block_dropped_still_rebuilds_it() {
        // The proposer's pool stripped the key, this node's kept it: the id is the same, the
        // bytes are not, and the block commits to the stripped ones.
        let block = block_of(vec![transfer(4, false)]);
        let pool = pool_of(&[transfer(4, true)]);
        let rebuilt = CompactBlock::of(&block)
            .rebuild(|id| pool.get(id).cloned())
            .unwrap();
        assert_eq!(rebuilt.transactions[0].public_key, None);
        assert!(rebuilt.verify_merkle_root());
    }

    #[test]
    fn a_key_the_block_carries_and_the_pool_does_not_hold_is_not_invented() {
        let block = block_of(vec![transfer(0, true), transfer(1, true)]);
        let pool = pool_of(&[transfer(0, false), transfer(1, true)]);
        assert_eq!(
            CompactBlock::of(&block)
                .rebuild(|id| pool.get(id).cloned())
                .unwrap_err(),
            RebuildError::KeyNotHeld(1)
        );
    }

    #[test]
    fn every_missing_transaction_is_counted() {
        let txs: Vec<_> = (0..5).map(|n| transfer(n, false)).collect();
        let block = block_of(txs.clone());
        let pool = pool_of(&txs[1..3]);
        assert_eq!(
            CompactBlock::of(&block)
                .rebuild(|id| pool.get(id).cloned())
                .unwrap_err(),
            RebuildError::Missing(3)
        );
    }

    #[test]
    fn a_reference_that_does_not_match_the_header_is_refused() {
        // A relay flipped a key flag: every transaction is found, and the block they make is not
        // the one the proposer signed.
        let txs = vec![transfer(0, true), transfer(1, false)];
        let block = block_of(txs.clone());
        let mut compact = CompactBlock::of(&block);
        compact.transactions[0].carries_key = false;
        assert_eq!(
            compact
                .rebuild(|id| pool_of(&txs).get(id).cloned())
                .unwrap_err(),
            RebuildError::RootMismatch
        );
        // …and so is a reordering, which moves no transaction in or out.
        let mut reordered = CompactBlock::of(&block);
        reordered.transactions.swap(0, 1);
        assert_eq!(
            reordered
                .rebuild(|id| pool_of(&txs).get(id).cloned())
                .unwrap_err(),
            RebuildError::RootMismatch
        );
    }

    #[test]
    fn a_proposal_keeps_its_round_and_proof_of_lock_on_the_way() {
        let txs = vec![transfer(0, false)];
        let proposal = Proposal::reproposal(5, 3, block_of(txs.clone()), vec![]);
        let pool = pool_of(&txs);
        let rebuilt = CompactProposal::of(&proposal)
            .rebuild(|id| pool.get(id).cloned())
            .unwrap();
        assert_eq!((rebuilt.round, rebuilt.valid_round), (5, Some(3)));
        assert_eq!(rebuilt.block.hash(), proposal.block.hash());
    }

    #[test]
    fn a_full_block_travels_in_a_small_fraction_of_its_bytes() {
        // 400 transfers without keys, the shape of a full block of known senders (#243).
        let txs: Vec<_> = (0..400).map(|n| transfer(n, false)).collect();
        let block = block_of(txs);
        let full = bincode::serialize(&block).unwrap().len();
        let compact = bincode::serialize(&CompactBlock::of(&block)).unwrap().len();
        println!("full {full} B, compact {compact} B");
        assert!(full > 1_300_000, "premise: a full block ({full} B)");
        assert!(
            compact * 40 < full,
            "compact {compact} B against full {full} B"
        );
    }
}
