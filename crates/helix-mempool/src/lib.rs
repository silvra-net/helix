use helix_core::{transaction::Amount, Transaction};
use helix_crypto::Hash;
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("Transaction {0} already in mempool")]
    AlreadyExists(String),
    #[error("Mempool full (max {0} transactions)")]
    Full(usize),
    #[error("Fee too low: got {got}, minimum {min}")]
    FeeTooLow { got: Amount, min: Amount },
    #[error("Invalid transaction: {0}")]
    Invalid(String),
}

pub type MempoolResult<T> = Result<T, MempoolError>;

const DEFAULT_MAX_SIZE: usize = 10_000;
const DEFAULT_MIN_FEE: Amount = 1_000; // 1000 nano-HLX

/// Fee-prioritized transaction pool.
/// Higher fee → included in next block first.
pub struct Mempool {
    /// fee (descending) → vec of tx hashes at that fee level
    by_fee: BTreeMap<std::cmp::Reverse<Amount>, Vec<String>>,
    /// hash → transaction
    by_hash: HashMap<String, Transaction>,
    max_size: usize,
    min_fee: Amount,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            by_fee: BTreeMap::new(),
            by_hash: HashMap::new(),
            max_size: DEFAULT_MAX_SIZE,
            min_fee: DEFAULT_MIN_FEE,
        }
    }

    pub fn add(&mut self, tx: Transaction) -> MempoolResult<()> {
        if tx.fee < self.min_fee {
            return Err(MempoolError::FeeTooLow {
                got: tx.fee,
                min: self.min_fee,
            });
        }

        let hash = tx.hash().to_hex();

        if self.by_hash.contains_key(&hash) {
            return Err(MempoolError::AlreadyExists(hash));
        }

        if self.by_hash.len() >= self.max_size {
            return Err(MempoolError::Full(self.max_size));
        }

        // Verify signature before accepting
        tx.verify_signature()
            .map_err(|e| MempoolError::Invalid(e.to_string()))?;

        self.by_fee
            .entry(std::cmp::Reverse(tx.fee))
            .or_default()
            .push(hash.clone());

        self.by_hash.insert(hash, tx);
        Ok(())
    }

    /// Take up to `max_count` highest-fee transactions for block inclusion.
    /// Does NOT remove them — call `remove_committed` after the block is finalized.
    pub fn take(&self, max_count: usize) -> Vec<Transaction> {
        let mut result = Vec::with_capacity(max_count);
        'outer: for hashes in self.by_fee.values() {
            for hash in hashes {
                if result.len() >= max_count {
                    break 'outer;
                }
                if let Some(tx) = self.by_hash.get(hash) {
                    result.push(tx.clone());
                }
            }
        }
        result
    }

    /// Remove transactions that were committed in a block
    pub fn remove_committed(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            let key = hash.to_hex();
            if let Some(tx) = self.by_hash.remove(&key) {
                let bucket = self.by_fee.get_mut(&std::cmp::Reverse(tx.fee));
                if let Some(bucket) = bucket {
                    bucket.retain(|h| h != &key);
                    if bucket.is_empty() {
                        self.by_fee.remove(&std::cmp::Reverse(tx.fee));
                    }
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.by_hash.contains_key(&hash.to_hex())
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_core::{Transaction, TxType};
    use helix_crypto::{Address, KeyPair, Signature};

    fn make_tx(keypair: &KeyPair, fee: Amount, nonce: u64) -> Transaction {
        let addr = Address::from_public_key(&keypair.public);
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: addr.clone(),
            to: Some(addr),
            amount: 1_000_000,
            fee,
            nonce,
            data: vec![],
            signature: Signature::from_bytes(vec![0u8; 32]),
            public_key: keypair.public.clone(),
        };
        let hash = tx.signing_hash();
        tx.signature = keypair.sign(hash.as_bytes()).unwrap();
        tx
    }

    #[test]
    fn test_add_and_take() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        let tx1 = make_tx(&kp, 5_000, 0);
        let tx2 = make_tx(&kp, 10_000, 1);

        pool.add(tx1).unwrap();
        pool.add(tx2).unwrap();

        assert_eq!(pool.len(), 2);

        let taken = pool.take(10);
        // Higher fee comes first
        assert_eq!(taken[0].fee, 10_000);
        assert_eq!(taken[1].fee, 5_000);
    }

    #[test]
    fn test_fee_too_low_rejected() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();
        let tx = make_tx(&kp, 500, 0); // below 1000 min
        assert!(matches!(pool.add(tx), Err(MempoolError::FeeTooLow { .. })));
    }

    #[test]
    fn test_remove_committed() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();
        let tx = make_tx(&kp, 5_000, 0);
        let hash = tx.hash();
        pool.add(tx).unwrap();
        assert_eq!(pool.len(), 1);
        pool.remove_committed(&[hash]);
        assert_eq!(pool.len(), 0);
    }
}
