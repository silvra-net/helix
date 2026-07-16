pub mod db;
pub mod mem;

use helix_core::Block;
use helix_crypto::Hash;
use helix_executor::receipt::Receipt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Block not found at height {0}")]
    BlockNotFound(u64),
    #[error("Block hash not found: {0}")]
    HashNotFound(String),
    #[error("Database error: {0}")]
    Db(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type StorageResult<T> = Result<T, StorageError>;

pub trait BlockStore: Send + Sync {
    fn get_block_by_hash(&self, hash: &Hash) -> StorageResult<Block>;
    fn get_block_by_height(&self, height: u64) -> StorageResult<Block>;
    fn put_block(&mut self, block: Block) -> StorageResult<()>;

    /// Persist the execution outcome of each transaction in a block, keyed by tx hash.
    ///
    /// Being in a block is not the same as having worked: a transaction the executor rejected
    /// (bad nonce, insufficient balance, zero-amount transfer) is committed and paid for like
    /// any other, and every `Receipt::failure` reason was invisible outside the node's own logs
    /// until this was stored. `/transactions/{hash}` answered `confirmed` to all of them, which
    /// is the difference between "your money arrived" and "it didn't".
    fn put_receipts(&mut self, receipts: &[Receipt]) -> StorageResult<()>;

    /// The stored outcome for a transaction, or `None` if this node has none — either the
    /// transaction isn't on this chain, or its block predates receipt storage. `None` means
    /// "this node cannot say", never "it succeeded".
    fn get_receipt(&self, tx_hash: &Hash) -> StorageResult<Option<Receipt>>;

    fn latest_height(&self) -> u64;
    fn latest_hash(&self) -> Hash;
}
