pub mod db;
pub mod mem;

use helix_core::Block;
use helix_crypto::Hash;
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
    fn latest_height(&self) -> u64;
    fn latest_hash(&self) -> Hash;
}
