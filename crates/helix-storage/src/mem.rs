use std::collections::HashMap;

use helix_core::Block;
use helix_crypto::Hash;

use crate::{BlockStore, StorageResult, StorageError};

pub struct MemBlockStore {
    by_hash: HashMap<String, Block>,
    by_height: HashMap<u64, Hash>,
    latest_height: u64,
}

impl MemBlockStore {
    pub fn new() -> Self {
        MemBlockStore {
            by_hash: HashMap::new(),
            by_height: HashMap::new(),
            latest_height: 0,
        }
    }
}

impl Default for MemBlockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockStore for MemBlockStore {
    fn get_block_by_hash(&self, hash: &Hash) -> StorageResult<Block> {
        self.by_hash
            .get(&hash.to_hex())
            .cloned()
            .ok_or_else(|| StorageError::HashNotFound(hash.to_hex()))
    }

    fn get_block_by_height(&self, height: u64) -> StorageResult<Block> {
        let hash = self
            .by_height
            .get(&height)
            .ok_or(StorageError::BlockNotFound(height))?;
        self.get_block_by_hash(hash)
    }

    fn put_block(&mut self, block: Block) -> StorageResult<()> {
        let hash = block.hash();
        let height = block.height();
        self.by_height.insert(height, hash);
        self.by_hash.insert(hash.to_hex(), block);
        if height > self.latest_height {
            self.latest_height = height;
        }
        Ok(())
    }

    fn latest_height(&self) -> u64 {
        self.latest_height
    }

    fn latest_hash(&self) -> Hash {
        self.by_height
            .get(&self.latest_height)
            .copied()
            .unwrap_or(Hash::ZERO)
    }
}
