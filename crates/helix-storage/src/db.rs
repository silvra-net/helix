use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;

use helix_core::Block;
use helix_crypto::Hash;
use helix_executor::state::{AccountState, ChainState};

use crate::{BlockStore, StorageError, StorageResult};

const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const HEIGHT_IDX: TableDefinition<u64, &[u8]> = TableDefinition::new("height_index");
const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("accounts");
const NAMES: TableDefinition<&str, &str> = TableDefinition::new("names");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

const META_HEIGHT: &str = "latest_height";
const META_HASH: &str = "latest_hash";
const META_BURNED: &str = "total_burned";

pub struct HelixDb {
    db: Database,
}

impl HelixDb {
    pub fn open(path: &Path) -> StorageResult<Self> {
        let db = Database::create(path).map_err(|e| StorageError::Db(e.to_string()))?;
        // Ensure tables exist
        let tx = db.begin_write().map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(BLOCKS).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(HEIGHT_IDX).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(ACCOUNTS).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(NAMES).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(META).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.commit().map_err(|e| StorageError::Db(e.to_string()))?;
        Ok(HelixDb { db })
    }

    // ── Account state ────────────────────────────────────────────────────────

    pub fn save_chain_state(&self, state: &ChainState) -> StorageResult<()> {
        let tx = self.db.begin_write().map_err(|e| StorageError::Db(e.to_string()))?;
        {
            let mut accounts = tx.open_table(ACCOUNTS).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut names = tx.open_table(NAMES).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut meta = tx.open_table(META).map_err(|e| StorageError::Db(e.to_string()))?;

            for (addr, account) in &state.accounts {
                let encoded = bincode::serialize(account)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                accounts.insert(addr.as_str(), encoded.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for (name, owner) in &state.names {
                names.insert(name.as_str(), owner.as_str())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            meta.insert(META_BURNED, &state.total_burned.to_le_bytes()[..])
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
        tx.commit().map_err(|e| StorageError::Db(e.to_string()))
    }

    pub fn load_chain_state(&self, total_supply: u64) -> StorageResult<ChainState> {
        let tx = self.db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
        let accounts_table = tx.open_table(ACCOUNTS).map_err(|e| StorageError::Db(e.to_string()))?;
        let names_table = tx.open_table(NAMES).map_err(|e| StorageError::Db(e.to_string()))?;
        let meta_table = tx.open_table(META).map_err(|e| StorageError::Db(e.to_string()))?;

        let mut accounts = std::collections::HashMap::new();
        let mut iter = accounts_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let account: AccountState = bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            accounts.insert(k.value().to_string(), account);
        }

        let mut names = std::collections::HashMap::new();
        let mut name_iter = names_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = name_iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            names.insert(k.value().to_string(), v.value().to_string());
        }

        let total_burned = meta_table
            .get(META_BURNED)
            .ok()
            .flatten()
            .and_then(|v| {
                let bytes: [u8; 8] = v.value().try_into().ok()?;
                Some(u64::from_le_bytes(bytes))
            })
            .unwrap_or(0);

        Ok(ChainState { accounts, total_supply, total_burned, names })
    }

    pub fn get_account(&self, address: &str) -> StorageResult<Option<AccountState>> {
        let tx = self.db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
        let table = tx.open_table(ACCOUNTS).map_err(|e| StorageError::Db(e.to_string()))?;
        match table.get(address).map_err(|e| StorageError::Db(e.to_string()))? {
            Some(v) => Ok(Some(
                bincode::deserialize(v.value())
                    .map_err(|e| StorageError::Serialization(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }
}

impl BlockStore for HelixDb {
    fn get_block_by_hash(&self, hash: &Hash) -> StorageResult<Block> {
        let tx = self.db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
        let table = tx.open_table(BLOCKS).map_err(|e| StorageError::Db(e.to_string()))?;
        match table.get(hash.as_bytes().as_slice()).map_err(|e| StorageError::Db(e.to_string()))? {
            Some(v) => bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string())),
            None => Err(StorageError::HashNotFound(hash.to_hex())),
        }
    }

    fn get_block_by_height(&self, height: u64) -> StorageResult<Block> {
        let tx = self.db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
        let heights = tx.open_table(HEIGHT_IDX).map_err(|e| StorageError::Db(e.to_string()))?;
        match heights.get(height).map_err(|e| StorageError::Db(e.to_string()))? {
            Some(hash_bytes) => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(hash_bytes.value());
                self.get_block_by_hash(&Hash::from_bytes(arr))
            }
            None => Err(StorageError::BlockNotFound(height)),
        }
    }

    fn put_block(&mut self, block: Block) -> StorageResult<()> {
        let hash = block.hash();
        let height = block.height();
        let encoded = bincode::serialize(&block)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        let tx = self.db.begin_write().map_err(|e| StorageError::Db(e.to_string()))?;
        {
            let mut blocks = tx.open_table(BLOCKS).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut heights = tx.open_table(HEIGHT_IDX).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut meta = tx.open_table(META).map_err(|e| StorageError::Db(e.to_string()))?;

            blocks.insert(hash.as_bytes().as_slice(), encoded.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
            heights.insert(height, hash.as_bytes().as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;

            // Update latest only if this block is newer
            let current = meta.get(META_HEIGHT).ok().flatten()
                .and_then(|v| {
                    let b: [u8; 8] = v.value().try_into().ok()?;
                    Some(u64::from_le_bytes(b))
                })
                .unwrap_or(0);

            if height >= current {
                meta.insert(META_HEIGHT, &height.to_le_bytes()[..])
                    .map_err(|e| StorageError::Db(e.to_string()))?;
                meta.insert(META_HASH, hash.as_bytes().as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
        }
        tx.commit().map_err(|e| StorageError::Db(e.to_string()))
    }

    fn latest_height(&self) -> u64 {
        let Ok(tx) = self.db.begin_read() else { return 0 };
        let Ok(meta) = tx.open_table(META) else { return 0 };
        meta.get(META_HEIGHT).ok().flatten()
            .and_then(|v| {
                let b: [u8; 8] = v.value().try_into().ok()?;
                Some(u64::from_le_bytes(b))
            })
            .unwrap_or(0)
    }

    fn latest_hash(&self) -> Hash {
        let Ok(tx) = self.db.begin_read() else { return Hash::ZERO };
        let Ok(meta) = tx.open_table(META) else { return Hash::ZERO };
        meta.get(META_HASH).ok().flatten()
            .and_then(|v| {
                let bytes = v.value();
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    Some(Hash::from_bytes(arr))
                } else {
                    None
                }
            })
            .unwrap_or(Hash::ZERO)
    }
}
