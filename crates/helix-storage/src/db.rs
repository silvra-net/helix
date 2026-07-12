use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;

use helix_core::Block;
use helix_crypto::Hash;
use helix_executor::governance::{GovernanceParams, GovernanceProposal};
use helix_executor::state::{AccountState, ChainState};

use crate::{BlockStore, StorageError, StorageResult};

const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const HEIGHT_IDX: TableDefinition<u64, &[u8]> = TableDefinition::new("height_index");
const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("accounts");
const NAMES: TableDefinition<&str, &str> = TableDefinition::new("names");
const PERSONHOOD: TableDefinition<&str, &[u8]> = TableDefinition::new("personhood");
const GUARDIANS: TableDefinition<&str, &[u8]> = TableDefinition::new("guardians");
const RECOVERY_REQUESTS: TableDefinition<&str, &[u8]> = TableDefinition::new("recovery_requests");
const RECOVERY_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("recovery_keys");
const PROPOSALS: TableDefinition<u64, &[u8]> = TableDefinition::new("proposals");
const PERSONHOOD_COMMITMENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("personhood_commitments");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

const META_HEIGHT: &str = "latest_height";
const META_HASH: &str = "latest_hash";
const META_BURNED: &str = "total_burned";
const META_MIN_VALIDATOR_STAKE: &str = "gov_min_validator_stake";
const META_FUEL_PER_FEE_UNIT: &str = "gov_fuel_per_fee_unit";
const META_NEXT_PROPOSAL_ID: &str = "gov_next_proposal_id";

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
        tx.open_table(PERSONHOOD).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(GUARDIANS).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(RECOVERY_REQUESTS).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(RECOVERY_KEYS).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(PROPOSALS).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(PERSONHOOD_COMMITMENTS).map_err(|e| StorageError::Db(e.to_string()))?;
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
            let mut personhood = tx.open_table(PERSONHOOD).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut guardians = tx.open_table(GUARDIANS).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut recovery_requests = tx.open_table(RECOVERY_REQUESTS).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut recovery_keys = tx.open_table(RECOVERY_KEYS).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut proposals = tx.open_table(PROPOSALS).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut personhood_commitments = tx.open_table(PERSONHOOD_COMMITMENTS).map_err(|e| StorageError::Db(e.to_string()))?;
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
            for (addr, status) in &state.personhood {
                let encoded = bincode::serialize(status)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                personhood.insert(addr.as_str(), encoded.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for (addr, set) in &state.guardians {
                let encoded = bincode::serialize(set)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                guardians.insert(addr.as_str(), encoded.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for (addr, request) in &state.recovery_requests {
                let encoded = bincode::serialize(request)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                recovery_requests.insert(addr.as_str(), encoded.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for (addr, key) in &state.recovery_keys {
                let encoded = bincode::serialize(key)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                recovery_keys.insert(addr.as_str(), encoded.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for (id, proposal) in &state.proposals {
                let encoded = bincode::serialize(proposal)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                proposals.insert(*id, encoded.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for commitment in &state.used_personhood_commitments {
                personhood_commitments.insert(commitment.as_slice(), &[][..])
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            meta.insert(META_BURNED, &state.total_burned.to_le_bytes()[..])
                .map_err(|e| StorageError::Db(e.to_string()))?;
            meta.insert(
                META_MIN_VALIDATOR_STAKE,
                &state.governance_params.min_validator_stake.to_le_bytes()[..],
            )
            .map_err(|e| StorageError::Db(e.to_string()))?;
            meta.insert(
                META_FUEL_PER_FEE_UNIT,
                &state.governance_params.fuel_per_fee_unit.to_le_bytes()[..],
            )
            .map_err(|e| StorageError::Db(e.to_string()))?;
            meta.insert(META_NEXT_PROPOSAL_ID, &state.next_proposal_id.to_le_bytes()[..])
                .map_err(|e| StorageError::Db(e.to_string()))?;
        }
        tx.commit().map_err(|e| StorageError::Db(e.to_string()))
    }

    pub fn load_chain_state(&self, total_supply: u64) -> StorageResult<ChainState> {
        let tx = self.db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
        let accounts_table = tx.open_table(ACCOUNTS).map_err(|e| StorageError::Db(e.to_string()))?;
        let names_table = tx.open_table(NAMES).map_err(|e| StorageError::Db(e.to_string()))?;
        let personhood_table = tx.open_table(PERSONHOOD).map_err(|e| StorageError::Db(e.to_string()))?;
        let guardians_table = tx.open_table(GUARDIANS).map_err(|e| StorageError::Db(e.to_string()))?;
        let recovery_requests_table = tx.open_table(RECOVERY_REQUESTS).map_err(|e| StorageError::Db(e.to_string()))?;
        let recovery_keys_table = tx.open_table(RECOVERY_KEYS).map_err(|e| StorageError::Db(e.to_string()))?;
        let proposals_table = tx.open_table(PROPOSALS).map_err(|e| StorageError::Db(e.to_string()))?;
        let personhood_commitments_table = tx.open_table(PERSONHOOD_COMMITMENTS).map_err(|e| StorageError::Db(e.to_string()))?;
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

        let mut personhood = std::collections::HashMap::new();
        let mut personhood_iter = personhood_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = personhood_iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let status = bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            personhood.insert(k.value().to_string(), status);
        }

        let mut guardians = std::collections::HashMap::new();
        let mut guardians_iter = guardians_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = guardians_iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let set = bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            guardians.insert(k.value().to_string(), set);
        }

        let mut recovery_requests = std::collections::HashMap::new();
        let mut recovery_requests_iter = recovery_requests_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = recovery_requests_iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let request = bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            recovery_requests.insert(k.value().to_string(), request);
        }

        let mut recovery_keys = std::collections::HashMap::new();
        let mut recovery_keys_iter = recovery_keys_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = recovery_keys_iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let key = bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            recovery_keys.insert(k.value().to_string(), key);
        }

        let mut proposals = std::collections::HashMap::new();
        let mut proposals_iter = proposals_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = proposals_iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let proposal: GovernanceProposal = bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            proposals.insert(k.value(), proposal);
        }

        let mut used_personhood_commitments = std::collections::HashSet::new();
        let mut personhood_commitments_iter = personhood_commitments_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = personhood_commitments_iter.next() {
            let (k, _v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let commitment: [u8; 16] = k.value().try_into().map_err(|_| {
                StorageError::Serialization("personhood commitment key must be 16 bytes".to_string())
            })?;
            used_personhood_commitments.insert(commitment);
        }

        let read_meta_u64 = |key: &str| -> Option<u64> {
            meta_table.get(key).ok().flatten().and_then(|v| {
                let bytes: [u8; 8] = v.value().try_into().ok()?;
                Some(u64::from_le_bytes(bytes))
            })
        };

        let total_burned = read_meta_u64(META_BURNED).unwrap_or(0);
        let default_params = GovernanceParams::default();
        let governance_params = GovernanceParams {
            min_validator_stake: read_meta_u64(META_MIN_VALIDATOR_STAKE)
                .unwrap_or(default_params.min_validator_stake),
            fuel_per_fee_unit: read_meta_u64(META_FUEL_PER_FEE_UNIT)
                .unwrap_or(default_params.fuel_per_fee_unit),
        };
        let next_proposal_id = read_meta_u64(META_NEXT_PROPOSAL_ID).unwrap_or(0);

        Ok(ChainState {
            accounts,
            total_supply,
            total_burned,
            names,
            personhood,
            guardians,
            recovery_requests,
            recovery_keys,
            governance_params,
            proposals,
            next_proposal_id,
            used_personhood_commitments,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use helix_core::genesis_block;
    use helix_crypto::{Address, KeyPair};

    /// A block + chain state written by one `HelixDb` handle must be readable
    /// back after the process (simulated here by dropping and reopening the
    /// handle) restarts — the entire point of moving off the in-memory store.
    #[test]
    fn blocks_and_chain_state_survive_reopening_the_database() {
        let mut path = std::env::temp_dir();
        path.push(format!("helix-db-test-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let kp = KeyPair::generate();
        let validator = Address::from_public_key(&kp.public);
        let sig = kp.sign(b"test-genesis").unwrap();
        let genesis = genesis_block(validator.clone(), kp.public.clone(), sig);
        let genesis_hash = genesis.hash();

        {
            let mut db = HelixDb::open(&path).unwrap();
            db.put_block(genesis).unwrap();

            let mut state = ChainState::new(1_000_000);
            state.set_balance(&validator, 42);
            state.used_personhood_commitments.insert([7u8; 16]);
            db.save_chain_state(&state).unwrap();
        }

        // Reopen — nothing but the file on disk carries state across this point.
        let db = HelixDb::open(&path).unwrap();
        assert_eq!(db.latest_height(), 0);
        assert_eq!(db.latest_hash(), genesis_hash);
        assert_eq!(db.get_block_by_height(0).unwrap().hash(), genesis_hash);

        let loaded = db.load_chain_state(1_000_000).unwrap();
        assert_eq!(loaded.get(&validator).unwrap().balance, 42);
        // A used personhood commitment must also survive a restart — otherwise a
        // replayed proof would be accepted again right after the node restarts.
        assert!(loaded.used_personhood_commitments.contains(&[7u8; 16]));

        let _ = std::fs::remove_file(&path);
    }
}
