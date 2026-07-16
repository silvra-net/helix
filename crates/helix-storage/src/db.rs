use redb::{Database, MultimapTableDefinition, ReadableTable, TableDefinition};
use std::path::Path;

use helix_core::Block;
use helix_crypto::{Address, Hash, PublicKey};
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
/// "{validator}:{height}:{round}" → already-slashed double-sign incidents.
const SLASHED_DOUBLE_SIGN_INCIDENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("slashed_double_sign_incidents");
/// Key = authority public key bytes, value unused — same set-as-table pattern as
/// `PERSONHOOD_COMMITMENTS`. A node accepts a `ProvePersonhood` signature from any one
/// entry in this table (see `ChainState::personhood_authorities`'s doc comment).
const PERSONHOOD_AUTHORITIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("personhood_authorities");
/// validator address string → bincode(`DelegationPool`).
const VALIDATOR_POOLS: TableDefinition<&str, &[u8]> = TableDefinition::new("validator_pools");
/// validator address string → bincode(`HashMap<delegator_address, shares>`) — the whole
/// per-validator delegator map stored as one blob, same "one blob per outer key" shape as
/// `GUARDIANS`/`RECOVERY_REQUESTS` rather than a multimap keyed by (validator, delegator).
const DELEGATOR_SHARES: TableDefinition<&str, &[u8]> = TableDefinition::new("delegator_shares");
/// source validator address string → bincode(`Vec<Redelegation>`) — the whole per-source list
/// as one blob, same "one blob per outer key" shape as `DELEGATOR_SHARES`. These entries are
/// what keeps redelegated stake slashable for the validator it left (see `TxType::Redelegate`),
/// so losing them on restart would not merely drop state: it would silently hand every
/// in-flight redelegation a full escape from the source's slashing window.
const REDELEGATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("redelegations");
/// contract address string → bincode(`HashMap<key_bytes, value_bytes>`) — the whole
/// per-contract storage map stored as one blob, same "one blob per outer key" shape as
/// `DELEGATOR_SHARES`. Without this table, `ChainState.contract_storage` would silently
/// reset to empty on every node restart, wiping every deployed contract's state.
const CONTRACT_STORAGE: TableDefinition<&str, &[u8]> = TableDefinition::new("contract_storage");
/// address string → stake in nano-HLX (8-byte little-endian) — see
/// `ChainState::genesis_extra_validators`'s doc comment for why this needs its own table
/// rather than being re-derivable from `ACCOUNTS` (genesis composition can drift from
/// current stakes long after startup).
const GENESIS_EXTRA_VALIDATORS: TableDefinition<&str, &[u8]> = TableDefinition::new("genesis_extra_validators");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// address string → (block height, tx index within block), both big-endian so a
/// key's values sort in ascending chain order for free. Lets `address_transactions`
/// look up only the transactions touching one address instead of scanning every
/// block in the chain on every request.
const ADDRESS_TX_INDEX: MultimapTableDefinition<&str, &[u8]> = MultimapTableDefinition::new("address_tx_index");
/// tx hash bytes → (block height, tx index within block), same 12-byte value
/// encoding as `ADDRESS_TX_INDEX`. Backs `tx_location()` — a single-key lookup
/// instead of scanning every block for the one that happens to contain a hash.
const TX_HASH_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tx_hash_index");

const META_HEIGHT: &str = "latest_height";
const META_HASH: &str = "latest_hash";
const META_BURNED: &str = "total_burned";
const META_ISSUED: &str = "total_issued";
const META_MIN_VALIDATOR_STAKE: &str = "gov_min_validator_stake";
const META_FUEL_PER_FEE_UNIT: &str = "gov_fuel_per_fee_unit";
const META_NEXT_PROPOSAL_ID: &str = "gov_next_proposal_id";
const META_GENESIS_VALIDATOR_STAKE: &str = "genesis_validator_stake";

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
        tx.open_table(SLASHED_DOUBLE_SIGN_INCIDENTS).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(PERSONHOOD_AUTHORITIES).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(VALIDATOR_POOLS).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(DELEGATOR_SHARES).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(REDELEGATIONS).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(CONTRACT_STORAGE).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(GENESIS_EXTRA_VALIDATORS).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(META).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_multimap_table(ADDRESS_TX_INDEX).map_err(|e| StorageError::Db(e.to_string()))?;
        tx.open_table(TX_HASH_INDEX).map_err(|e| StorageError::Db(e.to_string()))?;
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
            let mut slashed_double_sign_incidents = tx.open_table(SLASHED_DOUBLE_SIGN_INCIDENTS).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut personhood_authorities = tx.open_table(PERSONHOOD_AUTHORITIES).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut validator_pools = tx.open_table(VALIDATOR_POOLS).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut delegator_shares = tx.open_table(DELEGATOR_SHARES).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut redelegations = tx.open_table(REDELEGATIONS).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut contract_storage = tx.open_table(CONTRACT_STORAGE).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut genesis_extra_validators = tx.open_table(GENESIS_EXTRA_VALIDATORS).map_err(|e| StorageError::Db(e.to_string()))?;
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
            // Recovery requests are the one persisted collection whose entries are *removed*
            // as well as added (a request is cleared on cancel/completion — see
            // `ChainState::clear_recovery_request`). Insert-only persistence would leave the
            // cleared row in the table, so on the next node restart the request would
            // resurrect and re-lock the account (re-introducing exactly the lockout that
            // `CancelRecoveryRequest` was added to fix). Prune any DB key no longer present in
            // state before re-inserting the current set. All other tables here are add/update-
            // only, so they don't need this.
            {
                let current: std::collections::HashSet<String> =
                    state.recovery_requests.keys().cloned().collect();
                let stale: Vec<String> = recovery_requests
                    .iter()
                    .map_err(|e| StorageError::Db(e.to_string()))?
                    .filter_map(|entry| {
                        let (k, _) = entry.ok()?;
                        let key = k.value().to_string();
                        (!current.contains(&key)).then_some(key)
                    })
                    .collect();
                for key in stale {
                    recovery_requests
                        .remove(key.as_str())
                        .map_err(|e| StorageError::Db(e.to_string()))?;
                }
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
            for incident in &state.slashed_double_sign_incidents {
                slashed_double_sign_incidents.insert(incident.as_str(), &[][..])
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            meta.insert(META_BURNED, &state.total_burned.to_le_bytes()[..])
                .map_err(|e| StorageError::Db(e.to_string()))?;
            meta.insert(META_ISSUED, &state.total_issued.to_le_bytes()[..])
                .map_err(|e| StorageError::Db(e.to_string()))?;
            meta.insert(
                META_GENESIS_VALIDATOR_STAKE,
                &state.genesis_validator_stake.to_le_bytes()[..],
            )
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
            for authority in &state.personhood_authorities {
                personhood_authorities.insert(authority.as_bytes(), &[][..])
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for (addr, pool) in &state.validator_pools {
                let encoded = bincode::serialize(pool)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                validator_pools.insert(addr.as_str(), encoded.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for (addr, shares) in &state.delegator_shares {
                let encoded = bincode::serialize(shares)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                delegator_shares.insert(addr.as_str(), encoded.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            // Unlike every other table here, this one needs stale keys actively removed: a
            // source validator's entry disappears from `ChainState::redelegations` once its
            // last window closes (`prune_expired_redelegations`), and these loops only ever
            // insert. Leaving the old blob behind would resurrect expired redelegations on the
            // next restart — re-exposing settled stake to a slash it had already outlived.
            let stale: Vec<String> = {
                let mut out = Vec::new();
                let iter = redelegations.iter().map_err(|e| StorageError::Db(e.to_string()))?;
                for entry in iter {
                    let (k, _) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
                    if !state.redelegations.contains_key(k.value()) {
                        out.push(k.value().to_string());
                    }
                }
                out
            };
            for key in &stale {
                redelegations.remove(key.as_str()).map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for (src, entries) in &state.redelegations {
                let encoded = bincode::serialize(entries)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                redelegations.insert(src.as_str(), encoded.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for (addr, storage) in &state.contract_storage {
                let encoded = bincode::serialize(storage)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                contract_storage.insert(addr.as_str(), encoded.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
            for (addr, stake) in &state.genesis_extra_validators {
                genesis_extra_validators.insert(addr.as_str(), &stake.to_le_bytes()[..])
                    .map_err(|e| StorageError::Db(e.to_string()))?;
            }
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
        let slashed_double_sign_incidents_table = tx.open_table(SLASHED_DOUBLE_SIGN_INCIDENTS).map_err(|e| StorageError::Db(e.to_string()))?;
        let personhood_authorities_table = tx.open_table(PERSONHOOD_AUTHORITIES).map_err(|e| StorageError::Db(e.to_string()))?;
        let validator_pools_table = tx.open_table(VALIDATOR_POOLS).map_err(|e| StorageError::Db(e.to_string()))?;
        let delegator_shares_table = tx.open_table(DELEGATOR_SHARES).map_err(|e| StorageError::Db(e.to_string()))?;
        let redelegations_table = tx.open_table(REDELEGATIONS).map_err(|e| StorageError::Db(e.to_string()))?;
        let contract_storage_table = tx.open_table(CONTRACT_STORAGE).map_err(|e| StorageError::Db(e.to_string()))?;
        let genesis_extra_validators_table = tx.open_table(GENESIS_EXTRA_VALIDATORS).map_err(|e| StorageError::Db(e.to_string()))?;
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

        let mut slashed_double_sign_incidents = std::collections::HashSet::new();
        let mut slashed_double_sign_incidents_iter = slashed_double_sign_incidents_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = slashed_double_sign_incidents_iter.next() {
            let (k, _v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            slashed_double_sign_incidents.insert(k.value().to_string());
        }

        let mut personhood_authorities = Vec::new();
        let mut personhood_authorities_iter = personhood_authorities_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = personhood_authorities_iter.next() {
            let (k, _v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            personhood_authorities.push(PublicKey::from_bytes(k.value().to_vec()));
        }

        let mut validator_pools = std::collections::HashMap::new();
        let mut validator_pools_iter = validator_pools_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = validator_pools_iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let pool = bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            validator_pools.insert(k.value().to_string(), pool);
        }

        let mut delegator_shares = std::collections::HashMap::new();
        let mut delegator_shares_iter = delegator_shares_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = delegator_shares_iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let shares = bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            delegator_shares.insert(k.value().to_string(), shares);
        }

        let mut redelegations = std::collections::HashMap::new();
        let redelegations_iter = redelegations_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        for entry in redelegations_iter {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let entries = bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            redelegations.insert(k.value().to_string(), entries);
        }

        let mut contract_storage = std::collections::HashMap::new();
        let mut contract_storage_iter = contract_storage_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = contract_storage_iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let storage = bincode::deserialize(v.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            contract_storage.insert(k.value().to_string(), storage);
        }

        let mut genesis_extra_validators = Vec::new();
        let mut genesis_extra_validators_iter = genesis_extra_validators_table.iter().map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(entry) = genesis_extra_validators_iter.next() {
            let (k, v) = entry.map_err(|e| StorageError::Db(e.to_string()))?;
            let stake_bytes: [u8; 8] = v.value().try_into().map_err(|_| {
                StorageError::Serialization("genesis extra validator stake must be 8 bytes".to_string())
            })?;
            let address = Address::from_str(k.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            genesis_extra_validators.push((address, u64::from_le_bytes(stake_bytes)));
        }

        let read_meta_u64 = |key: &str| -> Option<u64> {
            meta_table.get(key).ok().flatten().and_then(|v| {
                let bytes: [u8; 8] = v.value().try_into().ok()?;
                Some(u64::from_le_bytes(bytes))
            })
        };

        let total_burned = read_meta_u64(META_BURNED).unwrap_or(0);
        let total_issued = read_meta_u64(META_ISSUED).unwrap_or(0);
        let default_params = GovernanceParams::default();
        let governance_params = GovernanceParams {
            min_validator_stake: read_meta_u64(META_MIN_VALIDATOR_STAKE)
                .unwrap_or(default_params.min_validator_stake),
            fuel_per_fee_unit: read_meta_u64(META_FUEL_PER_FEE_UNIT)
                .unwrap_or(default_params.fuel_per_fee_unit),
        };
        let next_proposal_id = read_meta_u64(META_NEXT_PROPOSAL_ID).unwrap_or(0);
        // Absent only for a chain that launched before this key existed, and such a chain can
        // only have used the compile-time default — so falling back to it recovers the true
        // historical value rather than guessing. The next `save_chain_state` (i.e. the next
        // block) writes it down, after which the constant no longer has any say over this
        // chain's genesis and can be retuned freely. That ordering matters: deploy this while
        // `VALIDATOR_GENESIS_STAKE_HLX` still holds the value the chain actually launched with,
        // never together with a change to it, or the migration pins down the wrong number.
        let genesis_validator_stake = read_meta_u64(META_GENESIS_VALIDATOR_STAKE)
            .unwrap_or(
                helix_executor::genesis::VALIDATOR_GENESIS_STAKE_HLX
                    * helix_executor::genesis::NANO_PER_HLX,
            );

        Ok(ChainState {
            accounts,
            total_supply,
            total_issued,
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
            slashed_double_sign_incidents,
            personhood_authorities,
            validator_pools,
            delegator_shares,
            redelegations,
            contract_storage,
            genesis_extra_validators,
            genesis_validator_stake,
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

    /// Returns `(block_height, tx_index_within_block)` for every transaction that
    /// touched `address` (as sender or recipient), newest first, after applying
    /// `offset`/`limit` — backed by `ADDRESS_TX_INDEX` instead of scanning every
    /// block in the chain on every call.
    pub fn address_transactions(
        &self,
        address: &str,
        limit: usize,
        offset: usize,
    ) -> StorageResult<Vec<(u64, u32)>> {
        let tx = self.db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
        let table = tx.open_multimap_table(ADDRESS_TX_INDEX).map_err(|e| StorageError::Db(e.to_string()))?;
        let mut entries = Vec::new();
        let mut iter = table.get(address).map_err(|e| StorageError::Db(e.to_string()))?;
        while let Some(v) = iter.next() {
            let v = v.map_err(|e| StorageError::Db(e.to_string()))?;
            let bytes = v.value();
            let height = u64::from_be_bytes(bytes[..8].try_into().unwrap());
            let tx_index = u32::from_be_bytes(bytes[8..].try_into().unwrap());
            entries.push((height, tx_index));
        }
        // Stored ascending (big-endian height sorts numerically) — reverse for
        // newest-first before paginating.
        entries.reverse();
        Ok(entries.into_iter().skip(offset).take(limit).collect())
    }

    /// `(block_height, tx_index_within_block)` for the transaction with this hash,
    /// if it's been included in a block yet — backed by `TX_HASH_INDEX` instead of
    /// scanning every block looking for the one that happens to contain it.
    pub fn tx_location(&self, tx_hash: &Hash) -> StorageResult<Option<(u64, u32)>> {
        let tx = self.db.begin_read().map_err(|e| StorageError::Db(e.to_string()))?;
        let table = tx.open_table(TX_HASH_INDEX).map_err(|e| StorageError::Db(e.to_string()))?;
        match table.get(tx_hash.as_bytes().as_slice()).map_err(|e| StorageError::Db(e.to_string()))? {
            Some(v) => {
                let bytes = v.value();
                let height = u64::from_be_bytes(bytes[..8].try_into().unwrap());
                let tx_index = u32::from_be_bytes(bytes[8..].try_into().unwrap());
                Ok(Some((height, tx_index)))
            }
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
            let mut address_tx_index = tx.open_multimap_table(ADDRESS_TX_INDEX).map_err(|e| StorageError::Db(e.to_string()))?;
            let mut tx_hash_index = tx.open_table(TX_HASH_INDEX).map_err(|e| StorageError::Db(e.to_string()))?;

            blocks.insert(hash.as_bytes().as_slice(), encoded.as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;
            heights.insert(height, hash.as_bytes().as_slice())
                .map_err(|e| StorageError::Db(e.to_string()))?;

            for (tx_index, txn) in block.transactions.iter().enumerate() {
                let mut value = [0u8; 12];
                value[..8].copy_from_slice(&height.to_be_bytes());
                value[8..].copy_from_slice(&(tx_index as u32).to_be_bytes());

                tx_hash_index.insert(txn.hash().as_bytes().as_slice(), value.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
                address_tx_index.insert(txn.from.as_str(), value.as_slice())
                    .map_err(|e| StorageError::Db(e.to_string()))?;
                if let Some(to) = &txn.to {
                    if to != &txn.from {
                        address_tx_index.insert(to.as_str(), value.as_slice())
                            .map_err(|e| StorageError::Db(e.to_string()))?;
                    }
                }
            }

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
    use helix_core::{genesis_block, BlockHeader, CryptoVersion, TxType};
    use helix_crypto::{Address, KeyPair, PublicKey, Signature};

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&PublicKey::from_bytes(vec![seed; 8]))
    }

    fn transfer(from: &Address, to: &Address, nonce: u64) -> helix_core::Transaction {
        helix_core::Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: from.clone(),
            to: Some(to.clone()),
            amount: 10,
            fee: 1,
            nonce,
            data: vec![],
            crypto_version: Default::default(),
            signature: Signature::from_bytes(vec![]),
            public_key: PublicKey::from_bytes(vec![]),
        }
    }

    fn block_with_txs(height: u64, validator: &Address, transactions: Vec<helix_core::Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                height,
                timestamp: 1_000 + height,
                prev_hash: Hash::ZERO,
                merkle_root: Hash::ZERO,
                validator: validator.clone(),
                public_key: PublicKey::from_bytes(vec![]),
                crypto_version: CryptoVersion::MlDsa,
                base_fee_per_byte: helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
                signature: Signature::from_bytes(vec![]),
            },
            transactions,
        }
    }

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
            state.total_issued = 123_456;
            state.used_personhood_commitments.insert([7u8; 16]);
            state.slashed_double_sign_incidents.insert("validator1:10:0".to_string());
            state.personhood_authorities.push(kp.public.clone());
            state.validator_pools.insert(
                validator.to_string(),
                helix_executor::state::DelegationPool {
                    total_shares: 500,
                    total_delegated_stake: 550,
                    commission_bps: 1_500,
                },
            );
            let mut delegators = std::collections::HashMap::new();
            delegators.insert(addr(9).to_string(), 500u64);
            state.delegator_shares.insert(validator.to_string(), delegators);
            let mut contract_kv = std::collections::HashMap::new();
            contract_kv.insert(b"greeting".to_vec(), b"hello".to_vec());
            state.contract_storage.insert(validator.to_string(), contract_kv);
            db.save_chain_state(&state).unwrap();
        }

        // Reopen — nothing but the file on disk carries state across this point.
        let db = HelixDb::open(&path).unwrap();
        assert_eq!(db.latest_height(), 0);
        assert_eq!(db.latest_hash(), genesis_hash);
        assert_eq!(db.get_block_by_height(0).unwrap().hash(), genesis_hash);

        let loaded = db.load_chain_state(1_000_000).unwrap();
        assert_eq!(loaded.get(&validator).unwrap().balance, 42);
        // Cumulative issuance (genesis allocation + minted block rewards) must survive a
        // restart too — otherwise a node restart would silently reset the mint counter and
        // let the halving schedule effectively start over, breaking the supply cap.
        assert_eq!(loaded.total_issued, 123_456);
        // A used personhood commitment must also survive a restart — otherwise a
        // replayed proof would be accepted again right after the node restarts.
        assert!(loaded.used_personhood_commitments.contains(&[7u8; 16]));
        // Same for a slashed double-sign incident — otherwise it could be re-slashed
        // (or a node that missed the original slash could apply it a second time)
        // right after a restart.
        assert!(loaded.slashed_double_sign_incidents.contains("validator1:10:0"));
        // The personhood authority must also survive a restart — it's genesis-time-only
        // configuration, never re-read from env/config on subsequent starts.
        assert_eq!(loaded.personhood_authorities, vec![kp.public.clone()]);
        // Delegation pools and delegator shares must also survive a restart — otherwise
        // every delegator's stake and every validator's commission rate would silently
        // vanish the moment a node restarts.
        let pool = loaded.validator_pools.get(&validator.to_string()).unwrap();
        assert_eq!(pool.total_shares, 500);
        assert_eq!(pool.total_delegated_stake, 550);
        assert_eq!(pool.commission_bps, 1_500);
        assert_eq!(
            loaded.delegator_shares.get(&validator.to_string()).unwrap().get(&addr(9).to_string()),
            Some(&500u64)
        );
        // Deployed contract storage must also survive a restart — otherwise every
        // contract's on-chain state would silently reset to empty the moment a node
        // restarts, even though its code and balance would not.
        assert_eq!(
            loaded.contract_storage.get(&validator.to_string()).unwrap().get(b"greeting".as_slice()),
            Some(&b"hello".to_vec())
        );

        let _ = std::fs::remove_file(&path);
    }

    fn fresh_db() -> (HelixDb, std::path::PathBuf) {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "helix-db-address-index-test-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        (HelixDb::open(&path).unwrap(), path)
    }

    #[test]
    fn address_transactions_finds_sent_and_received_newest_first() {
        let (mut db, path) = fresh_db();
        let alice = addr(1);
        let bob = addr(2);
        let carol = addr(3);

        db.put_block(block_with_txs(0, &alice, vec![transfer(&alice, &bob, 0)])).unwrap();
        db.put_block(block_with_txs(
            1,
            &alice,
            vec![transfer(&bob, &alice, 0), transfer(&carol, &bob, 0)],
        ))
        .unwrap();

        let refs = db.address_transactions(alice.to_string().as_str(), 10, 0).unwrap();
        assert_eq!(refs.len(), 2);
        // Newest block first.
        assert_eq!(refs[0].0, 1);
        assert_eq!(refs[1].0, 0);

        // Carol only appears once, in block 1.
        let carol_refs = db.address_transactions(carol.to_string().as_str(), 10, 0).unwrap();
        assert_eq!(carol_refs, vec![(1, 1)]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tx_location_finds_a_committed_transaction() {
        let (mut db, path) = fresh_db();
        let alice = addr(1);
        let bob = addr(2);
        let carol = addr(3);

        let tx0 = transfer(&alice, &bob, 0);
        let tx1_a = transfer(&bob, &alice, 0);
        let tx1_b = transfer(&carol, &bob, 0);
        let (hash0, hash1_a, hash1_b) = (tx0.hash(), tx1_a.hash(), tx1_b.hash());

        db.put_block(block_with_txs(0, &alice, vec![tx0])).unwrap();
        db.put_block(block_with_txs(1, &alice, vec![tx1_a, tx1_b])).unwrap();

        assert_eq!(db.tx_location(&hash0).unwrap(), Some((0, 0)));
        assert_eq!(db.tx_location(&hash1_a).unwrap(), Some((1, 0)));
        assert_eq!(db.tx_location(&hash1_b).unwrap(), Some((1, 1)));

        let _ = std::fs::remove_file(&path);
    }

    /// Regression test: `hlx tx status` called `GET /transactions/:hash`, which
    /// wasn't implemented server-side at all until this fix — a hash that was
    /// never included in any block must resolve as "not found", not error.
    #[test]
    fn tx_location_returns_none_for_an_unknown_hash() {
        let (mut db, path) = fresh_db();
        let alice = addr(1);
        db.put_block(block_with_txs(0, &alice, vec![transfer(&alice, &addr(2), 0)])).unwrap();

        let unknown = transfer(&addr(9), &addr(8), 0).hash();
        assert_eq!(db.tx_location(&unknown).unwrap(), None);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn address_transactions_honors_limit_and_offset() {
        let (mut db, path) = fresh_db();
        let alice = addr(1);
        let bob = addr(2);

        for h in 0..5u64 {
            db.put_block(block_with_txs(h, &alice, vec![transfer(&alice, &bob, h)])).unwrap();
        }

        let page1 = db.address_transactions(alice.to_string().as_str(), 2, 0).unwrap();
        assert_eq!(page1.iter().map(|(h, _)| *h).collect::<Vec<_>>(), vec![4, 3]);

        let page2 = db.address_transactions(alice.to_string().as_str(), 2, 2).unwrap();
        assert_eq!(page2.iter().map(|(h, _)| *h).collect::<Vec<_>>(), vec![2, 1]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn address_transactions_survives_reopening_the_database() {
        let alice = addr(1);
        let bob = addr(2);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "helix-db-address-index-persist-test-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = std::fs::remove_file(&path);

        {
            let mut db = HelixDb::open(&path).unwrap();
            db.put_block(block_with_txs(0, &alice, vec![transfer(&alice, &bob, 0)])).unwrap();
        }

        let db = HelixDb::open(&path).unwrap();
        let refs = db.address_transactions(alice.to_string().as_str(), 10, 0).unwrap();
        assert_eq!(refs, vec![(0, 0)]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cleared_recovery_request_does_not_resurrect_after_reopening() {
        use helix_identity::RecoveryRequest;
        let (db, path) = fresh_db();
        let owner = addr(1);
        let new_key = helix_crypto::KeyPair::generate().public;

        // Save state with an active recovery request for `owner`.
        let mut state = ChainState::new(1_000_000);
        state.set_recovery_request(&owner, RecoveryRequest::new(new_key));
        db.save_chain_state(&state).unwrap();

        // The request is cancelled/completed → removed from state → persisted again.
        state.clear_recovery_request(&owner);
        db.save_chain_state(&state).unwrap();

        // Reopen (like a node restart) and reload: the cleared request must NOT come back —
        // otherwise it would re-lock the account, re-introducing the CancelRecovery-era bug.
        drop(db);
        let db = HelixDb::open(&path).unwrap();
        let loaded = db.load_chain_state(1_000_000).unwrap();
        assert!(
            loaded.recovery_request(&owner).is_none(),
            "a cleared recovery request resurrected from the DB after reopening"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn genesis_validator_stake_survives_reopening_the_database() {
        let (db, path) = fresh_db();
        // Unlike the compile-time default, standing in for a chain launched under a
        // differently-tuned build — the case the stored value exists to survive.
        let launched_with = 330_000 * helix_executor::genesis::NANO_PER_HLX;

        let mut state = ChainState::new(1_000_000);
        state.genesis_validator_stake = launched_with;
        db.save_chain_state(&state).unwrap();

        drop(db);
        let db = HelixDb::open(&path).unwrap();
        let loaded = db.load_chain_state(1_000_000).unwrap();

        assert_eq!(
            loaded.genesis_validator_stake, launched_with,
            "a restart must not quietly swap this chain's genesis stake for the binary's default"
        );
    }

    /// A database written before this key existed must come back with the compile-time default,
    /// because that is provably what such a chain launched with — and the next save writes it
    /// down, so the constant stops having a say from then on. Get this wrong and the migration
    /// pins the wrong number into a live chain's genesis forever.
    #[test]
    fn a_database_predating_the_genesis_stake_key_falls_back_to_the_default() {
        let (db, path) = fresh_db();

        // Save normally, then delete the key to reproduce a DB written by an older build.
        let state = ChainState::new(1_000_000);
        db.save_chain_state(&state).unwrap();
        {
            let tx = db.db.begin_write().unwrap();
            {
                let mut meta = tx.open_table(META).unwrap();
                meta.remove(META_GENESIS_VALIDATOR_STAKE).unwrap();
            }
            tx.commit().unwrap();
        }
        drop(db);

        let db = HelixDb::open(&path).unwrap();
        let loaded = db.load_chain_state(1_000_000).unwrap();
        assert_eq!(
            loaded.genesis_validator_stake,
            helix_executor::genesis::VALIDATOR_GENESIS_STAKE_HLX
                * helix_executor::genesis::NANO_PER_HLX,
        );

        // The migration: one save is enough to pin it down permanently.
        db.save_chain_state(&loaded).unwrap();
        drop(db);
        let db = HelixDb::open(&path).unwrap();
        assert_eq!(
            db.load_chain_state(1_000_000).unwrap().genesis_validator_stake,
            helix_executor::genesis::VALIDATOR_GENESIS_STAKE_HLX
                * helix_executor::genesis::NANO_PER_HLX,
        );
    }

    #[test]
    fn redelegations_survive_reopening_the_database() {
        use helix_executor::state::Redelegation;
        let (db, path) = fresh_db();
        let (src, dst, delegator) = (addr(1), addr(2), addr(3));

        let mut state = ChainState::new(1_000_000);
        state.redelegations.insert(
            src.to_string(),
            vec![Redelegation {
                delegator: delegator.to_string(),
                dst: dst.to_string(),
                amount: 100_000_000_000,
                unlock_height: 302_400,
            }],
        );
        db.save_chain_state(&state).unwrap();

        // A node restart must not forget that this stake is still slashable for `src` —
        // forgetting it would silently hand every in-flight redelegation a free escape.
        drop(db);
        let db = HelixDb::open(&path).unwrap();
        let loaded = db.load_chain_state(1_000_000).unwrap();

        let entries = loaded.redelegations.get(&src.to_string()).expect("src's claim must survive");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].delegator, delegator.to_string());
        assert_eq!(entries[0].dst, dst.to_string());
        assert_eq!(entries[0].amount, 100_000_000_000);
        assert_eq!(entries[0].unlock_height, 302_400);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pruned_redelegation_does_not_resurrect_after_reopening() {
        use helix_executor::state::Redelegation;
        let (db, path) = fresh_db();
        let (src, dst, delegator) = (addr(1), addr(2), addr(3));

        let mut state = ChainState::new(1_000_000);
        state.redelegations.insert(
            src.to_string(),
            vec![Redelegation {
                delegator: delegator.to_string(),
                dst: dst.to_string(),
                amount: 100_000_000_000,
                unlock_height: 302_400,
            }],
        );
        db.save_chain_state(&state).unwrap();

        // The window closes and the entry is pruned out of state, removing the whole `src` key.
        state.prune_expired_redelegations(302_400);
        assert!(state.redelegations.is_empty());
        db.save_chain_state(&state).unwrap();

        // These save loops only insert, so without an explicit stale-key removal the old blob
        // would still be in the table and reload as a live claim — re-exposing stake to a slash
        // window it had already outlived.
        drop(db);
        let db = HelixDb::open(&path).unwrap();
        let loaded = db.load_chain_state(1_000_000).unwrap();
        assert!(
            loaded.redelegations.is_empty(),
            "an expired redelegation resurrected from the DB after reopening"
        );

        let _ = std::fs::remove_file(&path);
    }
}
