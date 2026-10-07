//! The state commitment (#270): a lattice hash over every entry of the chain state.
//!
//! **What it is — the consensus definition.** Every entry of the state is encoded as
//! `bincode((domain, key, value))` — or `(domain, key)` for a set, `(domain, outer, inner, value)`
//! for a map of maps — and mapped by blake3's extendable output onto 1024 sixteen-bit lanes
//! (`LtHash::with`). The commitment is the lane-wise sum of all of them, wrapping, plus one entry
//! for the scalar parameters (`GLOBALS`). `state_hash` is blake3 over a domain tag and the sum's
//! checksum. A sum does not care about order, so no collection needs sorting, and it can be
//! updated: subtract an entry's old encoding, add its new one.
//!
//! **How a node keeps it — local, not consensus.** The collections record what each write
//! overwrote (`tracked`); settling the commitment after a block subtracts those pre-images and adds
//! the current values, so a block costs what it changed, not what the chain holds. A collection
//! without pre-images (deserialized, built whole) is recomputed in full. Either way the result is
//! the same sum — which is why a node may later find its changes differently without a reset.
//!
//! The lattice construction is Solana's (`solana-lattice-hash`, the one their mainnet commits
//! accounts with), not ours. Two properties of it are pinned here because a change in either would
//! be a fork: its output for known inputs (`lattice_hash_known_answers`), and the byte order it
//! reads lanes in — native, so a big-endian build would compute a different hash for every state.

#[cfg(target_endian = "big")]
compile_error!(
    "the state commitment reads blake3 output as native-endian 16-bit lanes (solana-lattice-hash); \
     on a big-endian target every state root would differ from every other node's"
);

use serde::Serialize;
use solana_lattice_hash::lt_hash::LtHash;

use helix_crypto::Hash;

/// Domain tags, one per kind of entry. Never reused, never renumbered: each is part of every
/// committed state root.
pub(crate) mod domain {
    pub const GLOBALS: u8 = 0;
    pub const ACCOUNTS: u8 = 1;
    pub const NAMES: u8 = 2;
    pub const PERSONHOOD: u8 = 3;
    pub const GUARDIANS: u8 = 4;
    pub const RECOVERY_REQUESTS: u8 = 5;
    pub const RECOVERY_KEYS: u8 = 6;
    pub const VALIDATOR_KEYS: u8 = 7;
    pub const ACCOUNT_KEYS: u8 = 8;
    pub const PROPOSALS: u8 = 9;
    pub const USED_PERSONHOOD_COMMITMENTS: u8 = 10;
    pub const SLASHED_DOUBLE_SIGN_INCIDENTS: u8 = 11;
    pub const VALIDATOR_POOLS: u8 = 12;
    pub const DELEGATOR_SHARES: u8 = 13;
    pub const REWARD_ADDRESSES: u8 = 14;
    pub const REDELEGATIONS: u8 = 15;
    pub const CONTRACT_STORAGE: u8 = 16;
    pub const PENDING_VALIDATORS: u8 = 17;
    pub const ACTIVE_VALIDATORS: u8 = 18;
    pub const PROBATIONARY_VALIDATORS: u8 = 19;
    pub const PROBATION_SEEN: u8 = 20;
    pub const MISSED_BLOCKS: u8 = 21;
    pub const JAILED_UNTIL: u8 = 22;
}

/// The lattice hash of one encoded entry.
pub(crate) fn lattice_of(bytes: &[u8]) -> LtHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    LtHash::with(&hasher)
}

/// The lattice hash of one entry: `bincode(parts)`, where `parts` starts with the domain tag.
pub(crate) fn entry<T: Serialize + ?Sized>(parts: &T) -> LtHash {
    lattice_of(&bincode::serialize(parts).expect("state entries always serialize"))
}

/// The state root for a lattice sum.
pub(crate) fn root(lattice: &LtHash) -> Hash {
    let mut bytes = b"helix-state-v2:".to_vec();
    bytes.extend_from_slice(&lattice.checksum().0);
    Hash::digest(&bytes)
}

/// The sum as of the last settlement — `None` until the first. Kept out of serialization: a state
/// that arrives as bytes is recomputed, never trusted to carry its own commitment.
#[derive(Clone, Default)]
pub struct Commitment(pub(crate) Option<LtHash>);

impl std::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(lattice) => write!(f, "Commitment({})", root(lattice).to_hex()),
            None => write!(f, "Commitment(unsettled)"),
        }
    }
}

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::Hash as StdHash;

use crate::governance::GovernanceProposal;
use crate::state::ChainState;
use crate::tracked::{TrackedMap, TrackedSet};

/// One collection's share of the commitment.
trait Part {
    fn is_tracked(&self) -> bool;
    /// Add every entry the collection holds.
    fn add_all(&self, lattice: &mut LtHash);
    /// Subtract what each key written since the last settlement held then, add what it holds now.
    fn fold_touched(&self, lattice: &mut LtHash);
}

struct MapPart<'a, K, V, F> {
    map: &'a TrackedMap<K, V>,
    contribution: F,
}

impl<K: Eq + StdHash, V, F: Fn(&K, &V) -> LtHash> Part for MapPart<'_, K, V, F> {
    fn is_tracked(&self) -> bool {
        self.map.is_tracked()
    }

    fn add_all(&self, lattice: &mut LtHash) {
        for (key, value) in self.map.iter() {
            lattice.mix_in(&(self.contribution)(key, value));
        }
    }

    fn fold_touched(&self, lattice: &mut LtHash) {
        for (key, before) in self.map.touched() {
            if let Some(value) = before {
                lattice.mix_out(&(self.contribution)(key, value));
            }
            if let Some(value) = self.map.get(key) {
                lattice.mix_in(&(self.contribution)(key, value));
            }
        }
    }
}

struct SetPart<'a, K> {
    set: &'a TrackedSet<K>,
    domain: u8,
}

impl<K: Eq + StdHash + Serialize> Part for SetPart<'_, K> {
    fn is_tracked(&self) -> bool {
        self.set.is_tracked()
    }

    fn add_all(&self, lattice: &mut LtHash) {
        for key in self.set.iter() {
            lattice.mix_in(&entry(&(self.domain, key)));
        }
    }

    fn fold_touched(&self, lattice: &mut LtHash) {
        for (key, was_present) in self.set.touched() {
            if *was_present {
                lattice.mix_out(&entry(&(self.domain, key)));
            }
            if self.set.contains(key) {
                lattice.mix_in(&entry(&(self.domain, key)));
            }
        }
    }
}

/// A plain `(domain, key, value)` entry.
fn keyed<K: Serialize, V: Serialize>(domain: u8) -> impl Fn(&K, &V) -> LtHash {
    move |key, value| entry(&(domain, key, value))
}

/// A map of maps contributes one `(domain, outer, inner, value)` entry per inner key — the sum of
/// them, so that a later node can update inner keys one at a time under the same definition.
fn nested<K: Serialize, I: Serialize, V: Serialize>(domain: u8) -> impl Fn(&K, &HashMap<I, V>) -> LtHash {
    move |outer, inner| {
        let mut sum = LtHash::identity();
        for (key, value) in inner {
            sum.mix_in(&entry(&(domain, outer, key, value)));
        }
        sum
    }
}

/// A proposal as committed: its voters sorted, because they are held in a `HashSet`.
fn proposal_entry(id: &u64, p: &GovernanceProposal) -> LtHash {
    let mut voters: Vec<&str> = p.voters.iter().map(String::as_str).collect();
    voters.sort_unstable();
    entry(&(
        domain::PROPOSALS,
        id,
        (
            &p.proposer,
            &p.param,
            p.new_value,
            p.created_at_height,
            voters,
            p.yes_stake,
            p.quorum_denominator,
            p.activation_height,
            p.executed,
        ),
    ))
}

impl ChainState {
    /// Every keyed collection with its share of the commitment. Destructured without `..`: a new
    /// field does not compile until it is either given a part here or named as left out — and a
    /// field left out is state two nodes may disagree on without either noticing.
    fn parts(&self) -> Vec<Box<dyn Part + '_>> {
        let ChainState {
            // Not state of the chain: which chain this is, a per-block scratch record, the height
            // bookkeeping, and the commitment itself.
            chain_id: _,
            balance_journal: _,
            applied_height: _,
            commitment: _,
            // The scalar parameters, committed together as one entry (`globals_entry`).
            total_supply: _,
            total_issued: _,
            total_burned: _,
            governance_params: _,
            next_proposal_id: _,
            protocol_version: _,
            scheduled_upgrade: _,
            personhood_authorities: _,
            genesis_validator_stake: _,
            genesis_allocations: _,
            accounts,
            names,
            personhood,
            guardians,
            recovery_requests,
            recovery_keys,
            validator_keys,
            account_keys,
            proposals,
            used_personhood_commitments,
            slashed_double_sign_incidents,
            validator_pools,
            delegator_shares,
            reward_addresses,
            redelegations,
            contract_storage,
            pending_validators,
            active_validators,
            probationary_validators,
            probation_seen,
            missed_blocks,
            jailed_until,
        } = self;
        vec![
            Box::new(MapPart { map: accounts, contribution: keyed(domain::ACCOUNTS) }),
            Box::new(MapPart { map: names, contribution: keyed(domain::NAMES) }),
            Box::new(MapPart { map: personhood, contribution: keyed(domain::PERSONHOOD) }),
            Box::new(MapPart { map: guardians, contribution: keyed(domain::GUARDIANS) }),
            Box::new(MapPart { map: recovery_requests, contribution: keyed(domain::RECOVERY_REQUESTS) }),
            Box::new(MapPart { map: recovery_keys, contribution: keyed(domain::RECOVERY_KEYS) }),
            Box::new(MapPart { map: validator_keys, contribution: keyed(domain::VALIDATOR_KEYS) }),
            Box::new(MapPart { map: account_keys, contribution: keyed(domain::ACCOUNT_KEYS) }),
            Box::new(MapPart { map: proposals, contribution: proposal_entry }),
            Box::new(SetPart { set: used_personhood_commitments, domain: domain::USED_PERSONHOOD_COMMITMENTS }),
            Box::new(SetPart { set: slashed_double_sign_incidents, domain: domain::SLASHED_DOUBLE_SIGN_INCIDENTS }),
            Box::new(MapPart { map: validator_pools, contribution: keyed(domain::VALIDATOR_POOLS) }),
            Box::new(MapPart { map: delegator_shares, contribution: nested(domain::DELEGATOR_SHARES) }),
            Box::new(MapPart { map: reward_addresses, contribution: keyed(domain::REWARD_ADDRESSES) }),
            Box::new(MapPart { map: redelegations, contribution: keyed(domain::REDELEGATIONS) }),
            Box::new(MapPart { map: contract_storage, contribution: nested(domain::CONTRACT_STORAGE) }),
            Box::new(SetPart { set: pending_validators, domain: domain::PENDING_VALIDATORS }),
            Box::new(SetPart { set: active_validators, domain: domain::ACTIVE_VALIDATORS }),
            Box::new(SetPart { set: probationary_validators, domain: domain::PROBATIONARY_VALIDATORS }),
            Box::new(SetPart { set: probation_seen, domain: domain::PROBATION_SEEN }),
            Box::new(MapPart { map: missed_blocks, contribution: keyed(domain::MISSED_BLOCKS) }),
            Box::new(MapPart { map: jailed_until, contribution: keyed(domain::JAILED_UNTIL) }),
        ]
    }

    /// The scalar parameters as one entry. Small and fixed in size, so recomputed on every read
    /// rather than tracked.
    fn globals_entry(&self) -> LtHash {
        let personhood_authorities: BTreeSet<&[u8]> =
            self.personhood_authorities.iter().map(|k| k.as_bytes()).collect();
        let genesis_allocations: BTreeMap<&str, u64> =
            self.genesis_allocations.iter().map(|(a, n)| (a.as_str(), *n)).collect();
        entry(&(
            domain::GLOBALS,
            (
                self.total_supply,
                self.total_issued,
                self.total_burned,
                &self.governance_params,
                self.next_proposal_id,
                personhood_authorities,
                self.genesis_validator_stake,
                genesis_allocations,
                self.protocol_version,
                self.scheduled_upgrade.map(|u| (u.version, u.height)),
            ),
        ))
    }

    /// The keyed collections' sum, from every entry.
    fn full_lattice(&self) -> LtHash {
        let mut lattice = LtHash::identity();
        for part in self.parts() {
            part.add_all(&mut lattice);
        }
        lattice
    }

    /// The keyed collections' sum, brought forward from the last settlement by what was written
    /// since. `None` when there is no settlement to start from or a collection lost track.
    fn incremental_lattice(&self) -> Option<LtHash> {
        let mut lattice = self.commitment.0.clone()?;
        let parts = self.parts();
        if !parts.iter().all(|part| part.is_tracked()) {
            return None;
        }
        for part in &parts {
            part.fold_touched(&mut lattice);
        }
        Some(lattice)
    }

    /// The chain's state commitment. Every block carries the root of the state its predecessor
    /// produced (`BlockHeader::prev_state_root`, #194), signed by its proposer and checked by every
    /// node that applies it: in consensus, in the P2P block sync and in the RPC sync (#242). Two
    /// nodes whose execution diverged therefore find out at the next block, and a snapshot can be
    /// checked against a signed header (`HELIX_TRUSTED_CHECKPOINT`). Anything that belongs to the
    /// state goes in here — `parts` will not compile until a new field says whether it does.
    ///
    /// Costs what was written since the last settlement, or every entry when there is none (a
    /// state loaded or received whole, before `settle_commitment`). Until 2026-10-07 this rehashed
    /// the whole state on every call — 55 ms at 100,000 accounts, asked for every proposal sent and
    /// received and for every `/status` (#270).
    pub fn state_hash(&self) -> Hash {
        let mut lattice = self.incremental_lattice().unwrap_or_else(|| self.full_lattice());
        lattice.mix_in(&self.globals_entry());
        root(&lattice)
    }

    /// Fold everything written since the last settlement into the commitment and start recording
    /// afresh. `execute_block` settles after every block; a state loaded or received whole settles
    /// once, which is its one full computation.
    pub fn settle_commitment(&mut self) {
        let lattice = self.incremental_lattice().unwrap_or_else(|| self.full_lattice());
        self.commitment = Commitment(Some(lattice));
        let ChainState {
            chain_id: _,
            balance_journal: _,
            applied_height: _,
            commitment: _,
            total_supply: _,
            total_issued: _,
            total_burned: _,
            governance_params: _,
            next_proposal_id: _,
            protocol_version: _,
            scheduled_upgrade: _,
            personhood_authorities: _,
            genesis_validator_stake: _,
            genesis_allocations: _,
            accounts,
            names,
            personhood,
            guardians,
            recovery_requests,
            recovery_keys,
            validator_keys,
            account_keys,
            proposals,
            used_personhood_commitments,
            slashed_double_sign_incidents,
            validator_pools,
            delegator_shares,
            reward_addresses,
            redelegations,
            contract_storage,
            pending_validators,
            active_validators,
            probationary_validators,
            probation_seen,
            missed_blocks,
            jailed_until,
        } = self;
        accounts.settled();
        names.settled();
        personhood.settled();
        guardians.settled();
        recovery_requests.settled();
        recovery_keys.settled();
        validator_keys.settled();
        account_keys.settled();
        proposals.settled();
        used_personhood_commitments.settled();
        slashed_double_sign_incidents.settled();
        validator_pools.settled();
        delegator_shares.settled();
        reward_addresses.settled();
        redelegations.settled();
        contract_storage.settled();
        pending_validators.settled();
        active_validators.settled();
        probationary_validators.settled();
        probation_seen.settled();
        missed_blocks.settled();
        jailed_until.settled();
    }

    /// Debug builds: the commitment kept from writes equals the one recomputed from every entry.
    /// A difference means a write reached the state without passing through its tracked
    /// collection — on a live node that would be a root no restarted node agrees with.
    #[cfg(debug_assertions)]
    pub(crate) fn assert_commitment_is_exact(&self) {
        if let Some(incremental) = self.incremental_lattice() {
            let full = self.full_lattice();
            assert!(
                incremental == full,
                "the state commitment kept from writes ({}) differs from a full recomputation ({}) \
                 — a write reached the state without passing through its tracked collection",
                root(&incremental).to_hex(),
                root(&full).to_hex()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::PublicKey;
    use helix_crypto::Address;

    /// The lattice construction's own published answers (solana-lattice-hash 4.2.2,
    /// `test_hello_world`). Every state root depends on them: an update of the crate that changed
    /// either would be a fork with everyone not running it, so it has to turn this red first.
    #[test]
    fn lattice_hash_known_answers() {
        assert_eq!(
            lattice_of(b"hello").checksum().0,
            [
                79, 156, 26, 184, 156, 205, 94, 208, 182, 235, 33, 147, 111, 153, 229, 152, 207,
                133, 75, 109, 182, 198, 119, 61, 11, 81, 41, 70, 24, 87, 100, 85,
            ]
        );
        assert_eq!(
            lattice_of(b"world!").checksum().0,
            [
                171, 53, 185, 10, 179, 49, 48, 151, 87, 43, 141, 13, 43, 152, 121, 1, 144, 7, 120,
                188, 115, 248, 214, 220, 229, 210, 175, 134, 215, 231, 18, 245,
            ]
        );
    }

    #[test]
    fn domain_tags_are_distinct() {
        use domain::*;
        let tags = [
            GLOBALS, ACCOUNTS, NAMES, PERSONHOOD, GUARDIANS, RECOVERY_REQUESTS, RECOVERY_KEYS,
            VALIDATOR_KEYS, ACCOUNT_KEYS, PROPOSALS, USED_PERSONHOOD_COMMITMENTS,
            SLASHED_DOUBLE_SIGN_INCIDENTS, VALIDATOR_POOLS, DELEGATOR_SHARES, REWARD_ADDRESSES,
            REDELEGATIONS, CONTRACT_STORAGE, PENDING_VALIDATORS, ACTIVE_VALIDATORS,
            PROBATIONARY_VALIDATORS, PROBATION_SEEN, MISSED_BLOCKS, JAILED_UNTIL,
        ];
        let distinct: std::collections::BTreeSet<u8> = tags.iter().copied().collect();
        assert_eq!(distinct.len(), tags.len(), "two collections share a domain tag");
    }

    /// Byte patterns, not keys: hashing them into the state needs no valid key.
    fn key(n: u8) -> PublicKey {
        PublicKey::from_bytes(vec![n; 1952])
    }

    fn address(n: u8) -> Address {
        Address::from_public_key(&key(n))
    }

    /// A state with something in every collection, settled.
    fn populated() -> ChainState {
        let mut state = ChainState::new(1_000_000);
        for n in 1..=5u8 {
            let a = address(n);
            state.update_account(&a, |acc| {
                acc.balance = 1_000 * n as u64;
                acc.nonce = n as u64;
            });
            state.names.insert(format!("name{n}"), a.to_string());
            state.missed_blocks.insert(a.to_string(), n as u32);
            state.jailed_until.insert(a.to_string(), 100 + n as u64);
            state.pending_validators.insert(a.clone());
            state.active_validators.insert(a.clone());
            state.slashed_double_sign_incidents.insert(format!("incident-{n}"));
            state.probation_seen.insert(a.clone());
            state.reward_addresses.insert(a.to_string(), address(9));
            state.used_personhood_commitments.insert([n; 16]);
            state.delegator_shares.entry(address(1).to_string()).or_default().insert(a.to_string(), n as u64);
            state
                .contract_storage
                .entry(address(2).to_string())
                .or_default()
                .insert(vec![n], vec![n, n]);
        }
        state.settle_commitment();
        state
    }

    /// What a node that just started would compute for the same state: everything from scratch.
    fn recomputed(state: &ChainState) -> Hash {
        let copy: ChainState = bincode::deserialize(&bincode::serialize(state).unwrap()).unwrap();
        assert!(copy.commitment.0.is_none(), "a state received as bytes carries no commitment");
        copy.state_hash()
    }

    /// The commitment kept from writes is the one a restarted node recomputes — after every kind
    /// of write each collection offers, before and after settling.
    #[test]
    fn writes_keep_the_commitment_equal_to_a_full_recomputation() {
        let mut state = populated();
        let settled_root = state.state_hash();
        assert_eq!(settled_root, recomputed(&state), "positive control: equal right after settling");

        state.update_account(&address(1), |acc| acc.balance += 1); // entry, changed
        state.update_account(&address(2), |_| {}); // entry, unchanged
        state.update_account(&address(9), |acc| acc.balance = 7); // entry, new key
        state.names.remove("name3"); // remove
        state.names.insert("name1".into(), address(5).to_string()); // overwrite
        state.names.insert("fresh".into(), address(5).to_string()); // insert
        state.names.insert("gone-again".into(), address(5).to_string()); // insert, then
        state.names.remove("gone-again"); // remove in the same block
        if let Some(n) = state.missed_blocks.get_mut(&address(4).to_string()) {
            *n += 3; // get_mut
        }
        state.jailed_until.retain(|_, until| *until % 2 == 0); // retain
        state.pending_validators.remove(&address(2)); // set remove
        state.active_validators.insert(address(9)); // set insert
        state.used_personhood_commitments.retain(|c| c[0] != 3); // set retain
        state
            .delegator_shares
            .get_mut(&address(1).to_string())
            .unwrap()
            .insert(address(3).to_string(), 99); // nested, inner overwrite
        state.contract_storage.remove(&address(2).to_string()); // nested, whole outer key
        state.probation_seen.clear(); // set clear (every epoch rotation does this)
        state.reward_addresses.clear(); // map clear

        assert_ne!(state.state_hash(), settled_root, "positive control: the writes changed the state");
        assert_eq!(state.state_hash(), recomputed(&state), "before settling");
        state.settle_commitment();
        assert_eq!(state.state_hash(), recomputed(&state), "after settling");
        state.assert_commitment_is_exact();
    }

    /// Two nodes that built the same state in different orders commit to the same root.
    #[test]
    fn the_root_does_not_depend_on_the_order_entries_were_written_in() {
        let mut one = ChainState::new(0);
        let mut two = ChainState::new(0);
        for n in 1..=20u8 {
            one.update_account(&address(n), |acc| acc.balance = n as u64);
        }
        for n in (1..=20u8).rev() {
            two.update_account(&address(n), |acc| acc.balance = n as u64);
        }
        one.settle_commitment();
        assert_eq!(one.state_hash(), two.state_hash());
    }

    /// A pass over every value mutably cannot say which changed: the collection drops out of
    /// incremental tracking, and the root is recomputed — still exact.
    #[test]
    fn a_write_to_every_value_at_once_falls_back_to_a_full_recomputation() {
        let mut state = populated();
        for acc in state.accounts.values_mut() {
            acc.balance += 1;
        }
        assert!(state.incremental_lattice().is_none(), "no pre-images, no incremental update");
        assert_eq!(state.state_hash(), recomputed(&state));
        state.settle_commitment();
        assert!(state.incremental_lattice().is_some(), "settling brings it back");
        assert_eq!(state.state_hash(), recomputed(&state));
    }

    /// Every collection is in the root: one change anywhere moves it.
    #[test]
    fn a_change_in_any_collection_changes_the_root() {
        type Change = fn(&mut ChainState);
        let changes: &[(&str, Change)] = &[
            ("accounts", |s| s.update_account(&address(1), |a| a.nonce += 1)),
            ("names", |s| { s.names.insert("x".into(), "y".into()); }),
            ("account_keys", |s| { s.account_keys.insert(address(7).to_string(), key(7)); }),
            ("validator_keys", |s| { s.validator_keys.insert(address(7).to_string(), key(7)); }),
            ("recovery_keys", |s| { s.recovery_keys.insert(address(7).to_string(), key(7)); }),
            ("used_personhood_commitments", |s| { s.used_personhood_commitments.insert([9; 16]); }),
            ("slashed_double_sign_incidents", |s| { s.slashed_double_sign_incidents.insert("new".into()); }),
            ("delegator_shares", |s| { s.delegator_shares.entry("v".into()).or_default().insert("d".into(), 1); }),
            ("reward_addresses", |s| { s.reward_addresses.insert(address(1).to_string(), address(2)); }),
            ("contract_storage", |s| { s.contract_storage.entry("c".into()).or_default().insert(vec![1], vec![2]); }),
            ("pending_validators", |s| { s.pending_validators.insert(address(8)); }),
            ("active_validators", |s| { s.active_validators.insert(address(8)); }),
            ("probationary_validators", |s| { s.probationary_validators.insert(address(8)); }),
            ("probation_seen", |s| { s.probation_seen.insert(address(8)); }),
            ("missed_blocks", |s| { s.missed_blocks.insert("x".into(), 1); }),
            ("jailed_until", |s| { s.jailed_until.insert("x".into(), 1); }),
            ("personhood", |s| { s.personhood.insert(address(1).to_string(), helix_identity::PersonhoodStatus::Verified { verified_at_height: 3 }); }),
            ("guardians", |s| { s.guardians.insert(address(1).to_string(), helix_identity::GuardianSet { guardians: vec![address(2)] }); }),
            ("recovery_requests", |s| { s.recovery_requests.insert(address(1).to_string(), helix_identity::RecoveryRequest { votes: vec![] }); }),
            ("proposals", |s| {
                s.proposals.insert(
                    1,
                    crate::governance::GovernanceProposal {
                        id: 1,
                        proposer: address(1).to_string(),
                        param: crate::governance::GovernanceParam::FuelPerFeeUnit,
                        new_value: 2,
                        created_at_height: 3,
                        voters: [address(1).to_string(), address(2).to_string()].into_iter().collect(),
                        yes_stake: 4,
                        quorum_denominator: 5,
                        activation_height: 0,
                        executed: false,
                    },
                );
            }),
            ("validator_pools", |s| { s.validator_pools.insert(address(1).to_string(), crate::state::DelegationPool { total_shares: 1, total_delegated_stake: 1, commission_bps: 0 }); }),
            ("redelegations", |s| {
                s.redelegations.insert(
                    address(1).to_string(),
                    vec![crate::state::Redelegation { delegator: address(1).to_string(), dst: address(2).to_string(), amount: 1, unlock_height: 9 }],
                );
            }),
            ("total_supply", |s| s.total_supply += 1),
            ("total_issued", |s| s.total_issued += 1),
            ("total_burned", |s| s.total_burned += 1),
            ("governance_params", |s| s.governance_params.fuel_per_fee_unit += 1),
            ("next_proposal_id", |s| s.next_proposal_id += 1),
            ("protocol_version", |s| s.protocol_version += 1),
            ("scheduled_upgrade", |s| s.scheduled_upgrade = Some(crate::governance::ScheduledUpgrade { version: 2, height: 9 })),
            ("personhood_authorities", |s| s.personhood_authorities.push(key(6))),
            ("genesis_validator_stake", |s| s.genesis_validator_stake += 1),
            ("genesis_allocations", |s| s.genesis_allocations.push((address(6), 1))),
        ];
        assert_eq!(
            changes.len(),
            22 + 10,
            "every committed collection and every global, once each — see `parts` and `globals_entry`"
        );
        let base = populated();
        let root = base.state_hash();
        for (name, change) in changes {
            let mut changed = base.clone();
            change(&mut changed);
            assert_ne!(changed.state_hash(), root, "a change in {name} must move the root");
            assert_eq!(changed.state_hash(), recomputed(&changed), "{name}: incremental is exact");
        }
    }
}
