pub mod genesis;
pub mod receipt;
pub mod state;

pub use genesis::GenesisConfig;
pub use receipt::{BlockReceipt, Receipt};
pub use state::{AccountState, ChainState};

use helix_core::{transaction::TxType, Block, Transaction};
use helix_crypto::{Address, Hash, PublicKey};
use helix_identity::{GuardianSet, HelixName, RecoveryRequest};
use thiserror::Error;

pub use helix_identity::{PersonhoodError, PersonhoodStatus};

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    #[error("Insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: u64, have: u64 },
    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },
    #[error("Signature verification failed")]
    InvalidSignature,
    #[error("Invalid transaction: {0}")]
    Invalid(String),
}

pub type ExecutionResult<T> = Result<T, ExecutionError>;

/// Execute all transactions in a block, updating chain state in place.
/// Skips invalid transactions (records failure in receipt) rather than
/// reverting the whole block — validators earn fees even on failed txs.
/// Execute all transactions in a block and distribute fees.
///
/// `reward_address` — where the validator's 50 % fee share lands.
/// Falls back to the block's validator address when `None`.
pub fn execute_block(
    state: &mut ChainState,
    block: &Block,
    reward_address: Option<&Address>,
) -> BlockReceipt {
    let validator = block.header.validator.clone();
    let fee_recipient = reward_address.unwrap_or(&validator);
    let mut receipts = Vec::with_capacity(block.transactions.len());
    let mut total_burned = 0u64;
    let mut total_validator_reward = 0u64;

    let height = block.height();
    for tx in &block.transactions {
        let receipt = execute_transaction(state, tx, fee_recipient, height);
        total_burned += receipt.fee_burned;
        total_validator_reward += receipt.fee_to_validator;
        receipts.push(receipt);
    }

    state.total_burned = state.total_burned.saturating_add(total_burned);

    BlockReceipt {
        block_hash: block.hash().to_hex(),
        height: block.height(),
        tx_receipts: receipts,
        total_burned,
        validator_reward: total_validator_reward,
    }
}

/// Execute a single transaction against the current chain state.
pub fn execute_transaction(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    height: u64,
) -> Receipt {
    let tx_hash = tx.hash();

    // Signature check first — fee is still charged on nonce/balance failure
    if !verify_tx_signature(state, tx) {
        return Receipt::failure(tx_hash, "invalid signature", 0, 0);
    }

    match tx.tx_type {
        TxType::Transfer => execute_transfer(state, tx, validator, tx_hash),
        TxType::Stake => execute_stake(state, tx, validator, tx_hash),
        TxType::Unstake => execute_unstake(state, tx, validator, tx_hash),
        TxType::RegisterName => execute_register_name(state, tx, validator, tx_hash),
        TxType::RegisterIdentity => execute_register_identity(state, tx, validator, tx_hash, height),
        TxType::RegisterGuardians => execute_register_guardians(state, tx, validator, tx_hash),
        TxType::ApproveRecovery => execute_approve_recovery(state, tx, validator, tx_hash),
        TxType::DeployContract | TxType::CallContract => {
            // WASM VM is Phase 4 — accept and charge fee, no state change yet
            charge_fee_only(state, tx, validator, tx_hash)
        }
    }
}

/// Verify a transaction's signature, accounting for social recovery: if `tx.from`'s
/// control was ever rotated by guardian quorum (see [`execute_approve_recovery`]), the
/// active override key must have produced the signature — the address no longer needs to
/// derive from `tx.public_key`, since that's the whole point of a recovered account.
/// Otherwise this falls back to the normal address-derivation + ML-DSA check.
fn verify_tx_signature(state: &ChainState, tx: &Transaction) -> bool {
    match state.recovery_key(&tx.from) {
        Some(active_key) => {
            tx.public_key.as_bytes() == active_key.as_bytes()
                && helix_crypto::verify(active_key, tx.signing_hash().as_bytes(), &tx.signature).is_ok()
        }
        None => tx.verify_signature().is_ok(),
    }
}

fn execute_transfer(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(
            tx_hash,
            &format!("nonce mismatch: expected {}, got {}", sender.nonce, tx.nonce),
            0,
            0,
        );
    }

    let total_cost = tx.amount.saturating_add(tx.fee);
    if sender.balance < total_cost {
        return Receipt::failure(
            tx_hash,
            &format!(
                "insufficient balance: need {}, have {}",
                total_cost, sender.balance
            ),
            0,
            0,
        );
    }

    // Deduct from sender
    state.update_account(&tx.from, |acc| {
        acc.balance -= total_cost;
        acc.nonce += 1;
    });

    // Credit receiver
    if let Some(to) = &tx.to {
        state.update_account(to, |acc| {
            acc.balance += tx.amount;
        });
    }

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn execute_stake(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }

    let total_cost = tx.amount.saturating_add(tx.fee);
    if sender.balance < total_cost {
        return Receipt::failure(tx_hash, "insufficient balance", 0, 0);
    }

    state.update_account(&tx.from, |acc| {
        acc.balance -= total_cost;
        acc.staked += tx.amount;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn execute_unstake(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }
    if sender.staked < tx.amount {
        return Receipt::failure(tx_hash, "insufficient staked amount", 0, 0);
    }
    if sender.balance < tx.fee {
        return Receipt::failure(tx_hash, "insufficient balance for fee", 0, 0);
    }

    state.update_account(&tx.from, |acc| {
        acc.staked -= tx.amount;
        acc.balance += tx.amount; // returned immediately (unbonding period: Phase 4)
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn execute_register_name(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }
    if sender.balance < tx.fee {
        return Receipt::failure(tx_hash, "insufficient balance for fee", 0, 0);
    }

    let raw_name = match std::str::from_utf8(&tx.data) {
        Ok(s) => s,
        Err(_) => return Receipt::failure(tx_hash, "name payload is not valid UTF-8", 0, 0),
    };
    let name = match HelixName::new(raw_name) {
        Ok(n) => n,
        Err(e) => return Receipt::failure(tx_hash, &format!("invalid name: {e}"), 0, 0),
    };

    if state.resolve_name(name.as_str()).is_some() {
        return Receipt::failure(tx_hash, "name already registered", 0, 0);
    }

    state.names.insert(name.as_str().to_string(), tx.from.to_string());
    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// Proof of Personhood: `tx.from` attests that `tx.to` is a unique human.
/// Phase 1 sybil resistance is social-graph only (any address may attest);
/// ZK-STARK-based verification replaces this in a later phase.
fn execute_register_identity(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    height: u64,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }
    if sender.balance < tx.fee {
        return Receipt::failure(tx_hash, "insufficient balance for fee", 0, 0);
    }

    let Some(attestee) = tx.to.clone() else {
        return Receipt::failure(tx_hash, "attestation requires a target address (tx.to)", 0, 0);
    };
    if attestee == tx.from {
        return Receipt::failure(tx_hash, "cannot attest your own identity", 0, 0);
    }

    let current = state.personhood_status(&attestee);
    let updated = match current.attest(tx.from.clone(), height) {
        Ok(status) => status,
        Err(e) => return Receipt::failure(tx_hash, &e.to_string(), 0, 0),
    };
    state.set_personhood_status(&attestee, updated);

    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// Owner registers (or replaces) their social-recovery guardian set. `tx.data` is a
/// newline-separated list of guardian address strings. Blocked while a recovery vote is
/// in progress, so guardians can't be swapped out mid-recovery to sabotage a quorum.
fn execute_register_guardians(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }
    if sender.balance < tx.fee {
        return Receipt::failure(tx_hash, "insufficient balance for fee", 0, 0);
    }
    if state.recovery_request(&tx.from).is_some() {
        return Receipt::failure(
            tx_hash,
            "cannot change guardians while a recovery request is pending",
            0,
            0,
        );
    }

    let raw = match std::str::from_utf8(&tx.data) {
        Ok(s) => s,
        Err(_) => return Receipt::failure(tx_hash, "guardian payload is not valid UTF-8", 0, 0),
    };
    let mut guardians = Vec::new();
    for line in raw.lines().filter(|l| !l.is_empty()) {
        match Address::from_str(line) {
            Ok(addr) => guardians.push(addr),
            Err(e) => {
                return Receipt::failure(tx_hash, &format!("invalid guardian address: {e}"), 0, 0)
            }
        }
    }

    let set = match GuardianSet::new(&tx.from, guardians) {
        Ok(s) => s,
        Err(e) => return Receipt::failure(tx_hash, &e.to_string(), 0, 0),
    };
    state.set_guardians(&tx.from, set);

    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// A registered guardian (`tx.from`) approves rotating `tx.to`'s controlling public key to
/// the one carried in `tx.data`. Once `threshold` (3-of-5) distinct guardians approve the
/// *same* key, it becomes the address's active recovery override (see
/// [`verify_tx_signature`]) — from that point on, only that key can sign for the address.
/// Approving a different key than the one currently pending restarts the vote.
fn execute_approve_recovery(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }
    if sender.balance < tx.fee {
        return Receipt::failure(tx_hash, "insufficient balance for fee", 0, 0);
    }

    let Some(target) = tx.to.clone() else {
        return Receipt::failure(
            tx_hash,
            "recovery approval requires a target address (tx.to)",
            0,
            0,
        );
    };

    let Some(guardian_set) = state.guardians(&target) else {
        return Receipt::failure(tx_hash, "target address has no registered guardians", 0, 0);
    };
    if !guardian_set.contains(&tx.from) {
        return Receipt::failure(
            tx_hash,
            "sender is not a registered guardian for this address",
            0,
            0,
        );
    }
    let threshold = guardian_set.threshold();

    let new_key = PublicKey::from_bytes(tx.data.clone());
    if !new_key.is_valid() {
        return Receipt::failure(tx_hash, "proposed public key is not a valid ML-DSA key", 0, 0);
    }

    let mut request = state
        .recovery_request(&target)
        .filter(|r| r.new_public_key == new_key)
        .cloned()
        .unwrap_or_else(|| RecoveryRequest::new(new_key.clone()));

    let finalized = match request.approve(tx.from.clone(), threshold) {
        Ok(reached) => reached,
        Err(e) => return Receipt::failure(tx_hash, &e.to_string(), 0, 0),
    };

    if finalized {
        state.set_recovery_key(&target, new_key);
        state.clear_recovery_request(&target);
    } else {
        state.set_recovery_request(&target, request);
    }

    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn charge_fee_only(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);
    if sender.balance < tx.fee {
        return Receipt::failure(tx_hash, "insufficient balance for fee", 0, 0);
    }
    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });
    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// 70% of fee is burned (deflationary), 30% goes to the block validator
fn distribute_fee(
    state: &mut ChainState,
    validator: &Address,
    fee: u64,
) -> ExecutionResult<(u64, u64)> {
    let burned = fee / 2;      // 50% deflationary burn
    let reward = fee - burned; // 50% to block validator
    state.update_account(validator, |acc| {
        acc.balance += reward;
    });
    Ok((burned, reward))
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_core::TxType;
    use helix_crypto::{KeyPair, Signature};

    fn signed_register_name_tx(kp: &KeyPair, from: &Address, name: &str, nonce: u64, fee: u64) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::RegisterName,
            from: from.clone(),
            to: None,
            amount: 0,
            fee,
            nonce,
            data: name.as_bytes().to_vec(),
            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    #[test]
    fn register_name_succeeds_and_charges_fee() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        let tx = signed_register_name_tx(&kp, &addr, "alice", 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.resolve_name("alice"), Some(addr.to_string().as_str()));
        assert_eq!(state.name_of(&addr), Some("alice"));
        assert_eq!(state.get(&addr).unwrap().balance, 1_000_000 - 10_000);
        assert_eq!(state.get(&addr).unwrap().nonce, 1);
    }

    #[test]
    fn register_name_rejects_already_taken_name() {
        let kp_a = KeyPair::generate();
        let addr_a = Address::from_public_key(&kp_a.public);
        let kp_b = KeyPair::generate();
        let addr_b = Address::from_public_key(&kp_b.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr_a, |acc| acc.balance = 1_000_000);
        state.update_account(&addr_b, |acc| acc.balance = 1_000_000);

        let tx_a = signed_register_name_tx(&kp_a, &addr_a, "alice", 0, 10_000);
        assert!(execute_transaction(&mut state, &tx_a, &validator, 0).success);

        let tx_b = signed_register_name_tx(&kp_b, &addr_b, "alice", 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx_b, &validator, 0);
        assert!(!receipt.success);
        assert_eq!(state.resolve_name("alice"), Some(addr_a.to_string().as_str()));
    }

    #[test]
    fn register_name_rejects_invalid_name() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        let tx = signed_register_name_tx(&kp, &addr, "AB", 0, 10_000); // too short + uppercase
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);
        assert!(!receipt.success);
        assert!(state.resolve_name("ab").is_none());
    }

    fn signed_attest_tx(kp: &KeyPair, from: &Address, to: &Address, nonce: u64, fee: u64) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::RegisterIdentity,
            from: from.clone(),
            to: Some(to.clone()),
            amount: 0,
            fee,
            nonce,
            data: vec![],
            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    #[test]
    fn attestation_reaches_verified_after_threshold() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let attestee_kp = KeyPair::generate();
        let attestee = Address::from_public_key(&attestee_kp.public);

        let mut state = ChainState::new(0);
        state.update_account(&attestee, |acc| acc.balance = 1_000_000);

        for i in 0..helix_identity::ATTESTATION_THRESHOLD {
            let attester_kp = KeyPair::generate();
            let attester = Address::from_public_key(&attester_kp.public);
            state.update_account(&attester, |acc| acc.balance = 1_000_000);

            let tx = signed_attest_tx(&attester_kp, &attester, &attestee, 0, 10_000);
            let receipt = execute_transaction(&mut state, &tx, &validator, 50 + i as u64);
            assert!(receipt.success, "attestation {i} failed: {:?}", receipt.error);
        }

        assert!(state.has_personhood(&attestee));
    }

    #[test]
    fn attestation_rejects_self_attestation() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        let tx = signed_attest_tx(&kp, &addr, &addr, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 1);
        assert!(!receipt.success);
        assert!(!state.has_personhood(&addr));
    }

    #[test]
    fn attestation_rejects_duplicate_from_same_attester() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let attester_kp = KeyPair::generate();
        let attester = Address::from_public_key(&attester_kp.public);
        let attestee = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&attester, |acc| acc.balance = 1_000_000);

        let tx1 = signed_attest_tx(&attester_kp, &attester, &attestee, 0, 10_000);
        assert!(execute_transaction(&mut state, &tx1, &validator, 1).success);

        let tx2 = signed_attest_tx(&attester_kp, &attester, &attestee, 1, 10_000);
        let receipt = execute_transaction(&mut state, &tx2, &validator, 2);
        assert!(!receipt.success);
    }

    #[test]
    fn attestation_rejects_once_already_verified() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let attestee = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.set_personhood_status(
            &attestee,
            PersonhoodStatus::Verified { verified_at_height: 5 },
        );

        let attester_kp = KeyPair::generate();
        let attester = Address::from_public_key(&attester_kp.public);
        state.update_account(&attester, |acc| acc.balance = 1_000_000);

        let tx = signed_attest_tx(&attester_kp, &attester, &attestee, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 10);
        assert!(!receipt.success);
    }

    fn signed_register_guardians_tx(
        kp: &KeyPair,
        from: &Address,
        guardians: &[Address],
        nonce: u64,
        fee: u64,
    ) -> Transaction {
        let data = guardians
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::RegisterGuardians,
            from: from.clone(),
            to: None,
            amount: 0,
            fee,
            nonce,
            data,
            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    fn signed_approve_recovery_tx(
        kp: &KeyPair,
        from: &Address,
        target: &Address,
        new_public_key: &helix_crypto::PublicKey,
        nonce: u64,
        fee: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::ApproveRecovery,
            from: from.clone(),
            to: Some(target.clone()),
            amount: 0,
            fee,
            nonce,
            data: new_public_key.as_bytes().to_vec(),
            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    #[test]
    fn register_guardians_succeeds_with_valid_set() {
        let owner_kp = KeyPair::generate();
        let owner = Address::from_public_key(&owner_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&owner, |acc| acc.balance = 1_000_000);

        let guardians: Vec<Address> = (0..5)
            .map(|_| Address::from_public_key(&KeyPair::generate().public))
            .collect();
        let tx = signed_register_guardians_tx(&owner_kp, &owner, &guardians, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.guardians(&owner).unwrap().guardians.len(), 5);
        assert_eq!(state.guardians(&owner).unwrap().threshold(), 3);
    }

    #[test]
    fn register_guardians_rejects_too_few() {
        let owner_kp = KeyPair::generate();
        let owner = Address::from_public_key(&owner_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&owner, |acc| acc.balance = 1_000_000);

        let guardians: Vec<Address> = (0..2)
            .map(|_| Address::from_public_key(&KeyPair::generate().public))
            .collect();
        let tx = signed_register_guardians_tx(&owner_kp, &owner, &guardians, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(!receipt.success);
        assert!(state.guardians(&owner).is_none());
    }

    #[test]
    fn recovery_quorum_rotates_control_and_old_key_stops_working() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let owner_kp = KeyPair::generate();
        let owner = Address::from_public_key(&owner_kp.public);

        let mut state = ChainState::new(0);
        state.update_account(&owner, |acc| acc.balance = 1_000_000);

        let guardian_kps: Vec<KeyPair> = (0..5).map(|_| KeyPair::generate()).collect();
        let guardian_addrs: Vec<Address> = guardian_kps
            .iter()
            .map(|kp| Address::from_public_key(&kp.public))
            .collect();
        for addr in &guardian_addrs {
            state.update_account(addr, |acc| acc.balance = 1_000_000);
        }

        let reg_tx = signed_register_guardians_tx(&owner_kp, &owner, &guardian_addrs, 0, 10_000);
        assert!(execute_transaction(&mut state, &reg_tx, &validator, 0).success);

        // Owner loses their key; guardians agree on a new one.
        let new_kp = KeyPair::generate();

        // 2 of 5 approvals — below the 3-of-5 threshold, no rotation yet.
        for i in 0..2 {
            let tx = signed_approve_recovery_tx(
                &guardian_kps[i],
                &guardian_addrs[i],
                &owner,
                &new_kp.public,
                0,
                10_000,
            );
            let receipt = execute_transaction(&mut state, &tx, &validator, 1);
            assert!(receipt.success, "approval {i} failed: {:?}", receipt.error);
        }
        assert!(state.recovery_key(&owner).is_none());

        // 3rd approval reaches threshold — control rotates.
        let tx = signed_approve_recovery_tx(
            &guardian_kps[2],
            &guardian_addrs[2],
            &owner,
            &new_kp.public,
            0,
            10_000,
        );
        assert!(execute_transaction(&mut state, &tx, &validator, 1).success);
        assert!(state.recovery_key(&owner).is_some());

        // Old key can no longer sign for this address.
        let old_key_tx = signed_register_guardians_tx(&owner_kp, &owner, &guardian_addrs, 1, 10_000);
        let receipt = execute_transaction(&mut state, &old_key_tx, &validator, 2);
        assert!(!receipt.success, "old key should no longer control the account");

        // New key now controls the address.
        let mut transfer_tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: owner.clone(),
            to: Some(guardian_addrs[0].clone()),
            amount: 100,
            fee: 10_000,
            nonce: 1,
            data: vec![],
            signature: Signature::from_bytes(vec![]),
            public_key: new_kp.public.clone(),
        };
        transfer_tx.signature = new_kp.sign(transfer_tx.signing_hash().as_bytes()).unwrap();
        let receipt = execute_transaction(&mut state, &transfer_tx, &validator, 3);
        assert!(receipt.success, "new key should control the account: {:?}", receipt.error);
    }

    #[test]
    fn approve_recovery_rejects_non_guardian() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let owner_kp = KeyPair::generate();
        let owner = Address::from_public_key(&owner_kp.public);

        let mut state = ChainState::new(0);
        state.update_account(&owner, |acc| acc.balance = 1_000_000);

        let guardian_addrs: Vec<Address> = (0..5)
            .map(|_| Address::from_public_key(&KeyPair::generate().public))
            .collect();
        let reg_tx = signed_register_guardians_tx(&owner_kp, &owner, &guardian_addrs, 0, 10_000);
        assert!(execute_transaction(&mut state, &reg_tx, &validator, 0).success);

        let outsider_kp = KeyPair::generate();
        let outsider = Address::from_public_key(&outsider_kp.public);
        state.update_account(&outsider, |acc| acc.balance = 1_000_000);

        let new_kp = KeyPair::generate();
        let tx = signed_approve_recovery_tx(&outsider_kp, &outsider, &owner, &new_kp.public, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 1);
        assert!(!receipt.success);
        assert!(state.recovery_key(&owner).is_none());
    }
}
