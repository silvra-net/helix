pub mod genesis;
pub mod governance;
pub mod receipt;
pub mod state;

pub use genesis::GenesisConfig;
pub use governance::{GovernanceParam, GovernanceParams, GovernanceProposal};
pub use receipt::{BlockReceipt, Receipt};
pub use state::{AccountState, ChainState, UNBONDING_PERIOD};

use helix_core::{
    transaction::{PersonhoodProofPayload, TxType},
    Block, Transaction,
};
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
        TxType::Unstake => execute_unstake(state, tx, validator, tx_hash, height),

        TxType::RegisterName => execute_register_name(state, tx, validator, tx_hash),
        TxType::RegisterIdentity => execute_register_identity(state, tx, validator, tx_hash, height),
        TxType::RegisterGuardians => execute_register_guardians(state, tx, validator, tx_hash),
        TxType::ApproveRecovery => execute_approve_recovery(state, tx, validator, tx_hash),
        TxType::DeployContract => execute_deploy_contract(state, tx, validator, tx_hash),
        TxType::CallContract => execute_call_contract(state, tx, validator, tx_hash),
        TxType::CreateProposal => execute_create_proposal(state, tx, validator, tx_hash, height),
        TxType::VoteProposal => execute_vote_proposal(state, tx, validator, tx_hash, height),
        TxType::ProvePersonhood => execute_prove_personhood(state, tx, validator, tx_hash),
        TxType::ClaimUnbonded => execute_claim_unbonded(state, tx, validator, tx_hash, height),
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
                && helix_crypto::verify_with_scheme(
                    tx.crypto_version,
                    active_key,
                    tx.signing_hash().as_bytes(),
                    &tx.signature,
                )
                .is_ok()
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
    if tx.amount == 0 {
        return Receipt::failure(tx_hash, "transfer amount must be greater than zero", 0, 0);
    }

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
    height: u64,
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
    // Only one unbonding queue entry at a time — simplifies state and slash accounting.
    if sender.unbonding_stake > 0 {
        return Receipt::failure(
            tx_hash,
            "an unbonding is already in progress; claim it before unstaking more",
            0,
            0,
        );
    }

    let unlock_height = height + state::UNBONDING_PERIOD;
    state.update_account(&tx.from, |acc| {
        acc.staked -= tx.amount;
        // Stake moves to the unbonding queue — still slashable during this period.
        acc.unbonding_stake = tx.amount;
        acc.unbonding_unlock_height = unlock_height;
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn execute_claim_unbonded(
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
    if sender.unbonding_stake == 0 {
        return Receipt::failure(tx_hash, "no unbonding stake to claim", 0, 0);
    }
    if !sender.can_claim_unbonded(height) {
        return Receipt::failure(
            tx_hash,
            &format!(
                "unbonding period not over: unlocks at height {}, current {}",
                sender.unbonding_unlock_height, height
            ),
            0,
            0,
        );
    }

    state.update_account(&tx.from, |acc| {
        acc.balance += acc.unbonding_stake;
        acc.unbonding_stake = 0;
        acc.unbonding_unlock_height = 0;
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

/// Deploy a WASM contract: `tx.data` is validated as a WASM module and stored as the
/// deploying account's code. There's no separate contract-address derivation yet — the
/// deployer's own address becomes the contract account, so only its key can redeploy.
fn execute_deploy_contract(
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
    if tx.to.is_some() {
        return Receipt::failure(tx_hash, "deploy transactions must not set a recipient", 0, 0);
    }
    if tx.data.is_empty() {
        return Receipt::failure(tx_hash, "deploy transaction is missing WASM bytecode", 0, 0);
    }
    if let Err(e) = helix_vm::validate(&tx.data) {
        return Receipt::failure(tx_hash, &format!("invalid contract bytecode: {e}"), 0, 0);
    }

    state.update_account(&tx.from, |acc| {
        acc.code = Some(tx.data.clone());
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// Call a deployed contract at `tx.to`, running its exported `call()` entry point with
/// fuel metering. `tx.amount` (if any) is transferred to the contract's balance only on
/// successful execution, matching normal transfer semantics.
fn execute_call_contract(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }

    let Some(target) = tx.to.clone() else {
        return Receipt::failure(tx_hash, "call transactions require a target contract address", 0, 0);
    };

    let total_cost = tx.amount.saturating_add(tx.fee);
    if sender.balance < total_cost {
        return Receipt::failure(
            tx_hash,
            &format!("insufficient balance: need {}, have {}", total_cost, sender.balance),
            0,
            0,
        );
    }

    let Some(code) = state.get(&target).and_then(|acc| acc.code.clone()) else {
        return Receipt::failure(tx_hash, "target address has no deployed contract", 0, 0);
    };

    let fuel_limit = tx.fee.saturating_mul(state.governance_params.fuel_per_fee_unit);
    if let Err(e) = helix_vm::call(&code, fuel_limit) {
        // Charge the fee and advance the nonce even though the call failed — fuel-
        // metered execution was actually attempted and consumed real validator CPU.
        // Without this, the identical tx (nonce never moved, balance never touched)
        // can be resubmitted and re-executed by every validator forever at zero
        // cost — e.g. a deliberately fuel-exhausting loop makes this a free,
        // repeatable DoS instead of a one-time failed call.
        state.update_account(&tx.from, |acc| {
            acc.balance -= tx.fee;
            acc.nonce += 1;
        });
        return distribute_fee(state, validator, tx.fee)
            .map(|_| Receipt::failure(tx_hash, &format!("contract call failed: {e}"), 0, 0))
            .unwrap_or_else(|de| Receipt::failure(tx_hash, &de.to_string(), 0, 0));
    }

    state.update_account(&tx.from, |acc| {
        acc.balance -= total_cost;
        acc.nonce += 1;
    });
    state.update_account(&target, |acc| {
        acc.balance += tx.amount;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// Create a stake-weighted governance proposal to change one protocol parameter. Only
/// current stakers may propose — same skin-in-the-game requirement as voting.
fn execute_create_proposal(
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
    if sender.staked == 0 {
        return Receipt::failure(tx_hash, "only stakers may create governance proposals", 0, 0);
    }

    let (param, new_value) = match governance::decode_proposal(&tx.data) {
        Ok(p) => p,
        Err(e) => return Receipt::failure(tx_hash, &format!("invalid proposal payload: {e}"), 0, 0),
    };

    let id = state.next_proposal_id;
    state.next_proposal_id += 1;
    state.set_proposal(GovernanceProposal {
        id,
        proposer: tx.from.to_string(),
        param,
        new_value,
        created_at_height: height,
        voters: Default::default(),
        yes_stake: 0,
        // Frozen quorum denominator for this proposal's lifetime — see the field's
        // doc comment on why this must not be recomputed live at vote time.
        total_staked_at_creation: state.total_staked(),
        executed: false,
    });

    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// Cast a stake-weighted yes-vote on a pending proposal (`tx.data` = proposal id). Once
/// accumulated yes-stake crosses the 2/3-plus-one supermajority of total staked HLX, the
/// parameter change is applied immediately and the proposal is marked executed.
fn execute_vote_proposal(
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
    if sender.staked == 0 {
        return Receipt::failure(tx_hash, "only stakers may vote", 0, 0);
    }

    let proposal_id = match governance::decode_vote(&tx.data) {
        Ok(id) => id,
        Err(e) => return Receipt::failure(tx_hash, &format!("invalid vote payload: {e}"), 0, 0),
    };

    let Some(mut proposal) = state.proposal(proposal_id).cloned() else {
        return Receipt::failure(tx_hash, "proposal not found", 0, 0);
    };
    if proposal.executed {
        return Receipt::failure(tx_hash, "proposal already executed", 0, 0);
    }
    if proposal.is_expired(height) {
        return Receipt::failure(tx_hash, "voting period has expired", 0, 0);
    }
    if !proposal.voters.insert(tx.from.to_string()) {
        return Receipt::failure(tx_hash, "address already voted on this proposal", 0, 0);
    }
    proposal.yes_stake = proposal.yes_stake.saturating_add(sender.staked);

    // Quorum is checked against the total stake frozen at proposal creation, not a
    // live recomputation — otherwise a voter could vote yes then immediately
    // unstake, shrinking the denominator while their already-counted yes_stake
    // stays put, letting a trivial follow-up vote cross a quorum that no longer
    // reflects real backing.
    if proposal.yes_stake >= governance::quorum_threshold(proposal.total_staked_at_creation) {
        match proposal.param {
            GovernanceParam::MinValidatorStake => {
                state.governance_params.min_validator_stake = proposal.new_value;
            }
            GovernanceParam::FuelPerFeeUnit => {
                state.governance_params.fuel_per_fee_unit = proposal.new_value;
            }
        }
        proposal.executed = true;
    }
    state.set_proposal(proposal);

    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn execute_prove_personhood(
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

    let payload: PersonhoodProofPayload = match bincode::deserialize(&tx.data) {
        Ok(p) => p,
        Err(_) => return Receipt::failure(tx_hash, "invalid personhood proof payload", 0, 0),
    };

    let proof = helix_zkp::PersonhoodProof::from_bytes(payload.proof_bytes);
    if !helix_zkp::verify_personhood(&proof, payload.commitment) {
        return Receipt::failure(tx_hash, "ZK personhood proof verification failed", 0, 0);
    }

    // Mark account as ZK-STARK personhood-verified in chain state
    state.set_personhood_status(
        &tx.from,
        PersonhoodStatus::Verified { verified_at_height: 0 },
    );
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
            crypto_version: kp.scheme,

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
            crypto_version: kp.scheme,

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
            crypto_version: kp.scheme,

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
            crypto_version: kp.scheme,

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
            crypto_version: Default::default(),

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

    fn valid_contract_wasm() -> Vec<u8> {
        wat::parse_str(r#"(module (func (export "call")))"#).unwrap()
    }

    fn signed_contract_tx(
        kp: &KeyPair,
        from: &Address,
        tx_type: TxType,
        to: Option<Address>,
        amount: u64,
        data: Vec<u8>,
        nonce: u64,
        fee: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type,
            from: from.clone(),
            to,
            amount,
            fee,
            nonce,
            data,
            crypto_version: kp.scheme,

            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    #[test]
    fn deploy_contract_stores_code_and_charges_fee() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        let tx = signed_contract_tx(
            &kp,
            &addr,
            TxType::DeployContract,
            None,
            0,
            valid_contract_wasm(),
            0,
            10_000,
        );
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert!(state.get(&addr).unwrap().code.is_some());
        assert_eq!(state.get(&addr).unwrap().balance, 1_000_000 - 10_000);
    }

    #[test]
    fn deploy_contract_rejects_invalid_bytecode() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        let tx = signed_contract_tx(
            &kp,
            &addr,
            TxType::DeployContract,
            None,
            0,
            b"not wasm".to_vec(),
            0,
            10_000,
        );
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(!receipt.success);
        assert!(state.get(&addr).unwrap().code.is_none());
    }

    #[test]
    fn call_contract_executes_and_transfers_value() {
        let deployer_kp = KeyPair::generate();
        let deployer = Address::from_public_key(&deployer_kp.public);
        let caller_kp = KeyPair::generate();
        let caller = Address::from_public_key(&caller_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&deployer, |acc| acc.balance = 1_000_000);
        state.update_account(&caller, |acc| acc.balance = 1_000_000);

        let deploy_tx = signed_contract_tx(
            &deployer_kp,
            &deployer,
            TxType::DeployContract,
            None,
            0,
            valid_contract_wasm(),
            0,
            10_000,
        );
        assert!(execute_transaction(&mut state, &deploy_tx, &validator, 0).success);

        let call_tx = signed_contract_tx(
            &caller_kp,
            &caller,
            TxType::CallContract,
            Some(deployer.clone()),
            5_000,
            vec![],
            0,
            10_000,
        );
        let receipt = execute_transaction(&mut state, &call_tx, &validator, 1);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.get(&caller).unwrap().balance, 1_000_000 - 5_000 - 10_000);
        assert_eq!(
            state.get(&deployer).unwrap().balance,
            1_000_000 - 10_000 + 5_000
        );
    }

    #[test]
    fn call_contract_rejects_target_without_code() {
        let caller_kp = KeyPair::generate();
        let caller = Address::from_public_key(&caller_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&caller, |acc| acc.balance = 1_000_000);

        let tx = signed_contract_tx(
            &caller_kp,
            &caller,
            TxType::CallContract,
            Some(target),
            0,
            vec![],
            0,
            10_000,
        );
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);
        assert!(!receipt.success);
    }

    #[test]
    fn call_contract_charges_fee_and_advances_nonce_on_out_of_gas_failure() {
        let deployer_kp = KeyPair::generate();
        let deployer = Address::from_public_key(&deployer_kp.public);
        let caller_kp = KeyPair::generate();
        let caller = Address::from_public_key(&caller_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&deployer, |acc| acc.balance = 1_000_000);
        state.update_account(&caller, |acc| acc.balance = 1_000_000);

        let looping_wasm = wat::parse_str(r#"(module (func (export "call") (loop br 0)))"#).unwrap();
        let deploy_tx = signed_contract_tx(
            &deployer_kp,
            &deployer,
            TxType::DeployContract,
            None,
            0,
            looping_wasm,
            0,
            10_000,
        );
        assert!(execute_transaction(&mut state, &deploy_tx, &validator, 0).success);

        let call_tx = signed_contract_tx(
            &caller_kp,
            &caller,
            TxType::CallContract,
            Some(deployer),
            0,
            vec![],
            0,
            1, // 1 fuel unit — nowhere near enough to complete the loop
        );
        let receipt = execute_transaction(&mut state, &call_tx, &validator, 1);

        // The call itself still fails (ran out of fuel) ...
        assert!(!receipt.success);
        // ... but the fee was charged and the nonce advanced anyway, since
        // execution actually ran and consumed real (fuel-metered) CPU — otherwise
        // this exact tx could be resubmitted and re-executed forever for free.
        assert_eq!(state.get(&caller).unwrap().balance, 1_000_000 - 1);
        assert_eq!(state.get(&caller).unwrap().nonce, 1);
    }

    fn signed_governance_tx(
        kp: &KeyPair,
        from: &Address,
        tx_type: TxType,
        data: Vec<u8>,
        nonce: u64,
        fee: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type,
            from: from.clone(),
            to: None,
            amount: 0,
            fee,
            nonce,
            data,
            crypto_version: kp.scheme,

            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    #[test]
    fn create_proposal_rejects_non_staker() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        let data = governance::encode_proposal(governance::GovernanceParam::FuelPerFeeUnit, 5);
        let tx = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(!receipt.success);
        assert!(state.proposals.is_empty());
    }

    #[test]
    fn create_proposal_succeeds_for_staker_and_charges_fee() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 500_000;
        });

        let data = governance::encode_proposal(governance::GovernanceParam::FuelPerFeeUnit, 5);
        let tx = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 100);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        let proposal = state.proposal(0).expect("proposal 0 should exist");
        assert_eq!(proposal.new_value, 5);
        assert_eq!(proposal.created_at_height, 100);
        assert!(!proposal.executed);
        assert_eq!(state.get(&addr).unwrap().balance, 1_000_000 - 10_000);
    }

    #[test]
    fn vote_reaching_supermajority_applies_param_change_immediately() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let proposer_kp = KeyPair::generate();
        let proposer = Address::from_public_key(&proposer_kp.public);
        let voter_kp = KeyPair::generate();
        let voter = Address::from_public_key(&voter_kp.public);

        let mut state = ChainState::new(0);
        // Two stakers, 50/50 split. Neither alone reaches 2/3, but together they do.
        state.update_account(&proposer, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 500_000;
        });
        state.update_account(&voter, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 500_000;
        });

        let data = governance::encode_proposal(governance::GovernanceParam::FuelPerFeeUnit, 99);
        let create_tx =
            signed_governance_tx(&proposer_kp, &proposer, TxType::CreateProposal, data, 0, 10_000);
        assert!(execute_transaction(&mut state, &create_tx, &validator, 0).success);
        assert_eq!(state.governance_params.fuel_per_fee_unit, governance::DEFAULT_FUEL_PER_FEE_UNIT);

        // Proposer's own vote (50%) isn't enough for 2/3 quorum yet.
        let self_vote = signed_governance_tx(
            &proposer_kp,
            &proposer,
            TxType::VoteProposal,
            governance::encode_vote(0),
            1,
            10_000,
        );
        assert!(execute_transaction(&mut state, &self_vote, &validator, 1).success);
        assert!(!state.proposal(0).unwrap().executed);

        // Second staker's vote pushes yes-stake to 100% — crosses the 2/3 threshold.
        let second_vote = signed_governance_tx(
            &voter_kp,
            &voter,
            TxType::VoteProposal,
            governance::encode_vote(0),
            0,
            10_000,
        );
        let receipt = execute_transaction(&mut state, &second_vote, &validator, 2);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert!(state.proposal(0).unwrap().executed);
        assert_eq!(state.governance_params.fuel_per_fee_unit, 99);
    }

    #[test]
    fn vote_rejects_double_voting_from_same_address() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 500_000;
        });

        let data = governance::encode_proposal(governance::GovernanceParam::MinValidatorStake, 1);
        let create_tx = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data, 0, 10_000);
        assert!(execute_transaction(&mut state, &create_tx, &validator, 0).success);

        let vote_tx =
            signed_governance_tx(&kp, &addr, TxType::VoteProposal, governance::encode_vote(0), 1, 10_000);
        assert!(execute_transaction(&mut state, &vote_tx, &validator, 1).success);

        let repeat_vote_tx =
            signed_governance_tx(&kp, &addr, TxType::VoteProposal, governance::encode_vote(0), 2, 10_000);
        let receipt = execute_transaction(&mut state, &repeat_vote_tx, &validator, 2);
        assert!(!receipt.success);
    }

    #[test]
    fn quorum_survives_voter_unstaking_after_voting() {
        // Reproduces the vote-then-unstake manipulation: an attacker votes yes with a
        // large stake (short of quorum alone), then immediately unstakes that same
        // stake. Under the old bug (quorum checked against a live-recomputed total),
        // the shrunk total's quorum threshold could later be crossed by a trivial
        // extra vote using the attacker's already-unstaked, phantom contribution.
        // With quorum frozen at proposal creation, that same trivial vote must still
        // fall short.
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let attacker_kp = KeyPair::generate();
        let attacker = Address::from_public_key(&attacker_kp.public);
        let honest_kp = KeyPair::generate();
        let honest = Address::from_public_key(&honest_kp.public);
        let tiny_kp = KeyPair::generate();
        let tiny = Address::from_public_key(&tiny_kp.public);

        let mut state = ChainState::new(0);
        state.update_account(&attacker, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 200;
        });
        state.update_account(&honest, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 150;
        });
        // `tiny` isn't staked yet — added only after proposal creation, so it never
        // contributes to the frozen quorum denominator, only to `yes_stake`.
        state.update_account(&tiny, |acc| acc.balance = 1_000_000);

        let data = governance::encode_proposal(governance::GovernanceParam::FuelPerFeeUnit, 42);
        let create_tx =
            signed_governance_tx(&attacker_kp, &attacker, TxType::CreateProposal, data, 0, 1);
        assert!(execute_transaction(&mut state, &create_tx, &validator, 0).success);
        // Frozen denominator: 200 (attacker) + 150 (honest) = 350 -> quorum 234.
        assert_eq!(state.proposal(0).unwrap().total_staked_at_creation, 350);
        assert_eq!(governance::quorum_threshold(350), 234);

        let attacker_vote = signed_governance_tx(
            &attacker_kp,
            &attacker,
            TxType::VoteProposal,
            governance::encode_vote(0),
            1,
            1,
        );
        assert!(execute_transaction(&mut state, &attacker_vote, &validator, 1).success);
        // 200 alone is comfortably short of the 234 quorum — not a boundary fluke.
        assert!(!state.proposal(0).unwrap().executed);
        assert_eq!(state.proposal(0).unwrap().yes_stake, 200);

        // Attacker fully unstakes right after voting — their already-counted
        // yes_stake contribution is now backed by nothing.
        let unstake_tx = signed_unstake_tx(&attacker_kp, &attacker, 200, 2, 1);
        assert!(execute_transaction(&mut state, &unstake_tx, &validator, 2).success);
        assert_eq!(state.get(&attacker).unwrap().staked, 0);
        // Live total shrank to 150 (honest only) -- the old bug's quorum_threshold(150) is 101.
        assert_eq!(state.total_staked(), 150);
        assert_eq!(governance::quorum_threshold(state.total_staked()), 101);

        // `tiny` stakes a token amount and votes yes purely to trigger a fresh
        // quorum check. 200 (attacker's stale vote) + 1 (tiny) = 201, which would
        // have crossed the OLD buggy live quorum (101) but must still fall short of
        // the frozen quorum (234).
        state.update_account(&tiny, |acc| acc.staked = 1);
        let tiny_vote = signed_governance_tx(
            &tiny_kp,
            &tiny,
            TxType::VoteProposal,
            governance::encode_vote(0),
            0,
            1,
        );
        let receipt = execute_transaction(&mut state, &tiny_vote, &validator, 3);
        assert!(receipt.success, "vote tx itself should still succeed: {:?}", receipt.error);
        assert_eq!(state.proposal(0).unwrap().yes_stake, 201);
        assert!(
            !state.proposal(0).unwrap().executed,
            "quorum must stay frozen at proposal creation, not shrink with a voter's later unstake"
        );
        assert_eq!(state.governance_params.fuel_per_fee_unit, governance::DEFAULT_FUEL_PER_FEE_UNIT);
    }

    #[test]
    fn vote_rejects_after_voting_period_expires() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let proposer_kp = KeyPair::generate();
        let proposer = Address::from_public_key(&proposer_kp.public);
        let voter_kp = KeyPair::generate();
        let voter = Address::from_public_key(&voter_kp.public);

        let mut state = ChainState::new(0);
        state.update_account(&proposer, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 500_000;
        });
        state.update_account(&voter, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 500_000;
        });

        let data = governance::encode_proposal(governance::GovernanceParam::MinValidatorStake, 1);
        let create_tx = signed_governance_tx(&proposer_kp, &proposer, TxType::CreateProposal, data, 0, 10_000);
        assert!(execute_transaction(&mut state, &create_tx, &validator, 0).success);

        let expired_height = governance::VOTING_PERIOD_BLOCKS + 1;
        let vote_tx =
            signed_governance_tx(&voter_kp, &voter, TxType::VoteProposal, governance::encode_vote(0), 0, 10_000);
        let receipt = execute_transaction(&mut state, &vote_tx, &validator, expired_height);
        assert!(!receipt.success);
    }

    // ── Unbonding / ClaimUnbonded tests ──────────────────────────────────────

    fn signed_tx_simple(kp: &KeyPair, from: &Address, tx_type: TxType, nonce: u64, fee: u64) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type,
            from: from.clone(),
            to: None,
            amount: 0,
            fee,
            nonce,
            data: vec![],
            crypto_version: kp.scheme,
            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    fn signed_unstake_tx(kp: &KeyPair, from: &Address, amount: u64, nonce: u64, fee: u64) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Unstake,
            from: from.clone(),
            to: None,
            amount,
            fee,
            nonce,
            data: vec![],
            crypto_version: kp.scheme,
            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    #[test]
    fn unstake_moves_to_unbonding_not_balance() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 100_000;
            acc.staked = 500_000;
        });

        let tx = signed_unstake_tx(&kp, &addr, 200_000, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 1);
        assert!(receipt.success, "{:?}", receipt.error);

        let acc = state.get(&addr).unwrap();
        assert_eq!(acc.staked, 300_000, "active stake should be reduced");
        assert_eq!(acc.unbonding_stake, 200_000, "unstaked amount should be in unbonding");
        assert_eq!(acc.balance, 90_000, "only fee deducted from balance, unbonded not released");
        assert_eq!(acc.unbonding_unlock_height, 1 + UNBONDING_PERIOD);
    }

    #[test]
    fn claim_unbonded_before_period_fails() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 100_000;
            acc.staked = 500_000;
        });

        let unstake_tx = signed_unstake_tx(&kp, &addr, 200_000, 0, 10_000);
        execute_transaction(&mut state, &unstake_tx, &validator, 1);

        // Try to claim one block before unlock
        let claim_tx = signed_tx_simple(&kp, &addr, TxType::ClaimUnbonded, 1, 10_000);
        let receipt = execute_transaction(&mut state, &claim_tx, &validator, UNBONDING_PERIOD);
        assert!(!receipt.success, "should fail: unlock height is 1 + UNBONDING_PERIOD");
    }

    #[test]
    fn claim_unbonded_after_period_succeeds() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 100_000;
            acc.staked = 500_000;
        });

        let unstake_tx = signed_unstake_tx(&kp, &addr, 200_000, 0, 10_000);
        execute_transaction(&mut state, &unstake_tx, &validator, 1);

        // Claim exactly at unlock height
        let unlock = 1 + UNBONDING_PERIOD;
        let claim_tx = signed_tx_simple(&kp, &addr, TxType::ClaimUnbonded, 1, 10_000);
        let receipt = execute_transaction(&mut state, &claim_tx, &validator, unlock);
        assert!(receipt.success, "{:?}", receipt.error);

        let acc = state.get(&addr).unwrap();
        assert_eq!(acc.unbonding_stake, 0);
        assert_eq!(acc.unbonding_unlock_height, 0);
        // balance: 100_000 - 10_000 (unstake fee) + 200_000 (claimed) - 10_000 (claim fee) = 280_000
        assert_eq!(acc.balance, 280_000);
    }

    #[test]
    fn slash_hits_both_staked_and_unbonding() {
        let addr = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.staked = 1_000_000;
            acc.unbonding_stake = 500_000;
        });

        // 10% slash (1000 bps)
        let slashed = state.slash(&addr, 1_000);
        let acc = state.get(&addr).unwrap();
        assert_eq!(acc.staked, 900_000);
        assert_eq!(acc.unbonding_stake, 450_000);
        assert_eq!(slashed, 150_000); // 100k + 50k
    }

    #[test]
    fn double_unbonding_rejected() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 200_000;
            acc.staked = 1_000_000;
        });

        let tx1 = signed_unstake_tx(&kp, &addr, 300_000, 0, 10_000);
        assert!(execute_transaction(&mut state, &tx1, &validator, 1).success);

        let tx2 = signed_unstake_tx(&kp, &addr, 100_000, 1, 10_000);
        let receipt = execute_transaction(&mut state, &tx2, &validator, 2);
        assert!(!receipt.success, "second unstake while first is unbonding should fail");
    }
}
