pub mod genesis;
pub mod governance;
pub mod receipt;
pub mod state;

pub use genesis::GenesisConfig;
pub use governance::{GovernanceParam, GovernanceParams, GovernanceProposal};
pub use receipt::{BlockReceipt, Receipt};
pub use state::{AccountState, ChainState, UNBONDING_PERIOD};

use helix_consensus::DoubleSignEvidence;
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
        TxType::RegisterIdentity => execute_register_identity(state, tx, tx_hash),
        TxType::RegisterGuardians => execute_register_guardians(state, tx, validator, tx_hash),
        TxType::ApproveRecovery => execute_approve_recovery(state, tx, validator, tx_hash),
        TxType::DeployContract => execute_deploy_contract(state, tx, validator, tx_hash),
        TxType::CallContract => execute_call_contract(state, tx, validator, tx_hash),
        TxType::CreateProposal => execute_create_proposal(state, tx, validator, tx_hash, height),
        TxType::VoteProposal => execute_vote_proposal(state, tx, validator, tx_hash, height),
        TxType::ProvePersonhood => execute_prove_personhood(state, tx, validator, tx_hash),
        TxType::ClaimUnbonded => execute_claim_unbonded(state, tx, validator, tx_hash, height),
        TxType::CancelRecoveryRequest => execute_cancel_recovery_request(state, tx, validator, tx_hash),
        TxType::SubmitDoubleSignEvidence => execute_submit_double_sign_evidence(state, tx, validator, tx_hash),
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

    // If this unstake would drop the sender below the validator minimum, and they're
    // currently the ONLY account that meets it, reject: allowing it would leave
    // ChainState::stakers() empty. rotate_validator_set() can't safely rotate into an empty
    // set (it deliberately no-ops rather than halt block production — see CTO Backlog item
    // 34), so the current validator set's voting power would stay frozen forever even
    // though nobody backing it holds any stake anymore. This only guards voluntary exits;
    // it doesn't (and shouldn't) protect a validator's stake from a deserved slash.
    let min_stake = state.governance_params.min_validator_stake;
    let was_staker = sender.staked >= min_stake;
    let remains_staker = sender.staked.saturating_sub(tx.amount) >= min_stake;
    if was_staker && !remains_staker {
        let other_staker_remains = state.stakers().iter().any(|(addr, _)| addr != &tx.from);
        if !other_staker_remains {
            return Receipt::failure(
                tx_hash,
                "cannot unstake below the validator minimum: you are the last eligible \
                 validator and the network would be left with none",
                0,
                0,
            );
        }
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

/// `RegisterIdentity` was Phase 1's social-graph personhood attestation: any address could
/// attest any other, and `ATTESTATION_THRESHOLD` (3) distinct attesters flipped the target to
/// `PersonhoodStatus::Verified`. That path has been fully superseded by the authority-gated
/// ZK proof in `execute_prove_personhood` (backlog points 27/28) — but was left live and
/// completely undermined that fix: an attacker only needs 3 freely-generated addresses (cost:
/// three tx fees) to attest a target and reach `Verified`, with no ZK proof and no authority
/// signature at all, bypassing Sybil resistance entirely and unlocking the 1% (instead of
/// 0.5%) validator voting-power cap for a fully self-issued identity. Disabled outright,
/// failing closed like the no-authority-configured branch of `execute_prove_personhood` — the
/// only sanctioned path to `Verified` is now the authority-gated ZK proof.
fn execute_register_identity(_state: &mut ChainState, _tx: &Transaction, tx_hash: Hash) -> Receipt {
    Receipt::failure(
        tx_hash,
        "RegisterIdentity (social-graph attestation) is disabled; personhood verification \
         requires an authority-signed ZK proof via ProvePersonhood",
        0,
        0,
    )
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

/// `tx.from` clears their own pending (sub-threshold) `RecoveryRequest`. Without this, a
/// single guardian who approves a bogus key — and never reaches the threshold, whether by
/// mistake, going offline, or acting maliciously — permanently locks the owner out of
/// `RegisterGuardians` (which refuses to run while any recovery request is pending), since
/// there was previously no way to clear a sub-threshold request short of reaching quorum.
fn execute_cancel_recovery_request(
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
    if state.recovery_request(&tx.from).is_none() {
        return Receipt::failure(tx_hash, "no pending recovery request to cancel", 0, 0);
    }

    state.clear_recovery_request(&tx.from);

    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// Applies a slash for a proven double-sign. `tx.from` is just the reporter — anyone may
/// submit this, since both votes carry their own independently-verifiable signatures and the
/// evidence proves itself. Executed identically by every node through the normal transaction
/// pipeline, unlike the validator-local BFT evidence detection that triggers a report (see
/// `TxType::SubmitDoubleSignEvidence`'s doc comment for why that distinction matters).
fn execute_submit_double_sign_evidence(
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

    let evidence: DoubleSignEvidence = match bincode::deserialize(&tx.data) {
        Ok(e) => e,
        Err(_) => return Receipt::failure(tx_hash, "invalid double-sign evidence payload", 0, 0),
    };

    if !evidence.is_valid() {
        return Receipt::failure(
            tx_hash,
            "evidence is not structurally valid (validator/height/round mismatch or identical block hashes)",
            0,
            0,
        );
    }
    if evidence.vote_a.verify_signature().is_err() {
        return Receipt::failure(tx_hash, "vote_a signature verification failed", 0, 0);
    }
    if evidence.vote_b.verify_signature().is_err() {
        return Receipt::failure(tx_hash, "vote_b signature verification failed", 0, 0);
    }

    // A validator can only meaningfully double-sign once per (height, round) — reject a
    // resubmission of an incident already slashed, whether by this reporter or another.
    let incident_key = format!("{}:{}:{}", evidence.validator, evidence.height, evidence.round);
    if !state.slashed_double_sign_incidents.insert(incident_key) {
        return Receipt::failure(tx_hash, "this double-sign incident was already slashed", 0, 0);
    }

    state.slash(&evidence.validator, helix_consensus::SLASH_FRACTION_BPS);

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
    if let Err(e) = param.validate(new_value) {
        return Receipt::failure(tx_hash, &e.to_string(), 0, 0);
    }
    // MinValidatorStake additionally needs a *dynamic* ceiling, not just the static floor
    // above: a value higher than every current staker's own stake would disqualify all of
    // them at once, leaving ChainState::stakers() empty. rotate_validator_set() can't
    // safely rotate into an empty set (it no-ops rather than halt block production), so
    // this would freeze the validator set exactly as if the last validator had voluntarily
    // unstaked below the minimum (execute_unstake already guards that path directly) —
    // just reached through a governance proposal instead. Capping the proposed value at
    // the current largest single stake guarantees at least that one account stays
    // eligible, so this specific proposal can never be the cause of an empty set.
    if let GovernanceParam::MinValidatorStake = param {
        let ceiling = state.max_single_stake();
        if new_value > ceiling {
            return Receipt::failure(
                tx_hash,
                &format!(
                    "proposed min_validator_stake {new_value} exceeds the current largest \
                     single stake {ceiling} — would disqualify every validator at once"
                ),
                0,
                0,
            );
        }
    }

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

    // The ZK proof alone only shows knowledge of *some* secret matching `commitment` —
    // helix_zkp::prove_personhood will generate a valid proof for any secret the caller
    // picks, with no external gatekeeping. Without an authority's signature, anyone could
    // self-issue unlimited "verified" identities for free (see `PersonhoodProofPayload`'s
    // doc comment). No authority configured at all means personhood is disabled outright —
    // failing closed rather than silently trusting the ZK proof alone. Any ONE of the
    // configured authorities may issue — see `ChainState::personhood_authorities`'s doc
    // comment for why this is a list rather than a single key.
    if state.personhood_authorities.is_empty() {
        return Receipt::failure(tx_hash, "no personhood authority configured", 0, 0);
    }
    let authority_sig_valid = state.personhood_authorities.iter().any(|authority| {
        helix_crypto::verify_with_scheme(
            payload.authority_crypto_version,
            authority,
            &payload.commitment,
            &payload.authority_signature,
        )
        .is_ok()
    });
    if !authority_sig_valid {
        return Receipt::failure(tx_hash, "personhood authority signature verification failed", 0, 0);
    }

    // The STARK circuit only proves knowledge of a secret matching `commitment` —
    // it isn't bound to `tx.from`. Once submitted, `commitment`+`proof_bytes` are
    // public on-chain, so without this check anyone could copy them into a
    // ProvePersonhood tx from a different address and get the same free pass.
    if !state.used_personhood_commitments.insert(payload.commitment) {
        return Receipt::failure(tx_hash, "personhood commitment already claimed", 0, 0);
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
    fn register_identity_social_attestation_is_disabled() {
        // Regression for the bypass this closes: previously, ATTESTATION_THRESHOLD (3)
        // freely-generated, attacker-controlled addresses attesting a target were enough to
        // reach PersonhoodStatus::Verified with no ZK proof and no authority signature at
        // all — completely undermining the Sybil-resistance fix in
        // execute_prove_personhood (backlog points 27/28). RegisterIdentity must now be
        // rejected unconditionally and never grant personhood, no matter how many distinct
        // attesters submit it.
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let attestee = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);

        for i in 0..helix_identity::ATTESTATION_THRESHOLD {
            let attester_kp = KeyPair::generate();
            let attester = Address::from_public_key(&attester_kp.public);
            state.update_account(&attester, |acc| acc.balance = 1_000_000);

            let tx = signed_attest_tx(&attester_kp, &attester, &attestee, 0, 10_000);
            let receipt = execute_transaction(&mut state, &tx, &validator, 50 + i as u64);
            assert!(!receipt.success, "attestation {i} unexpectedly succeeded");
        }

        assert!(!state.has_personhood(&attestee));
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

    fn signed_cancel_recovery_request_tx(kp: &KeyPair, from: &Address, nonce: u64, fee: u64) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::CancelRecoveryRequest,
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

    #[test]
    fn cancel_recovery_request_unblocks_guardian_changes() {
        // A single guardian's sub-threshold approval must not be able to permanently
        // lock the owner out of ever changing their guardian set again.
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

        // One malicious/careless guardian approves a bogus key — 1 of 5, nowhere near
        // the 3-of-5 threshold, and never will be (the other guardians simply never act).
        let bogus_kp = KeyPair::generate();
        let approve_tx = signed_approve_recovery_tx(
            &guardian_kps[0],
            &guardian_addrs[0],
            &owner,
            &bogus_kp.public,
            0,
            10_000,
        );
        assert!(execute_transaction(&mut state, &approve_tx, &validator, 1).success);
        assert!(state.recovery_request(&owner).is_some());

        // Owner is now locked out of changing guardians...
        let blocked_tx = signed_register_guardians_tx(&owner_kp, &owner, &guardian_addrs, 1, 10_000);
        let receipt = execute_transaction(&mut state, &blocked_tx, &validator, 2);
        assert!(!receipt.success, "guardian changes should be blocked while a request is pending");

        // ...until they cancel the stuck request themselves, still with their original key
        // (recovery never finalized, so no override key was ever set).
        let cancel_tx = signed_cancel_recovery_request_tx(&owner_kp, &owner, 1, 10_000);
        let receipt = execute_transaction(&mut state, &cancel_tx, &validator, 2);
        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert!(state.recovery_request(&owner).is_none());

        // Guardian changes work again.
        let unblocked_tx = signed_register_guardians_tx(&owner_kp, &owner, &guardian_addrs, 2, 10_000);
        let receipt = execute_transaction(&mut state, &unblocked_tx, &validator, 3);
        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
    }

    #[test]
    fn cancel_recovery_request_rejects_when_none_pending() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let owner_kp = KeyPair::generate();
        let owner = Address::from_public_key(&owner_kp.public);

        let mut state = ChainState::new(0);
        state.update_account(&owner, |acc| acc.balance = 1_000_000);

        let tx = signed_cancel_recovery_request_tx(&owner_kp, &owner, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);
        assert!(!receipt.success);
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
    fn create_proposal_rejects_zero_min_validator_stake() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 500_000;
        });

        // A min_validator_stake of 0 would let every zero-stake account pass the
        // `stakers()` filter, exploding the validator set / stalling BFT quorum.
        let data = governance::encode_proposal(governance::GovernanceParam::MinValidatorStake, 0);
        let tx = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(!receipt.success);
        assert!(state.proposals.is_empty());
        // Rejected before any balance/nonce mutation — the tx is simply invalid.
        assert_eq!(state.get(&addr).unwrap().balance, 1_000_000);
        assert_eq!(state.get(&addr).unwrap().nonce, 0);
    }

    #[test]
    fn create_proposal_rejects_zero_fuel_per_fee_unit() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 500_000;
        });

        // A fuel_per_fee_unit of 0 would give every contract call a fuel limit of 0,
        // bricking all contract calls network-wide.
        let data = governance::encode_proposal(governance::GovernanceParam::FuelPerFeeUnit, 0);
        let tx = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(!receipt.success);
        assert!(state.proposals.is_empty());
    }

    #[test]
    fn create_proposal_rejects_near_zero_min_validator_stake() {
        // 1 nano-HLX is nonzero, so the plain zero-check alone wouldn't catch this — but
        // it's economically indistinguishable from 0 (every account trivially clears it),
        // so it must still be rejected by the floor.
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 500_000;
        });

        let data = governance::encode_proposal(governance::GovernanceParam::MinValidatorStake, 1);
        let tx = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(!receipt.success);
        assert!(state.proposals.is_empty());
    }

    #[test]
    fn create_proposal_accepts_min_validator_stake_exactly_at_floor() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let floor = crate::genesis::MIN_VALIDATOR_STAKE / 100;
        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            // Must be >= floor: the new dynamic ceiling on MinValidatorStake proposals caps
            // the proposed value at the largest current single stake, so a tiny stake here
            // would (correctly) block the floor-boundary proposal this test wants to check.
            acc.staked = floor;
        });
        let data = governance::encode_proposal(governance::GovernanceParam::MinValidatorStake, floor);
        let tx = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.proposal(0).unwrap().new_value, floor);

        // One nano below the floor must still fail — confirms the boundary is exact.
        let data2 = governance::encode_proposal(governance::GovernanceParam::MinValidatorStake, floor - 1);
        let tx2 = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data2, 1, 10_000);
        assert!(!execute_transaction(&mut state, &tx2, &validator, 1).success);
    }

    #[test]
    fn create_proposal_rejects_min_validator_stake_above_every_current_stake() {
        // The scenario this closes: a proposal that would set min_validator_stake above
        // what ANY current account has staked would disqualify every validator at once,
        // leaving ChainState::stakers() empty and freezing the validator set exactly like
        // an unguarded last-validator unstake would (see the guard in execute_unstake).
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        // Must clear the static floor (MIN_VALIDATOR_STAKE / 100) so this test actually
        // exercises the dynamic ceiling check, not the unrelated floor check.
        let floor = crate::genesis::MIN_VALIDATOR_STAKE / 100;
        let largest_stake = floor + 1_000_000_000;

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = largest_stake;
        });

        let data = governance::encode_proposal(
            governance::GovernanceParam::MinValidatorStake,
            largest_stake + 1,
        );
        let tx = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(!receipt.success, "proposal exceeding every current stake must be rejected");
        assert!(state.proposals.is_empty());
    }

    #[test]
    fn create_proposal_accepts_min_validator_stake_up_to_the_largest_current_stake() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let floor = crate::genesis::MIN_VALIDATOR_STAKE / 100;
        let largest_stake = floor + 1_000_000_000;

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = largest_stake;
        });

        // Exactly at the current largest stake — the proposer themselves would still
        // qualify afterward, so this must be allowed.
        let data =
            governance::encode_proposal(governance::GovernanceParam::MinValidatorStake, largest_stake);
        let tx = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
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

        let data = governance::encode_proposal(governance::GovernanceParam::FuelPerFeeUnit, 1);
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

        let data = governance::encode_proposal(governance::GovernanceParam::FuelPerFeeUnit, 1);
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

    #[test]
    fn unstake_rejects_last_validator_dropping_below_minimum() {
        // The sole account meeting min_validator_stake tries to unstake enough to drop
        // below it. Allowing this would leave ChainState::stakers() empty, which
        // rotate_validator_set() can't safely rotate into (see CTO Backlog item 34) — it
        // would freeze the current validator set's voting power forever with nobody behind
        // it holding any real stake.
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let min_stake = crate::genesis::MIN_VALIDATOR_STAKE;

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = min_stake;
        });

        // Would drop staked to min_stake - 1, below the threshold.
        let tx = signed_unstake_tx(&kp, &addr, 1, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 1);

        assert!(!receipt.success, "last validator must not be able to unstake below the minimum");
        assert_eq!(state.get(&addr).unwrap().staked, min_stake, "stake must be untouched");
        assert_eq!(state.get(&addr).unwrap().unbonding_stake, 0);
    }

    #[test]
    fn unstake_allows_dropping_below_minimum_when_another_validator_remains() {
        let kp1 = KeyPair::generate();
        let addr1 = Address::from_public_key(&kp1.public);
        let kp2 = KeyPair::generate();
        let addr2 = Address::from_public_key(&kp2.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let min_stake = crate::genesis::MIN_VALIDATOR_STAKE;

        let mut state = ChainState::new(0);
        state.update_account(&addr1, |acc| {
            acc.balance = 1_000_000;
            acc.staked = min_stake;
        });
        state.update_account(&addr2, |acc| {
            acc.balance = 1_000_000;
            acc.staked = min_stake;
        });

        // addr1 can fully exit — addr2 still meets the minimum afterward.
        let tx = signed_unstake_tx(&kp1, &addr1, min_stake, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 1);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.get(&addr1).unwrap().staked, 0);
        assert_eq!(state.get(&addr1).unwrap().unbonding_stake, min_stake);
    }

    #[test]
    fn unstake_allows_partial_reduction_that_stays_above_minimum() {
        // Sole validator, but the unstake amount doesn't drop them below the threshold —
        // no risk to the validator set, must be allowed.
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let min_stake = crate::genesis::MIN_VALIDATOR_STAKE;

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = min_stake * 2;
        });

        let tx = signed_unstake_tx(&kp, &addr, min_stake, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 1);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.get(&addr).unwrap().staked, min_stake);
    }

    fn signed_personhood_tx(
        kp: &KeyPair,
        from: &Address,
        payload: &PersonhoodProofPayload,
        nonce: u64,
        fee: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::ProvePersonhood,
            from: from.clone(),
            to: None,
            amount: 0,
            fee,
            nonce,
            data: bincode::serialize(payload).unwrap(),
            crypto_version: kp.scheme,
            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    fn personhood_payload(
        authority_kp: &KeyPair,
        commitment: [u8; 16],
        proof_bytes: Vec<u8>,
    ) -> PersonhoodProofPayload {
        PersonhoodProofPayload {
            commitment,
            proof_bytes,
            authority_signature: authority_kp.sign(&commitment).unwrap(),
            authority_crypto_version: authority_kp.scheme,
        }
    }

    #[test]
    fn prove_personhood_succeeds_and_sets_verified_status() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let authority_kp = KeyPair::generate();

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);
        state.personhood_authorities.push(authority_kp.public.clone());

        let (proof, commitment) = helix_zkp::prove_personhood([1u8; 16]);
        let payload = personhood_payload(&authority_kp, commitment, proof.as_bytes().to_vec());
        let tx = signed_personhood_tx(&kp, &addr, &payload, 0, 10_000);

        let receipt = execute_transaction(&mut state, &tx, &validator, 0);
        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert!(state.has_personhood(&addr));
    }

    #[test]
    fn prove_personhood_succeeds_with_second_of_multiple_authorities() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let other_authority_kp = KeyPair::generate();
        let authority_kp = KeyPair::generate();

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);
        state.personhood_authorities.push(other_authority_kp.public.clone());
        state.personhood_authorities.push(authority_kp.public.clone());

        let (proof, commitment) = helix_zkp::prove_personhood([1u8; 16]);
        let payload = personhood_payload(&authority_kp, commitment, proof.as_bytes().to_vec());
        let tx = signed_personhood_tx(&kp, &addr, &payload, 0, 10_000);

        let receipt = execute_transaction(&mut state, &tx, &validator, 0);
        assert!(receipt.success, "signature from any configured authority must be accepted, got: {:?}", receipt.error);
        assert!(state.has_personhood(&addr));
    }

    #[test]
    fn prove_personhood_rejects_when_no_authority_configured() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let authority_kp = KeyPair::generate(); // exists, but never registered with the chain

        let mut state = ChainState::new(0); // personhood_authorities left empty
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        let (proof, commitment) = helix_zkp::prove_personhood([1u8; 16]);
        let payload = personhood_payload(&authority_kp, commitment, proof.as_bytes().to_vec());
        let tx = signed_personhood_tx(&kp, &addr, &payload, 0, 10_000);

        let receipt = execute_transaction(&mut state, &tx, &validator, 0);
        assert!(!receipt.success, "must fail closed with no authority configured");
        assert!(!state.has_personhood(&addr));
    }

    #[test]
    fn prove_personhood_rejects_self_issued_commitment_without_authority_signature() {
        // The core of the fix: the ZK proof alone (a self-chosen secret, no external
        // gatekeeping) must not be enough — it needs the configured authority's signature
        // over the commitment too. Here the "attacker" signs with their own key instead of
        // the real authority's.
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let real_authority_kp = KeyPair::generate();
        let attacker_pretending_to_be_authority = KeyPair::generate();

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);
        state.personhood_authorities.push(real_authority_kp.public.clone());

        let (proof, commitment) = helix_zkp::prove_personhood([1u8; 16]);
        let payload = personhood_payload(&attacker_pretending_to_be_authority, commitment, proof.as_bytes().to_vec());
        let tx = signed_personhood_tx(&kp, &addr, &payload, 0, 10_000);

        let receipt = execute_transaction(&mut state, &tx, &validator, 0);
        assert!(!receipt.success, "self-issued commitment without the real authority's signature must be rejected");
        assert!(!state.has_personhood(&addr));
    }

    #[test]
    fn prove_personhood_rejects_replayed_commitment_from_different_address() {
        // `commitment`+`proof_bytes` become public the moment the first tx lands
        // on-chain. The STARK circuit never binds them to `tx.from`, so without
        // the commitment-reuse check, a second address copying the exact same
        // payload would get personhood-verified for free — no secret knowledge of
        // their own, defeating Sybil resistance entirely.
        let kp1 = KeyPair::generate();
        let addr1 = Address::from_public_key(&kp1.public);
        let kp2 = KeyPair::generate();
        let addr2 = Address::from_public_key(&kp2.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let authority_kp = KeyPair::generate();

        let mut state = ChainState::new(0);
        state.update_account(&addr1, |acc| acc.balance = 1_000_000);
        state.update_account(&addr2, |acc| acc.balance = 1_000_000);
        state.personhood_authorities.push(authority_kp.public.clone());

        let (proof, commitment) = helix_zkp::prove_personhood([9u8; 16]);
        let payload = personhood_payload(&authority_kp, commitment, proof.as_bytes().to_vec());

        let tx1 = signed_personhood_tx(&kp1, &addr1, &payload, 0, 10_000);
        assert!(execute_transaction(&mut state, &tx1, &validator, 0).success);
        assert!(state.has_personhood(&addr1));

        // Same exact payload (commitment + proof_bytes), different address/signature.
        let tx2 = signed_personhood_tx(&kp2, &addr2, &payload, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx2, &validator, 1);

        assert!(!receipt.success, "replayed commitment must be rejected");
        assert!(!state.has_personhood(&addr2), "copying address must not gain personhood");
        // Original claimant is unaffected.
        assert!(state.has_personhood(&addr1));
    }

    fn signed_vote(
        kp: &KeyPair,
        validator: &Address,
        vote_type: helix_consensus::VoteType,
        height: u64,
        round: u32,
        block_hash: Hash,
    ) -> helix_consensus::Vote {
        let mut vote = helix_consensus::Vote {
            vote_type,
            height,
            round,
            block_hash,
            validator: validator.clone(),
            public_key: kp.public.clone(),
            crypto_version: kp.scheme,
            signature: Signature::from_bytes(vec![]),
        };
        vote.signature = kp.sign(&vote.signing_bytes()).unwrap();
        vote
    }

    fn signed_evidence_tx(
        reporter_kp: &KeyPair,
        reporter: &Address,
        evidence: &DoubleSignEvidence,
        nonce: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::SubmitDoubleSignEvidence,
            from: reporter.clone(),
            to: None,
            amount: 0,
            fee: 0,
            nonce,
            data: bincode::serialize(evidence).unwrap(),
            crypto_version: reporter_kp.scheme,
            signature: Signature::from_bytes(vec![]),
            public_key: reporter_kp.public.clone(),
        };
        tx.signature = reporter_kp.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    #[test]
    fn submit_double_sign_evidence_slashes_the_validator() {
        let validator_kp = KeyPair::generate();
        let validator_addr = Address::from_public_key(&validator_kp.public);
        let reporter_kp = KeyPair::generate();
        let reporter = Address::from_public_key(&reporter_kp.public);
        let block_validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&validator_addr, |acc| acc.staked = 1_000_000);
        state.update_account(&reporter, |acc| acc.balance = 1_000_000);

        let vote_a = signed_vote(
            &validator_kp,
            &validator_addr,
            helix_consensus::VoteType::Precommit,
            10,
            0,
            Hash::digest(b"block-a"),
        );
        let vote_b = signed_vote(
            &validator_kp,
            &validator_addr,
            helix_consensus::VoteType::Precommit,
            10,
            0,
            Hash::digest(b"block-b"),
        );
        let evidence = DoubleSignEvidence {
            validator: validator_addr.clone(),
            height: 10,
            round: 0,
            vote_a,
            vote_b,
        };

        let tx = signed_evidence_tx(&reporter_kp, &reporter, &evidence, 0);
        let receipt = execute_transaction(&mut state, &tx, &block_validator, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        let expected_slash = 1_000_000 * helix_consensus::SLASH_FRACTION_BPS / 10_000;
        assert_eq!(state.get(&validator_addr).unwrap().staked, 1_000_000 - expected_slash);
        assert_eq!(state.total_burned, expected_slash);
    }

    #[test]
    fn submit_double_sign_evidence_rejects_duplicate_incident() {
        let validator_kp = KeyPair::generate();
        let validator_addr = Address::from_public_key(&validator_kp.public);
        let reporter_kp = KeyPair::generate();
        let reporter = Address::from_public_key(&reporter_kp.public);
        let block_validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&validator_addr, |acc| acc.staked = 1_000_000);
        state.update_account(&reporter, |acc| acc.balance = 1_000_000);

        let vote_a = signed_vote(
            &validator_kp,
            &validator_addr,
            helix_consensus::VoteType::Precommit,
            10,
            0,
            Hash::digest(b"block-a"),
        );
        let vote_b = signed_vote(
            &validator_kp,
            &validator_addr,
            helix_consensus::VoteType::Precommit,
            10,
            0,
            Hash::digest(b"block-b"),
        );
        let evidence = DoubleSignEvidence {
            validator: validator_addr.clone(),
            height: 10,
            round: 0,
            vote_a,
            vote_b,
        };

        let tx1 = signed_evidence_tx(&reporter_kp, &reporter, &evidence, 0);
        assert!(execute_transaction(&mut state, &tx1, &block_validator, 0).success);
        let staked_after_first_slash = state.get(&validator_addr).unwrap().staked;

        // Same incident reported again (could be a different reporter in practice) — must
        // not slash a second time for the same (validator, height, round).
        let tx2 = signed_evidence_tx(&reporter_kp, &reporter, &evidence, 1);
        let receipt = execute_transaction(&mut state, &tx2, &block_validator, 1);
        assert!(!receipt.success);
        assert_eq!(state.get(&validator_addr).unwrap().staked, staked_after_first_slash);
    }

    #[test]
    fn submit_double_sign_evidence_rejects_non_conflicting_votes() {
        // Same block_hash on both votes — not a double-sign, just the same vote twice.
        let validator_kp = KeyPair::generate();
        let validator_addr = Address::from_public_key(&validator_kp.public);
        let reporter_kp = KeyPair::generate();
        let reporter = Address::from_public_key(&reporter_kp.public);
        let block_validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&validator_addr, |acc| acc.staked = 1_000_000);
        state.update_account(&reporter, |acc| acc.balance = 1_000_000);

        let same_hash = Hash::digest(b"block-a");
        let vote_a = signed_vote(&validator_kp, &validator_addr, helix_consensus::VoteType::Precommit, 10, 0, same_hash);
        let vote_b = signed_vote(&validator_kp, &validator_addr, helix_consensus::VoteType::Precommit, 10, 0, same_hash);
        let evidence = DoubleSignEvidence {
            validator: validator_addr.clone(),
            height: 10,
            round: 0,
            vote_a,
            vote_b,
        };

        let tx = signed_evidence_tx(&reporter_kp, &reporter, &evidence, 0);
        let receipt = execute_transaction(&mut state, &tx, &block_validator, 0);
        assert!(!receipt.success);
        assert_eq!(state.get(&validator_addr).unwrap().staked, 1_000_000);
    }

    #[test]
    fn submit_double_sign_evidence_rejects_forged_vote_signature() {
        let validator_kp = KeyPair::generate();
        let validator_addr = Address::from_public_key(&validator_kp.public);
        let attacker_kp = KeyPair::generate(); // does NOT hold validator_kp's key
        let reporter = Address::from_public_key(&attacker_kp.public);
        let block_validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&validator_addr, |acc| acc.staked = 1_000_000);
        state.update_account(&reporter, |acc| acc.balance = 1_000_000);

        // A real vote_a from the validator...
        let vote_a = signed_vote(
            &validator_kp,
            &validator_addr,
            helix_consensus::VoteType::Precommit,
            10,
            0,
            Hash::digest(b"block-a"),
        );
        // ...but vote_b is forged: claims to be from validator_addr, signed by someone else.
        let mut vote_b = signed_vote(
            &attacker_kp,
            &validator_addr, // claimed validator (doesn't match attacker_kp's real address)
            helix_consensus::VoteType::Precommit,
            10,
            0,
            Hash::digest(b"block-b"),
        );
        vote_b.public_key = validator_kp.public.clone(); // impersonate the pubkey too
        let evidence = DoubleSignEvidence {
            validator: validator_addr.clone(),
            height: 10,
            round: 0,
            vote_a,
            vote_b,
        };

        let tx = signed_evidence_tx(&attacker_kp, &reporter, &evidence, 0);
        let receipt = execute_transaction(&mut state, &tx, &block_validator, 0);
        assert!(!receipt.success, "forged vote signature must be rejected");
        assert_eq!(state.get(&validator_addr).unwrap().staked, 1_000_000);
    }
}
