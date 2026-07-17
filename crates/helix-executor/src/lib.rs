pub mod genesis;
pub mod governance;
pub mod receipt;
pub mod state;

pub use genesis::GenesisConfig;
pub use governance::{GovernanceParam, GovernanceParams, GovernanceProposal};
pub use receipt::{BlockReceipt, Receipt};
pub use state::{
    self_bond_ratio_ok, AccountState, ChainState, DelegationPool, DEFAULT_COMMISSION_BPS,
    MAX_COMMISSION_BPS, MIN_SELF_BOND_RATIO_BPS, UNBONDING_PERIOD,
};

use helix_consensus::DoubleSignEvidence;
use helix_core::{
    transaction::{personhood_authority_preimage, PersonhoodProofPayload, TxType},
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
/// Execute all transactions in a block, distribute fees, and mint this
/// block's scheduled issuance (see `genesis::scheduled_block_reward`).
///
/// `reward_address` — where the validator's 50 % fee share *and* the block reward land.
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
    let base_fee_per_byte = block.header.base_fee_per_byte;
    for tx in &block.transactions {
        let receipt = execute_transaction(state, tx, fee_recipient, height, base_fee_per_byte);
        total_burned += receipt.fee_burned;
        total_validator_reward += receipt.fee_to_validator;
        receipts.push(receipt);
    }

    state.total_burned = state.total_burned.saturating_add(total_burned);

    // Redelegations whose source-slashing window has closed stop being consensus state. Done
    // after the transactions so an entry created in this block is never pruned by it.
    state.prune_expired_redelegations(height);

    // Block reward: minted independently of transaction volume, capped so `total_issued`
    // never crosses the `total_supply` hard cap regardless of what the schedule says.
    let scheduled = genesis::scheduled_block_reward(height);
    let block_reward_minted = scheduled.min(state.mintable_headroom());
    if block_reward_minted > 0 {
        credit_validator_reward(state, fee_recipient, block_reward_minted);
        state.total_issued = state.total_issued.saturating_add(block_reward_minted);
    }

    BlockReceipt {
        block_hash: block.hash().to_hex(),
        height: block.height(),
        tx_receipts: receipts,
        total_burned,
        validator_reward: total_validator_reward,
        block_reward_minted,
    }
}

/// Execute a single transaction against the current chain state. `base_fee_per_byte` is this
/// block's EIP-1559 base fee (`block.header.base_fee_per_byte`); the base-fee portion of the
/// transaction's fee (`base_fee_per_byte × tx.size_bytes()`) is burned and the rest tips the
/// validator (see [`distribute_fee`]).
pub fn execute_transaction(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    height: u64,
    base_fee_per_byte: u64,
) -> Receipt {
    let tx_hash = tx.hash();

    // Signature first: an unsigned transaction is nobody's, so there is no one to charge.
    if !verify_tx_signature(state, tx) {
        return Receipt::failure(tx_hash, "invalid signature", 0, 0);
    }

    // EIP-1559: the transaction must be able to pay this block's base fee for its size, and
    // that portion of its fee is burned. A transaction that can't pay is not includable —
    // reject it with no state change (a correct proposer never packs one, and block validation
    // independently re-derives base_fee_per_byte).
    //
    // Slashing evidence (`SubmitDoubleSignEvidence`) is exempt: it is a consensus-safety public
    // good that proves itself (both conflicting votes are signed), is deduplicated on-chain, and
    // cannot be spammed profitably. Its ~16 KB two-vote payload already exceeds the flat reporter
    // fee at the *floor* base fee, so subjecting it to the fee market would price slashing reports
    // out of every block and silently disable slashing — the exact failure class fixed once before
    // when the evidence tx paid fee 0. Every other transaction pays the base fee for its size.
    let base_fee_amount = if tx.tx_type == TxType::SubmitDoubleSignEvidence {
        0
    } else {
        base_fee_per_byte.saturating_mul(tx.size_bytes())
    };
    if tx.fee < base_fee_amount {
        return Receipt::failure(tx_hash, "fee below block base fee", 0, 0);
    }

    // Intrinsic validity, decided once here rather than re-derived by eighteen executors: the
    // sender must be at this nonce, and must be able to cover the fee. These two alone decide
    // whether a transaction is includable at all, and neither can be charged for — there is
    // either nothing to take, or no defined position in the sender's order to take it from.
    // Everything past this point is a transaction that has paid.
    let sender = state.get_or_default(&tx.from);
    if tx.nonce != sender.nonce {
        return Receipt::failure(
            tx_hash,
            &format!("nonce mismatch: expected {}, got {}", sender.nonce, tx.nonce),
            0,
            0,
        );
    }
    if sender.balance < tx.fee {
        return Receipt::failure(
            tx_hash,
            &format!("cannot pay the fee: needs {}, has {}", tx.fee, sender.balance),
            0,
            0,
        );
    }

    let receipt = match tx.tx_type {
        TxType::Transfer => execute_transfer(state, tx, validator, tx_hash, base_fee_amount),
        TxType::Stake => execute_stake(state, tx, validator, tx_hash, base_fee_amount),
        TxType::Unstake => execute_unstake(state, tx, validator, tx_hash, height, base_fee_amount),

        TxType::RegisterName => execute_register_name(state, tx, validator, tx_hash, base_fee_amount),
        TxType::RegisterIdentity => execute_register_identity(state, tx, tx_hash, base_fee_amount),
        TxType::RegisterGuardians => execute_register_guardians(state, tx, validator, tx_hash, base_fee_amount),
        TxType::ApproveRecovery => execute_approve_recovery(state, tx, validator, tx_hash, base_fee_amount),
        TxType::DeployContract => execute_deploy_contract(state, tx, validator, tx_hash, base_fee_amount),
        TxType::CallContract => execute_call_contract(state, tx, validator, tx_hash, height, base_fee_amount),
        TxType::CreateProposal => execute_create_proposal(state, tx, validator, tx_hash, height, base_fee_amount),
        TxType::VoteProposal => execute_vote_proposal(state, tx, validator, tx_hash, height, base_fee_amount),
        TxType::ProvePersonhood => execute_prove_personhood(state, tx, validator, tx_hash, base_fee_amount),
        TxType::ClaimUnbonded => execute_claim_unbonded(state, tx, validator, tx_hash, height, base_fee_amount),
        TxType::CancelRecoveryRequest => execute_cancel_recovery_request(state, tx, validator, tx_hash, base_fee_amount),
        TxType::SubmitDoubleSignEvidence => execute_submit_double_sign_evidence(state, tx, validator, tx_hash, base_fee_amount),
        TxType::Delegate => execute_delegate(state, tx, validator, tx_hash, base_fee_amount),
        TxType::Undelegate => execute_undelegate(state, tx, validator, tx_hash, height, base_fee_amount),
        TxType::Redelegate => execute_redelegate(state, tx, validator, tx_hash, height, base_fee_amount),
        TxType::SetCommission => execute_set_commission(state, tx, validator, tx_hash, base_fee_amount),
    };

    if receipt.success {
        return receipt;
    }
    // The operation failed, but the transaction itself was the sender's own, correctly ordered,
    // and payable — it took a block slot and real validator CPU (verifying its ML-DSA signature
    // alone means hashing ~5.3 KB of key and signature), so it pays for that.
    //
    // Until this existed, it did not. An empty wallet could sign a transfer it could never
    // afford, have it admitted, packed, executed and rejected, and pay nothing — and because the
    // nonce never moved either, the very same signed bytes could be replayed forever. Worse, the
    // fee it merely *claimed* still ranked it: the mempool sorts on a self-declared number, so
    // the unfunded transaction outbid paying ones for the pool and got packed first.
    // `execute_call_contract` had already reasoned its way to exactly this conclusion for traps;
    // the other seventeen executors never got it.
    //
    // Safe to charge here because a failing executor never mutates: each validates fully before
    // committing, and `distribute_fee` — the only fallible-looking step after a commit — cannot
    // actually fail. A failure receipt therefore means chain state is untouched.
    charge_failed_transaction(state, tx, validator, tx_hash, base_fee_amount, receipt)
}

/// Take the fee for a transaction that was includable — right sender, right nonce, fee
/// affordable — but whose operation failed. The fee is charged and the nonce advances exactly as
/// on success; only the operation's effect is missing.
///
/// Reports the real burn/tip split rather than zeroes. Receipts are persisted and served over
/// RPC now, so the split is the answer to "what did this cost me" — and a failed transaction is
/// precisely when someone asks.
fn charge_failed_transaction(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    base_fee_amount: u64,
    failed: Receipt,
) -> Receipt {
    let reason = failed.error.unwrap_or_else(|| "transaction failed".to_string());
    // `execute_transaction` established `balance >= fee` before dispatching.
    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });
    let (burned, reward) = distribute_fee(state, validator, tx.fee, base_fee_amount)
        .expect("distribute_fee is infallible");
    Receipt::failure(tx_hash, &reason, burned, reward)
}

/// Can `tx`'s sender actually cover the fee it declares?
///
/// The one question the mempool cannot answer for itself: it holds no chain state, by design
/// (see `Mempool::add_with_recovery_key`), so `fee` arrives there as a number the sender merely
/// *claims*. The pool ranks and evicts on that claim, and the block producer packs by it — so
/// until this was asked at admission, a wallet with no funds at all could claim any fee it liked,
/// outbid every paying transaction for pool space, get packed first, and then fail at execution
/// costing exactly nothing, because there was nothing to take from it. Free, and repeatable with
/// the same bytes forever.
///
/// Deliberately the *same* rule `execute_transaction` uses to decide includability, and no
/// stricter: not `amount + fee`, because a transaction whose amount is short still executes and
/// still pays, and its balance may legitimately change before it is included. Admission and
/// execution must agree — if they drift, this pool starts either admitting transactions that
/// cannot execute or refusing ones that could.
///
/// Belongs at the callers that already hold chain state (the RPC submit path and the P2P gossip
/// path), not inside the pool: the pool's state-freedom is a design decision, not an oversight.
pub fn can_pay_fee(state: &ChainState, tx: &Transaction) -> bool {
    state.get_or_default(&tx.from).balance >= tx.fee
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
    base_fee_amount: u64,
) -> Receipt {
    if tx.amount == 0 {
        return Receipt::failure(tx_hash, "transfer amount must be greater than zero", 0, 0);
    }
    // A transfer must name a recipient. Without this, a `Transfer` with `to: None` debits the
    // sender by `amount + fee` (below) but credits nobody, silently destroying `amount` — a
    // footgun that only ever burns the sender's own funds, but there is no legitimate reason
    // to route value into the void through the transfer path.
    let Some(recipient) = tx.to.clone() else {
        return Receipt::failure(tx_hash, "transfer requires a recipient address (tx.to)", 0, 0);
    };

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
    state.update_account(&recipient, |acc| {
        acc.balance += tx.amount;
    });

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn execute_stake(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    base_fee_amount: u64,
) -> Receipt {
    if tx.amount == 0 {
        return Receipt::failure(tx_hash, "stake amount must be greater than zero", 0, 0);
    }

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

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn execute_unstake(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    height: u64,
    base_fee_amount: u64,
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

    // Guards against a validator with delegators shedding its own stake down to (or toward)
    // nothing while keeping `effective_stake()` (and so voting power/block production) intact
    // on the back of delegators' capital alone — see `MIN_SELF_BOND_RATIO_BPS`'s doc comment.
    let delegated = state.validator_pools.get(&tx.from.to_string()).map(|p| p.total_delegated_stake).unwrap_or(0);
    if delegated > 0 {
        let remaining_self = sender.staked - tx.amount;
        if !state::self_bond_ratio_ok(remaining_self, delegated) {
            return Receipt::failure(
                tx_hash,
                "cannot unstake: would drop your self-bond ratio below the required minimum \
                 while delegators are still backing this validator",
                0,
                0,
            );
        }
    }

    let unlock_height = height + state::UNBONDING_PERIOD;
    state.update_account(&tx.from, |acc| {
        acc.staked -= tx.amount;
        // Stake moves to the unbonding queue — still slashable during this period. `None`
        // marks it as this account's own self-bond, so `ChainState::slash` on this address
        // reaches it (rather than some other validator's slash, as with `Undelegate`).
        acc.unbonding_stake = tx.amount;
        acc.unbonding_unlock_height = unlock_height;
        acc.unbonding_source = None;
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn execute_claim_unbonded(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    height: u64,
    base_fee_amount: u64,
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
        // The unbonding period is over: these funds have left every slashing window they were
        // in, so the source validator is no longer meaningful. Harmless to leave set today
        // (`slash` scales `unbonding_stake`, now 0, and both writers set the source
        // explicitly), but an empty queue that still names a validator is a lie about the
        // account's state and exactly the kind of thing a later reader would trust.
        acc.unbonding_source = None;
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// `tx.to` names the validator to delegate to, `tx.amount` is how much liquid HLX to lock
/// into its pool. Mints pool shares proportional to the pool's current value per share (see
/// `DelegationPool`'s doc comment) — a fresh or fully-slashed-out pool (`total_shares == 0`
/// or `total_delegated_stake == 0`) prices new shares 1:1 with the deposited amount rather
/// than dividing by zero, exactly like a brand-new pool would.
fn execute_delegate(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    base_fee_amount: u64,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }
    let Some(target) = &tx.to else {
        return Receipt::failure(tx_hash, "delegate requires a target validator address", 0, 0);
    };
    if tx.amount == 0 {
        return Receipt::failure(tx_hash, "delegation amount must be greater than zero", 0, 0);
    }
    let total_cost = tx.amount.saturating_add(tx.fee);
    if sender.balance < total_cost {
        return Receipt::failure(
            tx_hash,
            &format!("insufficient balance: need {}, have {}", total_cost, sender.balance),
            0,
            0,
        );
    }
    let target_key = target.to_string();
    let target_self_staked = state.accounts.get(&target_key).map(|a| a.staked).unwrap_or(0);
    if target_self_staked == 0 {
        return Receipt::failure(
            tx_hash,
            "target address has never self-staked — not a recognized validator identity",
            0,
            0,
        );
    }

    let existing_delegated =
        state.validator_pools.get(&target_key).map(|p| p.total_delegated_stake).unwrap_or(0);
    let prospective_delegated = existing_delegated.saturating_add(tx.amount);
    if !state::self_bond_ratio_ok(target_self_staked, prospective_delegated) {
        return Receipt::failure(
            tx_hash,
            "delegation rejected: this validator's self-bond ratio is already at its maximum \
             leverage for its current self-stake",
            0,
            0,
        );
    }

    let pool = state
        .validator_pools
        .entry(target_key.clone())
        .or_insert_with(|| DelegationPool {
            total_shares: 0,
            total_delegated_stake: 0,
            commission_bps: DEFAULT_COMMISSION_BPS,
        });
    let shares_to_mint = if pool.total_shares == 0 || pool.total_delegated_stake == 0 {
        tx.amount
    } else {
        (tx.amount as u128 * pool.total_shares as u128 / pool.total_delegated_stake as u128) as u64
    };
    // Reject a delegation too small to mint even one share against the pool's current
    // value-per-share. Once rewards have compounded the pool above 1:1 (value per share > 1),
    // an amount below that per-share value floors to zero shares — and without this guard the
    // stake would still be added to `total_delegated_stake`, silently handing the delegator's
    // funds to the existing shareholders (the classic share-rounding / vault-inflation loss).
    // Failing closed keeps the would-be delegator's balance intact; they simply need to
    // delegate at least one share's worth.
    if shares_to_mint == 0 {
        return Receipt::failure(
            tx_hash,
            "delegation amount is too small to mint any pool shares at the current share price",
            0,
            0,
        );
    }
    pool.total_shares += shares_to_mint;
    pool.total_delegated_stake += tx.amount;

    *state
        .delegator_shares
        .entry(target_key)
        .or_default()
        .entry(tx.from.to_string())
        .or_insert(0) += shares_to_mint;

    state.update_account(&tx.from, |acc| {
        acc.balance -= total_cost;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// `tx.data` names the source validator (UTF-8 address string), `tx.to` the destination, and
/// `tx.amount` the HLX value (not raw shares) to move. Redeems shares from the source pool at
/// its current share price and mints shares in the destination pool at *its* price, in one
/// transaction and with no unbonding wait — but records the moved capital as still slashable
/// for the source until `UNBONDING_PERIOD` has passed. See `TxType::Redelegate`.
fn execute_redelegate(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    height: u64,
    base_fee_amount: u64,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }
    if sender.balance < tx.fee {
        return Receipt::failure(tx_hash, "insufficient balance for fee", 0, 0);
    }
    if tx.amount == 0 {
        return Receipt::failure(tx_hash, "redelegation amount must be greater than zero", 0, 0);
    }
    let Some(dst) = &tx.to else {
        return Receipt::failure(tx_hash, "redelegate requires a destination validator address", 0, 0);
    };
    let Ok(src_str) = std::str::from_utf8(&tx.data) else {
        return Receipt::failure(tx_hash, "redelegate source address is not valid UTF-8", 0, 0);
    };
    let Ok(src) = Address::from_str(src_str) else {
        return Receipt::failure(tx_hash, "redelegate source is not a valid address", 0, 0);
    };
    let (src_key, dst_key) = (src.to_string(), dst.to_string());
    if src_key == dst_key {
        return Receipt::failure(tx_hash, "cannot redelegate to the same validator", 0, 0);
    }

    // No A->B->C hopping while the earlier hop's window is still open — see `TxType::Redelegate`.
    let sender_key = tx.from.to_string();
    let already_redelegating = state
        .redelegations
        .values()
        .flatten()
        .any(|r| r.delegator == sender_key && r.dst == src_key);
    if already_redelegating {
        return Receipt::failure(
            tx_hash,
            "this delegation is itself still inside a redelegation window; wait for it to end \
             before moving the stake on",
            0,
            0,
        );
    }

    // The destination must be a real validator identity and must have the self-bond headroom to
    // take the stake — identical to what `execute_delegate` demands, since that is exactly what
    // this is from the destination's point of view.
    let dst_self_staked = state.accounts.get(&dst_key).map(|a| a.staked).unwrap_or(0);
    if dst_self_staked == 0 {
        return Receipt::failure(
            tx_hash,
            "destination address has never self-staked — not a recognized validator identity",
            0,
            0,
        );
    }
    let dst_existing = state.validator_pools.get(&dst_key).map(|p| p.total_delegated_stake).unwrap_or(0);
    if !state::self_bond_ratio_ok(dst_self_staked, dst_existing.saturating_add(tx.amount)) {
        return Receipt::failure(
            tx_hash,
            "redelegation rejected: the destination validator's self-bond ratio is already at \
             its maximum leverage for its current self-stake",
            0,
            0,
        );
    }

    // --- Redeem from the source pool (mirrors `execute_undelegate`'s share math) ---
    let Some(src_pool) = state.validator_pools.get(&src_key) else {
        return Receipt::failure(tx_hash, "no delegation pool for the source validator", 0, 0);
    };
    if src_pool.total_shares == 0 || src_pool.total_delegated_stake == 0 {
        return Receipt::failure(tx_hash, "source delegation pool is empty", 0, 0);
    }
    let Some(owned_shares) = state
        .delegator_shares
        .get(&src_key)
        .and_then(|m| m.get(&sender_key))
        .copied()
    else {
        return Receipt::failure(tx_hash, "no delegation from this address to the source validator", 0, 0);
    };
    let my_value =
        (owned_shares as u128 * src_pool.total_delegated_stake as u128 / src_pool.total_shares as u128) as u64;
    if tx.amount > my_value {
        return Receipt::failure(
            tx_hash,
            &format!("insufficient delegated balance: have {}, requested {}", my_value, tx.amount),
            0,
            0,
        );
    }
    let src_shares_to_burn = ((tx.amount as u128 * src_pool.total_shares as u128)
        .div_ceil(src_pool.total_delegated_stake as u128)) as u64;
    let src_shares_to_burn = src_shares_to_burn.min(owned_shares);

    // --- Mint into the destination pool (mirrors `execute_delegate`'s share math) ---
    let dst_shares_to_mint = match state.validator_pools.get(&dst_key) {
        Some(p) if p.total_shares > 0 && p.total_delegated_stake > 0 => {
            (tx.amount as u128 * p.total_shares as u128 / p.total_delegated_stake as u128) as u64
        }
        _ => tx.amount,
    };
    if dst_shares_to_mint == 0 {
        return Receipt::failure(
            tx_hash,
            "redelegation amount is too small to mint any shares at the destination's current \
             share price",
            0,
            0,
        );
    }

    // Everything is validated — commit.
    {
        let src_pool = state.validator_pools.get_mut(&src_key).expect("checked above");
        src_pool.total_shares -= src_shares_to_burn;
        src_pool.total_delegated_stake -= tx.amount;
    }
    {
        let holders = state.delegator_shares.get_mut(&src_key).expect("checked above");
        let remaining = owned_shares - src_shares_to_burn;
        if remaining == 0 {
            holders.remove(&sender_key);
        } else {
            holders.insert(sender_key.clone(), remaining);
        }
    }
    let dst_pool = state.validator_pools.entry(dst_key.clone()).or_insert_with(|| DelegationPool {
        total_shares: 0,
        total_delegated_stake: 0,
        commission_bps: DEFAULT_COMMISSION_BPS,
    });
    dst_pool.total_shares += dst_shares_to_mint;
    dst_pool.total_delegated_stake += tx.amount;
    *state
        .delegator_shares
        .entry(dst_key.clone())
        .or_default()
        .entry(sender_key.clone())
        .or_insert(0) += dst_shares_to_mint;

    // The source's claim on this capital outlives its presence in the source's pool.
    state.redelegations.entry(src_key).or_default().push(state::Redelegation {
        delegator: sender_key,
        dst: dst_key,
        amount: tx.amount,
        unlock_height: height + state::UNBONDING_PERIOD,
    });

    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// `tx.to` names the validator to undelegate from, `tx.amount` is the HLX value (not raw
/// shares) to redeem — including any rewards auto-compounded, or losses from slashing, since
/// the delegation was made. Converts to shares internally, rounding the share count *up*
/// (against the withdrawer, in the remaining delegators' favor) so a delegator can never
/// extract fractionally more than their true proportional share of the pool. The redeemed
/// value moves into `tx.from`'s own unbonding queue — the exact same one `TxType::Unstake`
/// uses, including the single-slot-at-a-time restriction (see `execute_unstake`), so it's
/// just as slashable during the wait and claimed the same way via `TxType::ClaimUnbonded`.
fn execute_undelegate(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    height: u64,
    base_fee_amount: u64,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }
    if sender.balance < tx.fee {
        return Receipt::failure(tx_hash, "insufficient balance for fee", 0, 0);
    }
    let Some(target) = &tx.to else {
        return Receipt::failure(tx_hash, "undelegate requires a target validator address", 0, 0);
    };
    if tx.amount == 0 {
        return Receipt::failure(tx_hash, "undelegation amount must be greater than zero", 0, 0);
    }
    if sender.unbonding_stake > 0 {
        return Receipt::failure(
            tx_hash,
            "an unbonding is already in progress; claim it before undelegating more",
            0,
            0,
        );
    }

    let target_key = target.to_string();
    let Some(pool) = state.validator_pools.get(&target_key) else {
        return Receipt::failure(tx_hash, "no delegation pool for this validator", 0, 0);
    };
    if pool.total_shares == 0 || pool.total_delegated_stake == 0 {
        return Receipt::failure(tx_hash, "delegation pool is empty", 0, 0);
    }
    let Some(owned_shares) = state
        .delegator_shares
        .get(&target_key)
        .and_then(|m| m.get(&tx.from.to_string()))
        .copied()
    else {
        return Receipt::failure(tx_hash, "no delegation from this address to this validator", 0, 0);
    };
    let my_value = (owned_shares as u128 * pool.total_delegated_stake as u128 / pool.total_shares as u128) as u64;
    if tx.amount > my_value {
        return Receipt::failure(
            tx_hash,
            &format!("insufficient delegated balance: have {}, requested {}", my_value, tx.amount),
            0,
            0,
        );
    }
    // Ceiling division: burn at least enough shares to cover `tx.amount`, never less —
    // rounds against the withdrawer rather than the remaining pool.
    let shares_to_burn = ((tx.amount as u128 * pool.total_shares as u128)
        .div_ceil(pool.total_delegated_stake as u128)) as u64;
    let shares_to_burn = shares_to_burn.min(owned_shares);

    {
        let pool = state.validator_pools.get_mut(&target_key).unwrap();
        pool.total_shares -= shares_to_burn;
        pool.total_delegated_stake -= tx.amount;
    }
    let delegator_map = state.delegator_shares.get_mut(&target_key).unwrap();
    let remaining = owned_shares - shares_to_burn;
    if remaining == 0 {
        delegator_map.remove(&tx.from.to_string());
    } else {
        delegator_map.insert(tx.from.to_string(), remaining);
    }

    let unlock_height = height + state::UNBONDING_PERIOD;
    state.update_account(&tx.from, |acc| {
        acc.unbonding_stake = tx.amount;
        acc.unbonding_unlock_height = unlock_height;
        // Remember which pool this capital came out of: it is no longer in
        // `validator_pools[target]` for that validator's pool slash to reach, but it was
        // backing `target` right up to this transaction and stays slashable for `target`'s
        // misbehavior until the unbonding period ends. See `ChainState::slash`.
        acc.unbonding_source = Some(target.to_string());
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// `tx.from` sets its own validator commission rate — `tx.data` is 2 little-endian bytes
/// (basis points, 0-`MAX_COMMISSION_BPS`). Creates an empty pool entry if `tx.from` has never
/// had a delegator yet, purely to record the rate so the first delegation reads it back
/// instead of silently falling to `DEFAULT_COMMISSION_BPS`.
fn execute_set_commission(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    base_fee_amount: u64,
) -> Receipt {
    let sender = state.get_or_default(&tx.from);

    if tx.nonce != sender.nonce {
        return Receipt::failure(tx_hash, "nonce mismatch", 0, 0);
    }
    if sender.balance < tx.fee {
        return Receipt::failure(tx_hash, "insufficient balance for fee", 0, 0);
    }
    if tx.data.len() != 2 {
        return Receipt::failure(tx_hash, "malformed commission payload: expected 2 bytes", 0, 0);
    }
    let commission_bps = u16::from_le_bytes([tx.data[0], tx.data[1]]);
    if commission_bps > MAX_COMMISSION_BPS {
        return Receipt::failure(
            tx_hash,
            &format!("commission {} bps exceeds the maximum of {} bps", commission_bps, MAX_COMMISSION_BPS),
            0,
            0,
        );
    }

    state
        .validator_pools
        .entry(tx.from.to_string())
        .or_insert_with(|| DelegationPool {
            total_shares: 0,
            total_delegated_stake: 0,
            commission_bps: DEFAULT_COMMISSION_BPS,
        })
        .commission_bps = commission_bps;

    state.update_account(&tx.from, |acc| {
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn execute_register_name(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    base_fee_amount: u64,
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

    distribute_fee(state, validator, tx.fee, base_fee_amount)
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
fn execute_register_identity(_state: &mut ChainState, _tx: &Transaction, tx_hash: Hash, _base_fee_amount: u64) -> Receipt {
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
    base_fee_amount: u64,
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

    distribute_fee(state, validator, tx.fee, base_fee_amount)
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
    base_fee_amount: u64,
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
        return Receipt::failure(tx_hash, "proposed public key is not a valid PQC public key", 0, 0);
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

    distribute_fee(state, validator, tx.fee, base_fee_amount)
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
    base_fee_amount: u64,
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

    distribute_fee(state, validator, tx.fee, base_fee_amount)
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
    base_fee_amount: u64,
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

    distribute_fee(state, validator, tx.fee, base_fee_amount)
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
    base_fee_amount: u64,
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
    if tx.data.len() > helix_vm::MAX_CONTRACT_CODE_SIZE {
        // Enforced here (consensus layer), not just at the RPC body-size limit, so a
        // P2P-gossiped oversized deploy can't bloat every validator's permanent state.
        return Receipt::failure(
            tx_hash,
            &format!(
                "contract bytecode {} bytes exceeds the {}-byte limit",
                tx.data.len(),
                helix_vm::MAX_CONTRACT_CODE_SIZE
            ),
            0,
            0,
        );
    }
    if let Err(e) = helix_vm::validate(&tx.data) {
        return Receipt::failure(tx_hash, &format!("invalid contract bytecode: {e}"), 0, 0);
    }

    state.update_account(&tx.from, |acc| {
        acc.code = Some(tx.data.clone());
        acc.balance -= tx.fee;
        acc.nonce += 1;
    });

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// Bridges a running contract to real `ChainState` for the duration of one call, buffering
/// every `storage_write`/`transfer` in memory rather than applying them immediately — see
/// `helix_vm`'s module doc comment ("Atomicity") for why: a trap partway through (including
/// running out of fuel) must leave chain state exactly as it was before the call started.
/// `into_commit_data` converts the buffered side effects into an owned, `state`-independent
/// value once the call has returned `Ok` — the caller applies it separately, after this
/// struct (and the borrow of `state` it holds for reads) has gone out of scope, so the
/// borrow checker doesn't see a conflict with the mutable access the commit itself needs.
struct ContractHostContext<'a> {
    state: &'a ChainState,
    contract: Address,
    contract_str: String,
    caller_str: String,
    value: u64,
    height: u64,
    input: Vec<u8>,
    storage_writes: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    transfers: Vec<(Address, u64)>,
    /// Running total already earmarked for `transfers` this call — `available_balance()`
    /// subtracts this so a contract can't `transfer()` the same nano-HLX twice in one call.
    pending_debit: u64,
    return_data: Vec<u8>,
}

struct ContractCommitData {
    contract: Address,
    storage_writes: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    transfers: Vec<(Address, u64)>,
    #[allow(dead_code)] // not yet surfaced anywhere (no view-call/return-data plumbing to the RPC layer yet) — kept for the next increment rather than discarded
    return_data: Vec<u8>,
}

impl<'a> ContractHostContext<'a> {
    fn new(state: &'a ChainState, contract: Address, caller: Address, value: u64, height: u64, input: Vec<u8>) -> Self {
        ContractHostContext {
            contract_str: contract.to_string(),
            caller_str: caller.to_string(),
            contract,
            value,
            height,
            input,
            state,
            storage_writes: Default::default(),
            transfers: Vec::new(),
            pending_debit: 0,
            return_data: Vec::new(),
        }
    }

    /// What this contract could still send via `transfer()` right now: its real on-chain
    /// balance, plus the value sent with this call (not yet credited to real state — that
    /// only happens on commit, like everything else here), minus whatever this same call has
    /// already earmarked.
    fn available_balance(&self) -> u64 {
        let real = self.state.get(&self.contract).map(|a| a.balance).unwrap_or(0);
        real.saturating_add(self.value).saturating_sub(self.pending_debit)
    }

    fn into_commit_data(self) -> ContractCommitData {
        ContractCommitData {
            contract: self.contract,
            storage_writes: self.storage_writes,
            transfers: self.transfers,
            return_data: self.return_data,
        }
    }
}

impl helix_vm::HostContext for ContractHostContext<'_> {
    fn storage_read(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(v) = self.storage_writes.get(key) {
            return Some(v.clone());
        }
        self.state.contract_storage_read(&self.contract, key)
    }

    fn storage_write(&mut self, key: &[u8], value: Vec<u8>) {
        self.storage_writes.insert(key.to_vec(), value);
    }

    fn transfer(&mut self, to: &str, amount: u64) -> helix_vm::TransferOutcome {
        let Ok(to_addr) = Address::from_str(to) else {
            return helix_vm::TransferOutcome::InvalidAddress;
        };
        if amount > self.available_balance() {
            return helix_vm::TransferOutcome::InsufficientBalance;
        }
        self.pending_debit += amount;
        self.transfers.push((to_addr, amount));
        helix_vm::TransferOutcome::Ok
    }

    fn caller(&self) -> &str {
        &self.caller_str
    }

    fn self_address(&self) -> &str {
        &self.contract_str
    }

    fn value(&self) -> u64 {
        self.value
    }

    fn block_height(&self) -> u64 {
        self.height
    }

    fn input(&self) -> &[u8] {
        &self.input
    }

    fn set_return_data(&mut self, data: Vec<u8>) {
        self.return_data = data;
    }
}

/// Call a deployed contract at `tx.to`, running its exported `call()` entry point with fuel
/// metering. `tx.amount` (if any) is credited to the contract's balance only on successful
/// execution, matching normal transfer semantics — and, as of host imports, so is everything
/// the contract itself did via `storage_write`/`transfer` (see `ContractHostContext`).
fn execute_call_contract(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    height: u64,
    base_fee_amount: u64,
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
    let mut ctx = ContractHostContext::new(state, target.clone(), tx.from.clone(), tx.amount, height, tx.data.clone());
    let call_result = helix_vm::call(&code, fuel_limit, &mut ctx);

    if let Err(e) = call_result {
        // `ctx` (and every storage_write/transfer it buffered) is simply dropped here, never
        // applied — the atomicity guarantee host imports need: a trap must leave chain state
        // exactly as it was before the call started.
        //
        // The fee is still charged and the nonce still advances, because fuel-metered execution
        // was genuinely attempted and burned real validator CPU — a deliberately fuel-exhausting
        // loop must be a one-time cost to its author, not a free tx replayable forever. That
        // charge used to happen right here, and only here; it now happens centrally in
        // `execute_transaction` for every failing transaction. Doing it in both places would
        // take the fee twice. The old code also reported the split as `0, 0` while actually
        // charging, which is a lie the central path does not tell.
        return Receipt::failure(tx_hash, &format!("contract call failed: {e}"), 0, 0);
    }

    // `ctx` is consumed here, ending the immutable borrow of `state` it held for reads —
    // only past this point can `state` be borrowed mutably again to apply the call's effects.
    let commit = ctx.into_commit_data();

    state.update_account(&tx.from, |acc| {
        acc.balance -= total_cost;
        acc.nonce += 1;
    });
    state.update_account(&target, |acc| {
        acc.balance += tx.amount;
    });
    for (key, value) in commit.storage_writes {
        state.contract_storage_write(&commit.contract, key, value);
    }
    for (to, amount) in commit.transfers {
        state.update_account(&commit.contract, |acc| acc.balance -= amount);
        state.update_account(&to, |acc| acc.balance += amount);
    }

    distribute_fee(state, validator, tx.fee, base_fee_amount)
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
    base_fee_amount: u64,
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

    distribute_fee(state, validator, tx.fee, base_fee_amount)
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
    base_fee_amount: u64,
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

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

fn execute_prove_personhood(
    state: &mut ChainState,
    tx: &Transaction,
    validator: &Address,
    tx_hash: Hash,
    base_fee_amount: u64,
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
    // The authority signs over the commitment *bound to the claiming address* (`tx.from`),
    // not the bare commitment — otherwise a mempool observer could lift this whole payload
    // out of the pending tx and claim the verification from their own address first. Binding
    // it here means an authority-issued payload is only ever usable from the exact address it
    // was issued to (see `personhood_authority_preimage`).
    let signed_preimage = personhood_authority_preimage(&payload.commitment, &tx.from);
    let authority_sig_valid = state.personhood_authorities.iter().any(|authority| {
        helix_crypto::verify_with_scheme(
            payload.authority_crypto_version,
            authority,
            &signed_preimage,
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

    distribute_fee(state, validator, tx.fee, base_fee_amount)
        .map(|(burned, reward)| Receipt::success(tx_hash, burned, reward))
        .unwrap_or_else(|e| Receipt::failure(tx_hash, &e.to_string(), 0, 0))
}

/// Credit a validator reward (a block-reward mint or a fee's validator-half) to `recipient`,
/// splitting it between the validator's own balance and its delegation pool (if it has one)
/// — see `DelegationPool`'s doc comment for why this stays O(1) regardless of delegator
/// count. `recipient` is normally the real block validator, but can be a
/// `HELIX_REWARD_ADDRESS` override (see `execute_block`) — in that case a pool keyed to the
/// *real* validator's address is correctly left untouched here (nobody delegates to a
/// reward-redirect address, only to the validator identity itself), so this degrades safely
/// to the pre-delegation 100%-to-recipient behavior in that one edge case.
fn credit_validator_reward(state: &mut ChainState, recipient: &Address, amount: u64) {
    if amount == 0 {
        return;
    }
    let key = recipient.to_string();
    let Some(pool) = state.validator_pools.get(&key) else {
        state.update_account(recipient, |acc| acc.balance = acc.balance.saturating_add(amount));
        return;
    };
    let self_stake = state.accounts.get(&key).map(|a| a.staked).unwrap_or(0) as u128;
    let total_stake = self_stake + pool.total_delegated_stake as u128;
    if total_stake == 0 {
        state.update_account(recipient, |acc| acc.balance = acc.balance.saturating_add(amount));
        return;
    }
    let self_share = (amount as u128 * self_stake / total_stake) as u64;
    let delegated_share = amount - self_share;
    let commission = (delegated_share as u128 * pool.commission_bps as u128 / 10_000) as u64;
    let pool_gain = delegated_share - commission;
    let validator_total = self_share + commission;

    state.update_account(recipient, |acc| {
        acc.balance = acc.balance.saturating_add(validator_total)
    });
    if pool_gain > 0 {
        // Just inserted/confirmed present via the `let Some(pool)` above.
        state.validator_pools.get_mut(&key).unwrap().total_delegated_stake += pool_gain;
    }
}

/// EIP-1559 fee split: the **base fee** portion (`base_fee_amount = block base_fee_per_byte ×
/// tx size`, computed by the caller) is burned; the remainder of the fee is the validator's
/// **tip** (split with its delegation pool, if any — see `credit_validator_reward`). Callers
/// guarantee `fee >= base_fee_amount` (underpaying transactions are rejected up front in
/// `execute_transaction`), but this clamps defensively so it can never over-burn.
fn distribute_fee(
    state: &mut ChainState,
    validator: &Address,
    fee: u64,
    base_fee_amount: u64,
) -> ExecutionResult<(u64, u64)> {
    let burned = base_fee_amount.min(fee); // base fee is burned
    let reward = fee - burned;             // tip goes to the block validator
    credit_validator_reward(state, validator, reward);
    Ok((burned, reward))
}

// Kani feasibility study (see CLAUDE.md backlog): a harness proving distribute_fee()'s
// fee-conservation property (burned + reward == fee, for every u64 fee) was attempted
// here and deliberately removed again — it does not terminate in practice. ChainState
// is HashMap-backed, and CBMC gets stuck trying to fully unwind the loop inside
// std's SipHasher13::write (observed hanging past 1200 loop iterations with no default
// bound, and still not converging within a 150s budget even with an explicit
// `#[kani::unwind(20)]`). This isn't specific to this function — it's a structural
// limitation of bounded model checking against anything touching std HashMap without
// substantially more harness engineering (e.g. a verification-only state stub instead
// of the real ChainState) than fits a feasibility study. See the backlog entry for the
// full writeup and recommendation; genesis.rs's kani_proofs module has the harnesses
// that *do* work (pure arithmetic, no HashMap in the call path).

#[cfg(test)]
mod tests {
    use super::*;
    use helix_core::{BlockHeader, CryptoVersion, TxType};
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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.resolve_name("alice"), Some(addr.to_string().as_str()));
        assert_eq!(state.name_of(&addr), Some("alice"));
        assert_eq!(state.get(&addr).unwrap().balance, 1_000_000 - 10_000);
        assert_eq!(state.get(&addr).unwrap().nonce, 1);
    }

    #[test]
    fn tx_below_block_base_fee_is_rejected_then_base_fee_is_burned_and_rest_tips() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let to = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        // A transfer whose flat fee (10) can't cover base_fee_per_byte(1) × its size (hundreds
        // of bytes) is not includable — rejected up front with no state change.
        let tx = signed_tx(&kp, &addr, TxType::Transfer, Some(to.clone()), 1, vec![], 0, 10);
        assert!(tx.size_bytes() > 10, "tx must be larger than its fee for this to test the gate");
        let rejected = execute_transaction(&mut state, &tx, &validator, 0, 1);
        assert!(!rejected.success);
        assert_eq!(rejected.error.as_deref(), Some("fee below block base fee"));
        assert_eq!(state.get(&addr).unwrap().balance, 1_000_000, "rejected tx must not touch balance");
        assert_eq!(state.get(&addr).unwrap().nonce, 0, "rejected tx must not advance nonce");

        // With a fee it can afford, exactly base_fee_per_byte × size is burned; the rest tips
        // the validator (EIP-1559 split, replacing the old flat 50/50).
        let base_fee_per_byte = 1u64;
        let tx2 = signed_tx(&kp, &addr, TxType::Transfer, Some(to.clone()), 1, vec![], 0, 100_000);
        let expected_burn = base_fee_per_byte * tx2.size_bytes();
        let ok = execute_transaction(&mut state, &tx2, &validator, 0, base_fee_per_byte);
        assert!(ok.success, "expected success, got: {:?}", ok.error);
        assert_eq!(ok.fee_burned, expected_burn);
        assert_eq!(ok.fee_to_validator, 100_000 - expected_burn);
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
        assert!(execute_transaction(&mut state, &tx_a, &validator, 0, 0).success);

        let tx_b = signed_register_name_tx(&kp_b, &addr_b, "alice", 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx_b, &validator, 0, 0);
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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);
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
            let receipt = execute_transaction(&mut state, &tx, &validator, 50 + i as u64, 0);
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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

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
        assert!(execute_transaction(&mut state, &reg_tx, &validator, 0, 0).success);

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
            let receipt = execute_transaction(&mut state, &tx, &validator, 1, 0);
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
        assert!(execute_transaction(&mut state, &tx, &validator, 1, 0).success);
        assert!(state.recovery_key(&owner).is_some());

        // Old key can no longer sign for this address.
        let old_key_tx = signed_register_guardians_tx(&owner_kp, &owner, &guardian_addrs, 1, 10_000);
        let receipt = execute_transaction(&mut state, &old_key_tx, &validator, 2, 0);
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
        let receipt = execute_transaction(&mut state, &transfer_tx, &validator, 3, 0);
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
        assert!(execute_transaction(&mut state, &reg_tx, &validator, 0, 0).success);

        let outsider_kp = KeyPair::generate();
        let outsider = Address::from_public_key(&outsider_kp.public);
        state.update_account(&outsider, |acc| acc.balance = 1_000_000);

        let new_kp = KeyPair::generate();
        let tx = signed_approve_recovery_tx(&outsider_kp, &outsider, &owner, &new_kp.public, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 1, 0);
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
        assert!(execute_transaction(&mut state, &reg_tx, &validator, 0, 0).success);

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
        assert!(execute_transaction(&mut state, &approve_tx, &validator, 1, 0).success);
        assert!(state.recovery_request(&owner).is_some());

        // Owner is now locked out of changing guardians... The attempt is rejected but still
        // pays and consumes nonce 1, like any payable transaction that took a block slot and
        // failed — hence nonce 2 for the next one.
        let blocked_tx = signed_register_guardians_tx(&owner_kp, &owner, &guardian_addrs, 1, 10_000);
        let receipt = execute_transaction(&mut state, &blocked_tx, &validator, 2, 0);
        assert!(!receipt.success, "guardian changes should be blocked while a request is pending");

        // ...until they cancel the stuck request themselves, still with their original key
        // (recovery never finalized, so no override key was ever set).
        let cancel_tx = signed_cancel_recovery_request_tx(&owner_kp, &owner, 2, 10_000);
        let receipt = execute_transaction(&mut state, &cancel_tx, &validator, 2, 0);
        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert!(state.recovery_request(&owner).is_none());

        // Guardian changes work again.
        let unblocked_tx = signed_register_guardians_tx(&owner_kp, &owner, &guardian_addrs, 3, 10_000);
        let receipt = execute_transaction(&mut state, &unblocked_tx, &validator, 3, 0);
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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);
        assert!(!receipt.success);
    }

    fn valid_contract_wasm() -> Vec<u8> {
        wat::parse_str(r#"(module (func (export "call")))"#).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success);
        assert!(state.get(&addr).unwrap().code.is_none());
    }

    #[test]
    fn deploy_contract_rejects_oversized_bytecode() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        // One byte past the consensus-layer code-size ceiling — must be rejected before it
        // can be written into permanent, replicated account state (regardless of transport).
        let oversized = vec![0u8; helix_vm::MAX_CONTRACT_CODE_SIZE + 1];
        let tx = signed_contract_tx(
            &kp,
            &addr,
            TxType::DeployContract,
            None,
            0,
            oversized,
            0,
            10_000,
        );
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success, "oversized deploy must fail");
        assert!(state.get(&addr).unwrap().code.is_none(), "no code may be stored");
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
        assert!(execute_transaction(&mut state, &deploy_tx, &validator, 0, 0).success);

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
        let receipt = execute_transaction(&mut state, &call_tx, &validator, 1, 0);

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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);
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
        assert!(execute_transaction(&mut state, &deploy_tx, &validator, 0, 0).success);

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
        let receipt = execute_transaction(&mut state, &call_tx, &validator, 1, 0);

        // The call itself still fails (ran out of fuel) ...
        assert!(!receipt.success);
        // ... but the fee was charged and the nonce advanced anyway, since
        // execution actually ran and consumed real (fuel-metered) CPU — otherwise
        // this exact tx could be resubmitted and re-executed forever for free.
        assert_eq!(state.get(&caller).unwrap().balance, 1_000_000 - 1);
        assert_eq!(state.get(&caller).unwrap().nonce, 1);
    }

    // ── Host import tests ───────────────────────────────────────────────────────
    //
    // These exercise real contract execution against a real ChainState (not the mocked
    // HostContext in helix-vm's own unit tests) — the whole point is proving the
    // ContractHostContext bridge, storage persistence/isolation, and atomicity-on-trap all
    // hold when wired to the actual state machine every other transaction type shares.

    /// A contract that writes a fixed key/value into its own storage on every call.
    fn storage_writer_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
                (import "env" "storage_write" (func $storage_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "greeting")
                (data (i32.const 16) "hello")
                (func (export "call")
                    (drop (call $storage_write (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 5)))
                )
            )
            "#,
        )
        .unwrap()
    }

    #[test]
    fn call_contract_storage_write_persists_into_real_chain_state() {
        let deployer_kp = KeyPair::generate();
        let deployer = Address::from_public_key(&deployer_kp.public);
        let caller_kp = KeyPair::generate();
        let caller = Address::from_public_key(&caller_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&deployer, |acc| acc.balance = 1_000_000);
        state.update_account(&caller, |acc| acc.balance = 1_000_000);

        let deploy_tx = signed_contract_tx(&deployer_kp, &deployer, TxType::DeployContract, None, 0, storage_writer_wasm(), 0, 10_000);
        assert!(execute_transaction(&mut state, &deploy_tx, &validator, 0, 0).success);

        assert_eq!(state.contract_storage_read(&deployer, b"greeting"), None, "nothing written yet");

        let call_tx = signed_contract_tx(&caller_kp, &caller, TxType::CallContract, Some(deployer.clone()), 0, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &call_tx, &validator, 1, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.contract_storage_read(&deployer, b"greeting"), Some(b"hello".to_vec()));
    }

    #[test]
    fn call_contract_storage_is_isolated_between_different_contracts() {
        let deployer_a_kp = KeyPair::generate();
        let deployer_a = Address::from_public_key(&deployer_a_kp.public);
        let deployer_b_kp = KeyPair::generate();
        let deployer_b = Address::from_public_key(&deployer_b_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&deployer_a, |acc| acc.balance = 1_000_000);
        state.update_account(&deployer_b, |acc| acc.balance = 1_000_000);

        // Both contracts write to the exact same key ("greeting") — same bytecode, deployed
        // by two different addresses, so two different contract accounts.
        let deploy_a = signed_contract_tx(&deployer_a_kp, &deployer_a, TxType::DeployContract, None, 0, storage_writer_wasm(), 0, 10_000);
        let deploy_b = signed_contract_tx(&deployer_b_kp, &deployer_b, TxType::DeployContract, None, 0, storage_writer_wasm(), 0, 10_000);
        assert!(execute_transaction(&mut state, &deploy_a, &validator, 0, 0).success);
        assert!(execute_transaction(&mut state, &deploy_b, &validator, 0, 0).success);

        let call_a = signed_contract_tx(&deployer_a_kp, &deployer_a, TxType::CallContract, Some(deployer_a.clone()), 0, vec![], 1, 10_000);
        assert!(execute_transaction(&mut state, &call_a, &validator, 1, 0).success);

        // B never called its own contract — its storage must still be untouched, even though
        // A's identical contract just wrote the exact same key.
        assert_eq!(state.contract_storage_read(&deployer_a, b"greeting"), Some(b"hello".to_vec()));
        assert_eq!(
            state.contract_storage_read(&deployer_b, b"greeting"),
            None,
            "one contract's storage write must never be visible under a different contract's address"
        );
    }

    /// A contract that transfers a fixed amount to a fixed recipient address on every call.
    fn transfer_wasm(recipient: &Address, amount: i64) -> Vec<u8> {
        let addr_str = recipient.to_string();
        wat::parse_str(format!(
            r#"
            (module
                (import "env" "transfer" (func $transfer (param i32 i32 i64) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "{addr_str}")
                (func (export "call")
                    (drop (call $transfer (i32.const 0) (i32.const {len}) (i64.const {amount})))
                )
            )
            "#,
            len = addr_str.len(),
        ))
        .unwrap()
    }

    #[test]
    fn call_contract_transfer_moves_real_balance_to_a_third_party() {
        let deployer_kp = KeyPair::generate();
        let deployer = Address::from_public_key(&deployer_kp.public);
        let caller_kp = KeyPair::generate();
        let caller = Address::from_public_key(&caller_kp.public);
        let recipient = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&deployer, |acc| acc.balance = 1_000_000);
        state.update_account(&caller, |acc| acc.balance = 1_000_000);

        let wasm = transfer_wasm(&recipient, 300);
        let deploy_tx = signed_contract_tx(&deployer_kp, &deployer, TxType::DeployContract, None, 0, wasm, 0, 10_000);
        assert!(execute_transaction(&mut state, &deploy_tx, &validator, 0, 0).success);

        // Send 1000 along with the call — the contract's available balance during execution
        // is its real balance (0) plus this value, so the 300 transfer only succeeds because
        // of it (proves `value()` is credited before host calls run, not only after).
        let call_tx = signed_contract_tx(&caller_kp, &caller, TxType::CallContract, Some(deployer.clone()), 1_000, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &call_tx, &validator, 1, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.get(&recipient).unwrap().balance, 300);
        // The deployer's address doubles as the contract's account. It started at 1_000_000,
        // paid a 10_000 deploy fee, then received the 1000 tx.amount and sent 300 back out:
        // 1_000_000 - 10_000 + 1_000 - 300 = 990_700.
        assert_eq!(state.get(&deployer).unwrap().balance, 990_700);
    }

    #[test]
    fn call_contract_trap_rolls_back_storage_writes_and_transfers_atomically() {
        let deployer_kp = KeyPair::generate();
        let deployer = Address::from_public_key(&deployer_kp.public);
        let caller_kp = KeyPair::generate();
        let caller = Address::from_public_key(&caller_kp.public);
        let recipient = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&deployer, |acc| acc.balance = 1_000_000);
        state.update_account(&caller, |acc| acc.balance = 1_000_000);

        // Writes storage, transfers funds out, THEN traps unconditionally — every side
        // effect before the trap must still be fully rolled back, exactly like every other
        // transaction type already guarantees.
        let addr_str = recipient.to_string();
        let wasm = wat::parse_str(format!(
            r#"
            (module
                (import "env" "storage_write" (func $storage_write (param i32 i32 i32 i32) (result i32)))
                (import "env" "transfer" (func $transfer (param i32 i32 i64) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "greeting")
                (data (i32.const 16) "hello")
                (data (i32.const 32) "{addr_str}")
                (func (export "call")
                    (drop (call $storage_write (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 5)))
                    (drop (call $transfer (i32.const 32) (i32.const {len}) (i64.const 500)))
                    (unreachable)
                )
            )
            "#,
            len = addr_str.len(),
        ))
        .unwrap();

        let deploy_tx = signed_contract_tx(&deployer_kp, &deployer, TxType::DeployContract, None, 0, wasm, 0, 10_000);
        assert!(execute_transaction(&mut state, &deploy_tx, &validator, 0, 0).success);

        let call_tx = signed_contract_tx(&caller_kp, &caller, TxType::CallContract, Some(deployer.clone()), 1_000, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &call_tx, &validator, 1, 0);

        assert!(!receipt.success, "a trapped call must fail");
        assert_eq!(state.contract_storage_read(&deployer, b"greeting"), None, "the storage write before the trap must be rolled back");
        assert!(state.get(&recipient).is_none(), "the transfer before the trap must be rolled back — recipient must not even have an account");
        assert_eq!(
            state.get(&deployer).unwrap().balance,
            990_000,
            "the contract's own balance (1_000_000 minus the 10_000 deploy fee) must be \
             untouched by the trapped call — tx.amount is only credited on success, same as \
             before host imports existed"
        );
        // Matches the pre-existing out-of-gas-failure contract: fee charged, nonce advanced,
        // even though the call itself failed — real (fuel-metered) CPU was still spent.
        assert_eq!(state.get(&caller).unwrap().balance, 1_000_000 - 10_000);
        assert_eq!(state.get(&caller).unwrap().nonce, 1);
    }

    #[test]
    fn call_contract_input_is_the_transaction_data() {
        let deployer_kp = KeyPair::generate();
        let deployer = Address::from_public_key(&deployer_kp.public);
        let caller_kp = KeyPair::generate();
        let caller = Address::from_public_key(&caller_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&deployer, |acc| acc.balance = 1_000_000);
        state.update_account(&caller, |acc| acc.balance = 1_000_000);

        // Echoes its call input straight into storage under key "in".
        let wasm = wat::parse_str(
            r#"
            (module
                (import "env" "get_input" (func $get_input (param i32 i32) (result i32)))
                (import "env" "storage_write" (func $storage_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "in")
                (func (export "call")
                    (local $len i32)
                    (local.set $len (call $get_input (i32.const 64) (i32.const 32)))
                    (drop (call $storage_write (i32.const 0) (i32.const 2) (i32.const 64) (local.get $len)))
                )
            )
            "#,
        )
        .unwrap();
        let deploy_tx = signed_contract_tx(&deployer_kp, &deployer, TxType::DeployContract, None, 0, wasm, 0, 10_000);
        assert!(execute_transaction(&mut state, &deploy_tx, &validator, 0, 0).success);

        let call_tx = signed_contract_tx(&caller_kp, &caller, TxType::CallContract, Some(deployer.clone()), 0, b"pass-through".to_vec(), 0, 10_000);
        let receipt = execute_transaction(&mut state, &call_tx, &validator, 1, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.contract_storage_read(&deployer, b"in"), Some(b"pass-through".to_vec()));
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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

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
        let receipt = execute_transaction(&mut state, &tx, &validator, 100, 0);

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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success);
        assert!(state.proposals.is_empty(), "the chain-stalling proposal must not exist");
        // The proposal is refused; the fee is charged, as for any payable transaction that took a
        // block slot and failed.
        assert_eq!(state.get(&addr).unwrap().balance, 1_000_000 - 10_000);
        assert_eq!(state.get(&addr).unwrap().nonce, 1);
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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.proposal(0).unwrap().new_value, floor);

        // One nano below the floor must still fail — confirms the boundary is exact.
        let data2 = governance::encode_proposal(governance::GovernanceParam::MinValidatorStake, floor - 1);
        let tx2 = signed_governance_tx(&kp, &addr, TxType::CreateProposal, data2, 1, 10_000);
        assert!(!execute_transaction(&mut state, &tx2, &validator, 1, 0).success);
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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

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
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

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
        assert!(execute_transaction(&mut state, &create_tx, &validator, 0, 0).success);
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
        assert!(execute_transaction(&mut state, &self_vote, &validator, 1, 0).success);
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
        let receipt = execute_transaction(&mut state, &second_vote, &validator, 2, 0);

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
        assert!(execute_transaction(&mut state, &create_tx, &validator, 0, 0).success);

        let vote_tx =
            signed_governance_tx(&kp, &addr, TxType::VoteProposal, governance::encode_vote(0), 1, 10_000);
        assert!(execute_transaction(&mut state, &vote_tx, &validator, 1, 0).success);

        let repeat_vote_tx =
            signed_governance_tx(&kp, &addr, TxType::VoteProposal, governance::encode_vote(0), 2, 10_000);
        let receipt = execute_transaction(&mut state, &repeat_vote_tx, &validator, 2, 0);
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
        assert!(execute_transaction(&mut state, &create_tx, &validator, 0, 0).success);
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
        assert!(execute_transaction(&mut state, &attacker_vote, &validator, 1, 0).success);
        // 200 alone is comfortably short of the 234 quorum — not a boundary fluke.
        assert!(!state.proposal(0).unwrap().executed);
        assert_eq!(state.proposal(0).unwrap().yes_stake, 200);

        // Attacker fully unstakes right after voting — their already-counted
        // yes_stake contribution is now backed by nothing.
        let unstake_tx = signed_unstake_tx(&attacker_kp, &attacker, 200, 2, 1);
        assert!(execute_transaction(&mut state, &unstake_tx, &validator, 2, 0).success);
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
        let receipt = execute_transaction(&mut state, &tiny_vote, &validator, 3, 0);
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
        assert!(execute_transaction(&mut state, &create_tx, &validator, 0, 0).success);

        let expired_height = governance::VOTING_PERIOD_BLOCKS + 1;
        let vote_tx =
            signed_governance_tx(&voter_kp, &voter, TxType::VoteProposal, governance::encode_vote(0), 0, 10_000);
        let receipt = execute_transaction(&mut state, &vote_tx, &validator, expired_height, 0);
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
        let receipt = execute_transaction(&mut state, &tx, &validator, 1, 0);
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
        execute_transaction(&mut state, &unstake_tx, &validator, 1, 0);

        // Try to claim one block before unlock
        let claim_tx = signed_tx_simple(&kp, &addr, TxType::ClaimUnbonded, 1, 10_000);
        let receipt = execute_transaction(&mut state, &claim_tx, &validator, UNBONDING_PERIOD, 0);
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
        execute_transaction(&mut state, &unstake_tx, &validator, 1, 0);

        // Claim exactly at unlock height
        let unlock = 1 + UNBONDING_PERIOD;
        let claim_tx = signed_tx_simple(&kp, &addr, TxType::ClaimUnbonded, 1, 10_000);
        let receipt = execute_transaction(&mut state, &claim_tx, &validator, unlock, 0);
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
        assert!(execute_transaction(&mut state, &tx1, &validator, 1, 0).success);

        let tx2 = signed_unstake_tx(&kp, &addr, 100_000, 1, 10_000);
        let receipt = execute_transaction(&mut state, &tx2, &validator, 2, 0);
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
        let receipt = execute_transaction(&mut state, &tx, &validator, 1, 0);

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
        let receipt = execute_transaction(&mut state, &tx, &validator, 1, 0);

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
        let receipt = execute_transaction(&mut state, &tx, &validator, 1, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.get(&addr).unwrap().staked, min_stake);
    }

    #[test]
    fn unstake_rejects_dropping_self_bond_ratio_below_minimum() {
        // Validator has 100_000 self-staked and 900_000 delegated (exactly the 10% floor:
        // 100_000 / 1_000_000 effective = 10%). Unstaking even a small amount would push self
        // stake below what MIN_SELF_BOND_RATIO_BPS requires against the existing delegated
        // pool — must be rejected even though this validator isn't the last one in the
        // network (a separate, already-covered guard).
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let other_validator_kp = KeyPair::generate();
        let other_validator = Address::from_public_key(&other_validator_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let min_stake = crate::genesis::MIN_VALIDATOR_STAKE;

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 100_000;
        });
        // A second validator so the "last staker" guard never fires here.
        state.update_account(&other_validator, |acc| acc.staked = min_stake);
        state.validator_pools.insert(
            addr.to_string(),
            DelegationPool { total_shares: 900_000, total_delegated_stake: 900_000, commission_bps: DEFAULT_COMMISSION_BPS },
        );

        let tx = signed_unstake_tx(&kp, &addr, 1, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 1, 0);

        assert!(!receipt.success, "unstake must be rejected: self-bond ratio would drop below the minimum");
        assert_eq!(state.get(&addr).unwrap().staked, 100_000, "stake must be untouched");
        let _ = other_validator_kp;
    }

    #[test]
    fn unstake_allows_dropping_self_bond_ratio_when_no_delegators() {
        // Same starting self-stake as above, but with no delegation pool — the self-bond
        // ratio guard must not fire for a validator nobody has delegated to.
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let other_validator_kp = KeyPair::generate();
        let other_validator = Address::from_public_key(&other_validator_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let min_stake = crate::genesis::MIN_VALIDATOR_STAKE;

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| {
            acc.balance = 1_000_000;
            acc.staked = 100_000;
        });
        state.update_account(&other_validator, |acc| acc.staked = min_stake);

        let tx = signed_unstake_tx(&kp, &addr, 1, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 1, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        let _ = other_validator_kp;
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
        claimant: &Address,
    ) -> PersonhoodProofPayload {
        // The authority signs the commitment bound to the claiming address, matching what
        // `execute_prove_personhood` verifies (see `personhood_authority_preimage`).
        let preimage = personhood_authority_preimage(&commitment, claimant);
        PersonhoodProofPayload {
            commitment,
            proof_bytes,
            authority_signature: authority_kp.sign(&preimage).unwrap(),
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
        let payload = personhood_payload(&authority_kp, commitment, proof.as_bytes().to_vec(), &addr);
        let tx = signed_personhood_tx(&kp, &addr, &payload, 0, 10_000);

        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);
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
        let payload = personhood_payload(&authority_kp, commitment, proof.as_bytes().to_vec(), &addr);
        let tx = signed_personhood_tx(&kp, &addr, &payload, 0, 10_000);

        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);
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
        let payload = personhood_payload(&authority_kp, commitment, proof.as_bytes().to_vec(), &addr);
        let tx = signed_personhood_tx(&kp, &addr, &payload, 0, 10_000);

        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);
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
        let payload = personhood_payload(&attacker_pretending_to_be_authority, commitment, proof.as_bytes().to_vec(), &addr);
        let tx = signed_personhood_tx(&kp, &addr, &payload, 0, 10_000);

        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);
        assert!(!receipt.success, "self-issued commitment without the real authority's signature must be rejected");
        assert!(!state.has_personhood(&addr));
    }

    #[test]
    fn prove_personhood_rejects_reused_commitment_even_with_a_valid_second_binding() {
        // A commitment may only ever be claimed once. Here the authority mistakenly (or
        // maliciously) issues a *correctly bound* payload for the same commitment to two
        // different addresses — the address binding alone wouldn't stop the second one, so the
        // `used_personhood_commitments` dedup must: the first claim consumes the commitment,
        // and the second — despite carrying its own valid authority signature — is rejected.
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
        let payload1 = personhood_payload(&authority_kp, commitment, proof.as_bytes().to_vec(), &addr1);
        let payload2 = personhood_payload(&authority_kp, commitment, proof.as_bytes().to_vec(), &addr2);

        let tx1 = signed_personhood_tx(&kp1, &addr1, &payload1, 0, 10_000);
        assert!(execute_transaction(&mut state, &tx1, &validator, 0, 0).success);
        assert!(state.has_personhood(&addr1));

        // Second address has its OWN valid authority binding, but the commitment is spent.
        let tx2 = signed_personhood_tx(&kp2, &addr2, &payload2, 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx2, &validator, 1, 0);

        assert!(!receipt.success, "a commitment claimed once must never be claimed again");
        assert!(!state.has_personhood(&addr2), "reusing a spent commitment must not gain personhood");
        assert!(state.has_personhood(&addr1));
    }

    #[test]
    fn prove_personhood_rejects_front_run_payload_bound_to_another_address() {
        // The front-running defense: an authority issues a payload to the victim (addr1). It
        // is public in the mempool, so an attacker (addr2) copies commitment + proof_bytes +
        // authority_signature verbatim and races to submit it from their own address first.
        // Because the authority signed over the commitment bound to addr1, the signature check
        // fails for addr2 — the attacker gains nothing, AND the commitment is NOT consumed, so
        // the victim can still claim their verification afterward.
        let victim_kp = KeyPair::generate();
        let victim = Address::from_public_key(&victim_kp.public);
        let attacker_kp = KeyPair::generate();
        let attacker = Address::from_public_key(&attacker_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let authority_kp = KeyPair::generate();

        let mut state = ChainState::new(0);
        state.update_account(&victim, |acc| acc.balance = 1_000_000);
        state.update_account(&attacker, |acc| acc.balance = 1_000_000);
        state.personhood_authorities.push(authority_kp.public.clone());

        let (proof, commitment) = helix_zkp::prove_personhood([7u8; 16]);
        // Authority-issued payload, bound to the victim's address.
        let victim_payload = personhood_payload(&authority_kp, commitment, proof.as_bytes().to_vec(), &victim);

        // Attacker submits the victim's exact payload from their own address, front-running.
        let attack_tx = signed_personhood_tx(&attacker_kp, &attacker, &victim_payload, 0, 10_000);
        let attack_receipt = execute_transaction(&mut state, &attack_tx, &validator, 0, 0);
        assert!(!attack_receipt.success, "a payload bound to another address must be rejected");
        assert!(!state.has_personhood(&attacker), "front-runner must not gain personhood");

        // The commitment was never consumed, so the real victim can still claim it.
        let victim_tx = signed_personhood_tx(&victim_kp, &victim, &victim_payload, 0, 10_000);
        let victim_receipt = execute_transaction(&mut state, &victim_tx, &validator, 1, 0);
        assert!(victim_receipt.success, "victim's own claim must still succeed, got: {:?}", victim_receipt.error);
        assert!(state.has_personhood(&victim));
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
        let receipt = execute_transaction(&mut state, &tx, &block_validator, 0, 0);

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
        assert!(execute_transaction(&mut state, &tx1, &block_validator, 0, 0).success);
        let staked_after_first_slash = state.get(&validator_addr).unwrap().staked;

        // Same incident reported again (could be a different reporter in practice) — must
        // not slash a second time for the same (validator, height, round).
        let tx2 = signed_evidence_tx(&reporter_kp, &reporter, &evidence, 1);
        let receipt = execute_transaction(&mut state, &tx2, &block_validator, 1, 0);
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
        let receipt = execute_transaction(&mut state, &tx, &block_validator, 0, 0);
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
        let receipt = execute_transaction(&mut state, &tx, &block_validator, 0, 0);
        assert!(!receipt.success, "forged vote signature must be rejected");
        assert_eq!(state.get(&validator_addr).unwrap().staked, 1_000_000);
    }

    fn empty_block(validator: &Address, height: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                height,
                timestamp: 0,
                prev_hash: Hash::ZERO,
                merkle_root: Hash::ZERO,
                validator: validator.clone(),
                public_key: KeyPair::generate().public,
                crypto_version: CryptoVersion::MlDsa,
                base_fee_per_byte: helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
                signature: Signature::from_bytes(vec![]),
            },
            transactions: vec![],
        }
    }

    #[test]
    fn execute_block_mints_the_scheduled_block_reward_to_the_validator() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(crate::genesis::TOTAL_SUPPLY_HLX * crate::genesis::NANO_PER_HLX);

        let block = empty_block(&validator, 1);
        let receipt = execute_block(&mut state, &block, None);

        let expected = crate::genesis::scheduled_block_reward(1);
        assert_eq!(receipt.block_reward_minted, expected);
        assert_eq!(state.get(&validator).unwrap().balance, expected);
        assert_eq!(state.total_issued, expected);
    }

    #[test]
    fn execute_block_mints_to_reward_address_override_not_the_block_validator() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let reward_addr = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(crate::genesis::TOTAL_SUPPLY_HLX * crate::genesis::NANO_PER_HLX);

        let block = empty_block(&validator, 1);
        execute_block(&mut state, &block, Some(&reward_addr));

        assert!(state.get(&validator).is_none(), "reward must not land on the block validator when an override is set");
        assert!(state.get(&reward_addr).unwrap().balance > 0);
    }

    #[test]
    fn execute_block_never_mints_past_the_total_supply_cap() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let cap = crate::genesis::TOTAL_SUPPLY_HLX * crate::genesis::NANO_PER_HLX;
        let mut state = ChainState::new(cap);
        // Leave only a sliver of headroom under the cap — less than a full scheduled reward.
        let sliver = 100u64;
        state.total_issued = cap - sliver;

        let block = empty_block(&validator, 1);
        let receipt = execute_block(&mut state, &block, None);

        assert_eq!(receipt.block_reward_minted, sliver, "must clamp to remaining headroom, not mint the full schedule");
        assert_eq!(state.total_issued, cap);
        assert_eq!(state.mintable_headroom(), 0);

        // A second block at a fully exhausted cap must mint nothing at all.
        let block2 = empty_block(&validator, 2);
        let receipt2 = execute_block(&mut state, &block2, None);
        assert_eq!(receipt2.block_reward_minted, 0);
        assert_eq!(state.total_issued, cap);
    }

    #[test]
    fn execute_block_reward_decays_across_halving_eras() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(crate::genesis::TOTAL_SUPPLY_HLX * crate::genesis::NANO_PER_HLX);

        let first_era_block = empty_block(&validator, 1);
        let r1 = execute_block(&mut state, &first_era_block, None).block_reward_minted;

        let second_era_block = empty_block(&validator, crate::genesis::HALVING_INTERVAL_BLOCKS);
        let r2 = execute_block(&mut state, &second_era_block, None).block_reward_minted;

        assert_eq!(r1, crate::genesis::INITIAL_BLOCK_REWARD_HLX * crate::genesis::NANO_PER_HLX);
        assert_eq!(r2, r1 / 2, "reward must halve once height crosses a halving interval boundary");
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_tx(
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
    fn delegate_rejects_target_that_never_self_staked() {
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000);

        let tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target), 500_000_000, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success);
        assert!(state.validator_pools.is_empty());
    }

    #[test]
    fn delegate_mints_shares_1to1_for_a_fresh_pool() {
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let target_kp = KeyPair::generate();
        let target = Address::from_public_key(&target_kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000);
        state.update_account(&target, |acc| acc.staked = 100_000 * 1_000_000_000);

        let tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 500_000_000, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(receipt.success, "{:?}", receipt);
        let pool = state.validator_pools.get(&target.to_string()).unwrap();
        assert_eq!(pool.total_shares, 500_000_000);
        assert_eq!(pool.total_delegated_stake, 500_000_000);
        assert_eq!(pool.commission_bps, DEFAULT_COMMISSION_BPS);
        assert_eq!(
            state.delegator_shares.get(&target.to_string()).unwrap().get(&delegator.to_string()).copied(),
            Some(500_000_000)
        );
        // Effective stake now includes the delegation.
        assert_eq!(state.effective_stake(&target), 100_000 * 1_000_000_000 + 500_000_000);
    }

    #[test]
    fn delegate_second_delegator_gets_fewer_shares_after_pool_appreciates() {
        let d1_kp = KeyPair::generate();
        let d1 = Address::from_public_key(&d1_kp.public);
        let d2_kp = KeyPair::generate();
        let d2 = Address::from_public_key(&d2_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&d1, |acc| acc.balance = 1_000_000_000_000);
        state.update_account(&d2, |acc| acc.balance = 1_000_000_000_000);
        state.update_account(&target, |acc| acc.staked = 100_000 * 1_000_000_000);

        let tx1 = signed_tx(&d1_kp, &d1, TxType::Delegate, Some(target.clone()), 1_000_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &tx1, &validator, 0, 0).success);

        // Pool appreciates 10x (simulating compounded rewards) without any new shares minted.
        state.validator_pools.get_mut(&target.to_string()).unwrap().total_delegated_stake = 10_000_000_000;

        let tx2 = signed_tx(&d2_kp, &d2, TxType::Delegate, Some(target.clone()), 1_000_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &tx2, &validator, 0, 0).success);

        let d2_shares = *state.delegator_shares.get(&target.to_string()).unwrap().get(&d2.to_string()).unwrap();
        // d2 paid the same HLX as d1 but into a pool worth 10x per share, so gets ~1/10th the shares.
        assert_eq!(d2_shares, 100_000_000, "buying into an appreciated pool must mint proportionally fewer shares");
    }

    #[test]
    fn delegate_rejects_amount_too_small_to_mint_a_share() {
        // Share-rounding / vault-inflation guard: once a pool's value-per-share exceeds 1
        // (here 10x after compounded rewards), a delegation below that per-share value floors
        // to zero shares. Without the guard the stake would still be swallowed into the pool
        // for the existing shareholders' benefit, silently losing the delegator's funds.
        let d1_kp = KeyPair::generate();
        let d1 = Address::from_public_key(&d1_kp.public);
        let victim_kp = KeyPair::generate();
        let victim = Address::from_public_key(&victim_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&d1, |acc| acc.balance = 1_000_000_000_000);
        state.update_account(&victim, |acc| acc.balance = 1_000_000_000_000);
        state.update_account(&target, |acc| acc.staked = 100_000 * 1_000_000_000);

        let tx1 = signed_tx(&d1_kp, &d1, TxType::Delegate, Some(target.clone()), 1_000_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &tx1, &validator, 0, 0).success);
        // Pool appreciates 10x (compounded rewards) → value-per-share = 10 nHLX.
        state.validator_pools.get_mut(&target.to_string()).unwrap().total_delegated_stake = 10_000_000_000;

        let victim_balance_before = state.get(&victim).unwrap().balance;
        // 5 nHLX < 10 nHLX per share → would mint floor(5 * 1e9 / 10e9) = 0 shares.
        let tx2 = signed_tx(&victim_kp, &victim, TxType::Delegate, Some(target.clone()), 5, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx2, &validator, 0, 0);

        assert!(!receipt.success, "a delegation that would mint zero shares must be rejected");
        // What this guard exists for: not one nano of the delegation is absorbed by the pool's
        // existing shareholders. The fee is charged like on any failed payable transaction — the
        // 5 nHLX it tried to delegate is what must stay put.
        assert_eq!(
            state.get(&victim).unwrap().balance,
            victim_balance_before - 10_000,
            "only the fee may leave — the delegated amount must not be absorbed"
        );
        assert_eq!(state.get(&victim).unwrap().nonce, 1, "a charged failure consumes its nonce");
        let pool = state.validator_pools.get(&target.to_string()).unwrap();
        assert_eq!(pool.total_delegated_stake, 10_000_000_000, "pool value must be untouched");
        assert_eq!(pool.total_shares, 1_000_000_000, "pool shares must be untouched");
        assert!(
            state.delegator_shares.get(&target.to_string()).and_then(|m| m.get(&victim.to_string())).is_none(),
            "no zero-share position may be recorded for the victim"
        );
    }

    #[test]
    fn transfer_without_recipient_is_rejected_without_destroying_the_amount() {
        // A `Transfer` with `to: None` used to debit `amount + fee` from the sender and credit
        // nobody, silently destroying `amount`. It must be rejected instead — the amount stays
        // put. The fee is charged, as for any payable transaction that took a block slot and
        // failed; that is the fee's job, and it is not what this test guards.
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        let tx = signed_tx(&kp, &addr, TxType::Transfer, None, 100_000, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success, "a recipient-less transfer must be rejected");
        assert_eq!(
            state.get(&addr).unwrap().balance,
            1_000_000 - 10_000,
            "only the fee may leave — the 100_000 must not be destroyed"
        );
        assert_eq!(state.get(&addr).unwrap().nonce, 1, "a charged failure consumes its nonce");
    }

    /// The DoS this whole gate exists for, executor half. A transaction that its sender could
    /// pay for but that fails anyway used to cost exactly nothing: no fee, and — worse — no
    /// nonce, so the identical signed bytes could be replayed forever. Every validator would
    /// re-verify its ~5.3 KB ML-DSA signature every time, for free.
    #[test]
    fn a_failed_transaction_pays_its_fee_and_cannot_be_replayed() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let recipient = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        // Enough for the fee, nowhere near enough for the transfer itself.
        state.update_account(&addr, |acc| acc.balance = 50_000);

        let tx = signed_tx(&kp, &addr, TxType::Transfer, Some(recipient.clone()), 1_000_000, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success, "the transfer is unaffordable and must fail");
        assert_eq!(state.get(&addr).unwrap().balance, 40_000, "the fee must be charged");
        assert_eq!(state.get(&addr).unwrap().nonce, 1, "the nonce must be consumed");
        assert_eq!(receipt.fee_to_validator, 10_000, "the receipt must report where the fee went");
        assert_eq!(state.get(&validator).unwrap().balance, 10_000, "the validator must be paid for the work");
        assert!(state.get(&recipient).is_none(), "the recipient must receive nothing");

        // The same bytes again: the nonce moved, so this is no longer replayable.
        let again = execute_transaction(&mut state, &tx, &validator, 0, 0);
        assert!(!again.success);
        assert!(again.error.unwrap().contains("nonce mismatch"), "a replay must be refused on nonce");
        assert_eq!(state.get(&addr).unwrap().balance, 40_000, "a refused replay must not charge twice");
    }

    /// The counterweight: a sender who cannot even cover the fee is charged nothing, because
    /// there is nothing to charge. That is exactly why the pool must refuse them at admission
    /// (`can_pay_fee`) — execution alone can never make this case cost anything.
    #[test]
    fn a_sender_who_cannot_cover_the_fee_is_not_charged_and_keeps_its_nonce() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        let tx = signed_tx(&kp, &addr, TxType::Transfer, Some(validator.clone()), 1_000, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success);
        assert!(receipt.error.unwrap().contains("cannot pay the fee"));
        assert_eq!(receipt.fee_burned, 0);
        assert_eq!(receipt.fee_to_validator, 0);
        assert_eq!(state.get_or_default(&addr).balance, 0);
        assert_eq!(state.get_or_default(&addr).nonce, 0);
    }

    #[test]
    fn stake_zero_amount_is_rejected() {
        // Consistency with transfer/delegate/undelegate, which all reject a zero amount: a
        // zero-value stake is a pure no-op and must not be recorded as one.
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&addr, |acc| acc.balance = 1_000_000);

        let tx = signed_tx(&kp, &addr, TxType::Stake, None, 0, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success, "a zero-amount stake must be rejected");
        assert_eq!(state.get(&addr).unwrap().staked, 0, "nothing may be staked");
        assert_eq!(
            state.get(&addr).unwrap().balance,
            1_000_000 - 10_000,
            "the fee is still charged: the transaction was payable and took a block slot"
        );
    }

    #[test]
    fn delegate_rejects_when_it_would_breach_self_bond_ratio() {
        // Target has 100_000 self-staked and already 900_000 delegated — exactly at the 10%
        // floor. Any further delegation would push it under, so it must be rejected even
        // though the target is otherwise a perfectly valid, self-staked validator.
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000);
        state.update_account(&target, |acc| acc.staked = 100_000);
        state.validator_pools.insert(
            target.to_string(),
            DelegationPool { total_shares: 900_000, total_delegated_stake: 900_000, commission_bps: DEFAULT_COMMISSION_BPS },
        );

        let tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 1, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success, "delegation must be rejected: would push self-bond ratio below the minimum");
        assert_eq!(state.validator_pools.get(&target.to_string()).unwrap().total_delegated_stake, 900_000, "pool must be untouched");
    }

    #[test]
    fn delegate_allows_up_to_exactly_the_self_bond_ratio_floor() {
        // Same setup, but the delegation lands exactly at the 10% floor (100_000 self vs
        // 900_000 delegated = 1_000_000 effective) rather than over it — must succeed, this
        // is the boundary case for `self_bond_ratio_ok`.
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000);
        state.update_account(&target, |acc| acc.staked = 100_000);

        let tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 900_000, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(receipt.success, "expected success, got: {:?}", receipt.error);
        assert_eq!(state.validator_pools.get(&target.to_string()).unwrap().total_delegated_stake, 900_000);
    }

    #[test]
    fn delegate_does_not_count_the_targets_unbonding_stake_as_self_bond() {
        // The target has 100_000 in the unbonding queue on top of 100_000 active self-stake.
        // That unbonding capital is still slashable, but it is on its way out and nothing
        // re-checks the ratio once `ClaimUnbonded` pays it out — so it must NOT buy the target
        // extra delegation headroom. With only the active 100_000 counting, a 900_000 pool is
        // already exactly at the floor and this further delegation has to be rejected; if
        // `unbonding_stake` were (wrongly) counted, 200_000 self-bond would leave room for it.
        // See `state::self_bond_ratio_ok`'s doc comment.
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000);
        state.update_account(&target, |acc| {
            acc.staked = 100_000;
            acc.unbonding_stake = 100_000;
            acc.unbonding_unlock_height = UNBONDING_PERIOD;
        });
        state.validator_pools.insert(
            target.to_string(),
            DelegationPool { total_shares: 900_000, total_delegated_stake: 900_000, commission_bps: DEFAULT_COMMISSION_BPS },
        );

        let tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 100_000, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success, "unbonding stake must not count toward the self-bond ratio");
        assert_eq!(state.validator_pools.get(&target.to_string()).unwrap().total_delegated_stake, 900_000, "pool must be untouched");
    }

    #[test]
    fn unstake_ratio_check_never_sees_an_active_unbonding_queue() {
        // Guards the invariant that makes the delegate-side decision above the ONLY place
        // `unbonding_stake` could matter for the self-bond ratio: `execute_unstake` rejects any
        // sender that already has an unbonding in progress, before the ratio check is reached.
        // So `sender.unbonding_stake` is always 0 at that check by construction, and there is
        // no "unstake twice to game the ratio" path to defend against.
        let kp = KeyPair::generate();
        let staker = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&staker, |acc| {
            acc.balance = 1_000_000_000;
            acc.staked = 500_000;
            acc.unbonding_stake = 100_000;
            acc.unbonding_unlock_height = UNBONDING_PERIOD;
        });

        let tx = signed_tx(&kp, &staker, TxType::Unstake, None, 50_000, vec![], 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);

        assert!(!receipt.success, "a second unstake while unbonding must be rejected");
        assert!(
            receipt.error.as_deref().unwrap_or_default().contains("unbonding is already in progress"),
            "expected the single-slot unbonding rejection, got: {:?}",
            receipt.error
        );
        assert_eq!(state.get(&staker).unwrap().staked, 500_000, "stake must be untouched");
    }

    #[test]
    fn undelegate_redeems_value_and_moves_to_own_unbonding_queue() {
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000);
        state.update_account(&target, |acc| acc.staked = 100_000 * 1_000_000_000);

        let delegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 500_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &delegate_tx, &validator, 0, 0).success);

        let undelegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Undelegate, Some(target.clone()), 200_000_000, vec![], 1, 10_000);
        let receipt = execute_transaction(&mut state, &undelegate_tx, &validator, 10, 0);
        assert!(receipt.success, "{:?}", receipt);

        let acc = state.get(&delegator).unwrap();
        assert_eq!(acc.unbonding_stake, 200_000_000);
        assert_eq!(acc.unbonding_unlock_height, 10 + state::UNBONDING_PERIOD);

        let pool = state.validator_pools.get(&target.to_string()).unwrap();
        assert_eq!(pool.total_delegated_stake, 300_000_000);
        let remaining_shares = *state.delegator_shares.get(&target.to_string()).unwrap().get(&delegator.to_string()).unwrap();
        assert_eq!(remaining_shares, 300_000_000);
    }

    #[test]
    fn undelegate_rejects_amount_above_owned_value() {
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000);
        state.update_account(&target, |acc| acc.staked = 100_000 * 1_000_000_000);

        let delegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 500_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &delegate_tx, &validator, 0, 0).success);

        let undelegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Undelegate, Some(target.clone()), 999_999_999, vec![], 1, 10_000);
        let receipt = execute_transaction(&mut state, &undelegate_tx, &validator, 10, 0);
        assert!(!receipt.success);
    }

    #[test]
    fn undelegate_rejects_while_unbonding_already_in_progress() {
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000);
        state.update_account(&target, |acc| acc.staked = 100_000 * 1_000_000_000);

        let delegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 500_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &delegate_tx, &validator, 0, 0).success);

        let u1 = signed_tx(&delegator_kp, &delegator, TxType::Undelegate, Some(target.clone()), 100_000_000, vec![], 1, 10_000);
        assert!(execute_transaction(&mut state, &u1, &validator, 10, 0).success);

        let u2 = signed_tx(&delegator_kp, &delegator, TxType::Undelegate, Some(target.clone()), 100_000_000, vec![], 2, 10_000);
        let receipt = execute_transaction(&mut state, &u2, &validator, 11, 0);
        assert!(!receipt.success, "a second concurrent unbonding must be rejected, same as self-unstake");
    }

    #[test]
    fn set_commission_rejects_above_max() {
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&from, |acc| acc.balance = 1_000_000);

        let over_max = MAX_COMMISSION_BPS + 1;
        let tx = signed_tx(&kp, &from, TxType::SetCommission, None, 0, over_max.to_le_bytes().to_vec(), 0, 10_000);
        let receipt = execute_transaction(&mut state, &tx, &validator, 0, 0);
        assert!(!receipt.success);
    }

    #[test]
    fn set_commission_applies_before_any_delegation_and_is_read_back() {
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&from, |acc| acc.balance = 1_000_000);

        let tx = signed_tx(&kp, &from, TxType::SetCommission, None, 0, 2_500u16.to_le_bytes().to_vec(), 0, 10_000);
        assert!(execute_transaction(&mut state, &tx, &validator, 0, 0).success);

        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000);
        state.update_account(&from, |acc| acc.staked += 100_000 * 1_000_000_000);

        let delegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(from.clone()), 500_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &delegate_tx, &validator, 0, 0).success);

        assert_eq!(state.validator_pools.get(&from.to_string()).unwrap().commission_bps, 2_500);
    }

    #[test]
    fn credit_validator_reward_splits_by_stake_ratio_and_commission() {
        let target_kp = KeyPair::generate();
        let target = Address::from_public_key(&target_kp.public);
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);

        let fee_validator = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(crate::genesis::TOTAL_SUPPLY_HLX * crate::genesis::NANO_PER_HLX);
        // Self-stake 100, delegated 300 -> 25%/75% split of the reward before commission.
        state.update_account(&target, |acc| acc.staked = 100 * 1_000_000_000);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000_000);
        let delegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 300 * 1_000_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &delegate_tx, &fee_validator, 0, 0).success);
        // Commission 10% (default) on the delegated 75% share.
        let pool_before = state.validator_pools.get(&target.to_string()).unwrap().total_delegated_stake;
        let validator_balance_before = state.get(&target).unwrap().balance;

        credit_validator_reward(&mut state, &target, 1_000_000_000);

        let self_share = 250_000_000u64; // 25% of 1e9
        let delegated_share = 750_000_000u64; // 75%
        let commission = delegated_share / 10; // 10% default commission
        let pool_gain = delegated_share - commission;

        assert_eq!(
            state.get(&target).unwrap().balance,
            validator_balance_before + self_share + commission
        );
        assert_eq!(
            state.validator_pools.get(&target.to_string()).unwrap().total_delegated_stake,
            pool_before + pool_gain
        );
    }

    #[test]
    fn credit_validator_reward_is_unchanged_when_no_pool_exists() {
        let validator = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(crate::genesis::TOTAL_SUPPLY_HLX * crate::genesis::NANO_PER_HLX);
        state.update_account(&validator, |acc| acc.staked = 100_000 * 1_000_000_000);

        credit_validator_reward(&mut state, &validator, 1_000_000_000);

        assert_eq!(state.get(&validator).unwrap().balance, 1_000_000_000, "100% must go to the validator when it has no delegators");
    }

    #[test]
    fn slash_reduces_delegation_pool_proportionally() {
        let target_kp = KeyPair::generate();
        let target = Address::from_public_key(&target_kp.public);
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);

        let fee_validator = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(0);
        state.update_account(&target, |acc| acc.staked = 100_000 * 1_000_000_000);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000_000);
        let delegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 100_000_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &delegate_tx, &fee_validator, 0, 0).success);

        let shares_before = *state.delegator_shares.get(&target.to_string()).unwrap().get(&delegator.to_string()).unwrap();

        state.slash(&target, 500); // 5%, same fraction as real double-sign slashing

        let pool = state.validator_pools.get(&target.to_string()).unwrap();
        assert_eq!(pool.total_delegated_stake, 95_000_000_000, "pool value must drop by exactly 5%");
        let shares_after = *state.delegator_shares.get(&target.to_string()).unwrap().get(&delegator.to_string()).unwrap();
        assert_eq!(shares_after, shares_before, "shares outstanding must not change — only the pool's value per share does");
        // Self-stake also slashed 5%, exactly as before delegation existed.
        assert_eq!(state.get(&target).unwrap().staked, 100_000 * 1_000_000_000 * 95 / 100);
    }

    #[test]
    fn undelegating_before_the_slash_lands_does_not_escape_it() {
        // The evasion CTO Backlog #84 was about: double-sign evidence travels as a transaction,
        // so it necessarily lands after the misbehavior it proves. A delegator watching for it
        // undelegates first, moving their capital out of the pool the slash reaches. Their funds
        // are still inside the unbonding period, so they must still be slashed — this is the
        // delegated-stake counterpart of the rule that already stopped a validator from
        // double-signing and immediately queueing an unstake to escape punishment.
        let target = Address::from_public_key(&KeyPair::generate().public);
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let fee_validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&target, |acc| acc.staked = 100_000 * 1_000_000_000);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000_000);

        let delegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 100_000_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &delegate_tx, &fee_validator, 0, 0).success);

        // Target double-signs here. Evidence is in flight but has not been executed yet — the
        // delegator (or anyone watching the mempool) gets to act first.
        let undelegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Undelegate, Some(target.clone()), 100_000_000_000, vec![], 1, 10_000);
        assert!(execute_transaction(&mut state, &undelegate_tx, &fee_validator, 0, 0).success);
        assert_eq!(
            state.get(&delegator).unwrap().unbonding_source.as_deref(),
            Some(target.to_string().as_str()),
            "the unbonding must remember the pool it came out of"
        );

        // Now the evidence lands and the 5% double-sign slash is applied to the target.
        let burned = state.slash(&target, 500);

        assert_eq!(
            state.get(&delegator).unwrap().unbonding_stake,
            95_000_000_000,
            "the escaped delegation must still take the full 5% slash"
        );
        assert_eq!(
            burned,
            5_000_000_000 + 100_000 * 1_000_000_000 * 5 / 100,
            "burn must cover the delegator's 5% plus the validator's own 5%"
        );
    }

    #[test]
    fn slash_does_not_reach_stake_unbonding_out_of_a_different_validators_pool() {
        // The mirror image of the test above, and the reason `unbonding_source` is an
        // `Option<validator>` rather than a bool: a validator may itself be someone else's
        // delegator. Here `slashed` had delegated to `other` and undelegated; that capital sits
        // in `slashed`'s unbonding queue but was backing `other`, not `slashed`. Slashing
        // `slashed` for its own double-sign must leave it alone — it is `other`'s pool capital
        // and only `other`'s misbehavior can reach it.
        let slashed_kp = KeyPair::generate();
        let slashed = Address::from_public_key(&slashed_kp.public);
        let other = Address::from_public_key(&KeyPair::generate().public);
        let fee_validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&other, |acc| acc.staked = 100_000 * 1_000_000_000);
        state.update_account(&slashed, |acc| {
            acc.staked = 100_000 * 1_000_000_000;
            acc.balance = 1_000_000_000_000;
        });

        let delegate_tx = signed_tx(&slashed_kp, &slashed, TxType::Delegate, Some(other.clone()), 100_000_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &delegate_tx, &fee_validator, 0, 0).success);
        let undelegate_tx = signed_tx(&slashed_kp, &slashed, TxType::Undelegate, Some(other.clone()), 100_000_000_000, vec![], 1, 10_000);
        assert!(execute_transaction(&mut state, &undelegate_tx, &fee_validator, 0, 0).success);

        state.slash(&slashed, 500);

        assert_eq!(
            state.get(&slashed).unwrap().unbonding_stake,
            100_000_000_000,
            "capital unbonding out of another validator's pool must not be slashed here"
        );
        assert_eq!(
            state.get(&slashed).unwrap().staked,
            100_000 * 1_000_000_000 * 95 / 100,
            "its own self-bond must still take the 5%"
        );
    }

    #[test]
    fn claiming_unbonded_delegation_clears_its_source_validator() {
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let target = Address::from_public_key(&KeyPair::generate().public);
        let fee_validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&target, |acc| acc.staked = 100_000 * 1_000_000_000);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000_000);

        let delegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(target.clone()), 100_000_000_000, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &delegate_tx, &fee_validator, 0, 0).success);
        let undelegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Undelegate, Some(target.clone()), 100_000_000_000, vec![], 1, 10_000);
        assert!(execute_transaction(&mut state, &undelegate_tx, &fee_validator, 0, 0).success);

        let claim_tx = signed_tx(&delegator_kp, &delegator, TxType::ClaimUnbonded, None, 0, vec![], 2, 10_000);
        let receipt = execute_transaction(&mut state, &claim_tx, &fee_validator, UNBONDING_PERIOD, 0);
        assert!(receipt.success, "expected success, got: {:?}", receipt.error);

        let acc = state.get(&delegator).unwrap();
        assert_eq!(acc.unbonding_stake, 0);
        assert_eq!(acc.unbonding_source, None, "an empty queue must not still name a validator");

        // Once claimed, the funds are liquid and beyond every slashing window — a later slash of
        // the validator they used to back must not touch them.
        let balance_before = acc.balance;
        state.slash(&target, 500);
        assert_eq!(
            state.get(&delegator).unwrap().balance,
            balance_before,
            "claimed funds are out of reach of the source validator's slash"
        );
    }

    /// Two validators with self-stake, and `delegator` funded and already delegated `amount`
    /// to `src`. Returns (src, dst, delegator keypair, delegator address, fee validator).
    fn redelegation_fixture(amount: u64) -> (Address, Address, KeyPair, Address, Address, ChainState) {
        let src = Address::from_public_key(&KeyPair::generate().public);
        let dst = Address::from_public_key(&KeyPair::generate().public);
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);
        let fee_validator = Address::from_public_key(&KeyPair::generate().public);

        let mut state = ChainState::new(0);
        state.update_account(&src, |acc| acc.staked = 100_000 * 1_000_000_000);
        state.update_account(&dst, |acc| acc.staked = 100_000 * 1_000_000_000);
        state.update_account(&delegator, |acc| acc.balance = 1_000_000_000_000);

        let delegate_tx = signed_tx(&delegator_kp, &delegator, TxType::Delegate, Some(src.clone()), amount, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &delegate_tx, &fee_validator, 0, 0).success);

        (src, dst, delegator_kp, delegator, fee_validator, state)
    }

    fn redelegate_tx(kp: &KeyPair, from: &Address, src: &Address, dst: &Address, amount: u64, nonce: u64) -> Transaction {
        signed_tx(kp, from, TxType::Redelegate, Some(dst.clone()), amount, src.to_string().into_bytes(), nonce, 10_000)
    }

    #[test]
    fn redelegate_moves_stake_between_pools_without_unbonding() {
        let amount = 100_000_000_000;
        let (src, dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);

        let tx = redelegate_tx(&kp, &delegator, &src, &dst, amount, 1);
        let receipt = execute_transaction(&mut state, &tx, &fee_validator, 0, 0);
        assert!(receipt.success, "expected success, got: {:?}", receipt.error);

        assert_eq!(state.validator_pools.get(&src.to_string()).unwrap().total_delegated_stake, 0, "source pool must be drained");
        assert_eq!(state.validator_pools.get(&dst.to_string()).unwrap().total_delegated_stake, amount, "destination pool must hold it");
        assert_eq!(
            state.get(&delegator).unwrap().unbonding_stake,
            0,
            "redelegation must not route through the unbonding queue at all"
        );
        assert!(
            state.delegator_shares.get(&dst.to_string()).unwrap().contains_key(&delegator.to_string()),
            "delegator must hold shares in the destination pool"
        );
    }

    #[test]
    fn redelegating_before_the_slash_lands_does_not_escape_it() {
        // The whole reason redelegation needs its own bookkeeping. Without it this would be a
        // strictly better escape than undelegating: instant, and the stake keeps earning at the
        // destination the entire time.
        let amount = 100_000_000_000;
        let (src, dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);

        // src double-signs; the delegator front-runs the evidence transaction.
        let tx = redelegate_tx(&kp, &delegator, &src, &dst, amount, 1);
        assert!(execute_transaction(&mut state, &tx, &fee_validator, 0, 0).success);

        state.slash(&src, 500);

        let shares = *state.delegator_shares.get(&dst.to_string()).unwrap().get(&delegator.to_string()).unwrap();
        let dst_pool = state.validator_pools.get(&dst.to_string()).unwrap();
        let my_value = (shares as u128 * dst_pool.total_delegated_stake as u128 / dst_pool.total_shares as u128) as u64;
        assert_eq!(my_value, amount * 95 / 100, "the redelegated stake must still take src's 5% slash");
    }

    #[test]
    fn slashing_a_redelegation_source_spares_the_destinations_other_delegators() {
        // The redelegator alone chose to back `src`, so the loss must come out of their shares
        // at `dst` — not out of `dst`'s pool value, which every other delegator there shares.
        let amount = 100_000_000_000;
        let (src, dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);

        let bystander_kp = KeyPair::generate();
        let bystander = Address::from_public_key(&bystander_kp.public);
        state.update_account(&bystander, |acc| acc.balance = 1_000_000_000_000);
        let bystander_delegate = signed_tx(&bystander_kp, &bystander, TxType::Delegate, Some(dst.clone()), amount, vec![], 0, 10_000);
        assert!(execute_transaction(&mut state, &bystander_delegate, &fee_validator, 0, 0).success);

        let tx = redelegate_tx(&kp, &delegator, &src, &dst, amount, 1);
        assert!(execute_transaction(&mut state, &tx, &fee_validator, 0, 0).success);

        state.slash(&src, 500);

        let pool = state.validator_pools.get(&dst.to_string()).unwrap();
        let value_of = |addr: &Address| {
            let shares = *state.delegator_shares.get(&dst.to_string()).unwrap().get(&addr.to_string()).unwrap();
            (shares as u128 * pool.total_delegated_stake as u128 / pool.total_shares as u128) as u64
        };
        assert_eq!(value_of(&bystander), amount, "the bystander never backed src and must lose nothing");
        assert_eq!(value_of(&delegator), amount * 95 / 100, "the redelegator takes the full loss");
    }

    #[test]
    fn slashing_the_redelegation_destination_does_not_reach_the_source() {
        // The mirror case: `dst` misbehaving hits its pool (including the freshly arrived
        // stake, which is genuinely backing dst now), but must not touch `src`'s books.
        let amount = 100_000_000_000;
        let (src, dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);

        let tx = redelegate_tx(&kp, &delegator, &src, &dst, amount, 1);
        assert!(execute_transaction(&mut state, &tx, &fee_validator, 0, 0).success);

        state.slash(&dst, 500);

        assert_eq!(
            state.validator_pools.get(&dst.to_string()).unwrap().total_delegated_stake,
            amount * 95 / 100,
            "dst's own pool slash applies normally to stake now backing it"
        );
        assert_eq!(
            state.redelegations.get(&src.to_string()).unwrap()[0].amount,
            amount,
            "src's outstanding claim is unaffected by dst's misbehavior"
        );
    }

    #[test]
    fn redelegate_rejects_hopping_while_a_window_is_still_open() {
        let amount = 100_000_000_000;
        let (src, dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);
        let third = Address::from_public_key(&KeyPair::generate().public);
        state.update_account(&third, |acc| acc.staked = 100_000 * 1_000_000_000);

        let hop1 = redelegate_tx(&kp, &delegator, &src, &dst, amount, 1);
        assert!(execute_transaction(&mut state, &hop1, &fee_validator, 0, 0).success);

        // dst -> third, while src's claim on this stake is still open. Rejected: each further
        // hop would have to keep every earlier source's claim alive on the same capital.
        let hop2 = redelegate_tx(&kp, &delegator, &dst, &third, amount, 2);
        let receipt = execute_transaction(&mut state, &hop2, &fee_validator, 0, 0);
        assert!(!receipt.success, "A->B->C hopping inside the window must be rejected");
        assert!(
            receipt.error.as_deref().unwrap_or_default().contains("still inside a redelegation window"),
            "expected the hop rejection, got: {:?}",
            receipt.error
        );
    }

    #[test]
    fn redelegate_is_allowed_again_once_the_window_has_expired() {
        let amount = 100_000_000_000;
        let (src, dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);
        let third = Address::from_public_key(&KeyPair::generate().public);
        state.update_account(&third, |acc| acc.staked = 100_000 * 1_000_000_000);

        let hop1 = redelegate_tx(&kp, &delegator, &src, &dst, amount, 1);
        assert!(execute_transaction(&mut state, &hop1, &fee_validator, 0, 0).success);

        state.prune_expired_redelegations(UNBONDING_PERIOD);
        assert!(state.redelegations.is_empty(), "the expired entry must be pruned");

        let hop2 = redelegate_tx(&kp, &delegator, &dst, &third, amount, 2);
        let receipt = execute_transaction(&mut state, &hop2, &fee_validator, UNBONDING_PERIOD, 0);
        assert!(receipt.success, "expected success once the window closed, got: {:?}", receipt.error);
    }

    #[test]
    fn pruned_redelegation_is_beyond_the_sources_reach() {
        let amount = 100_000_000_000;
        let (src, dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);

        let tx = redelegate_tx(&kp, &delegator, &src, &dst, amount, 1);
        assert!(execute_transaction(&mut state, &tx, &fee_validator, 0, 0).success);
        state.prune_expired_redelegations(UNBONDING_PERIOD);

        state.slash(&src, 500);

        assert_eq!(
            state.validator_pools.get(&dst.to_string()).unwrap().total_delegated_stake,
            amount,
            "once the window closes, src's slash can no longer reach the moved stake"
        );
    }

    #[test]
    fn redelegate_rejects_same_source_and_destination() {
        let amount = 100_000_000_000;
        let (src, _dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);

        let tx = redelegate_tx(&kp, &delegator, &src, &src, amount, 1);
        let receipt = execute_transaction(&mut state, &tx, &fee_validator, 0, 0);
        assert!(!receipt.success, "redelegating to the same validator must be rejected");
    }

    #[test]
    fn redelegate_rejects_amount_above_owned_value() {
        let amount = 100_000_000_000;
        let (src, dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);

        let tx = redelegate_tx(&kp, &delegator, &src, &dst, amount * 2, 1);
        let receipt = execute_transaction(&mut state, &tx, &fee_validator, 0, 0);
        assert!(!receipt.success, "cannot redelegate more than is delegated");
        assert!(state.redelegations.is_empty(), "a rejected redelegation must leave no claim behind");
    }

    #[test]
    fn redelegate_rejects_destination_that_never_self_staked() {
        let amount = 100_000_000_000;
        let (src, _dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);
        let stranger = Address::from_public_key(&KeyPair::generate().public);

        let tx = redelegate_tx(&kp, &delegator, &src, &stranger, amount, 1);
        let receipt = execute_transaction(&mut state, &tx, &fee_validator, 0, 0);
        assert!(!receipt.success, "destination must be a real validator identity");
    }

    #[test]
    fn redelegate_rejects_breaching_the_destinations_self_bond_ratio() {
        let amount = 100_000_000_000;
        let (src, dst, kp, delegator, fee_validator, mut state) = redelegation_fixture(amount);
        // Leave dst with only enough self-stake to back a fraction of the incoming amount.
        state.update_account(&dst, |acc| acc.staked = 1_000_000);

        let tx = redelegate_tx(&kp, &delegator, &src, &dst, amount, 1);
        let receipt = execute_transaction(&mut state, &tx, &fee_validator, 0, 0);
        assert!(!receipt.success, "destination's self-bond ratio must gate redelegation in too");
        assert_eq!(
            state.validator_pools.get(&src.to_string()).unwrap().total_delegated_stake,
            amount,
            "a rejected redelegation must leave the source pool untouched"
        );
    }

    #[test]
    fn stakers_counts_delegated_stake_toward_validator_set_eligibility() {
        let target_kp = KeyPair::generate();
        let target = Address::from_public_key(&target_kp.public);
        let delegator_kp = KeyPair::generate();
        let delegator = Address::from_public_key(&delegator_kp.public);

        let fee_validator = Address::from_public_key(&KeyPair::generate().public);
        let mut state = ChainState::new(0);
        state.governance_params.min_validator_stake = 100_000 * 1_000_000_000;
        // Below the minimum on self-stake alone, but within the self-bond ratio floor
        // (15_000 self-staked clears MIN_SELF_BOND_RATIO_BPS against up to 135_000 delegated).
        state.update_account(&target, |acc| acc.staked = 15_000 * 1_000_000_000);
        state.update_account(&delegator, |acc| acc.balance = 200_000 * 1_000_000_000_000);

        assert!(state.stakers().is_empty(), "self-stake alone is below the minimum");

        let delegate_tx = signed_tx(
            &delegator_kp, &delegator, TxType::Delegate, Some(target.clone()),
            90_000 * 1_000_000_000, vec![], 0, 10_000,
        );
        assert!(execute_transaction(&mut state, &delegate_tx, &fee_validator, 0, 0).success);

        let stakers = state.stakers();
        assert_eq!(stakers.len(), 1, "effective (self + delegated) stake now clears the minimum");
        assert_eq!(stakers[0].0, target);
    }
}
