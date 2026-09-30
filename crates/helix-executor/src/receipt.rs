use helix_crypto::Hash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: String,
    pub success: bool,
    pub fee_burned: u64,
    pub fee_to_validator: u64,
    pub error: Option<String>,
}

impl Receipt {
    pub fn success(tx_hash: Hash, fee_burned: u64, fee_to_validator: u64) -> Self {
        Receipt {
            tx_hash: tx_hash.to_hex(),
            success: true,
            fee_burned,
            fee_to_validator,
            error: None,
        }
    }

    pub fn failure(tx_hash: Hash, reason: &str, fee_burned: u64, fee_to_validator: u64) -> Self {
        Receipt {
            tx_hash: tx_hash.to_hex(),
            success: false,
            fee_burned,
            fee_to_validator,
            error: Some(reason.to_string()),
        }
    }
}

/// Which part of a block's effect a [`BalanceChange`] is (#260).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BalanceChangeKind {
    /// What a transaction did to an account itself: its fee, the value it moved, a stake, a claim.
    #[default]
    Transaction,
    /// A validator's income — fee tips, the block reward, commission — paid to its payout
    /// address. Only its own share: what its delegators earn goes into the pool, which is not a
    /// liquid balance.
    Reward,
    /// A transfer a smart contract made while the transaction ran, out of the contract's balance
    /// and into the recipient's.
    Contract,
}

/// One liquid balance moving in a block (#260).
///
/// A block's changes, summed per account, are exactly how much each liquid balance moved in it —
/// `execute_block` checks that in debug builds, and it is what lets a reader account for every
/// nano-HLX, including what a contract paid out and what a validator earned, neither of which is
/// a transaction to the receiving address. Not consensus state: derived from execution, like a
/// receipt, and kept by each node for the blocks it executes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceChange {
    /// Position of the transaction in its block; `None` for the block itself (its reward).
    pub tx_index: Option<u32>,
    /// The account whose liquid balance moved.
    pub account: String,
    pub kind: BalanceChangeKind,
    /// Signed change in nano-HLX. One entry per account, transaction and kind: several moves of
    /// the same balance within one transaction are added up.
    pub delta: i128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockReceipt {
    pub block_hash: String,
    pub height: u64,
    pub tx_receipts: Vec<Receipt>,
    pub total_burned: u64,
    pub validator_reward: u64,
    /// New HLX minted for this block via the halving block-reward schedule (see
    /// `genesis::scheduled_block_reward`), on top of `validator_reward`'s fee share. 0 once
    /// the schedule has decayed to nothing or the `TOTAL_SUPPLY_HLX` cap is reached.
    pub block_reward_minted: u64,
    /// Validators downtime-jailed by this block's `record_block_participation` call — the
    /// caller (`helix-node`'s `apply_finalized_block`) fast-jails them out of the live
    /// `BftEngine::validator_set` immediately, the same way it already does for
    /// `SubmitDoubleSignEvidence`, rather than waiting for the next epoch rotation.
    pub newly_jailed: Vec<helix_crypto::Address>,
    /// `Some` only on an epoch boundary, carrying the freshly rotated signing set as
    /// `(address, effective_stake, probationary)` that `execute_block` just committed to
    /// `ChainState::active_validators` / `probationary_validators`. The node builds the consensus
    /// `ValidatorSet` from this instead of rotating on its own, so that block execution stays the
    /// single place that decides who validates. `probationary = true` entries sign but carry no
    /// voting power and take no proposer turn (backlog #132) — see
    /// `ChainState::rotate_active_validators` and `helix_consensus::Validator::probationary`.
    pub rotated_validators: Option<Vec<(helix_crypto::Address, u64, bool)>>,
    /// Every liquid balance this block moved, and why (#260).
    pub balance_changes: Vec<BalanceChange>,
}

impl BlockReceipt {
    pub fn successful_txs(&self) -> usize {
        self.tx_receipts.iter().filter(|r| r.success).count()
    }

    pub fn failed_txs(&self) -> usize {
        self.tx_receipts.iter().filter(|r| !r.success).count()
    }
}
