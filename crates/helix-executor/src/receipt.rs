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
}

impl BlockReceipt {
    pub fn successful_txs(&self) -> usize {
        self.tx_receipts.iter().filter(|r| r.success).count()
    }

    pub fn failed_txs(&self) -> usize {
        self.tx_receipts.iter().filter(|r| !r.success).count()
    }
}
