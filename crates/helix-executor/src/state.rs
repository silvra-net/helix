use std::collections::HashMap;

use helix_crypto::Address;
use serde::{Deserialize, Serialize};

/// Per-account ledger state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub address: String,
    /// Liquid balance in nano-HLX (1 HLX = 1_000_000_000 nano-HLX)
    pub balance: u64,
    /// Locked in PoS stake
    pub staked: u64,
    /// Next expected nonce — prevents replay attacks
    pub nonce: u64,
}

impl AccountState {
    pub fn new(address: &Address) -> Self {
        AccountState {
            address: address.to_string(),
            balance: 0,
            staked: 0,
            nonce: 0,
        }
    }

    pub fn balance_hlx(&self) -> f64 {
        self.balance as f64 / 1_000_000_000.0
    }

    pub fn staked_hlx(&self) -> f64 {
        self.staked as f64 / 1_000_000_000.0
    }
}

/// Full world state of the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// address string → account state
    pub accounts: HashMap<String, AccountState>,
    /// Total HLX supply in nano-HLX (fixed at genesis)
    pub total_supply: u64,
    /// Cumulative burned fees — reduces circulating supply
    pub total_burned: u64,
}

impl ChainState {
    pub fn new(total_supply: u64) -> Self {
        ChainState {
            accounts: HashMap::new(),
            total_supply,
            total_burned: 0,
        }
    }

    pub fn get(&self, address: &Address) -> Option<&AccountState> {
        self.accounts.get(&address.to_string())
    }

    pub fn get_or_default(&self, address: &Address) -> AccountState {
        self.accounts
            .get(&address.to_string())
            .cloned()
            .unwrap_or_else(|| AccountState::new(address))
    }

    pub fn update_account<F>(&mut self, address: &Address, f: F)
    where
        F: FnOnce(&mut AccountState),
    {
        let key = address.to_string();
        let acc = self
            .accounts
            .entry(key)
            .or_insert_with(|| AccountState::new(address));
        f(acc);
    }

    pub fn set_balance(&mut self, address: &Address, balance: u64) {
        self.update_account(address, |acc| acc.balance = balance);
    }

    pub fn circulating_supply(&self) -> u64 {
        self.total_supply.saturating_sub(self.total_burned)
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }
}
