use helix_crypto::Address;

use crate::state::ChainState;

/// Total HLX supply: 500 million (like a modern chain, not Bitcoin's 21M scarcity)
pub const TOTAL_SUPPLY_HLX: u64 = 500_000_000;
pub const NANO_PER_HLX: u64 = 1_000_000_000;
pub const TOTAL_SUPPLY_NANO: u64 = TOTAL_SUPPLY_HLX * NANO_PER_HLX;

/// Genesis allocation for the initial validator (devnet)
pub const GENESIS_VALIDATOR_ALLOCATION_HLX: u64 = 100_000_000; // 100M HLX

pub struct GenesisConfig {
    pub validator: Address,
    pub allocations: Vec<(Address, u64)>, // (address, amount in nano-HLX)
}

impl GenesisConfig {
    pub fn devnet(validator: Address) -> Self {
        let genesis_amount = GENESIS_VALIDATOR_ALLOCATION_HLX * NANO_PER_HLX;
        GenesisConfig {
            allocations: vec![(validator.clone(), genesis_amount)],
            validator,
        }
    }

    /// Build the initial ChainState from this genesis config
    pub fn build_state(&self) -> ChainState {
        let mut state = ChainState::new(TOTAL_SUPPLY_NANO);

        for (address, amount) in &self.allocations {
            state.set_balance(address, *amount);
        }

        state
    }
}
