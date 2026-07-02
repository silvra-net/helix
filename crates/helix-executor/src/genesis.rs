use helix_crypto::Address;

use crate::state::ChainState;

pub const NANO_PER_HLX: u64 = 1_000_000_000;

/// Hard cap — never more than 100 M HLX will ever exist.
/// Supply can only decrease over time as 50 % of every fee is burned.
pub const TOTAL_SUPPLY_HLX: u64 = 100_000_000;

/// Minimum stake required to enter the active validator set.
/// 100 k HLX = 0.1 % of total supply — enough skin-in-the-game for slashing to hurt,
/// low enough that legitimate node operators can participate.
pub const MIN_VALIDATOR_STAKE: u64 = 100_000 * NANO_PER_HLX;

/// Validator pre-stake at genesis.  The validator needs this staked from block 0 so it
/// survives the first epoch rotation (which filters by MIN_VALIDATOR_STAKE).
const VALIDATOR_GENESIS_STAKE_HLX: u64 = 1_000_000; // 1 M HLX

/// Pre-funded genesis wallets: (address, balance_HLX, staked_HLX).
const GENESIS_PREFUND: &[(&str, u64, u64)] = &[
    // Moris — admin wallet, remaining supply after validator stake
    (
        "hlxmtJXFwsfj1VE4rxseZaS3JvN9dC4vHR7z",
        TOTAL_SUPPLY_HLX - VALIDATOR_GENESIS_STAKE_HLX, // 99 M HLX
        0,
    ),
];

pub struct GenesisConfig {
    pub validator: Address,
    pub allocations: Vec<(Address, u64)>, // (address, nano-HLX balance)
}

impl GenesisConfig {
    pub fn devnet(validator: Address) -> Self {
        let mut allocations = Vec::new();
        for (addr_str, hlx, _) in GENESIS_PREFUND {
            if let Ok(addr) = Address::from_str(addr_str) {
                allocations.push((addr, hlx * NANO_PER_HLX));
            }
        }
        GenesisConfig { allocations, validator }
    }

    /// Build the initial ChainState.
    /// - Total supply  = 100 M HLX (hard cap)
    /// - Validator     = 1 M HLX staked at genesis (no spendable balance — earns via fees)
    /// - Moris         = 99 M HLX spendable balance
    /// circulating_supply = total_supply − total_burned (starts at 100 M, decreases with burns)
    pub fn build_state(&self) -> ChainState {
        let total = TOTAL_SUPPLY_HLX * NANO_PER_HLX;
        let mut state = ChainState::new(total);

        // Spendable balances
        for (address, nano) in &self.allocations {
            state.set_balance(address, *nano);
        }

        // Validator genesis stake — staked directly so it survives epoch 1 rotation
        state.set_validator_stake(&self.validator, VALIDATOR_GENESIS_STAKE_HLX * NANO_PER_HLX);

        state
    }
}
