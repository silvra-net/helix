use helix_crypto::{Address, PublicKey};

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

/// Pre-funded genesis wallets beyond the validator itself: (address, balance_HLX).
/// Currently empty — the validator's own address receives the entire remaining
/// supply directly (see `GenesisConfig::devnet`). No separate external wallet is
/// pre-funded at genesis anymore (decision 2026-07-05: funds stay with the validator
/// until explicitly transferred out on request, instead of auto-flowing to a
/// personal wallet at genesis).
const GENESIS_PREFUND: &[(&str, u64)] = &[];

pub struct GenesisConfig {
    pub validator: Address,
    pub allocations: Vec<(Address, u64)>, // (address, nano-HLX balance)
    /// The network's personhood-issuing authority, if configured — see
    /// `ChainState::personhood_authority`'s doc comment. `None` means `ProvePersonhood` stays
    /// disabled until an operator explicitly sets one; there is deliberately no default here
    /// (auto-generating a keypair would produce an authority nobody actually holds the
    /// private key for, which would just brick the feature a different way).
    pub personhood_authority: Option<PublicKey>,
}

impl GenesisConfig {
    pub fn devnet(validator: Address) -> Self {
        Self::devnet_with_personhood_authority(validator, None)
    }

    pub fn devnet_with_personhood_authority(
        validator: Address,
        personhood_authority: Option<PublicKey>,
    ) -> Self {
        let mut allocations = Vec::new();
        for (addr_str, hlx) in GENESIS_PREFUND {
            if let Ok(addr) = Address::from_str(addr_str) {
                allocations.push((addr, hlx * NANO_PER_HLX));
            }
        }
        // Validator bekommt die komplette restliche Supply (nach Stake) als liquide
        // Balance auf der eigenen Adresse — kein separater externer Admin-Wallet-Fluss
        // mehr (Entscheidung Moris 2026-07-05).
        allocations.push((validator.clone(), (TOTAL_SUPPLY_HLX - VALIDATOR_GENESIS_STAKE_HLX) * NANO_PER_HLX));
        GenesisConfig { allocations, validator, personhood_authority }
    }

    /// Build the initial ChainState.
    /// - Total supply = 100 M HLX (hard cap)
    /// - Validator     = 1 M HLX staked + 99 M HLX liquide Balance, alles auf derselben Adresse
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

        state.personhood_authority = self.personhood_authority.clone();

        state
    }
}
