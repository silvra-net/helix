use helix_crypto::{Address, PublicKey};

use crate::state::ChainState;

pub const NANO_PER_HLX: u64 = 1_000_000_000;

/// Hard cap — never more than 100 M HLX will ever exist, full stop. Unlike a chain that
/// dumps its entire supply into circulation at genesis, this is an asymptotic ceiling: see
/// `scheduled_block_reward` and `ChainState::total_issued`. Supply also only ever decreases
/// relative to whatever has been issued, as 50 % of every fee is burned.
pub const TOTAL_SUPPLY_HLX: u64 = 100_000_000;

/// Minimum stake required to enter the active validator set.
/// 100 k HLX = 0.1 % of total supply — enough skin-in-the-game for slashing to hurt,
/// low enough that legitimate node operators can participate.
pub const MIN_VALIDATOR_STAKE: u64 = 100_000 * NANO_PER_HLX;

/// Validator pre-stake at genesis.  The validator needs this staked from block 0 so it
/// survives the first epoch rotation (which filters by MIN_VALIDATOR_STAKE). This is the
/// ONLY genesis allocation — see `GENESIS_PREFUND`'s doc comment for why there is
/// deliberately no liquid pre-mine on top of it.
const VALIDATOR_GENESIS_STAKE_HLX: u64 = 1_000_000; // 1 M HLX

/// Pre-funded genesis wallets beyond the validator's bootstrap stake: (address, balance_HLX).
/// Empty by design (decision 2026-07-15, superseding the 2026-07-05 decision to liquid-dump
/// the entire remaining ~99 M HLX supply to the validator at genesis): a chain that hands its
/// founder the whole supply on day one isn't meaningfully different from a pre-mined coin,
/// regardless of what the whitepaper says about caps. The 99 M HLX difference between
/// `TOTAL_SUPPLY_HLX` and the genesis stake is instead released gradually, earned by
/// whoever actually produces blocks, via `scheduled_block_reward` — the same shape as
/// Bitcoin's coinbase subsidy. Nothing stops an operator from prefunding specific wallets
/// here for legitimate bootstrap needs (e.g. a faucet), it's just empty today.
const GENESIS_PREFUND: &[(&str, u64)] = &[];

/// Starting per-block issuance before any halving, in whole HLX. Minted on top of the
/// validator's fee share for every block (including empty ones) via `scheduled_block_reward`
/// — this is what makes validator income independent of transaction volume, addressing the
/// gap a fee-only model has once/if fee revenue alone isn't enough to secure the network.
pub const INITIAL_BLOCK_REWARD_HLX: u64 = 1;

/// Block-reward halving interval: one Helix-year at the current 2 s block time
/// (365 days × 86 400 s ÷ 2 s per block = 15 768 000 blocks). Chosen to be Bitcoin-shaped —
/// geometric decay toward an asymptote rather than a cliff-edge cutoff or perpetual flat
/// issuance that inflates forever. The schedule's total eventual emission converges to
/// `2 × INITIAL_BLOCK_REWARD_HLX × HALVING_INTERVAL_BLOCKS` ≈ 31.5 M HLX — comfortably inside
/// the 99 M HLX of headroom under `TOTAL_SUPPLY_HLX`, so in practice the reward decays to
/// economically-irrelevant amounts (and eventually to exactly 0 via integer division) long
/// before the cap could ever bind. The cap is still enforced explicitly wherever the reward
/// is actually minted (see `ChainState::mintable_headroom`) — this margin is a design
/// comfort, not the safety mechanism itself.
pub const HALVING_INTERVAL_BLOCKS: u64 = 15_768_000;

/// Deterministic block-reward schedule in nano-HLX: `INITIAL_BLOCK_REWARD_HLX`, halved once
/// per `HALVING_INTERVAL_BLOCKS`. Pure integer arithmetic — no floating point anywhere in
/// this path — so every node computes the exact same reward for the exact same height, which
/// consensus safety depends on. This function only describes the *schedule*; it does not
/// know about (and does not enforce) the `TOTAL_SUPPLY_HLX` cap — callers must clamp the
/// actual mint to `ChainState::mintable_headroom()`.
pub fn scheduled_block_reward(height: u64) -> u64 {
    let era = height / HALVING_INTERVAL_BLOCKS;
    if era >= 64 {
        // A right-shift by >= the integer's bit width is a logic error in Rust (panics under
        // overflow checks, silently wraps without them) — guard it explicitly even though the
        // reward has long since integer-divided down to 0 well before era 64 in practice
        // (a 1 HLX = 1e9-nano starting reward is fully gone by era 30).
        return 0;
    }
    (INITIAL_BLOCK_REWARD_HLX * NANO_PER_HLX) >> era
}

pub struct GenesisConfig {
    pub validator: Address,
    pub allocations: Vec<(Address, u64)>, // (address, nano-HLX balance)
    /// The network's personhood-issuing authorities, if configured — see
    /// `ChainState::personhood_authorities`'s doc comment. Empty means `ProvePersonhood` stays
    /// disabled until an operator explicitly sets at least one; there is deliberately no
    /// default here (auto-generating a keypair would produce an authority nobody actually
    /// holds the private key for, which would just brick the feature a different way).
    pub personhood_authorities: Vec<PublicKey>,
}

impl GenesisConfig {
    pub fn devnet(validator: Address) -> Self {
        Self::devnet_with_personhood_authority(validator, Vec::new())
    }

    pub fn devnet_with_personhood_authority(
        validator: Address,
        personhood_authorities: Vec<PublicKey>,
    ) -> Self {
        let mut allocations = Vec::new();
        for (addr_str, hlx) in GENESIS_PREFUND {
            if let Ok(addr) = Address::from_str(addr_str) {
                allocations.push((addr, hlx * NANO_PER_HLX));
            }
        }
        GenesisConfig { allocations, validator, personhood_authorities }
    }

    /// Build the initial ChainState.
    /// - `total_supply` (the hard cap) = 100 M HLX, set once and never changed afterward.
    /// - `total_issued` (what's actually in circulation) starts at just the validator's 1 M
    ///   HLX bootstrap stake plus any `GENESIS_PREFUND` allocations — the remaining ~99 M HLX
    ///   of headroom is minted gradually via `scheduled_block_reward`, not handed out here.
    /// - circulating_supply = total_issued − total_burned (starts at ~1 M, grows with block
    ///   rewards, shrinks with burns)
    pub fn build_state(&self) -> ChainState {
        let total_supply = TOTAL_SUPPLY_HLX * NANO_PER_HLX;
        let mut state = ChainState::new(total_supply);
        let mut issued = 0u64;

        // Spendable balances
        for (address, nano) in &self.allocations {
            state.set_balance(address, *nano);
            issued += nano;
        }

        // Validator genesis stake — staked directly so it survives epoch 1 rotation
        let validator_stake = VALIDATOR_GENESIS_STAKE_HLX * NANO_PER_HLX;
        state.set_validator_stake(&self.validator, validator_stake);
        issued += validator_stake;

        state.total_issued = issued;
        state.personhood_authorities = self.personhood_authorities.clone();

        state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduled_block_reward_starts_at_initial_reward() {
        assert_eq!(scheduled_block_reward(0), INITIAL_BLOCK_REWARD_HLX * NANO_PER_HLX);
        assert_eq!(scheduled_block_reward(HALVING_INTERVAL_BLOCKS - 1), INITIAL_BLOCK_REWARD_HLX * NANO_PER_HLX);
    }

    #[test]
    fn scheduled_block_reward_halves_each_era() {
        let initial = INITIAL_BLOCK_REWARD_HLX * NANO_PER_HLX;
        assert_eq!(scheduled_block_reward(HALVING_INTERVAL_BLOCKS), initial / 2);
        assert_eq!(scheduled_block_reward(2 * HALVING_INTERVAL_BLOCKS), initial / 4);
        assert_eq!(scheduled_block_reward(3 * HALVING_INTERVAL_BLOCKS), initial / 8);
    }

    #[test]
    fn scheduled_block_reward_decays_to_zero_and_stays_there() {
        // 1 HLX = 1e9 nano needs ~30 halvings to integer-divide down to 0.
        assert_eq!(scheduled_block_reward(35 * HALVING_INTERVAL_BLOCKS), 0);
        // Far beyond the era>=64 shift-safety guard — must not panic or wrap back up.
        assert_eq!(scheduled_block_reward(1_000 * HALVING_INTERVAL_BLOCKS), 0);
        assert_eq!(scheduled_block_reward(u64::MAX), 0);
    }

    #[test]
    fn build_state_no_longer_liquid_dumps_the_full_supply_to_the_validator() {
        let validator = Address::from_public_key(&helix_crypto::KeyPair::generate().public);
        let cfg = GenesisConfig::devnet(validator.clone());
        let state = cfg.build_state();

        let acc = state.get(&validator).expect("validator account must exist at genesis");
        assert_eq!(acc.staked, VALIDATOR_GENESIS_STAKE_HLX * NANO_PER_HLX);
        assert_eq!(acc.balance, 0, "no liquid pre-mine — everything beyond the bootstrap stake is earned via block rewards");
        assert_eq!(state.total_issued, VALIDATOR_GENESIS_STAKE_HLX * NANO_PER_HLX);
        assert_eq!(state.total_supply, TOTAL_SUPPLY_HLX * NANO_PER_HLX);
        assert!(state.mintable_headroom() > 0, "the vast majority of supply must remain unminted at genesis");
    }
}
