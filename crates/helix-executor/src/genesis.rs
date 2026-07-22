use helix_crypto::{Address, PublicKey};

use crate::state::ChainState;

pub const NANO_PER_HLX: u64 = 1_000_000_000;

/// Hard cap — never more than 33 M HLX will ever exist, full stop. This is an *honest* cap
/// (decision 2026-07-15): it is sized to sit just above what the emission schedule actually
/// pays out, not at an aspirational round number the chain could never reach. The 1 HLX
/// halving subsidy (`scheduled_block_reward`) emits a geometric series that converges to
/// `2 × INITIAL_BLOCK_REWARD_HLX × HALVING_INTERVAL_BLOCKS ≈ 31.5 M HLX`; plus the 200 k genesis
/// allocation that is the real asymptotic max supply ≈ 31.7 M. The cap is set to 33 M so
/// it clears that asymptote with a small (~4 %) margin and never binds prematurely — but it
/// is a genuine ceiling, not the ~67 M of phantom headroom the old 100 M value carried (a
/// cap 3× larger than anything the schedule could mint reads as dishonest to anyone who does
/// the arithmetic). Unlike a chain that dumps its whole supply into circulation at genesis,
/// this ceiling is approached asymptotically via `scheduled_block_reward` /
/// `ChainState::total_issued`; supply only ever *decreases* relative to what's been issued,
/// as 50 % of every fee is burned.
pub const TOTAL_SUPPLY_HLX: u64 = 33_000_000;

/// Minimum stake required to enter the active validator set.
/// 100 k HLX = 0.1 % of total supply — enough skin-in-the-game for slashing to hurt,
/// low enough that legitimate node operators can participate.
pub const MIN_VALIDATOR_STAKE: u64 = 100_000 * NANO_PER_HLX;

/// Default validator pre-stake at genesis, for a chain being launched fresh. The validator
/// needs this staked from block 0 so it survives the first epoch rotation (which filters by
/// MIN_VALIDATOR_STAKE). This is the ONLY genesis allocation — see `GENESIS_PREFUND`'s doc
/// comment for why there is deliberately no liquid pre-mine on top of it.
///
/// Only a *default*: the value a chain actually launched with is recorded in
/// `ChainState::genesis_validator_stake` and handed to joining nodes via `GET /genesis`, so
/// retuning this constant does not retroactively rewrite the genesis of chains already
/// running under the old value. It applies to new chains only.
pub const VALIDATOR_GENESIS_STAKE_HLX: u64 = 100_000; // = MIN_VALIDATOR_STAKE

/// Liquid balance the bootstrap validator holds at genesis, on top of its stake.
///
/// Exists because `VALIDATOR_GENESIS_STAKE_HLX` sits exactly on `MIN_VALIDATOR_STAKE`: a single
/// 5% slash (`SLASH_FRACTION_BPS`) leaves 95k and drops the validator out of the set at the next
/// epoch, and it cannot stake its way back out of thin air. This reserve makes that recoverable
/// in one transaction — staking takes effect immediately, only *unstaking* waits out the
/// unbonding period. It doubles as an operator's working balance before block rewards accumulate.
///
/// Credited to whoever `GenesisConfig::validator` is, never a hardcoded address: this constant
/// ships in a public repo, and naming one deployment's wallet here would prefund it on every
/// chain anyone launches from this source. See `GENESIS_PREFUND` on why a founder allocation
/// stays small; 500k is ~1.5% of the supply this chain eventually reaches.
///
/// Raised from 100k on 2026-07-22, and the reason is arithmetic rather than appetite. A
/// validator set needs **four** members before it survives one going offline (`3f + 1`), each
/// needs `MIN_VALIDATOR_STAKE` (100k), and block rewards accrue at ~0.56 HLX per block — so
/// nobody can earn their way in, and a bootstrap validator holding 100k cannot fund even one
/// other operator. That is not a theoretical limit: this chain sat halted with two validators
/// because the second one's operator was unreachable, and the whole circulating supply was
/// short of what a third would have cost. 500k funds three additional validators (110k each,
/// the extra 10k being fee headroom — an operator who stakes every coin cannot afford the
/// `Unjail` transaction that gets them back) and leaves a working reserve.
///
/// It is a launch reserve to be handed out, not a holding. If a deployment ever wants a
/// genuinely small founder balance, lower this *and* accept that its validator set grows only
/// as fast as people arrive with their own 100k.
pub const VALIDATOR_GENESIS_LIQUID_HLX: u64 = 500_000;

/// Pre-funded genesis wallets beyond the validator's bootstrap stake: (address, balance_HLX).
/// Empty by design (decision 2026-07-15, superseding the 2026-07-05 decision to liquid-dump
/// the entire remaining ~99 M HLX supply to the validator at genesis): a chain that hands its
/// founder the whole supply on day one isn't meaningfully different from a pre-mined coin,
/// regardless of what the whitepaper says about caps. The ~31.5 M HLX difference between
/// `TOTAL_SUPPLY_HLX` and the genesis stake is instead released gradually, earned by
/// whoever actually produces blocks, via `scheduled_block_reward` — the same shape as
/// Bitcoin's coinbase subsidy. Nothing stops an operator from prefunding specific wallets
/// here for legitimate bootstrap needs (e.g. a faucet or a treasury), it's just empty today.
///
/// Like `VALIDATOR_GENESIS_STAKE_HLX`, this is a default for chains launching *fresh*: what a
/// chain actually allocated is recorded in `ChainState::genesis_allocations` and handed to
/// joining nodes over `GET /genesis`. That is what makes filling this in safe at all — before
/// it, a populated prefund would have been rebuilt by each joining node from *its own* binary,
/// so any build skew became a genesis mismatch and a diverged chain.
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
/// `2 × INITIAL_BLOCK_REWARD_HLX × HALVING_INTERVAL_BLOCKS` ≈ 31.5 M HLX — which, plus the 200 k
/// genesis allocation, is exactly why `TOTAL_SUPPLY_HLX` is set to 33 M (a tight, honest ceiling
/// just above that asymptote), so in practice the reward decays to economically-irrelevant
/// amounts (and eventually to exactly 0 via integer division) just as the cap is approached
/// but before it could ever bind. The cap is still enforced explicitly wherever the reward
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
    /// Liquid genesis balances (address, nano-HLX). Seeded from the `GENESIS_PREFUND` default
    /// for a chain launching fresh; a node joining an existing chain replaces it with that
    /// chain's real allocations from the peer's `GET /genesis`, exactly like `validator_stake`
    /// and `extra_validators`. See `ChainState::genesis_allocations`.
    pub allocations: Vec<(Address, u64)>,
    /// The network's personhood-issuing authorities, if configured — see
    /// `ChainState::personhood_authorities`'s doc comment. Empty means `ProvePersonhood` stays
    /// disabled until an operator explicitly sets at least one; there is deliberately no
    /// default here (auto-generating a keypair would produce an authority nobody actually
    /// holds the private key for, which would just brick the feature a different way).
    pub personhood_authorities: Vec<PublicKey>,
    /// Additional validators to pre-stake directly at genesis, beyond `validator` (address,
    /// nano-HLX stake). Empty by default — every chain still starts with exactly one
    /// bootstrap validator unless an operator explicitly opts into more. Exists because
    /// organically growing from one validator to several requires each new validator to
    /// accumulate `MIN_VALIDATOR_STAKE` (100k HLX) via block rewards (1 HLX/block) or
    /// transfers from an already-funded account — economically real, but far too slow to
    /// ever set up a genuinely multi-validator network (let alone test one) in anything
    /// short of months. Setting this lets an operator launch with real multi-validator BFT
    /// (proposer rotation, live voting) active from block 0 instead. Populated from
    /// `HELIX_GENESIS_EXTRA_VALIDATORS`/`helix.toml`'s `genesis_extra_validators` — see
    /// `helix-node::node::HelixNode::new` — and, for a node joining an existing chain via
    /// `sync_peer`, from that peer's `GET /genesis` response (`ChainState::genesis_extra_validators`
    /// carries it forward so it can be replayed identically by every later-joining node).
    pub extra_validators: Vec<(Address, u64)>,
    /// Bootstrap stake (nano-HLX) for `validator`. Defaults to `VALIDATOR_GENESIS_STAKE_HLX`
    /// for a chain launching fresh; a node joining an existing chain overwrites it with that
    /// chain's real value from the peer's `GET /genesis`, rather than trusting its own binary's
    /// constant to still match what the chain launched with years earlier. See
    /// `ChainState::genesis_validator_stake`.
    pub validator_stake: u64,
}

/// Rebuild the genesis `ChainState` a chain started from, given the parts that cannot be
/// re-derived from its genesis block.
///
/// The one function both sides of a join use: the peer calls it to publish the hash its genesis
/// state has (`GET /genesis`), and the joining node calls it to build the state it will run on.
/// Same inputs, same code — so if the two disagree, the disagreement can only come from their
/// *binaries*, which is exactly what the comparison is meant to catch. Two copies of this logic
/// would defeat the check: they could drift and agree on being wrong.
///
/// `governance_params` is the peer's *current* value, not necessarily its genesis-time one — see
/// `get_genesis`'s doc comment for why that gap is accepted. Both sides use the same value, so it
/// does not affect the comparison.
pub fn rebuild_genesis_state(
    validator: Address,
    personhood_authorities: Vec<PublicKey>,
    extra_validators: Vec<(Address, u64)>,
    validator_stake: u64,
    allocations: Vec<(Address, u64)>,
    governance_params: crate::governance::GovernanceParams,
) -> ChainState {
    let mut cfg = GenesisConfig::devnet_with_personhood_authority(validator, personhood_authorities);
    cfg.extra_validators = extra_validators;
    cfg.validator_stake = validator_stake;
    cfg.allocations = allocations;
    let mut state = cfg.build_state();
    state.governance_params = governance_params;
    state
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
        // Routed through `allocations` rather than credited directly in `build_state` so it lands
        // in `ChainState::genesis_allocations` like any other genesis balance — which is what
        // carries it to a joining node over `GET /genesis` instead of leaving it to that node's
        // own constants (see `genesis_allocations`).
        allocations.push((validator.clone(), VALIDATOR_GENESIS_LIQUID_HLX * NANO_PER_HLX));
        GenesisConfig {
            allocations,
            validator,
            personhood_authorities,
            extra_validators: Vec::new(),
            validator_stake: VALIDATOR_GENESIS_STAKE_HLX * NANO_PER_HLX,
        }
    }

    /// Build the initial ChainState.
    /// - `total_supply` (the hard cap) = 33 M HLX, set once and never changed afterward.
    /// - `total_issued` (what's actually in circulation) starts at just the validator's 100 k
    ///   HLX bootstrap stake, its 100 k liquid reserve, and any `GENESIS_PREFUND` allocations —
    ///   the remaining ~32.8 M HLX of headroom is minted gradually via `scheduled_block_reward`,
    ///   not handed out here.
    /// - circulating_supply = total_issued − total_burned (starts at ~200 k, grows with block
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
        state.genesis_allocations = self.allocations.clone();

        // Validator genesis stake — staked directly so it survives epoch 1 rotation
        let validator_stake = self.validator_stake;
        state.set_validator_stake(&self.validator, validator_stake);
        state.genesis_validator_stake = validator_stake;
        issued += validator_stake;

        // Extra genesis validators, if configured — see `extra_validators`'s doc comment.
        for (address, stake) in &self.extra_validators {
            state.set_validator_stake(address, *stake);
            issued += stake;
        }
        state.genesis_extra_validators = self.extra_validators.clone();

        state.total_issued = issued;
        state.personhood_authorities = self.personhood_authorities.clone();

        state
    }
}

// Kani feasibility study (see CLAUDE.md backlog): example-based tests below check
// scheduled_block_reward() at a handful of chosen heights. These harnesses instead ask
// Kani's bounded model checker to prove the same properties for *every* u64 height —
// the entire input space, not the points we happened to think of — via `cargo kani`.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// The shift-overflow guard (`era >= 64`) must hold for literally every u64 height,
    /// not just u64::MAX and a couple of large multiples as the example tests check —
    /// this is exactly the class of "did I get the boundary condition right for all
    /// inputs" question unit tests are structurally unable to answer.
    #[kani::proof]
    fn scheduled_block_reward_never_panics() {
        let height: u64 = kani::any();
        let _ = scheduled_block_reward(height);
    }

    /// The schedule must never hand out more than the starting reward, for any height —
    /// this is the property callers actually rely on to reason about total emission.
    #[kani::proof]
    fn scheduled_block_reward_never_exceeds_the_initial_reward() {
        let height: u64 = kani::any();
        let reward = scheduled_block_reward(height);
        assert!(reward <= INITIAL_BLOCK_REWARD_HLX * NANO_PER_HLX);
    }

    /// Later (or equal) heights must never pay a *larger* reward than earlier ones —
    /// the halving schedule must be monotonically non-increasing over the entire
    /// domain, not just at the era boundaries the example tests happen to probe.
    #[kani::proof]
    fn scheduled_block_reward_is_monotonically_non_increasing() {
        let earlier: u64 = kani::any();
        let later: u64 = kani::any();
        kani::assume(earlier <= later);
        assert!(scheduled_block_reward(earlier) >= scheduled_block_reward(later));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn some_address() -> Address {
        Address::from_public_key(&helix_crypto::KeyPair::generate().public)
    }

    /// A fresh chain launches on the compile-time default, and records that it did — the record
    /// is what later lets the default change without rewriting this chain's genesis.
    #[test]
    fn a_fresh_genesis_records_the_stake_it_launched_with() {
        let validator = some_address();
        let state = GenesisConfig::devnet(validator.clone()).build_state();

        let expected = VALIDATOR_GENESIS_STAKE_HLX * NANO_PER_HLX;
        assert_eq!(state.genesis_validator_stake, expected);
        assert_eq!(state.accounts[&validator.to_string()].staked, expected);
    }

    /// The path a joining node takes: it overrides `validator_stake` with the value its peer
    /// reports, and `build_state` must honour that instead of the constant. Without this the
    /// node would rebuild a genesis the chain never had and diverge from everyone on it.
    #[test]
    fn build_state_stakes_the_configured_amount_not_the_compile_time_default() {
        let validator = some_address();
        // Deliberately unlike the default, standing in for a chain that launched under a
        // differently-tuned build.
        let peer_stake = 330_000 * NANO_PER_HLX;
        assert_ne!(peer_stake, VALIDATOR_GENESIS_STAKE_HLX * NANO_PER_HLX);

        let mut cfg = GenesisConfig::devnet(validator.clone());
        cfg.validator_stake = peer_stake;
        let state = cfg.build_state();

        assert_eq!(state.accounts[&validator.to_string()].staked, peer_stake);
        assert_eq!(state.genesis_validator_stake, peer_stake);
        assert_eq!(
            state.total_issued,
            peer_stake + VALIDATOR_GENESIS_LIQUID_HLX * NANO_PER_HLX,
            "issuance must count what was really staked, plus the validator's liquid reserve"
        );
    }

    /// The joining path for liquid balances: a node must credit the allocations its peer
    /// reports, and record them, rather than applying its own `GENESIS_PREFUND` default. This is
    /// what makes an operator treasury or faucet safe to configure at all — without it, filling
    /// the constant means every node with a different build rebuilds a different genesis.
    #[test]
    fn build_state_credits_the_configured_allocations_not_the_compile_time_default() {
        let validator = some_address();
        let treasury = some_address();
        let peer_allocation = 100_000 * NANO_PER_HLX;

        let mut cfg = GenesisConfig::devnet(validator.clone());
        // A joining node *replaces* the list rather than adding to it — including the local
        // build's own validator reserve, which belongs to a chain it isn't joining.
        cfg.allocations = vec![(treasury.clone(), peer_allocation)];
        let state = cfg.build_state();

        assert_eq!(state.accounts[&treasury.to_string()].balance, peer_allocation);
        assert_eq!(state.genesis_allocations, vec![(treasury, peer_allocation)]);
        assert_eq!(
            state.accounts.get(&validator.to_string()).map(|a| a.balance),
            Some(0),
            "the local default reserve must not survive being replaced by the peer's list"
        );
        assert_eq!(
            state.total_issued,
            peer_allocation + VALIDATOR_GENESIS_STAKE_HLX * NANO_PER_HLX,
            "issuance must count the liquid balances too, or the supply books are wrong"
        );
    }

    /// Both genesis records must be part of `state_hash`, so two nodes that disagree about them
    /// are caught by the one tool built to spot divergence.
    ///
    /// Deliberately mutates `ChainState` directly instead of going through `build_state`: doing
    /// it via config would also change `accounts` (a different stake, a funded treasury), and
    /// the hash would then differ for that reason alone — passing whether or not these fields
    /// are in `Canonical` at all, which is the very thing under test.
    #[test]
    fn the_genesis_records_are_part_of_the_state_hash() {
        let base = ChainState::new(33_000_000 * NANO_PER_HLX);

        let mut other_stake = ChainState::new(33_000_000 * NANO_PER_HLX);
        other_stake.genesis_validator_stake = 330_000 * NANO_PER_HLX;
        assert_ne!(base.state_hash(), other_stake.state_hash(), "stake must be hashed");

        let mut other_allocations = ChainState::new(33_000_000 * NANO_PER_HLX);
        other_allocations.genesis_allocations = vec![(some_address(), 100_000 * NANO_PER_HLX)];
        assert_ne!(base.state_hash(), other_allocations.state_hash(), "allocations must be hashed");
    }

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

    /// Genesis hands the founder a bounded, deliberate allocation and nothing more. The 2026-07-15
    /// version of this test asserted `balance == 0` — no liquid pre-mine at all. That is no longer
    /// the rule: the validator now also gets `VALIDATOR_GENESIS_LIQUID_HLX` so a slash that drops
    /// it under `MIN_VALIDATOR_STAKE` is recoverable (see that constant). The principle the old
    /// assertion protected is unchanged and still enforced here — genesis must stay a rounding
    /// error against total supply, with everything else earned block by block.
    #[test]
    fn genesis_allocates_only_the_bootstrap_stake_and_its_reserve() {
        let validator = Address::from_public_key(&helix_crypto::KeyPair::generate().public);
        let cfg = GenesisConfig::devnet(validator.clone());
        let state = cfg.build_state();

        let acc = state.get(&validator).expect("validator account must exist at genesis");
        assert_eq!(acc.staked, VALIDATOR_GENESIS_STAKE_HLX * NANO_PER_HLX);
        assert_eq!(acc.balance, VALIDATOR_GENESIS_LIQUID_HLX * NANO_PER_HLX);
        assert_eq!(
            state.total_issued,
            (VALIDATOR_GENESIS_STAKE_HLX + VALIDATOR_GENESIS_LIQUID_HLX) * NANO_PER_HLX,
            "nothing may be issued at genesis beyond the stake and its reserve"
        );
        assert_eq!(state.total_supply, TOTAL_SUPPLY_HLX * NANO_PER_HLX);

        // The load-bearing claim: this is a bootstrap, not a pre-mine. Anything approaching a
        // meaningful share of supply here would make the halving schedule decoration.
        //
        // This bound was "rounds to 0%" until 2026-07-22, when `VALIDATOR_GENESIS_LIQUID_HLX`
        // went from 100k to 500k and genesis reached ~1.8%. That was a deliberate devnet
        // decision by the CEO, not drift: a validator set needs four members to survive one
        // outage, each needs `MIN_VALIDATOR_STAKE`, and the bootstrap validator is the only
        // possible source of that capital on a chain nobody can mine their way into. The
        // assertion is re-baselined rather than deleted, and deliberately left tight — 2% still
        // fails on any further increase, so the next person to raise this has to come here and
        // say so out loud. If this ever needs to move again, that is a monetary-policy call and
        // belongs to whoever owns the tokenomics, not to whoever is editing genesis.
        let genesis_share_permille = state.total_issued * 1_000 / (TOTAL_SUPPLY_HLX * NANO_PER_HLX);
        assert!(
            genesis_share_permille < 20,
            "genesis is {genesis_share_permille}‰ of total supply — past 2% this stops being a \
             bootstrap allocation and becomes a pre-mine"
        );
        assert!(state.mintable_headroom() > 0, "the vast majority of supply must remain unminted");
    }
}
