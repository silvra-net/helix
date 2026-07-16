# Helix Tokenomics

Authoritative description of HLX monetary policy, the security model, and the open
questions. Written to be honest about limitations rather than to market — a coin that
wants to stand next to BTC/ETH/SOL is bought by people who read the emission curve.

All values below are the genesis defaults in `helix-executor/src/genesis.rs` /
`governance.rs`. Parameters marked *(governance-adjustable)* can be changed on the live
chain by a 2/3-of-stake governance proposal; everything else is fixed at genesis.

## The one-paragraph version

No pre-mine. 1,000,000 HLX is staked (not liquid) by the bootstrap validator at genesis so
the chain can produce blocks at all; every other coin is *earned* by producing blocks, via a
Bitcoin-shaped halving emission. Half of every transaction fee is burned, half pays the
block's validator. Security comes from staked HLX (Proof-of-Stake), not from the emission
schedule — the two are deliberately decoupled.

## Supply

| Quantity | Value |
|---|---|
| Hard supply cap (`TOTAL_SUPPLY_HLX`) | 33,000,000 HLX |
| Genesis stake (bootstrap validator, non-liquid) | 1,000,000 HLX |
| Initial block reward | 1 HLX/block |
| Halving interval | 15,768,000 blocks (~1 year at 2 s blocks) |
| Liquid pre-mine | none |

**Emission curve.** The reward is `1 HLX >> era`, where `era = height / 15,768,000`. It
halves once per ~year and integer-divides to **zero after ~30 years** (era 30: `1e9 nano >> 30
== 0`). Summed, total emission converges to:

```
Σ (1 HLX >> era) × 15,768,000 blocks  ≈  2 × 15,768,000  ≈  31,536,000 HLX
```

So the **real asymptotic max supply is ≈ 31.7M HLX** (200k genesis + ~31.5M emitted), *minus*
cumulative burns.

> **Genesis allocation cut 1M → 200k (2026-07-16).** The bootstrap validator now starts with
> 100k staked — exactly `MIN_VALIDATOR_STAKE`, the same bar every other validator must clear —
> plus 100k liquid so a 5% slash dropping it under that bar is recoverable in one transaction.
> The old 1M was a leftover from the 100M-cap era, where it read as 1% of the nominal ceiling;
> against *real* supply it was always ~3.07%, and the 33M honesty fix exposed that without
> revisiting it. At 200k the founder's genesis share is ~0.6%.
>
> Worth stating plainly, since the number invites more weight than it deserves: this is
> **cosmetic against the real distribution dynamic**. A sole validator collects every block
> reward — ~15.7M in the first year — so its share trends to ~99% regardless of whether genesis
> was 200k or 1M. The genesis line is not what concentrates supply; running the only node is.
> That only changes when other validators start earning (see the `3f+1` note in the README).

> ✅ **Honest cap (decided & shipped 2026-07-15).** `TOTAL_SUPPLY_HLX` was 100M — a ceiling
> the schedule could never reach (~67M / two-thirds phantom headroom), which reads as
> dishonest to anyone who does the arithmetic. It is now **33M**, sized to clear the ~31.7M
> real asymptote with a small (~4%) margin so it never binds prematurely but is a genuine
> ceiling. Decision (Vistos, full monetary authority): keep the supply scarce — hold the 1 HLX
> reward and correct the *cap* down to the truth, rather than inflating the reward to make a
> round 100M real. Applied by lowering the constant + resetting the (single-account, zero
> external-holder) prod chain so its genesis reflects the honest cap; `total_supply` is
> reconstructed from the binary constant on join, so all nodes now agree on 33M.

## Fees

- Fee is a **user-set field** on each transaction (`tx.fee`, in nano-HLX), floored by a
  local mempool anti-spam minimum (`DEFAULT_MIN_FEE = 1000 nano`, per-node, *not* consensus).
- `fuel_limit = tx.fee × fuel_per_fee_unit` *(governance-adjustable, default 1)* — the fee
  buys execution fuel at a governance-set price.
- **50 % of every fee is burned, 50 % pays the block validator** (`distribute_fee`).
- Block ordering is a **bid market** (highest fee included first) but there is **no
  EIP-1559-style floating base fee** — nominal per-fuel cost is constant unless governance
  moves `fuel_per_fee_unit`.

**Do fees stay constant forever?** Nominally yes — the per-fuel price is fixed until a
governance vote changes it. That is fine while blocks are near-empty, but it means fees do
*not* automatically respond to congestion or to a large change in HLX's fiat price. A serious
L1 eventually wants an automatic base-fee mechanism (or at least a consensus-level, not
per-node, min fee). See backlog.

## Validator economics & the stake requirement

| Parameter | Value |
|---|---|
| Minimum validator stake | 100,000 HLX *(governance-adjustable, floor 1,000 HLX)* |
| Voting-power cap per validator | 1 % of total |
| Slashing (equivocation) | 5 % of stake (`SLASH_FRACTION_BPS = 500`) |
| Delegated staking | implemented (pool shares, auto-compounding, slashable) |

**Should the stake requirement halve as the block reward halves?** — **No, and it would be
actively harmful.** The two knobs answer different questions:

- The **halving** is *monetary policy*: how fast new supply enters.
- The **stake minimum** is *security policy*: how much skin-in-the-game a validator posts.

Coupling them would make security decay exponentially — a network that secures *more* value
over time while requiring *less* collateral to attack it. That is backwards. Note also that
the barrier already falls on its own in the way that matters: 100k HLX is **10 % of the
entire genesis supply** on day one (very hard to acquire early), but a shrinking fraction of
the money supply as ~31.5M HLX is emitted and distributed. Measured as a share of all coins,
the entry barrier *decreases* automatically with a fixed nominal stake.

The legitimate worry inside the question — "what if HLX appreciates so much that 100k HLX
prices everyone out and the validator set centralizes?" (Ethereum's 32-ETH debate) — is
real, and is answered by two mechanisms that already exist, *not* by an automatic schedule:

1. **Governance-adjustable minimum** — a deliberate 2/3-stake vote can lower it (floor 1k),
   so the network chooses when the bar moves instead of it decaying on a hardcoded curve.
2. **Delegated staking** — small holders pool stake behind a validator without each needing
   100k. This is the real decentralization lever: you lower participation cost by *pooling*,
   not by weakening every validator's individual collateral.

## Is the long-term model sound?

Mostly yes, with a coherent philosophy (no pre-mine, fair earned emission, deflationary
burn, PoS security decoupled from monetary policy).

- ✅ **Phantom supply cap — resolved 2026-07-15.** Cap corrected from 100M to an honest 33M
  (see the Supply section). This was the one credibility issue with a clear-cut fix.

Two open questions remain — both touch consensus economics, so they belong in deliberate
design/governance rather than a hotfix, and are tracked in the dev-loop backlog:

1. **No automatic fee market** (backlog #80). Fine today; a major L1 wants base-fee/congestion
   pricing and a consensus-level min fee, not just a per-node mempool floor.
2. **Post-emission security budget** (backlog #81, the Bitcoin problem). After ~year 30
   validators live on *50 %* of fees only. Whether that sustains a decentralized set depends
   entirely on fee demand; the burn share is itself a lever (it could taper post-emission to
   fund security). Deflation from the burn should raise the fiat value of that fee share,
   partially self-correcting — but this must be modeled, not assumed.

*Last reviewed: 2026-07-15.*
