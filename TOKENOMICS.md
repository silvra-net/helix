# Helix Tokenomics

Authoritative description of HLX monetary policy, the security model, and the open
questions. Written to be honest about limitations rather than to market — a coin that
wants to stand next to BTC/ETH/SOL is bought by people who read the emission curve.

All values below are the genesis defaults in `helix-executor/src/genesis.rs` /
`governance.rs`. Parameters marked *(governance-adjustable)* can be changed on the live
chain by a 2/3-of-stake governance proposal; everything else is fixed at genesis.

## The one-paragraph version

No pre-mine. Genesis hands the bootstrap validator 200,000 HLX and nothing else: 100,000
staked — exactly the minimum the rules demand of any validator — so the chain can produce
blocks at all, plus 100,000 liquid so a slash that drops it under that minimum is recoverable.
Every other coin is *earned* by producing blocks, via a Bitcoin-shaped halving emission. Each
transaction burns a base fee proportional to its size and tips the validator whatever was paid
above it. Security comes from staked HLX (Proof-of-Stake), not from the emission schedule — the
two are deliberately decoupled.

## Supply

| Quantity | Value |
|---|---|
| Hard supply cap (`TOTAL_SUPPLY_HLX`) | 33,000,000 HLX |
| Genesis stake (bootstrap validator, non-liquid) | 100,000 HLX (= `MIN_VALIDATOR_STAKE`) |
| Genesis liquid reserve (bootstrap validator) | 100,000 HLX (slash recovery — see below) |
| Genesis total | 200,000 HLX (~0.6 % of what the chain ever reaches) |
| Initial block reward | 1 HLX/block |
| Halving interval | 15,768,000 blocks (~1 year at 2 s blocks) |
| Founder pre-mine beyond the above | none |

**Emission curve.** The reward is `1 HLX >> era`, where `era = height / 15,768,000`. It halves
once per ~year and integer-divides to zero at era 30 (`1e9 nano >> 30 == 0`).

"Thirty years" is the arithmetic, not the deadline: halving means the subsidy stops *mattering*
long before it stops existing. By **year 10** it is ~42 HLX/day across the entire validator set,
by year 15 about one. Anything that depends on the subsidy — validator income above all — has to
work by then, not by year 30. See [what pays for security](#the-one-real-open-question-what-pays-for-security-once-emission-stops).

Summed, total emission converges to:

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

Helix charges **per transaction byte**, EIP-1559 style (shipped 2026-07-15, backlog #80).

- Every block header carries a **base fee** (`base_fee_per_byte`), derived deterministically
  from the parent block's fullness: ±12.5 % per block toward a 1 MB target, floored at 1
  nano/byte. It is part of the signed header and re-checked on validation, so a proposer cannot
  pick it.
- Each transaction owes `base_fee_per_byte × its size`. **That portion is burned in full.**
  Whatever the sender paid *above* it is the **tip**, and the tip is the validator's entire
  income from that transaction (`distribute_fee`) — shared with its delegation pool, if any.
- `fuel_limit = tx.fee × fuel_per_fee_unit` *(governance-adjustable, default 1)* — the fee also
  buys execution fuel for contract calls.
- `SubmitDoubleSignEvidence` is **exempt** from the base fee: its ~16 KB two-vote payload costs
  more than the flat reporter fee even at the floor, so charging it would price slashing reports
  out of every block and silently disable slashing.

**Size dominates.** Post-quantum signatures are large — ML-DSA-65 is 3,309 bytes of signature
plus 1,952 of public key — so a plain transfer is **~5,410 bytes and owes ~5,410 nano at the
floor**. A contract deploy carries its bytecode too, up to ~71,000 nano at the 64 KiB limit.
Clients do not guess at this: `helix tx send` asks the node for the current base fee, prices the
transaction for its real size, and adds 100 % headroom so it still clears if the fee climbs while
it waits (backlog #88). The mempool refuses anything that cannot afford the base fee, rather than
letting it be mined and fail.

> ✅ **Automatic fee market — resolved 2026-07-15 (was open question #1 here).** Fees now respond
> to congestion on their own and no longer depend on a governance vote to reprice, and the
> anti-spam floor is a consensus rule (the base fee) rather than a per-node convention.

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

- ✅ **Automatic fee market — resolved 2026-07-15** (see Fees). Congestion now reprices itself.

### The one real open question: what pays for security once emission stops?

This was filed as "the Bitcoin problem, ~year 30, validators live on 50 % of fees". Modelling it
(2026-07-16) showed **both halves of that framing were wrong**, and the truth is sharper.

**There is no 50 % share.** Since the fee market shipped, the base fee is burned *in full* and the
validator's income is the tip alone. Nothing in consensus guarantees a validator any part of a
transaction's fee: a sender who pays exactly the base fee pays the validator **zero**, and the
transaction is perfectly valid. Today's ~50 % is an artifact of the CLI's 100 % headroom default —
a client-side convention, not a rule.

**The cliff is not at year 30.** The subsidy halves yearly, so it stops mattering long before it
reaches literal zero:

| Year | Subsidy, HLX/day (whole network) | Per validator, at 4 |
|-----:|---------------------------------:|--------------------:|
| 0    | 43,200                           | 10,800              |
| 5    | 1,350                            | 337                 |
| 10   | **42**                           | **10.6**            |
| 15   | 1.3                              | 0.33                |
| 30   | 0                                | 0                   |

By **year 10** the subsidy is ~42 HLX/day across the entire validator set. The question is not
what happens in 30 years; it is what happens in **ten**.

**How Helix compares.** This model is strictly harsher than either chain it borrows from:

| | Fee handling | Emission | What secures it long-term |
|---|---|---|---|
| Bitcoin | all fees → miner | → 0 | fees, entirely |
| Ethereum | base burned, tip → validator | **perpetual** | issuance, with fees on top |
| **Helix** | base burned, tip → validator | **→ 0** | **tips alone** |

Helix took Ethereum's *fee* design and Bitcoin's *emission* design. Each is coherent on its own;
together they leave voluntary tips as the only long-run security budget. Ethereum can burn its
base fee precisely because issuance never stops paying validators.

**Scale check.** At the floor, with blocks at the 1 MB target (~184 transfers/block) and clients
tipping the CLI default, tips come to ~43 HLX/day network-wide — about the year-10 subsidy. So
tips replace the subsidy only if blocks are *consistently full*. They do scale: sustained demand
raises the base fee, and a client tipping proportionally raises its tip with it. But that scaling
rests on a convention, not on consensus.

**The levers, and what fits.**

1. **Taper the burn.** Post-emission, route some or all of the base fee to the validator instead
   of burning it — Bitcoin's model, reached from the other direction. Turns deflation into
   security spending, needs no new issuance, and stays inside the 33M cap. It is the only lever
   compatible with an honest hard cap, and the natural shape is a governance parameter that
   tapers as the subsidy decays.
2. **Perpetual tail emission** (Ethereum, Monero). Simple and proven, but breaks the 33M cap —
   the exact credibility problem the cap was fixed to solve. Non-starter unless the cap itself is
   reopened.
3. **Do nothing.** Bet that fee demand and a tipping convention carry it. That is a bet on
   behaviour, and it is what the chain currently does by default.

**Recommendation:** lever 1, decided deliberately and well before it binds — a security budget is
not something to design once it is already too thin. Not urgent in wall-clock terms; a decision
that only needs making before validators notice the subsidy shrinking. But "not urgent" has been
the reason this stayed vague through two rewrites.

**Related, and concrete:** the mempool orders by `tx.fee` (the total) while the validator earns
`fee − base_fee` (the tip). Those diverge — a large transaction paying exactly its base fee
outranks a small one that tips well, and pays the validator nothing. Ethereum sorts by effective
priority fee for exactly this reason. Tracked as backlog #92.

*Last reviewed: 2026-07-16.*
