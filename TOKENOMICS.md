# Helix Tokenomics

HLX monetary policy, the security model, and the open question — written to be honest about
limitations rather than to market. A coin that wants to be taken seriously is bought by people
who read the emission curve.

All values are the defaults in `helix-executor/src/genesis.rs` and `governance.rs`. Parameters
marked *(governance)* can be changed on the running chain by a two-thirds stake vote; everything
else is fixed at genesis.

## The one-paragraph version

A small, bounded genesis allocation instead of a pre-mine: the bootstrap validator starts with
100,000 HLX — 10,000 staked, exactly the minimum every validator needs, so the chain can produce
blocks at all, and 90,000 liquid, so a slash that drops it below that minimum is recoverable and
the first operators can be funded to stake. That is about 0.3% of the supply the chain ever
reaches. Every other coin is *earned* by producing blocks, on a Bitcoin-shaped halving schedule.
Each transaction burns a base fee proportional to its size and tips the block's proposer whatever
was paid above it. Security comes from staked HLX, not from the emission schedule — the two are
deliberately decoupled.

## Supply

| Quantity | Value |
|---|---|
| Hard supply cap (`TOTAL_SUPPLY_HLX`) | 33,000,000 HLX |
| Genesis stake (bootstrap validator) | 10,000 HLX (= `MIN_VALIDATOR_STAKE`) |
| Genesis liquid reserve (bootstrap validator) | 90,000 HLX |
| Genesis total | 100,000 HLX (~0.3% of what the chain ever reaches) |
| Other genesis allocations | none |
| Initial block reward | 1 HLX per block, to its proposer |
| Halving interval | 15,768,000 blocks (~1 year at 2 s blocks) |

**Emission curve.** The reward is `1 HLX >> era`, where `era = height / 15,768,000`: it halves
about once a year and reaches zero at era 30 (`1e9 nano >> 30 == 0`). Summed:

```
Σ (1 HLX >> era) × 15,768,000 blocks  ≈  2 × 15,768,000  ≈  31,536,000 HLX
```

So the **real maximum supply is ≈ 31.6M HLX** (100k genesis + ~31.5M emitted), *minus* cumulative
burns. The 33M cap sits just above it, so it never binds early and is a genuine ceiling — not a
round number the schedule could never reach.

"Thirty years" is the arithmetic, not the deadline: the subsidy stops *mattering* long before it
stops existing — see [what pays for security](#the-open-question-what-pays-for-security-once-emission-stops).

**Circulating supply** = total issued − total burned; `GET /status` reports both.

## Fees

Helix charges **per transaction byte**, EIP-1559 style.

- Every block header carries a **base fee** (`base_fee_per_byte`), derived from the parent block's
  fullness: ±12.5% per block toward a 1 MB target, floored at 1 nano/byte. It is part of the
  signed header, so a proposer cannot choose it.
- Each transaction owes `base_fee_per_byte × its size`. **That portion is burned in full.**
  Whatever the sender paid above it is the **tip**, the proposer's entire income from that
  transaction — shared with its delegation pool, if it has one. The pool ranks transactions by
  tip, not by total fee.
- The fee also buys execution fuel for contract calls: `fuel_limit = fee × fuel_per_fee_unit`
  *(governance, default 1)*.
- Two transactions pay no base fee, because charging one would switch off a safety mechanism:
  double-sign evidence (its two-vote payload is ~16 KB) and the heartbeat a validator on probation
  sends to prove its node runs.

**Size dominates.** ML-DSA-65 signatures are 3,309 bytes and public keys 1,952. An account's
first transaction carries its key and is about 5.4 KB; every later one travels without it, about
3.5 KB — at the floor, some 5,400 and 3,500 nano-HLX. Wallets ask the node for the current base
fee, price the transaction for the size its block will carry, and add 100% headroom so it still
clears if the fee rises while it waits — and never pay more than 1 HLX on their own.

## Validator economics

| Parameter | Value |
|---|---|
| Minimum validator stake | 10,000 HLX *(governance, floor 100 HLX)* |
| Voting-power cap per validator | 1% of total stake |
| Slashing (double-signing) | 5% of stake and of the delegation pool |
| Downtime | jailed, no slash |
| Delegation | pool shares, auto-compounding, slashable |
| Commission | default 10%, at most 50% |
| Unbonding | 7 days, slashable throughout |

**Should the stake requirement halve with the block reward?** No — the two answer different
questions. The halving is *monetary policy*: how fast new supply enters. The stake minimum is
*security policy*: how much collateral a validator posts. Coupling them would make security decay
exponentially while the value it protects grows. And the barrier falls by itself where it matters:
a fixed nominal stake is a shrinking share of the money supply as emission distributes coins.

If HLX ever becomes so valuable that the minimum prices operators out (Ethereum's 32-ETH debate),
two mechanisms already answer it: the minimum is **governance-adjustable** — lowered deliberately
by vote rather than on a hard-coded curve — and **delegation** lets small holders pool stake behind
a validator. Participation gets cheaper by pooling, not by weakening every validator's collateral.

## The open question: what pays for security once emission stops?

**There is no fixed share of fees for validators.** The base fee is burned in full and the
validator's income is the tip alone. Nothing in consensus guarantees a tip: a sender who pays
exactly the base fee pays the proposer zero, and the transaction is valid. That wallets tip about
as much as they burn is a client-side convention (their 100% headroom), not a rule.

**The cliff is not at year 30.** The subsidy halves yearly, so it stops mattering long before it
reaches zero:

| Year | Subsidy, HLX/day (whole network) | Per validator, at 4 |
|-----:|---------------------------------:|--------------------:|
| 0    | 43,200                           | 10,800              |
| 5    | 1,350                            | 337                 |
| 10   | **42**                           | **10.6**            |
| 15   | 1.3                              | 0.33                |
| 30   | 0                                | 0                   |

The question is what happens in **ten** years, not thirty.

**How Helix compares.** This model is harsher than either chain it borrows from:

| | Fee handling | Emission | What secures it long-term |
|---|---|---|---|
| Bitcoin | all fees → miner | → 0 | fees, entirely |
| Ethereum | base burned, tip → validator | **perpetual** | issuance, with fees on top |
| **Helix** | base burned, tip → validator | **→ 0** | **tips alone** |

Helix took Ethereum's fee design and Bitcoin's emission design. Each is coherent on its own;
together they leave voluntary tips as the only long-run security budget. Ethereum can burn its
base fee precisely because its issuance never stops paying validators.

**Scale check.** At the floor, with blocks at the 1 MB target and wallets tipping their default,
tips come to about 0.001 HLX per block — ~43 HLX a day across the network, about the year-10
subsidy. Tips replace the subsidy only if blocks are consistently full. They do scale with demand
— a rising base fee raises a proportional tip with it — but that scaling rests on a wallet
convention, not on consensus.

**The levers:**

1. **Taper the burn.** Once emission has faded, route some or all of the base fee to the proposer
   instead of burning it — Bitcoin's model, reached from the other side. It turns deflation into
   security spending, needs no new issuance and stays inside the 33M cap; its natural shape is a
   governance parameter that tapers as the subsidy decays.
2. **Perpetual tail emission** (Ethereum, Monero). Simple and proven, but it breaks the 33M cap —
   the credibility the honest cap was set to establish.
3. **Do nothing** — bet that fee demand and the tipping convention carry it.

**Recommendation:** lever 1, decided deliberately and well before it binds. It is monetary policy
and belongs to whoever owns the tokenomics; nothing about it is urgent in wall-clock terms, except
that a security budget should not be designed once it is already too thin.

## History

- **2026-09-30 (0.20.0):** genesis allocation 100,000 HLX — 10,000 staked, 90,000 liquid.
- **2026-08-26:** minimum validator stake 100,000 → 10,000 HLX (governance floor 1,000 → 100);
  the genesis reserve had been raised to 500,000 on 2026-07-22 to fund the first operators.
- **2026-07-16:** genesis allocation cut from 1M to 200k (100k staked, 100k liquid).
- **2026-07-15:** supply cap 100M → 33M, so the cap is a real ceiling for the schedule; per-byte
  base fee (EIP-1559 style) replaces a flat minimum fee.

Every change reset the testnet; none carried balances across.

*Last reviewed: 2026-09-30.*
