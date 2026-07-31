# Staking & delegation

> Part of the [Helix documentation](../README.md) — deep reference, split out of the README to keep it short.

## Staking

Staking in Helix serves three distinct purposes — pick the one you actually want, they're not
mutually exclusive:

- **Run a validator** (self-stake + a node) — actively produce blocks, earn from it, and get
  governance voting power.
- **Delegate to a validator** — earn a share of *its* block rewards, proportional to your
  delegation, without running anything yourself. No governance voting power.
- **Self-stake without running a node** — governance voting power only, no yield (you're not
  producing blocks, so there's nothing to earn a share of).

### Staking as a Node Operator (Validator)

> **Stake the address your node signs with — not some other wallet.** Your node has its own
> validator identity in `validator-key.json` (auto-generated on first start if you didn't supply
> one). Staking a *different* address — say a wallet you already had funded — makes that address
> a validator the network then waits on, while **no node is signing for it**. In a small set that
> single "phantom" validator halts the chain, and it can't be removed until the chain moves again
> (which it can't, because it's waiting on the phantom). This is the single most common validator
> mis-setup. Guard against it in step 1 by *verifying the two addresses are the same*.

1. **Get a node running** (see [Running a Node](running-a-node.md#running-a-node)) and read off
   the address it validates as — **this is the only address you may stake**:
   ```bash
   helix wallet address --key validator-key.json     # e.g. hlxbx7oYT7n1...  ← your node's identity
   ```
   If you want your validator to *be* an existing wallet of yours, don't stake that wallet
   against a freshly-generated node key — instead make that wallet the node's key: point
   `HELIX_VALIDATOR_KEY` at its key file, or restore it into place with
   `helix wallet restore --mnemonic "…" --output validator-key.json`, then re-check the address
   above. The node signs with whatever `validator-key.json` holds, nothing else.
2. **Stake at least the minimum** (100,000 HLX — ~0.3% of the total supply) **from that exact
   address**, using that same key file:
   ```bash
   helix tx stake 100000 --key validator-key.json
   ```
   The `--key` here must be the same file whose address you read in step 1. If `helix tx stake`
   uses any other key, you have just created a phantom validator — see the warning above.
3. **Wait for two epoch rotations** (an epoch is 100 blocks — a few minutes at the 2s block time).
   The validator set is rebuilt at each boundary from every account meeting the minimum stake,
   counting both self-stake and anything delegated to it (see below). A new staker waits out the
   first epoch, spends the second on *probation* — in the signing set, but with zero voting power
   and no proposer turn — and is a full voting validator from the boundary after that, when its
   round-robin proposer turns begin.

   Probation is a test, not just a delay. During that epoch your node automatically sends a
   small, fee-free **heartbeat transaction** signed with the staking key, and promotion happens
   only if one of them (or a co-signed block) actually reached the chain. A staked address with
   no node behind it sends nothing, is never promoted, and so never becomes quorum-critical — it
   simply stays powerless and tries again. Nothing is slashed and nothing is lost.

   You do not have to do anything for this, and it costs nothing: the heartbeat is exempt from
   the base fee precisely because an operator who staked their whole balance has nothing liquid
   left to pay with. If your validator never leaves probation, the near-certain cause is that
   your node is signing as a *different* key than the one you staked from — check step 1 again.
   `GET /validators` shows `tier` and `probation_liveness_seen` for exactly this diagnosis.
4. **Earn**: every block you produce mints you a share of that block's transaction fees (50%
   of each fee; the other 50% is burned) plus a fixed block reward (starts at 1 HLX, halves
   yearly — see [Token Economics](internals.md#token-economics)), paid even on empty blocks. If you have
   delegators, your share is proportional to your self-stake versus their delegated total,
   plus a commission cut of theirs (see below) — with none, you keep 100% exactly as before.
5. **Unstaking**: `helix tx unstake <amount> --key validator-key.json` moves stake into a
   7-day unbonding period (still slashable during this window) before it's claimable:
   ```bash
   helix tx unstake 50000 --key validator-key.json
   # ... 7 days later ...
   helix tx claim-unbonded --key validator-key.json
   ```
   You can't unstake below the minimum if you're currently the *only* account meeting it —
   that would empty the validator set and halt the chain, so it's rejected outright rather
   than allowed and left to fail later.
6. **Set your commission** (optional, before or after you have delegators):
   ```bash
   helix tx set-commission 1000 --key validator-key.json   # 1000 bps = 10% (the default)
   ```
   Capped at 5000 bps (50%) — not to stop you from legitimately charging more, but to bound
   the "advertise a low rate, raise it once delegators are locked in" rug-pull: even a
   maximally hostile change can never claim more than half of what delegators earn.

**Slashing risk:** double-signing (proposing or voting for two different blocks at the same
height/round) burns 5% of your stake *and* 5% of your delegators' pooled stake, and jails you
from BFT rounds immediately — not just at the next epoch. Run one node per key. Ever.

What the node protects for you, and what it does not: a persisted signing high-water mark stops a
*restart* from re-signing a height it already signed (an honest reboot is safe), and the data
directory is file-locked so a second node started against the **same** directory refuses to start
with a clear "already in use" error rather than double-signing. Neither of those helps if you run
a second node **elsewhere with a copy of the key** — separate machine, separate data directory.
That setup has its own high-water mark that knows nothing of the first, so the two can sign
conflicting blocks and slash you. There is no remote-signer coordination yet; "one node per key"
is a discipline you keep, not something the software can currently enforce across machines.

**Downtime risk (no slash, but real friction):** a validator whose precommit is missing from
`last_commit` for ~150 consecutive blocks (~5 minutes) is downtime-jailed — excluded from
`stakers()`, earning nothing, until it explicitly rejoins:
```bash
helix tx unjail --key validator-key.json   # only once your node is actually back and connected
```
Requires the minimum jail window (~300 blocks, ~10 minutes) to have passed and your stake to
still meet the minimum. Unlike double-sign slashing this costs no HLX — going offline isn't
proof of malice, only sustained silence is treated as a liveness problem — but it isn't
automatic either: the same reasoning that makes an ordinary restart safe (jailing survives it,
so the same flaky connection can't refreeze the chain every time you reboot) is exactly why
rejoining needs a deliberate transaction, not a timer. Check whether you're currently jailed
with `helix account <your-address>`.

### Delegating to a Validator

Earn a share of a validator's block rewards without running any infrastructure:

```bash
helix tx delegate hlxValidatorAddress... 100 --key alice.json  # delegate 100 HLX
helix validator show hlxValidatorAddress...                     # see the pool: delegated
                                                                  # total, commission, effective stake
helix account alice_address                                     # see your own position's
                                                                  # current value, under "Delegations"
```

Delegation uses a share-pool model (the same one Cosmos SDK and liquid-staking protocols like
Lido use): you receive pool shares priced at the pool's current value per share, and every
reward the validator earns adds directly to the pool's total value — instantly making every
existing share worth more, with no separate "claim rewards" step. Your position **auto-
compounds** for free; check its current value any time with `helix account`.

```bash
helix tx undelegate hlxValidatorAddress... 50 --key alice.json  # redeem 50 HLX of current value
# ... 7 days later (same unbonding queue as self-staking) ...
helix tx claim-unbonded --key alice.json
```

`undelegate`'s amount is the HLX value you want back (principal plus whatever compounded, or
minus anything lost to a slash since you delegated), not raw shares — the CLI/executor
convert internally.

### Switching Validators

Undelegating and re-delegating means 7 days out of the market. To move a delegation directly,
with no unbonding wait and no missed rewards:

```bash
helix tx redelegate hlxOldValidator... hlxNewValidator... 50 --key alice.json
```

The stake earns at the old validator up to this transaction and at the new one immediately
after. What it does *not* do is shed the old validator's slashing risk: the moved stake stays
slashable for the validator you left for a full 7 days, so redelegating away from one that has
already double-signed does not dodge the hit — the loss comes out of your shares at the new
validator, leaving that validator's other delegators untouched. Redelegating stake that is
itself still inside such a window is rejected; wait it out before moving again.

A few things worth knowing about delegation generally:

- **No governance power.** Delegating moves your economic exposure to the validator's
  performance, not your vote — governance weight stays tied to your own `helix tx stake`
  balance only (see [Governance](cli.md#governance)). Want both? Self-stake for the vote, delegate
  separately (to any validator, including a different one) for the yield.
- **You share slashing risk.** If the validator you delegated to double-signs, your pool
  value drops by the same 5% its own self-stake does — this is deliberate, not a bug: it's
  what gives delegators a real reason to pick a reliable validator instead of just the lowest
  commission rate.
- **Undelegating does not outrun a slash.** Double-sign evidence travels as a transaction, so
  it always lands some blocks after the misbehavior it proves. Undelegating in that window
  does not save you: redeemed stake stays slashable for the validator you left, for the whole
  7-day unbonding period, exactly as if it were still in the pool. `helix account` names the
  validator your unbonding stake is still exposed to. Only `tx claim-unbonded`, after the
  period ends, puts the funds beyond reach.
- **Only one unbonding slot at a time**, same as self-staking — claim a pending unbonding
  before starting another (whether from undelegating or unstaking).

### Self-Staking Without a Node (Governance Only)

If you just want a say in governance without operating infrastructure or picking a validator
to trust:

```bash
helix tx stake 100 --key alice.json     # any amount above 0 grants voting power
```

Your voting weight in `helix governance vote` is exactly your staked balance. Unstaking and
claiming work identically to the validator flow above (same 7-day unbonding window, same
commands). This path earns nothing — for yield without running a node, delegate instead (see
above).

---
