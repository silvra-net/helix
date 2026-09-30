# Staking & delegation

> Part of the [Helix documentation](../README.md).

## Staking

Three ways to put HLX to work — they combine freely:

- **Run a validator** — stake and run a node. Produces blocks, earns block rewards and fee tips,
  and votes in governance.
- **Delegate to a validator** — earn a share of its rewards without running anything. No
  governance vote.
- **Stake without a node** — a governance vote, no yield.

### Running a validator

> **Stake the address your node signs with — no other.** The node's identity is its
> `validator-key.json`. Stake a different wallet and that wallet's address becomes a validator
> nothing signs for; it will never be promoted and earns nothing. Step 1 checks this.

1. **Run a node and let it sync** — see [Running a Node](running-a-node.md#running-a-node). Wait
   until `helix chain status` shows peers and a moving height. Then read the address your node
   signs as:
   ```bash
   helix wallet address --key validator-key.json
   ```
   To validate as an existing wallet of yours, make that wallet the node's key instead: point
   `HELIX_VALIDATOR_KEY` at its file, or restore it with
   `helix wallet restore --output validator-key.json` (it asks for the 24 words).
2. **Fund that address and stake from it.** The minimum is 10,000 HLX (a governance parameter —
   `GET /governance/params` shows the current value); keep a margin above it, because a slash
   takes 5% and a validator below the minimum drops out of the set:
   ```bash
   helix tx stake 10000 --key validator-key.json
   ```
   Stake delegated to you counts toward the minimum too.
3. **Wait two epochs** (an epoch is 100 blocks, a few minutes). The first boundary after your
   stake puts you on **probation** — in the signing set, without voting power or proposer turns.
   Your node proves it is running by sending a small, fee-free heartbeat signed with your key (or
   by co-signing a block); the next boundary then makes you a full validator. A staked address
   with no node behind it is never promoted, loses nothing, and simply waits. If you stay on
   probation, your node signs as a different key than the one you staked — check step 1.
   `GET /validators` shows `tier` and `probation_liveness_seen`.
4. **Earn.** The proposer of each block receives its block reward (1 HLX at launch, halving about
   once a year — see [Token Economics](internals.md#token-economics)) and the tips of its
   transactions — what senders paid above the base fee, which is burned. With delegators, the
   reward splits by your self-stake against the delegated total, and you keep a commission on
   their part.
5. **Set your commission** (optional; default 10%, at most 50%):
   ```bash
   helix tx set-commission 1000 --key validator-key.json   # basis points: 1000 = 10%
   ```
   The cap bounds what raising the rate after delegators arrive can take from them.
6. **Pay your rewards to a wallet off the server** (optional, recommended):
   ```bash
   helix tx set-reward-address <address> --key validator-key.json
   helix tx set-reward-address --clear --key validator-key.json   # back to the validator key
   ```
   The validator key has to live on the server; with a reward address set, your rewards,
   tips and commission go to a wallet whose key never does. Your delegators' share is unaffected,
   and `GET /validators` shows every validator's `reward_address`. Double-check it: rewards sent to
   an address you cannot open are gone.
7. **Unstake** when you want out — the stake unbonds for 7 days, and stays slashable meanwhile:
   ```bash
   helix tx unstake <amount> --key validator-key.json
   helix tx claim-unbonded --key validator-key.json     # after the 7 days
   ```
   The last validator cannot unstake below the minimum: that would leave the chain without one.

### Slashing and jailing

**Double-signing** — two different votes for the same height and round — costs 5% of your stake
and 5% of your delegators' pool, and removes you from the active set at once. Each offence is
punished once. **Run one node per key, ever.** The node protects you against itself: it remembers
what it last signed (`validator-key.signing-state.json`) so a restart never signs again, and it
locks its data directory so a second node on the same directory refuses to start. Neither helps
against a copy of the key running on another machine — that one keeps its own memory and can sign
against the first.

**Downtime** costs no HLX, but removes you from the set until you come back deliberately. Each
missed block you should have signed adds 2 to a counter, each signed one takes 1 off, so the
counter grows while you sign less than two thirds of your blocks. At the threshold you are jailed:

- after **1,800 blocks** of complete silence (about an hour);
- and also, over a longer stretch, if you keep signing less than two thirds — what the quorum needs
  from each validator.

Reboots, upgrades and short outages stay far below that. To return, once your node is back and
synced — at least 300 blocks after the jailing, with your stake still at the minimum:

```bash
helix tx unjail --key validator-key.json
```

`helix account <address>` shows whether you are jailed and from which height you can unjail.

### Delegating to a validator

```bash
helix tx delegate <validator-address> 100 --key alice.json   # delegate 100 HLX
helix validator show <validator-address>                     # its pool: delegated total, commission
helix account <your-address>                                 # your positions, under "Delegations"
```

Delegation uses a share pool, like the Cosmos SDK's: you receive shares at the pool's current
value, and every reward the validator earns raises the value of every share. Your position
compounds by itself — there is nothing to claim.

```bash
helix tx undelegate <validator-address> 50 --key alice.json  # take out 50 HLX of current value
helix tx claim-unbonded --key alice.json                      # after the 7-day unbonding
```

- **You share the validator's slashing risk.** A double-sign costs its delegators 5% of their
  position too — which is the reason to choose a reliable validator, not just a cheap one.
- **Undelegating does not escape a slash.** Evidence arrives some blocks after the offence; stake
  you undelegate stays slashable for that validator for the whole 7 days of unbonding.
  `helix account` names the validator your unbonding stake is still exposed to.
- **One unbonding at a time** — claim it before starting another, whether from undelegating or
  unstaking.
- **No governance vote.** Voting weight is your own staked balance only.

### Switching validators

```bash
helix tx redelegate <old-validator> <new-validator> 50 --key alice.json
```

The stake moves at once and keeps earning. It stays slashable for the validator you left for 7
days — switching away from one that already double-signed does not avoid the loss — and during
those 7 days it can neither move on to a third validator nor be undelegated.

### Staking without a node

```bash
helix tx stake 100 --key alice.json
```

Your governance voting weight is your staked balance; unstaking works as above. Opening a proposal
takes a stake of at least the minimum validator stake — see [Governance](cli.md#governance). This
earns nothing; to earn without a node, delegate. (Staking the minimum or more makes the address a
validator candidate; without a node behind it, it stays on probation and never votes in
consensus.)
