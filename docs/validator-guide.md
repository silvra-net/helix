# Running a validator — a guide

> Part of the [Helix documentation](../README.md). This is the path from an empty machine to a
> validator that signs every block, in one place. The reference for each step is linked; nothing
> here replaces it.

**In short:** a machine that stays on, the release binary under a supervisor, a disk limit, sync
first, stake from the node's own key, then watch one line in the log.

---

## 1. Choose the machine

A validator is expected to sign **every block, around the clock**. Each block it should have signed
and did not adds to a downtime debt, and after about **1,800 blocks of silence — 45 to 50 minutes**
at the chain's current pace — it is jailed: out of the set until it unjails, and from protocol 2 on
also slashed — 1 %, 3 %, then 5 % of its stake and its delegators' pool, burned, for each jail
within about 30 days (see [Slashing and jailing](staking.md#slashing-and-jailing)). Restarts and
updates cost a few blocks and are absorbed. A laptop that sleeps is not.

What one validator used on mainnet in its first week (measured 2026-10-14; the chain then made
about 55,000 blocks a day, one every 1.6 s on average, with 16 active validators):

| | Measured | Plan for |
|---|---|---|
| **CPU** | well under one core | 2 vCPU |
| **Memory** | 250–330 MB, flat, with `MALLOC_ARENA_MAX=2` | 1 GB minimum, 2 GB comfortable |
| **Disk** | ~50 KB per block, **~2.8 GB a day** without a limit | with `HELIX_KEEP_BYTES=20G`: up to 32 GB for the database (it grows in doubling steps) plus room for the system; below 1 GiB free the node stops — see [Disk usage](running-a-node.md#disk-usage) |
| **Network** | see the three profiles below | always on; a stable line matters more than a fast one |

Pick the profile that matches the machine. The settings are environment variables (or the same
names in `helix.toml`, see [Configuration](running-a-node.md#configuration)).

### Profile A — a server in a data center (recommended)

```ini
Environment=MALLOC_ARENA_MAX=2
Environment=HELIX_KEEP_BYTES=20G
```

and **open port 8546/tcp inbound**, so the other validators reach you directly instead of through
one hub. Relay stays on (the default): your node passes every message on to every peer, which
costs upload and makes the network more robust. That is the right trade on a data-center line.

### Profile B — a home connection

Everything from A, plus:

```ini
Environment=HELIX_P2P_RELAY=off
# From 1.1.0:
# Environment=HELIX_P2P_OUTBOUND_PEERS=4
```

Every peer passes every message on to every other, so a node hears each vote and block once per
peer — and with relay on it sends each one on to all of them again. On the production validator, on
a ~25 Mbit down / ~10 Mbit up home line:

| Setting | Download | Upload |
|---|---|---|
| not in the validator set (following only) | ~85 kB/s | — |
| relay on, as a validator (2026-10-13) | — | the whole ~1.2 MB/s upload, for days |
| relay off, as a validator, 12 peers it dialed | ~2.2 MB/s | ~0.7 MB/s* |
| relay off, as a validator, at most 4 peers it dials | ~0.9–1.0 MB/s | ~0.6 MB/s* |

\* Including about 0.4 MB/s that node serves to others over its public RPC. A home validator that
serves no public RPC sends less.

With relay off a validator still hears every proposal and vote, finalizes each block itself and
follows finished blocks by block sync instead of hearing every peer's copy of them (1.0.1). It signed
82–84 % of the certificates in the first hours — the jail threshold is two thirds. Do **not** relay
off a node that other nodes reach the network only through. If you also serve your RPC publicly,
pace what it sends to joining nodes: `HELIX_RPC_SYNC_RATE=400K` (well below your upload). Details:
[On a home connection](running-a-node.md#on-a-home-connection).

### Profile C — a small machine (1 GB RAM, a small disk)

Everything from A, with a tighter disk limit, and join from a checkpoint (step 3) instead of
replaying every block:

```ini
Environment=MALLOC_ARENA_MAX=2
Environment=HELIX_KEEP_BYTES=10G      # the database stays under 16 GB
```

A 1 GB machine runs a validator; it has no room for anything heavy beside it.

---

## 2. Install and run it as a service

Download `helix-cli-<version>-<platform>` from the
[Releases page](https://github.com/silvra-net/helix/releases), unpack it, and check it:

```bash
./helix --version          # the version you downloaded
```

Run it under a supervisor that restarts it — systemd, for example, with the settings of your
profile ([full example](running-a-node.md#running-it-as-a-service)):

```ini
# /etc/systemd/system/helix.service
[Service]
User=helix
WorkingDirectory=/var/lib/helix
ExecStart=/usr/local/bin/helix start
Environment=MALLOC_ARENA_MAX=2
Environment=HELIX_KEEP_BYTES=20G
Restart=on-failure
RestartSec=5
```

The working directory holds everything the node keeps. Stop it with `systemctl stop helix`, never
with `kill -9`.

## 3. Join the chain, and wait until it is synced

**Fast, from a checkpoint** (recommended for profile C, and for anyone who does not want to replay
every block):

```bash
curl -s https://node.silvra.net/sync/checkpoint     # <height>:<block hash>:<state root>
```

Set it once, for the first start only: `Environment=HELIX_TRUSTED_CHECKPOINT=<the whole line>`. The
checkpoint is what your node trusts instead of replaying history — if you can ask more than one node,
ask and compare; if `node.silvra.net` is the only one you can reach, you trust its operator, the same
one who publishes the release. See [Joining fast from a checkpoint](running-a-node.md#joining-fast-from-a-checkpoint).

**Or by replay** — set nothing, and the node downloads and verifies every block from genesis. That
takes hours, and a disk limit applies while it catches up.

Either way, **do not stake until the node is synced**:

```bash
helix chain status          # "Syncing : false", Peers above 0, and the height moving
```

## 4. Look after the key

On its first start the node creates `validator-key.json` — your validator's identity.

```bash
helix wallet address --key validator-key.json       # the address your node signs as
chmod 600 validator-key.json
```

- **Back it up off the machine** (with `validator-key.signing-state.json` beside it). Losing it loses
  the validator; whoever reads it can sign as you.
- **Never run two nodes with the same key** — not even briefly, not as a "backup node". Two nodes sign
  two different votes, and that is slashed: 5 % of the stake, and out of the set.
- Want to validate as a wallet you already have? Make that wallet the node's key before you stake —
  see [Running a validator](staking.md#running-a-validator), step 1.

## 5. Stake from the node's key

The minimum is **10,000 HLX** (a governance parameter; `helix governance params` shows it). Keep a
margin above it — a slash takes 5 %, and below the minimum a validator drops out of the set — and
keep some HLX liquid for fees:

```bash
helix tx stake 14000 --key validator-key.json       # e.g. from a 15,000 HLX balance
```

**Stake the address from step 4, and no other.** Staking from a different wallet makes *that*
address a validator nothing signs for.

## 6. Wait for activation — two epoch boundaries

An epoch is 100 blocks, a few minutes. The first boundary after your stake puts you on
**probation** (in the signing set, no voting power yet); your node proves it is running by itself
(a small fee-free heartbeat, or a signature in a block); the next boundary makes you **active**.

```bash
curl -s https://node.silvra.net/validators | jq '.validators[] | select(.address=="<your address>") | {tier, active, probation_liveness_seen}'
```

Stuck on probation for more than a couple of epochs almost always means the node signs as a
different key than the one you staked — compare with step 4.

## 7. Confirm it signs

Under protocol 2 a validator starts its first epochs owing a downtime debt of 2,400 (of the 3,600
that jail): one whose node does not sign is jailed after 600 blocks. A validator that signs pays it
off within hours — `helix account` shows the debt going down.

Once a minute the node writes a health line. A validator doing its job:

```
Health: ✓ validating · last co-signed #362172 (3s ago) · height 362173 · peers 5
```

The same on the node's own status page (`http://127.0.0.1:8545` in a browser) and in
`curl -s localhost:8545/diagnostics | jq` (`last_cosigned_secs_ago`). On
[explorer.silvra.net](https://explorer.silvra.net) your address appears in the validator panel with
its attendance over the last blocks.

## 8. Optional: rewards and commission

```bash
helix tx set-reward-address <a wallet whose key is not on the server> --key validator-key.json
helix tx set-commission 1000 --key validator-key.json      # basis points: 1000 = 10 %
```

See [Running a validator](staking.md#running-a-validator), steps 5–6.

---

## Day to day

- **Updates:** stop the node, replace the binary, start it. Data, key and stake stay. A release that
  needs more says so in its notes.
- **Protocol upgrades** change the rules at a height stakers voted for. A node whose release does not
  support the new version stops cleanly before that height and says so every minute beforehand —
  install the release that does, before the height. `helix governance params` shows a scheduled
  upgrade; see [Protocol upgrades](running-a-node.md#protocol-upgrades).
- **Restarts** cost a few blocks of downtime debt and are paid back by signing; a nightly restart
  is fine.
- **Jailed anyway?** Bring the node back, let it sync, then `helix tx unjail --key validator-key.json`
  (allowed from the height `helix account <address>` names). Under protocol 2 the jail has cost
  stake; below 10,000 HLX, stake more first. A validator left jailed for a week after that height
  is unbonded.
- **Never** delete `helix-data.redb` — rename it if you want it gone; the chain can always be fetched
  again.

## When something is wrong

| What you see | What it usually is | What to do |
|---|---|---|
| `tier` stays `probationary` | the node signs as another key than the staked one | step 4: compare addresses; fix the node's key, not the stake |
| Health line says the node is **BEHIND** what peers claim, for long | the line cannot carry blocks fast enough, or the node is stuck | home line: profile B; otherwise restart once, do not delete data |
| `NOT reachable from the outside` | port 8546 closed | open it (profile A); a node takes part fully without it, only less robustly |
| Node refuses to start: database of another chain | a database from the test network or another chain | rename `helix-data.redb` and `helix-peers.txt`; keep the key and signing state |
| `jailed_until` in `helix account` | downtime | see "Jailed anyway?" above |
| The node keeps stopping | memory, disk, or the supervisor | [When your node keeps stopping](running-a-node.md#when-your-node-keeps-stopping) — and `/diagnostics` is safe to share when asking for help |
