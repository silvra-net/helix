# Helix Blockchain (HLX)

[![CI](https://github.com/silvra-net/helix/actions/workflows/ci.yml/badge.svg)](https://github.com/silvra-net/helix/actions/workflows/ci.yml)
[![Release](https://github.com/silvra-net/helix/actions/workflows/release.yml/badge.svg)](https://github.com/silvra-net/helix/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> The quantum-secure, human-centric blockchain for everyone.

Helix is a Layer-1 blockchain built from the ground up for the post-quantum era. It uses
NIST-standardized post-quantum cryptography, delivers instant BFT finality, and makes
blockchain accessible to everyday users through human-readable names and social wallet
recovery.

This README is a practical guide: install it, run a node, use the CLI, stake — as an
operator or as a regular holder. Deeper reference material (REST API, wire formats, crate
layout) lives further down for when you need it.

**New here? Pick your path:**

- 🧑‍💻 **Just want to try it?** → [Quick Start](#quick-start) gets you from clone to first
  transaction in five commands.
- 💰 **Holding HLX / want to earn rewards?** → [Using the CLI](#using-the-cli-hlx) and
  [Staking](#staking) (you can delegate without running a node).
- 🖥️ **Running a validator?** → [Installation](#installation) → [Running a Node](#running-a-node).
- 🔬 **Here for the internals?** → [Consensus](#consensus), [Cryptography](#cryptography--determinism),
  and the [Reference](#reference).

<details>
<summary><b>📖 Full table of contents</b></summary>

**Getting started**
- [Why Helix?](#why-helix) — the one-table pitch
- [Quick Start](#quick-start) — clone → node → first transaction
- [Installation](#installation) — prerequisites, release download, build from source

**Running & operating a node**
- [Running a Node](#running-a-node) — config file, environment variables, chain data
- [Joining an existing network](#joining-an-existing-network)
- [Bootstrapping a multi-validator network](#bootstrapping-a-multi-validator-network)
- [Docker deployment](#docker-deployment)

**Using Helix**
- [Using the CLI (`hlx`)](#using-the-cli-hlx) — wallets, sending, names, contracts, personhood, recovery
- [Staking](#staking) — run a validator, or delegate to one
- [Governance](#governance) — propose and vote on protocol parameters

**How it works**
- [Consensus](#consensus) — Proof-of-Stake + BFT finality
- [Architecture](#architecture) — the crate stack
- [Cryptography & Determinism](#cryptography--determinism) — the quantum-safety picture
- [Token Economics](#token-economics) — supply, emission, fees

**Reference**
- [REST API](#rest-api) — endpoints your CLI and apps talk to
- [Transaction / Address formats](#reference) — wire-level detail
- [Security](#security) — hardening notes and current limitations

</details>

---

## Why Helix?

| Problem with existing chains | Helix solution |
|---|---|
| SHA-256 / ECDSA broken by quantum computers | ML-DSA-65 — NIST FIPS 204 |
| PoW wastes energy, PoS creates plutocracy | PoS + Proof of Personhood — 1% voting cap per identity |
| Hexadecimal addresses, no recovery | `alice.hlx` names + social guardian recovery |
| No plan for quantum migration | Algorithm versioning built into the protocol |
| ZK proofs vulnerable (SNARKs use elliptic curves) | ZK-STARKs only — hash-based, quantum-safe |
| Billions lost to smart contract bugs | WASM VM, fuel-metered, deterministic by construction |

---

## Quick Start

The fastest path from a clean checkout to a running node and your first transaction.

```bash
# 1. Build
git clone https://github.com/silvra-net/helix.git
cd helix
cargo build --release
# binaries: target/release/helix (the node), target/release/hlx (the CLI)

# 2. Run a node (starts a fresh devnet genesis on first launch)
./target/release/helix
# leave this running in its own terminal — everything below talks to it over
# its REST API at http://127.0.0.1:8545
```

In a second terminal:

```bash
HLX=./target/release/hlx

# 3. Create a wallet
$HLX wallet new -o alice.json
#   Address    : hlx...
#   Saved to   : alice.json

# 4. Check the chain
$HLX chain status

# 5. Fund it — the node's own validator key already holds the genesis stake, so to move
#    real HLX around you'll first need a funded key (see "Funding a wallet on your own
#    devnet" below). Once alice.json has a balance:
$HLX tx send hlx... 10 --key alice.json     # send 10 HLX to another address
$HLX tx status <hash>                        # check it landed
$HLX account hlx...                          # see the resulting balance
```

That's the whole loop: a wallet is just a keypair, a transaction is a signed JSON object,
and the node is the thing that executes and gossips it. Everything past this point is detail
on top of these five commands.

### Funding a wallet on your own devnet

A freshly started node's genesis allocates stake only to the validator's own address — there
is no faucet. To get spendable HLX to a new wallet on your own devnet, send from the
validator key itself:

```bash
# The node's own signing key lives at ./validator-key.bin and is already a valid
# CLI wallet file (same JSON format `hlx wallet` produces) — use it directly:
$HLX tx send hlx... 100 --key validator-key.bin
```

If you're connecting to someone else's running network instead of starting your own, ask
them for testnet funds the same way — there's no protocol-level faucet.

---

## Installation

### Prerequisites

```bash
# Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# System dependencies (Ubuntu/Debian)
sudo apt-get install pkg-config libssl-dev
```

### Option A: Download a Release

Prebuilt binaries for Linux, macOS (Apple Silicon), and Windows are published on the
[Releases page](https://github.com/silvra-net/helix/releases) for every tagged version
(built automatically by [CI](.github/workflows/release.yml) on every tag push). Download the
archive for your platform, extract it, and you have `helix` and `hlx` ready to run — no Rust
toolchain needed.

### Option B: Build From Source

```bash
git clone https://github.com/silvra-net/helix.git
cd helix
cargo build --release
```

Binaries are placed in `target/release/`:
- `helix` — the node
- `hlx` — the CLI

---

## Running a Node

```bash
./target/release/helix
```

On first start, the node:
- Loads or generates a persistent ML-DSA keypair (`validator-key.bin`)
- Creates the genesis block with the configured HLX allocation (or, if `sync_peer`/
  `HELIX_SYNC_PEER` is set and no local chain exists yet, fetches the *real* genesis from
  that peer instead — see "Joining an Existing Network" below)
- Starts producing blocks every 2 seconds
- Exposes REST API on `http://127.0.0.1:8545`
- Listens for P2P peers on `0.0.0.0:8546`

Everything the CLI and REST API do is just talking to this process — there's no separate
indexer or backend.

### Config File

Instead of setting env vars individually, the node reads an optional `helix.toml`
in the working directory (a different path can be set via `HELIX_CONFIG`). Every
field is optional; the matching env var (if set) always overrides the file, so
existing env-var-only setups keep working unchanged:

```toml
# helix.toml
rpc_bind = "0.0.0.0:8545"
p2p_listen_addr = "0.0.0.0:8546"
reward_address = "hlx..."
sync_peer = "http://seed-host:8545"
validator_crypto_scheme = "ml-dsa"
mempool_tx_ttl_secs = 1800
p2p_public_addr = "helix.example.com"
genesis_extra_validators = "hlx1abc...:100000,hlx1def...:100000"
```

An absent file is not an error (all fields default to unset); a present but
malformed file (bad TOML, or an unknown field) fails node startup.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `HELIX_CONFIG` | `./helix.toml` | Path to the config file described above. |
| `HELIX_REWARD_ADDRESS` | (validator address) | Address that receives the 50% validator fee reward. Set this to your app wallet address so fees land there instead of the signing key. Overrides `reward_address` in `helix.toml`. |
| `HELIX_RPC_BIND` | `127.0.0.1:8545` | REST API bind address. Set to `0.0.0.0:8545` when the node isn't reached through a local reverse proxy/tunnel (e.g. running in a container). Overrides `rpc_bind` in `helix.toml`. |
| `HELIX_P2P_LISTEN` | `0.0.0.0:8546` | P2P listen address. Overrides `p2p_listen_addr` in `helix.toml`. |
| `HELIX_SYNC_PEER` | (none) | `http://host:8545` of a trusted peer — fetches this chain's genesis from it (if you have no local chain yet) and any missing historical blocks. Overrides `sync_peer` in `helix.toml`. Both the one-off startup sync and the live mid-run gap-fill fallback (triggered when a gossiped block arrives ahead of our tip) honor this. |
| `HELIX_VALIDATOR_CRYPTO_SCHEME` | `ml-dsa` | Signature scheme for a newly generated validator key (`ml-dsa` or `sphincs-plus`). Only applies the first time a key is generated — ignored once `validator-key.bin` exists. Overrides `validator_crypto_scheme` in `helix.toml`. |
| `HELIX_VALIDATOR_KEY_PASSPHRASE` | (none) | Passphrase to decrypt `validator-key.bin` if it was encrypted (e.g. via `hlx wallet encrypt`). Not needed for the default plaintext key file. |
| `HELIX_MEMPOOL_TX_TTL_SECS` | `1800` (30 min) | How long an unconfirmed transaction may sit in the mempool before it's evicted, freeing its (sender, nonce) slot. Overrides `mempool_tx_ttl_secs` in `helix.toml`. |
| `HELIX_P2P_PUBLIC_ADDR` | (none) | This node's own externally-dialable host (a domain or public IP, no scheme/port — the configured P2P port is appended automatically). Set this on any node reachable from the outside so it can announce itself to peers via peer exchange (see "Network Resilience" below). Overrides `p2p_public_addr` in `helix.toml`. Leave unset for followers with no public/forwarded port — they still relay addresses they learn from others. |
| `HELIX_GENESIS_EXTRA_VALIDATORS` | (none) | Comma-separated `address:stake_hlx` pairs — additional validators to pre-stake directly at genesis, beyond the one bootstrap validator every chain has always had. Only takes effect for a fresh chain (same caveat as `HELIX_PERSONHOOD_AUTHORITIES`). See "Bootstrapping a Multi-Validator Network" below. Overrides `genesis_extra_validators` in `helix.toml`. |
| `HELIX_P2P_SEED_PEERS` | (none) | Comma-separated libp2p multiaddrs (e.g. `/ip4/1.2.3.4/tcp/8546,/dns4/peer.example/tcp/8546`) to dial directly, in addition to the one derived from `sync_peer`. Use this to wire a validator set into a full mesh — every validator should peer with every other, not hub-and-spoke through one node. Overrides `p2p_seed_peers` in `helix.toml`. |
| `HELIX_P2P_DISABLE_MDNS` | (off) | Set truthy (`1`/`true`) to turn off mDNS LAN auto-discovery, leaving only seed peers + peer exchange. Needed only when two independent Helix networks share a LAN (mDNS would otherwise cross-wire them). Overrides `p2p_disable_mdns` in `helix.toml`. |

```bash
HELIX_REWARD_ADDRESS=hlx... ./target/release/helix
```

### Persistent Validator Key

The node stores its validator keypair in `validator-key.bin` (in the working directory):
- File format: unified `KeyFile` JSON (the same format used by `hlx wallet`) — fields
  `address`, `public_key`, `algo`, `encryption` (`plaintext` or `aes256gcm-argon2id`),
  `secret_key`, plus `kdf_salt`/`nonce` when encrypted
- Generated once on first start (plaintext); reused on every subsequent restart
- Validator address stays the same across restarts
- **Back this file up** — losing it means losing your validator identity
- Because it's the same format as a CLI wallet, you can use it directly as `--key
  validator-key.bin` with any `hlx` command — see the Quick Start's funding step above

### Persistent Chain Data

Blocks and chain state (balances, names, personhood, guardians) are stored in
`helix-data.redb` (in the working directory), a single-file [redb](https://github.com/cberner/redb)
database:
- Written on every finalized block — survives node restarts and crashes
- On startup, the node loads existing state from this file if present, or
  builds/fetches genesis on first run (see above)
- **Back this file up** alongside `validator-key.bin` — losing it loses chain history

### Joining an Existing Network

To sync a new node against an already-running network instead of starting a fresh devnet:

```toml
# helix.toml
sync_peer = "http://seed-host:8545"
```

or `HELIX_SYNC_PEER=http://seed-host:8545 ./target/release/helix`. On first start (no local
`helix-data.redb` yet) the node fetches the peer's real genesis block and governance
parameters, adopts them as its own, then downloads every historical block in order,
verifying each one's signature, validator legitimacy, and chain continuity before applying
it. If sync stops partway (e.g. the peer becomes unreachable), whatever was already applied
stays persisted — just restart with the same `sync_peer` to resume.

Beyond that one-time historical sync, the node also asks `sync_peer` (via `GET /status`)
which port it listens on for P2P and dials it directly for live gossip — this matters
because the P2P layer's other discovery mechanism, mDNS, only ever finds peers on the same
local multicast segment and never works across the open internet, so a `sync_peer` reachable
only over a real network needs this explicit dial to receive any block after the one it
synced at startup. This is best-effort: if it fails (e.g. the peer is running an older
version without `p2p_port` in its `/status`), the node still starts and falls back to
mDNS-only discovery.

### Network Resilience (Peer Exchange)

Two independent discovery mechanisms feed a node's P2P connections: mDNS (LAN-only) and the
one explicit `sync_peer` dial described above. On their own, both leave every follower node
connected to exactly one other peer — the one in its own `sync_peer` setting. That's a
hub-and-spoke topology: if that one hub goes offline, every follower connected only to it is
cut off from the rest of the network, with no path to any other follower, even though those
other followers are still online and reachable.

Peer exchange closes this gap. Every node maintains a set of known-dialable peer addresses
(seeded from its own `p2p_public_addr`, if set, and its `sync_peer`'s resolved address), and
gossips that set to its connected peers — once right after each new connection, and every 30
seconds after that. A node that receives an address it didn't already know dials it directly.
The practical effect: once even a handful of nodes know each other's public addresses, the
network self-heals into a real mesh instead of depending on any single node staying up.

Only nodes with `p2p_public_addr` (or `HELIX_P2P_PUBLIC_ADDR`) set actually announce
themselves — set this on any node with a real, externally-reachable P2P port (a public IP,
or a domain pointing at one, with port `8546`/your configured P2P port open). A node behind
NAT with no forwarded port should leave it unset; it still participates fully, both dialing
addresses it learns and relaying them onward, it just never advertises an address of its own
that nobody could actually reach.

### Bootstrapping a Multi-Validator Network

A chain with exactly one validator has a hard liveness ceiling no amount of peer exchange or
gossip resilience can fix: if that one validator's node goes down, block production stops
completely, full stop — every other node can still relay and store blocks, none of them can
propose or vote on new ones. Growing organically from one validator to several means each new
validator accumulating `MIN_VALIDATOR_STAKE` (100,000 HLX) via block rewards or transfers —
economically real, but on a 1 HLX/block schedule that's weeks to months, far too slow to stand
up a genuinely fault-tolerant network in any reasonable timeframe.

`HELIX_GENESIS_EXTRA_VALIDATORS` (or `genesis_extra_validators` in `helix.toml`) skips that
wait: it pre-stakes additional validators — by address, at whatever stake you choose — directly
into the genesis state, so they're active BFT participants (real proposer rotation, real
voting) from block 0, with no staking transactions or epoch rotation needed:

```toml
# helix.toml, on the node that will self-sign the fresh genesis
genesis_extra_validators = "hlx1bob...:100000,hlx1carol...:100000"
```

Only the node building the *fresh* genesis needs this set — it takes effect once, at first
startup on an empty `helix-data.redb`, exactly like `HELIX_PERSONHOOD_AUTHORITIES`. Every node
that later joins via `sync_peer` automatically adopts the same pre-staked validators as part of
genesis adoption (`GET /genesis` carries the list along), so the whole fleet agrees on the same
validator set without needing this variable set anywhere else. Bob and Carol still need their
own node processes running with the matching `validator-key.bin` (the key whose address you
staked) to actually participate — genesis only grants the stake, it doesn't run their nodes for
them.

**Wire the validators into a full mesh.** BFT relays prevotes and precommits between *all*
validators, so every validator should have a direct P2P connection to every other — not
hub-and-spoke through one seed node. A star topology drops relayed votes and collapses the
moment the hub goes down. Give each validator the others as `HELIX_P2P_SEED_PEERS` (in addition
to its one `sync_peer`), pointing at their P2P ports:

```bash
# on Alice's node (P2P :8546); Bob is bob.example:8546, Carol is carol.example:8546
HELIX_P2P_SEED_PEERS="/dns4/bob.example/tcp/8546,/dns4/carol.example/tcp/8546"
```

On first startup a fresh multi-validator network waits out a short one-time delay for the
gossip mesh to form before producing its first block — so give the fleet a few seconds after
the last validator comes online before expecting height to climb.

**A note on validator count and fault tolerance:** BFT quorum is `2/3 + 1` of total voting
power, and each validator's power is capped at 1% of total raw stake regardless of how much it
actually holds (a decentralization guarantee — see `ValidatorSet::new`). With exactly 3
validators of equal capped power, 2 of them together land *just* short of quorum — meaning
every single block needs all three to vote, so **3 validators tolerate zero of them being
offline**, no better than 1 in the specific sense of "how many can go down before the chain
halts" (though vastly better for censorship-resistance and peer-exchange-style relay
resilience). Real Byzantine fault tolerance for `f` simultaneously faulty/offline validators
needs `3f + 1` — 4 validators to tolerate 1 down, 7 for 2, and so on. Plan validator count
accordingly for how much simultaneous downtime the network actually needs to survive.

### Docker Deployment

A `Dockerfile` is provided for running a validator node without a local Rust toolchain.
It's a multi-stage build (Rust builder → `debian:bookworm-slim` runtime) that produces
a small image containing only the `helix` node binary.

```bash
docker build -t helix-node .

docker run -d --name helix \
  -p 8545:8545 -p 8546:8546 \
  -v helix-data:/data \
  -e HELIX_RPC_BIND=0.0.0.0:8545 \
  helix-node
```

Notes:
- The container's working directory is `/data` — mount a named volume (or bind mount)
  there so `validator-key.bin` and `helix-data.redb` survive container recreation/upgrades.
- `HELIX_RPC_BIND=0.0.0.0:8545` is required for the REST API to be reachable from outside
  the container — the compiled-in default only binds `127.0.0.1`.
- To join an existing network instead of starting a fresh devnet genesis, set
  `HELIX_SYNC_PEER=http://<seed-host>:8545` and expose peer `8546/tcp` to the outside
  world (P2P is TCP-only, no UDP/QUIC in the current transport). If this container has a
  reachable public host/IP, also set `HELIX_P2P_PUBLIC_ADDR` so other nodes can find it
  through peer exchange (see "Network Resilience" above) even if the seed peer later goes
  offline.
- The image has not been pushed to a registry — build it locally or in your own CI.

---

## Using the CLI (`hlx`)

Every `hlx` command talks to a node over its REST API (`--node http://host:8545`, defaults
to `127.0.0.1:8545`) — the CLI itself holds no state beyond whatever wallet file you point
it at.

### Wallets

```bash
hlx wallet new -o alice.json                       # generate a new ML-DSA keypair
hlx wallet new -o alice.json --passphrase "..."     # ...encrypted at rest (AES-256-GCM + Argon2id)
hlx wallet new -o alice.json --scheme sphincs-plus  # ...using SPHINCS+ instead of ML-DSA

hlx wallet info --key alice.json                    # address, public key, algorithm
hlx wallet address --key alice.json                 # just the address (for scripting)
hlx wallet encrypt "newpass" --key alice.json        # add/change passphrase on an existing wallet
hlx wallet encrypt "" --key alice.json               # remove passphrase encryption

# A current validator-key.bin already works directly as --key (see "Persistent
# Validator Key" below) — this is only needed for older raw-byte key files from
# before the node switched to the JSON wallet format:
hlx wallet import-node-key --from old-validator-key.bin -o alice.json
```

A wallet file is portable — it's just JSON. Anyone with the file (and its passphrase, if
encrypted) can sign as that address, so treat it like a private key, because it is one.

### Sending HLX

```bash
hlx tx send hlx... 10.5 --key alice.json            # send 10.5 HLX
hlx tx send hlx... 10.5 --key alice.json --fee 20000  # custom fee (default: 10000 nano-HLX)
hlx tx status <hash>                                 # confirmed / pending / not found
```

### Querying the Chain

```bash
hlx chain status               # height, best hash, peer count, mempool size, sync state
hlx chain latest               # latest block, full transaction list
hlx chain block 142            # block by height
hlx account hlx...             # balance, staked amount, nonce
```

### Human-Readable Names

Register a `name.hlx` alias for your address instead of sharing the raw `hlx...` string:

```bash
hlx name register alice --key alice.json     # registers alice.hlx to alice.json's address
hlx name resolve alice.hlx                   # -> hlx...
```

### Smart Contracts

Contracts are WASM modules; the exported `call` function is the entry point. A small set of
host imports lets a contract read/write its own persistent key-value storage, move real HLX
balance, and read call context (caller, value sent, block height, input data) — see
[Cryptography & Determinism](#cryptography--determinism) for the full host-function ABI and
what it does and doesn't mean for safety. There is deliberately no cross-contract call import
in this version — a contract can only touch its own storage and move its own balance, which
closes off reentrancy as an attack surface entirely rather than requiring every contract
author to defend against it.

```bash
hlx contract deploy my_contract.wasm --key alice.json
#   Contract address: hlx...   (the deployer's own address — see note below)

hlx contract call hlx... --key alice.json --amount 1.5 --fee 50000 --data "hello"
#   --fee also sets the fuel budget for this call — a call that runs out of fuel still
#   charges the fee and advances the nonce, exactly like real gas markets do on revert
#   --data is passed to the contract's call function as raw input bytes (UTF-8 encoded)

hlx contract storage hlx... greeting
#   Reads back one key from the contract's own storage — a debugging/exploration
#   tool, since a contract's storage schema is entirely up to its own bytecode
```

If a call traps (an explicit `unreachable`, an out-of-bounds memory access, or running out of
fuel) every storage write and transfer it made is rolled back completely — nothing it did is
ever partially applied. The fee is still charged and the nonce still advances, since real
compute was spent either way.

> **Note:** a contract's address is currently the same as its deployer's address (no derived
> `CREATE`/`CREATE2`-style contract addresses yet) — one contract per deploying key at a time.

### Proof of Personhood

`hlx identity status <address>` shows an address's verification status
(`Unverified`/`Verified`). Verification itself is intentionally gated behind a network
personhood authority's signature over a ZK-STARK proof (`ProvePersonhood`), not exposed as a
plain CLI flow yet — the point is that Sybil resistance can't come from a client-side command
alone. `hlx identity attest` still exists as a command but always fails on submission: an
earlier, unauthenticated "3 peers vouch for you" attestation path existed and was removed
(the transaction now unconditionally rejects) once it became clear it bypassed the
authority-gated proof entirely.

Verified personhood matters for one thing: it raises your voting-power cap as a validator
from 0.5% to 1% of the network (see [Consensus](#consensus)).
It is not required to hold, send, or stake HLX.

### Social Recovery

Lets a small group of guardians rotate a lost account to a new key, without ever exposing the
original key or requiring a central recovery authority.

```bash
# 1. The account owner registers 3-10 guardians (their addresses, not keys)
hlx recovery register-guardians hlx... hlx... hlx... --key owner.json

# 2. Check the guardian set and quorum threshold at any time
hlx recovery status hlx...
#   Guardians (2 of 3): [...]
#   Quorum is proportional to however many guardians you register (roughly 2/3, rounded
#   up) — not a fixed "3-of-5" regardless of set size, despite what the set size range
#   (3-10) might suggest.

# 3. If the owner loses their key: each guardian independently approves rotating
#    the account to a replacement public key (hex-encoded)
hlx recovery approve hlx... <new_pubkey_hex> --key guardian1.json
hlx recovery approve hlx... <new_pubkey_hex> --key guardian2.json
#    Once enough guardians approve (quorum, shown by `recovery status`), the account's
#    controlling key rotates immediately — the old key is permanently locked out, the new
#    key can now sign for that address. Re-recovery to yet another key later works the same
#    way, any number of times.
```

A single stuck guardian request that never reaches quorum can be cleared at the protocol
level (`CancelRecoveryRequest`, signed by the account owner with their still-valid original
key) so a malicious or unresponsive guardian can't lock you out of ever changing your
guardian set — but there is no `hlx recovery` CLI subcommand for it yet; it currently
requires constructing that transaction directly against the REST API.

### Governance

Any account with a nonzero stake (see [Staking](#staking) — this does *not* require the full
validator minimum) can propose and vote on two runtime-adjustable parameters:
`min-validator-stake` and `fuel-per-fee-unit`.

```bash
hlx governance params                          # current values
hlx governance propose fuel-per-fee-unit 3 --key alice.json
hlx governance list                            # all proposals
hlx governance show 0                          # one proposal's vote tally
hlx governance vote 0 --key alice.json          # cast a stake-weighted yes-vote
```

A proposal passes once yes-votes reach a 2/3-plus-one supermajority of the total stake that
existed *when the proposal was created* (frozen at creation so a voter can't game the
denominator by unstaking after voting), or expires unexecuted after 1000 blocks. Every
address can vote once per proposal.

---

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

1. **Get a node running** (see [Running a Node](#running-a-node)) — its `validator-key.bin`
   is the identity that will stake and produce blocks.
2. **Stake at least the minimum** (100,000 HLX — 0.1% of the total supply) using that same
   key:
   ```bash
   hlx tx stake 100000 --key validator-key.bin
   ```
3. **Wait for the next epoch rotation** (every 100 blocks — at most a few minutes at the 2s
   block time). The validator set is rebuilt from every account meeting the minimum stake —
   counting both self-stake and anything delegated to it (see below) — once included, your
   node starts getting round-robin proposer turns.
4. **Earn**: every block you produce mints you a share of that block's transaction fees (50%
   of each fee; the other 50% is burned) plus a fixed block reward (starts at 1 HLX, halves
   yearly — see [Token Economics](#token-economics)), paid even on empty blocks. If you have
   delegators, your share is proportional to your self-stake versus their delegated total,
   plus a commission cut of theirs (see below) — with none, you keep 100% exactly as before.
5. **Unstaking**: `hlx tx unstake <amount> --key validator-key.bin` moves stake into a
   7-day unbonding period (still slashable during this window) before it's claimable:
   ```bash
   hlx tx unstake 50000 --key validator-key.bin
   # ... 7 days later ...
   hlx tx claim-unbonded --key validator-key.bin
   ```
   You can't unstake below the minimum if you're currently the *only* account meeting it —
   that would empty the validator set and halt the chain, so it's rejected outright rather
   than allowed and left to fail later.
6. **Set your commission** (optional, before or after you have delegators):
   ```bash
   hlx tx set-commission 1000 --key validator-key.bin   # 1000 bps = 10% (the default)
   ```
   Capped at 5000 bps (50%) — not to stop you from legitimately charging more, but to bound
   the "advertise a low rate, raise it once delegators are locked in" rug-pull: even a
   maximally hostile change can never claim more than half of what delegators earn.

**Slashing risk:** double-signing (proposing or voting for two different blocks at the same
height/round) burns 5% of your stake *and* 5% of your delegators' pooled stake, and jails you
from BFT rounds immediately — not just at the next epoch. Run one node per key. Ever.

### Delegating to a Validator

Earn a share of a validator's block rewards without running any infrastructure:

```bash
hlx tx delegate hlxValidatorAddress... 100 --key alice.json    # delegate 100 HLX
hlx validator show hlxValidatorAddress...                       # see the pool: delegated
                                                                  # total, commission, effective stake
hlx account alice_address                                       # see your own position's
                                                                  # current value, under "Delegations"
```

Delegation uses a share-pool model (the same one Cosmos SDK and liquid-staking protocols like
Lido use): you receive pool shares priced at the pool's current value per share, and every
reward the validator earns adds directly to the pool's total value — instantly making every
existing share worth more, with no separate "claim rewards" step. Your position **auto-
compounds** for free; check its current value any time with `hlx account`.

```bash
hlx tx undelegate hlxValidatorAddress... 50 --key alice.json   # redeem 50 HLX of current value
# ... 7 days later (same unbonding queue as self-staking) ...
hlx tx claim-unbonded --key alice.json
```

`undelegate`'s amount is the HLX value you want back (principal plus whatever compounded, or
minus anything lost to a slash since you delegated), not raw shares — the CLI/executor
convert internally. A few things worth knowing:

- **No governance power.** Delegating moves your economic exposure to the validator's
  performance, not your vote — governance weight stays tied to your own `hlx tx stake`
  balance only (see [Governance](#governance)). Want both? Self-stake for the vote, delegate
  separately (to any validator, including a different one) for the yield.
- **You share slashing risk.** If the validator you delegated to double-signs, your pool
  value drops by the same 5% its own self-stake does — this is deliberate, not a bug: it's
  what gives delegators a real reason to pick a reliable validator instead of just the lowest
  commission rate.
- **Only one unbonding slot at a time**, same as self-staking — claim a pending unbonding
  before starting another (whether from undelegating or unstaking).

### Self-Staking Without a Node (Governance Only)

If you just want a say in governance without operating infrastructure or picking a validator
to trust:

```bash
hlx tx stake 100 --key alice.json     # any amount above 0 grants voting power
```

Your voting weight in `hlx governance vote` is exactly your staked balance. Unstaking and
claiming work identically to the validator flow above (same 7-day unbonding window, same
commands). This path earns nothing — for yield without running a node, delegate instead (see
above).

---

## Consensus

Helix uses Tendermint-style BFT finality on top of a Proof-of-Stake validator set:

1. **Propose** — elected validator proposes a new block
2. **Prevote** — all validators prevote (2/3+ needed to advance)
3. **Precommit** — validators precommit (2/3+ = instant finality)
4. **Commit** — block is final, no reorganizations possible

**Block time:** 2 seconds. A stalled round (no quorum within 15 block-time ticks — e.g. the
proposer is offline) automatically advances to the next round-robin proposer instead of
halting the chain.

**Proof of Personhood** caps how much voting power a single identity can accumulate:
- Without verification: voting power capped at 0.5% of the network
- With verification: voting power capped at 1% of the network

> **Maturity note (please read before relying on it).** Helix currently runs as a single- to
> few-validator devnet. The vote-counting, equivocation detection, and double-sign slashing are
> in place and tested, but the engine does **not yet implement Tendermint's cross-round vote
> *locking* (`locked_value` / proof-of-lock)** — the safety mechanism that prevents two
> different blocks from finalizing at the same height across rounds under a network partition or
> a ⅓-Byzantine validator set. This is safe for the single-/few-validator devnet it runs as
> today, but Byzantine-fault-tolerant safety with an untrusted **≥4-validator** set is
> deliberately still on the roadmap, not a finished guarantee. See [Security](#security).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        helix-node                           │
│              (orchestrator, event loop, P2P)                │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ helix-rpc    │ helix-p2p    │helix-consensus│helix-executor  │
│ REST API     │ libp2p       │ PoS + BFT    │ State machine  │
├──────────────┴──────────────┴──────────────┴────────────────┤
│                       helix-storage                         │
│              Persistent (redb-backed HelixDb)               │
├─────────────────────────────────────────────────────────────┤
│  helix-core    │  helix-crypto   │  helix-identity          │
│  Block, Tx     │  ML-DSA, BLAKE3 │  Names, Personhood       │
│  TxType, etc.  │  Addresses      │  Social Recovery         │
└─────────────────────────────────────────────────────────────┘

CLI: hlx (helix-cli)   ←→   REST API :8545   ←→   P2P :8546
```

---

## Cryptography & Determinism

| Primitive | Algorithm | Standard | Quantum-safe |
|---|---|---|---|
| Digital Signatures | ML-DSA-65 | NIST FIPS 204 | ✅ |
| Backup Signatures | SLH-DSA-SHA2-192s | NIST FIPS 205 | ✅ |
| Hashing | BLAKE3 | — | ✅ (2× security margin vs Grover) |
| Zero-Knowledge | ZK-STARKs | — | ✅ (hash-based) |
| Transport | libp2p Noise (X25519) | — | Classical — see note |

> **What is and isn't quantum-safe here.** Everything that goes *onto the ledger* — signatures
> (ML-DSA), the state it commits to, and the hashes/proofs binding it together — is
> post-quantum. The peer-to-peer *transport* encryption is libp2p's classical Noise (X25519),
> which is fine for a blockchain: all P2P traffic (blocks, transactions, votes) is public data
> broadcast to every peer, so there is nothing confidential for a "harvest-now-decrypt-later"
> quantum adversary to steal. What a quantum adversary *could* eventually do — forge signatures
> or rewrite history — is exactly what the post-quantum signature and hash layer prevents. An
> earlier ML-KEM-768 session-encryption overlay was removed: it added key-exchange machinery
> that never actually encrypted anything, so it was misleading complexity rather than added
> security.

**Contract determinism:** `helix-vm` disables WASM floats entirely (via wasmi's
`WasmFeatures` validator gate, rejected at deploy time) — every validator must reach the
identical execution result for the identical call, and floats are a known cross-platform
non-determinism risk (the reason the EVM never got them). Execution is fuel-metered
(`--fee` doubles as the fuel budget), so an out-of-gas contract traps deterministically
instead of hanging a validator.

**Contract host imports:** a contract talks to the chain through a small `(ptr, len)`
byte-buffer ABI under the WASM import module `"env"`:

| Function | Signature | Purpose |
|---|---|---|
| `storage_read` | `(key_ptr, key_len, out_ptr, out_len) -> i32` | Read this contract's own storage |
| `storage_write` | `(key_ptr, key_len, val_ptr, val_len) -> i32` | Write this contract's own storage |
| `transfer` | `(addr_ptr, addr_len, amount) -> i32` | Move real HLX out of this contract's balance |
| `get_caller` / `get_self_address` | `(out_ptr, out_len) -> i32` | The calling address / this contract's own address |
| `get_input` | `(out_ptr, out_len) -> i32` | The `--data` bytes passed with this call |
| `get_value` / `get_block_height` | `() -> i64` / `() -> i64` | HLX sent with this call / current block height |
| `set_return_data` | `(ptr, len) -> i32` | Set this call's return data (not yet surfaced to callers) |

Every storage read/write, transfer, and context read costs fuel, so there's no free way to
grief a validator into doing unbounded work. A contract can **only** read/write its own
storage and move its own balance — there is deliberately no cross-contract call import in
this version, which removes reentrancy as an attack surface entirely rather than requiring
every contract author to defend against it themselves. All effects of a call are buffered and
only committed to real chain state if the call succeeds; a trap (explicit `unreachable`,
out-of-bounds memory access, running out of fuel) rolls back every storage write and transfer
the call made, with zero partial effects — while the fee is still charged and the nonce still
advances, since real compute was spent either way.

---

## Token Economics

- **Hard cap:** 100,000,000 HLX — never more, forever. This is an asymptotic ceiling the
  emission schedule approaches, not an amount handed out at genesis — the same shape as
  Bitcoin's 21M cap.
- **Denomination:** 1 HLX = 1,000,000,000 nano-HLX
- **Fee split:** 50% burned (deflationary) / 50% to block validator
- **Block reward:** a halving issuance schedule mints new HLX every block (independent of
  transaction volume), so validator income doesn't depend on fee revenue alone. Starts at
  1 HLX/block, halves every 15,768,000 blocks (~1 year at the 2s block time) — the same
  geometric-decay shape as Bitcoin's coinbase subsidy, always clamped so cumulative issuance
  never crosses the 100M cap regardless of what the schedule alone would pay out.
- **Minimum validator stake:** 100,000 HLX (0.1% of supply) — runtime-adjustable via
  governance, floored at 0.001% of supply so it can never be pushed low enough to let
  unstaked accounts flood the validator set.
- **Unbonding period:** 7 days from `tx unstake` to claimable — stake stays slashable the
  whole time.
- **Slashing:** 5% of staked HLX burned, plus immediate exclusion from BFT rounds, on
  confirmed double-sign.
- **Circulating supply** = total issued − total burned. Total issued starts small (just the
  genesis validator stake) and grows block by block via the emission schedule above.
- No liquid HLX is pre-mined to any wallet at genesis — the genesis validator receives only
  its bootstrap stake, and earns everything beyond that the same way any future validator
  would: by producing blocks.

---

## REST API

Base URL: `http://127.0.0.1:8545` (or wherever you've bound/proxied it — see `HELIX_RPC_BIND`).

| Method | Path | Description |
|---|---|---|
| GET | `/` | Node info & endpoint list |
| GET | `/status` | Height, hash, mempool size, supply stats |
| GET | `/genesis` | This chain's genesis block + governance params + any `genesis_extra_validators` (used by fresh nodes joining via `sync_peer`) |
| GET | `/blocks/latest` | Latest block with full transaction list |
| GET | `/blocks/height/:n` | Block by height |
| GET | `/blocks/height/:n/header` | Header only (for light clients) |
| GET | `/blocks/height/:n/proof/:tx_hash` | Merkle inclusion proof for a transaction |
| GET | `/blocks/hash/:hash` | Block by hash |
| GET | `/blocks/range` | Range of blocks (`?from=&count=`) |
| GET | `/accounts/:address` | Balance, staked amount, nonce — 400 on invalid address format |
| GET | `/accounts/:address/name` | Registered `.hlx` name for this address |
| GET | `/accounts/:address/personhood` | Proof of Personhood status |
| GET | `/accounts/:address/guardians` | Social-recovery guardian set |
| GET | `/accounts/:address/recovery` | Pending/active recovery status |
| GET | `/accounts/:address/transactions` | Transaction history (`?limit=&offset=`) |
| GET | `/accounts/:address/delegations` | This account's delegations across validators, with current value |
| GET | `/accounts/:address/storage/:key_hex` | One hex-encoded key/value from a deployed contract's own storage |
| GET | `/validators/:address/pool` | A validator's delegation pool — delegated stake, commission, effective stake |
| GET | `/names/:name` | Resolve name to address |
| GET | `/governance/params` | Current runtime-adjustable protocol parameters |
| GET | `/governance/proposals` | All proposals (`?limit=&offset=`) |
| GET | `/governance/proposals/:id` | One proposal's status |
| GET | `/mempool` | Pending transaction count |
| GET | `/sync/blocks` | Raw block range for peer sync (`?from=&count=`) |
| POST | `/transactions` | Submit a signed transaction |
| GET | `/transactions/:hash` | Transaction status (confirmed/pending/not found) |

### Status response

```json
{
  "version": "0.1.0",
  "height": 142,
  "best_hash": "a3f8c2...",
  "peer_count": 0,
  "is_syncing": false,
  "mempool_size": 0,
  "total_accounts": 2,
  "circulating_supply_hlx": 1000141.9995,
  "total_burned_hlx": 0.0005,
  "state_hash": "b3f1a9...",
  "p2p_port": 8546
}
```

`state_hash` is an operator-facing diagnostic (not part of consensus, not signed) — compare it
across nodes at the same height to spot execution divergence. `p2p_port` is this node's own
libp2p listen port — used by a joining peer to dial it directly, see "Joining an Existing
Network" above.

---

## Reference

### Transaction Format

Transactions are signed ML-DSA (or SPHINCS+) objects. The signing hash is
`BLAKE3(bincode::serialize(TxPayload))`, where `TxPayload` excludes `signature` and
`public_key`.

```json
{
  "version": 1,
  "tx_type": "Transfer",
  "from": "hlx...",
  "to": "hlx...",
  "amount": 100000000000,
  "fee": 1000000,
  "nonce": 0,
  "data": [],
  "signature": "<hex>",
  "public_key": "<hex>"
}
```

- `amount` and `fee` are in **nano-HLX** (1 HLX = 1,000,000,000 nano-HLX)
- `nonce` is per-sender, strictly monotonic, starts at 0 — multiple sequential-nonce
  transactions from one sender can be submitted and included in the same block
- Minimum fee: 1,000 nano-HLX
- The mempool validates the signature before accepting

### Address Format

```
hlx  +  Base58( 0x01 ‖ BLAKE3(pubkey)[0..20] ‖ checksum[0..4] )
         ^^^^^
         version byte (ML-DSA = 0x01 — bumped during algorithm migration)
         checksum = BLAKE3(BLAKE3(versioned_payload))[0..4]
```

Example: `hlxmtJXFwsfj1VE4rxseZaS3JvN9dC4vHR7z`

### Crate Structure

| Crate | Description |
|---|---|
| `helix-crypto` | ML-DSA/SPHINCS+ keypairs, BLAKE3 hash, addresses, merkle trees |
| `helix-core` | Block, BlockHeader, Transaction, TxType primitives |
| `helix-executor` | Transaction execution, account state, genesis, fee distribution |
| `helix-consensus` | PoS + BFT engine, validator set rotation, slashing |
| `helix-mempool` | Fee-prioritized pool — sorts by (sender, nonce) within fee tier |
| `helix-storage` | Persistent redb-backed block + chain-state store (`HelixDb`) |
| `helix-p2p` | libp2p networking: gossipsub + mDNS discovery |
| `helix-identity` | Proof of Personhood, human-readable names, social recovery |
| `helix-vm` | WASM contract execution (`wasmi`, fuel-metered, deterministic) |
| `helix-zkp` | ZK-STARK proof generation/verification for Proof of Personhood |
| `helix-rpc` | Axum REST API server (`:8545`) |
| `helix-node` | Node binary — orchestrates all subsystems |
| `helix-cli` | `hlx` command-line tool |

---

## Security

**Hardening that's in place:**

- **Persistent validator key** is stored unencrypted in `validator-key.bin` by default —
  protect this file, or encrypt it (`HELIX_VALIDATOR_KEY_PASSPHRASE` / `hlx wallet encrypt`)
- The P2P transport uses libp2p's classical Noise (X25519) encryption; this is fine because all
  P2P traffic is public ledger data — see [Cryptography](#cryptography--determinism) for the full
  quantum-safety picture
- Per-IP rate limiting and connection limits protect the public RPC and P2P surface from
  simple flood/spam abuse
- Minimum fee (1,000 nano-HLX) prevents zero-cost transaction spam
- Transactions are signature-bound to their sender address, replay-protected by per-account
  nonces, and money-path arithmetic is overflow-checked; delegation uses shares-based accounting
  hardened against rounding/inflation loss
- Double-signing is provable on-chain and slashed; misbehaving peers are scored and banned

**Known limitations (honest status, not finished guarantees):**

- **BFT cross-round vote locking is not implemented yet.** The engine finalizes on a
  Precommit supermajority but has no Tendermint-style `locked_value`/proof-of-lock, so
  Byzantine-fault-tolerant *safety* against an untrusted **≥4-validator** set (partition or
  ⅓-Byzantine scenarios) is still on the roadmap. Fine for the single-/few-validator devnet
  Helix runs as today — see the [Consensus](#consensus) maturity note. Do not run this as an
  open, adversarial multi-validator network expecting fork-safety yet.
- The personhood *authority* is a trust anchor: any one configured authority can vouch for a
  human. This removes a single point of failure for availability, but is not (yet) M-of-N
  threshold issuance.

Report security issues privately before public disclosure.

---

## License

MIT — see LICENSE file.

---

*Built with Rust. Quantum-secure by design.*
