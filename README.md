# Helix Blockchain (HLX)

[![CI](https://github.com/silvra-net/helix/actions/workflows/ci.yml/badge.svg)](https://github.com/silvra-net/helix/actions/workflows/ci.yml)
[![Release](https://github.com/silvra-net/helix/actions/workflows/release.yml/badge.svg)](https://github.com/silvra-net/helix/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A Layer-1 blockchain secured end-to-end by NIST-standardized post-quantum cryptography.
> **Public testnet live, with independent validators. Mainnet launches once the validator set is proven — by milestone, not by calendar.**

Helix is built for the post-quantum era from the first line: every signature is ML-DSA-65
(NIST FIPS 204), not a classical curve with a migration plan attached. On top of that sit
Tendermint-style BFT finality, a fuel-metered WASM contract VM, ZK-STARK proofs (hash-based, no
elliptic curves), human-readable `.hlx` names and social wallet recovery.

**It runs.** The public network finalizes a block every two seconds, co-signed by validators
that independent operators run on their own hardware. A freshly downloaded binary finds the
network, checks its genesis against the one compiled in, recomputes the genesis state instead of
trusting the peer that served it, syncs, and follows the chain — with no configuration. Every
client command below talks to it out of the box.

**What it is not yet.** The chain is a **testnet**: it is reset from genesis when its format
changes, and **HLX on it is a valueless test token, not an investment.** The validator set is
still small — see [Security](#security) for what that means for its fault tolerance.

**Pick your path:**

- 🖱️ **Prefer a desktop app?** → [Desktop wallet](#desktop-wallet) — balance, send, receive,
  staking, names, recovery, governance, and running a validator, without a shell.
- 🧑‍💻 **Want to try it?** → [Quick Start](#quick-start): a wallet and your first look at the
  chain in three commands.
- 💰 **Holding HLX, or want to earn rewards?** → [Using the CLI](docs/cli.md#using-the-cli-helix)
  and [Staking](docs/staking.md#staking) — you can delegate without running a node.
- 🖥️ **Running a validator?** → [Installation](docs/installation.md#installation) →
  [Running a Node](docs/running-a-node.md#running-a-node), or the desktop wallet's **Node** tab —
  both run the same `helix` binary.
- 🔬 **Here for the internals?** → [Consensus](docs/internals.md#consensus),
  [Cryptography](docs/internals.md#cryptography--determinism) and the
  [Reference](docs/reference.md#reference).

---

## Why Helix?

| Problem with existing chains | Helix |
|---|---|
| ECDSA and Ed25519 signatures fall to a large quantum computer | ML-DSA-65 (NIST FIPS 204) on every transaction, block and vote |
| Stake buys voting power without limit | Every validator's voting power is capped at 1% of all stake; a verified human reaches the cap with half the stake |
| Hexadecimal addresses, no way back from a lost key | `alice.hlx` names and social recovery through guardians |
| No plan for the next cryptographic migration | The signature scheme is versioned in every transaction |
| ZK proofs that rest on elliptic curves (SNARKs) | ZK-STARKs only — hash-based |
| A contract that runs forever stalls the chain | WASM VM, fuel-metered per transaction and per block, no floating point |

---

## Roadmap to Mainnet

| Phase | Status | What it means |
|---|---|---|
| **Core protocol** | ✅ Done | PoS with BFT finality, ML-DSA-65 signatures, WASM VM, ZK-STARK proofs, names, social recovery — implemented and running. |
| **Public testnet** | ✅ Live | `node.silvra.net` finalizes blocks continuously; anyone can run a node or use the CLI against it. |
| **Validation from anywhere** | ✅ Verified | A validator behind a firewall, NAT or HTTPS proxy takes part over the WebSocket transport — the network's own hub runs behind a Cloudflare tunnel. |
| **Independent validators** | 🔄 Growing | External operators co-sign the live chain from their own hardware. Four validators survive one failure, seven survive two. [Become one →](docs/running-a-node.md#bootstrapping-a-multi-validator-network) |
| **Continuous adversarial review** | 🔄 Ongoing | See [Security](#security). |
| **Mainnet** | 🎯 When it's earned | Fresh genesis, a freshly generated validator key, no more resets — launched once enough independent validators run stably to survive failures. |

---

## Quick Start

> **This is the public testnet.** It is reset from genesis when the chain format changes, and
> HLX on it is a valueless test token that does not carry over to mainnet. Send transactions,
> deploy contracts, break things — that is what it is for.

**One binary does everything.** `helix start` runs a node; every other subcommand
(`helix wallet`, `helix tx`, …) is a client. **You don't need a node to use Helix** — the client
talks to the live network with no setup and no local chain.

```bash
# (with `helix` on your PATH — otherwise ./target/release/helix)

# 1. Create a wallet
helix wallet new -o alice.json --passphrase     # asks for a passphrase twice
#   Address    : hlx...

# 2. Look at the live chain
helix chain status
helix account <address>

# 3. Once alice.json holds HLX, send some
helix tx send <address> 10 --key alice.json
helix tx status <hash>
```

Client commands use a node running on this machine if one answers, and the public testnet
(`https://node.silvra.net`) otherwise. Point them elsewhere with `--node <url>` or
`HELIX_NODE=<url>`.

### Running your own node

A node **joins the public network by default** — on first start it fetches and checks the
genesis, syncs the chain and follows it. Nothing to configure:

```bash
helix start
# REST API on http://127.0.0.1:8545, P2P on port 8546
```

Client commands on the same machine find it by themselves and say so. Everything about operating
one — settings, disk limits, running behind a proxy, becoming a validator — is in
[Running a Node](docs/running-a-node.md#running-a-node).

### A private chain for development

`HELIX_NEW_CHAIN=1` starts a chain of your own instead: the node signs its own genesis and runs
standalone. Its validator key (`./validator-key.json`, a regular CLI wallet file) starts with
10,000 HLX staked and 90,000 liquid, so it can fund other wallets:

```bash
HELIX_NEW_CHAIN=1 helix start
helix --node http://127.0.0.1:8545 tx send <address> 100 --key validator-key.json
```

### Building from source

```bash
git clone https://github.com/silvra-net/helix.git
cd helix
git checkout v0.20.4   # the latest release tag
cargo build --release  # one binary: target/release/helix
```

Build a **release tag** to join the public network. Between releases `master` can carry the
next version's rules — consensus, state or transaction format the running chain does not have
yet — and a node built from it stops with an error as soon as the state it computes departs from
the chain's. Try `master` on a private chain (`HELIX_NEW_CHAIN=1`).

---

## Desktop wallet

**Helix Wallet** is a desktop app for Linux, macOS and Windows that does everything the CLI does
— wallet, send and receive, staking and delegation, names, recovery, governance — **including
running a validator node**, with a live console.

- **Download** it from the [latest release](https://github.com/silvra-net/helix/releases/latest):
  `helix-gui-*.AppImage`, `.deb` or `.rpm` (Linux), `.dmg` (macOS), `.msi` or `.exe`
  (Windows). The command-line tools are the `helix-cli-*` archives of the same release.
- **Your key never leaves your machine.** It is generated locally and stored in the same
  encrypted key-file format as the CLI's; the wallet signs itself and talks to a node only over
  its public API. The 24-word recovery phrase also restores the wallet in the Spark mobile app.
- **It locks itself after 10 minutes without use** and clears the key from memory; a laptop
  closed with the wallet open wakes up locked. The lock protects a wallet with a passphrase — set
  one when you create the wallet, or later under **Settings → Passphrase**.
- **It never pays more than 1 HLX in fees on its own.** A node that lies about the fee level
  cannot make the wallet sign away its balance.
- **It uses your own node if one is running** on the machine, and the public network otherwise.
- **Run a validator without a terminal.** The app bundles the same `helix` binary the CLI ships.
  The **Node** tab starts and stops it and shows its output; stake, click Start, and watch for
  `Block committed`. Switching to a server later costs nothing — same key file either way.

Source and build steps: [`gui/`](gui/README.md).

The **block explorer** at [explorer.silvra.net](https://explorer.silvra.net) shows blocks,
transactions, accounts and validators, including who co-signed each block. It talks to a node
from your own browser and can be pointed at yours; source in
[silvra-net/helix-explorer](https://github.com/silvra-net/helix-explorer). Every node also serves
a **status page about itself** at its own root URL — height, sync state, peers, memory, whether
it is co-signing — compiled into the binary.

---

## Documentation

- **[Installation](docs/installation.md)** — system requirements, downloads, building from source
- **[Running a node](docs/running-a-node.md)** — settings, disk limits, joining the network, proxies and tunnels, validators, Docker
- **[Using the CLI](docs/cli.md)** — wallets, sending, fees, names, contracts, personhood, recovery, governance
- **[Staking and delegation](docs/staking.md)** — run a validator, or delegate to one
- **[Internals](docs/internals.md)** — consensus, architecture, cryptography, token economics
- **[Reference](docs/reference.md)** — REST API, transaction and address formats, crate layout
- **[Integrating Helix](docs/exchange-integration.md)** — for exchanges and custodians: deposits, withdrawals and nonces over the REST API, a Bitcoin-Core-style wallet RPC served by the node itself (`helix.conf`, `helix-cli`, `walletnotify`), the Mesh (Rosetta) Data and Construction API, supply endpoints for listings
- **[Tokenomics](TOKENOMICS.md)** — supply, emission, fees

---

## Security

**Continuous adversarial review.** Helix is developed with Claude, Anthropic's AI model, which
reviews the codebase continuously as part of development — not as a one-off. It attacks the
protocol, networking, wallets and RPC the way an adversary would, runs each attack as a test
before fixing it, and confirms each fix by reverting it and watching that test fail. Dozens of
issues have been found and fixed this way; every one is described in the commit that fixes it.

**In place:**

- **Keys.** Wallet files are readable by their owner only and can be encrypted with a
  passphrase (Argon2id + AES-256-GCM); passphrases are never typed on the command line. The
  validator key can be encrypted too (`HELIX_VALIDATOR_KEY_PASSPHRASE`) — it is not by default,
  so treat `validator-key.json` like the key it is: whoever reads it can sign as your validator
  and get it slashed.
- **Transactions** are bound to their sender, to a per-account nonce and to the chain they were
  signed for — the chain id is the genesis hash, so a signature is valid on exactly one chain.
- **Fees.** Every transaction pays a base fee per byte, which is burned and moves with demand
  (at most ±12.5% per block). Wallets cap a fee they price themselves at 1 HLX.
- **Validators.** Signing two different votes for the same height and round is provable on-chain
  and costs 5% of stake, once per offence. A validator that stops signing is jailed: one that is
  completely silent after 1,800 blocks (about an hour), and one that signs less than two thirds
  of its blocks over time as well. It returns with an explicit `Unjail` transaction.
- **Network.** A node forwards only messages it has decoded and accepted, holds the author —
  never the relaying node — responsible for bad data, bounds every message and response it
  reads, and answers other nodes' requests without holding up its own votes.
- **Node.** It refuses to start on a database from another chain or on a setting it cannot read,
  instead of guessing, and stops writing — with its database intact — before the disk is full
  (Linux and macOS).
  `GET /diagnostics` reports its state, including how its previous run ended, without addresses,
  paths or keys ([Reference](docs/reference.md#diagnostics-response)).

**Known limitations:**

- **The testnet is reset** whenever the chain format changes, until mainnet. Balances do not
  survive a reset; nothing on this chain is money.
- **Fault tolerance is a property of the running set, not of the code.** `n` validators survive
  `⌊(n−1)/3⌋` failures: four survive one, seven survive two. The public set is still small, so
  the chain depends on its operators keeping their nodes up; when too many are missing it stops
  and waits — it does not fork. The [explorer](https://explorer.silvra.net) shows the current
  set.
- **Consensus at scale is shown in tests, not yet in production.** Vote locking, re-proposal and
  equivocation handling are exercised by fault-injection and chaos tests — five engines with a
  third of all messages lost, no fork in any run — and by multi-node tests with real processes.
  The live network is still small.
- **Proof of personhood rests on trusted authorities**, any one of which can vouch for a human.
  The public testnet configures none, so personhood is off there.
- **The P2P transport is encrypted with classical cryptography** (libp2p Noise, X25519). What it
  carries is public ledger data, and every transaction, block and vote in it is ML-DSA-signed: a
  quantum attacker could read the traffic but not forge any of it. Details in
  [Cryptography](docs/internals.md#cryptography--determinism).

Please report security issues privately before public disclosure.

---

## License

MIT — see [LICENSE](LICENSE).
