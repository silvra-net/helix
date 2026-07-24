# Helix Blockchain (HLX)

[![CI](https://github.com/silvra-net/helix/actions/workflows/ci.yml/badge.svg)](https://github.com/silvra-net/helix/actions/workflows/ci.yml)
[![Release](https://github.com/silvra-net/helix/actions/workflows/release.yml/badge.svg)](https://github.com/silvra-net/helix/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A Layer-1 blockchain secured end-to-end by NIST-standardized post-quantum cryptography.
> **Public testnet live, with independent validators. Mainnet launches once the validator set is proven — by milestone, not by calendar.**

Helix is built from the ground up for the post-quantum era: every signature is NIST
ML-DSA-65 (FIPS 204), not a classical curve with a migration roadmap bolted on later. On
top of that sit Tendermint-style BFT finality, a fuel-metered WASM contract VM, ZK-STARK
proofs (hash-based, no elliptic curves), human-readable names, and social wallet recovery.

**What already works, and is tested.** This is not a whitepaper — it runs. The public
network produces finalized blocks continuously, every client command below talks to it out of
the box, and the core is covered by an automated test suite that gates every commit (the CI
badge above is green on `master`). Recently verified end-to-end on real infrastructure:

- **Post-quantum signatures throughout** — ML-DSA-65 (FIPS 204) on every transaction, block,
  and vote; deterministic state execution reproduced bit-for-bit across independent nodes.
- **BFT consensus between independent validators** — proposals and votes finalize blocks
  across separate nodes, and a validator that drops out halts finality until it returns
  (quorum is real, not cosmetic).
- **Validate from anywhere, even behind a firewall** — nodes reach the network over a
  WebSocket transport that traverses an HTTPS reverse proxy / Cloudflare tunnel, so a new
  operator can run a full validating node without opening a single inbound port.
- **Zero-config onboarding** — a freshly downloaded binary discovers the network, verifies
  genesis independently (it recomputes the genesis state hash rather than trusting the seed),
  syncs history, and follows live — no manual peer configuration.

**What is honestly not there yet.** Several independent validators now secure the public network,
but the set is still small and hardening — small enough that `2/3+1` quorum needs every one of
them, so it tolerates **zero** faults today: if one drops, the chain halts until it returns (four
independent validators is where it first survives a loss). The chain is still a **testnet**:
it is reset from genesis when the format changes, and **HLX on it is a valueless test token,
not an investment.** The consensus and cryptography have not yet had an external security
audit. The road from here to mainnet is deliberately short and public — see
[Roadmap to Mainnet](#roadmap-to-mainnet) — and every gap is documented, not hidden; the
full list is in [Security](#security).

This README is a practical guide: install it, run a node, use the CLI, stake — as an
operator or as a regular holder. Deeper reference material (REST API, wire formats, crate
layout) lives in the [`docs/`](docs/) directory.

**New here? Pick your path:**

- 🖱️ **Prefer a desktop app?** → [Desktop wallet](#desktop-wallet) — download, no shell:
  balance, send, receive, staking, and even running a validator, console included.
- 🧑‍💻 **Just want to try it?** → [Quick Start](#quick-start) gets you from clone to first
  transaction in five commands.
- 💰 **Holding HLX / want to earn rewards?** → [Using the CLI](docs/cli.md#using-the-cli-helix) and
  [Staking](docs/staking.md#staking) (you can delegate without running a node).
- 🖥️ **Running a validator?** → [Installation](docs/installation.md#installation) → [Running a Node](docs/running-a-node.md#running-a-node)
  (terminal), or the desktop app's **Node** tab if you'd rather not touch a shell — both run the
  identical `helix` binary.
- 🔬 **Here for the internals?** → [Consensus](docs/internals.md#consensus), [Cryptography](docs/internals.md#cryptography--determinism),
  and the [Reference](docs/reference.md#reference).

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

## Roadmap to Mainnet

Helix is being built in the open, and the path from today's testnet to a lasting mainnet is
short and concrete. Nothing here is hidden behind a "coming soon."

| Phase | Status | What it means |
|---|---|---|
| **Core protocol** | ✅ Done | PoS + BFT finality, ML-DSA-65 signatures, WASM VM, ZK-STARK proofs, names, social recovery — all implemented and running. |
| **Public testnet** | ✅ Live | `helix.silvra.net` produces finalized blocks continuously; anyone can run a node or use the CLI against it today. |
| **Remote validation** | ✅ Verified | A node behind any HTTPS proxy / firewall can validate over the WebSocket transport — proven end-to-end with independent validators reaching BFT quorum through a Cloudflare tunnel. |
| **Independent validators** | 🔄 Underway | The first external operators are already co-signing the live chain from their own hardware. The set is small and still hardening toward surviving a fault — four is where `3f+1` first tolerates losing one. This is the main gate to mainnet. [Become one →](docs/running-a-node.md#bootstrapping-a-multi-validator-network) |
| **External security audit** | ⏳ Planned | Independent review of consensus and cryptography before value is ever at stake. |
| **Mainnet** | 🎯 When it's earned | Fresh genesis, a freshly generated validator key, no more resets — launched once several independent validators run stably enough to survive a fault, by milestone rather than a fixed date. This is the chain meant to last. |

If you want to help secure the network as one of the founding independent validators, the
infrastructure is ready today — see
[Bootstrapping a Multi-Validator Network](docs/running-a-node.md#bootstrapping-a-multi-validator-network).

---

## Quick Start

> **This is the public testnet, not mainnet.** `helix.silvra.net` is live and stable, but it
> is still reset from genesis when the chain format changes. **HLX on the testnet is a
> valueless test token** — it is for trying the network, not for holding value, and it will
> not carry over to mainnet.
>
> Point a node at it, send transactions, deploy a contract, break things — that is exactly what
> it is for. Mainnet launches from a fresh genesis once several independent validators run stably
> enough to survive a fault — by milestone, not a fixed date; see [Roadmap to Mainnet](#roadmap-to-mainnet).

**One binary does everything.** `helix` is both the node and the client: `helix start` runs a
node, every other subcommand (`helix wallet`, `helix tx`, …) is a thin RPC client. **You don't
need to run a node to use Helix** — the client talks to the live network out of the box,
no setup, no config, no local chain to sync.

```bash
# (assumes `helix` is on your PATH — otherwise use ./target/release/helix)

# 1. Create a wallet (a wallet is just a keypair)
helix wallet new -o alice.json
#   Address    : hlx...
#   Saved to   : alice.json

# 2. Look at the live chain — this already talks to the public network
helix chain status
helix account <some-address>

# 3. Once alice.json has a balance, send some HLX
helix tx send hlx... 10 --key alice.json     # send 10 HLX to another address
helix tx status <hash>                        # check it landed
```

Every client command targets `https://helix.silvra.net` (the public testnet) by
default. Point it somewhere else any time with `--node <url>` or `HELIX_NODE=<url>` — e.g. at
your own local node (below).

### Running your own node

Want to run infrastructure rather than just use the chain? A node also **joins the public
network by default** — on first start it fetches the real genesis and syncs the chain, no
peer to configure:

```bash
helix start          # or ./target/release/helix start
# fetches genesis from the public network, syncs history, then follows the live chain
# REST API on http://127.0.0.1:8545, P2P on 0.0.0.0:8546
```

Point your client at it with `helix --node http://127.0.0.1:8545 <command>`.

### Running your own private devnet

For development or testing you'll want an isolated chain that doesn't touch the public
network. Set `HELIX_NEW_CHAIN=1` — the node self-signs its own genesis and runs standalone:

```bash
HELIX_NEW_CHAIN=1 helix start
```

Its genesis allocates stake only to the validator's own address (there's no faucet), so to
get spendable HLX to a new wallet, send from the validator key itself — it lives at
`./validator-key.json` and is already a valid CLI wallet (same JSON format `helix wallet`
produces):

```bash
helix --node http://127.0.0.1:8545 tx send hlx... 100 --key validator-key.json
```

### Building from source

```bash
git clone https://github.com/silvra-net/helix.git
cd helix
cargo build --release
# single binary: target/release/helix (node + client)
```

---

## Desktop wallet

Prefer not to touch a shell? **Helix Wallet** (`helix-gui`) is a desktop app (Linux, macOS,
Windows) that does everything the CLI does — wallet, send/receive, staking/delegation, names,
recovery, governance — **including running a full validator node**, with a live console. Pick
either the GUI or the [CLI](docs/cli.md#using-the-cli-helix); neither is missing functionality the other has.

- **Download** the installer for your OS from the
  [latest release](https://github.com/silvra-net/helix/releases/latest) —
  `helix-gui-*.AppImage` / `.deb` (Linux), `.dmg` (macOS), `.msi` (Windows). The paired CLI
  archive is named `helix-cli-*` — same versioning, same release, consistent naming.
- **Your key stays on your machine.** It is generated locally, encrypted at rest with the same
  `KeyFile` format the CLI uses, and never leaves the app — the wallet signs transactions itself
  and only talks to a node over its public REST API. The 24-word recovery phrase is shown once
  and also works in the Spark mobile app.
- **Run a node without a terminal.** The exact `helix` binary the CLI ships is bundled into the
  app as a companion process (a Tauri "sidecar" — same code, not a reimplementation). The
  **Node** tab starts/stops it and streams its output live, so becoming a validator is: stake
  enough (same tab), click Start, watch the console for `Block committed`. Prefer a server
  instead? `helix start` in a terminal does the same thing — the two are interchangeable, and
  switching between them later costs nothing (same `validator-key.json`/wallet file either way).
- Same honest caveat as everywhere: it points at the public **testnet** by default, and HLX
  there is a valueless test token that does not survive a chain reset.

Source and build steps are in [`gui/`](gui/README.md). There is also a browser **block
explorer** served by every node at its root URL — open
[helix.silvra.net](https://helix.silvra.net).

---

---

## Documentation

The README covers what Helix is and how to get started. The full reference lives in [`docs/`](docs/):

- **[Installation](docs/installation.md)** — system requirements, prerequisites, release download, building from source
- **[Running &amp; operating a node](docs/running-a-node.md)** — config, environment variables, joining the network, running behind a proxy/tunnel, bootstrapping a multi-validator set, Docker
- **[Using the CLI](docs/cli.md)** — wallets, sending, fees, names, smart contracts, personhood, recovery, governance
- **[Staking &amp; delegation](docs/staking.md)** — run a validator, or delegate to one
- **[Internals](docs/internals.md)** — consensus, architecture, cryptography, token economics
- **[Reference](docs/reference.md)** — REST API, transaction/address formats, crate structure

---

## Security

**Hardening that's in place:**

- **Persistent validator key** is stored unencrypted in `validator-key.json` by default —
  protect this file, or encrypt it (`HELIX_VALIDATOR_KEY_PASSPHRASE` / `helix wallet encrypt`)
- The P2P transport uses libp2p's classical Noise (X25519) encryption; this is fine because all
  P2P traffic is public ledger data — see [Cryptography](docs/internals.md#cryptography--determinism) for the full
  quantum-safety picture
- Per-IP rate limiting and connection limits protect the public RPC and P2P surface from
  simple flood/spam abuse
- Minimum fee (1,000 nano-HLX) prevents zero-cost transaction spam
- Transactions are signature-bound to their sender address, replay-protected by per-account
  nonces, and money-path arithmetic is overflow-checked; delegation uses shares-based accounting
  hardened against rounding/inflation loss
- Double-signing is provable on-chain and slashed; misbehaving peers are scored and banned
- A validator that goes silent is **downtime-jailed** on-chain (`last_commit` +
  `ChainState::jailed_until`) after ~150 blocks of confirmed absence — removed from the active set
  until it submits an explicit `Unjail` transaction, surviving node restarts and carrying no slash
  for downtime alone. That recovers a large-enough set automatically; a set so small that quorum
  needs every validator halts instead — the safe failure, never a fork. See
  [Consensus](docs/internals.md#consensus) and [Staking](docs/staking.md#staking)

**Known limitations (honest status, not finished guarantees):**

- **The live chain is a testnet and is reset from genesis without warning.** Any
  time the chain format changes — a new transaction type, a new state field, a signature or
  hash change — the public chain is wiped and restarted, and this will keep happening until
  the format settles and mainnet launches. Balances do not survive it.
  Nothing on this chain is money. This is a deliberate trade while the protocol is still moving:
  a format change is cheap to make now because there is exactly one account and no external
  holders, and expensive to make once there are. The chain that is meant to persist will be
  launched explicitly, with at least four independent validators; treat every chain before that
  as disposable.

- **The public network runs a small validator set, so it still tolerates zero faults.** Several
  independent validators now co-sign the live chain, but the set is small and still hardening —
  with an equal-stake set that small, `2/3+1` quorum needs every one of them, so if any single
  validator drops, block production halts until it returns (see [Consensus](docs/internals.md#consensus)). The BFT
  machinery is real and tested against a 4-validator set (including killing one mid-flight), but
  fault tolerance is a property of the *deployed* set, not the code: it begins at four independent
  validators (`3f+1`) on separate machines and operators, where the network first survives losing
  one. Until the set is both larger and proven, treat the public chain's liveness as depending on
  its weakest operator. See
  [Bootstrapping a Multi-Validator Network](docs/running-a-node.md#bootstrapping-a-multi-validator-network).

- **BFT cross-round vote locking is implemented but not yet battle-tested at scale.** The
  engine now does Tendermint-style locking: once a validator sees a prevote-quorum for a value
  it locks on it (`locked_value`/`locked_round`), re-proposes that value with a proof-of-lock
  certificate when it proposes a later round, and withholds its prevote from any conflicting
  value that isn't backed by a new-enough POL — the mechanism that prevents two different blocks
  from finalizing at the same height across rounds. This is unit-tested (abstention, controlled
  unlock, POL verification, re-proposal) and the multi-validator integration test passes, but it
  has **not** yet been exercised against a large, genuinely adversarial ≥4-validator network with
  real partitions. Treat fork-safety as implemented-and-tested, not yet independently audited —
  see the [Consensus](docs/internals.md#consensus) maturity note.
- The personhood *authority* is a trust anchor: any one configured authority can vouch for a
  human. This removes a single point of failure for availability, but is not (yet) M-of-N
  threshold issuance.
- **No pruning or archival mode.** `helix-data.redb` keeps every block and every piece of state
  forever and grows without bound — see [System Requirements](docs/installation.md#system-requirements) for measured
  growth on prod. Fine for a young, low-traffic testnet; a real capacity plan (pruning, snapshot
  sync, or a separate archival tier) is needed before disk growth becomes anyone's problem.

Report security issues privately before public disclosure.

---

## License

MIT — see LICENSE file.

---

*Built with Rust. Quantum-secure by design.*
