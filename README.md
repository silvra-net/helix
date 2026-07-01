# Helix Blockchain (HLX)

> The quantum-secure, human-centric blockchain for everyone.

Helix is a Layer-1 blockchain built from the ground up for the post-quantum era. It uses NIST-standardized post-quantum cryptography, delivers instant BFT finality, and makes blockchain accessible to everyday users through human-readable names and social wallet recovery.

---

## Why Helix?

| Problem with existing chains | Helix solution |
|---|---|
| SHA-256 / ECDSA broken by quantum computers | ML-DSA (Dilithium3) — NIST PQC standard |
| PoW wastes energy, PoS creates plutocracy | PoS + Proof of Personhood — 1% voting cap per identity |
| Hexadecimal addresses, no recovery | `alice.hlx` names + social guardian recovery |
| No plan for quantum migration | Algorithm versioning built into the protocol |
| ZK proofs vulnerable (SNARKs use elliptic curves) | ZK-STARKs only — hash-based, quantum-safe |
| Billions lost to smart contract bugs | WASM VM + formal verification tooling (Phase 5) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        helix-node                           │
│              (orchestrator, event loop, P2P)                │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ helix-rpc    │ helix-p2p    │helix-consensus│helix-executor  │
│ REST/WS API  │ libp2p       │ PoS + BFT    │ State machine  │
├──────────────┴──────────────┴──────────────┴────────────────┤
│                       helix-storage                         │
│                 redb (blocks + accounts)                    │
├─────────────────────────────────────────────────────────────┤
│  helix-core    │  helix-crypto   │  helix-identity          │
│  Block, Tx     │  ML-DSA, BLAKE3 │  Names, Personhood       │
│  TxType, etc.  │  Addresses      │  Social Recovery         │
└─────────────────────────────────────────────────────────────┘

CLI: hlx (helix-cli)   ←→   REST API :8545   ←→   P2P :8546
```

---

## Cryptography

| Primitive | Algorithm | Standard | Quantum-safe |
|---|---|---|---|
| Digital Signatures | ML-DSA (Dilithium3) | NIST FIPS 204 | ✅ |
| Backup Signatures | SLH-DSA (SPHINCS+) | NIST FIPS 205 | ✅ |
| Hashing | BLAKE3 | — | ✅ (2× security margin vs Grover) |
| Zero-Knowledge | ZK-STARKs | — | ✅ (hash-based) |
| Transport | Noise (X25519) | — | ⚠️ Phase 6: ML-KEM upgrade |

> **Note:** The transport layer (P2P) currently uses X25519 via the Noise protocol — not yet post-quantum. Consensus signatures and all on-chain data are fully quantum-secure. Transport upgrade to ML-KEM is planned for Phase 6.

---

## Token Economics

- **Total supply:** 500,000,000 HLX (fixed)
- **Denomination:** 1 HLX = 1,000,000,000 nano-HLX
- **Fee split:** 70% burned (deflationary) / 30% to block validator
- **Staking:** Minimum stake required to become a validator
- **Voting power cap:** Max 1% of network per verified identity (Proof of Personhood)

---

## Consensus: PoS + BFT + Proof of Personhood

Helix uses Tendermint-style BFT finality on top of a Proof-of-Stake validator set:

1. **Propose** — elected validator proposes a new block
2. **Prevote** — all validators prevote (2/3+ needed to advance)
3. **Precommit** — validators precommit (2/3+ = instant finality)
4. **Commit** — block is final, no reorganizations possible

**Proof of Personhood** prevents stake concentration:
- Validators must have a verified on-chain identity
- Without verification: voting power capped at 0.5% of network
- With verification: voting power capped at 1% of network
- Identity is proven via ZK-STARK (privacy-preserving) or social attestation

---

## Getting Started

### Prerequisites

```bash
# Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# System dependencies (Ubuntu/Debian)
sudo apt-get install pkg-config libssl-dev
```

### Build

```bash
git clone <repo>
cd helix
cargo build --release
```

Binaries are placed in `target/release/`:
- `helix` — the node
- `hlx` — the CLI

### Run a Node (Devnet)

```bash
./target/release/helix
```

The node:
- Generates a fresh ML-DSA keypair on first start
- Creates the genesis block with 100M HLX allocated to the validator
- Starts producing blocks every 2 seconds
- Exposes REST API on `http://127.0.0.1:8545`
- Listens for P2P peers on `0.0.0.0:8546`

---

## CLI Reference (`hlx`)

```bash
# Wallet
hlx wallet new [--output wallet.json]    # Generate new keypair
hlx wallet info [--key wallet.json]      # Show address & public key
hlx wallet address [--key wallet.json]   # Print address only

# Chain queries
hlx chain status                         # Node status, height, supply
hlx chain latest                         # Latest block
hlx chain block <height>                 # Block by height

# Account
hlx account <address>                    # Balance, nonce, stake

# Transactions
hlx tx send <address> <amount_hlx>       # Send HLX
  --key wallet.json                      # Signing key
  --fee <nano_hlx>                       # Custom fee (default: 10000)
hlx tx status <hash>                     # Transaction status

# Options (global)
--node http://127.0.0.1:8545             # Override RPC node
```

### Example: Send HLX

```bash
# Create wallet
hlx wallet new --output alice.json

# Check balance
hlx account $(hlx wallet address --key alice.json)

# Send 10 HLX to Bob
hlx tx send hlxBobsAddressHere... 10.0 --key alice.json
```

---

## REST API

All endpoints return JSON. Base URL: `http://127.0.0.1:8545`

| Method | Path | Description |
|---|---|---|
| GET | `/` | Node info & endpoint list |
| GET | `/status` | Height, hash, mempool, supply stats |
| GET | `/blocks/latest` | Latest committed block |
| GET | `/blocks/height/:n` | Block by height |
| GET | `/blocks/hash/:hash` | Block by hash |
| GET | `/accounts/:address` | Account balance, nonce, stake |
| GET | `/mempool` | Pending transaction count |
| POST | `/transactions` | Submit a signed transaction |

### Example: `/status`

```json
{
  "version": "0.1.0",
  "height": 142,
  "best_hash": "a3f8c2...",
  "peer_count": 3,
  "is_syncing": false,
  "mempool_size": 7,
  "total_accounts": 1842,
  "circulating_supply_hlx": 499999823.7,
  "total_burned_hlx": 176.3
}
```

---

## Address Format

Helix addresses use Base58 encoding with a checksum:

```
hlx  +  Base58( version_byte || blake3(pubkey)[0..20] || checksum )

Example: hlxfd5oBCzmDnBJZSKFm3PHA4nyyTK6ueQo3
         ^^^
         prefix (always "hlx")
```

- **Version byte** = `0x01` (ML-DSA/Dilithium3) — bumped during quantum algorithm migration
- **Checksum** = first 4 bytes of `blake3(blake3(payload))` — catches typos

---

## Crate Structure

| Crate | Description |
|---|---|
| `helix-crypto` | ML-DSA keypairs, BLAKE3 hash, addresses, merkle trees |
| `helix-core` | Block, BlockHeader, Transaction, TxType primitives |
| `helix-executor` | Transaction execution engine, account state machine |
| `helix-consensus` | PoS + BFT engine, validator set, voting |
| `helix-mempool` | Fee-prioritized pending transaction pool |
| `helix-storage` | redb persistence (blocks + accounts) + in-memory store |
| `helix-p2p` | libp2p networking: gossipsub + mDNS discovery |
| `helix-identity` | Proof of Personhood, human-readable names, social recovery |
| `helix-rpc` | Axum REST API server |
| `helix-node` | Node binary — orchestrates all subsystems |
| `helix-cli` | `hlx` command-line tool |

---

## Roadmap

### ✅ Phase 1 — Foundation
- [x] ML-DSA (Dilithium3) keypairs and signatures
- [x] BLAKE3 hashing and Merkle trees
- [x] Address format with checksum and version byte
- [x] Block and Transaction types
- [x] In-memory block store

### ✅ Phase 2 — Living Chain
- [x] BFT consensus engine (single-validator devnet)
- [x] Block production loop (2s block time)
- [x] Fee-prioritized mempool
- [x] Axum REST API (7 endpoints)

### ✅ Phase 3 — State Machine
- [x] Transaction execution (Transfer, Stake, Unstake)
- [x] 70/30 fee burn/validator split
- [x] Genesis state (100M HLX allocation)
- [x] redb persistence (blocks + accounts)
- [x] `hlx` CLI tool (wallet, chain, tx commands)

### ✅ Phase 4 — Networking
- [x] README and documentation
- [x] libp2p 0.54 P2P networking (gossipsub + mDNS peer discovery)
- [x] Block and transaction broadcasting over gossipsub
- [x] Automatic local peer discovery via mDNS
- [x] Wallet passphrase encryption (AES-256-GCM + Argon2id)
- [x] P2P event loop integrated into node (peer count in RPC /status)

### 🔄 Phase 5 — Multi-Validator (current)
- [x] Full BFT round state machine (prevote/precommit)
- [x] ML-DSA signature verification on validator votes
- [x] Validator set rotation (epoch-based, rebuilt from on-chain stake)
- [x] Slashing on double-signing (evidence detection + stake burn)
- [x] P2P vote propagation between peers
- [ ] Proof of Personhood (social attestation)
- [ ] Human-readable names (`alice.hlx`)
- [ ] Social recovery wallets (3-of-5 guardians)

### 📋 Phase 6 — Smart Contracts
- [ ] WASM VM integration
- [ ] Contract deployment and execution
- [ ] Gas metering
- [ ] Formal verification tooling

### 📋 Phase 7 — Production Hardening
- [ ] ML-KEM transport encryption (quantum-secure P2P)
- [ ] ZK-STARK integration (privacy + Proof of Personhood)
- [ ] Quantum algorithm migration protocol
- [ ] On-chain governance (algorithm voting)
- [ ] Light client protocol

---

## Security

- **Do not use devnet keys on mainnet** — keys are stored unencrypted in Phase 1-3
- Wallet encryption (AES-256-GCM + Argon2) is implemented in Phase 4
- The transport layer (Noise/X25519) is not yet post-quantum — on-chain data is
- Report security issues privately before public disclosure

---

## License

MIT — see LICENSE file.

---

*Built with Rust. Quantum-secure by design.*
