# Helix Blockchain (HLX)

> The quantum-secure, human-centric blockchain for everyone.

Helix is a Layer-1 blockchain built from the ground up for the post-quantum era. It uses NIST-standardized post-quantum cryptography, delivers instant BFT finality, and makes blockchain accessible to everyday users through human-readable names and social wallet recovery.

---

## Why Helix?

| Problem with existing chains | Helix solution |
|---|---|
| SHA-256 / ECDSA broken by quantum computers | ML-DSA (Dilithium3) — NIST FIPS 204 |
| PoW wastes energy, PoS creates plutocracy | PoS + Proof of Personhood — 1% voting cap per identity |
| Hexadecimal addresses, no recovery | `alice.hlx` names + social guardian recovery |
| No plan for quantum migration | Algorithm versioning built into the protocol |
| ZK proofs vulnerable (SNARKs use elliptic curves) | ZK-STARKs only — hash-based, quantum-safe |
| Billions lost to smart contract bugs | WASM VM + formal verification tooling (Phase 6) |

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
│                    In-memory (MemBlockStore)                 │
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
| Transport | Noise (X25519) | — | ⚠️ Phase 7: ML-KEM upgrade |

> **Note:** The transport layer (P2P) currently uses X25519 via the Noise protocol — not yet post-quantum. Consensus signatures and all on-chain data are fully quantum-secure.

---

## Token Economics

- **Hard cap:** 100,000,000 HLX — never more, forever
- **No inflation:** No new tokens are ever minted after genesis
- **Denomination:** 1 HLX = 1,000,000,000 nano-HLX
- **Fee split:** 50% burned (deflationary) / 50% to block validator
- **Minimum validator stake:** 100,000 HLX (0.1% of supply)
- **Slashing:** 5% of staked HLX burned on confirmed double-sign
- **Circulating supply** = total supply − total burned (starts at 100M, only decreases)

### Genesis allocation (devnet)
| Account | Amount | Purpose |
|---|---|---|
| Admin wallet | 99,000,000 HLX | Liquid, spendable |
| Validator | 1,000,000 HLX staked | Genesis stake — earns fees, cannot spend |

---

## Consensus: PoS + BFT + Proof of Personhood

Helix uses Tendermint-style BFT finality on top of a Proof-of-Stake validator set:

1. **Propose** — elected validator proposes a new block
2. **Prevote** — all validators prevote (2/3+ needed to advance)
3. **Precommit** — validators precommit (2/3+ = instant finality)
4. **Commit** — block is final, no reorganizations possible

**Block time:** 2 seconds. Tested stable at 15+ simultaneous transactions per block with no delay.

**Proof of Personhood** prevents stake concentration:
- Without verification: voting power capped at 0.5% of network
- With verification: voting power capped at 1% of network

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

On first start, the node:
- Loads or generates a persistent ML-DSA keypair (`validator-key.bin`)
- Creates the genesis block with the configured HLX allocation
- Starts producing blocks every 2 seconds
- Exposes REST API on `http://127.0.0.1:8545`
- Listens for P2P peers on `0.0.0.0:8546`

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `HELIX_REWARD_ADDRESS` | (validator address) | Address that receives the 50% validator fee reward. Set this to your app wallet address so fees land there instead of the signing key. |
| `HELIX_RPC_BIND` | `127.0.0.1:8545` | REST API bind address. Set to `0.0.0.0:8545` when the node isn't reached through a local reverse proxy/tunnel (e.g. running in a container). |
| `HELIX_SYNC_PEER` | (none) | `http://host:8545` of a trusted peer to fetch missing historical blocks from on startup. |
| `HELIX_VALIDATOR_CRYPTO_SCHEME` | `ml-dsa` | Signature scheme for a newly generated validator key (`ml-dsa` or `sphincs-plus`). Only applies the first time a key is generated — ignored once `validator-key.bin` exists. |

```bash
HELIX_REWARD_ADDRESS=hlx... ./target/release/helix
```

### Persistent Validator Key

The node stores its ML-DSA keypair in `validator-key.bin` (in the working directory):
- File format: `sk_bytes (4032 bytes) ‖ pk_bytes (1952 bytes)` = 5984 bytes total
- Generated once on first start; reused on every subsequent restart
- Validator address stays the same across restarts
- **Back this file up** — losing it means losing your validator identity

Use the start script for a consistent setup:
```bash
./scripts/start-node.sh
```

### Persistent Chain Data

Blocks and chain state (balances, names, personhood, guardians) are stored in
`helix-data.redb` (in the working directory), a single-file [redb](https://github.com/cberner/redb)
database:
- Written on every finalized block — survives node restarts and crashes
- On startup, the node loads existing state from this file if present, or
  builds genesis state on first run
- **Back this file up** alongside `validator-key.bin` — losing it loses chain history

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
  Losing that volume means losing the validator identity and chain history, same as a
  bare-metal deployment (see the two sections above).
- `HELIX_RPC_BIND=0.0.0.0:8545` is required for the REST API to be reachable from outside
  the container — the compiled-in default only binds `127.0.0.1`.
- To join an existing network instead of starting a fresh devnet genesis, set
  `HELIX_SYNC_PEER=http://<seed-host>:8545` and expose peer `8546/tcp` to the outside
  world (P2P is TCP-only, no UDP/QUIC in the current transport).
- The image has not been pushed to a registry — build it locally or in your own CI.

---

## CLI Reference (`hlx`)

```bash
# Wallet
hlx wallet new [--output wallet.json]            # Generate new ML-DSA keypair
hlx wallet info [--key wallet.json]              # Show address & public key
hlx wallet address [--key wallet.json]           # Print address only

# Chain queries
hlx chain status                                 # Node status, height, supply
hlx chain latest                                 # Latest block
hlx chain block <height>                         # Block by height

# Account
hlx account <address>                            # Balance, nonce, stake

# Transactions
hlx tx send <to_address> <amount_hlx>            # Send HLX
  --key wallet.json                              # Signing key
  --fee <nano_hlx>                              # Custom fee (default: 10000)
  --nonce <n>                                   # Override nonce (auto-fetched if omitted)
hlx tx status <hash>                             # Transaction status

# Names
hlx name register <name> [--key wallet.json]    # Register alice.hlx
hlx name resolve <name>                         # Resolve name to address

# Proof of Personhood
hlx identity attest <address> [--key ...]       # Attest a human
hlx identity status <address>                   # Show verification status

# Social recovery (3-of-5 guardians)
hlx recovery register-guardians <addr>...       # Set guardians
hlx recovery approve <target> <new_pubkey_hex>  # Guardian vote
hlx recovery status <address>                   # Guardian set & pending vote

# Options (global)
--node http://127.0.0.1:8545                    # Override RPC node URL
```

---

## REST API

Base URL: `http://127.0.0.1:8545` (proxied via nginx to `https://helix.silvra.net` in production)

| Method | Path | Description |
|---|---|---|
| GET | `/` | Node info & endpoint list |
| GET | `/status` | Height, hash, mempool size, supply stats |
| GET | `/blocks/latest` | Latest block with full transaction list |
| GET | `/blocks/height/:n` | Block by height |
| GET | `/blocks/hash/:hash` | Block by hash |
| GET | `/accounts/:address` | Balance (HLX), nonce, staked amount — 400 on invalid address format |
| GET | `/accounts/:address/name` | Registered `.hlx` name for this address |
| GET | `/accounts/:address/personhood` | Proof of Personhood status |
| GET | `/accounts/:address/guardians` | Social-recovery guardian set |
| GET | `/accounts/:address/recovery` | Pending/active recovery status |
| GET | `/names/:name` | Resolve name to address |
| GET | `/mempool` | Pending transaction count |
| POST | `/transactions` | Submit a signed transaction |

### Block response (includes full transaction list)

```json
{
  "hash": "a3f8c2...",
  "height": 142,
  "timestamp": 1782900000000,
  "tx_count": 3,
  "validator": "hlx...",
  "prev_hash": "...",
  "merkle_root": "...",
  "transactions": [
    {
      "hash": "6f6559...",
      "from": "hlxnxh...",
      "to": "hlxmtJ...",
      "amount_hlx": 100.0,
      "fee_hlx": 0.001,
      "tx_type": "Transfer",
      "nonce": 0
    }
  ]
}
```

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
  "circulating_supply_hlx": 99999999.9995,
  "total_burned_hlx": 0.0005
}
```

---

## Transaction Format

Transactions are signed ML-DSA objects. The signing hash is `BLAKE3(bincode::serialize(TxPayload))` where `TxPayload` excludes `signature` and `public_key`.

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
- `nonce` is per-sender, strictly monotonic, starts at 0
- Minimum fee: 1,000 nano-HLX
- The mempool validates the signature before accepting

### Nonce behaviour

The executor validates nonces strictly. Multiple TXs from the same sender with sequential nonces (`N`, `N+1`, `N+2`) are all safe to submit in the same block — the mempool sorts them by `(sender, nonce)` before block inclusion.

---

## Address Format

```
hlx  +  Base58( 0x01 ‖ BLAKE3(pubkey)[0..20] ‖ checksum[0..4] )
         ^^^^^
         version byte (ML-DSA = 0x01 — bumped during algorithm migration)
         checksum = BLAKE3(BLAKE3(versioned_payload))[0..4]
```

Example: `hlxmtJXFwsfj1VE4rxseZaS3JvN9dC4vHR7z`

---

## Fee Distribution (50/50 Split)

Every confirmed transaction fee is split at execution time:

```
Fee (nano-HLX)
  ├── 50% → burned (subtracted from circulating_supply permanently)
  └── 50% → fee recipient

Fee recipient = HELIX_REWARD_ADDRESS env var (if set) OR block validator address
```

This makes HLX deflationary by design: every transaction reduces supply.

---

## Crate Structure

| Crate | Description |
|---|---|
| `helix-crypto` | ML-DSA keypairs, BLAKE3 hash, addresses, merkle trees |
| `helix-core` | Block, BlockHeader, Transaction, TxType primitives |
| `helix-executor` | Transaction execution, account state, genesis, fee distribution |
| `helix-consensus` | PoS + BFT engine, validator set rotation, slashing |
| `helix-mempool` | Fee-prioritized pool — sorts by (sender, nonce) within fee tier |
| `helix-storage` | Persistent redb-backed block + chain-state store (`HelixDb`) |
| `helix-p2p` | libp2p networking: gossipsub + mDNS discovery |
| `helix-identity` | Proof of Personhood, human-readable names, social recovery |
| `helix-rpc` | Axum REST API server (`:8545`) |
| `helix-node` | Node binary — orchestrates all subsystems |
| `helix-cli` | `hlx` command-line tool |

---

## Roadmap

### ✅ Phase 1 — Foundation
- [x] ML-DSA (Dilithium3) keypairs and signatures
- [x] BLAKE3 hashing and Merkle trees
- [x] Address format with checksum and version byte
- [x] Block and Transaction types

### ✅ Phase 2 — Living Chain
- [x] BFT consensus engine (single-validator devnet)
- [x] Block production loop (2s block time)
- [x] Fee-prioritized mempool with nonce ordering
- [x] Axum REST API (12 endpoints, full block TX data)

### ✅ Phase 3 — State Machine
- [x] Transaction execution (Transfer, Stake, Unstake)
- [x] 50/50 fee burn / validator split
- [x] 100M HLX hard cap — no inflation ever
- [x] Configurable fee reward address (`HELIX_REWARD_ADDRESS`)
- [x] Genesis state with pre-staked validator
- [x] `hlx` CLI tool

### ✅ Phase 4 — Networking & Hardening
- [x] libp2p P2P networking (gossipsub + mDNS)
- [x] Block and transaction broadcasting
- [x] Wallet passphrase encryption (AES-256-GCM + Argon2id)
- [x] Persistent validator keypair (`validator-key.bin`)
- [x] Slashing on double-signing (5% stake burned)
- [x] Validator minimum stake (100,000 HLX)

### ✅ Phase 5 — Identity & Recovery
- [x] Proof of Personhood (social attestation)
- [x] Human-readable names (`alice.hlx`)
- [x] Social recovery wallets (3-of-5 guardians)

### 🔄 Phase 6 — Smart Contracts
- [x] WASM VM integration (`helix-vm` crate, `wasmi` interpreter, fuel-metered, no host imports)
- [x] Contract deployment and execution (`DeployContract`/`CallContract` txs; deployer address doubles as the contract account — no derived contract addresses yet)
- [x] Gas metering (fuel-based; `tx.fee` currently doubles as the execution fuel budget — no separate gas-price market yet)
- [ ] Formal verification tooling

### 📋 Phase 7 — Production Hardening
- [x] Persistent block storage (redb on disk)
- [x] BFT round-timeout — a stalled round (no quorum within 3 block-time ticks) auto-advances to the next round-robin proposer instead of halting the chain
- [x] ML-KEM transport encryption (quantum-secure P2P) — ML-KEM-768 (NIST FIPS 203) key encapsulation in `helix-crypto`; per-peer post-quantum session keys established via `helix/session/1.0.0` gossipsub handshake (Hello/KemCt); session keys derived with BLAKE3 and used for AES-256-GCM message encryption — layered on top of Noise (X25519) for defense-in-depth
- [x] ZK-STARK integration — `helix-zkp` crate (winterfell 0.13, Blake3 Merkle commitments, ~95 bits conjectured security); `PersonhoodAir` 64-row squaring circuit (`C = secret^(2^63)` in the 128-bit prime field); `TxType::ProvePersonhood` submits a STARK proof on-chain; executor verifies proof + marks account `PersonhoodStatus::Verified`; 4 tests: roundtrip, wrong-commitment rejected, truncated proof rejected, distinct commitments per secret
- [x] Quantum algorithm migration protocol — crypto-agility in key files (scheme-tagged `[tag][sk][pk]`), `CryptoScheme` dispatch for signing and verification, `Vote::crypto_version` and `BlockHeader::crypto_version` propagate the scheme through consensus; `HELIX_VALIDATOR_CRYPTO_SCHEME=sphincs-plus` env var for new keys; backward-compat with legacy untagged keys
- [x] Block proposer signature verification — `BlockHeader::verify_signature()` checks public key → address derivation and ML-DSA/SPHINCS+ signature under `crypto_version`; `validate_block()` rejects forged blocks
- [x] On-chain governance (`CreateProposal`/`VoteProposal` txs; stake-weighted 2/3-plus-one supermajority adjusts `min_validator_stake` or `fuel_per_fee_unit`; 1000-block voting window)
- [x] Light client protocol (header-only sync via `GET /blocks/height/:n/header`; Merkle inclusion proofs via `GET /blocks/height/:n/proof/:tx_hash` + `helix_crypto::verify_merkle_proof`; block proposer signature self-verifiable via `BlockHeader::verify_signature()` — `public_key` travels with the header so a light client without full state can verify)
- [x] Tx-History endpoint (`GET /accounts/:address/transactions`)
- [x] Per-IP rate limiting on the REST API (`helix-rpc::rate_limit`; token-bucket, 30 burst / 10 req/s sustained per IP; Cloudflare `CF-Connecting-IP`/`X-Forwarded-For`-aware so the public tunnel doesn't bucket every visitor under one IP)

---

## Security

- **Persistent validator key** is stored unencrypted in `validator-key.bin` — protect this file
- The base transport layer (Noise/X25519) is classical, but P2P messages are additionally encrypted with ML-KEM-768 (post-quantum) session keys — see Phase 7 above; Noise remains for defense-in-depth
- Minimum fee (1,000 nano-HLX) prevents zero-cost spam
- Report security issues privately before public disclosure

---

## License

MIT — see LICENSE file.

---

*Built with Rust. Quantum-secure by design.*
