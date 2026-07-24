# Reference — API, formats, crates

> Part of the [Helix documentation](../README.md) — deep reference, split out of the README to keep it short.

## REST API

Base URL: `https://helix.silvra.net` for the public network, or `http://127.0.0.1:8545` for
your own node (or wherever you've bound/proxied it — see `HELIX_RPC_BIND`).

| Method | Path | Description |
|---|---|---|
| GET | `/` | Node info & endpoint list |
| GET | `/status` | Height, hash, mempool size, supply stats |
| GET | `/genesis` | Everything needed to rebuild this chain's exact genesis state: the genesis block, governance params, the bootstrap validator's stake, any extra genesis validators, and any liquid genesis allocations (used by fresh nodes joining via `sync_peer`) |
| GET | `/blocks/latest` | Latest block with full transaction list |
| GET | `/blocks/height/:n` | Block by height |
| GET | `/blocks/height/:n/header` | Header only (for light clients) |
| GET | `/blocks/height/:n/proof/:tx_hash` | Merkle inclusion proof for a transaction |
| GET | `/blocks/hash/:hash` | Block by hash |
| GET | `/blocks/range` | Range of blocks (`?from=&count=`) — display view, per-tx status included; not the sync path (see `/sync/blocks`) |
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
| POST | `/transactions` | Submit a signed transaction — 400 if the signature, nonce slot, fee, or the sender's ability to pay it fails the check |
| GET | `/transactions/:hash` | Transaction outcome — `applied` / `failed` (with `error`) / `pending` / `unknown`; 404 if no such transaction |

### Status response

```json
{
  "version": "0.7.0",
  "height": 142,
  "best_hash": "a3f8c2...",
  "peer_count": 0,
  "is_syncing": false,
  "mempool_size": 0,
  "total_accounts": 2,
  "circulating_supply_hlx": 1000141.9995,
  "total_burned_hlx": 0.0005,
  "state_hash": "b3f1a9...",
  "p2p_port": 8546,
  "base_fee_per_byte": 1
}
```

`state_hash` is an operator-facing diagnostic (not part of consensus, not signed) — compare it
across nodes at the same height to spot execution divergence. `p2p_port` is this node's own
libp2p listen port — used by a joining peer to dial it directly, see "Joining an Existing
Network" above. `base_fee_per_byte` is what the next block will charge per transaction byte;
price against it rather than hardcoding a fee, since a flat number is only right until the
network gets busy (see "Fees" above).

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
| `helix-node` | The `helix` binary — `helix start` orchestrates all subsystems; other subcommands are the CLI client |
| `helix-cli` | Client subcommand library (wallet, tx, chain, …) linked into the `helix` binary |

---
