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
| GET | `/sync/tip-certificate` | The commit certificate for this node's current tip — the one certificate `/sync/blocks` cannot carry, because a block's proof lives in its *successor* and the tip has none yet |
| GET | `/validators` | The active validator set: each validator's tier, stake and `voting_power`, plus the set's `total_voting_power` and `quorum_threshold` |
| GET | `/diagnostics` | Operational state of this node — see below |
| POST | `/transactions` | Submit a signed transaction — 400 if the signature, nonce slot, fee, or the sender's ability to pay it fails the check |
| GET | `/transactions/:hash` | Transaction outcome — `applied` / `failed` (with `error`) / `pending` / `unknown`; 404 if no such transaction |

### Status response

```json
{
  "version": "0.10.2",
  "height": 142,
  "best_hash": "a3f8c2...",
  "peer_count": 2,
  "is_syncing": false,
  "mempool_size": 0,
  "total_accounts": 2,
  "circulating_supply_hlx": 1000141.9995,
  "total_burned_hlx": 0.0005,
  "state_hash": "b3f1a9...",
  "state_height": 142,
  "p2p_port": 8546,
  "p2p_public_addr": "/dns4/p2p.example.net/tcp/443/tls/ws",
  "base_fee_per_byte": 1
}
```

`state_hash` is an operator-facing diagnostic (not part of consensus, not signed) — compare it
across nodes to spot execution divergence. **Match on `state_height`, not on `height`:** `height`
and `best_hash` come from the block store while `state_hash` comes from the in-memory chain state,
and a response sampled mid-commit carries height N−1 next to the state of N. `state_height` is read
under the same lock as `state_hash`, so those two always belong together — comparing `state_hash`
across nodes that merely share a `height` reports divergences that aren't there. `p2p_port` is this node's own
libp2p listen port — used by a joining peer to dial it directly, see "Joining an Existing
Network" above. `base_fee_per_byte` is what the next block will charge per transaction byte;
price against it rather than hardcoding a fee, since a flat number is only right until the
network gets busy (see "Fees" above).

### Diagnostics response

`GET /diagnostics` answers the questions that come up when a node is misbehaving. It is
deliberately **not** the node's log — see the note below on why.

```json
{
  "version": "0.10.2",
  "uptime_secs": 8412,
  "height": 36377,
  "state_height": 36377,
  "is_syncing": false,
  "peer_count": 2,
  "validators_not_heard_from": 1,
  "last_cosigned_height": 36376,
  "last_cosigned_secs_ago": 5982,
  "rss_kb": 344328,
  "machine_total_kb": 32758376,
  "previous_run": {
    "version": "0.10.2",
    "clean_exit": false,
    "ran_for_secs": 553,
    "last_height": 36119,
    "last_seen_unix": 1786023222,
    "rss_kb": 1835008
  }
}
```

What each field is for:

- **`last_cosigned_height` / `last_cosigned_secs_ago`** — the single most useful pair for a
  validator. A node whose height is current but whose last co-signature is an hour old is up,
  connected, and not participating. `null` on a node that has not co-signed during this run,
  including every non-validator.
- **`validators_not_heard_from`** — how many validators' votes are not arriving *here*. Read the
  direction carefully: it is what this node observes, not a claim that those validators are down.
  This node cannot tell an absent peer from a broken link to a healthy one.
- **`rss_kb` / `machine_total_kb`** — an out-of-memory kill leaves nothing in the node's own log,
  because the kernel decides and the process never runs again. These two numbers are how that
  becomes visible instead of mysterious.
- **`previous_run`** — how the *last* run ended. `clean_exit: false` means nothing marked it as an
  orderly stop: a crash, an OOM kill, `kill -9`, or the machine going down. Use `last_seen_unix`
  with `journalctl --since=@<n>` or `dmesg -T` to find what the system was doing at that moment.
  `null` on a first run. See "When your node keeps stopping" in
  [running a node](running-a-node.md).

**Why this is not the log.** Serving raw log output is the obvious way to build a remote debugging
endpoint and the wrong one: a log carries whatever anyone ever put in it, so the guarantee "nothing
sensitive is exposed" would have to be re-earned by every future log line — written by somebody not
thinking about this endpoint at all. On a node with a directly reachable listener the log carries
peer addresses, which is the network topology an eclipse attack needs. An enumerated response has
the opposite property: what is exposed is written down in one place and adding to it is a
deliberate act, which the test `diagnostics_expose_no_addresses_keys_or_paths` enforces.

The practical consequence is the useful one: **this response is safe to paste to anyone.** It
carries no addresses, no file paths, no keys and no peer identifiers, so an operator can share it
when asking for help without having to read through it first.

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
  "chain_id": "<hex>",
  "signature": "<hex>",
  "public_key": "<hex>"
}
```

- `amount` and `fee` are in **nano-HLX** (1 HLX = 1,000,000,000 nano-HLX)
- `nonce` is per-sender, strictly monotonic, starts at 0 — multiple sequential-nonce
  transactions from one sender can be submitted and included in the same block
- `chain_id` is the **genesis hash of the chain the transaction is valid on**, and it is covered
  by the signature. A node refuses any transaction whose `chain_id` is not its own, naming both
  values. Without it the same signed bytes would spend on every Helix chain that shares the
  sender's key and nonce — Ethereum's EIP-155 problem, and not a hypothetical one: the validator
  fundings of 2026-08-07 came out byte-identical to those of the 2026-08-05 reset
- Minimum fee: 1,000 nano-HLX
- The mempool validates the signature before accepting

Wallets take the chain id from a compiled-in constant when talking to the public endpoint, and
from the endpoint itself only when you named it (your own node, a devnet). That asymmetry is
deliberate: an endpoint that gets to answer "which chain are you on?" gets to decide what your
signature authorises. `HELIX_CHAIN_ID` overrides both, for offline signing and fresh devnets.

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
