# Reference — API, formats, crates

> Part of the [Helix documentation](../README.md).

## REST API

Base URL: `https://node.silvra.net` for the public network, or `http://127.0.0.1:8545` for
your own node (or wherever you've bound/proxied it — see `HELIX_RPC_BIND`).

| Method | Path | Description |
|---|---|---|
| GET | `/` | Node info & endpoint list |
| GET | `/status` | Height, hash, mempool size, supply stats; `protocol_version` (the rules the chain runs), `supported_protocol_version` (the highest this build runs) and `scheduled_upgrade` (`{version, height, supported}` or `null`) — `supported: false` means this node stops before `height` until it is updated |
| GET | `/genesis` | Everything needed to rebuild this chain's exact genesis state: the genesis block, governance params, the bootstrap validator's stake, the liquid genesis allocations, the personhood authorities and the genesis state hash a joining node recomputes and compares |
| GET | `/blocks/latest` | Latest block with full transaction list |
| GET | `/blocks/height/:n` | Block by height |
| GET | `/blocks/height/:n/header` | Header only (for light clients) |
| GET | `/blocks/height/:n/proof/:tx_hash` | Merkle inclusion proof for a transaction — replay it from the returned `leaf_hash`, not from `tx_hash` (see Transaction Format) |
| GET | `/blocks/hash/:hash` | Block by hash |
| GET | `/blocks/range` | Range of blocks (`?from=&count=`) — display view, per-tx status included; not the sync path (see `/sync/blocks`) |
| GET | `/accounts/:address` | Balance, staked amount, nonce, and `state_height` — the block the balance is as of, read together with it. A valid address the chain has never seen answers **404** with `state_height` too: its balance is zero as of that block. 400 on invalid address format |
| GET | `/accounts/:address/name` | Registered `.hlx` name for this address |
| GET | `/accounts/:address/personhood` | Proof of Personhood status |
| GET | `/accounts/:address/guardians` | Social-recovery guardian set |
| GET | `/accounts/:address/recovery` | Pending/active recovery status; `pending_keys` lists every key the guardians name, with its votes |
| GET | `/accounts/:address/transactions` | Transaction history (`?limit=&offset=`). A pruning node cannot show transactions from blocks it dropped; `history_starts_at_block` and `omitted_below_horizon` say so rather than returning a short list as if complete |
| GET | `/accounts/:address/delegations` | This account's delegations across validators, with current value |
| GET | `/accounts/:address/storage/:key_hex` | One hex-encoded key/value from a deployed contract's own storage |
| GET | `/validators/:address/pool` | A validator's delegation pool — delegated stake, commission, effective stake, and `reward_address` (where the validator's own share is paid; `null` = to the validator itself) |
| GET | `/names/:name` | Resolve name to address; a free name answers 404 with its `registration_price_nano` |
| GET | `/governance/params` | Current runtime-adjustable protocol parameters, `protocol_version` and `scheduled_upgrade` |
| GET | `/governance/proposals` | Proposals whose voting period is still running (`?limit=&offset=`); a closed one leaves the state. A protocol upgrade carries `activation_height`, the first block under its version |
| GET | `/governance/proposals/:id` | One proposal's status |
| GET | `/mempool` | Pending transaction count |
| GET | `/mempool/transactions` | The hash of every transaction waiting in this node's pool, sorted: `{"transactions": ["…"]}`. Each one's body is at `/transactions/:hash` |
| GET | `/supply/circulating` | Every HLX in existence — issued less burned, staked included — as a bare number in HLX, plain text: what listing sites fetch |
| GET | `/supply/total` | The same number: Helix has no locked or allocated-but-unissued supply that would set the two apart |
| GET | `/supply/max` | The hard cap, 33,000,000; no block reward is minted beyond it |
| GET | `/sync/blocks` | Raw block range for peer sync (`?from=&count=`). `&encoding=bincode` returns the same blocks as `application/octet-stream` instead of JSON — ~3.5× fewer bytes and a fraction of the serving node's CPU, because JSON renders every byte of an ML-DSA key or signature as a decimal number. Clients try it once and fall back to JSON if the peer does not know it. The JSON answer is streamed a block at a time; the bincode answer, `/blocks/range` and `/sync/snapshot` are built whole, so a node builds at most four of them at once — further requests wait for a place, and after 30 s get **503** with `Retry-After` |
| GET | `/sync/checkpoint` | A height, block hash and **state root** to anchor a fast join to, in the exact shape `HELIX_TRUSTED_CHECKPOINT` takes (`{"height":10000,"block_hash":"…","state_root":"…","checkpoint":"10000:…:…"}`). **An answer, not a proof:** a checkpoint taken from the node you are about to sync from is the same party vouching for itself. It is worth something when it is *compared* — every node answers this, so ask two or three and see whether they agree. The `state_root` is the half that decides whether a snapshot can be believed at all; without it a joining node has nothing to check a state against that the serving peer does not also control. Names only a height where a join would actually succeed: the stored snapshot and the block at that height must both still be here. 404 while none is, which is normal on a young or freshly pruned node. |
| GET | `/sync/snapshot` | The chain state plus the height it belongs to, as `application/octet-stream` (bincode only — nobody reads a snapshot, and JSON would cost 4.5x for nothing). Without a parameter: whatever state this node holds right now. With **`?height=N`**: the newest *stored* snapshot at or below N, or **404** — never a substitute. That distinction is the point. A receiver verifies a snapshot by hashing it and comparing against `prev_state_root` in the header of the next block, which is signed; it can only do that for a height that stands still, and the live tip moves while it is checking. Stored snapshots are taken every `HELIX_SNAPSHOT_INTERVAL` heights (default 10000). Verifying still needs the block it compares against to be genuine, which is an out-of-band checkpoint the operator supplies — what Ethereum calls weak subjectivity. |
| GET | `/sync/tip-certificate` | The commit certificate for this node's current tip — the one certificate `/sync/blocks` cannot carry, because a block's proof lives in its *successor* and the tip has none yet |
| GET | `/validators` | The active validator set: each validator's tier, stake, `voting_power`, commission and `reward_address`, plus the set's `total_voting_power` and `quorum_threshold` |
| GET | `/diagnostics` | Operational state of this node — see below |
| POST | `/transactions` | Submit a signed transaction — 400 if the signature, nonce slot, fee, or the sender's ability to pay it fails the check |
| GET | `/transactions/:hash` | Transaction outcome — `applied` / `failed` (with `error`) / `pending` / `unknown`; 404 if no such transaction. A `pending` one carries `from`, `to`, `amount_nano`, `fee_nano`, `tx_type`, `nonce` and `memo`; once in a block it carries the whole transaction, `fee_burned_nano` / `fee_to_validator_nano` and the raw `data_hex` |

**Exact amounts.** Every amount is reported twice: `…_hlx` as a JSON number, for display, and
`…_nano` as a **decimal string** of nano-HLX, which is exact. A JSON number is a double in most
languages and stops counting single nano-HLX above ~9 million HLX; anything that books, reconciles
or compares amounts must read the `…_nano` fields. They are: `balance_nano`, `staked_nano`,
`unbonding_stake_nano` on an account; `circulating_supply_nano` and `total_burned_nano` in
`/status`; `amount_nano` and `fee_nano` on every transaction a block, the history or the lookup
returns.

How an exchange or custodian puts these together — deposits, withdrawals, nonces — is in
[Integrating Helix](exchange-integration.md).

**Memo.** A `Transfer` whose `data` is UTF-8 of at most 256 bytes carries that text as its memo,
and every transaction view shows it as `memo` (absent otherwise) — how an exchange that receives on
one address tells deposits apart. `helix tx send --memo` sets it. Other bytes stay in `data`,
visible as `data_hex` in the lookup, but are no memo.

**Balance changes.** Every block view carries `balance_changes`: each liquid balance the block
moved, as `{"tx_index", "tx_hash", "account", "kind", "delta_nano"}` — `tx_index`/`tx_hash` are
`null` for the block's own reward, `kind` is `transaction` (the fee, the value moved, a stake or a
claim), `reward` (a validator's tips, block reward and commission) or `contract` (a transfer a
contract made), and `delta_nano` is signed. Summed per account they are exactly how much each
liquid balance moved in the block. `GET /transactions/:hash` lists the transaction's own, and each
row of an address history carries `balance_change_nano`, what the transaction did to that address.
A node keeps them for the blocks it executes; absent means it has no record, never that nothing
moved. An account a contract paid finds that transaction in its history.

**Finality.** A transaction in a block is final: consensus is BFT, a block is committed only with
two thirds of the voting power behind it, and a committed block is never reverted. There is no
confirmation count to wait for: `applied` in `/transactions/:hash` is final. (While Helix is a
testnet, a reset replaces the whole chain — see the README.)

### Status response

```json
{
  "version": "0.20.0",
  "height": 1248,
  "best_hash": "e430e388…",
  "peer_count": 3,
  "is_syncing": false,
  "mempool_size": 0,
  "total_accounts": 4,
  "circulating_supply_hlx": 101247.999987591,
  "total_burned_hlx": 1.2409e-05,
  "circulating_supply_nano": "101247999987591",
  "total_burned_nano": "12409",
  "state_hash": "eb24dea7…",
  "state_height": 1248,
  "p2p_port": 8546,
  "p2p_public_addr": "/dns4/p2p.silvra.net/tcp/443/tls/ws",
  "base_fee_per_byte": 1
}
```

`state_hash` is an operator-facing diagnostic (not part of consensus, not signed) — compare it
across nodes to spot execution divergence. **Match on `state_height`, not on `height`:** `height`
and `best_hash` come from the block store while `state_hash` comes from the in-memory chain state,
and a response sampled mid-commit carries height N−1 next to the state of N. `state_height` is read
under the same lock as `state_hash`, so those two always belong together — comparing `state_hash`
across nodes that merely share a `height` reports divergences that aren't there. `p2p_port` is this node's own
libp2p listen port — used by a joining peer to dial it directly, see
[Joining the network](running-a-node.md#joining-the-network). `base_fee_per_byte` is what the next
block will charge per transaction byte; price against it rather than hardcoding a fee, since a
flat number is only right until the network gets busy (see [Fees](cli.md#fees)).

### `GET /whoami`

Answers the one question a node cannot answer about itself: **what address does the rest of the
world reach me at?** A node knows the port it listens on and nothing about how it looks from
outside, so without this it can only announce an address its operator configured by hand.

```json
{ "ip": "203.0.113.7", "multiaddr_kind": "ip4" }
```

`ip` is the address the request arrived from — the socket's peer on a direct connection, or the
forwarding header (`CF-Connecting-IP`, `X-Forwarded-For`) when the request came through a proxy
and the socket therefore says `127.0.0.1`. Headers are trusted **only** in that case, so a caller
on a direct connection cannot talk itself into a different answer. `multiaddr_kind` is `ip4` or
`ip6`, matching the address.

Add `?p2p_port=<n>` and this node also opens a TCP connection back to `<ip>:<n>` and reports
whether it got through:

```json
{ "ip": "203.0.113.7", "multiaddr_kind": "ip4",
  "probed": "/ip4/203.0.113.7/tcp/8546", "reachable": true }
```

The probed address is always built from the address the request came from — only the port is the
caller's to choose — so this cannot be aimed at a third party. `reachable: false` carries a
`probe_error` naming the cause (refused vs. timed out, which distinguishes a closed port from a
firewalled one). Nodes call this on their sync peer at startup and every ten minutes; see
"Network Resilience" in `running-a-node.md`.

### Diagnostics response

`GET /diagnostics` answers the questions that come up when a node is misbehaving. It is
deliberately **not** the node's log — see the note below on why. Abbreviated example (the node
also reports disk and memory totals, load, threads and open file descriptors):

```json
{
  "version": "0.20.0",
  "uptime_secs": 8412,
  "height": 36377,
  "state_height": 36377,
  "is_syncing": false,
  "peer_count": 2,
  "validators_not_heard_from": 1,
  "peer_tip_height": 36378,
  "rounds_lost_with_quorum_power": 0,
  "compact_blocks_rebuilt": 1532,
  "compact_blocks_not_rebuilt": 4,
  "chain_db_bytes_per_block": 81426,
  "earliest_block": null,
  "disk_days_remaining": 82,
  "chain_db_plateau_kb": null,
  "last_cosigned_height": 36376,
  "last_cosigned_secs_ago": 5982,
  "rss_kb": 344328,
  "machine_total_kb": 32758376,
  "previous_run": {
    "version": "0.20.0",
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
- **`peer_tip_height`** — the highest tip any connected peer claims. Compare it with `height`.
  Anything above it means **this** node is the one behind, and that matters more than it sounds:
  a validator below the tip cannot vote on the next height, so it is missing from the quorum, and
  a chain that looks like it is waiting for somebody else is in fact waiting for you. `null`
  while no peer has claimed a tip yet, which is not the same as being level.
- **`rounds_lost_with_quorum_power`** — rounds this node lost *while it had heard enough voting
  power to close them*. Zero on a healthy chain, and worth watching because it separates two
  failures that look identical from outside. If votes are missing, the named validators in the
  "Validator silent" lines are the reason. If this number is climbing, the votes are arriving and
  the round is failing anyway — which means the prevotes went to different values, some for the
  block and some for nil, because the proposal did not reach everyone inside its window. That is a
  network-timing problem, not an availability one, and no amount of restarting the absent validator
  fixes it.
- **`compact_blocks_rebuilt` / `compact_blocks_not_rebuilt`** — proposals and committed blocks
  travel compact (the header and the transaction ids), and each node rebuilds them from the
  transactions it already holds. These count the blocks that mattered here — a proposal for the
  height this validator is deciding, a committed block right above its tip — that it could rebuild,
  and the ones it could not, for each of which it fetched or waited for the whole block. A few
  misses are normal: a transaction can reach a node a moment after the block that carries it. A
  share that stays high means transactions are arriving late, and the bandwidth compact blocks save
  is being spent after all. Both count from this process's start.
- **`earliest_block`** — the lowest height this node still holds, or `null` when it keeps
  everything. A node run with `HELIX_KEEP_BLOCKS` drops older blocks to bound disk growth, and
  below this height it can answer neither a block query nor a wallet's history lookup — not because
  the chain lacks them, but because this node does. `null` rather than `0`, for the same reason
  `peer_tip_height` uses it: "I keep it all" and "my horizon happens to sit at genesis" are
  different claims, and only one of them means *ask me for any block*.
- **`chain_db_plateau_kb`** — the size the database levels off at when this node bounds its
  history (`HELIX_KEEP_BLOCKS`); `null` on an archive node, which has no ceiling. When it is set
  and fits the volume, **`disk_days_remaining` is `null`** — a pruning node's growth is not a line,
  and extrapolating one names a day that never arrives. A plateau *larger* than the disk still
  fills it, just later, so that case keeps its countdown.
- **`chain_db_bytes_per_block` / `disk_days_remaining`** — what this chain actually costs to store,
  and how long the volume lasts at that rate. Measured from the node's own database rather than
  estimated, because the figure that matters is what *this* validator set writes: roughly half of
  every block is its commit certificate, one ML-DSA signature per validator, and that half does
  not shrink when traffic does. The days figure is an extrapolation at the configured
  block time, and `null` whenever anything it needs is missing — a runway that reports a number it
  cannot support would be believed.
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
`BLAKE3("helix-tx-v1:" ‖ bincode(TxPayload))`, where `TxPayload` is every field below except
`signature` and `public_key`, in this order.

This is the body `POST /transactions` takes — a transfer of 15,000 HLX (arrays shortened):

```text
{
  "version": 1,
  "tx_type": "Transfer",
  "from": "hlxbx7oYT7n1nidYCxLrk1LUQ93CTXFrGWNt",
  "to": "hlxk6QWXDZjCtvBunTwdVscNnYpYb6bg1pvQ",
  "amount": 15000000000000,
  "fee": 10886,
  "nonce": 0,
  "data": [],
  "crypto_version": "MlDsa",
  "chain_id": [15, 12, 58, 131, …],     32 numbers: the genesis hash as bytes
  "signature": [ … ],                   the signature's bytes (3,309 for ML-DSA-65)
  "public_key": [ … ]                   the key's bytes (1,952), or null — see below
}
```

- **Hashes, signatures and keys are JSON arrays of byte values, not hex strings**; a hex string is
  refused. Addresses are strings. `to` is `null` for transaction types without a recipient.
- `amount`, `fee` and `nonce` are unsigned 64-bit integers. Clients in languages whose numbers are
  doubles (JavaScript) must write them without passing through a float — above 2^53 nano-HLX
  (~9 million HLX) a double loses precision.
- `tx_type` is one of: `Transfer`, `Stake`, `Unstake`, `RegisterIdentity`, `RegisterName`,
  `RegisterGuardians`, `ApproveRecovery`, `DeployContract`, `CallContract`, `CreateProposal`,
  `VoteProposal`, `ProvePersonhood`, `ClaimUnbonded`, `CancelRecoveryRequest`,
  `SubmitDoubleSignEvidence`, `Delegate`, `Undelegate`, `Redelegate`, `SetCommission`, `Unjail`,
  `ProbationHeartbeat`, `SetRewardAddress` (bincode encodes them by this position).
- `crypto_version` is `MlDsa` or `SphincsPlus`.
- `data` is type-specific; for a `Transfer` it is empty or the memo's UTF-8 bytes (at most 256).
- `amount` and `fee` are in **nano-HLX** (1 HLX = 1,000,000,000 nano-HLX)
- `nonce` is per-sender, strictly monotonic, starts at 0 — multiple sequential-nonce
  transactions from one sender can be submitted and included in the same block
- `chain_id` is the **genesis hash of the chain the transaction is valid on**, and it is covered
  by the signature. A node refuses any transaction whose `chain_id` is not its own, naming both
  values. Without it the same signed bytes would spend on every Helix chain that shares the
  sender's key and nonce — Ethereum's EIP-155 problem, and not a hypothetical one: the validator
  fundings of 2026-08-07 came out byte-identical to those of the 2026-08-05 reset
- The fee must cover `base_fee_per_byte × size` (the size of the transaction as its block carries
  it), and at least 1,000 nano-HLX; the base-fee part is burned, the rest goes to the block's
  proposer. `GET /status` reports `base_fee_per_byte`
- The mempool validates the signature before accepting
- `public_key` may be `null` once the chain knows the sender's key. The first transaction an
  address signs puts the key it derives from on record; after that a node keeps the transaction
  **without** the key, so blocks carry each ~2 KB key once instead of once per transaction (#243).
  Wallets can keep sending it — a node strips it, and one that does not know the key yet needs
  it. A socially recovered account signs with its recovery key, and a transaction without a key
  is checked against that one, never against the key on record. Nodes gossip every transaction
  **with** its key, so each peer checks it against nothing but its own bytes
- The **transaction id** (`tx_hash`) is `BLAKE3("helix-txid-v1:" ‖ signing hash ‖ signature)` —
  independent of `public_key`, so the id a wallet is given at submission is the id the block
  carries. A block's `merkle_root` is over each transaction's **leaf hash**,
  `BLAKE3("helix-txleaf-v1:" ‖ bincode(transaction))`, which does cover whether the key is
  there: the base fee is charged per byte of what the block carries, so the header has to pin
  that form. `GET /blocks/height/:n/proof/:tx_hash` returns both, and a proof is replayed from
  `leaf_hash`

Wallets take the chain id from a compiled-in constant when talking to the public endpoint, and
from the endpoint itself only when you named it (your own node, a devnet). That asymmetry is
deliberate: an endpoint that gets to answer "which chain are you on?" gets to decide what your
signature authorises. `HELIX_CHAIN_ID` overrides both, for offline signing and fresh devnets.

**Signing elsewhere.** `helix tx send … --offline --nonce <n> --fee <nano>` signs on a machine
that talks to no node and prints this JSON body; `helix tx submit <file>` (or `-` for stdin) sends
it from one that does. The transaction id is printed at signing, before anything is broadcast.

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
| `helix-mempool` | Transaction pool: admits only what the sender can pay, packs each sender's next executable nonce first, highest tip across senders |
| `helix-storage` | Persistent redb-backed block + chain-state store (`HelixDb`) |
| `helix-p2p` | libp2p networking: gossip (a separate lane for transactions), compact blocks, block and round sync, peer exchange, mDNS |
| `helix-identity` | Proof of Personhood, human-readable names, social recovery |
| `helix-vm` | WASM contract execution (`wasmi`, fuel-metered, deterministic) |
| `helix-zkp` | ZK-STARK proof generation/verification for Proof of Personhood |
| `helix-rpc` | Axum REST API server (`:8545`) |
| `helix-mesh` | `helix mesh` — the Mesh (Rosetta) Data and Construction API in front of a node's REST API (`--offline` for the signing machine), see [Integrating Helix](exchange-integration.md#mesh-rosetta-api) |
| `helix-walletd` | The Bitcoin-Core-style wallet RPC for exchanges — served by `helix start` with `server=1` in the wallet's `helix.conf` (or `HELIX_WALLET_RPC`), or as `helix wallet-rpc`; `helix-cli`/`helix rpc` is its `bitcoin-cli`; see [Integrating Helix](exchange-integration.md#bitcoin-style-wallet-rpc) |
| `helix-node` | The `helix` binary — `helix start` orchestrates all subsystems; other subcommands are the CLI client |
| `helix-cli` | Client subcommand library (wallet, tx, chain, …) linked into the `helix` binary |

---
