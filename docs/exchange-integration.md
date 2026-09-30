# Integrating Helix — exchanges, custodians, payment services

> Part of the [Helix documentation](../README.md). The endpoints and the transaction format are
> in the [Reference](reference.md); this page is about using them to hold customer funds.

**Helix is a testnet.** Its chain is reset when a release needs it, and HLX on it has no value.
This page describes the interface an integration builds on, so that one can be written and
tested now; it is not an invitation to list a testnet coin.

**This page describes the current code.** `--memo`, `--offline`, `helix tx submit`, the chain id in
`helix chain status`, and the fix that lets a syncing node keep transaction outcomes are newer
than the 0.20.0 release: build from source (see [Installation](installation.md)) until the next
one. The `…_nano` fields and `memo` in API answers are already served by `node.silvra.net`.

## At a glance

| | |
|---|---|
| Unit | 1 HLX = 1,000,000,000 nano-HLX. Amounts are integers in nano-HLX. |
| Exact amounts in JSON | every `…_nano` field, a decimal **string** (the `…_hlx` fields are doubles, for display) |
| Finality | BFT: a transaction in a block is final. No confirmation count. |
| Block time | about 2 seconds |
| Signatures | ML-DSA-65 (FIPS 204): signature 3,309 bytes, public key 1,952 bytes |
| Deposit reference | a transfer's `memo`, UTF-8, at most 256 bytes |
| Chain id | the genesis block's hash; every transaction signs it |
| Nonces | per sender, strictly sequential from 0 |
| Fee | `base_fee_per_byte × size` burned, anything above it tips the proposer |

## Run your own node

Read the chain from a node you run, not from the public endpoint: it is the only answer you do not
have to trust someone else for, and it lifts the public rate limit. Setup is in
[Running a Node](running-a-node.md). For an integration:

- **Keep the whole history.** Leave `HELIX_KEEP_BLOCKS` and `HELIX_KEEP_BYTES` unset. A pruning
  node cannot show transactions below its horizon; the address history then says so
  (`history_starts_at_block`, `omitted_below_horizon`) instead of returning a short list.
- **Do not join from a checkpoint.** A node started with `HELIX_TRUSTED_CHECKPOINT` holds no blocks
  and no transaction outcomes from before that height.
- **Wait for the sync.** `GET /status` reports `is_syncing` and `height`; read deposits only once
  `is_syncing` is false.
- **Raise the rate limit on your own node** if you scan quickly: `HELIX_RPC_RATE_LIMIT=burst,refill`
  (default `500,100` per client IP).
- **Use a build newer than 0.20.0.** 0.20.0 and earlier did not keep transaction outcomes for
  blocks they took over sync, and answered `unknown` for them (#259).

## Addresses

An address is `hlx` followed by Base58 of a version byte, the first 20 bytes of the BLAKE3 hash of
the public key, and a 4-byte checksum. A mistyped address fails the checksum.

**Validate a withdrawal address before accepting it:** `GET /accounts/<address>` answers **400**
for anything that is not an address, **404** for a valid address that has never been used, and 200
with the account otherwise. 404 is not an error — a fresh address is a normal destination.

**There is no key derivation from a master public key** (no xpub, as in BIP32). ML-DSA does not
support it. Two ways to give each customer a deposit route:

1. **One shared deposit address, a memo per customer.** The customer sends with the memo you
   assigned (`helix tx send <address> <amount> --memo <ref>`, the desktop wallet, or any client
   that sets `data`). You credit by memo. A deposit without a known memo is a support case — say
   so on your deposit page.
2. **One key per customer.** `helix wallet new --output <file> --passphrase-file <file>` creates
   one; the address is in the file and in `helix wallet address --key <file>`. Every key is a
   separate secret to store and sweep from.

## Detecting deposits

**Scan blocks.** `GET /blocks/range?from=<height>&count=<n>` returns up to 500 blocks with every
transaction and its outcome; `GET /blocks/height/<n>` returns one. Remember the last height you
processed and continue from there. Credit a transaction when **all** of these hold:

- `tx_type` is `Transfer`,
- `to` is your deposit address,
- `status` is `applied`.

Take the amount from `amount_nano` and the customer reference from `memo`. Identify the deposit
by its `hash` — the same transaction can never be applied twice.

`status` can also be:

- `failed` — the transaction is in a block, its fee was charged, and it moved nothing (the reason
  is in `error`). Do not credit it.
- `unknown` — this node has no record of the outcome (0.20.0 or earlier, catching up over sync;
  or a checkpoint join). Do not credit it; ask a node that executed the block.

**Or read an address's history:** `GET /accounts/<address>/transactions?limit=<n>&offset=<m>`,
newest first, at most 200 per page, the same fields and statuses as above.

**One transfer at a time, not balances.** A balance can change without a transaction to your
address in it: block rewards if the address validates, and transfers a smart contract makes, which
this API does not list yet. Reconcile deposits against transactions, and treat a balance you
cannot explain as something to investigate, not to credit.

## Sending withdrawals

**Nonce.** Each transaction from an address carries the next nonce, starting at 0; `GET
/accounts/<address>` reports the next one as `nonce`. Several transactions from one address can be
pending at once and land in the same block, as long as their nonces follow each other without a
gap. For a hot wallet, keep the next nonce yourself instead of asking before every transaction.

**Fee.** At least `base_fee_per_byte × size`: `GET /status` reports `base_fee_per_byte`; the size
of a transfer is about 3,500 bytes, or about 5,400 for an address's first transaction, which
carries its public key. The base fee moves with load — leave headroom. The CLI and the desktop
wallet price automatically at twice the base fee and never pay more than 1 HLX on their own.

**Signing.**

- **CLI, online:** `helix tx send <to> <amount> --key <file> [--passphrase-file <file>]`.
- **CLI, key offline:** on the machine with the key,
  `helix tx send <to> <amount> --key <file> --offline --nonce <n> --fee <nano> --output tx.json`;
  on an online machine, `helix tx submit tx.json`. Set `HELIX_CHAIN_ID` on the offline machine
  (`helix chain status` prints it as "Chain id"), or it signs for the chain its release was built
  for. See [CLI → Sending HLX](cli.md#sending-hlx).
- **Your own code:** sign with the `helix-core` and `helix-crypto` crates (Rust), or the
  [mobile bindings](../mobile/README.md) (Kotlin, via UniFFI). The JSON body and what the
  signature covers are in [Reference → Transaction Format](reference.md#transaction-format). There
  is no JavaScript implementation of ML-DSA signing in this repository.

**Amounts are exact.** The CLI reads `2.01` as exactly 2,010,000,000 nano-HLX and refuses more than
nine decimals. In your own code, keep amounts as integers in nano-HLX from end to end.

**Tracking.** The transaction id is known when you sign — `--offline` prints it — and is the `hash`
the node answers with. Poll `GET /transactions/<id>`:

| Answer | Meaning | What to do |
|---|---|---|
| 200, `applied` | final | done |
| 200, `failed` | in a block, fee charged, nothing moved; `error` says why | the nonce is used; fix the cause and send a new transaction |
| 200, `pending` | in this node's pool | wait |
| 404, `expired` | left the pool unincluded (after 30 minutes by default); nothing charged, nonce unused | submit the same signed transaction again, or sign a new one **with the same nonce** |
| 404 | this node never saw it | submit it |

Submitting the same signed transaction twice is harmless: while it is pending the node answers
"already in mempool", once it is applied "Nonce already spent". Two *different* transactions with
the same nonce can never both apply — that is how you replace a stuck withdrawal.

## Not available yet

- **Transfers made by smart contracts** are not listed in the address history or the block view;
  they only show in balances. On this testnet no contract makes any.
- **A Mesh (Rosetta) API.** The specification supports ML-DSA-65 as a curve and signature type;
  whether Helix will serve one has not been decided.
