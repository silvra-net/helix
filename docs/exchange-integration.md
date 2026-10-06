# Integrating Helix — exchanges, custodians, payment services

> Part of the [Helix documentation](../README.md). The endpoints and the transaction format are
> in the [Reference](reference.md); this page is about using them to hold customer funds.

**Helix is a testnet.** Its chain is reset when a release needs it, and HLX on it has no value.
This page describes the interface an integration builds on, so that one can be written and
tested now; it is not an invitation to list a testnet coin.

**Use 0.20.3 or later.** `--memo`, `--offline`, `helix tx submit`, the chain id in `helix chain
status`, the exact amount fields and a syncing node that keeps transaction outcomes arrived in
0.20.1; every balance change of a block, recorded and served, and the Mesh Data API in 0.20.2;
the Bitcoin-style wallet RPC (`helix.conf`, `helix-cli`), the Mesh Construction API and the
container image in 0.20.3.

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
| Ways to integrate | this page's REST API · a **Bitcoin-Core-style wallet RPC** served by the node (`server=1` in `helix.conf`, called with `helix-cli`) · the **Mesh (Rosetta)** Data and Construction API (`helix mesh`) |
| Supply | `GET /supply/circulating`, `/supply/total`, `/supply/max` — a bare number in HLX |
| Container | `ghcr.io/silvra-net/helix:<version>` (and `:latest`), from 0.20.3 on |

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
- **Start it with 0.20.1 or later.** 0.20.0 and earlier did not keep transaction outcomes for
  blocks they took over sync, and answered `unknown` for them (#259); a node that synced under
  0.20.0 keeps that gap for the blocks it synced then.

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

**Payments from smart contracts.** A contract can pay your address while running a transaction
that names only the contract. Such a payment is not a `Transfer` to you — it appears in the
block's `balance_changes` with `kind` `contract`, your address as `account` and a positive
`delta_nano`, and the transaction then shows in your address history with `balance_change_nano`.
Credit it by that entry, identified by block height, transaction hash and your address.

**Every balance change, accounted for.** Each block view carries `balance_changes`: every liquid
balance the block moved, with the transaction (`tx_index`, `tx_hash`; `null` for the block's own
reward), the `account`, the `kind` (`transaction`, `reward`, `contract`) and a signed
`delta_nano`. Summed per account they are exactly how much each balance moved, so a balance can be
reconciled block by block. Every history row has `balance_change_nano` too: what that transaction
did to the address, fee included. Both come from a node running 0.20.2 or later, and only for blocks
it executed itself — absent means "this node has no record", never "nothing moved".

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

## Bitcoin-style wallet RPC

Most exchanges integrate a chain through the interface they already run for Bitcoin and its
descendants. The Helix node serves that interface itself — like `bitcoind`, one process: a wallet
speaking Bitcoin Core's JSON-RPC, with the same method names, parameters, answers and error codes,
configured by a `bitcoin.conf`-style file and called with a `bitcoin-cli`-style tool.

### helix.conf

The wallet lives in `helix-wallet/` next to the node's database (`HELIX_WALLET_DIR` to move it) —
Bitcoin's data directory. Its settings go into `helix.conf` there, in `bitcoin.conf`'s format:

```ini
server=1
rpcport=8547
rpcauth=exchange:6a3f…$9c1e…          # from Bitcoin Core's share/rpcauth/rpcauth.py
walletnotify=/opt/exchange/deposit.sh %s
blocknotify=/opt/exchange/newblock.sh %s
```

```bash
HELIX_WALLET_PASSPHRASE_FILE=/etc/helix/wallet-passphrase helix start
```

On the first start the node makes the wallet at the current height, for the chain the node is on —
encrypted under the passphrase in `HELIX_WALLET_PASSPHRASE_FILE` if one is given (then unlock it
with `walletpassphrase`, as in Bitcoin Core). **Run it on the exchange's own node, not on a
validator** — a hot wallet does not belong in the consensus process.

| Key | |
|---|---|
| `server=1` | Switches the wallet RPC on. Without it the file is read by `helix-cli` only. |
| `rpcbind`, `rpcport` | Where it listens. Default `127.0.0.1:8547`. |
| `rpcallowip` | Who may connect besides this machine: an address or a network (`10.0.0.5`, `10.0.0.0/8`, `10.0.0.0/255.0.0.0`, `fd00::/8`); repeat it for more. **Without it, only this machine** — and listening beyond it without one stops the start, as Bitcoin Core requires. Anyone else gets HTTP 403. |
| `rpcuser` + `rpcpassword`, `rpcauth` | HTTP Basic authentication; `rpcauth` lines take Bitcoin Core's salted hash, so the password is not in the file. The cookie the wallet writes to `.cookie` at every start works always (`rpccookiefile` to move it). |
| `walletnotify` | A command run for every change to a wallet transaction: when it is signed and submitted, when a block holds it (deposits, sends, sweeps), when it is given up. `%s` the transaction id, `%b` the block hash (`unconfirmed` before), `%h` the height (`-1` before), `%w` the wallet name (`''`). |
| `blocknotify` | A command run when the wallet's view of the chain moves on, `%s` the newest block's hash — once per round, so catching up many blocks runs it once. |
| `paytxfee` | A fee rate in HLX per kB that sends pay at least; `settxfee` changes it until restart. Sweeps pay the going fee. |
| `maxtxfee` | No transaction is signed with a larger fee, in HLX. Default 1. |
| `keypool` | Addresses an encrypted wallet makes ahead, to hand out while locked. Default 100. |
| `amountdecimals=8` | Amounts with eight decimals instead of nine — see below. |

Commands run through the shell, at most 16 at a time; one that fails is logged, not retried —
`listsinceblock` is what catches up, as with Bitcoin Core. Sections `[main]` and `[test]` apply on
their network (the public chain is `test`). **Bitcoin options that mean nothing for a Helix wallet**
(`txindex`, `dbcache`, `printtoconsole`, …) are accepted and named once in the log, so a copied
`bitcoin.conf` works. **An unknown key stops the start with the reason**, and so does `zmqpub…`:
Helix does not publish over ZMQ, and an exchange waiting for it would wait forever — use
`walletnotify` and `blocknotify`.

The wallet RPC can be configured from the node's environment or `helix.toml` instead
(`HELIX_WALLET_RPC=127.0.0.1:8547`, `HELIX_WALLET_RPC_USER` with `HELIX_WALLET_RPC_PASSWORD_FILE`;
in `helix.toml` `wallet_rpc`, `wallet_rpc_user`, `wallet_rpc_password_file`), but **one thing in
one place**: an address or a user set in both stops the start, with both named. The passphrase
for a new wallet comes only from `HELIX_WALLET_PASSPHRASE_FILE` (`wallet_passphrase_file`).

### helix-cli

`helix-cli` is `bitcoin-cli` for this wallet — the same binary under that name (a link: `ln -s
"$(command -v helix)" /usr/local/bin/helix-cli`; the container image has it), or `helix rpc`:

```bash
helix-cli -datadir=/var/lib/helix/helix-wallet getbalance
helix-cli walletpassphrase "$(cat /etc/helix/wallet-passphrase)" 600
helix-cli -named getblock blockhash=4dd5… verbosity=2
```

The options are `bitcoin-cli`'s: `-datadir` (the wallet directory), `-conf`, `-rpcconnect`,
`-rpcport`, `-rpcuser`/`-rpcpassword`, `-rpccookiefile`, `-named`, `-stdin`, `-stdinrpcpass`,
`-rpcwait`, `-rpcclienttimeout`. Credentials come from the options, else `rpcuser`/`rpcpassword`
in `helix.conf`, else the cookie. A string result is printed bare, anything else as JSON with every
amount's digits kept; an error prints `error code: -N` and `error message:` and exits with `N`, as
`bitcoin-cli` does. `-stdin` takes further parameters from standard input — a passphrase given
there stays out of the shell history.

### As its own process

To run the wallet against a node elsewhere instead:
`helix --node http://<node>:8545 wallet-rpc init --passphrase-file pw.txt`, then
`helix --node http://<node>:8545 wallet-rpc serve` (it reads `helix.conf` in `--wallet-dir` as the
node does). That node then needs a higher rate limit (`HELIX_RPC_RATE_LIMIT=5000,1000`): the wallet
reads every block, and the node limits requests per client address. Inside the node none of that
applies.

### Methods

| Method | What it does on Helix |
|---|---|
| `getnewaddress [label]` | A new deposit address, never handed out before — recorded on disk before it is returned. A locked wallet hands out addresses it made ahead (`keypoolrefill`). |
| `listsinceblock [blockhash] [target_confirmations]` | Deposits (`receive`) and sends since that block; `lastblock` to pass next time. |
| `gettransaction txid`, `listtransactions`, `getreceivedbyaddress` | As in Bitcoin Core. |
| `getbalance` | Everything the wallet's addresses hold, less what its own unconfirmed sends take. |
| `sendtoaddress address amount … [subtractfeefromamount]` | A withdrawal from the hot address; returns the transaction id. |
| `settxfee amount` | The fee rate per kB sends pay at least; `0` goes back to the going fee. |
| `getblock blockhash [verbosity]` | 1: the block with its transaction ids; 2: with each transaction as `getrawtransaction` shows it. |
| `getrawtransaction txid true` | Any transaction in a block or in the pool, with `vin` and `vout` — see below. |
| `validateaddress`, `getaddressinfo` | Address checks; `ismine` for the wallet's own. |
| `walletpassphrase`, `walletlock`, `keypoolrefill`, `backupwallet` | As in Bitcoin Core. |
| `getinfo`, `getblockchaininfo`, `getblockcount`, `getbestblockhash`, `getblockhash`, `getnetworkinfo`, `getwalletinfo`, `estimatesmartfee` | Chain and wallet state. `getinfo` is the old all-in-one call (removed from Bitcoin Core in 0.16), kept because many integrations still make it. Versions are numbers in Bitcoin Core's form: 0.20.2 is `200200`. |

### Where Helix differs

The service says so instead of pretending:

- **An account per address, not coins.** Each deposit is **swept** to the wallet's hot address as
  soon as a block holds it, and every send pays from there. A sweep moves nothing out of the
  wallet but its fee (one base fee, a few millionths of an HLX); it is listed as a `send` of 0 with
  that fee and `helix_sweep: true`, so `getbalance` and the list add up. Deposits are swept while
  the wallet is unlocked — keep it unlocked, or unlock it before withdrawals.
- **`vout` is whom a transaction paid, `vin` the account it came from.** `getblock 2` and
  `getrawtransaction` show each account the transaction's execution credited — the recipient of a
  transfer, whoever a contract paid — from the block's balance record, as `vout` with
  `scriptPubKey.address`. **A transfer that failed paid nobody and has no `vout`**, so a block
  scanner never credits it; `helix_status` says `applied` or `failed` (with `helix_error`). The
  sender's own debit and the validator's share of the fee are not outputs; `fee` is the fee. `vin`
  holds the sending `address` — there are no previous outputs to point to. A transaction still in
  the pool has no `vout` yet: it can still fail. All of this is the chain as the wallet has read it
  (`getblockcount`): a transaction in a block it reads a moment later shows as `pending` until then,
  so every `blockhash` it gives can be passed to `getblock`.
- **No serialized forms.** `getblock` with verbosity 0 and `getrawtransaction` without `true` are
  refused (-8): Helix's blocks and transactions are not in Bitcoin's format, and bytes no client
  can decode would only look like an answer.
- **Amounts have nine decimals**, written as JSON numbers with nine fixed places (`1.250000000`)
  and read exactly as sent — never through a floating-point number. Parse them as decimals.
  Bitcoin client libraries usually round what they *send* to eight decimals (python-bitcoinrpc
  sends `float(round(amount, 8))`); up to eight arrive exactly, and a ninth has to go as a string
  (`"0.123456789"`), which the wallet reads digit by digit.
- **Or eight, with `amountdecimals=8`** — for an integration that stores eight and would cut a
  ninth off. Every amount is then written with eight, rounded the way that can never cost the
  exchange: a deposit or a balance is never shown larger than it is (1.234567891 HLX received shows
  `1.23456789`), a send or a fee never smaller, a fee rate rounds up. An amount sent with a ninth
  decimal is refused (-3), as Bitcoin Core refuses a ninth. What the wallet holds is unchanged; the
  rounding is only in what it shows.
- **One confirmation is final** (BFT); there are no reorganisations, and `removed` is always empty.
- **A send that did not go through shows `confirmations: -1`** — one the chain charged but did not
  apply (with `helix_error`), or one whose nonce another transaction used (`abandoned: true`) — as
  Bitcoin Core shows a conflicted transaction. A client waiting for confirmations never counts it
  as paid.
- **`sendmany` is refused:** a Helix transaction pays one recipient. Call `sendtoaddress` once per
  recipient.
- **Fees** are set by the wallet from the node's base fee, with headroom, and refused above 1 HLX —
  a node reporting an absurd base fee cannot spend the exchange's money. `paytxfee`/`settxfee` raise
  them, `maxtxfee` caps them; `estimatesmartfee` reports the rate per kB.
- **No ZMQ.** `walletnotify` and `blocknotify` are the push side.
- **Every transaction the wallet signs is recorded before it is submitted**, and submitted again
  if it expires unincluded — after a crash or a node restart nothing it signed is forgotten.

The node must record balance changes for every block from the wallet's start on — any node
running 0.20.2 or later does, for the blocks it executes. Back up the wallet directory, or call
`backupwallet` — keys are written once and never changed, so a backup stays valid for every address
made before it.

## Mesh (Rosetta) API

`helix mesh` serves the [Mesh API](https://docs.cdp.coinbase.com/mesh/docs/welcome) (formerly
Rosetta) in front of your node — the Data API (`/network/list`, `/network/options`,
`/network/status`, `/block`, `/block/transaction`, `/account/balance`, `/mempool`,
`/mempool/transaction`) and the Construction API for a transfer of HLX (below). It runs as its own
process and reads the node's REST API — the same endpoints this page describes — so it can be
restarted without touching the node.

```bash
helix --node http://127.0.0.1:8545 mesh --listen 127.0.0.1:8080 --network testnet
```

(0.20.2 shipped it as a separate `helix-mesh` binary; since then it is part of `helix`.)

**Raise the node's rate limit for it.** The node limits requests per client address (500 at once,
100 a second by default), and `helix mesh` is one client asking for every block. Start the node
with, for example, `HELIX_RPC_RATE_LIMIT=5000,1000`; until then a throttled request comes back
as error 10, retriable, and a sync crawls.

(`HELIX_NODE`, `HELIX_MESH_LISTEN` and `HELIX_MESH_NETWORK` set the same.) The network
identifier is `{"blockchain": "Helix", "network": "<--network>"}`; the currency is
`{"symbol": "HLX", "decimals": 9}`, and every amount is in nano-HLX.

**The node behind it must have executed every block itself** with a build that records balance
changes (0.20.2 or later): synced from genesis, not joined from a checkpoint, not pruning.
Blocks come from those records, so a block the node has no record of is refused (error 5), never
shown with operations missing.

What a block holds:

| Operation | What it is |
|---|---|
| `FEE` | the fee a transaction paid, on its sender. A **failed** transaction carries only this: what it charged is its fee |
| `TRANSFER`, `STAKE`, `CALL_CONTRACT`, … | the rest of what an applied transaction moved, one type per transaction type |
| `CONTRACT_TRANSFER` | a payment a contract made during the transaction that called it |
| `REWARD` | a validator's tips, block reward and commission. The block reward is its own transaction, `reward-<block hash>` |
| `GENESIS` | the genesis allocations, in transaction `genesis-<genesis hash>` of block 0 (whose parent is itself, as the specification asks) |

Every operation is `SUCCESS`, and together they account for every liquid balance a block moved —
`mesh-cli check:data` reconciles every account against `/account/balance` without exemptions.
Staked and unbonding amounts are not liquid balance and are not shown as one.

Balances are available at the current block only (`historical_balance_lookup: false`); asked for
another block, `/account/balance` answers error 7 rather than a balance from the wrong one.

### Construction API

`/construction/derive`, `/preprocess`, `/metadata`, `/payloads`, `/combine`, `/parse`, `/hash` and
`/submit`, for one kind of transaction: **a transfer of HLX** — two `TRANSFER` operations, one
taking an amount from the sender, one giving the same amount to the recipient. Anything else is
refused (error 11) rather than built approximately.

- **Keys and signatures are `ml_dsa_65`** (FIPS 204 ML-DSA-65, in the Mesh specification since
  July 2026): public keys 1952 bytes, signatures 3309. `/construction/payloads` returns one payload
  to sign: the transaction's **signing hash, 32 bytes**. Helix verifies it as ML-DSA-65 with an
  **empty context string** over exactly those 32 bytes, so any conforming signer — randomised or
  deterministic — produces a signature that verifies. `/combine` checks it before anything reaches
  the node (error 14 if it does not verify, or is not the sender's).
- **`/preprocess`** asks for the sender's public key (`required_public_keys`): an account's first
  transaction carries it. A **memo** goes in its `metadata` (`{"memo": "…"}`, UTF-8, at most 256
  bytes), and so does a **nonce** you choose, to build several transfers from one account before the
  first is in a block; otherwise `/metadata` takes the account's next nonce from the node.
- **`/metadata`** returns the nonce, the chain to sign for (the genesis hash) and the fee, by the
  wallets' rule — priced on the size of the *signed* transaction, refused above 1 HLX — also as
  `suggested_fee`. `/payloads` builds nothing with a fee above 1 HLX.
- **The blobs** (`unsigned_transaction`, `signed_transaction`) are the transaction's canonical bytes
  in hex. `/hash` gives the id the node will report; `/submit` answers error 12 with the node's
  reason when it refuses, and treats the same transaction already in the pool as submitted.
- **Offline:** `helix mesh --offline` serves `/network/list`, `/network/options` and the steps that
  need no node (derive, preprocess, payloads, combine, parse, hash) on the machine that signs;
  everything else answers error 13 there.

**Checked how:** Coinbase's `mesh-cli check:construction` cannot run yet — its Go SDK signs no
ML-DSA. The flow is checked end to end against a real chain instead (`crates/helix-mesh/tests/
construction_live.rs`): built through the offline endpoints, signed with this repository's
ML-DSA-65, submitted, and each balance checked to the nano — an account's first transaction (key
carried) and its second (key known, priced without it).
