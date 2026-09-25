# Using the Helix CLI

> Part of the [Helix documentation](../README.md) — deep reference, split out of the README to keep it short.

## Using the CLI (`helix`)

The client subcommands of the `helix` binary (`helix wallet`, `helix tx`, `helix chain`, …)
talk to a node over its REST API — the same binary that runs the node with `helix start`, but
these commands never boot a node or open the chain database.

They pick a node in this order: whatever you passed with `--node` (or `HELIX_NODE=...`), then a
node running on this machine, then the public network (`https://node.silvra.net`). So running
your own node is enough to be asked — you do not have to configure anything — while a freshly
downloaded binary still works against the live chain out of the box. When a local node answers,
the client says so on stderr, and says it too if that node is still catching up, so a balance
from an unsynced chain is never presented as current. `stdout` is unaffected, so piping into
`jq` works exactly as before.

The client itself holds no state beyond whatever wallet file you point it at.

### Wallets

```bash
helix wallet new -o alice.json                       # generate a new ML-DSA keypair
helix wallet new -o alice.json --passphrase          # ...encrypted at rest — asks twice, no echo
helix wallet new -o alice.json --scheme sphincs-plus  # ...using SPHINCS+ instead of ML-DSA

helix wallet restore                                  # rebuild a wallet from its 24 words
helix wallet restore --mnemonic "trim thought ..."    # ...non-interactively (lands in shell history)

helix wallet info --key alice.json                    # address, public key, algorithm
helix wallet address --key alice.json                 # just the address (for scripting)
helix wallet address --key alice.json --verify        # ...unlocked and derived from the key itself
helix wallet encrypt --key alice.json                 # add/change its passphrase (asks, no echo)
helix wallet encrypt --key alice.json --remove        # remove the passphrase

```

**A validator key is already a wallet — no conversion needed.** The node's
`validator-key.json` is the exact same file format `helix wallet` produces, so you use it
directly with any command: `helix tx send ... --key validator-key.json`. There is no
per-use conversion step.

A wallet file is portable — it's just JSON. Anyone with the file (and its passphrase, if
encrypted) can sign as that address, so treat it like a private key, because it is one.

**A passphrase is never typed on the command line.** Anything there is saved in your shell
history — next to the wallet it protects — and readable by every user on the machine in the
process list while the command runs. So `--passphrase` takes no value: it asks, twice, without
echo, and refuses an empty answer. `--passphrase <value>` is refused with an explanation, and
the value is **not** used — treat it as exposed and choose another. Scripts read the passphrase
from a file instead:

```bash
helix wallet new -o bot.json --passphrase-file /run/secrets/helix-bot   # a mounted secret
helix wallet new -o bot.json --passphrase-file <(pass show helix/bot)   # never touches a disk
```

The file is used exactly as it is, minus one trailing newline (so `echo secret > file` works) —
spaces belong to the passphrase. An empty file is refused rather than giving you a wallet
without one, and a file other users can read gets a warning. The same two options work on
`wallet restore`, `wallet import-node-key` and (as `--passphrase-file`) `wallet encrypt`.

**Opening an encrypted wallet to sign** works the same way. Every command that signs — the `tx`
commands, `name register`, `identity attest`, `recovery register-guardians|approve`, `contract
deploy|call`, `governance propose|vote` — asks on the terminal, or reads `--passphrase-file`:

```bash
helix tx send hlx... 10 --key bot.json --passphrase-file /run/secrets/helix-bot
```

A script has nobody to answer a prompt, so with a file there is none: a passphrase that does not
open the wallet is an error naming the file, and an empty file says it is empty (usually a secret
that never arrived). Without a terminal and without the option, the error says to use
`--passphrase-file`. A file given for a wallet that has no passphrase is not read — the command
signs, and tells you the wallet is unencrypted. The `wallet` commands that open an existing
wallet (`address --verify`, `encrypt`) still ask on the terminal; there, `--passphrase-file`
means the *new* passphrase.

**What the CLI does to protect that file:**
- `wallet new`, `wallet restore` and `wallet import-node-key` **never overwrite** an existing
  file. Running `helix wallet new` twice in one directory used to replace the first
  `wallet.json` with a new wallet; now the second run stops with "already exists". Pick another
  `-o`, or move the old file away first.
- Key files are written **readable by their owner only** (mode `0600`), whatever the umask.
  Files written by older versions keep their mode until `wallet encrypt` rewrites them; to fix
  one by hand: `chmod 600 alice.json`.
- `wallet encrypt` replaces the file **in one step** (written beside it, then renamed), so a
  crash or a full disk cannot leave you with an empty wallet file.
- **A file whose address does not belong to its key is refused.** The address is stored in
  plaintext next to the (possibly encrypted) key, so someone who can write the file but does
  not know the passphrase could otherwise swap in their own address and have `wallet address`
  hand it out as yours. If you ever see "does not belong to the key stored in it", do not use
  the address that file shows — restore from your 24 words. One limit remains: `wallet
  address` and `wallet info` do not unlock the key, so a file forged consistently (address
  *and* public key replaced together) is only caught when the wallet is next unlocked — by any
  `tx` command, by `wallet address --verify`, or by the desktop wallet, which always unlocks.
  Before handing out an address for a large payment, get it with `--verify`.

#### The recovery phrase

Creating an ML-DSA wallet prints 24 words, once. Write them on paper. They *are* the wallet:
`helix wallet restore` turns them back into the exact same address on any machine, with no file
to copy — which is the point, because a wallet file lives on a disk, and disks die with the
machine they're in.

They are shown once and never again. The wallet file stores the key, not the words, and there is
no command to reprint them — a command that turns a wallet file into a displayed key is a
liability, not a feature. If you lose the phrase, the file still works; if you lose both, the
wallet is gone, and nobody can help you.

The words also work in the Spark app: same 24 words, same address, since both derive the key from
the same seed the phrase encodes. (SPHINCS+ wallets have no phrase — that scheme's key is not
re-derivable from a seed, so its file is the only copy.)

*(A converter, `helix wallet import-node-key`, exists only for the pre-2026-07 raw-binary key
format some very old nodes wrote. You almost certainly don't have one — modern keys are
already the JSON format.)*

### Sending HLX

```bash
helix tx send hlx... 10.5 --key alice.json            # send 10.5 HLX
helix tx send hlx... 10.5 --key alice.json --fee 20000  # pin the fee yourself; omit --fee and
                                                       # the CLI prices it off the chain's
                                                       # current base fee (see Fees, below)
helix tx status <hash>                                 # applied / failed (+ reason) / pending
```

### Fees

Helix charges **per transaction byte**, not per transaction: a block carries a base fee
(`base_fee_per_byte`, visible in `helix chain status`) and every transaction owes
`base_fee_per_byte × its size`. That portion is burned; anything above it tips the validator and
buys priority. The base fee drifts up to ±12.5% per block toward a 1 MB target, so it rises under
load and decays back to its floor of 1 nano/byte when blocks are quiet.

Size matters more here than on most chains, because Helix signs with post-quantum ML-DSA: a
signature is 3,309 bytes and a public key 1,952, so **a plain transfer is ~5.4 KB and costs
~5,410 nano-HLX at the floor** — about 0.0000054 HLX. A contract deploy carries its own bytecode
on top and costs proportionally more (up to ~71,000 nano at the 64 KiB code limit).

This is why `--fee` is optional and best left alone: omit it and the CLI asks the node what it
currently charges, prices the transaction for its actual size, and adds 100% headroom so it still
clears if the base fee climbs while the transaction waits. Pin `--fee` only when you want to
overpay for priority — or underpay and find out. A transaction paying less than its size costs is
rejected on submission, with the shortfall spelled out.

**A fee the CLI works out for itself never exceeds 1 HLX.** The base fee comes from the node you
talk to, and nothing in the protocol caps it — so a node that lies (a stranger's public endpoint,
or a compromised one) could otherwise have your wallet sign a transfer with millions of HLX in
fees. At the floor a transfer costs about 0.00001 HLX; the ceiling is ~92,000 times that. Above
it the CLI stops with "Not sent", the reported base fee and the fee in HLX. If the network really
is that busy, check the base fee against another node or the explorer and pass `--fee`
explicitly — an explicit fee is never second-guessed. The desktop wallet applies the same ceiling
and, having no fee field, asks you to wait or use the CLI.

Two rules follow from the fee being real money rather than a number you write down:

- **You must be able to afford the fee you declare.** Submission checks it against your balance
  and refuses otherwise. The mempool ranks by fee, so a fee nobody can pay would otherwise buy a
  place ahead of people who can.
- **A transaction that fails still pays.** If it was yours, correctly ordered, and you could cover
  the fee, then it took a block slot and a validator's time — a transfer larger than your balance,
  a contract call that runs out of fuel, a stake of zero. The fee is charged and the nonce
  advances; only the effect is missing. `helix tx status <hash>` reports `failed` and the reason.
  A transaction you *cannot* pay the fee for is not includable at all and costs nothing, because
  there is nothing to take.

### Querying the Chain

```bash
helix chain status               # height, best hash, peer count, mempool size, sync state
helix chain latest               # latest block, full transaction list
helix chain block 142            # block by height
helix account hlx...             # balance, staked amount, nonce
helix validator show hlx...      # a validator's pool: delegated stake, commission, effective stake
```

Every one of these talks to a node running on this machine if one answers, and the public network
otherwise. The chosen endpoint is printed to stderr, not stdout, so piping into `jq` is unaffected.
Override with `--node <url>` or `HELIX_NODE=<url>`.

### Human-Readable Names

Register a `name.hlx` alias for your address instead of sharing the raw `hlx...` string:

```bash
helix name register alice --key alice.json     # registers alice.hlx to alice.json's address
helix name resolve alice.hlx                   # -> hlx...
```

### Smart Contracts

Contracts are WASM modules; the exported `call` function is the entry point. A small set of
host imports lets a contract read/write its own persistent key-value storage, move real HLX
balance, and read call context (caller, value sent, block height, input data) — see
[Cryptography & Determinism](internals.md#cryptography--determinism) for the full host-function ABI and
what it does and doesn't mean for safety. There is deliberately no cross-contract call import
in this version — a contract can only touch its own storage and move its own balance, which
closes off reentrancy as an attack surface entirely rather than requiring every contract
author to defend against it.

```bash
helix contract deploy my_contract.wasm --key alice.json
#   Contract address: hlx...   (the deployer's own address — see note below)

helix contract call hlx... --key alice.json --amount 1.5 --fee 50000 --data "hello"
#   --fee also sets the fuel budget for this call — a call that runs out of fuel still
#   charges the fee and advances the nonce, exactly like real gas markets do on revert
#   --data is passed to the contract's call function as raw input bytes (UTF-8 encoded)

helix contract storage hlx... greeting
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

`helix identity status <address>` shows an address's verification status
(`Unverified`/`Verified`). Verification itself is intentionally gated behind a network
personhood authority's signature over a ZK-STARK proof (`ProvePersonhood`), not exposed as a
plain CLI flow yet — the point is that Sybil resistance can't come from a client-side command
alone. `helix identity attest` still exists as a command but always fails on submission: an
earlier, unauthenticated "3 peers vouch for you" attestation path existed and was removed
(the transaction now unconditionally rejects) once it became clear it bypassed the
authority-gated proof entirely.

Verified personhood matters for one thing: a validator's full stake counts toward its voting
power instead of half of it. The cap is the same for everyone — 1% of all stake — so
personhood helps only a validator below it; one already at the cap gains nothing (see
[Consensus](internals.md#consensus)).
It is not required to hold, send, or stake HLX.

### Social Recovery

Lets a small group of guardians rotate a lost account to a new key, without ever exposing the
original key or requiring a central recovery authority.

```bash
# 1. The account owner registers 3-10 guardians (their addresses, not keys)
helix recovery register-guardians hlx... hlx... hlx... --key owner.json

# 2. Check the guardian set and quorum threshold at any time
helix recovery status hlx...
#   Guardians (2 of 3): [...]
#   Quorum is proportional to however many guardians you register (roughly 2/3, rounded
#   up) — not a fixed "3-of-5" regardless of set size, despite what the set size range
#   (3-10) might suggest.

# 3. If the owner loses their key: each guardian independently approves rotating
#    the account to a replacement public key (hex-encoded)
helix recovery approve hlx... <new_pubkey_hex> --key guardian1.json
helix recovery approve hlx... <new_pubkey_hex> --key guardian2.json
#    Once enough guardians approve (quorum, shown by `recovery status`), the account's
#    controlling key rotates immediately — the old key is permanently locked out, the new
#    key can now sign for that address. Re-recovery to yet another key later works the same
#    way, any number of times.
```

**Replacing your guardians works even with a recovery vote in progress**, and doing so
cancels that vote. An owner who can still sign outranks a guardian's part-way approval —
recovery exists for a key that is *lost*, and signing proves yours is not. So a guardian who
turns hostile or unresponsive can simply be replaced; you do not have to clear anything first.

A stuck sub-threshold request can also be cleared on its own, without touching the guardian
set, at the protocol level (`CancelRecoveryRequest`, signed by the account owner). There is no
`helix recovery` CLI subcommand for either yet; both currently require constructing the
transaction directly against the REST API.

(Until 2026-09-22 registering guardians was *refused* while any request was pending, and
cancelling was the documented way out. It did not work: the owner needs two transactions
landing with nothing in between, a guardian needs one approval to re-open the request, and the
proposer decides the order inside a block — so a hostile guardian could never be removed.)

### Governance

Any account with a nonzero stake (see [Staking](staking.md#staking) — this does *not* require the full
validator minimum) can propose and vote on two runtime-adjustable parameters:
`min-validator-stake` and `fuel-per-fee-unit`.

```bash
helix governance params                          # current values
helix governance propose fuel-per-fee-unit 3 --key alice.json
helix governance list                            # all proposals
helix governance show 0                          # one proposal's vote tally
helix governance vote 0 --key alice.json          # cast a stake-weighted yes-vote
```

A proposal passes once yes-votes reach a 2/3-plus-one supermajority of the total stake that
existed *when the proposal was created* (frozen at creation so a voter can't game the
denominator by unstaking after voting), or expires unexecuted after 1000 blocks. Every
address can vote once per proposal.

---
