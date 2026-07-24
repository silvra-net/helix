# Using the Helix CLI

> Part of the [Helix documentation](../README.md) — deep reference, split out of the README to keep it short.

## Using the CLI (`helix`)

The client subcommands of the `helix` binary (`helix wallet`, `helix tx`, `helix chain`, …)
talk to a node over its REST API — the same binary that runs the node with `helix start`, but
these commands never boot a node or open the chain database. They target the public network
(`https://helix.silvra.net`) by default; point them at your own node with `--node
http://127.0.0.1:8545` (or `HELIX_NODE=...`). The client itself holds no state beyond whatever
wallet file you point it at.

### Wallets

```bash
helix wallet new -o alice.json                       # generate a new ML-DSA keypair
helix wallet new -o alice.json --passphrase "..."     # ...encrypted at rest (AES-256-GCM + Argon2id)
helix wallet new -o alice.json --scheme sphincs-plus  # ...using SPHINCS+ instead of ML-DSA

helix wallet restore                                  # rebuild a wallet from its 24 words
helix wallet restore --mnemonic "trim thought ..."    # ...non-interactively (lands in shell history)

helix wallet info --key alice.json                    # address, public key, algorithm
helix wallet address --key alice.json                 # just the address (for scripting)
helix wallet encrypt "newpass" --key alice.json        # add/change passphrase on an existing wallet
helix wallet encrypt "" --key alice.json               # remove passphrase encryption

```

**A validator key is already a wallet — no conversion needed.** The node's
`validator-key.json` is the exact same file format `helix wallet` produces, so you use it
directly with any command: `helix tx send ... --key validator-key.json`. There is no
per-use conversion step.

A wallet file is portable — it's just JSON. Anyone with the file (and its passphrase, if
encrypted) can sign as that address, so treat it like a private key, because it is one.

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
```

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

Verified personhood matters for one thing: it raises your voting-power cap as a validator
from 0.5% to 1% of the network (see [Consensus](internals.md#consensus)).
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

A single stuck guardian request that never reaches quorum can be cleared at the protocol
level (`CancelRecoveryRequest`, signed by the account owner with their still-valid original
key) so a malicious or unresponsive guardian can't lock you out of ever changing your
guardian set — but there is no `helix recovery` CLI subcommand for it yet; it currently
requires constructing that transaction directly against the REST API.

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
