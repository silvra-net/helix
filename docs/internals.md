# How Helix works — internals

> Part of the [Helix documentation](../README.md).

## Consensus

Helix uses Tendermint-style BFT finality on top of a Proof-of-Stake validator set:

1. **Propose** — elected validator proposes a new block
2. **Prevote** — all validators prevote (2/3+ needed to advance)
3. **Precommit** — validators precommit (2/3+ = instant finality)
4. **Commit** — block is final, no reorganizations possible

**Block time:** 2 seconds.

**When a proposer is offline,** the chain routes around it rather than halting. A validator that
receives no proposal within 6 ticks (~12s) prevotes **nil** — "nothing reached me" — and once 2/3+
of the voting power has said the same, every validator moves to the next round-robin proposer
together. Because that hand-off is agreed by quorum rather than decided by each node's own clock,
validators can't drift onto different rounds, which is what lets the wait be bounded. An 8-tick
round timeout remains as a backstop for the case where even nil never reaches quorum (e.g. too
much of the validator set is down to form any majority). Both windows grow with the round number
(Tendermint's `base + round · delta`, capped at 8 rounds), which is what lets two validators whose
clocks are offset converge instead of preserving the offset forever.

The nil window is deliberately wider than the time a healthy proposal needs, because it is also
the deadline for the round-sync *pull*: a validator that is missing the proposal asks a peer for
it, and an answer arriving after nil has been cast can no longer be used. It is sized against the
slowest link in the set rather than the fastest — a proposal that is sent promptly and is
perfectly valid still loses its round if it does not fan out in time.

**How a block travels.** Every transaction is gossiped once, on its own lane, when it is
submitted. Proposals and committed blocks then travel *compact*: the signed header, and for each
transaction only its id and whether the block's copy carries the sender's public key. Each node
rebuilds the block from its own pool and checks the result against the header's Merkle root, so
what it rebuilt is the block byte for byte. A node that lacks a transaction does not guess — it
asks a peer for the whole proposal (round sync), or fetches the committed block over block sync.
A full block of ~1.4 MB crosses a link as ~15 KB.

Nil is only ever a prevote. Helix never *precommits* nil, so "precommit quorum" keeps meaning
exactly one thing: a real block is final.

**When a validator stays silent for good** (crashed, never actually running, network-
partitioned — not just a slow round), round-advancement alone can't save liveness: with a small,
equal-stake validator set, `2/3+1` quorum can require *every* validator's vote, and no amount of
round-timeouts changes that. Helix does **not** paper over this with a local override. An earlier
build let each node drop a silent validator's power from its *own* quorum math, so a lone
validator could keep finalizing — but that is exactly the door through which two partitions each
finalize their own history, it forked the live chain once, and it was removed.

The consequence is blunt and deliberately honest: **if a validator the quorum depends on goes
silent, block production halts until it comes back.** A halt is visible and heals the instant the
node returns; a fork silently duplicates the whole ledger, balances and all, and does not. Between
the two, halting is the safe failure.

What still recovers on its own is the case where the set is large enough that quorum survives the
loss. Every block header carries `last_commit` — the precommit signatures that finalized its
*parent* (see `helix_core::CommitSig`) — and `ChainState` keeps, per validator, a debt that every
missing signature raises by 2 and every present one pays down by 1. It grows while a validator
signs fewer than two thirds of the blocks — the share quorum asks of the set — and shrinks above
that, so a validator that signs *now and then* is caught as surely as one that never does. A
validator that is silent outright reaches the threshold after exactly 1800 blocks (~1 hour at 2 s),
and is then **downtime-jailed**: removed from `stakers()` outright, independent of
stake, until it submits an explicit `Unjail` transaction (see [Staking](staking.md#staking)). It survives
node restarts and carries no slash — downtime isn't proof of malice, only lost quorum weight and
rewards while jailed. The catch is the same arithmetic as above: jailing is *counted from blocks*,
so it only ever fires while the chain is still producing them. In a set so small that quorum needs
every validator, a single silence stops the very blocks that would have counted the absence —
which is another way of saying that **three or fewer validators tolerate no fault at all** — four
survive one, seven survive two (see [Security](../README.md#security)).

Only validators in the **active set** are scored this way. A validator that has staked but is
still waiting out its one-epoch activation delay (see [Staking](staking.md#staking)) is not in the quorum
yet — nothing solicits its precommit and none would be counted — so those blocks are not held
against it. The wait the protocol imposes never counts as downtime.

**Voting power** is capped at 1% of all stake for every validator (`total_stake / 100`).
**Proof of Personhood** changes what goes into the cap, not the cap:
- Without verification: half the validator's stake, up to the cap
- With verification: the full stake, up to the cap

So personhood helps only a validator below the cap; one already at it gains nothing.

> **How far this is tested.** Vote counting, equivocation detection, double-sign slashing and
> Tendermint-style **cross-round vote locking** (`locked_value` / proof-of-lock — what stops two
> different blocks from finalizing at the same height across rounds) are covered by unit tests
> and by harnesses that run several real consensus engines against each other: a fault-injection
> harness (silent, deaf and partitioned validators), a chaos harness (a third of all messages lost
> for 400 ticks across fifty randomized networks — no fork in any run), and Byzantine tests with a
> validator that equivocates, including a split-brain one that sends each half of the network a
> different block. Multi-node tests run the same with real node processes. The live network has
> run with four to six validators; behaviour at a much larger scale is shown in tests, not yet in
> production. See [Security](../README.md#security).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        helix-node                           │
│              (orchestrator, event loop, P2P)                │
├──────────────┬─────────────┬────────────────┬───────────────┤
│ helix-rpc    │ helix-p2p   │ helix-consensus│ helix-executor│
│ REST API     │ libp2p      │ PoS + BFT      │ state machine │
├──────────────┼─────────────┼────────────────┼───────────────┤
│ helix-mempool│             │                │ helix-vm      │
│ tx pool      │             │                │ helix-zkp     │
├──────────────┴─────────────┴────────────────┴───────────────┤
│                       helix-storage                         │
│              Persistent (redb-backed HelixDb)               │
├─────────────────────────────────────────────────────────────┤
│  helix-core    │  helix-crypto   │  helix-identity          │
│  Block, Tx     │  ML-DSA, BLAKE3 │  Names, Personhood       │
│  TxType, etc.  │  Addresses      │  Social Recovery         │
└─────────────────────────────────────────────────────────────┘

helix-cli: the client subcommands, compiled into the same `helix` binary as the node.
CLI ←→ REST API :8545 ←→ node ←→ P2P :8546 ←→ other nodes
```

---

## Cryptography & Determinism

| Primitive | Algorithm | Standard | Quantum-safe |
|---|---|---|---|
| Digital Signatures | ML-DSA-65 | NIST FIPS 204 | ✅ |
| Backup Signatures | SLH-DSA-SHA2-192s | NIST FIPS 205 | ✅ |
| Hashing | BLAKE3 | — | ✅ (2× security margin vs Grover) |
| Zero-Knowledge | ZK-STARKs | — | ✅ (hash-based) |
| Transport | libp2p Noise (X25519) | — | Classical — see note |

> **What is and isn't quantum-safe here.** Everything that goes *onto the ledger* — signatures
> (ML-DSA), the state it commits to, and the hashes/proofs binding it together — is
> post-quantum. The peer-to-peer *transport* encryption is libp2p's classical Noise (X25519),
> which is fine for a blockchain: all P2P traffic (blocks, transactions, votes) is public data
> broadcast to every peer, so there is nothing confidential for a "harvest-now-decrypt-later"
> quantum adversary to steal. What a quantum adversary *could* eventually do — forge signatures
> or rewrite history — is exactly what the post-quantum signature and hash layer prevents. An
> earlier ML-KEM-768 session-encryption overlay was removed: it added key-exchange machinery
> that never actually encrypted anything, so it was misleading complexity rather than added
> security.

**State commitment:** every block carries the root of the state its predecessor produced
(`prev_state_root`), signed by its proposer and checked by every node that applies the block, so
two nodes whose execution differs find out at the next block. The root is a **lattice hash**
(LtHash, the construction Solana commits its accounts with, via `solana-lattice-hash`): every
entry of the state — an account, a name, a delegation share, one contract storage slot — is
encoded with a tag for its kind, mapped by BLAKE3's extendable output onto 1024 sixteen-bit
lanes, and the lanes of all entries are summed; the root is BLAKE3 over the sum. A sum does not
depend on the order entries are written in, and it can be updated: a block subtracts the old
encoding of each entry it changed and adds the new one, so it costs what the block wrote, not what
the chain holds (0.13 ms per block at 100,000 accounts, against 55 ms for rehashing everything).
A state that arrives whole — a snapshot, a database at start — is summed once from every entry.
There are no membership proofs (nothing needs them yet); they can be added later through a
protocol upgrade without a reset.

**Contract determinism:** `helix-vm` disables WASM floats entirely (via wasmi's
`WasmFeatures` validator gate, rejected at deploy time) — every validator must reach the
identical execution result for the identical call, and floats are a known cross-platform
non-determinism risk (the reason the EVM never got them). Execution is fuel-metered
(`--fee` doubles as the fuel budget), so an out-of-gas contract traps deterministically
instead of hanging a validator.

**Contract host imports:** a contract talks to the chain through a small `(ptr, len)`
byte-buffer ABI under the WASM import module `"env"`:

| Function | Signature | Purpose |
|---|---|---|
| `storage_read` | `(key_ptr, key_len, out_ptr, out_len) -> i32` | Read this contract's own storage |
| `storage_write` | `(key_ptr, key_len, val_ptr, val_len) -> i32` | Write this contract's own storage |
| `transfer` | `(addr_ptr, addr_len, amount) -> i32` | Move real HLX out of this contract's balance |
| `get_caller` / `get_self_address` | `(out_ptr, out_len) -> i32` | The calling address / this contract's own address |
| `get_input` | `(out_ptr, out_len) -> i32` | The `--data` bytes passed with this call |
| `get_value` / `get_block_height` | `() -> i64` / `() -> i64` | HLX sent with this call / current block height |
| `set_return_data` | `(ptr, len) -> i32` | Set this call's return data (not yet surfaced to callers) |

Every storage read/write, transfer, and context read costs fuel, so there's no free way to
grief a validator into doing unbounded work. A contract can **only** read/write its own
storage and move its own balance — there is deliberately no cross-contract call import in
this version, which removes reentrancy as an attack surface entirely rather than requiring
every contract author to defend against it themselves. All effects of a call are buffered and
only committed to real chain state if the call succeeds; a trap (explicit `unreachable`,
out-of-bounds memory access, running out of fuel) rolls back every storage write and transfer
the call made, with zero partial effects — while the fee is still charged and the nonce still
advances, since real compute was spent either way.

---

## Token Economics

- **Hard cap:** 33,000,000 HLX — never more, forever. This is an *honest* ceiling: it sits
  just above what the emission schedule actually pays out (the 1 HLX halving subsidy converges
  to ~31.5M emitted, plus the 100k genesis allocation ≈ 31.6M real max supply), not an
  aspirational round number the chain could never reach. The same asymptotic shape as Bitcoin's
  21M cap — approached over time, not handed out at genesis.
- **Genesis allocation:** 100,000 HLX — the bootstrap validator's 10k stake (exactly the
  minimum the rules demand of any validator, `MIN_VALIDATOR_STAKE`) plus a 90k liquid reserve.
  The reserve does two jobs: a slash that drops the stake below the minimum is recoverable, and
  the network's operators are funded out of it (15k apiece). That is ~0.3% of the supply the
  chain eventually reaches; everything else is earned block by block. There is no founder
  pre-mine beyond this.
- **Denomination:** 1 HLX = 1,000,000,000 nano-HLX
- **Fee split:** the base fee (`base_fee_per_byte × transaction size`) is burned in full; the
  rest of what the sender paid is the validator's tip. Not a fixed ratio — a sender who pays
  exactly the base fee tips nothing. See [Fees](cli.md#fees) and `TOKENOMICS.md`.
- **Block reward:** a halving issuance schedule mints new HLX every block (independent of
  transaction volume), so validator income doesn't depend on fee revenue alone. Starts at
  1 HLX/block, halves every 15,768,000 blocks (~1 year at the 2s block time) — the same
  geometric-decay shape as Bitcoin's coinbase subsidy, always clamped so cumulative issuance
  never crosses the 33M cap regardless of what the schedule alone would pay out.
- **Minimum validator stake:** 10,000 HLX (~0.03% of supply) — runtime-adjustable via
  governance, floored at 100 HLX so it can never be pushed low enough to let unstaked
  accounts flood the validator set.
- **Unbonding period:** 7 days from `tx unstake` to claimable — stake stays slashable the
  whole time. Same for delegated stake redeemed via `tx undelegate`: it remains slashable for
  the validator it was withdrawn from until the period ends. `tx redelegate` skips the wait
  but not the window: the stake earns at its new validator immediately while staying slashable
  for the old one for the same 7 days.
- **Slashing:** 5% of staked HLX burned, plus immediate exclusion from BFT rounds, on
  confirmed double-sign. Reaches the validator's own stake, its delegation pool, any stake
  still unbonding out of either, and any stake that redelegated away inside the window — so no
  exit taken ahead of the evidence escapes it.
- **Circulating supply** = total issued − total burned. Total issued starts at the genesis
  allocation (100,000 HLX) and grows block by block via the emission schedule above.

---
