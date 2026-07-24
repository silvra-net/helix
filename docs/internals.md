# How Helix works — internals

> Part of the [Helix documentation](../README.md) — deep reference, split out of the README to keep it short.

## Consensus

Helix uses Tendermint-style BFT finality on top of a Proof-of-Stake validator set:

1. **Propose** — elected validator proposes a new block
2. **Prevote** — all validators prevote (2/3+ needed to advance)
3. **Precommit** — validators precommit (2/3+ = instant finality)
4. **Commit** — block is final, no reorganizations possible

**Block time:** 2 seconds.

**When a proposer is offline,** the chain routes around it rather than halting. A validator that
receives no proposal within 2 ticks (~4s) prevotes **nil** — "nothing reached me" — and once 2/3+
of the voting power has said the same, every validator moves to the next round-robin proposer
together. Because that hand-off is agreed by quorum rather than decided by each node's own clock,
validators can't drift onto different rounds, which is what lets the wait be short. A 15-tick
round timeout remains as a backstop for the case where even nil never reaches quorum (e.g. too
much of the validator set is down to form any majority).

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
*parent* (see `helix_core::CommitSig`) — and `ChainState` counts, per validator, how many
consecutive blocks its signature was absent from. After ~150 blocks (~5 minutes) of confirmed
absence, the validator is **downtime-jailed**: removed from `stakers()` outright, independent of
stake, until it submits an explicit `Unjail` transaction (see [Staking](staking.md#staking)). It survives
node restarts and carries no slash — downtime isn't proof of malice, only lost quorum weight and
rewards while jailed. The catch is the same arithmetic as above: jailing is *counted from blocks*,
so it only ever fires while the chain is still producing them. In a set so small that quorum needs
every validator, a single silence stops the very blocks that would have counted the absence —
which is just another way of saying **a small validator set tolerates zero faults** (see
[Security](../README.md#security)).

Only validators in the **active set** are scored this way. A validator that has staked but is
still waiting out its one-epoch activation delay (see [Staking](staking.md#staking)) is not in the quorum
yet — nothing solicits its precommit and none would be counted — so those blocks are not held
against it. The wait the protocol imposes never counts as downtime.

**Proof of Personhood** caps how much voting power a single identity can accumulate:
- Without verification: voting power capped at 0.5% of the network
- With verification: voting power capped at 1% of the network

> **Maturity note (please read before relying on it).** The public Helix network currently
> runs a small validator set. The vote-counting, equivocation detection, double-sign slashing, and
> Tendermint-style **cross-round vote locking** (`locked_value` / proof-of-lock — the safety
> mechanism that stops two different blocks from finalizing at the same height across rounds
> under a network partition or a ⅓-Byzantine validator set) are all in place and unit-tested.
> What is *not* yet proven is behaviour under a large, genuinely adversarial, untrusted
> **≥4-validator** network — that needs real-world partition and Byzantine testing before the
> BFT-safety guarantee should be relied on in production. See [Security](../README.md#security).

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
│              Persistent (redb-backed HelixDb)               │
├─────────────────────────────────────────────────────────────┤
│  helix-core    │  helix-crypto   │  helix-identity          │
│  Block, Tx     │  ML-DSA, BLAKE3 │  Names, Personhood       │
│  TxType, etc.  │  Addresses      │  Social Recovery         │
└─────────────────────────────────────────────────────────────┘

CLI: helix <subcommand>   ←→   REST API :8545   ←→   P2P :8546
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
  to ~31.5M emitted, plus the 200k genesis allocation ≈ 31.7M real max supply), not an
  aspirational round number the chain could never reach. The same asymptotic shape as Bitcoin's
  21M cap — approached over time, not handed out at genesis.
- **Genesis allocation:** 200,000 HLX — the bootstrap validator's 100k stake (exactly the
  minimum the rules demand of any validator) plus a 100k liquid reserve, so a slash that drops
  it below that minimum is recoverable. That is ~0.6% of the supply the chain eventually
  reaches; everything else is earned block by block. There is no founder pre-mine beyond this.
- **Denomination:** 1 HLX = 1,000,000,000 nano-HLX
- **Fee split:** the base fee (`base_fee_per_byte × transaction size`) is burned in full; the
  rest of what the sender paid is the validator's tip. Not a fixed ratio — a sender who pays
  exactly the base fee tips nothing. See [Fees](cli.md#fees) and `TOKENOMICS.md`.
- **Block reward:** a halving issuance schedule mints new HLX every block (independent of
  transaction volume), so validator income doesn't depend on fee revenue alone. Starts at
  1 HLX/block, halves every 15,768,000 blocks (~1 year at the 2s block time) — the same
  geometric-decay shape as Bitcoin's coinbase subsidy, always clamped so cumulative issuance
  never crosses the 33M cap regardless of what the schedule alone would pay out.
- **Minimum validator stake:** 100,000 HLX (~0.3% of supply) — runtime-adjustable via
  governance, floored at 1,000 HLX so it can never be pushed low enough to let unstaked
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
- **Circulating supply** = total issued − total burned. Total issued starts small (just the
  genesis validator stake) and grows block by block via the emission schedule above.
- No liquid HLX is pre-mined to any wallet at genesis — the genesis validator receives only
  its bootstrap stake, and earns everything beyond that the same way any future validator
  would: by producing blocks.

---
