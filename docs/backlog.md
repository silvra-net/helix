# Backlog — Validator liveness, onboarding & operator tooling

Consolidated from the 2026-07-26 investigation into the recurring multi-validator
join stall ("a second validator bonds, then goes silent after its activation epoch
and the chain halts"). Grouped by priority. Items reference the external CTO backlog
where a number already exists; new items are numbered locally as `NEW-n`.

## Root cause summary (read this first)

Three distinct things stack up into the observed stall:

1. **The regression that flipped "works" to "halts" (0.8.5).** Commit `09d2de2`
   removed the local liveness exclusion (`liveness_adjusted_validator_set`) because
   it forked the chain (two groups each finalizing below quorum). Correct for safety
   — but in ≤0.8.4 it *masked* a briefly-silent joining validator by routing around
   it, which is why onboarding "just worked" with up to 5 validators. Since 0.8.5 a
   silent validator halts the chain (proper BFT). Do **not** re-add the exclusion.

2. **No sync/liveness gate before activation (the design gap).** Staking is a pure
   balance-transfer tx (`execute_stake`), activation is stake-threshold + a one-epoch
   `pending_validators` delay that only *warns*, and the validator health heartbeat is
   log-only (`validator_health_loop`, purely observational). So "bonded" (chain-state
   `active_validators`, what the explorer shows) is fully decoupled from "actually able
   to validate" (live `BftEngine.validator_set`). A node can be counted toward quorum
   while its live engine cannot participate.

3. **The set-source divergence (`engine_validator_set()` fallback).** When
   `active_validators` is empty it fell back to raw `stakers()` (no activation delay).
   `active_validators` is empty not only in the genesis window but through the entire
   *first activation epoch* (the first rotation defers everyone). A node building its
   live set from that fallback while a newcomer had already staked ran the undelayed
   set and diverged from the live one. **Fixed on this branch** (see DONE below).

At 2-of-2 any of these is fatal and unrecoverable: a halted set produces no blocks, so
no governance tx can shrink it. The structural answer is ≥4 validators (`3f+1`).

---

## P0 — Diagnose the live incident (needs the running nodes; cannot be done from the repo)

- [ ] **P0-1 — Read V2's `HealthVerdict`.** `WaitingActivation` (engine does not see
      itself in the active set → rotation didn't apply *or* consensus-key ≠ staking
      address) vs `NotValidating` (engine has itself but is still silent → round-state
      / proposer problem). Splits the whole problem in one line.
- [ ] **P0-2 — Compare V2's consensus-key address vs the bonded staking address** in
      `active_validators`. If they differ it is an onboarding/config fault, not a
      consensus bug — rule this out before touching consensus code.
- [ ] **P0-3 — V2 log around the activation height:** did `Validator set rotated
      (validators=N)` / `reconciled from synced state` appear? Establishes whether V2
      crossed activation while live or while syncing.
- [ ] **P0-4 — Recover the halted chain** (depends on P0-1..3). Document that a small
      set cannot self-recover from a halt.

## P1 — Close the design gap & fix the real bugs

- [ ] **P1-1 (NEW-1) — Pre-activation liveness gate.** Promote `pending → active` only
      after the joiner submits a signed heartbeat/attestation at a recent height. Binds
      voting power to a demonstrably-synced node instead of to elapsed time. This kills
      the whole bug class at the root.
- [ ] **P1-2 (NEW-2) — Client-side stake guard.** `hlx stake --validator` refuses / hard-
      warns while the local node reports `is_syncing`, and warns if the consensus key
      address ≠ the staking address.
- [ ] **P1-3 (NEW-3) — Real end-to-end liveness regression test.** Activation *across*
      the epoch boundary **and** production of the following block under N-of-N. The
      existing `a_validator_that_activates_while_syncing_ends_up_in_its_own_live_set`
      only asserts set *membership* at exactly `EPOCH_LENGTH*2` and misses the liveness.
- [ ] **P1-4 (NEW-4) — Single source of truth for the validator set.** Make the live
      `BftEngine` set a pure function of applied chain state, updated identically on
      *every* apply path (finalize, committed-block gossip, sync, gap-fill) instead of
      `rotate_validator_set` on some paths + `reconcile_engine_validator_set` on others.
      The patchwork is what keeps reopening the boundary bug.

## P2 — Observability, operator tooling & robustness

- [ ] **P2-1 (NEW-5) — Validator version in the explorer.** Version already lives in
      `/status`. Fast path: explorer polls each known validator's `/status`. Cleaner:
      add version to the gossiped health heartbeat. Show height + last-co-signed height
      alongside it. Diagnostic only — never consensus-relevant. (Requested 2026-07-26.)
- [ ] **P2-2 (NEW-6) — Local chain reset in CLI + GUI.** `hlx reset --confirm
      [--keep-keys (default)] [--genesis <file>]` and a guarded GUI button (typed
      confirmation). Separate "wipe local DB + re-sync" from "coordinated reset to a new
      genesis". **Never** delete keys/wallet; **testnet/devnet-only**. (Requested 2026-07-26.)
- [ ] **P2-3 (NEW-7) — "Two worlds" diff surfaced.** Per validator: chain-state
      `active_validators` vs live `BftEngine` set. Exactly the divergence that was
      invisible during this incident.
- [ ] **P2-4 (NEW-8) — Stall panel.** Height, round, quorum threshold vs available power,
      and *who is silent* (`record_round_liveness` already names them in the log — lift it
      into explorer/GUI), plus "stalled for Xs, waiting on validator Y".
- [ ] **P2-5 (NEW-9) — Last-signed height per validator** (from `last_commit`) in the
      explorer — instantly shows who stopped co-signing and when.
- [ ] **P2-6 (NEW-10) — Activation countdown** in explorer/GUI: "validator X activates at
      height H (~N blocks)", so operators see quorum-criticality coming.
- [ ] **P2-7 (NEW-11) — State snapshot export/import** so a reset/new node is ready in
      seconds instead of replaying thousands of blocks. Helps resets *and* onboarding.
- [ ] **P2-8 (NEW-12) — Halt-recovery runbook + tooling** for a stuck small set.
- [ ] **P2-9 (NEW-13) — Docker-compose multi-node testnet** that exercises validator
      joins across epoch boundaries, CI-runnable. Would have caught the current bug.
- [ ] **P2-10 — Run ≥4 validators** (ops, not code): quorum 4/5 tolerates one fault and
      restores self-healing. The 500k genesis reserve (`VALIDATOR_GENESIS_LIQUID_HLX`)
      already exists to fund three more — use it.

## DONE (this branch: `hardening/validator-liveness-tooling`)

- [x] **Seed `active_validators` with the genesis validators at genesis**
      (`GenesisConfig::build_state`) so `engine_validator_set()` no longer falls back to
      the undelayed `stakers()` set during the first activation epoch. Regression tests
      added in `genesis.rs` (incl. one that is red on the pre-fix code). **Genesis-hash
      changing — safe only for a fresh launch/reset; every node must upgrade + reset.**
