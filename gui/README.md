# Helix Wallet (desktop GUI)

A desktop wallet for the Helix blockchain — see your balance and transaction history, receive,
send HLX, and run your own node or validator, all without touching a shell. Backlog #83, stage
2+ (stage 1, the read-only block explorer, is served by the node itself at `GET /`).

**CLI/GUI parity:** `helix-cli` and `helix-gui` are two front ends over the same node/wallet
core — neither is a subset of the other. The GUI bundles the real `helix` binary as a sidecar
(see [Node/validator panel](#node--validator-panel) below), so installing the wallet alone is a
complete validator setup — no separate CLI download needed, and vice versa.

> **Status:** wallet create/restore/unlock, overview (balance/staked/history), receive, and
> locally-signed transactions — transfers, staking/delegation, `.hlx` names, social recovery
> (guardians), governance, a node/validator panel with a live console, and persistent
> application logging for bug reports.

## Why Tauri (not a browser page)

The one hard problem a wallet GUI has is **where the private key lives**. Here it lives in the
Rust backend and **never crosses into the webview**:

- `src-tauri` links the real `helix-crypto` and `helix-core` crates and reuses the exact ML-DSA
  signing + canonical (bincode) transaction encoding the CLI and node use — no re-implementation
  of the crypto in JavaScript.
- The unlocked `KeyPair` sits in `WalletState` (a `Mutex`) in the backend. Every command hands
  the frontend addresses, amounts, and statuses — never key bytes.
- Wallets are stored in the OS app-data dir as the same `KeyFile` JSON the CLI writes
  (AES-256-GCM + Argon2id when a passphrase is set). The 24-word BIP39 phrase is shown once and
  never persisted — and it matches the Spark mobile app (pinned test vector).

## Layout

```
gui/
├── src/                 React + TypeScript frontend
│   ├── api.ts           typed wrappers over the Tauri commands
│   ├── App.tsx          shell: onboarding / unlock / main (overview, send, receive)
│   └── views/           Setup, Unlock, MnemonicReveal, Overview, Send, Receive, Node, Settings
└── src-tauri/           Rust backend
    └── src/
        ├── wallet.rs        create / restore / unlock via KeyFile + bip39 (pure, unit-tested)
        ├── pricing.rs       hlx→nano + price-and-sign (mirrors helix-cli::fee)
        ├── rpc.rs           async REST client to the node
        ├── commands.rs      the Tauri command surface (the security boundary)
        ├── node_process.rs  spawns/stops the bundled `helix` sidecar, streams its console
        └── state.rs         the in-memory unlocked wallet
```

## Node / validator panel

The **Node** tab runs `helix start` as a real child process (the bundled sidecar binary, built
from the same `helix-node` crate as the standalone CLI — not a reimplementation) and streams its
stdout/stderr as a live console, exactly like running the CLI in a terminal. This is what makes
the GUI a full validator setup on its own: start/stop the node, watch it sync and propose blocks,
and — if it ever gets jailed for downtime — unjail it, all from the same window as the wallet.

## Diagnostics / logging

Two independent logging layers, for two different questions:
- **Node tab console** — the bundled node's own stdout/stderr, live, for "what is my node doing
  right now."
- **Settings → Diagnostics** — a persistent, rotating log file (`tauri-plugin-log`) covering the
  wallet app itself: node spawn/stop/crash, wallet create/restore/unlock failures, and every
  transaction submission (never passphrase/mnemonic/private key), plus uncaught frontend errors.
  This is what to attach to a bug report — it survives after the console tab has scrolled past
  the moment something went wrong, and it's there even if nobody was watching the Node tab when
  it happened. Settings shows the log folder path with a copy button.

## Run it

Prerequisites: [Rust](https://rustup.rs), [Node 18+](https://nodejs.org), and the
[Tauri v2 system dependencies](https://v2.tauri.app/start/prerequisites/) for your OS
(on Linux: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `librsvg2-dev`, `build-essential`, …).

```bash
cd gui
npm install
npm run tauri dev      # launches the app against https://helix.silvra.net by default
```

The node URL is editable in the top bar (defaults to the public testnet; point it at
`http://127.0.0.1:8545` for your own node).

To package: `npm run tauri build`. This requires the sidecar binary to exist first at
`src-tauri/binaries/helix-<target-triple>[.exe]` (Tauri's `externalBin` convention) — build it
with `cargo build --release --bin helix` from the repo root and copy it into place; CI does this
automatically (see below).

App icons ship in `src-tauri/icons/` (regenerate from a new source with
`npm run tauri icon app-icon.png`).

CI builds full installers (with the sidecar bundled in) for Linux, macOS, and Windows on every
push that touches `gui/` (and on demand via *Actions → Build Helix Wallet → Run workflow*).
Download them from the run's **Artifacts** — this is a plain CI build, not a tagged release, so
it's the way to grab a build to test without waiting for the next `vX.Y.Z` release. Tagged
releases (`release.yml`) build the same installers plus the standalone CLI archive and publish
both as GitHub Release assets, named consistently: `helix-cli-<tag>-<platform>.*` and
`helix-gui-<tag>-<platform>.*`.

## Verification note

The security-critical core — key derivation, `KeyFile` round-trips, and transaction
signing — is covered by unit tests in `wallet.rs` and `pricing.rs` that run against the **real**
`helix-crypto`/`helix-core` crates (including the pinned Spark-compatibility vector). The Rust
backend (`cargo check`/`clippy`) and the frontend (`tsc --noEmit`, `npm run build`) both compile
clean, and CI builds the full installer for all three platforms — but no window system is
available in the authoring sandbox, so the actual running app (sidecar spawn, the Node tab
console, click-through UX) was never seen rendered. Run `npm run tauri dev` on a machine with the
Tauri prerequisites installed to check that by eye.

## Roadmap (stages of backlog #83)

- **SA1** ✅ read-only explorer — served by the node (`GET /`)
- **SA2/SA3** ✅ local wallet + balance/history + signed send
- **SA4** ✅ staking / delegation UI — stake, unstake, claim, delegate, redelegate, commission
- **Names** ✅ `.hlx` — register, resolve, send to a name, name shown on Overview
- **Recovery** ✅ social recovery — register guardians, approve/cancel a recovery, share your key
- **Governance** ✅ view parameters + proposals, vote, propose a change
- **Settings** ✅ re-reveal the recovery phrase (re-auth'd), view address / public key, view the
  diagnostic log folder
- **Node** ✅ run a bundled node/validator as a sidecar with a live console (start/stop, unjail),
  or connect to a remote one — status (height/peers/sync), validator standing vs the stake
  threshold with a stake-toward-validator assistant, live "blocks you proposed" signal
- smart-contract deploy/call is a developer feature left out of the wallet, and proof-of-personhood
  is deferred (verification is authority-gated and can't be a self-serve wallet flow)
