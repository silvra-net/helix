# Helix Wallet (desktop GUI)

A desktop wallet for the Helix blockchain — see your balance and transaction history, receive,
and send HLX without touching the shell. Backlog #83, stage 2+ (stage 1, the read-only block
explorer, is served by the node itself at `GET /`).

> **Status:** MVP scaffold — wallet create/restore/unlock, overview (balance/staked/history),
> receive, and locally-signed send. Staking, names, and governance are the next stages.

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
│   └── views/           Setup, Unlock, MnemonicReveal, Overview, Send, Receive
└── src-tauri/           Rust backend
    └── src/
        ├── wallet.rs    create / restore / unlock via KeyFile + bip39 (pure, unit-tested)
        ├── pricing.rs   hlx→nano + price-and-sign (mirrors helix-cli::fee)
        ├── rpc.rs       async REST client to the node
        ├── commands.rs  the Tauri command surface (the security boundary)
        └── state.rs     the in-memory unlocked wallet
```

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

To package: `npm run tauri build`. App icons ship in `src-tauri/icons/` (regenerate from a new
source with `npm run tauri icon app-icon.png`).

CI builds installers for Linux, macOS, and Windows on every push that touches `gui/`
(and on demand via *Actions → Build Helix Wallet → Run workflow*). Download them from the
run's **Artifacts**.

## Verification note

The security-critical core — key derivation, `KeyFile` round-trips, and transaction
signing — is covered by unit tests in `wallet.rs` and `pricing.rs` that run against the **real**
`helix-crypto`/`helix-core` crates (including the pinned Spark-compatibility vector). The full
Tauri build (webview/system deps) was not exercised in the authoring sandbox; run `npm run tauri
dev` on a machine with the Tauri prerequisites installed.

## Roadmap (stages of backlog #83)

- **SA1** ✅ read-only explorer — served by the node (`GET /`)
- **SA2/SA3** ✅ local wallet + balance/history + signed send
- **SA4** ✅ staking / delegation UI — stake, unstake, claim, delegate, redelegate, commission
- **Names** ✅ `.hlx` — register, resolve, send to a name, name shown on Overview
- social recovery, governance, and a node control panel are the remaining follow-ups
