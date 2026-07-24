# Installing Helix

> Part of the [Helix documentation](../README.md) — deep reference, split out of the README to keep it short.

## Installation

### System Requirements

These are measured against the live `helix.silvra.net` deployment (a small validator set and
light but real testnet traffic — blocks are small, no longer empty), not synthetic benchmarks.
Treat them as a starting point, not a ceiling: they will need revisiting once the network carries
sustained transaction volume.

| Resource | Minimum | Recommended | Notes |
|---|---|---|---|
| **CPU** | 1 vCPU | 2+ vCPU | Block production/validation itself is cheap (ML-DSA-65 sign/verify, one block every 2s) — the prod node runs at ~0% CPU most of the time. Extra headroom matters if you also serve a busy RPC endpoint or process contract calls. STARK proof *generation* for Proof of Personhood happens client-side (`helix identity prove-personhood`), not on the node — it doesn't count against validator sizing. |
| **RAM** | 512 MB | 1 GB+ | Observed: ~19 MB right after startup, growing to the low hundreds of MB during normal operation as the redb page cache and gossipsub mesh state fill in. |
| **Disk** | 5 GB free to start | 20 GB+, monitored | `helix-data.redb` grows continuously — there is no pruning or archival mode yet (see [Security](../README.md#security)). Measured on prod: ~387 MB accumulated over ~15.6 hours of block production (roughly 25 MB/hour at the current light-traffic rate) — expect this to change substantially, in either direction, as traffic grows and/or pruning lands. **Never delete the file to reclaim space** — renaming it forces a fresh genesis, exactly like a chain reset. |
| **Network** | Outbound HTTPS (443) | — | A *following/validating* node needs only outbound access — RPC sync and the WebSocket P2P transport both ride over standard HTTPS/WSS, so no inbound port-forwarding or public IP is required, even behind NAT/CGNAT (see [Validating from behind a reverse proxy](running-a-node.md#validating-from-behind-a-reverse-proxy--cloudflare-tunnel)). Running your own public seed instead needs inbound `8545/tcp` (RPC) and, if you want raw-TCP P2P reachable directly, `8546/tcp`. |
| **OS / Arch** | Linux x86_64, macOS (Apple Silicon), Windows x86_64 | — | The platforms [CI](../.github/workflows/release.yml) builds and publishes releases for. Other platforms need building from source (`cargo build --release`) and are untested. |

Storage growth is the one number worth watching yourself rather than trusting a table: run
`du -h helix-data.redb` periodically, or check free space on the data directory (`df -h`)
alongside your node's own `GET /status`.

### Prerequisites

```bash
# Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# System dependencies (Ubuntu/Debian)
sudo apt-get install pkg-config libssl-dev
```

### Option A: Download a Release

Prebuilt binaries for Linux, macOS (Apple Silicon), and Windows are published on the
[Releases page](https://github.com/silvra-net/helix/releases) for every tagged version
(built automatically by [CI](../.github/workflows/release.yml) on every tag push). Download the
archive for your platform, extract it, and you have `helix` ready to run — no Rust
toolchain needed.

### Option B: Build From Source

```bash
git clone https://github.com/silvra-net/helix.git
cd helix
cargo build --release
```

A single binary is placed in `target/release/`:
- `helix` — the node (`helix start`) **and** the client (`helix wallet`, `helix tx`, …)

---
