# Running & operating a node

> Part of the [Helix documentation](../README.md) — deep reference, split out of the README to keep it short.

## Running a Node

```bash
./target/release/helix start
```

On first start, the node:
- Loads or generates a persistent ML-DSA keypair (`validator-key.json`)
- **Joins the public Helix network by default** — fetches the real genesis from the built-in
  seed (`https://helix.silvra.net`), downloads and verifies the chain history, then follows
  the live chain. No peer to configure. (Override the seed with `HELIX_SYNC_PEER`, or set
  `HELIX_NEW_CHAIN=1` to start a standalone chain instead — see "Joining the network" below.)
- Follows/produces blocks every 2 seconds
- Exposes REST API on `http://127.0.0.1:8545`
- Listens for P2P peers on `0.0.0.0:8546`

Everything the CLI and REST API do is just talking to this process — there's no separate
indexer or backend.

### Config File

Instead of setting env vars individually, the node reads an optional `helix.toml`
in the working directory (a different path can be set via `HELIX_CONFIG`). Every
field is optional; the matching env var (if set) always overrides the file, so
existing env-var-only setups keep working unchanged:

```toml
# helix.toml
rpc_bind = "0.0.0.0:8545"
p2p_listen_addr = "0.0.0.0:8546"
reward_address = "hlx..."
# By default the node joins the public network via the built-in seed. Override the seed:
sync_peer = "http://seed-host:8545"
# ...or run a standalone chain instead (private devnet / a brand-new network's origin node):
# new_chain = true
validator_crypto_scheme = "ml-dsa"
mempool_tx_ttl_secs = 1800
p2p_public_addr = "helix.example.com"
genesis_extra_validators = "hlx1abc...:100000,hlx1def...:100000"
```

An absent file is not an error (all fields default to unset); a present but
malformed file (bad TOML, or an unknown field) fails node startup.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `HELIX_CONFIG` | `./helix.toml` | Path to the config file described above. |
| `HELIX_REWARD_ADDRESS` | (validator address) | Address that receives the 50% validator fee reward. Set this to your app wallet address so fees land there instead of the signing key. Overrides `reward_address` in `helix.toml`. |
| `HELIX_RPC_BIND` | `127.0.0.1:8545` | REST API bind address. Set to `0.0.0.0:8545` when the node isn't reached through a local reverse proxy/tunnel (e.g. running in a container). Overrides `rpc_bind` in `helix.toml`. |
| `HELIX_P2P_LISTEN` | `0.0.0.0:8546` | P2P listen address (raw TCP). Overrides `p2p_listen_addr` in `helix.toml`. |
| `HELIX_P2P_WS_LISTEN` | (none) | Extra P2P listen address that carries libp2p inside a **WebSocket** (e.g. `127.0.0.1:8547`), on top of the raw TCP above. Set this when the node's only route in from outside is an HTTPS reverse proxy or a Cloudflare tunnel, which forward WebSockets but not raw TCP — see "Validating from behind a reverse proxy / Cloudflare tunnel" below. Overrides `p2p_ws_listen_addr` in `helix.toml`. |
| `HELIX_SYNC_PEER` | `https://helix.silvra.net` | `http://host:8545` of a trusted peer — fetches this chain's genesis from it (if you have no local chain yet) and any missing historical blocks, and is the target of the periodic RPC catch-up that keeps a follower current when the peer's raw P2P port isn't reachable. Defaults to the public network's seed; override to point at a different network, or set `HELIX_NEW_CHAIN=1` to disable seeding entirely. Overrides `sync_peer` in `helix.toml`. |
| `HELIX_NEW_CHAIN` | (off) | Set truthy (`1`/`true`) to run a **standalone chain** — the node self-signs its own genesis instead of joining the public network via the default seed. Set this for a private devnet, or for the origin node of a brand-new network. Ignored if a sync peer is explicitly configured. Overrides `new_chain` in `helix.toml`. |
| `HELIX_VALIDATOR_KEY` | `validator-key.json` | Path to the validator key file (unified `KeyFile` JSON, same format as `helix wallet`). Overrides `validator_key_path` in `helix.toml`. |
| `HELIX_VALIDATOR_CRYPTO_SCHEME` | `ml-dsa` | Signature scheme for a newly generated validator key (`ml-dsa` or `sphincs-plus`). Only applies the first time a key is generated — ignored once `validator-key.json` exists. Overrides `validator_crypto_scheme` in `helix.toml`. |
| `HELIX_VALIDATOR_KEY_PASSPHRASE` | (none) | Passphrase to decrypt `validator-key.json` if it was encrypted (e.g. via `helix wallet encrypt`). Not needed for the default plaintext key file. |
| `HELIX_MEMPOOL_TX_TTL_SECS` | `1800` (30 min) | How long an unconfirmed transaction may sit in the mempool before it's evicted, freeing its (sender, nonce) slot. Overrides `mempool_tx_ttl_secs` in `helix.toml`. |
| `HELIX_FAUCET_KEY` | (off) | Path to a key file for a **testnet faucet** on this node, exposing `POST /faucet` (`{"address":"hlx…"}`) and a form in the explorer. Unset means no faucet, which is the default for every node. Fund a **separate** account for this — never the validator key; the node refuses to start a faucet whose address is its own validator address, because that key signs blocks and this endpoint signs on request from the open internet. A request tops the recipient up *to* `HELIX_FAUCET_TOPUP_HLX`, so an address that already holds that gets nothing, and the faucet can never pay out more than the account was funded with. |
| `HELIX_FAUCET_TOPUP_HLX` | `10` | Balance the faucet tops an address up to. At the fee floor a transfer costs about 0.00001 HLX, so 10 HLX is on the order of a million transactions. |
| `HELIX_FAUCET_KEY_PASSPHRASE` | (none) | Passphrase for `HELIX_FAUCET_KEY` if that file was encrypted. |
| `HELIX_DB_CACHE_MB` | `128` | Page cache the embedded database may hold, in MiB. Sized so a node fits comfortably on a 1 GB machine: a full sync of the live chain peaks around 280 MB of RSS in total and stays there. Raise it (e.g. `512`) on a server with memory to spare and RPC read traffic to serve; there is no reason to lower it. |
| `HELIX_P2P_PUBLIC_ADDR` | (none) | This node's own externally-dialable address, announced to peers via peer exchange (see "Network Resilience" below). Either a bare host (a domain or public IP, no scheme/port — the configured raw-TCP P2P port is appended automatically), or, for a node behind a proxy/tunnel, a full multiaddr starting with `/` (e.g. `/dns4/host/tcp/443/tls/ws`). Overrides `p2p_public_addr` in `helix.toml`. Leave unset for followers with no public/forwarded port — they still relay addresses they learn from others. |
| `HELIX_GENESIS_EXTRA_VALIDATORS` | (none) | Comma-separated `address:stake_hlx` pairs — additional validators to pre-stake directly at genesis, beyond the one bootstrap validator every chain has always had. Only takes effect for a fresh chain (same caveat as `HELIX_PERSONHOOD_AUTHORITIES`). See "Bootstrapping a Multi-Validator Network" below. Overrides `genesis_extra_validators` in `helix.toml`. |
| `HELIX_P2P_SEED_PEERS` | (none) | Comma-separated libp2p multiaddrs (e.g. `/ip4/1.2.3.4/tcp/8546,/dns4/peer.example/tcp/8546`) to dial directly, in addition to the one derived from `sync_peer`. Use this to wire a validator set into a full mesh — every validator should peer with every other, not hub-and-spoke through one node. Overrides `p2p_seed_peers` in `helix.toml`. |
| `HELIX_P2P_DISABLE_MDNS` | (off) | Set truthy (`1`/`true`) to turn off mDNS LAN auto-discovery, leaving only seed peers + peer exchange. Needed only when two independent Helix networks share a LAN (mDNS would otherwise cross-wire them). Overrides `p2p_disable_mdns` in `helix.toml`. |

```bash
HELIX_REWARD_ADDRESS=hlx... ./target/release/helix start
```

### Persistent Validator Key

The node stores its validator keypair in `validator-key.json` (in the working directory,
or wherever `HELIX_VALIDATOR_KEY` / `validator_key_path` points):
- **Same format as a CLI wallet.** It's the unified `KeyFile` JSON that `helix wallet`
  produces — a validator key *is* a wallet. Use it directly as `--key validator-key.json`
  with any `helix` client command (see the Quick Start's funding step); there is no conversion step.
- Fields: `address`, `public_key`, `algo`, `encryption` (`plaintext` or
  `aes256gcm-argon2id`), `secret_key`, plus `kdf_salt`/`nonce` when encrypted
- Generated once on first start (plaintext); reused on every subsequent restart, so the
  validator address stays the same
- **Back this file up** — losing it means losing your validator identity

### Persistent Chain Data

Blocks and chain state (balances, names, personhood, guardians) are stored in
`helix-data.redb` (in the working directory), a single-file [redb](https://github.com/cberner/redb)
database:
- Written on every finalized block — survives node restarts and crashes
- On startup, the node loads existing state from this file if present, or
  builds/fetches genesis on first run (see above)
- **Back this file up** alongside `validator-key.json` — losing it loses chain history

### Joining the network

**A node joins the public Helix network by default** — no configuration needed. On first
start (no local `helix-data.redb` yet) it fetches the built-in seed's real genesis block and
governance parameters, adopts them as its own, then downloads every historical block in
order, verifying each one's signature, validator legitimacy, and chain continuity before
applying it. If sync stops partway (e.g. the network is briefly unreachable), whatever was
already applied stays persisted — just restart to resume.

To join a *different* network instead, point `sync_peer` at one of its nodes:

```toml
# helix.toml
sync_peer = "http://seed-host:8545"
```

or `HELIX_SYNC_PEER=http://seed-host:8545 helix start`. To not join any network — a private
devnet or the origin node of a brand-new network — set `HELIX_NEW_CHAIN=1` (or `new_chain =
true`) and the node self-signs its own genesis instead.

**Staying current.** A joined node stays up to date two ways: live P2P gossip (the primary
path), plus a periodic RPC catch-up that polls the sync peer for any new blocks every few
seconds. The RPC fallback matters because a node's raw P2P port isn't always publicly
reachable — the public seed, for instance, is served through an HTTPS tunnel that only
exposes its RPC — so gossip alone would leave a fresh follower stuck at the height it synced
at startup. The periodic RPC pull closes that gap over the one channel that's always
reachable. (The node also asks the seed via `GET /status` for its P2P address and dials it
directly for lower-latency gossip on top — preferring the seed's announced public multiaddr,
including a `/tls/ws` WebSocket address behind a proxy, over a raw-TCP guess it can't reach.)

### Network Resilience (Peer Exchange)

Two independent discovery mechanisms feed a node's P2P connections: mDNS (LAN-only) and the
one explicit `sync_peer` dial described above. On their own, both leave every follower node
connected to exactly one other peer — the one in its own `sync_peer` setting. That's a
hub-and-spoke topology: if that one hub goes offline, every follower connected only to it is
cut off from the rest of the network, with no path to any other follower, even though those
other followers are still online and reachable.

Peer exchange closes this gap. Every node maintains a set of known-dialable peer addresses
(seeded from its own `p2p_public_addr`, if set, and its `sync_peer`'s resolved address), and
gossips that set to its connected peers — once right after each new connection, and every 30
seconds after that. A node that receives an address it didn't already know dials it directly.
The practical effect: once even a handful of nodes know each other's public addresses, the
network self-heals into a real mesh instead of depending on any single node staying up.

Only nodes with `p2p_public_addr` (or `HELIX_P2P_PUBLIC_ADDR`) set actually announce
themselves — set this on any node with a real, externally-reachable P2P port (a public IP,
or a domain pointing at one, with port `8546`/your configured P2P port open). A node behind
NAT with no forwarded port should leave it unset; it still participates fully, both dialing
addresses it learns and relaying them onward, it just never advertises an address of its own
that nobody could actually reach.

### Validating from behind a reverse proxy / Cloudflare tunnel

A node's raw P2P transport is TCP. That is a problem for the common home-server setup where the
only way in from the internet is an HTTPS reverse proxy or a Cloudflare tunnel: those forward
HTTP and WebSocket traffic on port 443, but not raw TCP on some other port. Such a node can
still fetch genesis and follow the chain over its RPC (which *is* proxied), but peers can never
dial its libp2p port — so it never receives gossip, and **gossip is what validating requires**:
BFT needs proposals and votes, and those only travel over P2P, never RPC. The result is a node
that can observe the chain but not take part in producing it.

`HELIX_P2P_WS_LISTEN` fixes this by additionally carrying libp2p inside a WebSocket, which a
proxy *does* forward. Point the proxy/tunnel at this WebSocket port, and peers dial the node at
`/dns4/<your-host>/tcp/443/tls/ws` — the proxy terminates TLS and forwards the plaintext
WebSocket to your listener behind it. This costs nothing in peer authenticity: libp2p's Noise
handshake runs *inside* the WebSocket, so the proxy carries the frames but cannot impersonate a
peer — the outer TLS is transport packaging, not the trust boundary.

```bash
# On the node behind the tunnel: listen on a local WebSocket port, and announce the
# publicly-dialable /tls/ws address so peers can reach you.
HELIX_P2P_WS_LISTEN="127.0.0.1:8547"          # tunnel forwards 443 -> here
HELIX_P2P_PUBLIC_ADDR="/dns4/your-host.example/tcp/443/tls/ws"
```

A node that announces a public address this way serves it in its `GET /status` response, so a
peer syncing from it **discovers the WebSocket address automatically** — just set `sync_peer` to
the node's RPC URL and the right `/tls/ws` P2P path is used with no separate seed config:

```bash
# On a peer connecting to it — no manual P2P seed needed:
HELIX_SYNC_PEER="https://your-host.example"   # RPC over the same proxy; P2P WS is auto-discovered
```

(You can still pin extra peers explicitly with `HELIX_P2P_SEED_PEERS` for a validator mesh — see
below — but you no longer need it just to reach a tunnelled seed.) Nodes reached over WebSocket
and nodes on plain TCP interoperate freely — every node can dial both `/ws`/`/tls/ws` and raw
`/tcp` multiaddrs regardless of how it is itself reachable. A node not behind a proxy needs none
of this and keeps using raw TCP as before.

### Bootstrapping a Multi-Validator Network

A chain with exactly one validator has a hard liveness ceiling no amount of peer exchange or
gossip resilience can fix: if that one validator's node goes down, block production stops
completely, full stop — every other node can still relay and store blocks, none of them can
propose or vote on new ones.

**How many validators you actually need.** BFT tolerates `f` simultaneous failures only at
`3f+1` validators: 4 to survive one, 7 to survive two. Three is not a middle ground — with three
of equal weight, any two together land exactly one voting unit below the `2/3 + 1` threshold, so
every block needs all three and the network tolerates *zero* failures, same as running one.

**They also have to be big enough to matter.** Voting power is capped at 1% of total stake per
validator (see [Consensus](internals.md#consensus)), and that cap is what equalizes validators of unequal
stake — but only once it actually binds them. Adding validators too small to reach the cap
leaves the largest one holding a quorum by itself, so killing it still halts the chain and the
small ones are decoration. As a rule of thumb, a new validator needs more than `total_stake/50`
staked for the cap to bind it (`total_stake/100` if it has verified personhood).

Growing organically means funding each new validator with `MIN_VALIDATOR_STAKE` (100,000 HLX)
via transfers, or waiting for the existing validator's block rewards to accumulate it — at 1
HLX/block and 2s blocks that is ~43,200 HLX/day, so roughly two days per validator. Real, but
slow if you want a fault-tolerant network standing up today.

`MIN_VALIDATOR_STAKE` is not fixed, though: it is a **governance parameter** (floor
`MIN_VALIDATOR_STAKE / 100` = 1,000 HLX). Lowering it by vote is often the cheaper path to more
validators than funding each one to 100,000 — a smaller stake still carries full voting weight as
long as it clears the 1% cap (`> total_stake/50`). See the governance flow in
[Using the CLI](cli.md#governance).

`HELIX_GENESIS_EXTRA_VALIDATORS` (or `genesis_extra_validators` in `helix.toml`) skips that
wait: it pre-stakes additional validators — by address, at whatever stake you choose — directly
into the genesis state, so they're active BFT participants (real proposer rotation, real
voting) from block 0, with no staking transactions or epoch rotation needed:

```toml
# helix.toml, on the node that will self-sign the fresh genesis
new_chain = true     # this is a brand-new standalone network, not the public one
genesis_extra_validators = "hlx1bob...:100000,hlx1carol...:100000"
```

Only the node building the *fresh* genesis needs this set — it takes effect once, at first
startup on an empty `helix-data.redb`, exactly like `HELIX_PERSONHOOD_AUTHORITIES`. Every node
that later joins via `sync_peer` automatically adopts the same pre-staked validators as part of
genesis adoption (`GET /genesis` carries the list along), so the whole fleet agrees on the same
validator set without needing this variable set anywhere else. Bob and Carol still need their
own node processes running with the matching `validator-key.json` (the key whose address you
staked) to actually participate — genesis only grants the stake, it doesn't run their nodes for
them.

**Wire the validators into a full mesh.** BFT relays prevotes and precommits between *all*
validators, so every validator should have a direct P2P connection to every other — not
hub-and-spoke through one seed node. A star topology drops relayed votes and collapses the
moment the hub goes down. Give each validator the others as `HELIX_P2P_SEED_PEERS` (in addition
to its one `sync_peer`), pointing at their P2P ports:

```bash
# on Alice's node (P2P :8546); Bob is bob.example:8546, Carol is carol.example:8546
HELIX_P2P_SEED_PEERS="/dns4/bob.example/tcp/8546,/dns4/carol.example/tcp/8546"
```

On first startup a fresh multi-validator network waits out a short one-time delay for the
gossip mesh to form before producing its first block — so give the fleet a few seconds after
the last validator comes online before expecting height to climb.

**A note on validator count and fault tolerance:** BFT quorum is `2/3 + 1` of total voting
power, and each validator's power is capped at 1% of total raw stake regardless of how much it
actually holds (a decentralization guarantee — see `ValidatorSet::new`). With exactly 3
validators of equal capped power, 2 of them together land *just* short of quorum — meaning
every single block needs all three to vote, so **3 validators tolerate zero of them being
offline**, no better than 1 in the specific sense of "how many can go down before the chain
halts" (though vastly better for censorship-resistance and peer-exchange-style relay
resilience). Real Byzantine fault tolerance for `f` simultaneously faulty/offline validators
needs `3f + 1` — 4 validators to tolerate 1 down, 7 for 2, and so on. Plan validator count
accordingly for how much simultaneous downtime the network actually needs to survive.

**Founding-validator checklist.** If you're standing up one of the first independent
validators, here is the whole path end to end — most operators run behind a home
server / firewall, so this assumes the WebSocket-tunnel setup:

1. **Generate a validator key** on the machine that will run the node, and never let the
   24-word phrase leave it: `helix wallet new -o validator-key.json`. Note the address.
2. **Fund that address** with at least `MIN_VALIDATOR_STAKE` (100,000 HLX) — either pre-staked
   into genesis via `genesis_extra_validators` (for a brand-new network's launch), or by
   transfer / accumulated block rewards (to join an existing one). Fund it now, but **do not
   send the `Stake` transaction yet** — that is the last step, once the node is provably
   connected. Budget somewhat above the minimum: a slash takes 5% of your stake, and landing
   below `MIN_VALIDATOR_STAKE` drops you out of the set entirely.
3. **Expose a P2P path in.** Behind a proxy/tunnel, forward an HTTPS hostname (e.g.
   `p2p.yourdomain.net`) to your local WebSocket port and set:
   ```bash
   HELIX_P2P_WS_LISTEN="127.0.0.1:8547"                        # tunnel 443 -> here
   HELIX_P2P_PUBLIC_ADDR="/dns4/p2p.yourdomain.net/tcp/443/tls/ws"
   ```
   (On a machine with a real public IP and an open port, skip the tunnel and just set
   `HELIX_P2P_PUBLIC_ADDR="yourdomain.net"` — the raw TCP P2P port is appended automatically.)
4. **Announce yourself** — step 3's `HELIX_P2P_PUBLIC_ADDR` is what makes you *reachable* by
   other validators via peer exchange. Without it you can only make outbound connections;
   with it you become a full mesh member. This is the answer to "can everyone connect to
   everyone?": yes — but only between the nodes that each publish a reachable address.
5. **Mesh with the other validators** so consensus votes never depend on a single hub. Set
   each of the other validators as seeds (in addition to the one `sync_peer` that bootstraps
   your history):
   ```bash
   HELIX_SYNC_PEER="https://helix.silvra.net"                 # history + auto WS discovery
   HELIX_P2P_SEED_PEERS="/dns4/p2p.bob.net/tcp/443/tls/ws,/dns4/p2p.carol.net/tcp/443/tls/ws"
   ```
6. **Start and verify:** `helix start`, then confirm `peer_count` climbs above zero and your
   node is following the chain. `helix chain status` shows height advancing.
7. **Only now, stake:** `helix tx stake <amount> --key validator-key.json`. Staking before the
   node is connected is the one ordering mistake worth avoiding — the address becomes a
   validator on schedule whether or not anything is listening, and a validator that never
   answers is jailed for downtime (~5 minutes of missed blocks) and has to `tx unjail` to get
   back. You join the active set one full epoch (~100 blocks / ~3.3 minutes) after the
   rotation that first sees your stake; that wait is deliberate and is not counted against you.

### Docker Deployment

A `Dockerfile` is provided for running a validator node without a local Rust toolchain.
It's a multi-stage build (Rust builder → `debian:bookworm-slim` runtime) that produces
a small image containing only the `helix` binary (node + client; the container runs `helix start`).

```bash
docker build -t helix-node .

docker run -d --name helix \
  -p 8545:8545 -p 8546:8546 \
  -v helix-data:/data \
  -e HELIX_RPC_BIND=0.0.0.0:8545 \
  helix-node
```

Notes:
- The container's working directory is `/data` — mount a named volume (or bind mount)
  there so `validator-key.json` and `helix-data.redb` survive container recreation/upgrades.
- `HELIX_RPC_BIND=0.0.0.0:8545` is required for the REST API to be reachable from outside
  the container — the compiled-in default only binds `127.0.0.1`.
- By default the container joins the public network (fetches genesis from the built-in seed).
  To join a *different* network, set `HELIX_SYNC_PEER=http://<seed-host>:8545`; to run a
  standalone chain, set `HELIX_NEW_CHAIN=1`. Either way, expose peer `8546/tcp` to the outside
  world (P2P is TCP-only, no UDP/QUIC in the current transport). If this container has a
  reachable public host/IP, also set `HELIX_P2P_PUBLIC_ADDR` so other nodes can find it
  through peer exchange (see "Network Resilience" above) even if the seed peer later goes
  offline.
- The image has not been pushed to a registry — build it locally or in your own CI.

---
