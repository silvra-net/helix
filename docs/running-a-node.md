# Running & operating a node

> Part of the [Helix documentation](../README.md) — deep reference, split out of the README to keep it short.

## Running a Node

```bash
./target/release/helix start
```

On first start, the node:
- Loads or generates a persistent ML-DSA keypair (`validator-key.json`)
- **Joins the public Helix network by default** — fetches the real genesis from the built-in
  seed (`https://node.silvra.net`), downloads and verifies the chain history, then follows
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
| `HELIX_SYNC_PEER` | `https://node.silvra.net` | `http://host:8545` of a trusted peer — fetches this chain's genesis from it (if you have no local chain yet) and any missing historical blocks, and is the target of the periodic RPC catch-up that keeps a follower current when the peer's raw P2P port isn't reachable. Defaults to the public network's seed; override to point at a different network, or set `HELIX_NEW_CHAIN=1` to disable seeding entirely. Overrides `sync_peer` in `helix.toml`. |
| `HELIX_NEW_CHAIN` | (off) | Set truthy (`1`/`true`) to run a **standalone chain** — the node self-signs its own genesis instead of joining the public network via the default seed. Set this for a private devnet, or for the origin node of a brand-new network. Ignored if a sync peer is explicitly configured. Overrides `new_chain` in `helix.toml`. |
| `HELIX_GENESIS_HASH` | the public chain's genesis, compiled in | Hex hash of the genesis block you expect to join, checked against whatever the sync peer serves **before** anything is written — a mismatch aborts startup instead of adopting the wrong chain. **Joining the public seed is already checked without setting anything**, against a hash built into the binary. Set this to join a different network, or to get past a build whose compiled-in hash predates a chain reset (see "Verifying which chain you joined"). Ignored with `HELIX_NEW_CHAIN`, and not applied when the genesis arrives over P2P from seed peers rather than from a named sync peer. Overrides `genesis_hash` in `helix.toml`. |
| `HELIX_CHAIN_ID` | the chain the endpoint you named is on; the public chain's genesis otherwise | Genesis hash of the chain that **wallet commands** sign transactions for (`Transaction.chain_id`). Rarely needed: pointed at the public endpoint the wallet uses its compiled-in value, and pointed at a node you named it asks that node. Set it to sign offline, or for a devnet whose genesis this build predates. A wrong value produces transactions the chain refuses by name, never silently. |
| `HELIX_VALIDATOR_KEY` | `validator-key.json` | Path to the validator key file (unified `KeyFile` JSON, same format as `helix wallet`). Overrides `validator_key_path` in `helix.toml`. |
| `HELIX_VALIDATOR_CRYPTO_SCHEME` | `ml-dsa` | Signature scheme for a newly generated validator key (`ml-dsa` or `sphincs-plus`). Only applies the first time a key is generated — ignored once `validator-key.json` exists. Overrides `validator_crypto_scheme` in `helix.toml`. |
| `HELIX_VALIDATOR_KEY_PASSPHRASE` | (none) | Passphrase to decrypt `validator-key.json` if it was encrypted (e.g. via `helix wallet encrypt`). Not needed for the default plaintext key file. |
| `HELIX_RPC_RATE_LIMIT` | `30,10` | Request budget per client IP as `burst,refill_per_sec`. The default is right for a public endpoint and is also **the binding limit on submission throughput** — 10 transactions per second per client, well under what the chain can include (~180/s at a 2 MB block every 2 s). Raise it on a private node you are the only user of. Malformed values are ignored with a warning; the node still starts on the default. |
| `HELIX_MEMPOOL_TX_TTL_SECS` | `1800` (30 min) | How long an unconfirmed transaction may sit in the mempool before it's evicted, freeing its (sender, nonce) slot. Overrides `mempool_tx_ttl_secs` in `helix.toml`. |
| `HELIX_DB_CACHE_MB` | `128` | Page cache the embedded database may hold, in MiB. Sized so a node fits comfortably on a 1 GB machine: a full sync of the live chain peaks around 280 MB of RSS in total and stays there. Raise it (e.g. `512`) on a server with memory to spare and RPC read traffic to serve; there is no reason to lower it. |
| `HELIX_P2P_PUBLIC_ADDR` | (none) | This node's own externally-dialable address, announced to peers via peer exchange (see "Network Resilience" below). Either a bare host (a domain or public IP, no scheme/port — the configured raw-TCP P2P port is appended automatically), or, for a node behind a proxy/tunnel, a full multiaddr starting with `/` (e.g. `/dns4/host/tcp/443/tls/ws`). Overrides `p2p_public_addr` in `helix.toml`. Leave unset for followers with no public/forwarded port — they still relay addresses they learn from others. |
| `HELIX_P2P_SEED_PEERS` | (none) | Comma-separated libp2p multiaddrs (e.g. `/ip4/1.2.3.4/tcp/8546,/dns4/peer.example/tcp/8546`) to dial directly, in addition to the one derived from `sync_peer`. With no local chain and no `sync_peer`, these are also where the genesis block is fetched from — see "Joining without an HTTP endpoint". Use this to wire a validator set into a full mesh — every validator should peer with every other, not hub-and-spoke through one node. Overrides `p2p_seed_peers` in `helix.toml`. |
| `HELIX_BLOCK_TIME_MS` | `2000` | Target interval between blocks, in milliseconds. **Consensus-relevant: every validator on a network must use the same value**, or nodes disagree about when a round has timed out. Intended for private devnets, where a shorter interval makes tests finish sooner; do not change it on a running network. |
| `HELIX_PERSONHOOD_AUTHORITIES` | (none) | Comma-separated hex public keys allowed to issue Proof-of-Personhood attestations. Only takes effect at genesis — an existing chain's authorities were fixed when it was created. Unset means personhood attestations are disabled on this chain. |
| `HELIX_NODE` | (auto) | Which node the **client** subcommands (`helix wallet`, `helix tx`, `helix chain`) talk to. Unset, they use a node running on this machine if one answers and the public network otherwise. Ignored by `helix start`, which configures itself from the variables above. |
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

### Remembered peers

Alongside the database, the node keeps `helix-peers.txt` — the addresses of peers it has met,
one multiaddr per line. It is written automatically every 30 seconds and read at startup, and
its only job is to save the node from starting over.

Without it, every restart put a node back on its first start: it came back knowing only the
seed you configured, no matter how much of the network it had been talking to. That makes the
whole network's ability to admit anyone depend on one machine staying reachable. This is the
same reason Bitcoin Core keeps `peers.dat` next to its DNS seeds — the seeds bootstrap the
first start, the file carries every one after it.

- **Safe to delete.** The node re-learns the network from its seeds; you only cost it a head
  start.
- **Safe to edit.** Adding an address by hand is how you point a node at a peer you know
  about. Lines that are not valid multiaddrs are ignored, so a typo costs nothing.
- **Not a substitute for your seed configuration.** Remembered peers are dialed *in addition
  to* your configured seeds, never instead of them — so an address that has gone stale, or one
  a hostile peer talked your node into remembering, can never cut it off from the network.
- Kept deliberately *outside* the chain database, so wiping chain data does not also erase how
  to find the chain again.

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

### Joining without an HTTP endpoint

`sync_peer` is an HTTP address, which means joining used to require somebody on the network to run
a reachable web server. It no longer does: a node with no local chain and no `sync_peer` will fetch
the genesis over P2P from whatever `p2p_seed_peers` it was given.

```toml
# helix.toml
p2p_seed_peers = "/dns4/peer.example/tcp/443/tls/ws"
genesis_hash   = "7bc4…"
```

Every node serves its own genesis, so this does not depend on any one machine staying up. Set
`genesis_hash` when you use it — see the next section for why it matters more here than over RPC.

If both are configured, `sync_peer` wins. Naming an RPC peer is an explicit choice about where your
chain comes from, and quietly preferring a different source would answer a question you already
answered.

### Verifying which chain you joined

A node with no local chain yet takes its genesis block from a peer. It has no state, no validator
set and no chain id at that point, so it cannot judge what it is handed: whoever answers decides
which chain this node spends its life on. Over P2P that is sharper still — the answer comes from
whichever peer replied first, not from an address you named. Joining the wrong one is not a loud failure —
every later block applies perfectly on top of the wrong ledger, and every balance the node reports
is quietly wrong.

**Joining the public network is already pinned.** The hash of its genesis is compiled into the
binary and checked automatically — Bitcoin's model, where the genesis is in the source and nobody
configures anything. You do not need to set it, and a mismatch will stop the node before it writes.

Two things follow from the hash living in the binary. Joining *another* network — anything you
reach through your own `HELIX_SYNC_PEER` — is not covered by it, because this build knows nothing
about that chain; pin it yourself. And a **chain reset publishes a new genesis**, which a binary
released before the reset cannot know: it will refuse to join and say so, naming its own version.
The repair is to upgrade to the release that followed the reset, or to set the hash by hand:

```toml
# helix.toml
genesis_hash = "7bc4…"   # the network's published genesis hash
```

or `HELIX_GENESIS_HASH=7bc4… helix start`. The node compares it against the block the peer serves
**before** writing anything, and refuses to start on a mismatch, naming both hashes. The current
value is printed by any node on this chain:

```bash
curl -s https://node.silvra.net/blocks/height/0 | jq -r .hash
```

Take it from a source you trust — release notes or a node you already run — not from the peer you
are about to sync from, which would be circular. A hash costs nothing to publish and needs no
infrastructure to stay reachable, which is exactly what makes it a better anchor than the endpoint.

Leaving it unset falls back to the compiled-in hash when you are joining the public seed, and to
trusting the peer otherwise — the node logs a warning in the second case, so the choice is visible.
**A chain reset produces a new genesis hash**: if the node refuses to start after one, take the
newly published value rather than removing the setting. Removing it does not help anyway when the
public seed is involved, since the compiled-in hash then applies instead.

**Staying current.** A joined node stays up to date two ways: live P2P gossip (the primary
path), plus a periodic RPC catch-up that polls the sync peer for any new blocks every few
seconds. The RPC fallback matters because a node's raw P2P port isn't always publicly
reachable — the public seed, for instance, is served through an HTTPS tunnel that only
exposes its RPC — so gossip alone would leave a fresh follower stuck at the height it synced
at startup. The periodic RPC pull closes that gap over the one channel that's always
reachable. (The node also asks the seed via `GET /status` for its P2P address and dials it
directly for lower-latency gossip on top — preferring the seed's announced public multiaddr,
including a `/tls/ws` WebSocket address behind a proxy, over a raw-TCP guess it can't reach.)

### The chain has stopped — what to do

**Do not delete your chain data.** It is almost never the problem, and it is the one action that
makes things worse: a node starting from an empty database has to sync the whole chain from
scratch, and until it does it cannot vote — so a validator that wipes its data removes itself from
the quorum for as long as the sync takes, on top of whatever stopped the chain in the first place.
This has happened, and it turned a recoverable outage into a 21-hour one.

Read the node's own health line first — it distinguishes the two cases:

- **"the chain is waiting for other validators to reconnect"** — your node is fine. Nothing you do
  locally will help; the chain resumes when enough validators are back. Restarting is harmless but
  pointless, and it restarts the internal wait timers.
- **"votes from at least one other validator are not arriving here"** — your node is healthy and
  connected, but somebody else's is not voting. Restarting yours will not help; the "Validator
  silent" lines just above name whose votes are missing. If you run one of those validators, that
  is the node to look at.
- **"restarting the node re-establishes its round"** — this node is the stuck one. Restart it
  (`pm2 restart <name>`, `systemctl restart …`, or however you run it). Your chain data and
  validator key stay where they are; that is exactly what makes the restart safe.

A stalled chain is normal when the validator set is small: consensus needs more than two-thirds of
voting power, so with three validators all three must be online. The chain does not lose anything
while it waits — it resumes from the same height once quorum is back.

If your node needs to catch up afterwards, it does so on its own (over P2P from any peer, or over
the RPC sync peer). Nothing needs to be reset for that.

### When your node keeps stopping

A node that vanishes leaves a log that simply ends, and afterwards a clean `systemctl stop`, a
crash, an out-of-memory kill and a `kill -9` look identical. So the node records how each run
ended, in `helix-last-run.json` beside the chain database, and reports it on the next start:

```
Previous run (v0.10.2) did NOT shut down cleanly. It ran 9 min, last seen at height 36119
(epoch 1786023222), using 1.8 GB of memory. Something ended it without warning — a crash, an
OOM kill, `kill -9`, or the machine going down. Check the system log around that time
(`journalctl -k --since` or `dmesg -T`) before assuming the node is at fault.
```

An orderly stop says so instead, quietly. If you see the warning above:

1. **Check memory first.** An OOM kill leaves nothing in the node's own log — the kernel decides
   and the process never runs again. If the reported memory is a large share of the machine's, that
   is your answer: `journalctl -k --since=@<last_seen_unix> | grep -i oom`.
2. **Then the machine.** A reboot, a hypervisor migration or a full disk all look the same from
   inside the process.
3. **Then the node.** A panic is the least likely of these and would normally leave a message.

The same information is available over HTTP at `GET /diagnostics`, so you can check a node without
reading its log:

```bash
curl -s localhost:8545/diagnostics | jq
```

**That output is safe to share.** It contains no addresses, no file paths, no keys and no peer
identifiers — enumerated on purpose, so you can paste it when asking for help without having to
audit it first. If you are reporting a problem, this is the single most useful thing to send.

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

**In most cases you do not need to configure an address at all — just open the port.** On
startup, and every ten minutes after, a node asks its sync peer `GET /whoami?p2p_port=<its port>`:
*what address did my request come from, and can you reach me back there?* The peer answers with
the address it saw and the result of actually connecting to that port from its side. Only if that
connection succeeded does the node start announcing the address on peer exchange. The log says
which happened:

```
INFO  This node is reachable from the outside and is now announcing that address to the network.
WARN  This node is NOT reachable from the outside, so other nodes can only find it through
      whichever peer it dialed. Open the P2P port to fix it.
```

A node cannot answer either half for itself. The address is only visible from outside, and the
port cannot be tested locally either — connecting to your own port proves the process is
listening, which was never in doubt, and says nothing about whether a firewall lets anyone else
through. Someone has to try the door from outside.

The address is rebuilt locally from the reported IP and the node's *own* port, and the peer's
report of what it probed must match exactly — so a peer cannot answer "I probed 198.51.100.9 and
it worked" and have your node announce a stranger's address. The residual trust is bounded: a
lying sync peer could still name a wrong IP, and the cost of that is other nodes dialing an
address whose handshake fails. If you would rather not extend even that much, set
`HELIX_P2P_PUBLIC_ADDR` and discovery is skipped entirely.

**Set `p2p_public_addr` (or `HELIX_P2P_PUBLIC_ADDR`) explicitly when discovery cannot work**, and
it then wins outright — automatic discovery is skipped entirely. Two cases need it:

- **Behind a reverse proxy or tunnel.** The reachable address is a WebSocket multiaddr on a port
  the node does not listen on (`/dns4/host/tcp/443/tls/ws`); no probe can derive that, and the
  probe will correctly report "not reachable".
- **A node with no sync peer** — the origin of its own chain has nobody to ask.

A node behind NAT with no forwarded port needs neither: it participates fully, dialing addresses
it learns and relaying them onward. It just never advertises one nobody could reach — and now it
*says so* once every ten minutes, instead of leaving the operator to guess.

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

Every validator joins the same way — there is no genesis shortcut that pre-stakes extra
validators. A network starts with exactly one bootstrap validator; every other validator is
added at runtime by funding its address and having it stake, whether the network launched
yesterday or years ago. Concretely, to add Bob and Carol to your network:

1. Each generates a validator key and starts a node that syncs your chain (`sync_peer` set to a
   node already on it), meshed with the others (see below). The node need not stake to sync — it
   can catch up and stay current first.
2. Fund each validator's address with at least `MIN_VALIDATOR_STAKE` plus a fee margin — by
   transfer from an already-funded account (`helix tx send`), or by letting block rewards
   accumulate.
3. **On the node whose key holds that stake**, send `helix tx stake 100000`. Verify the staking
   address matches the node's own key first (`helix wallet address --key validator-key.json`) —
   staking from one wallet while the node signs as a *different* self-generated key produces a
   "phantom" validator that is in the set but never signs, which freezes a small set.
4. The new staker is picked up at the next epoch boundary and becomes a full voting validator one
   epoch after that. The epoch in between is a *probation* epoch: the validator is already in the
   signing set, so it syncs and participates, but carries zero voting power and gets no proposer
   turn, so nothing the chain needs depends on it yet.

   > **Promotion is earned, not waited out.** During the probation epoch the node automatically
   > sends a small, fee-free heartbeat transaction signed with its validator key, and the
   > validator joins the voting set only if one of those (or a co-signed block) actually reached
   > the chain. A key with no node behind it sends neither, so it is never promoted: it stays in
   > the signing set at zero voting power, returns to the queue, and tries again whenever a node
   > does show up. It is not slashed and not evicted, and the chain never comes to depend on it.
   >
   > Step 3's address check still matters — it is the difference between activating and waiting
   > forever. If your node signs as a different key than the one you staked from, the staked
   > address will never be promoted, and the only symptom is that nothing happens. Check
   > `GET /validators`: a `probationary` entry whose `probation_liveness_seen` stays `false`
   > across a whole epoch is that mistake, not a slow network.

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
2. **Fund that address** with at least `MIN_VALIDATOR_STAKE` (100,000 HLX) by transfer or
   accumulated block rewards. Fund it now, but **do not send the `Stake` transaction yet** — that
   is the last step, once the node is provably connected. Budget somewhat above the minimum: a
   slash takes 5% of your stake, and landing below `MIN_VALIDATOR_STAKE` drops you out of the set
   entirely.
3. **Expose a P2P path in.** Behind a proxy/tunnel, forward an HTTPS hostname (e.g.
   `p2p.yourdomain.net`) to your local WebSocket port and set:
   ```bash
   HELIX_P2P_WS_LISTEN="127.0.0.1:8547"                        # tunnel 443 -> here
   HELIX_P2P_PUBLIC_ADDR="/dns4/p2p.yourdomain.net/tcp/443/tls/ws"
   ```
   (On a machine with a real public IP and an open port, skip the tunnel and just set
   `HELIX_P2P_PUBLIC_ADDR="yourdomain.net"` — the raw TCP P2P port is appended automatically.)
4. **Announce yourself.** On a machine with a real public IP this is automatic — open the P2P
   port and the node discovers and announces its own address (see "Network Resilience" above);
   watch for `This node is reachable from the outside` in the log. Behind a proxy or tunnel it
   is step 3's `HELIX_P2P_PUBLIC_ADDR` that does it. Either way, this is what makes you
   *reachable* by other validators rather than only able to dial out — the answer to "can
   everyone connect to everyone?": yes, between the nodes that each have a reachable address.
5. **Mesh with the other validators** so consensus votes never depend on a single hub. Set
   each of the other validators as seeds (in addition to the one `sync_peer` that bootstraps
   your history):
   ```bash
   HELIX_SYNC_PEER="https://node.silvra.net"                 # history + auto WS discovery
   HELIX_P2P_SEED_PEERS="/dns4/p2p.bob.net/tcp/443/tls/ws,/dns4/p2p.carol.net/tcp/443/tls/ws"
   ```
6. **Start and verify:** `helix start`, then confirm `peer_count` climbs above zero and your
   node is following the chain. `helix chain status` shows height advancing.
7. **Only now, stake — and stake *this node's* address, nothing else:**
   ```bash
   helix wallet address --key validator-key.json     # the address your node signs with
   helix tx stake <amount> --key validator-key.json   # stake that same key
   ```
   The address you stake **must** be the one your node validates as (step 1's key). Staking a
   *different* wallet you happen to have funded does not make this node a validator — it makes
   that other address a validator the network waits on while nothing signs for it, a "phantom"
   that halts a small set until the chain can move again (which it can't, because it's blocked on
   the phantom). If `helix wallet address` and the address you funded/staked don't match, fix
   that before staking, not after — a stalled chain can't accept the corrective transaction.

   Two ordering mistakes to avoid, both for the same reason (the address becomes a validator on
   schedule whether or not a matching node is listening):
   - **Wrong key** — the phantom case above.
   - **Right key, but staked before the node was connected** — a validator that never answers is
     jailed for downtime (~5 minutes of missed blocks) and has to `tx unjail` to get back. That's
     why staking is the *last* step, after step 6 shows the node meshed and following.

   You join the active set one full epoch (~100 blocks / ~3.3 minutes) after the rotation that
   first sees your stake; that wait is deliberate and is not counted against you.

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
  there so `validator-key.json`, `helix-data.redb` and `helix-peers.txt` survive container
  recreation/upgrades.
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
