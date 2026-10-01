# Running & operating a node

> Part of the [Helix documentation](../README.md).

## Running a Node

```bash
helix start      # or ./target/release/helix start
```

On first start the node:

- creates a validator key (`validator-key.json`) unless one exists;
- **joins the public network**: fetches the genesis from the built-in seed
  (`https://node.silvra.net`), checks it against the hash compiled into the binary, recomputes the
  genesis state instead of trusting the seed, then downloads and verifies every block and follows
  the live chain;
- serves its REST API on `http://127.0.0.1:8545` — and a status page about itself at that URL in a
  browser — and listens for peers on port `8546`.

Nothing needs configuring for that. The CLI and the desktop wallet on the same machine find the
node by themselves.

### Files a node keeps

All in its working directory:

| File | What it is | Back it up? |
|---|---|---|
| `validator-key.json` | The node's key — its validator identity. Same format as a CLI wallet: use it with `--key validator-key.json`. | **Yes.** Losing it loses the validator. Whoever reads it can sign as your validator (and get it slashed), so keep it `600` or encrypt it (`helix wallet encrypt`, then `HELIX_VALIDATOR_KEY_PASSPHRASE`). |
| `validator-key.signing-state.json` | What this key last signed. Keeps a restarted node from signing a second, conflicting vote for a height it already voted on — which is slashable. It belongs to one chain and starts over by itself on a new one. | **Keep it with the key**, and never run two nodes with the same key. |
| `helix-data.redb` | The chain database. | Not needed — the chain can always be fetched from the network again. **Never delete it**; rename it if you want it gone. |
| `helix-peers.txt` | Peers this node has met, so a restart does not start from the seed alone. | No. Safe to delete or edit by hand. |
| `helix-last-run.json` | How the previous run ended — see [When your node keeps stopping](#when-your-node-keeps-stopping). | No. |

### Running it as a service

For a node that should stay up, run it under a supervisor that restarts it, and set the three
things every long-running node wants:

```ini
# /etc/systemd/system/helix.service
[Unit]
Description=Helix node
After=network-online.target
Wants=network-online.target

[Service]
User=helix
WorkingDirectory=/var/lib/helix
ExecStart=/usr/local/bin/helix start
Environment=MALLOC_ARENA_MAX=2
Environment=HELIX_KEEP_BYTES=20G
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

- **`MALLOC_ARENA_MAX=2`** keeps memory flat. Without it glibc keeps memory freed by each thread
  for itself, and a node grew from 100 MB to 3 GB in four days without leaking anything.
- **A disk limit** (`HELIX_KEEP_BYTES` or `HELIX_KEEP_BLOCKS`) keeps the database from filling the
  disk — see [Disk usage](#disk-usage).
- **Port 8546 open inbound** if you can, so other validators reach you directly — see
  [Networking](#networking).

The node shuts down cleanly on `SIGTERM` and `SIGINT`. Stop it with your supervisor
(`systemctl stop helix`, `pm2 stop helix`), not with `kill -9`.

---

## Configuration

### Config file

Settings can go in `helix.toml` in the working directory (or wherever `HELIX_CONFIG` points)
instead of the environment. Every field is optional, and a matching environment variable always
wins:

```toml
# helix.toml
rpc_bind = "127.0.0.1:8545"
p2p_listen_addr = "0.0.0.0:8546"
sync_peer = "https://node.silvra.net"   # the default; point it at another network's node to join that
# new_chain = true                        # run a chain of your own instead
p2p_public_addr = "helix.example.com"
mempool_tx_ttl_secs = 1800
```

A missing file is fine; a malformed one — bad TOML or an unknown field — stops the node at start.

### Environment variables

**A value the node cannot read stops it at startup, with the reason,** for every setting whose
misreading could cost you: disk limits, checkpoints, seed peers, the public address. It used to
read typos as "unset", and a setting that silently does nothing is worse than a node that does
not start.

| Variable | Default | What it does |
|---|---|---|
| `HELIX_CONFIG` | `./helix.toml` | Path to the config file. |
| `HELIX_RPC_BIND` | `127.0.0.1:8545` | REST API address. Use `0.0.0.0:8545` only in a container or behind a proxy. |
| `HELIX_P2P_LISTEN` | `0.0.0.0:8546` | P2P address (TCP). |
| `HELIX_P2P_WS_LISTEN` | (none) | An extra P2P listener carrying libp2p inside a WebSocket, for a node reachable only through an HTTPS proxy or tunnel — see [Behind a proxy or tunnel](#behind-a-reverse-proxy-or-tunnel). |
| `HELIX_P2P_PUBLIC_ADDR` | (discovered) | The address this node announces to peers: a host (`helix.example.com`, the P2P port is appended) or a multiaddr (`/dns4/host/tcp/443/tls/ws`). Usually discovered by itself — set it behind a proxy or tunnel. |
| `HELIX_P2P_SEED_PEERS` | (none) | Comma-separated multiaddrs to dial in addition to the sync peer, e.g. `/ip4/203.0.113.7/tcp/8546,/dns4/peer.example/tcp/8546`. |
| `HELIX_P2P_DISABLE_MDNS` | off | `1` turns off discovery on the local network — needed only when two separate Helix networks share a LAN. |
| `HELIX_SYNC_PEER` | `https://node.silvra.net` | RPC endpoint of a node on the chain to join: the genesis and missing blocks come from it, and a follower polls it every 4 seconds for new blocks. |
| `HELIX_NEW_CHAIN` | off | `1` starts a chain of your own: the node signs its own genesis. For private chains and a new network's first node. |
| `HELIX_GENESIS_HASH` | the public chain's, compiled in | The genesis hash of the chain this node must be on — checked before anything is written, and at every start against the chain already stored. Set it to join another network, or when a binary's compiled-in hash predates a reset. |
| `HELIX_TRUSTED_CHECKPOINT` | (none) | `<height>:<block hash>:<state root>` — start a new node from a state snapshot instead of replaying the chain. See [Joining fast from a checkpoint](#joining-fast-from-a-checkpoint). |
| `HELIX_SNAPSHOT_INTERVAL` | `10000` | How often, in heights, this node stores a state snapshot that other nodes can start from. `0` turns that off. |
| `HELIX_KEEP_BLOCKS` | (keep all) | Keep only this many recent blocks (digits only, e.g. `100000`; at least 1000). |
| `HELIX_KEEP_BYTES` | (no limit) | Keep as many recent blocks as fit in this much disk: `20G`, `120GiB`, `4096M` (all binary units). |
| `HELIX_DB_CACHE_MB` | `128` | Database page cache in MiB. Raise it on a server that serves many reads. |
| `MALLOC_ARENA_MAX` | (unset) | Not a Helix variable — **set it to `2`**; see [Running it as a service](#running-it-as-a-service). |
| `HELIX_VALIDATOR_KEY` | `validator-key.json` | Path to the validator key. |
| `HELIX_VALIDATOR_KEY_PASSPHRASE` | (none) | Passphrase of an encrypted validator key. |
| `HELIX_VALIDATOR_CRYPTO_SCHEME` | `ml-dsa` | Scheme for a newly generated key: `ml-dsa` or `sphincs-plus`. Ignored once a key exists. |
| `HELIX_RPC_RATE_LIMIT` | `500,100` | Requests per client IP as `burst,refill_per_second`. Behind a Cloudflare tunnel the client IP comes from `CF-Connecting-IP`. |
| `HELIX_WALLET_RPC` | (off) | Serve a Bitcoin-Core-style wallet RPC from this node, on this address (`127.0.0.1:8547`) — for an exchange's own node, never a validator. Or, as with `bitcoind`, `server=1` in `helix.conf` in the wallet directory — one place, not both. A non-loopback address needs `rpcallowip` there. See [Integrating Helix](exchange-integration.md#bitcoin-style-wallet-rpc). |
| `HELIX_WALLET_DIR` | `helix-wallet` | The wallet's keys, issued-address log and ledger, and its `helix.conf` (Bitcoin's data directory). |
| `HELIX_WALLET_RPC_USER` | (none) | A user for the wallet RPC, with `HELIX_WALLET_RPC_PASSWORD_FILE` (the password only from a file). The cookie in the wallet directory works either way. |
| `HELIX_WALLET_RPC_PASSWORD_FILE` | (none) | See `HELIX_WALLET_RPC_USER`. |
| `HELIX_WALLET_PASSPHRASE_FILE` | (none) | Encrypts the wallet made on first start; unlock it with `walletpassphrase`. |
| `HELIX_MEMPOOL_TX_TTL_SECS` | `1800` | How long an unconfirmed transaction may wait in the pool. |
| `HELIX_MAX_PROPOSAL_BYTES` | `262144` | Transaction bytes this node packs into a block it proposes. Local policy — every node accepts blocks up to the protocol maximum of 2 MB. |
| `HELIX_BLOCK_TIME_MS` | `2000` | Block interval. **Every validator of a network must use the same value** — for private chains only. |
| `HELIX_PERSONHOOD_AUTHORITIES` | (none) | Comma-separated public keys (hex) that may attest personhood. Read only when the chain is created; none means personhood is off. |
| `HELIX_NODE` | (auto) | For **client** commands: which node to talk to. Unset, a node on this machine if one answers, the public network otherwise. |
| `HELIX_CHAIN_ID` | (auto) | For **client** commands: the chain to sign for. Needed only to sign offline, or for a private chain the build predates. |

**Rewards to another wallet are set on-chain,** not in the node:
`helix tx set-reward-address <address> --key validator-key.json` (see [Staking](staking.md#staking)).
`HELIX_REWARD_ADDRESS` is no longer read, and the node says so at start if it is still set.

---

## Joining the network

A node with no chain yet joins the public network by default. To join a **different** network,
point it at one of that network's nodes and pin its genesis:

```bash
HELIX_SYNC_PEER=https://node.other-network.example HELIX_GENESIS_HASH=<its genesis hash> helix start
```

To run a **chain of your own** — for development, or as the first node of a new network — set
`HELIX_NEW_CHAIN=1`. Its validator key starts with 10,000 HLX staked and 90,000 liquid.

### Verifying which chain you joined

A node with no chain yet cannot judge the genesis it is handed; whoever answers decides which
chain it spends its life on, and a wrong one fails silently — every block applies, every balance
is wrong. So the genesis is pinned:

- **The public network needs nothing.** Its genesis hash is compiled into each release and checked
  before anything is written.
- **Another network:** set `HELIX_GENESIS_HASH`, taken from its release notes or a node you trust —
  not from the peer you are about to sync from, which would be circular. Without it the node
  trusts the peer and warns.
- **After a reset** a release published before it cannot know the new genesis; it refuses to join
  and names its own version. Upgrade, or set the new hash by hand.

The current value is on any node: `curl -s https://node.silvra.net/blocks/height/0 | jq -r .hash`.

### After a chain reset

A reset starts a new chain; the release that comes with it says so. A node still holding the old
chain refuses to start, names both genesis hashes and the files to move aside:

```bash
mv helix-data.redb helix-data.redb.pre-reset.bak    # never delete it
mv helix-peers.txt helix-peers.txt.pre-reset.bak
```

Keep `validator-key.json` and `validator-key.signing-state.json` — the key carries over, and the
signing state starts over on the new chain by itself. In the desktop wallet: **Validate → Reset
local chain**. Balances and stakes of the old chain do not carry over.

### Joining fast from a checkpoint

Replaying every block from genesis takes a while. A new node can instead start from a state
snapshot, given a checkpoint:

```bash
curl -s https://node.silvra.net/sync/checkpoint        # <height>:<block hash>:<state root>
HELIX_TRUSTED_CHECKPOINT=<height>:<block hash>:<state root> helix start
```

**Ask more than one node and compare.** A checkpoint from the node you are about to sync from
proves nothing about that node — the state root has to come from outside, the same way the
genesis hash does. With it, the node fetches the snapshot, checks it against the state root and
the block against its hash, and continues from there; if anything does not match it says so and
replays from genesis instead. A checkpoint without the state root (`<height>:<block hash>`) still
anchors the blocks but does not license the shortcut.

The checkpoint applies only to a node with no chain yet. A value the node cannot read stops it —
a block hash has 64 characters (`echo -n <hash> | wc -c`).

### Joining without an HTTP endpoint

With no chain and no `HELIX_SYNC_PEER` but `HELIX_P2P_SEED_PEERS` set, a node fetches the genesis
over P2P from those peers. Set `HELIX_GENESIS_HASH` when you do this: the answer comes from
whichever peer replies first.

---

## Disk usage

The chain database grows with every block — about 17 KB for an empty block, about 47 KB per block
on the previous testnet chain (4–6 validators, light traffic), roughly 2 GB a day. Unset, a node
keeps everything, which is what an archive node is for. Everyone else should set a limit:

- **`HELIX_KEEP_BYTES=20G`** keeps as many recent blocks as fit in that much disk, whatever size
  blocks turn out to be. The database file grows in doubling steps and never shrinks, so ask for a
  little less than the power of two you mean: `120G` keeps it at 128 GB, `128G` can take it to 256.
- **`HELIX_KEEP_BLOCKS=100000`** keeps a fixed number of blocks (a little over two days).

Set both and the tighter one applies; at least 1000 blocks are always kept, and the genesis block
is never dropped. Pruning also runs while a new node catches up. Old blocks are deleted in batches
and their space is reused, so the file stops growing rather than shrinking. A pruning node cannot
serve the history it dropped; `/diagnostics` reports `earliest_block`.

**Below 1 GiB of free space the node stops writing and exits,** with a message saying so, and keeps
exiting on restart until there is room (Linux and macOS). A write that runs out of space half-way
can leave a database no build opens; stopping first keeps it intact. `GET /diagnostics` shows the
database size, bytes per block and — without a limit — the days of disk left.

---

## Networking

A node needs **outbound connections only**: it reaches the public seed over HTTPS and WebSocket,
from behind NAT or a firewall alike. But every node the others can reach directly makes the
network more robust — so **open port 8546** if you can.

### Network Resilience (Peer Exchange)

Nodes tell each other the addresses they know, every 30 seconds and whenever they connect, and dial
the ones they did not know. So a network turns into a mesh as soon as a few nodes are reachable,
instead of depending on one hub. A node remembers the peers it met across restarts
(`helix-peers.txt`), and when it has fewer than three peers it redials its seeds and every address
it remembers, every 30 seconds.

**A node finds its own address.** At start and every ten minutes it asks its sync peer which
address its request came from, and to try connecting back to its P2P port. Only if that succeeds
does it announce the address. The log says which:

```
INFO  This node is reachable from the outside and is now announcing that address to the network.
WARN  This node is NOT reachable from the outside, so other nodes can only find it through
      whichever peer it dialed. Open the P2P port to fix it.
```

A node that is not reachable still takes part fully — it dials out and relays addresses — it just
never announces one nobody could reach. Set `HELIX_P2P_PUBLIC_ADDR` when discovery cannot work
(behind a proxy or tunnel, or with no sync peer); it then wins outright.

### Behind a reverse proxy or tunnel

A proxy or Cloudflare tunnel forwards HTTPS and WebSockets on port 443, not raw TCP. Such a node can
follow the chain over RPC, but a validator needs peers to reach its P2P port — votes and proposals
travel only over P2P. So carry P2P inside a WebSocket, point the tunnel at it, and announce the
public address:

```bash
HELIX_P2P_WS_LISTEN="127.0.0.1:8547"                         # tunnel forwards 443 -> here
HELIX_P2P_PUBLIC_ADDR="/dns4/p2p.example.com/tcp/443/tls/ws"
```

This costs nothing in authenticity: libp2p's Noise handshake runs inside the WebSocket, so the
proxy carries the traffic but cannot pose as a peer. Nodes on WebSocket and on TCP interoperate
freely. A node that syncs from yours finds the WebSocket address by itself (your `/status` names
it); no seed configuration is needed on its side.

---

## Becoming a validator

The steps, the stake and delegation are in [Staking](staking.md#staking). What matters for the
node:

- **Sync first, stake last.** Start the node, wait until `helix chain status` shows peers and a
  moving height, and only then send the stake. A validator is expected to sign as soon as it is
  active; one that does not is jailed.
- **Stake the node's own key.** `helix wallet address --key validator-key.json` is the address
  your node signs as — stake that one. Staking from another wallet makes *that* address a
  validator nobody signs for.

### Bootstrapping a Multi-Validator Network

**How many validators a network needs.** BFT survives `f` validators failing only with `3f + 1`
of them: four survive one failure, seven survive two. Three are no better than one in that sense —
with three of equal weight, any two fall just short of the two-thirds quorum, so every block needs
all three.

**They have to be large enough to count.** Each validator's voting power is capped at 1% of the
total stake (see [Consensus](internals.md#consensus)); that cap is what makes validators of unequal
stake equal. A new validator reaches it with more than `total_stake / 50` staked (`total_stake /
100` with verified personhood). Validators below the cap weigh less, and a set in which one
validator still holds a quorum alone gains nothing from the others.

**Every validator joins the same way.** A network starts with one validator — the node that signed
the genesis. Every other one is added at runtime:

1. It runs a node that syncs the chain (see [Becoming a validator](#becoming-a-validator)).
2. Its key is funded with at least `MIN_VALIDATOR_STAKE` (10,000 HLX, a governance parameter) plus
   a margin — a slash takes 5% of the stake, and falling below the minimum drops a validator out of
   the set.
3. It stakes from the node's own key.
4. The next epoch boundary (every 100 blocks) puts it on **probation**: in the signing set, without
   voting power. During that epoch the node sends a small fee-free heartbeat signed with its key;
   once one lands on-chain — or a block it co-signed does — the next boundary makes it a full
   validator. A key with no node behind
   it never sends one and is never promoted — it cannot come to hold the chain up. `GET
   /validators` shows `probation_liveness_seen` for a validator on probation.

**Mesh the validators.** Votes travel between all validators, so each should reach every other
directly rather than all through one hub — a star stops when its hub's link does. Open port 8546,
or give each validator the others as seeds:

```bash
HELIX_P2P_SEED_PEERS="/dns4/bob.example/tcp/8546,/dns4/p2p.carol.example/tcp/443/tls/ws"
```

---

## Monitoring and troubleshooting

- **In a browser:** the node's own address (`http://127.0.0.1:8545`) shows its status page —
  height, sync state, peers, memory, whether it is co-signing.
- **Over HTTP:** `curl -s localhost:8545/diagnostics | jq` — uptime, sync state, validators whose
  votes are not arriving, when this node last co-signed, memory and disk, and how the previous run
  ended. **It is safe to share:** no addresses, paths, keys or peer ids. When asking for help, send
  this.
- **In the log:** a health line every minute.

### The chain has stopped — what to do

**Do not delete your chain data.** It is almost never the problem, and a validator starting from
an empty database cannot vote until it has synced again — it turns a short outage into a long one.
A restart that keeps the data is always safe.

Read the node's health line. It says only what the node can actually observe:

- **"This node has NO peers, so it cannot see the chain"** — it is cut off; the chain may be running
  without it. It redials by itself every 30 seconds; if the line stays, look at this machine's
  network path — firewall, tunnel, proxy.
- **"This node has FEWER PEERS than it wants and cannot reach quorum"** — the votes it misses may
  have no path to it. Give it a minute; if the line stays, check whether the other validators are
  reachable from here.
- **"This node is BEHIND the tip its peers report"** — the missing vote is likely this node's own:
  a validator below the tip cannot vote. Block sync closes the gap by itself; if the line keeps
  appearing, restart the node.
- **"This node is connected but hears NO other validator"** — a connection can stay open on one
  side after it died on the other. The node closes dead links within a few minutes by itself; if
  the line stays, restart it.
- **"Fewer validators are connected to this node than quorum needs"** — the missing ones may be down
  or reachable only through other peers. Restarting yours is safe but brings back nobody else.
- **"votes from at least one of them are not arriving here"** — your links work; someone's votes do
  not reach you. The "Validator silent" lines above it name whose.
- **"restarting the node re-establishes its round"** — this node is the stuck one. Restart it.

A stopped chain loses nothing: it continues from the same height once enough validators are back.
A node that fell behind catches up by itself.

A validator away for long enough is **jailed** — one that signs nothing for 1,800 blocks (about an
hour), or less than two thirds of its blocks over a longer stretch. It keeps its stake; once its
node is back and synced, `helix tx unjail --key validator-key.json` returns it to the set.

### When your node keeps stopping

A node that vanishes leaves a log that simply ends — a crash, an out-of-memory kill, `kill -9` and
a reboot look alike. So each run records how it ended (`helix-last-run.json`), and the next start
reports it:

```
Previous run (v0.20.0) did NOT shut down cleanly. It ran 9 min, last seen at height 36119
(<time>), using 1.8 GB of memory. Something ended it without warning — a crash, an OOM kill,
`kill -9`, or the machine going down. Check the system log around that time
(`journalctl -k --since` or `dmesg -T`) before assuming the node is at fault.
```

1. **Memory first.** An out-of-memory kill leaves nothing in the node's own log. If the reported
   memory is a large share of the machine's: `journalctl -k | grep -i oom`, and set
   `MALLOC_ARENA_MAX=2`.
2. **Then the disk.** Below 1 GiB free the node exits on purpose and says so — free space or set a
   [disk limit](#disk-usage).
3. **Then the machine** — reboots and migrations look the same from inside. A panic is the least
   likely cause and leaves a message.

---

## Docker Deployment

```bash
docker build -t helix-node .

docker run -d --name helix \
  -p 8545:8545 -p 8546:8546 \
  -v helix-data:/data \
  -e HELIX_RPC_BIND=0.0.0.0:8545 \
  -e MALLOC_ARENA_MAX=2 -e HELIX_KEEP_BYTES=20G \
  helix-node
```

- The image holds only the `helix` binary and runs `helix start` in `/data`. Mount a volume there
  so the key, its signing state and the database survive recreating the container.
- `HELIX_RPC_BIND=0.0.0.0:8545` makes the API reachable from outside the container; the default
  binds `127.0.0.1` only.
- It joins the public network by default. Set `HELIX_P2P_PUBLIC_ADDR` if the host has a public
  address, so other nodes find it.
- The image is not published to a registry; build it yourself.
