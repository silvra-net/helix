## Which download do I need?

**Two of them, and you only ever need one.**

| I want to… | Download |
|---|---|
| **Run a node or validator** (server, headless, no desktop) | `helix-cli-…` for your platform — unpack it and run `helix start`. No installer, no dependencies. |
| **Use the wallet on my desktop** (send, stake, see your history, run a node from the UI) | `helix-gui-…` for your platform. **The wallet already contains the node** — you do not need the CLI as well. |
| **Browse the chain** (blocks, transactions, any address) | Nothing to download — [explorer.silvra.net](https://explorer.silvra.net). Every node also serves its own status page at its root URL. |

### Which wallet installer?

- **Linux** — `.AppImage` runs anywhere without installing (make it executable and start it) · `.deb` for Debian/Ubuntu · `.rpm` for Fedora/RHEL
- **macOS** — `.dmg` (Apple Silicon)
- **Windows** — `.exe` is the normal installer · `.msi` is for managed/automated rollout

### Running a validator?

Start the node **first**, confirm `peer_count` is above zero, and only then send the stake
transaction — see the founding-validator checklist in the
[README](https://github.com/silvra-net/helix#readme). The wait itself is safe (a validator
serving its one-epoch activation delay is no longer charged with missed blocks), but a node
that isn't connected can't vote once it *is* activated.

### Your node cannot catch up, or reports "does not chain from the previous block"?

Its stored chain has diverged from the network's and cannot be repaired in place — it has to
re-sync from scratch. In the wallet: **Validate → Reset local chain** (it renames the old data, it
does not delete it). Headless: stop the node and rename `helix-data.redb` aside. Your keys and
your stake are untouched by this; only the block history is re-fetched.

### Running a node on a small machine?

Set `MALLOC_ARENA_MAX=2` in the node's environment — without it, glibc keeps freed memory in
per-thread arenas and a long-running node grows for days. And cap the database: `HELIX_KEEP_BLOCKS`
or `HELIX_KEEP_BYTES` (see [running a node](https://github.com/silvra-net/helix/blob/master/docs/running-a-node.md)).

---
