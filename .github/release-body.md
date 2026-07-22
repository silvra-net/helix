## Which download do I need?

**Two of them, and you only ever need one.**

| I want to… | Download |
|---|---|
| **Run a node or validator** (server, headless, no desktop) | `helix-cli-…` for your platform — unpack it and run `helix start`. No installer, no dependencies. |
| **Use the wallet on my desktop** (send, stake, explorer, run a node from the UI) | `helix-gui-…` for your platform. **The wallet already contains the node** — you do not need the CLI as well. |

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

### Your node was being killed for running out of memory?

That was us, not your machine. The embedded database applied its library's default page cache
of **1 GiB**, which we never overrode, so a node holding the chain settled at over 1.5 GB
resident — and a full sync on a small server ran out of room and aborted. This release caps it:
a complete sync of the live chain now peaks around **280 MB** and stays there, with no loss of
sync speed. `HELIX_DB_CACHE_MB` raises it again on machines with memory to spare.

### Your node cannot catch up, or reports "does not chain from the previous block"?

Its stored chain has diverged from the network's and cannot be repaired in place — it has to
re-sync from scratch. In the wallet: **Node → Reset chain data** (it renames the old data, it
does not delete it). Headless: stop the node and rename `helix-data.redb` aside. Your keys and
your stake are untouched by this; only the block history is re-fetched.

### Validator operators: this release changes consensus

**All operators must update together.** A node no longer counts a silent validator out of its
own quorum — that was a local decision each node made for itself, so two nodes could disagree
about it, each finalize a different block at the same height, and split the chain. They did.

The consequence is deliberate and worth stating plainly: a validator set that has lost more
than a third of its voting power now **halts** until the missing validators return, instead of
producing blocks without them. That is what BFT means, and tolerating one absence takes four
validators, not two. A halt is visible and heals by itself; a fork silently duplicates the
history and every balance in it.

A stalled node now also names the validator it is waiting for, once per round, in its log.

---
