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

Already jailed? Take this release **before** sending `helix tx unjail` — see below.

### Validator operators: this release changes consensus

Downtime-jailing and the catch-up loop both changed. Nodes running different versions can
disagree about who is jailed, so **all operators should update together**. If you are currently
jailed, install this version first and unjail afterwards.

---
