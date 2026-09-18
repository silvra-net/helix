//! Remembering which peers this node has met, across restarts (Masterplan Stufe 3).
//!
//! Peer exchange already tells a node about every other peer its neighbours know — but that
//! knowledge lived only in `known_addrs`, a `HashSet` in the service loop. Every restart threw it
//! away and left the node with exactly what its operator configured: in practice the one built-in
//! seed. So a node that had been running for weeks, gossiping with the whole network, was on its
//! first start again every single time it came back.
//!
//! Bitcoin's DNS seeds are bootstrap for the *first* start; `peers.dat` carries it from then on,
//! which is why nobody notices when a seed goes down. This is that file. It does not remove the
//! need for a seed on a brand-new node — nothing can, and Bitcoin does not either — it removes the
//! need for one on every *subsequent* start.
//!
//! **Deliberately not in the redb chain database.** An operator who deletes their chain data is
//! the exact person who most needs to find their way back to the network; that happened on
//! 2026-08-04 and cost 21 hours. Keeping this beside the chain rather than inside it means wiping
//! the chain does not also wipe the node's knowledge of who to ask for it.
//!
//! **Eclipse note.** These addresses are learned from the network, so a hostile peer can try to
//! fill the file with addresses it controls. That is why loading them *adds* dial targets and
//! never replaces the configured seeds: the seed list stays the redial basis in
//! `service.rs`, so the worst a poisoned file achieves is wasted dial attempts, never isolation.
//! The cap bounds the file; validation keeps unparseable junk out of the dialer.

use std::collections::HashSet;
use std::path::Path;

use libp2p::Multiaddr;
use tracing::{debug, warn};

/// How many learned addresses survive a restart.
///
/// Matches `service::MAX_KNOWN_PEER_ADDRS`, because this file is a snapshot of exactly that set —
/// a larger cap here could not be filled, and a smaller one would silently discard addresses the
/// running node considered worth keeping.
pub const MAX_PERSISTED_ADDRS: usize = 200;

/// Read remembered peer addresses.
///
/// Every failure mode returns an empty list rather than an error: a missing file is a first run, a
/// corrupt one is not worth refusing to start over, and in both cases the configured seeds still
/// get the node onto the network. A node that will not boot because it cannot read an *optimisation*
/// would be a worse failure than the one this fixes.
pub fn load(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let addrs = parse(&contents);
            debug!(count = addrs.len(), path = %path.display(), "Loaded remembered peer addresses");
            addrs
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Could not read the peer file — starting from the configured seeds only");
            Vec::new()
        }
    }
}

/// Write the addresses this node currently knows.
///
/// Best-effort by design: a node that cannot write this file is still a perfectly good node, and
/// the alternative — failing a consensus-carrying process over a cache write — is not a trade
/// worth making. Logged once per failure so a permanently unwritable path is still visible.
pub fn save(path: &Path, addrs: &HashSet<String>) {
    let contents = render(addrs);
    // Write-then-rename, so a crash mid-write cannot leave a half-written file that the next
    // start reads as the node's entire knowledge of the network.
    let tmp = path.with_extension("tmp");
    let written = std::fs::write(&tmp, contents).and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = written {
        warn!(path = %path.display(), error = %e, "Could not save known peers");
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Parse the file into dialable addresses, dropping anything that is not one.
///
/// Validation happens here rather than at the dialer so a hand-edited file — which is a supported
/// thing to do, it is the `addnode` of this design — reports its own typos by simply not using
/// them, instead of feeding them to libp2p on every restart forever.
fn parse(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| is_dialable(line))
        .map(str::to_string)
        .take(MAX_PERSISTED_ADDRS)
        .collect()
}

/// Could this address ever be dialed, or is it junk that will fail forever?
///
/// Parsing as a `Multiaddr` is not enough, and the production node proves it: its peer file held
/// `/dns4/43.133.224.33:8546/tcp/8546`, which parses cleanly because `dns4` accepts any string,
/// and which no resolver will ever answer — a hostname cannot contain a colon (RFC 1123). It was
/// dialed on every redial tick and never once connected.
///
/// These addresses come from other peers, so this is input validation, not tidiness. A peer can
/// announce whatever it likes, the set is capped at `MAX_PERSISTED_ADDRS`, and every slot spent on
/// something undialable is a slot not holding a peer that would answer — with the redial now
/// running whenever this node is under-connected rather than only at zero peers, that junk is
/// dialed far more often than it used to be.
///
/// Deliberately narrow: it rejects only what *cannot* resolve, never what merely looks unusual.
/// An address this node cannot reach today may be reachable tomorrow — that is a different thing
/// from an address no resolver can parse, and only the second is safe to drop.
pub fn is_dialable(addr: &str) -> bool {
    let Ok(parsed) = addr.parse::<Multiaddr>() else {
        return false;
    };
    // The empty string parses into a `Multiaddr` with no protocols at all, and every check below
    // is a search for something bad — so an address with nothing in it passed them all. Found by
    // the test, not by reading: `parse` here already drops empty lines, but `select_new_addrs`
    // takes its input straight from peer exchange and did not.
    if parsed.iter().next().is_none() {
        return false;
    }
    !parsed.iter().any(|p| {
        let name = match &p {
            libp2p::multiaddr::Protocol::Dns(n)
            | libp2p::multiaddr::Protocol::Dns4(n)
            | libp2p::multiaddr::Protocol::Dns6(n)
            | libp2p::multiaddr::Protocol::Dnsaddr(n) => n.as_ref(),
            _ => return false,
        };
        name.is_empty() || name.contains(':')
    })
}

/// One address per line, sorted, with a header explaining what the file is.
///
/// Sorted so the file does not churn between saves for a set that has not changed — that keeps a
/// diff meaningful and makes it obvious at a glance when the node really did learn something new.
/// Plain lines rather than JSON because the audience is an operator diagnosing why their node
/// cannot find the network, and because adding a peer by hand should not require knowing a format.
fn render(addrs: &HashSet<String>) -> String {
    let mut sorted: Vec<&String> = addrs.iter().collect();
    sorted.sort();
    sorted.truncate(MAX_PERSISTED_ADDRS);

    let mut out = String::from(
        "# Peers this node has met. Written automatically; safe to edit or delete.\n\
         # One multiaddr per line. Deleting this file only costs the node its head start.\n",
    );
    for addr in sorted {
        out.push_str(addr);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(addrs: &[&str]) -> HashSet<String> {
        addrs.iter().map(|s| s.to_string()).collect()
    }

    /// The whole point, in one assertion: what a node knew when it stopped is what it knows when
    /// it starts.
    #[test]
    fn what_the_node_knew_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("helix-peers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.txt");

        let known = set(&["/ip4/1.2.3.4/tcp/8546", "/dns4/example.net/tcp/443/tls/ws"]);
        save(&path, &known);

        let loaded: HashSet<String> = load(&path).into_iter().collect();
        assert_eq!(loaded, known);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A first run is not an error, and neither is a file somebody deleted.
    #[test]
    fn a_missing_file_is_a_first_run_not_a_failure() {
        assert!(load(Path::new("/nonexistent/helix/peers.txt")).is_empty());
    }

    /// Junk must not reach the dialer. A truncated write, a stray editor line, half a URL — none
    /// of it is an address, and passing it through would mean libp2p re-learning that on every
    /// start for the life of the file.
    #[test]
    fn only_real_addresses_come_back_out() {
        let parsed = parse(
            "# a comment\n\
             \n\
             /ip4/1.2.3.4/tcp/8546\n\
             not-an-address\n\
             http://example.com:8545\n\
             /dns4/example.net/tcp/443/tls/ws\n",
        );
        assert_eq!(
            parsed,
            vec!["/ip4/1.2.3.4/tcp/8546", "/dns4/example.net/tcp/443/tls/ws"]
        );
    }

    /// The bound a hostile peer runs into. Without it, whoever gossips the most addresses decides
    /// how large this file grows.
    #[test]
    fn a_flood_of_addresses_cannot_grow_the_file_without_bound() {
        let many: HashSet<String> = (0..MAX_PERSISTED_ADDRS * 3)
            .map(|i| format!("/ip4/10.0.{}.{}/tcp/8546", i / 256, i % 256))
            .collect();
        let rendered = render(&many);
        let lines = rendered.lines().filter(|l| !l.starts_with('#')).count();
        assert_eq!(lines, MAX_PERSISTED_ADDRS);
        assert_eq!(parse(&rendered).len(), MAX_PERSISTED_ADDRS);
    }

    /// An unchanged set must produce an unchanged file, or every save looks like news.
    #[test]
    fn the_same_peers_render_the_same_file() {
        let a = set(&[
            "/ip4/9.9.9.9/tcp/1",
            "/ip4/1.1.1.1/tcp/2",
            "/ip4/5.5.5.5/tcp/3",
        ]);
        let b = set(&[
            "/ip4/5.5.5.5/tcp/3",
            "/ip4/9.9.9.9/tcp/1",
            "/ip4/1.1.1.1/tcp/2",
        ]);
        assert_eq!(render(&a), render(&b));
    }

    /// A file that is entirely unreadable garbage must behave exactly like no file at all —
    /// the node still starts and still has its configured seeds.
    #[test]
    fn a_corrupt_file_degrades_to_a_first_run() {
        let dir = std::env::temp_dir().join(format!("helix-peers-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.txt");
        std::fs::write(&path, "\u{0}\u{1}garbage\nmore garbage").unwrap();

        assert!(load(&path).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod dialable_tests {
    use super::is_dialable;

    /// The entry that sat in the production peer file: a host:port pair put where a hostname
    /// belongs. It parses as a `Multiaddr` — `dns4` takes any string — and resolves never.
    #[test]
    fn a_hostname_carrying_a_port_is_not_dialable() {
        assert!(!is_dialable("/dns4/43.133.224.33:8546/tcp/8546"));
        assert!(!is_dialable("/dns4//tcp/8546"));
    }

    /// The control, and the half that matters more: everything real must survive. A validator
    /// dropped for looking unusual is worse than a junk address dialed forever.
    #[test]
    fn real_addresses_are_kept() {
        for addr in [
            "/ip4/101.33.68.38/tcp/8546",
            "/ip4/127.0.0.1/tcp/19731",
            "/dns4/p2p.silvra.net/tcp/443/tls/ws",
            "/dns4/sta-rack-server.tail11322f.ts.net/tcp/443",
            "/ip6/::1/tcp/8546",
            "/dns/example.com/tcp/443/wss",
        ] {
            assert!(is_dialable(addr), "{addr} must stay dialable");
        }
    }

    #[test]
    fn something_that_is_not_a_multiaddr_at_all_is_refused() {
        assert!(!is_dialable("43.133.224.33:8546"));
        assert!(!is_dialable("not an address"));
        assert!(!is_dialable(""));
    }
}
