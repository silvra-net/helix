use std::collections::HashSet;
use std::collections::HashMap;
use std::collections::VecDeque;

use tracing::warn;

use crate::net_addr::is_shared_proxy_address;

/// Number of protocol infractions (malformed gossipsub payloads, failed session
/// handshakes, etc.) a peer may commit before it is disconnected and refused
/// reconnection for the lifetime of this process.
const BAN_THRESHOLD: u32 = 5;

/// Upper bound on how many distinct identities/IPs we hold a permanent ban
/// for. Each ban costs an attacker `BAN_THRESHOLD` infractions, so this is
/// deliberately generous — it exists only to cap memory under a sustained
/// attack from many identities/IPs, not to limit normal operation. Once the
/// cap is hit, the oldest ban is evicted (and its subject un-banned) to make
/// room for the newest one.
const MAX_BANNED_ENTRIES: usize = 100_000;

/// Tracks per-peer misbehavior strikes and bans peers that cross the threshold.
///
/// This is intentionally process-local and in-memory: it stops a single noisy
/// or malicious peer from wasting bandwidth/CPU on a live connection, not a
/// persistent reputation system shared across restarts or peers.
///
/// Banning is keyed by both libp2p `PeerId` and remote IP address. A `PeerId`
/// is derived from a locally generated keypair, which an attacker can
/// regenerate for free — banning by `PeerId` alone lets a banned peer simply
/// reconnect with a fresh identity. Tracking the IP each `PeerId` last
/// connected from (via `note_connection`) lets a ban also stick to that IP,
/// so a reconnect attempt with a new `PeerId` from the same address is still
/// rejected.
#[derive(Debug, Default)]
pub struct PeerReputation {
    strikes: HashMap<String, u32>,
    banned: HashSet<String>,
    banned_order: VecDeque<String>,
    peer_ip: HashMap<String, String>,
    banned_ips: HashSet<String>,
    banned_ips_order: VecDeque<String>,
}

/// Insert `value` into `set`/`order` (a lookup set paired with its insertion
/// order), evicting the oldest entry once `max` is exceeded.
fn insert_bounded(set: &mut HashSet<String>, order: &mut VecDeque<String>, value: String, max: usize) {
    if set.insert(value.clone()) {
        order.push_back(value);
        if order.len() > max {
            if let Some(oldest) = order.pop_front() {
                set.remove(&oldest);
            }
        }
    }
}

impl PeerReputation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record which IP address `peer` last connected from, and report whether
    /// the connection should be rejected (`peer` or `ip` already banned).
    ///
    /// If `ip` is already banned, the `peer_ip` entry is deliberately NOT
    /// recorded. Without this short-circuit, an attacker connecting from an
    /// already-banned IP with an endless supply of free, freshly generated
    /// `PeerId`s could grow `peer_ip` without bound — no `BAN_THRESHOLD`
    /// infractions needed, just one connection attempt per identity. This
    /// case can't reuse the `insert_bounded` cap used for `banned`/
    /// `banned_ips`: those are rarely-added, high-cost entries (5
    /// infractions each) where losing the oldest ban under sustained attack
    /// is an acceptable tradeoff, whereas here every entry is free for the
    /// attacker to produce, so a bounded cap would just get evicted
    /// continuously by attack traffic and could push out legitimate peers'
    /// entries instead. Skipping the insert also doesn't need `on_disconnect`
    /// to change: it already exempts banned peers from cleanup so the IP
    /// ban stays resolvable after a legitimately-banned peer disconnects
    /// (see its docs) — this path simply never creates the entry to begin
    /// with, for identities that were never legitimate.
    pub fn note_connection(&mut self, peer: &str, ip: &str) -> bool {
        if self.banned.contains(peer) || self.banned_ips.contains(ip) {
            return true;
        }
        self.peer_ip.insert(peer.to_string(), ip.to_string());
        false
    }

    /// Record a protocol violation from `peer`. Returns `true` if this
    /// infraction pushed the peer over the ban threshold (i.e. the caller
    /// should disconnect them now).
    pub fn record_infraction(&mut self, peer: &str) -> bool {
        if self.is_banned(peer) {
            return true;
        }
        let strikes = self.strikes.entry(peer.to_string()).or_insert(0);
        *strikes += 1;
        if *strikes >= BAN_THRESHOLD {
            insert_bounded(&mut self.banned, &mut self.banned_order, peer.to_string(), MAX_BANNED_ENTRIES);
            if let Some(ip) = self.peer_ip.get(peer) {
                // Banning the IP alongside the peer assumes the IP identifies *whoever* is
                // misbehaving — true for a directly reachable listener, false behind a reverse
                // proxy, where every peer shares the proxy's loopback address (backlog #148,
                // measured on production: all inbound connections arrive from 127.0.0.1).
                //
                // There the IP ban is collective punishment with the whole validator set as the
                // collective: five infractions from one peer — malicious, or merely running a
                // broken build — would refuse every honest validator's connections and stall the
                // chain outright. That is a far worse outcome than the Sybil case the IP ban
                // exists to raise the cost of, and the Sybil case is one it cannot address here
                // anyway, since the attacker's address is the same as everyone else's.
                //
                // The peer ban above is untouched and does the real work: it is keyed on the
                // PeerId, which stays meaningful no matter what the connection travelled through.
                if is_shared_proxy_address(ip) {
                    warn!(
                        peer = %peer,
                        ip = %ip,
                        "Banning this peer, but not its address — peers reach this node through a \
                         local proxy, so the address is shared with every other peer and banning \
                         it would lock them all out."
                    );
                } else {
                    insert_bounded(&mut self.banned_ips, &mut self.banned_ips_order, ip.clone(), MAX_BANNED_ENTRIES);
                }
            }
            true
        } else {
            false
        }
    }

    /// `true` if `peer` is banned directly, or if the IP it last connected
    /// from is banned (e.g. because a different `PeerId` from that IP was
    /// banned earlier).
    pub fn is_banned(&self, peer: &str) -> bool {
        if self.banned.contains(peer) {
            return true;
        }
        self.peer_ip
            .get(peer)
            .map(|ip| self.banned_ips.contains(ip))
            .unwrap_or(false)
    }

    /// Drop tracking state for `peer` once its connection closes, so that
    /// many short-lived connections (each below the ban threshold) don't
    /// grow `strikes`/`peer_ip` without bound.
    ///
    /// Banned peers (directly, or via a banned IP) are exempt: their
    /// `peer_ip` entry must survive the disconnect, otherwise a banned
    /// `PeerId` reconnecting from the same IP would no longer resolve to
    /// that IP for the `is_banned` check.
    pub fn on_disconnect(&mut self, peer: &str) {
        if self.is_banned(peer) {
            return;
        }
        self.strikes.remove(peer);
        self.peer_ip.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tolerates_infractions_below_threshold() {
        let mut rep = PeerReputation::new();
        for _ in 0..BAN_THRESHOLD - 1 {
            assert!(!rep.record_infraction("peer-a"));
        }
        assert!(!rep.is_banned("peer-a"));
    }

    #[test]
    fn bans_once_threshold_is_reached() {
        let mut rep = PeerReputation::new();
        for _ in 0..BAN_THRESHOLD - 1 {
            rep.record_infraction("peer-a");
        }
        assert!(rep.record_infraction("peer-a"));
        assert!(rep.is_banned("peer-a"));
    }

    #[test]
    fn distinct_peers_tracked_independently() {
        let mut rep = PeerReputation::new();
        rep.record_infraction("peer-a");
        assert!(!rep.is_banned("peer-b"));
    }

    #[test]
    fn already_banned_peer_reports_banned_on_further_infractions() {
        let mut rep = PeerReputation::new();
        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction("peer-a");
        }
        assert!(rep.record_infraction("peer-a"));
    }

    /// Backlog #148: behind the production tunnel every peer connects from `127.0.0.1`, so banning
    /// the address of one misbehaving peer would refuse *every* validator and stall the chain —
    /// five malformed messages from one broken build would be enough. The peer ban still has to
    /// bite; only the collective half is dropped.
    #[test]
    fn banning_a_peer_behind_a_proxy_does_not_ban_the_shared_address() {
        let mut rep = PeerReputation::new();
        rep.note_connection("peer-bad", "127.0.0.1");
        rep.note_connection("peer-honest", "127.0.0.1");

        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction("peer-bad");
        }

        assert!(rep.is_banned("peer-bad"), "the misbehaving peer must still be banned");
        assert!(
            !rep.is_banned("peer-honest"),
            "an unrelated peer sharing the proxy's address must not be caught by it"
        );
        assert!(
            !rep.note_connection("peer-honest", "127.0.0.1"),
            "and it must still be able to connect"
        );
    }

    /// The control: on a directly reachable node the address really is the peer's, and the IP ban
    /// is the Sybil cost it was built to impose. An exemption that widened past loopback would
    /// silently remove that.
    #[test]
    fn banning_a_peer_on_a_routable_address_still_bans_the_address() {
        let mut rep = PeerReputation::new();
        rep.note_connection("peer-bad", "203.0.113.7");
        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction("peer-bad");
        }

        assert!(rep.is_banned("peer-bad"));
        assert!(
            rep.note_connection("peer-fresh-identity", "203.0.113.7"),
            "a new PeerId from a banned address must still be refused"
        );
    }

    #[test]
    fn banning_a_peer_also_bans_its_last_known_ip() {
        let mut rep = PeerReputation::new();
        rep.note_connection("peer-a", "1.2.3.4");
        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction("peer-a");
        }

        // A brand new PeerId connecting from the same banned IP is rejected
        // — the caller learns this from `note_connection`'s return value,
        // since (by design) no `peer_ip` entry is recorded for it.
        assert!(rep.note_connection("peer-a-fresh-identity", "1.2.3.4"));
    }

    #[test]
    fn different_ip_is_not_affected_by_unrelated_ban() {
        let mut rep = PeerReputation::new();
        rep.note_connection("peer-a", "1.2.3.4");
        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction("peer-a");
        }

        rep.note_connection("peer-b", "5.6.7.8");
        assert!(!rep.is_banned("peer-b"));
    }

    #[test]
    fn disconnect_clears_state_for_non_banned_peer() {
        let mut rep = PeerReputation::new();
        rep.note_connection("peer-a", "1.2.3.4");
        rep.record_infraction("peer-a");

        rep.on_disconnect("peer-a");

        // Strikes reset: a fresh threshold's worth of infractions is needed
        // again before this peer is banned.
        for _ in 0..BAN_THRESHOLD - 1 {
            assert!(!rep.record_infraction("peer-a"));
        }
        assert!(!rep.is_banned("peer-a"));
    }

    #[test]
    fn banned_set_evicts_oldest_entry_once_cap_is_reached() {
        let mut rep = PeerReputation::new();
        // Fill the cap with distinct banned peers (no IPs, to isolate the
        // `banned`/`banned_order` eviction path).
        for i in 0..MAX_BANNED_ENTRIES {
            let peer = format!("peer-{i}");
            for _ in 0..BAN_THRESHOLD {
                rep.record_infraction(&peer);
            }
        }
        assert!(rep.is_banned("peer-0"));

        // One more ban past the cap evicts the oldest (peer-0).
        let overflow_peer = "peer-overflow";
        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction(overflow_peer);
        }

        assert!(!rep.is_banned("peer-0"));
        assert!(rep.is_banned(overflow_peer));
        assert!(rep.is_banned("peer-1"));
    }

    #[test]
    fn disconnect_preserves_state_for_banned_peer_and_its_ip() {
        let mut rep = PeerReputation::new();
        rep.note_connection("peer-a", "1.2.3.4");
        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction("peer-a");
        }
        assert!(rep.is_banned("peer-a"));

        rep.on_disconnect("peer-a");

        // Still banned directly, and the IP ban still applies to a fresh
        // PeerId connecting from the same address (reported via
        // `note_connection`'s return value, not `is_banned`, since no
        // `peer_ip` entry is recorded for it).
        assert!(rep.is_banned("peer-a"));
        assert!(rep.note_connection("peer-a-fresh-identity", "1.2.3.4"));
    }

    #[test]
    fn note_connection_reports_not_banned_and_records_ip_for_new_peer() {
        let mut rep = PeerReputation::new();
        assert!(!rep.note_connection("peer-a", "1.2.3.4"));
        assert_eq!(rep.peer_ip.get("peer-a"), Some(&"1.2.3.4".to_string()));
    }

    #[test]
    fn note_connection_reports_banned_for_directly_banned_peer() {
        let mut rep = PeerReputation::new();
        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction("peer-a");
        }
        assert!(rep.note_connection("peer-a", "1.1.1.1"));
    }

    #[test]
    fn note_connection_skips_recording_peer_ip_when_ip_already_banned() {
        let mut rep = PeerReputation::new();
        rep.note_connection("peer-a", "9.9.9.9");
        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction("peer-a");
        }
        assert!(rep.is_banned("peer-a"));

        // Many fresh PeerIds connecting from the same now-banned IP are all
        // reported as banned...
        for i in 0..1000 {
            let fresh_peer = format!("peer-fresh-{i}");
            assert!(rep.note_connection(&fresh_peer, "9.9.9.9"));
        }
        // ...without growing `peer_ip`: only the original `peer-a` entry
        // (recorded before the ban) is present.
        assert_eq!(rep.peer_ip.len(), 1);
    }
}
