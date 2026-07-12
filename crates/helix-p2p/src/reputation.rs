use std::collections::HashSet;
use std::collections::HashMap;

/// Number of protocol infractions (malformed gossipsub payloads, failed session
/// handshakes, etc.) a peer may commit before it is disconnected and refused
/// reconnection for the lifetime of this process.
const BAN_THRESHOLD: u32 = 5;

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
    peer_ip: HashMap<String, String>,
    banned_ips: HashSet<String>,
}

impl PeerReputation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record which IP address `peer` last connected from. Call this on every
    /// new connection so a later ban can also be applied to the IP.
    pub fn note_connection(&mut self, peer: &str, ip: &str) {
        self.peer_ip.insert(peer.to_string(), ip.to_string());
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
            self.banned.insert(peer.to_string());
            if let Some(ip) = self.peer_ip.get(peer) {
                self.banned_ips.insert(ip.clone());
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

    #[test]
    fn banning_a_peer_also_bans_its_last_known_ip() {
        let mut rep = PeerReputation::new();
        rep.note_connection("peer-a", "1.2.3.4");
        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction("peer-a");
        }

        // A brand new PeerId connecting from the same banned IP is rejected.
        rep.note_connection("peer-a-fresh-identity", "1.2.3.4");
        assert!(rep.is_banned("peer-a-fresh-identity"));
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
    fn disconnect_preserves_state_for_banned_peer_and_its_ip() {
        let mut rep = PeerReputation::new();
        rep.note_connection("peer-a", "1.2.3.4");
        for _ in 0..BAN_THRESHOLD {
            rep.record_infraction("peer-a");
        }
        assert!(rep.is_banned("peer-a"));

        rep.on_disconnect("peer-a");

        // Still banned directly, and the IP ban still applies to a fresh
        // PeerId connecting from the same address.
        assert!(rep.is_banned("peer-a"));
        rep.note_connection("peer-a-fresh-identity", "1.2.3.4");
        assert!(rep.is_banned("peer-a-fresh-identity"));
    }
}
