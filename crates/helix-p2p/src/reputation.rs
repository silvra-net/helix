use std::collections::HashSet;
use std::collections::HashMap;
use std::collections::VecDeque;

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
            insert_bounded(&mut self.banned, &mut self.banned_order, peer.to_string(), MAX_BANNED_ENTRIES);
            if let Some(ip) = self.peer_ip.get(peer) {
                insert_bounded(&mut self.banned_ips, &mut self.banned_ips_order, ip.clone(), MAX_BANNED_ENTRIES);
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
        // PeerId connecting from the same address.
        assert!(rep.is_banned("peer-a"));
        rep.note_connection("peer-a-fresh-identity", "1.2.3.4");
        assert!(rep.is_banned("peer-a-fresh-identity"));
    }
}
