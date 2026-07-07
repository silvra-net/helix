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
#[derive(Debug, Default)]
pub struct PeerReputation {
    strikes: HashMap<String, u32>,
    banned: HashSet<String>,
}

impl PeerReputation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a protocol violation from `peer`. Returns `true` if this
    /// infraction pushed the peer over the ban threshold (i.e. the caller
    /// should disconnect them now).
    pub fn record_infraction(&mut self, peer: &str) -> bool {
        if self.banned.contains(peer) {
            return true;
        }
        let strikes = self.strikes.entry(peer.to_string()).or_insert(0);
        *strikes += 1;
        if *strikes >= BAN_THRESHOLD {
            self.banned.insert(peer.to_string());
            true
        } else {
            false
        }
    }

    pub fn is_banned(&self, peer: &str) -> bool {
        self.banned.contains(peer)
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
}
