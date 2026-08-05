//! Per-IP connection cap.
//!
//! `libp2p::connection_limits::Behaviour` bounds global/pending/per-peer connection
//! counts, but has no notion of the remote IP — a single attacker can still open
//! many connections as long as each one presents a fresh `PeerId` (trivial to
//! generate, they're just keypairs). This behaviour closes that gap by tracking
//! concurrent connections (pending + established, inbound only — we choose who we
//! dial, so outbound isn't an attacker-controlled vector) per source IP and denying
//! new ones past the configured limit.
//!
//! # Behind a reverse proxy this cap inverts (backlog #148)
//!
//! Measured on the production node 2026-08-05: every inbound P2P connection arrives from
//! `127.0.0.1`, because peers reach it through a Cloudflare tunnel that terminates locally. There
//! were no outbound connections at all. The source address libp2p sees is the proxy's, not the
//! peer's, and nothing in a plain TCP/WS tunnel carries the original one (no PROXY protocol).
//!
//! That makes the cap worse than absent, in both directions at once:
//!
//! - **As protection it is nil.** An attacker coming through the tunnel presents the same IP as
//!   every honest validator, so per-IP accounting cannot separate them — the exact Sybil case this
//!   was built for is the one it cannot see.
//! - **As a limit it is a weapon.** All operators share the *one* bucket. An attacker who opens
//!   `max_connections_per_ip` connections locks out every honest validator, and a growing set of
//!   legitimate peers can exhaust it with no attacker at all — `max_established_per_peer` is 4, so
//!   two peers can reach a cap of 8 on their own.
//!
//! So loopback sources are exempt here, and the global caps
//! (`max_peers` / `max_established_incoming`) carry the load instead. This does not weaken a real
//! deployment: on a node with a directly reachable listener, peer addresses are still their own and
//! the cap works as designed. It removes a denial-of-service vector on a proxied node while giving
//! up protection that was already, measurably, not there. Restoring genuine per-IP limits behind
//! the tunnel needs the real client address — PROXY protocol or an equivalent — which is a
//! deployment change, not a code change, and is noted as such in the backlog.

use std::collections::HashMap;
use std::task::{Context, Poll};

use libp2p::core::Multiaddr;
use libp2p::identity::PeerId;
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};

use tracing::warn;

use crate::service::multiaddr_ip;

#[derive(Debug, Clone, Copy)]
pub struct IpLimitExceeded {
    pub limit: u32,
}

impl std::fmt::Display for IpLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "connection limit exceeded: at most {} concurrent connections per IP are allowed", self.limit)
    }
}

impl std::error::Error for IpLimitExceeded {}

/// A source address the per-IP cap cannot meaningfully account for: it belongs to a local reverse
/// proxy, not to the peer behind it. See the module docs for why this is an exemption rather than
/// a stricter rule.
fn is_proxy_local(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => addr.is_loopback(),
        // Unparseable means we cannot key a count on it either; the global limits still apply.
        Err(_) => false,
    }
}

pub struct IpConnLimiter {
    max_per_ip: u32,
    counts: HashMap<String, u32>,
    by_connection: HashMap<ConnectionId, String>,
    /// IPs already reported as over the cap. Without this, the log line below is emitted on every
    /// dial attempt — and something hitting a connection limit is, by its nature, retrying.
    warned_ips: std::collections::HashSet<String>,
    /// Whether the "peers are arriving through a local proxy" notice has been logged. Once per
    /// process: it describes the deployment, not an event.
    warned_proxy_local: bool,
}

impl IpConnLimiter {
    pub fn new(max_per_ip: u32) -> Self {
        IpConnLimiter {
            max_per_ip,
            counts: HashMap::new(),
            by_connection: HashMap::new(),
            warned_ips: std::collections::HashSet::new(),
            warned_proxy_local: false,
        }
    }

    fn release(&mut self, connection_id: ConnectionId) {
        if let Some(ip) = self.by_connection.remove(&connection_id) {
            if let Some(count) = self.counts.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.counts.remove(&ip);
                }
            }
        }
    }
}

impl NetworkBehaviour for IpConnLimiter {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = void::Void;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        let Some(ip) = multiaddr_ip(remote_addr) else {
            // No IP in the address (e.g. a relay/onion address) — nothing to key
            // the per-IP count on, so let the global limits behaviour handle it.
            return Ok(());
        };

        // Peers behind a local reverse proxy all share its address — counting them together caps
        // the whole validator set at one bucket while separating nobody. Module docs for the full
        // reasoning; the global limits still bound this.
        if is_proxy_local(&ip) {
            if !self.warned_proxy_local {
                self.warned_proxy_local = true;
                warn!(
                    ip = %ip,
                    "Inbound peers arrive from a loopback address — this node is behind a reverse \
                     proxy, so the per-IP connection cap cannot tell peers apart and is not \
                     applied. Sybil resistance for these connections has to come from the proxy."
                );
            }
            return Ok(());
        }

        let count = self.counts.get(&ip).copied().unwrap_or(0);
        if count >= self.max_per_ip {
            // Previously silent. A cap that turns peers away without a trace is indistinguishable
            // from a network fault at exactly the moment someone is trying to work out why a
            // validator will not connect.
            if self.warned_ips.insert(ip.clone()) {
                warn!(
                    ip = %ip,
                    limit = self.max_per_ip,
                    "Refusing inbound connections from this address — per-IP cap reached. If this \
                     is a legitimate peer, raise max_connections_per_ip."
                );
            }
            return Err(ConnectionDenied::new(IpLimitExceeded { limit: self.max_per_ip }));
        }
        // Back under the cap: let this address be reported again if it recurs.
        self.warned_ips.remove(&ip);

        self.counts.insert(ip.clone(), count + 1);
        self.by_connection.insert(connection_id, ip);
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // Already counted in handle_pending_inbound_connection; the connection
        // simply transitions from pending to established under the same slot.
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // Outbound connections are dialed by us (seed peers / mDNS discovery),
        // not attacker-controlled — no per-IP limit applied.
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionClosed(closed) => self.release(closed.connection_id),
            FromSwarm::ListenFailure(failure) => self.release(failure.connection_id),
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        void::unreachable(event)
    }

    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: &str) -> Multiaddr {
        format!("/ip4/{ip}/tcp/9000").parse().unwrap()
    }

    fn dummy_local_addr() -> Multiaddr {
        "/ip4/0.0.0.0/tcp/8546".parse().unwrap()
    }

    #[test]
    fn allows_connections_up_to_the_per_ip_limit() {
        let mut limiter = IpConnLimiter::new(2);
        let local = dummy_local_addr();

        assert!(limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(1), &local, &addr("1.2.3.4")).is_ok());
        assert!(limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(2), &local, &addr("1.2.3.4")).is_ok());
    }

    #[test]
    fn denies_the_connection_that_exceeds_the_per_ip_limit() {
        let mut limiter = IpConnLimiter::new(2);
        let local = dummy_local_addr();

        limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(1), &local, &addr("1.2.3.4")).unwrap();
        limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(2), &local, &addr("1.2.3.4")).unwrap();

        let err = limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(3), &local, &addr("1.2.3.4"));
        assert!(err.is_err(), "third connection from the same IP should be denied");
    }

    #[test]
    fn different_ips_have_independent_limits() {
        let mut limiter = IpConnLimiter::new(1);
        let local = dummy_local_addr();

        assert!(limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(1), &local, &addr("1.2.3.4")).is_ok());
        assert!(limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(2), &local, &addr("5.6.7.8")).is_ok());
    }

    /// Backlog #148: behind the production tunnel every peer presents `127.0.0.1`, so the cap
    /// separates nobody and instead lets whoever connects first — attacker or not — exhaust the one
    /// shared bucket and lock the whole validator set out. Measured on the live node: all inbound
    /// connections loopback, none outbound.
    #[test]
    fn loopback_sources_are_not_capped_because_they_are_a_proxy_not_a_peer() {
        let mut limiter = IpConnLimiter::new(2);
        let local = dummy_local_addr();

        // Well past the cap of 2 — a proxied validator set reaches this routinely.
        for id in 1..=10 {
            assert!(
                limiter
                    .handle_pending_inbound_connection(
                        ConnectionId::new_unchecked(id),
                        &local,
                        &addr("127.0.0.1")
                    )
                    .is_ok(),
                "connection {id} from the local proxy must not be refused"
            );
        }
    }

    #[test]
    fn ipv6_loopback_is_exempt_too() {
        let mut limiter = IpConnLimiter::new(1);
        let local = dummy_local_addr();
        let v6: Multiaddr = "/ip6/::1/tcp/9000".parse().unwrap();

        limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(1), &local, &v6).unwrap();
        assert!(limiter
            .handle_pending_inbound_connection(ConnectionId::new_unchecked(2), &local, &v6)
            .is_ok());
    }

    /// The control for the exemption above: a node with a directly reachable listener sees real
    /// peer addresses, and there the cap is the Sybil defence it was built to be. An exemption that
    /// quietly widened to every address would remove that with no test noticing.
    #[test]
    fn a_routable_address_is_still_capped() {
        let mut limiter = IpConnLimiter::new(2);
        let local = dummy_local_addr();

        limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(1), &local, &addr("203.0.113.7")).unwrap();
        limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(2), &local, &addr("203.0.113.7")).unwrap();

        assert!(
            limiter
                .handle_pending_inbound_connection(
                    ConnectionId::new_unchecked(3),
                    &local,
                    &addr("203.0.113.7")
                )
                .is_err(),
            "a real remote address must still be capped — this is the Sybil defence itself"
        );
    }

    /// A private LAN address is a peer's own, not a proxy's: two validators on one network must
    /// stay independently accounted. Guards against "exempt anything that is not public".
    #[test]
    fn a_private_lan_address_is_still_capped() {
        let mut limiter = IpConnLimiter::new(1);
        let local = dummy_local_addr();

        limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(1), &local, &addr("192.168.1.50")).unwrap();
        assert!(limiter
            .handle_pending_inbound_connection(ConnectionId::new_unchecked(2), &local, &addr("192.168.1.50"))
            .is_err());
    }

    #[test]
    fn releasing_a_connection_frees_up_the_slot() {
        let mut limiter = IpConnLimiter::new(1);
        let local = dummy_local_addr();

        limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(1), &local, &addr("1.2.3.4")).unwrap();
        assert!(limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(2), &local, &addr("1.2.3.4")).is_err());

        limiter.release(ConnectionId::new_unchecked(1));

        assert!(limiter.handle_pending_inbound_connection(ConnectionId::new_unchecked(2), &local, &addr("1.2.3.4")).is_ok());
    }
}
