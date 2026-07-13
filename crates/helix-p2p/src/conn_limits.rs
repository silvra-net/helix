//! Per-IP connection cap.
//!
//! `libp2p::connection_limits::Behaviour` bounds global/pending/per-peer connection
//! counts, but has no notion of the remote IP — a single attacker can still open
//! many connections as long as each one presents a fresh `PeerId` (trivial to
//! generate, they're just keypairs). This behaviour closes that gap by tracking
//! concurrent connections (pending + established, inbound only — we choose who we
//! dial, so outbound isn't an attacker-controlled vector) per source IP and denying
//! new ones past the configured limit.

use std::collections::HashMap;
use std::task::{Context, Poll};

use libp2p::core::Multiaddr;
use libp2p::identity::PeerId;
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};

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

pub struct IpConnLimiter {
    max_per_ip: u32,
    counts: HashMap<String, u32>,
    by_connection: HashMap<ConnectionId, String>,
}

impl IpConnLimiter {
    pub fn new(max_per_ip: u32) -> Self {
        IpConnLimiter {
            max_per_ip,
            counts: HashMap::new(),
            by_connection: HashMap::new(),
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

        let count = self.counts.get(&ip).copied().unwrap_or(0);
        if count >= self.max_per_ip {
            return Err(ConnectionDenied::new(IpLimitExceeded { limit: self.max_per_ip }));
        }

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
