//! What a remote address does and does not tell us about who is on the other end.
//!
//! One fact about the deployment, needed by two unrelated mechanisms — the per-IP connection cap
//! and peer reputation — which is exactly why it lives here rather than in either of them. It was
//! briefly written out twice, on the reasoning that reputation should not have to depend on
//! `conn_limits`; that reasoning was right and the conclusion was not. A third module both of them
//! can use keeps them independent *and* keeps the definition in one place, which matters because
//! the two copies would drift the moment this stops meaning "loopback" (see below).

/// Whether this address belongs to a local reverse proxy rather than to the peer behind it.
///
/// Measured on the production node 2026-08-05: every inbound P2P connection arrives from
/// `127.0.0.1`, because peers reach it through a Cloudflare tunnel that terminates locally, and a
/// plain TCP/WS tunnel carries no PROXY protocol. The address is the proxy's; it says nothing about
/// which peer sent the connection, and every peer shares it.
///
/// Two mechanisms have to know this, for the same underlying reason and with the same consequence
/// — that anything keyed on the address is keyed on *all peers at once*:
///
/// - the per-IP connection cap, or one peer's connections exhaust the bucket for the whole
///   validator set (backlog #148);
/// - the IP ban that accompanies a peer ban, or five infractions from one peer lock every honest
///   validator out (backlog #148 again).
///
/// **When this definition changes, both change with it.** If PROXY protocol is ever added and real
/// client addresses become visible, this should stop returning `true` for loopback — and both call
/// sites must start limiting and banning by address again on the same day, not one of them.
pub fn is_shared_proxy_address(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => addr.is_loopback(),
        // Not an address we can key anything on. Treated as "not a proxy" so the caller applies
        // its normal rules rather than silently exempting something unrecognised.
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_shared_proxy_address;

    #[test]
    fn loopback_is_a_shared_proxy_address() {
        assert!(is_shared_proxy_address("127.0.0.1"));
        assert!(is_shared_proxy_address("127.0.0.53"));
        assert!(is_shared_proxy_address("::1"));
    }

    /// The control for both call sites at once: on a node with a directly reachable listener the
    /// address really is the peer's, and the cap and the ban are the defences they were built to
    /// be. An exemption creeping outwards to "anything not public" would disable both silently.
    #[test]
    fn a_routable_address_is_the_peers_own() {
        assert!(!is_shared_proxy_address("203.0.113.7"));
        assert!(!is_shared_proxy_address("2001:db8::1"));
    }

    /// A private LAN address belongs to the peer too — two validators on one network must stay
    /// separately accounted.
    #[test]
    fn a_private_lan_address_is_the_peers_own() {
        assert!(!is_shared_proxy_address("192.168.1.50"));
        assert!(!is_shared_proxy_address("10.0.0.4"));
    }

    #[test]
    fn something_that_is_not_an_address_is_not_exempt() {
        assert!(!is_shared_proxy_address(""));
        assert!(!is_shared_proxy_address("not-an-ip"));
    }
}
