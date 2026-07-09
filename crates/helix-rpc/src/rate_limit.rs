//! Per-IP token-bucket rate limiting for the public REST API.
//!
//! The node's RPC port is reachable at a fixed public URL (Cloudflare Tunnel
//! to `localhost:8545`), so it needs basic flood protection before testnet
//! launch. This is deliberately a simple in-process limiter rather than a
//! new dependency — good enough to blunt a single misbehaving client without
//! adding attack surface of its own.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Above this many tracked IPs, stale buckets are swept on the next request
/// so a burst of distinct source IPs can't grow the map without bound.
const MAX_TRACKED_IPS: usize = 10_000;
const STALE_AFTER_SECS: u64 = 600;

pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl RateLimiter {
    /// `capacity` is the burst size (tokens available up front); `refill_per_sec`
    /// is the sustained requests/sec each IP settles to once its burst is spent.
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        RateLimiter {
            capacity,
            refill_per_sec,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the request should proceed, `false` if `ip` is over budget.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();

        if buckets.len() > MAX_TRACKED_IPS {
            buckets.retain(|_, (_, last)| now.duration_since(*last).as_secs() < STALE_AFTER_SECS);
        }

        let entry = buckets.entry(ip).or_insert((self.capacity, now));
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.0 = (entry.0 + elapsed * self.refill_per_sec).min(self.capacity);
        entry.1 = now;

        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Resolves the real client IP for rate-limiting purposes. Behind the
/// Cloudflare Tunnel every connection arrives from `cloudflared` on
/// localhost, so the TCP peer address alone would bucket every visitor
/// together — Cloudflare's `CF-Connecting-IP` header (falling back to the
/// more generic `X-Forwarded-For`) carries the original client IP instead.
///
/// Both headers are attacker-controlled on any connection that didn't
/// actually come through the local tunnel (e.g. `HELIX_RPC_BIND=0.0.0.0:8545`
/// deployments reachable directly), so they're only trusted when the raw
/// socket peer is loopback — otherwise a client could send a fresh spoofed
/// value on every request and bypass the limiter entirely. In that case the
/// real socket address is used, which is exactly what the limiter needs.
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    if !peer.ip().is_loopback() {
        return peer.ip();
    }
    if let Some(ip) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
    {
        return ip;
    }
    if let Some(ip) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse().ok())
    {
        return ip;
    }
    peer.ip()
}

pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = client_ip(req.headers(), peer);
    if limiter.check(ip) {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(json!({ "error": "rate limit exceeded, slow down" })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn allows_requests_within_burst_capacity() {
        let limiter = RateLimiter::new(3.0, 1.0);
        let addr = ip(1);
        assert!(limiter.check(addr));
        assert!(limiter.check(addr));
        assert!(limiter.check(addr));
        assert!(!limiter.check(addr), "4th request within the same instant should exceed burst");
    }

    #[test]
    fn tracks_ips_independently() {
        let limiter = RateLimiter::new(1.0, 1.0);
        assert!(limiter.check(ip(1)));
        assert!(!limiter.check(ip(1)));
        // A different IP has its own untouched bucket.
        assert!(limiter.check(ip(2)));
    }

    #[test]
    fn refills_over_time() {
        // Low enough refill rate that back-to-back calls don't spuriously
        // refill a whole token, but a 5ms sleep clearly does.
        let limiter = RateLimiter::new(1.0, 200.0);
        let addr = ip(1);
        assert!(limiter.check(addr));
        assert!(!limiter.check(addr));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(limiter.check(addr), "bucket should have refilled after waiting");
    }

    #[test]
    fn prefers_cf_connecting_ip_over_socket_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(client_ip(&headers, peer), "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn falls_back_to_x_forwarded_for_first_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(client_ip(&headers, peer), "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn falls_back_to_socket_peer_without_headers() {
        let headers = HeaderMap::new();
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(client_ip(&headers, peer), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ignores_forwarded_headers_from_non_loopback_peer() {
        // A direct (non-tunneled) connection can set any header value it likes,
        // so it must not be trusted — otherwise a spoofed header would bypass
        // the limiter on every request.
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
        let peer: SocketAddr = "198.51.100.4:9000".parse().unwrap();
        assert_eq!(client_ip(&headers, peer), "198.51.100.4".parse::<IpAddr>().unwrap());
    }
}
