//! HTTP in front of the methods: Basic authentication as Bitcoin Core does it (a configured user
//! and password, `rpcauth` hashes, and a cookie file written at start), `rpcallowip`, single calls
//! and batches.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use base64::Engine;
use serde_json::value::RawValue;
use subtle::ConstantTimeEq;

use crate::conf::{allowed, RpcAuth};
use crate::daemon::Daemon;
use crate::methods;
use crate::rpc::{code, envelope, status_of, Params, Request, RpcError};

/// Who may call: `user:password` pairs (the cookie, `rpcuser`/`rpcpassword`) and `rpcauth` users.
pub struct Auth {
    accepted: Vec<Vec<u8>>,
    rpcauth: Vec<RpcAuth>,
}

impl Auth {
    pub fn new(pairs: Vec<String>, rpcauth: Vec<RpcAuth>) -> Self {
        Auth { accepted: pairs.into_iter().map(String::into_bytes).collect(), rpcauth }
    }

    /// Whether this `Authorization` header carries an accepted pair. Compared in constant time
    /// against every pair, so the answer's timing says nothing about how close a guess was.
    pub fn allows(&self, header: Option<&str>) -> bool {
        let Some(encoded) = header.and_then(|h| h.strip_prefix("Basic ")) else { return false };
        let Ok(given) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else { return false };
        let mut ok = subtle::Choice::from(0u8);
        for pair in &self.accepted {
            if pair.len() == given.len() {
                ok |= pair.as_slice().ct_eq(&given);
            }
        }
        if let Some((user, password)) = std::str::from_utf8(&given).ok().and_then(|g| g.split_once(':')) {
            for auth in &self.rpcauth {
                let same_user = auth.user.len() == user.len() && bool::from(auth.user.as_bytes().ct_eq(user.as_bytes()));
                if same_user && auth.accepts(password) {
                    ok |= subtle::Choice::from(1u8);
                }
            }
        }
        bool::from(ok)
    }
}

/// A wrong password waits this long for its answer, as in Bitcoin Core: it costs someone guessing
/// time and someone with the right password nothing.
pub const FAILED_AUTH_DELAY: Duration = Duration::from_millis(250);

/// Wrong passwords waited on at once at most. Bitcoin Core's four RPC threads are what really
/// bound its guess rate — four answers per 250 ms, sixteen a second, however many connections a
/// guesser opens — and this is that bound: without it the delay only slows each connection.
pub const FAILED_AUTH_AT_ONCE: usize = 4;

/// The largest request read, once it is known to come from an allowed client with the right
/// password — before that, none is read at all.
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;

/// One log line per interval for what any client can make happen as often as it likes — a
/// refused address, a wrong password — saying how many it stands for. A line per request lets
/// whoever reaches the port fill the disk, and a full disk stops the node (#245).
struct LogGate {
    interval: Duration,
    state: std::sync::Mutex<(Option<Instant>, u64)>,
}

impl LogGate {
    fn new(interval: Duration) -> Self {
        LogGate { interval, state: std::sync::Mutex::new((None, 0)) }
    }

    /// Count one; `Some(n)` when a line is due now, for the `n` since the last one.
    fn admit(&self) -> Option<u64> {
        let mut state = self.state.lock().expect("log gate");
        state.1 += 1;
        let now = Instant::now();
        if state.0.is_some_and(|last| now.duration_since(last) < self.interval) {
            return None;
        }
        let count = state.1;
        *state = (Some(now), 0);
        Some(count)
    }
}

#[derive(Clone)]
struct AppState {
    daemon: Arc<Daemon>,
    auth: Arc<Auth>,
    allow: Arc<Vec<ipnet::IpNet>>,
    started: Instant,
    failed_auth: Arc<tokio::sync::Semaphore>,
    refused_log: Arc<LogGate>,
    failed_log: Arc<LogGate>,
}

/// The service. Serve it with `into_make_service_with_connect_info::<SocketAddr>()`: who connects
/// decides whether they may (`rpcallowip`) before any password is looked at.
pub fn router(daemon: Arc<Daemon>, auth: Auth, allow: Vec<ipnet::IpNet>) -> Router {
    let state = AppState {
        daemon,
        auth: Arc::new(auth),
        allow: Arc::new(allow),
        started: Instant::now(),
        failed_auth: Arc::new(tokio::sync::Semaphore::new(FAILED_AUTH_AT_ONCE)),
        refused_log: Arc::new(LogGate::new(Duration::from_secs(60))),
        failed_log: Arc::new(LogGate::new(Duration::from_secs(60))),
    };
    // Bitcoin Core answers on `/` and `/wallet/<name>`; clients use either.
    Router::new().fallback(handle).with_state(state)
}

fn json_response(status: u16, body: String) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn one(state: &AppState, raw: &RawValue) -> (u16, String) {
    let request: Request = match serde_json::from_str(raw.get()) {
        Ok(r) => r,
        Err(e) => {
            let err = Err(RpcError::new(code::INVALID_REQUEST, format!("invalid request: {e}")));
            return (status_of(&err), envelope(None, &err));
        }
    };
    let answer = match Params::parse(request.params) {
        Ok(params) => methods::call(&state.daemon, &request.method, &params, state.started).await,
        Err(e) => Err(e),
    };
    if let Err(e) = &answer {
        tracing::debug!(method = %request.method, code = e.code, message = %e.message, "call refused");
    }
    (status_of(&answer), envelope(request.id, &answer))
}

async fn handle(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    // As Bitcoin Core: an address not allowed gets 403 and nothing else, whatever it sends — its
    // request is not even read.
    if !allowed(peer.ip(), &state.allow) {
        if let Some(count) = state.refused_log.admit() {
            tracing::warn!(%peer, count, "refused clients rpcallowip does not name (this one and the others since the last line)");
        }
        return StatusCode::FORBIDDEN.into_response();
    }
    let authorization = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if !state.auth.allows(authorization) {
        {
            let _turn = state.failed_auth.acquire().await.expect("the semaphore is never closed");
            tokio::time::sleep(FAILED_AUTH_DELAY).await;
        }
        if let Some(count) = state.failed_log.admit() {
            tracing::warn!(%peer, count, "incorrect password attempts (this one and the others since the last line)");
        }
        return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")], "").into_response();
    }
    let body: Bytes = match axum::body::to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let text = match std::str::from_utf8(&body) {
        Ok(t) => t.trim(),
        Err(_) => {
            let err = Err(RpcError::new(code::PARSE_ERROR, "Parse error"));
            return json_response(status_of(&err), envelope(None, &err));
        }
    };
    if text.starts_with('[') {
        let calls: Vec<&RawValue> = match serde_json::from_str(text) {
            Ok(c) => c,
            Err(_) => {
                let err = Err(RpcError::new(code::PARSE_ERROR, "Parse error"));
                return json_response(400, envelope(None, &err));
            }
        };
        let mut answers = Vec::with_capacity(calls.len());
        for raw in calls {
            answers.push(one(&state, raw).await.1);
        }
        return json_response(200, format!("[{}]", answers.join(",")));
    }
    match serde_json::from_str::<&RawValue>(text) {
        Ok(raw) => {
            let (status, body) = one(&state, raw).await;
            json_response(status, body)
        }
        Err(_) => {
            let err = Err(RpcError::new(code::PARSE_ERROR, "Parse error"));
            json_response(status_of(&err), envelope(None, &err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    fn basic(pair: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair))
    }

    const CHAIN: &str = "abababababababababababababababababababababababababababababababab";

    /// The service over a wallet whose node has a genesis block and nothing else, accepting
    /// `exchange:right` from this machine only.
    async fn service() -> (Router, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("helix-walletd-server-{}", rand::random::<u64>()));
        crate::keys::Keys::create(&dir, "test", CHAIN, 0, None).unwrap();
        let genesis = serde_json::json!({ "hash": CHAIN, "height": 0, "timestamp": 0, "prev_hash": "00".repeat(32) });
        let node = Router::new().route(
            "/blocks/height/:h/header",
            axum::routing::get(move || {
                let genesis = genesis.clone();
                async move { axum::Json(genesis) }
            }),
        );
        let daemon = Daemon::open(&dir, crate::node::Node::in_process(node), Default::default()).await.unwrap();
        (router(Arc::new(daemon), Auth::new(vec!["exchange:right".into()], Vec::new()), Vec::new()), dir)
    }

    fn call(from: [u8; 4], pair: &str, body: Vec<u8>) -> axum::http::Request<axum::body::Body> {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/")
            .header(header::AUTHORIZATION, basic(pair))
            .body(axum::body::Body::from(body))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::from((from, 40_000))));
        request
    }

    fn getblockcount() -> Vec<u8> {
        br#"{"method":"getblockcount","params":[],"id":1}"#.to_vec()
    }

    /// Bitcoin Core's bound on guessing a password: a wrong one is answered after 250 ms, four at
    /// a time — twenty take five rounds, however many connections they come on — while the right
    /// password, sent in the middle of them, is answered at once. Measured on tokio's clock, so it
    /// is exact and does not depend on how busy the machine is.
    #[tokio::test(start_paused = true)]
    async fn wrong_passwords_wait_four_at_a_time_and_the_right_one_does_not() {
        let (app, dir) = service().await;
        let started = tokio::time::Instant::now();
        let wrong: Vec<_> = (0..20)
            .map(|_| {
                let request = call([127, 0, 0, 1], "exchange:guess", getblockcount());
                let app = app.clone();
                tokio::spawn(async move { app.oneshot(request).await.unwrap().status() })
            })
            .collect();
        tokio::task::yield_now().await;
        let right = app.clone().oneshot(call([127, 0, 0, 1], "exchange:right", getblockcount())).await.unwrap();
        assert_eq!(right.status(), StatusCode::OK);
        assert!(started.elapsed() < FAILED_AUTH_DELAY, "the right password waited behind wrong ones: {:?}", started.elapsed());
        for answer in wrong {
            assert_eq!(answer.await.unwrap(), StatusCode::UNAUTHORIZED);
        }
        let rounds = 20 / FAILED_AUTH_AT_ONCE as u32;
        assert!(
            started.elapsed() >= FAILED_AUTH_DELAY * rounds,
            "twenty wrong passwords answered in {:?}: more than {FAILED_AUTH_AT_ONCE} at a time, or without waiting",
            started.elapsed()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A request from an address `rpcallowip` does not name, or without the right password, is
    /// answered without being read: three megabytes from either get 403 and 401, not the
    /// "payload too large" that reading them first would give — and no memory for them.
    #[tokio::test(start_paused = true)]
    async fn nothing_is_read_from_a_client_that_may_not_call() {
        let (app, dir) = service().await;
        let large = vec![b' '; 3 * 1024 * 1024];
        let refused = app.clone().oneshot(call([10, 0, 0, 9], "exchange:right", large.clone())).await.unwrap();
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let wrong = app.clone().oneshot(call([127, 0, 0, 1], "exchange:guess", large.clone())).await.unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let right = app.clone().oneshot(call([127, 0, 0, 1], "exchange:right", large)).await.unwrap();
        assert_eq!(right.status(), StatusCode::PAYLOAD_TOO_LARGE, "positive control: the limit holds for a caller who may call");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A flood of refusals is one log line a minute that says how many it stands for, not a line
    /// each — a line each lets whoever reaches the port fill the disk.
    #[test]
    fn a_flood_of_refusals_is_one_line_per_interval_with_its_count() {
        let gate = LogGate::new(Duration::from_millis(50));
        assert_eq!(gate.admit(), Some(1), "the first is logged at once");
        for _ in 0..999 {
            assert_eq!(gate.admit(), None);
        }
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(gate.admit(), Some(1000), "the next line counts every one since the last");
    }

    #[test]
    fn only_an_accepted_pair_gets_in() {
        let auth = Auth::new(vec!["exchange:s3cret".into(), "__cookie__:abc".into()], Vec::new());
        assert!(auth.allows(Some(&basic("exchange:s3cret"))));
        assert!(auth.allows(Some(&basic("__cookie__:abc"))));
        for refused in ["exchange:s3cre", "exchange:s3cret ", "Exchange:s3cret", "", ":"] {
            assert!(!auth.allows(Some(&basic(refused))), "{refused:?} must not get in");
        }
        assert!(!auth.allows(None));
        assert!(!auth.allows(Some("Bearer exchange:s3cret")));
        assert!(!auth.allows(Some("Basic not-base64!")));
    }

    /// An `rpcauth` line from Bitcoin Core's own test admits its user with that password, and
    /// nobody else with it.
    #[test]
    fn an_rpcauth_user_gets_in_with_the_password_and_only_then() {
        let rt = RpcAuth::parse("rt:93648e835a54c573682c2eb19f882535$7681e9c5b74bdd85e78166031d2058e1069b3ed7ed967c93fc63abba06f31144").unwrap();
        let auth = Auth::new(vec!["__cookie__:abc".into()], vec![rt]);
        assert!(auth.allows(Some(&basic("rt:cA773lm788buwYe4g4WT+05pKyNruVKjQ25x3n0DQcM="))));
        assert!(auth.allows(Some(&basic("__cookie__:abc"))), "the cookie still works");
        for refused in ["rt:wrong", "rt2:cA773lm788buwYe4g4WT+05pKyNruVKjQ25x3n0DQcM=", "rt:", "rt"] {
            assert!(!auth.allows(Some(&basic(refused))), "{refused:?} must not get in");
        }
    }
}
