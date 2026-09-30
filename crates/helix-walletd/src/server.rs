//! HTTP in front of the methods: Basic authentication as Bitcoin Core does it (a configured user
//! and password, and a cookie file written at start), single calls and batches.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use base64::Engine;
use serde_json::value::RawValue;
use subtle::ConstantTimeEq;

use crate::daemon::Daemon;
use crate::methods;
use crate::rpc::{code, envelope, status_of, Params, Request, RpcError};

/// The `user:password` pairs accepted.
pub struct Auth {
    accepted: Vec<Vec<u8>>,
}

impl Auth {
    pub fn new(pairs: Vec<String>) -> Self {
        Auth { accepted: pairs.into_iter().map(String::into_bytes).collect() }
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
        bool::from(ok)
    }
}

#[derive(Clone)]
struct AppState {
    daemon: Arc<Daemon>,
    auth: Arc<Auth>,
    started: Instant,
}

pub fn router(daemon: Arc<Daemon>, auth: Auth) -> Router {
    let state = AppState { daemon, auth: Arc::new(auth), started: Instant::now() };
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

async fn handle(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let authorization = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if !state.auth.allows(authorization) {
        return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")], "").into_response();
    }
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

    fn basic(pair: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair))
    }

    #[test]
    fn only_an_accepted_pair_gets_in() {
        let auth = Auth::new(vec!["exchange:s3cret".into(), "__cookie__:abc".into()]);
        assert!(auth.allows(Some(&basic("exchange:s3cret"))));
        assert!(auth.allows(Some(&basic("__cookie__:abc"))));
        for refused in ["exchange:s3cre", "exchange:s3cret ", "Exchange:s3cret", "", ":"] {
            assert!(!auth.allows(Some(&basic(refused))), "{refused:?} must not get in");
        }
        assert!(!auth.allows(None));
        assert!(!auth.allows(Some("Bearer exchange:s3cret")));
        assert!(!auth.allows(Some("Basic not-base64!")));
    }
}
