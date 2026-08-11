pub mod chain;
pub mod contract;
pub mod governance;
pub mod identity;
pub mod name;
pub mod recovery;
pub mod tx;
pub mod validator;
pub mod wallet;

use anyhow::{anyhow, bail, Context, Result};
use helix_core::{ChainIdSource, Transaction};
use helix_crypto::Hash;
use reqwest::StatusCode;
use serde_json::Value;

// ---------------------------------------------------------------------------------------------
// Talking to a node
//
// Every HTTP reply the CLI reads goes through this section. It used to make seventeen requests
// and look at the HTTP status code twice — at the two places where ignoring it had already cost
// somebody an afternoon (the fee lookup, and `tx status`). The other fifteen discarded the status
// and read the body as though only a healthy node could have sent it.
//
// That holds exactly until something *other* than the node answers, which is the normal case in
// this deployment: production sits behind a Cloudflare tunnel, and axum's own body-limit layer
// answers 413 without ever reaching a handler. Then a `serde_json` parse failure stands in for
// "the node is unreachable", and — worse — a JSON error page that happens to carry no `error`
// field reads as a perfectly good reply.
// ---------------------------------------------------------------------------------------------

/// GET a document that may legitimately not exist.
///
/// `Ok(None)` means the node answered 404 — the account, name or proposal really is not there.
/// Every other non-success status is an error carrying the node's own explanation when it gave
/// one, and the bare status code when it did not.
pub(crate) async fn get_optional(node: &str, path: &str, what: &str) -> Result<Option<Value>> {
    let url = format!("{}{}", node, path);
    let response = reqwest::get(&url)
        .await
        .with_context(|| format!("could not reach the node at {} to {}", node, what))?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let parsed = serde_json::from_str::<Value>(&body).ok();

    if status.is_success() {
        return parsed
            .map(Some)
            .ok_or_else(|| not_the_chain_answering(node, what, status, &body));
    }
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    Err(refusal(node, what, status, parsed.as_ref(), &body))
}

/// GET a document whose absence is not a meaningful answer — chain status, governance
/// parameters, a validator's pool. A 404 here means the URL is not a Helix node, not that the
/// chain has no status.
pub(crate) async fn get_json(node: &str, path: &str, what: &str) -> Result<Value> {
    get_optional(node, path, what).await?.ok_or_else(|| {
        anyhow!(
            "the node at {} has no {} — it answered 404, which usually means this address is \
             not a Helix node (or is running a version without that endpoint)",
            node,
            what
        )
    })
}

/// Fetch an account's next nonce.
///
/// An account the chain has never seen answers **404**, and that is a genuine zero: a first
/// transaction from a fresh address is nonce 0. Anything else that goes wrong must surface as an
/// error, because signing with a silent zero makes the executor reject the transaction with a
/// nonce complaint pointing at the account instead of at the broken connection.
///
/// This has now been wrong twice in the same spot, in opposite directions. It began as six
/// identical private copies whose callers all did `.await.unwrap_or(0)`, collapsing the
/// distinction entirely (#122). Centralising it fixed the callers and left `unwrap_or(0)` in the
/// helper — so the doc comment claimed the distinction was restored while any JSON reply lacking
/// a `nonce` field, from any source, still became a zero. The comment even described the wrong
/// mechanism: it said an unknown account replies with a body carrying no `nonce`, when the server
/// replies 404 with an `error`. It reached the right answer by the wrong route, which is why
/// nobody noticed.
pub(crate) async fn fetch_nonce(node: &str, address: &str) -> Result<u64> {
    let account = get_optional(node, &format!("/accounts/{}", address), "read the account nonce")
        .await?;
    match account {
        // A known account always reports its nonce. A reply that claims to be an account but
        // cannot say which nonce it is on is not one, and defaulting it to zero is how a broken
        // connection turns into a transaction the chain rejects for the wrong reason.
        Some(acc) => acc["nonce"].as_u64().ok_or_else(|| {
            anyhow!(
                "the node at {} returned an account for {} with no nonce field",
                node,
                address
            )
        }),
        None => Ok(0),
    }
}

/// Which chain to sign for — the value that stops a transaction signed here from being spendable
/// on a different Helix chain (backlog #174, `Transaction::chain_id`).
///
/// **Where the answer comes from is the security property, not a detail.** Asking the endpoint you
/// are about to submit to hands it the power to decide what your signature authorises: point a user
/// at a "testnet" RPC, answer with mainnet's id, and the transaction they believed was worthless is
/// spendable. So the public endpoint is never asked — its id is compiled in. An endpoint the user
/// named, or their own node, may be asked, because choosing to trust it is a choice they already
/// made. `HELIX_CHAIN_ID` overrides both, which is what makes offline signing and a fresh devnet
/// possible without a release.
///
/// Cached for the process: a `tx send` makes one of these, and paying for a round trip per
/// transaction would be a regression nobody asked for.
pub(crate) async fn resolve_chain_id(node: &str) -> Result<Hash> {
    static CACHED: tokio::sync::OnceCell<Hash> = tokio::sync::OnceCell::const_new();
    CACHED
        .get_or_try_init(|| async {
            if let Some(explicit) = std::env::var("HELIX_CHAIN_ID")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                return Hash::from_hex(&explicit).map_err(|_| {
                    anyhow!(
                        "HELIX_CHAIN_ID is not a 32-byte hex hash: {explicit:?}. It is a chain's \
                         genesis hash — read one with: curl -s <node>/blocks/height/0"
                    )
                });
            }

            match helix_core::chain_id_source(node) {
                ChainIdSource::CompiledIn => Ok(helix_core::default_chain_id()),
                ChainIdSource::AskEndpoint => {
                    let genesis = get_json(node, "/blocks/height/0", "learn which chain it is on")
                        .await?;
                    let hex = genesis["hash"].as_str().ok_or_else(|| {
                        anyhow!("the node at {node} returned a genesis block with no hash field")
                    })?;
                    Hash::from_hex(hex).map_err(|_| {
                        anyhow!("the node at {node} reported a malformed genesis hash: {hex:?}")
                    })
                }
            }
        })
        .await
        .copied()
}

/// Submit a signed transaction. The one implementation for the whole CLI — import it, do not
/// write another.
///
/// This existed as eight copies across six files (`tx`, `governance`, `contract`, `name`,
/// `identity`, `recovery`). They agreed with each other, which is the trap: an invariant kept in
/// eight places is one nobody can fix once. See `rpassword_read` and `fetch_nonce` for the two
/// previous times this cost real money or real security in this same crate.
pub(crate) async fn submit_tx(tx: &Transaction, node: &str) -> Result<Value> {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/transactions", node))
        .json(tx)
        .send()
        .await
        .with_context(|| format!("could not reach the node at {} to submit the transaction", node))?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let parsed = serde_json::from_str::<Value>(&body).ok();

    if !status.is_success() {
        return Err(match parsed.as_ref().and_then(|v| v["error"].as_str()) {
            Some(reason) => anyhow!("Transaction rejected: {}", reason),
            None => not_the_chain_answering(node, "submit the transaction", status, &body),
        });
    }

    let res = parsed.ok_or_else(|| {
        not_the_chain_answering(node, "submit the transaction", status, &body)
    })?;

    // Kept even though the node uses 400 for refusals today: a 2xx carrying `error` is still a
    // refusal, and this is the check every one of the eight copies performed.
    if let Some(err) = res.get("error") {
        bail!("Transaction rejected: {}", err);
    }

    // Acceptance *is* the node handing back the hash it stored. A success status with no hash
    // did not come from a Helix node accepting a transaction, and printing "Status : ?" and
    // exiting 0 there sends the sender away believing a transaction is on its way that was never
    // submitted — the one failure this whole path must not have.
    if res["tx_hash"].as_str().is_none() {
        bail!(
            "the node at {} accepted the request but returned no transaction hash — the \
             transaction was NOT submitted. Check that this address is a Helix node.",
            node
        );
    }
    Ok(res)
}

/// The two lines every submitting command prints once the node has taken the transaction.
pub(crate) fn report_submitted(res: &Value) {
    // Both fields are guaranteed present by `submit_tx`; a missing one there is an error, not a
    // question mark on screen.
    println!("  Tx hash : {}", res["tx_hash"].as_str().unwrap_or("?"));
    println!("  Status  : {}", res["status"].as_str().unwrap_or("accepted"));
}

/// A node that answered, but with a refusal it explained.
fn refusal(
    node: &str,
    what: &str,
    status: StatusCode,
    parsed: Option<&Value>,
    body: &str,
) -> anyhow::Error {
    match parsed.and_then(|v| v["error"].as_str()) {
        Some(reason) => anyhow!("the node at {} refused to {}: {}", node, what, reason),
        None => not_the_chain_answering(node, what, status, body),
    }
}

/// Something answered on that address and it was not this chain: a proxy error page, a body
/// limit, a different service entirely. Say so, and show enough of the reply to recognise it —
/// a bare `serde_json` parse error sends the reader looking for a bug in the CLI.
fn not_the_chain_answering(
    node: &str,
    what: &str,
    status: StatusCode,
    body: &str,
) -> anyhow::Error {
    anyhow!(
        "the node at {} answered HTTP {} when asked to {}, and the reply was not a Helix \
         response{}",
        node,
        status.as_u16(),
        what,
        excerpt(body)
    )
}

fn excerpt(body: &str) -> String {
    let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.is_empty() {
        return String::new();
    }
    let shown: String = flat.chars().take(160).collect();
    let ellipsis = if flat.chars().count() > 160 { "…" } else { "" };
    format!(" — it began: {}{}", shown, ellipsis)
}

#[cfg(test)]
mod node_reply_tests {
    use super::*;
    use axum::{http::header, response::IntoResponse, Router};
    use helix_core::TxType;
    use helix_crypto::{Address, KeyPair, Signature};

    /// Answers every path with one canned reply, so these run through the same reqwest path
    /// production uses — status code, headers and body included. A hand-stubbed transport would
    /// prove nothing here: the status code *is* what is under test.
    async fn mock_node(code: StatusCode, content_type: &'static str, body: &'static str) -> String {
        let app = Router::new().fallback(move || async move {
            (code, [(header::CONTENT_TYPE, content_type)], body).into_response()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{}", addr)
    }

    /// A real signed transfer. What is under test is how the CLI reads the *reply*, but sending
    /// a well-formed transaction keeps these tests honest about which end failed.
    fn a_transaction() -> Transaction {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: addr.clone(),
            to: Some(addr),
            amount: 1_000_000,
            fee: 10_000,
            nonce: 0,
            data: vec![],
            crypto_version: kp.scheme,
            chain_id: helix_crypto::Hash::ZERO,
            signature: Signature::from_bytes(vec![]),
            public_key: kp.public.clone(),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).expect("sign");
        tx
    }

    // -------------------------------------------------------------------------------------
    // submit_tx
    // -------------------------------------------------------------------------------------

    /// The failure this whole path exists to prevent, and the only silent one: something that is
    /// not the chain answers 200 with JSON that carries no `error` field. Every one of the eight
    /// copies this replaced printed "Tx hash : ?" and returned success — telling the sender a
    /// transaction was on its way that had never been submitted.
    #[tokio::test]
    async fn a_success_without_a_transaction_hash_is_not_a_submitted_transaction() {
        let node = mock_node(StatusCode::OK, "application/json", r#"{"ok":true}"#).await;

        let err = submit_tx(&a_transaction(), &node)
            .await
            .expect_err("a reply with no transaction hash must not be reported as accepted")
            .to_string();

        assert!(err.contains("NOT submitted"), "must say the transaction did not go: {err}");
    }

    /// The node's own refusal must survive intact — it is the sender's only explanation, and it
    /// arrives with a 400 rather than in a 200 body.
    #[tokio::test]
    async fn a_refusal_is_reported_with_the_nodes_own_reason() {
        let node = mock_node(
            StatusCode::BAD_REQUEST,
            "application/json",
            r#"{"error":"sender cannot pay the declared fee"}"#,
        )
        .await;

        let err = submit_tx(&a_transaction(), &node).await.unwrap_err().to_string();

        assert!(err.contains("cannot pay the declared fee"), "got: {err}");
    }

    /// Production sits behind a Cloudflare tunnel, so this is the ordinary failure, not an exotic
    /// one. It used to surface as a `serde_json` parse error, which reads like a bug in the CLI
    /// and sends the operator looking in the wrong place.
    #[tokio::test]
    async fn a_gateway_error_page_names_the_status_rather_than_failing_to_parse() {
        let node = mock_node(
            StatusCode::BAD_GATEWAY,
            "text/html",
            "<html><title>502 Bad Gateway</title></html>",
        )
        .await;

        let err = submit_tx(&a_transaction(), &node).await.unwrap_err().to_string();

        assert!(err.contains("502"), "must name the status: {err}");
        assert!(err.contains("not a Helix response"), "must say who did not answer: {err}");
        assert!(!err.to_lowercase().contains("expected value"), "not a parse error: {err}");
    }

    /// The control. If refusing bad replies also refused good ones, every test above would pass
    /// against a CLI that can no longer submit anything at all.
    #[tokio::test]
    async fn an_accepted_transaction_still_goes_through() {
        let node = mock_node(
            StatusCode::ACCEPTED,
            "application/json",
            r#"{"tx_hash":"abcd","status":"accepted"}"#,
        )
        .await;

        let res = submit_tx(&a_transaction(), &node).await.expect("must accept a real reply");
        assert_eq!(res["tx_hash"].as_str(), Some("abcd"));
    }

    // -------------------------------------------------------------------------------------
    // fetch_nonce
    // -------------------------------------------------------------------------------------

    /// The control that decides the shape of this whole change: an address the chain has never
    /// seen answers **404**, and its next nonce is genuinely 0. Treating every non-success status
    /// as an error — the obvious way to write this — would break the first transaction from every
    /// new account, including the stake that admits a new validator.
    #[tokio::test]
    async fn an_account_the_chain_has_never_seen_is_a_genuine_zero() {
        let node = mock_node(
            StatusCode::NOT_FOUND,
            "application/json",
            r#"{"error":"account hlx… not found"}"#,
        )
        .await;

        assert_eq!(fetch_nonce(&node, "hlxwhoever").await.unwrap(), 0);
    }

    /// And the reason that control is not the whole story. This reply is just as devoid of a
    /// `nonce` field as the 404 above, and `unwrap_or(0)` could not tell them apart — so a broken
    /// gateway produced a transaction signed with nonce 0, which the executor then rejected with
    /// a complaint about the account. #122 removed that default from the six callers and left it
    /// in the helper.
    #[tokio::test]
    async fn a_broken_gateway_is_not_mistaken_for_a_fresh_account() {
        let node = mock_node(StatusCode::BAD_GATEWAY, "application/json", r#"{"errors":[]}"#).await;

        let err = fetch_nonce(&node, "hlxwhoever").await.unwrap_err().to_string();
        assert!(err.contains("502"), "got: {err}");
    }

    #[tokio::test]
    async fn a_known_account_reports_its_own_nonce() {
        let node = mock_node(StatusCode::OK, "application/json", r#"{"nonce":7}"#).await;
        assert_eq!(fetch_nonce(&node, "hlxwhoever").await.unwrap(), 7);
    }

    /// An account body that cannot say which nonce it is on is not an account. Defaulting it to
    /// zero is the same silent failure by another route.
    #[tokio::test]
    async fn an_account_reply_without_a_nonce_is_an_error_not_a_zero() {
        let node = mock_node(StatusCode::OK, "application/json", r#"{"balance_hlx":5}"#).await;
        assert!(fetch_nonce(&node, "hlxwhoever").await.is_err());
    }

    // -------------------------------------------------------------------------------------
    // get_json / get_optional
    // -------------------------------------------------------------------------------------

    /// A chain always has a status. A 404 for one means this address is not a Helix node, and
    /// saying so beats printing a table of question marks.
    #[tokio::test]
    async fn a_missing_endpoint_is_reported_rather_than_shown_as_empty_fields() {
        let node = mock_node(StatusCode::NOT_FOUND, "application/json", r#"{}"#).await;

        let err = get_json(&node, "/status", "node status").await.unwrap_err().to_string();
        assert!(err.contains("not a Helix node"), "got: {err}");
    }

    #[tokio::test]
    async fn a_document_that_is_simply_absent_is_reported_as_absent_not_as_a_failure() {
        let node = mock_node(StatusCode::NOT_FOUND, "application/json", r#"{}"#).await;
        assert!(get_optional(&node, "/names/nobody", "resolve").await.unwrap().is_none());
    }

    /// A reachable socket that is not a node at all — someone's web server on the same port.
    #[tokio::test]
    async fn a_success_that_is_not_json_is_refused_rather_than_read_as_data() {
        let node = mock_node(StatusCode::OK, "text/html", "<html>hello</html>").await;

        let err = get_json(&node, "/status", "node status").await.unwrap_err().to_string();
        assert!(err.contains("not a Helix response"), "got: {err}");
    }
}
