pub mod chain;
pub mod contract;
pub mod governance;
pub mod identity;
pub mod name;
pub mod recovery;
pub mod tx;
pub mod validator;
pub mod wallet;

use anyhow::{Context, Result};

/// Fetch an account's next nonce from a node.
///
/// A *reachable* node that has never seen the account legitimately answers with no `nonce`
/// field — that is a genuine zero and we return it. But a node we cannot reach, or a reply we
/// cannot parse, must surface as an error: signing with a silent nonce 0 makes the executor
/// reject the transaction with a nonce complaint that points at the account instead of the dead
/// connection. This used to live as six identical private copies whose callers all did
/// `.await.unwrap_or(0)`, collapsing exactly that distinction (#122).
pub(crate) async fn fetch_nonce(node: &str, address: &str) -> Result<u64> {
    let res: serde_json::Value = reqwest::get(format!("{}/accounts/{}", node, address))
        .await
        .with_context(|| format!("could not reach node at {} to read the account nonce", node))?
        .json()
        .await
        .context("node returned a response that was not valid account JSON")?;
    Ok(res["nonce"].as_u64().unwrap_or(0))
}
