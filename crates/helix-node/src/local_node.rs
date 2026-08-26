//! Choosing which node the client subcommands talk to (Masterplan Stufe 2).
//!
//! Every `helix wallet`, `helix tx` and `helix chain` invocation used to go to
//! `https://node.silvra.net` unless the operator knew to set `--node` or `HELIX_NODE`. So the
//! people most likely to be running their own node — validators — were still having every balance
//! and every transaction answered by our server, and the whole point of running one was lost to a
//! default. Bitcoin Core has no such setting: `bitcoin-cli` talks to your node, and that is the
//! behaviour this restores.
//!
//! Precedence: what the operator explicitly asked for, then a node on this machine, then the public
//! network. The last step is what keeps a freshly downloaded binary working with no configuration
//! at all, which is the property the old default existed to provide.

use serde::Deserialize;
use std::time::Duration;

/// The public network, used when nothing else answers.
pub const PUBLIC_NODE: &str = "https://node.silvra.net";

/// How long to wait for a local node to answer before deciding there isn't one.
///
/// Generous for loopback (a healthy node answers `/status` in single-digit milliseconds) and short
/// enough that someone without a node pays no noticeable price for the probe. It is not a health
/// check: a local node too busy to answer in half a second is a local node that would make every
/// command crawl, and falling through to the public endpoint is the better answer for the person
/// typing the command.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Which node a command ended up talking to, and why — so the answer can say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chosen {
    /// The operator named it. Nothing is probed and nothing is announced.
    Explicit(String),
    /// A node answering on this machine.
    Local(String),
    /// No local node answered.
    Public(String),
}

impl Chosen {
    pub fn url(&self) -> &str {
        match self {
            Chosen::Explicit(u) | Chosen::Local(u) | Chosen::Public(u) => u,
        }
    }
}

/// The subset of `/status` this needs. Deliberately not the full response type: a client that
/// refuses to talk to its own node because the node grew a field would be worse than no feature.
#[derive(Debug, Deserialize)]
pub struct LocalStatus {
    pub height: u64,
    #[serde(default)]
    pub is_syncing: bool,
    #[serde(default)]
    pub sync_target_height: Option<u64>,
}

/// Decide without doing any I/O, so the precedence is testable on its own.
///
/// `local` is `Some(url)` when a node on this machine answered. The explicit setting wins even when
/// a local node is running: someone who names an endpoint has answered this question already, and
/// silently overriding them would be the same mistake in the other direction.
pub fn choose(explicit: Option<&str>, local: Option<&str>) -> Chosen {
    if let Some(url) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return Chosen::Explicit(url.trim_end_matches('/').to_string());
    }
    match local {
        Some(url) => Chosen::Local(url.trim_end_matches('/').to_string()),
        None => Chosen::Public(PUBLIC_NODE.to_string()),
    }
}

/// One line describing a local node's state, or `None` when there is nothing worth saying.
///
/// A node still catching up is the case that matters: its answers are real but old, and a wallet
/// that showed a stale balance without a word would be lying by omission. This is the progress
/// report the plan asks for in place of a blackout.
pub fn local_note(status: &LocalStatus) -> Option<String> {
    if !status.is_syncing {
        return None;
    }
    Some(match status.sync_target_height {
        Some(target) if target > status.height => format!(
            "Your node is still catching up — {} of {} blocks ({:.1}%). Balances may be out of date.",
            status.height,
            target,
            (status.height as f64 / target as f64) * 100.0,
        ),
        _ => format!(
            "Your node is still catching up (at block {}). Balances may be out of date.",
            status.height
        ),
    })
}

/// Ask a node on this machine whether it is there.
pub async fn probe(url: &str) -> Option<LocalStatus> {
    let client = reqwest::Client::builder().timeout(PROBE_TIMEOUT).build().ok()?;
    let resp = client.get(format!("{url}/status")).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<LocalStatus>().await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_endpoint_wins_even_when_a_local_node_is_running() {
        let c = choose(Some("http://example:8545"), Some("http://127.0.0.1:8545"));
        assert_eq!(c, Chosen::Explicit("http://example:8545".into()));
    }

    /// The change this whole module exists for: a validator running its own node was still asking
    /// our server for its own balance, because using its own required knowing about a flag.
    #[test]
    fn a_local_node_is_preferred_over_the_public_network() {
        let c = choose(None, Some("http://127.0.0.1:8545"));
        assert_eq!(c, Chosen::Local("http://127.0.0.1:8545".into()));
    }

    /// The property the old default existed to provide, and which must survive: a freshly
    /// downloaded binary works against the live chain with no configuration at all.
    #[test]
    fn without_a_local_node_the_public_network_is_still_the_default() {
        assert_eq!(choose(None, None), Chosen::Public(PUBLIC_NODE.into()));
    }

    /// An empty environment variable is unset, not an endpoint. `HELIX_NODE=` in a shell profile
    /// would otherwise send every command to the empty string.
    #[test]
    fn a_blank_explicit_setting_is_treated_as_unset() {
        assert_eq!(choose(Some("   "), None), Chosen::Public(PUBLIC_NODE.into()));
        assert_eq!(choose(Some(""), Some("http://127.0.0.1:8545")), Chosen::Local("http://127.0.0.1:8545".into()));
    }

    #[test]
    fn trailing_slashes_are_trimmed_so_paths_do_not_double_up() {
        assert_eq!(choose(Some("http://x:8545/"), None).url(), "http://x:8545");
        assert_eq!(choose(None, Some("http://127.0.0.1:8545/")).url(), "http://127.0.0.1:8545");
    }

    #[test]
    fn a_synced_node_says_nothing() {
        let s = LocalStatus { height: 100, is_syncing: false, sync_target_height: Some(100) };
        assert_eq!(local_note(&s), None);
    }

    /// Stale answers must be labelled. A wallet that showed a balance from 5000 blocks ago without
    /// a word would be lying by omission — that is the blackout the plan set out to remove.
    #[test]
    fn a_catching_up_node_reports_its_progress() {
        let s = LocalStatus { height: 500, is_syncing: true, sync_target_height: Some(1000) };
        let note = local_note(&s).expect("a syncing node has something to say");
        assert!(note.contains("500"), "{note}");
        assert!(note.contains("1000"), "{note}");
        assert!(note.contains("50.0%"), "{note}");
    }

    /// A node that is syncing but cannot say how far still has to say that much, rather than
    /// falling silent and looking synced.
    #[test]
    fn a_catching_up_node_without_a_target_still_says_so() {
        let s = LocalStatus { height: 500, is_syncing: true, sync_target_height: None };
        assert!(local_note(&s).expect("still worth saying").contains("catching up"));
    }
}
