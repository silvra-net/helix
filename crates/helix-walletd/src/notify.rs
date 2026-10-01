//! `walletnotify` and `blocknotify`, as Bitcoin Core runs them: a command, through the shell, for
//! every change to a wallet transaction and for every new block — the way most exchanges learn of a
//! deposit without polling.
//!
//! - `walletnotify`: `%s` is the transaction id, `%b` the block hash (`unconfirmed` before one holds
//!   it), `%h` its height (`-1` before), `%w` the wallet name (`''`, the default wallet). It runs
//!   when the wallet signs and submits a transaction, when a block holds one of its transactions
//!   (a deposit, a send, a sweep), and when it gives one up because its nonce went to another.
//! - `blocknotify`: `%s` is the block hash. It runs when the wallet's view of the chain moves on —
//!   once per round, with the newest block, so catching up a thousand blocks does not start a
//!   thousand commands (Bitcoin Core does not run it during its initial download either).
//!
//! Commands run in the background and never hold the wallet up; at most [`AT_ONCE`] run at a time,
//! the rest wait their turn. A command that fails is logged, not retried — the exchange's own
//! polling (`listsinceblock`) is what catches up, as with Bitcoin Core.

use std::sync::Arc;

use tokio::sync::Semaphore;

/// Commands running at once at most.
pub const AT_ONCE: usize = 16;

pub struct Notifier {
    wallet: Option<String>,
    block: Option<String>,
    permits: Arc<Semaphore>,
}

/// What may be put into a shell command: hex, and the `-` of a reward's pseudo-id. Anything else
/// is not substituted — the node is the exchange's own, but a command line is not where trust is
/// spent.
fn safe(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The `walletnotify` command for a transaction, `None` if there is none or the id is not safe.
pub fn wallet_command(template: &str, txid: &str, block: Option<(&str, u64)>) -> Option<String> {
    if !safe(txid) || block.is_some_and(|(hash, _)| !safe(hash)) {
        return None;
    }
    let (hash, height) = match block {
        Some((hash, height)) => (hash.to_string(), height.to_string()),
        None => ("unconfirmed".to_string(), "-1".to_string()),
    };
    Some(template.replace("%s", txid).replace("%b", &hash).replace("%h", &height).replace("%w", "''"))
}

/// The `blocknotify` command for a block.
pub fn block_command(template: &str, hash: &str) -> Option<String> {
    safe(hash).then(|| template.replace("%s", hash))
}

impl Notifier {
    pub fn new(wallet: Option<String>, block: Option<String>) -> Notifier {
        Notifier { wallet, block, permits: Arc::new(Semaphore::new(AT_ONCE)) }
    }

    pub fn wallet_tx(&self, txid: &str, block: Option<(&str, u64)>) {
        if let Some(template) = &self.wallet {
            match wallet_command(template, txid, block) {
                Some(command) => self.run("walletnotify", command),
                None => tracing::warn!(%txid, "walletnotify not run: the id holds characters a command line must not get"),
            }
        }
    }

    pub fn block(&self, hash: &str) {
        if let Some(template) = &self.block {
            match block_command(template, hash) {
                Some(command) => self.run("blocknotify", command),
                None => tracing::warn!(%hash, "blocknotify not run: the hash holds characters a command line must not get"),
            }
        }
    }

    fn run(&self, what: &'static str, command: String) {
        let permits = self.permits.clone();
        tokio::spawn(async move {
            let Ok(_permit) = permits.acquire_owned().await else { return };
            let shown = command.clone();
            let outcome = tokio::task::spawn_blocking(move || shell(&command).status()).await;
            match outcome {
                Ok(Ok(status)) if status.success() => tracing::debug!(what, command = %shown, "ran"),
                Ok(Ok(status)) => tracing::warn!(what, command = %shown, %status, "the command failed"),
                Ok(Err(e)) => tracing::warn!(what, command = %shown, err = %e, "the command could not be started"),
                Err(e) => tracing::warn!(what, command = %shown, err = %e, "the command's task broke off"),
            }
        });
    }
}

fn shell(command: &str) -> std::process::Command {
    #[cfg(windows)]
    {
        let mut c = std::process::Command::new("cmd");
        c.arg("/C").arg(command);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = std::process::Command::new("sh");
        c.arg("-c").arg(command);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_placeholders_are_bitcoin_cores() {
        let t = "notify %s %b %h %w";
        assert_eq!(wallet_command(t, "ab12", Some(("cd34", 7))).unwrap(), "notify ab12 cd34 7 ''");
        assert_eq!(wallet_command(t, "ab12", None).unwrap(), "notify ab12 unconfirmed -1 ''");
        assert_eq!(wallet_command(t, "reward-cd34", Some(("cd34", 7))).unwrap(), "notify reward-cd34 cd34 7 ''");
        assert_eq!(block_command("curl x/%s", "cd34").unwrap(), "curl x/cd34");
    }

    #[test]
    fn nothing_but_an_id_reaches_the_shell() {
        for bad in ["ab;rm -rf /", "$(id)", "a b", "", "ab`x`"] {
            assert!(wallet_command("n %s", bad, None).is_none(), "{bad:?}");
            assert!(block_command("n %s", bad).is_none(), "{bad:?}");
        }
        assert!(wallet_command("n %s", "ab12", Some(("x|y", 1))).is_none(), "the block hash too");
    }

    /// The command really runs, with the id in it — the end that matters to an exchange.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn the_command_runs_with_the_ids_filled_in() {
        let dir = std::env::temp_dir().join(format!("helix-notify-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("seen");
        let n = Notifier::new(
            Some(format!("echo wallet %s %b %h >> {}", out.display())),
            Some(format!("echo block %s >> {}", out.display())),
        );
        n.wallet_tx("aa11", Some(("bb22", 5)));
        n.wallet_tx("cc33", None);
        n.block("bb22");
        let mut lines = Vec::new();
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            lines = std::fs::read_to_string(&out).unwrap_or_default().lines().map(str::to_string).collect();
            if lines.len() == 3 {
                break;
            }
        }
        lines.sort();
        assert_eq!(lines, vec!["block bb22", "wallet aa11 bb22 5", "wallet cc33 unconfirmed -1"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
