//! Every way the CLI gets a passphrase: typed without echo, read from a file, or asked for when a
//! wallet has to be opened. One module so there is one implementation of each — the history of
//! `rpassword_read` below is what several private copies cost.

use anyhow::{bail, Context, Result};
use helix_crypto::KeyPair;

use crate::keyfile::KeyFile;

/// Read a passphrase without echoing it. The one implementation for the whole CLI — import it,
/// do not write another.
///
/// Named `rpassword_read` and taking a `_prompt` it ignored, this used to be a plain
/// `stdin().read_line` — so every wallet passphrase was typed in clear text and left sitting in
/// the terminal's scrollback. The name described the intent; nothing implemented it.
///
/// Fixing it here fixed one of six call sites. `identity`, `name`, `recovery`, `contract` and
/// `governance` each carried their own byte-identical copy of the broken version, so five
/// commands went on echoing the passphrase — and, because the ignored `_prompt` was never
/// printed, gave no sign they were waiting for one. Found on 2026-07-22 while walking the
/// governance path end to end. Hence `pub(crate)` and this note: a private duplicate cannot be
/// fixed once and stay fixed. (It did not stay fixed: `wallet encrypt` carried a sixth copy under
/// another name, `rpassword_prompt`, until 2026-09-23 — a grep for this name could not find it.)
pub(crate) fn rpassword_read(prompt: &str) -> Result<String> {
    Ok(as_typed(rpassword::prompt_password(prompt)?))
}

/// The passphrase exactly as typed, minus only a line ending.
///
/// This used to `trim()`, which also stripped spaces at either end — spaces the person typed on
/// purpose. Nothing else trims: `wallet new --passphrase`, the desktop wallet and the node's
/// `HELIX_VALIDATOR_KEY_PASSPHRASE` all take it byte for byte. So a passphrase with a space at
/// its edge — one pasted from a password manager is enough — opened in the desktop wallet and
/// never here, with "wrong passphrase?" as the only explanation. rpassword stops reading at the
/// Enter key and does not return it; the line ending is stripped anyway, in case a future
/// version or another input path does.
fn as_typed(line: String) -> String {
    line.trim_end_matches(['\r', '\n']).to_string()
}

/// A passphrase from a file: exactly its contents, minus one trailing line ending — which
/// `echo secret > file` adds and nobody means — and nothing else (#223: spaces are the
/// passphrase's own). An empty file is refused: a secret that failed to mount must not quietly
/// produce an unencrypted wallet.
pub(crate) fn read_passphrase_file(path: &std::path::Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("could not read the passphrase file {}", path.display()))?;
    let passphrase = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .unwrap_or(&raw)
        .to_string();
    if passphrase.is_empty() {
        bail!(
            "The passphrase file {} is empty, so no passphrase was set and nothing was written.",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.is_file() && meta.permissions().mode() & 0o077 != 0 {
                eprintln!(
                    "  ⚠  {} can be read by other users on this machine — `chmod 600` it.",
                    path.display()
                );
            }
        }
    }
    Ok(passphrase)
}

/// Ask for a new passphrase on the terminal. Without one — a script, a pipe, `< /dev/null` —
/// rpassword cannot open `/dev/tty` and says only "No such device or address (os error 6)"; for a
/// new passphrase there is a way round that, so the error names it.
pub(crate) fn ask_on_terminal(prompt: &str) -> Result<String> {
    rpassword_read(prompt).map_err(|e| {
        anyhow::anyhow!(
            "Could not ask for a passphrase: there is no terminal to type it into ({e}). In a \
             script, use --passphrase-file <path>."
        )
    })
}

/// Open a wallet for signing: ask for its passphrase on the terminal when it has one.
///
/// Every command that signs used to carry this as its own copy — fifteen of them, byte for byte,
/// plus two more in `wallet` — so a change to how a wallet is opened meant finding all seventeen.
pub(crate) fn unlock_key(kf: &KeyFile, prompt: &str) -> Result<KeyPair> {
    let pass = if kf.is_encrypted() {
        Some(rpassword_read(prompt)?)
    } else {
        None
    };
    kf.to_keypair(pass.as_deref())
}

#[cfg(test)]
mod as_typed_tests {
    use super::*;

    #[test]
    fn a_passphrase_keeps_the_spaces_that_were_typed() {
        assert_eq!(as_typed("correct horse ".into()), "correct horse ");
        assert_eq!(as_typed(" leading".into()), " leading");
        assert_eq!(as_typed("pw\r\n".into()), "pw");
        assert_eq!(as_typed("pw\n".into()), "pw");
    }
}
