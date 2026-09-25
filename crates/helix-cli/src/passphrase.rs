//! Every way the CLI gets a passphrase: typed without echo, read from a file, or asked for when a
//! wallet has to be opened. One module so there is one implementation of each — the history of
//! `rpassword_read` below is what several private copies cost.

use std::path::{Path, PathBuf};

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

/// A new passphrase from a file (`--passphrase-file` where a wallet is created or encrypted). An
/// empty file is refused: a secret that failed to mount must not quietly produce an unencrypted
/// wallet.
pub(crate) fn read_passphrase_file(path: &Path) -> Result<String> {
    let passphrase = passphrase_file_contents(path)?;
    if passphrase.is_empty() {
        bail!(
            "The passphrase file {} is empty, so no passphrase was set and nothing was written.",
            path.display()
        );
    }
    Ok(passphrase)
}

/// A passphrase file exactly as written, minus one trailing line ending — which `echo secret >
/// file` adds and nobody means — and nothing else (#223: spaces are the passphrase's own). What
/// an empty file means is the caller's to say.
fn passphrase_file_contents(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("could not read the passphrase file {}", path.display()))?;
    let passphrase = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .unwrap_or(&raw)
        .to_string();
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

/// The wallet that signs, and how to open it — the two options every command that signs a
/// transaction takes (`#[command(flatten)]`). One type, so a command cannot get the key without
/// the way to open it in a script.
#[derive(clap::Args, Debug, Clone)]
pub struct Signer {
    /// Wallet key file that signs this transaction
    #[arg(short, long, default_value = "wallet.json")]
    pub key: PathBuf,
    /// Read the wallet's passphrase from this file instead of asking — for scripts. One trailing
    /// newline is dropped, nothing else. Works with `<(pass show …)` and mounted secrets
    #[arg(long, value_name = "PATH")]
    pub passphrase_file: Option<PathBuf>,
}

impl Signer {
    /// Load the wallet and open it: from the passphrase file when one was given, otherwise by
    /// asking on the terminal — and only if it is encrypted at all.
    pub(crate) fn unlock(&self) -> Result<(KeyFile, KeyPair)> {
        let kf = KeyFile::load(&self.key)?;
        let kp = unlock_key(
            &kf,
            self.passphrase_file.as_deref(),
            "Wallet passphrase: ",
            &mut |p| ask_on_terminal(p),
        )?;
        Ok((kf, kp))
    }
}

/// Open a wallet: with the passphrase from `passphrase_file` if one was given, otherwise with what
/// `ask` returns for `prompt` — and without either when the wallet is not encrypted. `ask` is a
/// parameter so tests need no terminal.
///
/// Every command that signs used to carry the asking half as its own copy — fifteen of them, byte
/// for byte, plus two more in `wallet` — and none could be opened without a terminal, so a script
/// that signs had to keep its wallet in plaintext (#227).
///
/// A file given for a wallet without a passphrase is not read, and says so: nothing is lost by
/// signing, and a script handing every wallet the same file keeps working, but whoever believed
/// this wallet was encrypted should hear otherwise.
pub(crate) fn unlock_key(
    kf: &KeyFile,
    passphrase_file: Option<&Path>,
    prompt: &str,
    ask: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<KeyPair> {
    if !kf.is_encrypted() {
        if let Some(path) = passphrase_file {
            eprintln!(
                "  ⚠  This wallet has no passphrase, so {} was not read. Anyone who can read the \
                 wallet file can use it — `helix wallet encrypt` sets one.",
                path.display()
            );
        }
        return kf.to_keypair(None);
    }
    let Some(path) = passphrase_file else {
        let pass = ask(prompt)?;
        return kf.to_keypair(Some(&pass));
    };
    let pass = passphrase_file_contents(path)?;
    kf.to_keypair(Some(&pass)).map_err(|e| {
        // An empty file is most often a secret that never arrived — a mount that failed, a
        // variable that was unset when the file was written — and "wrong passphrase" would send
        // the reader looking for a typo. Not refused before trying: a wallet encrypted under the
        // empty passphrase (`wallet encrypt ""` did that until #221) opens with nothing else.
        if pass.is_empty() {
            anyhow::anyhow!(
                "The passphrase file {} is empty, and this wallet does not open without a \
                 passphrase. Nothing was signed. ({e})",
                path.display()
            )
        } else {
            anyhow::anyhow!(
                "The passphrase in {} does not open this wallet. Nothing was signed. ({e})",
                path.display()
            )
        }
    })
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

#[cfg(test)]
mod unlock_tests {
    use super::*;

    /// Answers every prompt with the same line, or fails like a missing terminal — and counts the
    /// prompts, so a test can say "never asked".
    struct Keyboard {
        answer: Option<&'static str>,
        asked: usize,
    }

    impl Keyboard {
        fn typing(answer: &'static str) -> Self {
            Keyboard {
                answer: Some(answer),
                asked: 0,
            }
        }

        fn absent() -> Self {
            Keyboard {
                answer: None,
                asked: 0,
            }
        }

        fn ask(&mut self, _prompt: &str) -> Result<String> {
            self.asked += 1;
            self.answer
                .map(str::to_string)
                .ok_or_else(|| anyhow::anyhow!("there is no terminal"))
        }
    }

    fn temp_file(contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "helix-unlock-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    fn wallet(passphrase: Option<&str>) -> (KeyFile, KeyPair) {
        let kp = KeyPair::generate();
        let kf = match passphrase {
            Some(p) => KeyFile::from_keypair_encrypted(&kp, p).unwrap(),
            None => KeyFile::from_keypair_plain(&kp),
        };
        (kf, kp)
    }

    fn unlock(kf: &KeyFile, file: Option<&Path>, keys: &mut Keyboard) -> Result<KeyPair> {
        unlock_key(kf, file, "Wallet passphrase: ", &mut |p| keys.ask(p))
    }

    /// The point of the option: a script opens an encrypted wallet and nothing waits for a
    /// terminal that is not there.
    #[test]
    fn a_script_opens_an_encrypted_wallet_from_a_file_without_being_asked() {
        let (kf, kp) = wallet(Some("correct horse"));
        let file = temp_file("correct horse\n");
        let mut keys = Keyboard::absent();
        let opened = unlock(&kf, Some(&file), &mut keys);
        std::fs::remove_file(&file).ok();
        assert_eq!(opened.unwrap().public, kp.public);
        assert_eq!(keys.asked, 0);
    }

    /// Spaces at the edges are the passphrase's own (#223), in a file as at the keyboard.
    #[test]
    fn a_passphrase_file_keeps_its_spaces() {
        let (kf, kp) = wallet(Some(" pw "));
        let file = temp_file(" pw \n");
        let opened = unlock(&kf, Some(&file), &mut Keyboard::absent());
        std::fs::remove_file(&file).ok();
        assert_eq!(opened.unwrap().public, kp.public);
    }

    /// Without a file nothing changes: the terminal is asked, once.
    #[test]
    fn without_a_file_the_terminal_is_asked_once() {
        let (kf, kp) = wallet(Some("pw"));
        let mut keys = Keyboard::typing("pw");
        assert_eq!(unlock(&kf, None, &mut keys).unwrap().public, kp.public);
        assert_eq!(keys.asked, 1);
    }

    /// A wrong passphrase in a file is not answered with a prompt either — a script has nobody
    /// to answer it — and the error names the file, which is what the reader has to fix.
    #[test]
    fn a_wrong_passphrase_in_the_file_names_the_file_and_asks_nobody() {
        let (kf, _) = wallet(Some("pw"));
        let file = temp_file("not it\n");
        let mut keys = Keyboard::typing("pw");
        let err = unlock(&kf, Some(&file), &mut keys)
            .err()
            .expect("must not open")
            .to_string();
        std::fs::remove_file(&file).ok();
        assert!(err.contains(&file.display().to_string()), "{err}");
        assert!(err.contains("does not open this wallet"), "{err}");
        assert!(err.contains("Nothing was signed"), "{err}");
        assert_eq!(keys.asked, 0);
    }

    /// An empty file is most often a secret that never arrived, and says so instead of "wrong
    /// passphrase".
    #[test]
    fn an_empty_file_says_it_is_empty() {
        let (kf, _) = wallet(Some("pw"));
        let file = temp_file("\n");
        let mut keys = Keyboard::typing("pw");
        let err = unlock(&kf, Some(&file), &mut keys)
            .err()
            .expect("must not open")
            .to_string();
        std::fs::remove_file(&file).ok();
        assert!(err.contains("is empty"), "{err}");
        assert_eq!(keys.asked, 0);
    }

    /// Why an empty file is not refused before trying: `wallet encrypt ""` encrypted under the
    /// empty passphrase until #221, and such a wallet opens with nothing else.
    #[test]
    fn a_wallet_encrypted_under_the_empty_passphrase_opens_from_an_empty_file() {
        let (kf, kp) = wallet(Some(""));
        let file = temp_file("");
        let opened = unlock(&kf, Some(&file), &mut Keyboard::absent());
        std::fs::remove_file(&file).ok();
        assert_eq!(opened.unwrap().public, kp.public);
    }

    /// A file named for a wallet without a passphrase is not read at all: the path below does not
    /// exist, and signing goes ahead.
    #[test]
    fn a_file_for_a_wallet_without_a_passphrase_is_not_read() {
        let (kf, kp) = wallet(None);
        let nowhere = std::env::temp_dir().join("helix-unlock-test-this-file-does-not-exist");
        let mut keys = Keyboard::absent();
        let opened = unlock(&kf, Some(&nowhere), &mut keys).unwrap();
        assert_eq!(opened.public, kp.public);
        assert_eq!(keys.asked, 0);
    }

    /// A file that cannot be read is an error, not a reason to fall back to asking.
    #[test]
    fn an_unreadable_file_is_an_error_and_not_a_prompt() {
        let (kf, _) = wallet(Some("pw"));
        let nowhere = std::env::temp_dir().join("helix-unlock-test-this-file-does-not-exist");
        let mut keys = Keyboard::typing("pw");
        let err = unlock(&kf, Some(&nowhere), &mut keys)
            .err()
            .expect("must not open")
            .to_string();
        assert!(err.contains("could not read the passphrase file"), "{err}");
        assert_eq!(keys.asked, 0);
    }
}

#[cfg(test)]
mod signer_arguments {
    use clap::{CommandFactory, Parser};

    use crate::commands::tx::TxCmd;
    use crate::Commands;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: Commands,
    }

    /// Every command that signs with a wallet can open it from a file — checked over the whole
    /// command tree rather than a list, so a command added later cannot take `--key` without it.
    ///
    /// `wallet` is left out on purpose: there `--passphrase-file` already means the *new*
    /// passphrase (`wallet new`, `wallet encrypt`), and opening an existing wallet stays a
    /// question at the terminal.
    #[test]
    fn every_command_that_signs_with_a_wallet_can_open_it_from_a_file() {
        fn walk(cmd: &clap::Command, path: String, found: &mut Vec<(String, bool)>) {
            let longs: Vec<&str> = cmd.get_arguments().filter_map(|a| a.get_long()).collect();
            if longs.contains(&"key") {
                found.push((path.clone(), longs.contains(&"passphrase-file")));
            }
            for sub in cmd.get_subcommands() {
                walk(sub, format!("{path} {}", sub.get_name()), found);
            }
        }
        let root = Cli::command();
        let mut found = Vec::new();
        for group in root.get_subcommands().filter(|c| c.get_name() != "wallet") {
            walk(group, group.get_name().to_string(), &mut found);
        }
        // Positive control: the walk reached the signing commands at all (18 when written).
        assert!(
            found.len() >= 18,
            "only {} commands with --key found: {found:?}",
            found.len()
        );
        let without: Vec<&String> = found
            .iter()
            .filter(|(_, has)| !has)
            .map(|(path, _)| path)
            .collect();
        assert!(
            without.is_empty(),
            "these take --key but not --passphrase-file: {without:?}"
        );
    }

    fn send(args: &[&str]) -> super::Signer {
        let mut argv = vec!["helix", "tx", "send", "hlx1recipient", "1"];
        argv.extend_from_slice(args);
        match Cli::try_parse_from(argv).unwrap().command {
            Commands::Tx {
                action: TxCmd::Send { signer, .. },
            } => signer,
            _ => unreachable!(),
        }
    }

    /// `-k`, `--key` and the default are what they were — every existing script keeps working.
    #[test]
    fn the_key_option_is_unchanged_and_the_file_is_optional() {
        let default = send(&[]);
        assert_eq!(default.key, std::path::PathBuf::from("wallet.json"));
        assert_eq!(default.passphrase_file, None);
        assert_eq!(
            send(&["-k", "a.json"]).key,
            std::path::PathBuf::from("a.json")
        );
        let both = send(&["--key", "b.json", "--passphrase-file", "secret"]);
        assert_eq!(both.key, std::path::PathBuf::from("b.json"));
        assert_eq!(
            both.passphrase_file,
            Some(std::path::PathBuf::from("secret"))
        );
    }
}
