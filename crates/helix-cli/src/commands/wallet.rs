use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use bip39::Mnemonic;
use clap::Subcommand;
use helix_crypto::{Address, CryptoScheme, KeyPair};

use crate::keyfile::KeyFile;
use crate::passphrase::{ask_on_terminal, read_passphrase_file, unlock_key};

/// Where a new wallet's passphrase comes from — never from the command line itself.
///
/// It used to be `--passphrase <value>`: typed into the shell, which saves it in the history file
/// next to the very wallet it protects, and shows it for as long as the command runs in the
/// process list every local user can read (`/proc/<pid>/cmdline`). Now `--passphrase` is a switch
/// that asks for it twice without echo, and scripts read it from a file.
///
/// **A file, not an environment variable,** for the scriptable path: only the path appears in the
/// command line and the history; a file is what Docker and Kubernetes secrets and systemd's
/// `LoadCredential=` already hand a process; and `--passphrase-file <(pass show helix)` works
/// without the secret ever touching a disk. A variable is inherited by every child process, sits
/// in `/proc/<pid>/environ`, and `VAR=secret helix …` puts it straight back into the history.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct NewPassphrase {
    /// Encrypt the key (AES-256-GCM + Argon2id) with a passphrase you are asked for twice,
    /// without echo. Takes no value — a passphrase typed here would be saved in your shell history
    #[arg(long, num_args = 0..=1, value_name = "NO VALUE")]
    passphrase: Option<Option<String>>,
    /// Read the passphrase from this file instead of asking — for scripts. One trailing newline
    /// is dropped, nothing else. Works with `<(pass show …)` and mounted secrets
    #[arg(long, value_name = "PATH", conflicts_with = "passphrase")]
    passphrase_file: Option<PathBuf>,
}

/// What refusing `--passphrase <value>` says. The passphrase has already been typed by the time
/// this runs, so the message is about that, not about syntax.
const PASSPHRASE_ON_COMMAND_LINE: &str = "A passphrase given on the command line is not used: it \
     is now in your shell history, and was visible in the process list while this ran. Nothing was \
     written. Treat that passphrase as exposed and choose a different one — use `--passphrase` \
     on its own to be asked for it, or `--passphrase-file <path>` in scripts. (In bash, \
     `history -d <number>` removes the line.)";

/// The new passphrase `source` asks for, or `None` for a plaintext wallet (neither option given).
/// `ask` shows a prompt and reads an answer without echo; a parameter so tests need no terminal.
fn resolve_new_passphrase(
    source: &NewPassphrase,
    ask: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<Option<String>> {
    match (&source.passphrase, &source.passphrase_file) {
        (Some(Some(_)), _) => bail!(PASSPHRASE_ON_COMMAND_LINE),
        (Some(None), _) => Ok(Some(ask_new_passphrase_twice(ask)?)),
        (None, Some(path)) => Ok(Some(read_passphrase_file(path)?)),
        (None, None) => Ok(None),
    }
}

/// Ask twice and require both to match. A typo in a passphrase typed without echo is otherwise
/// found the first time the wallet is opened — and a wallet nobody can open is lost unless its 24
/// words were written down (a SPHINCS+ wallet has none). An empty answer is refused rather than
/// read as "no passphrase": whoever asked for encryption and pressed Enter mistyped.
fn ask_new_passphrase_twice(ask: &mut dyn FnMut(&str) -> Result<String>) -> Result<String> {
    let first = ask("New passphrase: ")?;
    if first.is_empty() {
        bail!(
            "An empty passphrase protects nothing, so none was set and nothing was written. For a \
             wallet without a passphrase, leave out --passphrase."
        );
    }
    let second = ask("Repeat the passphrase: ")?;
    if first != second {
        bail!("The two passphrases differ, so nothing was written. Run the command again.");
    }
    Ok(first)
}

/// `wallet encrypt` used to take the new passphrase as its argument. Refuse it, and say why —
/// or, for the old empty argument, what replaced it.
fn refuse_encrypt_argument(passphrase_on_command_line: Option<&str>) -> Result<()> {
    match passphrase_on_command_line {
        Some("") => bail!("To remove the passphrase, use `helix wallet encrypt --remove`."),
        Some(_) => bail!(PASSPHRASE_ON_COMMAND_LINE),
        None => Ok(()),
    }
}

/// What `wallet encrypt` should do: `Some(passphrase)` to encrypt, `None` to remove encryption.
fn resolve_encrypt_target(
    passphrase_file: Option<&std::path::Path>,
    remove: bool,
    ask: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<Option<String>> {
    if remove {
        return Ok(None);
    }
    match passphrase_file {
        Some(path) => Ok(Some(read_passphrase_file(path)?)),
        None => Ok(Some(ask_new_passphrase_twice(ask)?)),
    }
}

/// Write `kp` encrypted under `passphrase`, or in plaintext when there is none — and an empty
/// passphrase is none. Encrypting under "" gave a file that reports `aes256gcm-argon2id` and
/// opens for anyone who presses Enter, while `wallet encrypt`'s own help promised that empty
/// removes encryption. The desktop wallet has always read empty as plaintext (its `encode`);
/// the four commands here used to decide separately, and now decide the same way.
fn encode(kp: &KeyPair, passphrase: Option<&str>) -> Result<KeyFile> {
    match passphrase {
        Some(pass) if !pass.is_empty() => {
            println!("Encrypting with AES-256-GCM + Argon2id...");
            KeyFile::from_keypair_encrypted(kp, pass)
        }
        _ => Ok(KeyFile::from_keypair_plain(kp)),
    }
}

/// A fresh 32-byte ML-DSA seed (FIPS 204's ξ) from the OS CSPRNG. Its own function so the one
/// place the entropy behind a wallet comes from is obvious and auditable.
fn random_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

/// Read the recovery phrase from the terminal.
///
/// Deliberately echoed, unlike a passphrase: these are 24 words being copied off paper, and
/// typing them blind makes a typo near-certain and impossible to spot — BIP39's checksum catches
/// it, but only tells you *that* it's wrong, never which word. The risk this prompt exists to
/// avoid is the phrase landing in shell history via `--mnemonic`, and it does that either way.
fn prompt_recovery_phrase() -> Result<String> {
    use std::io::Write;
    print!("Recovery phrase (24 words, separated by spaces): ");
    std::io::stdout().flush()?;
    let mut phrase = String::new();
    std::io::stdin().read_line(&mut phrase).context("could not read the recovery phrase")?;
    Ok(phrase)
}

/// Show the recovery phrase, once, at wallet creation.
///
/// It is printed rather than written anywhere: a file holding these words would just be a second
/// copy of the key with none of the protection the wallet file has, and writing it is the user's
/// decision — onto paper, not a disk that can fail with the wallet on it. There is deliberately
/// no command to print it again later; the wallet file does not store the words, only the seed,
/// and re-deriving them on demand would turn every read of that file into a key disclosure.
fn print_recovery_phrase(mnemonic: &Mnemonic) {
    let words: Vec<&'static str> = mnemonic.words().collect();
    println!();
    println!("  ┌─ Recovery phrase — write it down now, on paper ─────────────────────┐");
    for (row, chunk) in words.chunks(4).enumerate() {
        let line: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(col, w)| format!("{:>2}. {:<12}", row * 4 + col + 1, w))
            .collect();
        println!("  │  {} │", line.join(""));
    }
    println!("  └─────────────────────────────────────────────────────────────────────┘");
    println!();
    println!("  These 24 words ARE the wallet. Anyone who reads them owns it, and this is the");
    println!("  only time they are shown — the wallet file stores the key, not the words.");
    println!("  With them you can rebuild this exact address on any machine, from nothing:");
    println!("      helix wallet restore");
    println!("  Without them, losing the wallet file loses the wallet. Paper survives disks.");
}

#[derive(Subcommand)]
pub enum WalletCmd {
    /// Generate a new keypair (ML-DSA by default)
    New {
        #[arg(short, long, default_value = "wallet.json")]
        output: PathBuf,
        #[command(flatten)]
        passphrase: NewPassphrase,
        /// Signature scheme: "ml-dsa" (default) or "sphincs-plus" — pick the
        /// latter to migrate a wallet to the hash-based PQC scheme
        #[arg(long, default_value = "ml-dsa")]
        scheme: String,
    },
    /// Rebuild a wallet from the 24-word recovery phrase shown when it was created — the
    /// backup that survives the machine it was made on
    Restore {
        /// The 24 words, quoted. Omit to be prompted instead, which keeps them out of your
        /// shell history.
        #[arg(long)]
        mnemonic: Option<String>,
        #[arg(short, long, default_value = "wallet.json")]
        output: PathBuf,
        #[command(flatten)]
        passphrase: NewPassphrase,
    },
    /// Show address and public key for a wallet file
    Info {
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
    },
    /// Print address only (for scripting)
    Address {
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Unlock the key and print the address it derives, instead of the one stored beside
        /// it. Without this the address comes from the file's plaintext fields — checked
        /// against each other, but a forger who replaces both together is only caught on
        /// unlock. Use it before handing an address out for a large payment.
        #[arg(long)]
        verify: bool,
    },
    /// Add or change a wallet's passphrase — asked for twice, without echo — or remove it
    Encrypt {
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Read the new passphrase from this file instead of asking (for scripts; see
        /// `wallet new --help`)
        #[arg(long, value_name = "PATH", conflicts_with = "remove")]
        passphrase_file: Option<PathBuf>,
        /// Remove the passphrase: store the key in plaintext
        #[arg(long)]
        remove: bool,
        /// Refused. This used to be the new passphrase, typed on the command line, which puts it
        /// in your shell history. Kept only to say so instead of a bare parse error.
        #[arg(hide = true)]
        passphrase_on_command_line: Option<String>,
    },
    /// Import a node's raw validator key file (e.g. validator-key.bin) into a
    /// normal CLI wallet file, so `wallet info`/`tx send`/etc. can use it directly.
    /// Node key files use a different on-disk format than CLI wallets (raw
    /// [scheme-tag][secret][public] bytes, or legacy untagged ML-DSA) — this bridges
    /// the two without hand-rolled conversion code.
    ImportNodeKey {
        /// Path to the raw node key file (e.g. validator-key.bin)
        #[arg(short, long)]
        from: PathBuf,
        /// Output wallet file
        #[arg(short, long, default_value = "wallet.json")]
        output: PathBuf,
        #[command(flatten)]
        passphrase: NewPassphrase,
    },
}

pub async fn run(cmd: WalletCmd) -> Result<()> {
    match cmd {
        WalletCmd::New { output, passphrase, scheme } => {
            let scheme = match scheme.as_str() {
                "ml-dsa" => CryptoScheme::MlDsa,
                "sphincs-plus" => CryptoScheme::SphincsPlus,
                other => bail!("Unknown scheme '{}' — expected 'ml-dsa' or 'sphincs-plus'", other),
            };
            // Asked before the key exists, so a mismatch or a refusal leaves nothing behind.
            let passphrase = resolve_new_passphrase(&passphrase, &mut |p| ask_on_terminal(p))?;
            println!("Generating {:?} keypair...", scheme);
            // ML-DSA keys are generated from a seed we draw ourselves rather than by
            // `generate_for`, which keeps its randomness internal. The seed is the whole key
            // under FIPS 204, so holding it is what lets us also hand back the 24 words that
            // reproduce this wallet from nothing (see `print_recovery_phrase`). SPHINCS+ has no
            // equivalent re-derivable seed, so it keeps the old path and gets no words.
            let (kp, mnemonic) = match scheme {
                CryptoScheme::MlDsa => {
                    let seed = random_seed();
                    let mnemonic = Mnemonic::from_entropy(&seed)
                        .context("32 bytes is a valid BIP39 entropy length")?;
                    (KeyPair::from_mldsa_seed(&seed)?, Some(mnemonic))
                }
                CryptoScheme::SphincsPlus => (KeyPair::generate_for(scheme), None),
            };

            let kf = encode(&kp, passphrase.as_deref())?;

            kf.save(&output)?;
            println!();
            println!("  Address    : {}", kf.address);
            println!("  Public key : {}...", &kf.public_key[..32]);
            println!("  Algorithm  : {}", kf.algo);
            println!("  Encryption : {}", kf.encryption);
            println!("  Saved to   : {}", output.display());
            println!();
            if !kf.is_encrypted() {
                println!("  ⚠  No passphrase — key stored in plaintext. Use --passphrase for security.");
            } else {
                println!("  ✓  Key encrypted. Don't forget your passphrase — it cannot be recovered.");
            }

            if let Some(mnemonic) = mnemonic {
                print_recovery_phrase(&mnemonic);
            } else {
                println!();
                println!("  ⚠  SPHINCS+ wallets have no recovery phrase — this key exists only in");
                println!("     {}. Back up that file; losing it loses the wallet.", output.display());
            }
        }

        WalletCmd::Restore { mnemonic, output, passphrase } => {
            // Before the 24 words: a refused `--passphrase <value>` should not cost anyone a
            // second round of typing them.
            let passphrase = resolve_new_passphrase(&passphrase, &mut |p| ask_on_terminal(p))?;
            let phrase = match mnemonic {
                Some(words) => words,
                None => prompt_recovery_phrase()?,
            };
            let mnemonic = Mnemonic::parse_normalized(phrase.trim()).map_err(|e| {
                anyhow::anyhow!(
                    "That is not a valid recovery phrase ({e}). It must be the 24 words shown \
                     when the wallet was created, in order, spelled exactly."
                )
            })?;
            let seed = mnemonic.to_entropy();
            let kp = KeyPair::from_mldsa_seed(&seed)?;

            let kf = encode(&kp, passphrase.as_deref())?;
            kf.save(&output)?;

            println!("Wallet restored from its recovery phrase.");
            println!("  Address    : {}", kf.address);
            println!("  Saved to   : {}", output.display());
            println!();
            println!("  If that address isn't the one you expect, the phrase belongs to a");
            println!("  different wallet — nothing was lost, but nothing was recovered either.");
        }

        WalletCmd::Info { key } => {
            let kf = KeyFile::load(&key)?;
            println!("Wallet: {}", key.display());
            println!("  Address    : {}", kf.address);
            println!("  Algorithm  : {}", kf.algo);
            println!("  Encryption : {}", kf.encryption);
            println!("  Public key : {}...", &kf.public_key[..32]);
        }

        WalletCmd::Address { key, verify } => {
            let kf = KeyFile::load(&key)?;
            if verify {
                let kp = unlock_key(&kf, "Wallet passphrase: ")?;
                println!("{}", Address::from_public_key(&kp.public));
            } else {
                println!("{}", kf.address);
            }
        }

        WalletCmd::ImportNodeKey { from, output, passphrase } => {
            let passphrase = resolve_new_passphrase(&passphrase, &mut |p| ask_on_terminal(p))?;
            let data = std::fs::read(&from)
                .map_err(|e| anyhow::anyhow!("Could not read {}: {}", from.display(), e))?;

            // Gleiche Erkennung wie helix-node::load_or_create_keypair: legacy Format
            // (kein Tag-Byte, immer ML-DSA) vs. neues getaggtes Format.
            let legacy_len = CryptoScheme::MlDsa.secret_key_len() + CryptoScheme::MlDsa.public_key_len();
            let (scheme, sk_bytes, pk_bytes) = if data.len() == legacy_len {
                let sk_len = CryptoScheme::MlDsa.secret_key_len();
                (CryptoScheme::MlDsa, data[..sk_len].to_vec(), data[sk_len..].to_vec())
            } else {
                if data.is_empty() {
                    bail!("Node key file is empty");
                }
                let scheme = CryptoScheme::from_tag(data[0])
                    .map_err(|e| anyhow::anyhow!("Node key file: {}", e))?;
                let sk_len = scheme.secret_key_len();
                let pk_len = scheme.public_key_len();
                if data.len() != 1 + sk_len + pk_len {
                    bail!(
                        "Node key file has unexpected size ({} bytes, expected {})",
                        data.len(), 1 + sk_len + pk_len
                    );
                }
                (scheme, data[1..1 + sk_len].to_vec(), data[1 + sk_len..].to_vec())
            };

            let kp = KeyPair::from_raw(scheme, sk_bytes, pk_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid key in {}: {}", from.display(), e))?;

            let kf = encode(&kp, passphrase.as_deref())?;

            kf.save(&output)?;
            println!();
            println!("  Imported from : {}", from.display());
            println!("  Address       : {}", kf.address);
            println!("  Algorithm     : {}", kf.algo);
            println!("  Encryption    : {}", kf.encryption);
            println!("  Saved to      : {}", output.display());
            println!();
            println!("  Use it like any other wallet, e.g.: hlx tx send <to> <amount> --key {}", output.display());
        }

        WalletCmd::Encrypt {
            key,
            passphrase_file,
            remove,
            passphrase_on_command_line,
        } => {
            // A refused command line fails before anything is asked.
            refuse_encrypt_argument(passphrase_on_command_line.as_deref())?;
            let kf = KeyFile::load(&key)?;
            // The current passphrase first, so a wrong one fails before a new one is typed twice.
            let kp = unlock_key(&kf, "Current passphrase: ")?;
            let new_passphrase =
                resolve_encrypt_target(passphrase_file.as_deref(), remove, &mut |p| {
                    ask_on_terminal(p)
                })?;
            let new_kf = encode(&kp, new_passphrase.as_deref())?;
            // `replace`, not `save`: this is the one command that means to overwrite a key
            // file, and it rewrites the only copy — so in one step, never truncate-then-write.
            new_kf.replace(&key)?;
            if new_kf.is_encrypted() {
                let verb = if kf.is_encrypted() { "re-encrypted" } else { "encrypted" };
                println!("✓ Wallet {verb} at {}", key.display());
            } else {
                println!(
                    "✓ Encryption removed — {} now holds the key in plaintext",
                    key.display()
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::Address;

    /// The whole point of the phrase: 24 words on paper rebuild the exact same wallet, with no
    /// file involved. If this breaks, every backup taken until now is worthless.
    #[test]
    fn a_recovery_phrase_rebuilds_the_identical_wallet() {
        let seed = random_seed();
        let original = KeyPair::from_mldsa_seed(&seed).unwrap();
        let mnemonic = Mnemonic::from_entropy(&seed).unwrap();
        assert_eq!(mnemonic.words().count(), 24);

        // What `wallet restore` does with what the user typed.
        let reparsed = Mnemonic::parse_normalized(&mnemonic.to_string()).unwrap();
        let restored = KeyPair::from_mldsa_seed(&reparsed.to_entropy()).unwrap();

        assert_eq!(
            Address::from_public_key(&restored.public),
            Address::from_public_key(&original.public),
            "the phrase must reproduce the address, not merely some valid wallet"
        );
        assert_eq!(restored.secret.as_bytes(), original.secret.as_bytes());
    }

    /// Pinned against a value computed by the *other* implementation: Spark's `@scure/bip39` +
    /// `@noble/post-quantum` ml_dsa65, run over the same seed (2026-07-16). Helix and Spark
    /// derive keys with different libraries, and a phrase written down here is expected to
    /// restore a wallet there — so "both follow FIPS 204 and BIP39" has to be a checked fact,
    /// not an assumption. If this test ever fails, the two have diverged and phrases stop
    /// crossing between them.
    #[test]
    fn phrase_and_key_derivation_match_sparks_javascript_implementation() {
        let seed: Vec<u8> = (0u8..32).collect();

        let mnemonic = Mnemonic::from_entropy(&seed).unwrap();
        let words: Vec<&str> = mnemonic.words().collect();
        assert_eq!(&words[..3], &["abandon", "amount", "liar"], "@scure/bip39 gives these");

        let kp = KeyPair::from_mldsa_seed(&seed).unwrap();
        assert_eq!(
            Address::from_public_key(&kp.public).to_string(),
            "hlxZiWwobcPKCRx8qjZECjeitEufkor2NQ1S",
            "@noble/post-quantum ml_dsa65.keygen gives this address for the same seed"
        );
    }

    /// A phrase with a word out of place is not a wallet — BIP39's checksum makes that
    /// detectable, and restore must lean on it rather than silently deriving some other
    /// address the user would then wonder about.
    ///
    /// Fixed phrase, fixed transposition, on purpose. This test used to generate a random mnemonic
    /// and swap its first two words, which fails roughly **4 runs in 1000**: a 24-word phrase
    /// carries only an 8-bit checksum, so a transposition has about a 1-in-256 chance of landing on
    /// a phrase that checks out anyway. Measured over 20 000 samples: 77 still parsed (only 6 of
    /// them because the two swapped words happened to be identical — the coincidence, not the
    /// degenerate swap, was the real cause). A probabilistic assertion in the suite is worse than no
    /// assertion, because it teaches you to re-run a red build instead of reading it.
    #[test]
    fn a_corrupted_phrase_is_rejected_rather_than_restoring_a_stranger() {
        // Standard BIP39 test vector: 23×"abandon" + "art" is a valid 24-word phrase.
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon art";
        assert!(
            Mnemonic::parse_normalized(valid).is_ok(),
            "the fixture itself must be a valid phrase, or this test proves nothing"
        );

        let mut words: Vec<&str> = valid.split_whitespace().collect();
        let last = words.len() - 1;
        words.swap(0, last);
        assert!(
            Mnemonic::parse_normalized(&words.join(" ")).is_err(),
            "a transposed word must be caught by the checksum, not silently restore another wallet"
        );
    }

    /// The deterministic half of the same guarantee: a word that is not in the BIP39 list at all can
    /// never parse, no checksum luck involved. Guards the typo case (the common one in practice)
    /// independently of the transposition above.
    #[test]
    fn a_phrase_containing_a_word_outside_the_wordlist_is_rejected() {
        let mnemonic = Mnemonic::from_entropy(&random_seed()).unwrap();
        let mut words: Vec<String> = mnemonic.words().map(str::to_string).collect();
        words[0] = "helix".to_string(); // not a BIP39 word
        assert!(Mnemonic::parse_normalized(&words.join(" ")).is_err());
    }

    #[test]
    fn an_empty_passphrase_means_plaintext_not_a_lock_that_opens_on_enter() {
        let kp = KeyPair::generate();
        assert!(!encode(&kp, Some("")).unwrap().is_encrypted());
        assert!(!encode(&kp, None).unwrap().is_encrypted());
        assert!(encode(&kp, Some("x")).unwrap().is_encrypted());
    }

    mod passphrase_arguments {
        use super::super::*;
        use clap::Parser;

        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            wallet: WalletCmd,
        }

        fn parse(args: &[&str]) -> std::result::Result<WalletCmd, clap::Error> {
            Cli::try_parse_from(std::iter::once("wallet").chain(args.iter().copied()))
                .map(|c| c.wallet)
        }

        fn new_passphrase(args: &[&str]) -> NewPassphrase {
            match parse(args).expect("parses") {
                WalletCmd::New { passphrase, .. }
                | WalletCmd::Restore { passphrase, .. }
                | WalletCmd::ImportNodeKey { passphrase, .. } => passphrase,
                _ => panic!("not a command that sets a new passphrase"),
            }
        }

        /// Answers prompts in order, and counts how many it was shown.
        struct Keyboard {
            answers: Vec<&'static str>,
            asked: usize,
        }

        impl Keyboard {
            fn typing(answers: &[&'static str]) -> Self {
                Keyboard {
                    answers: answers.to_vec(),
                    asked: 0,
                }
            }
            fn ask(&mut self, _prompt: &str) -> Result<String> {
                let answer = self.answers.get(self.asked).map(|a| a.to_string());
                self.asked += 1;
                answer.ok_or_else(|| anyhow::anyhow!("asked more often than the test expected"))
            }
        }

        fn temp_file(contents: &str) -> std::path::PathBuf {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("helix-passphrase-{}-{nanos}", std::process::id()));
            std::fs::write(&path, contents).unwrap();
            path
        }

        /// The point of the change. By the time this runs the passphrase is in the history file,
        /// so it must not be *used* — a wallet encrypted under an exposed passphrase is worse
        /// than one the person knows to be unprotected — and the refusal says so.
        #[test]
        fn a_passphrase_typed_on_the_command_line_is_refused_not_used() {
            let mut keys = Keyboard::typing(&[]);
            let source = new_passphrase(&["new", "--passphrase", "hunter2"]);
            let err = resolve_new_passphrase(&source, &mut |p| keys.ask(p)).unwrap_err();
            assert!(err.to_string().contains("shell history"), "{err}");
            assert_eq!(keys.asked, 0, "refused before anything was asked");
        }

        #[test]
        fn the_switch_alone_asks_twice_and_the_answer_never_touches_the_command_line() {
            let mut keys = Keyboard::typing(&["correct horse", "correct horse"]);
            let source = new_passphrase(&["new", "--passphrase"]);
            let got = resolve_new_passphrase(&source, &mut |p| keys.ask(p)).unwrap();
            assert_eq!(got.as_deref(), Some("correct horse"));
            assert_eq!(keys.asked, 2);
        }

        /// Typed without echo, a typo is otherwise found the first time the wallet is opened.
        #[test]
        fn two_different_answers_set_nothing() {
            let mut keys = Keyboard::typing(&["correct horse", "correct hrose"]);
            let source = new_passphrase(&["new", "--passphrase"]);
            let err = resolve_new_passphrase(&source, &mut |p| keys.ask(p)).unwrap_err();
            assert!(err.to_string().contains("differ"), "{err}");
        }

        /// Whoever asked for encryption and pressed Enter mistyped; that is not "no passphrase".
        #[test]
        fn an_empty_answer_is_refused_not_read_as_no_passphrase() {
            let mut keys = Keyboard::typing(&[""]);
            let source = new_passphrase(&["new", "--passphrase"]);
            assert!(resolve_new_passphrase(&source, &mut |p| keys.ask(p)).is_err());
            assert_eq!(keys.asked, 1, "no point asking to repeat nothing");
        }

        /// Scripts that create a plaintext wallet keep working, and never meet a prompt.
        #[test]
        fn no_option_means_no_passphrase_and_no_question() {
            let mut keys = Keyboard::typing(&[]);
            let source = new_passphrase(&["new"]);
            assert_eq!(
                resolve_new_passphrase(&source, &mut |p| keys.ask(p)).unwrap(),
                None
            );
            assert_eq!(keys.asked, 0);
        }

        /// Exactly the file, minus the one line ending `echo secret > file` adds — spaces are
        /// the passphrase's own (#223), and an empty file is a secret that failed to arrive.
        #[test]
        fn a_passphrase_file_is_read_exactly_minus_one_line_ending() {
            for (contents, expected) in [
                ("pw\n", Some("pw")),
                ("pw\r\n", Some("pw")),
                ("pw", Some("pw")),
                (" pw \n", Some(" pw ")),
                ("pw\n\n", Some("pw\n")),
                ("", None),
                ("\n", None),
            ] {
                let path = temp_file(contents);
                let got = read_passphrase_file(&path).ok();
                std::fs::remove_file(&path).ok();
                assert_eq!(got.as_deref(), expected, "file contents {contents:?}");
            }
        }

        #[test]
        fn a_file_and_the_switch_together_do_not_parse() {
            assert!(parse(&["new", "--passphrase", "--passphrase-file", "secret"]).is_err());
        }

        /// The same options on every command that sets a new passphrase.
        #[test]
        fn restore_and_import_take_the_same_options() {
            let mut keys = Keyboard::typing(&[]);
            let refused = new_passphrase(&["restore", "--passphrase", "hunter2"]);
            assert!(resolve_new_passphrase(&refused, &mut |p| keys.ask(p)).is_err());
            let path = temp_file("from a file\n");
            let source = new_passphrase(&[
                "import-node-key",
                "--from",
                "validator-key.bin",
                "--passphrase-file",
                path.to_str().unwrap(),
            ]);
            let got = resolve_new_passphrase(&source, &mut |p| keys.ask(p)).unwrap();
            std::fs::remove_file(&path).ok();
            assert_eq!(got.as_deref(), Some("from a file"));
        }

        fn encrypt_parts(args: &[&str]) -> (Option<String>, Option<std::path::PathBuf>, bool) {
            match parse(args).expect("parses") {
                WalletCmd::Encrypt {
                    passphrase_on_command_line,
                    passphrase_file,
                    remove,
                    ..
                } => (passphrase_on_command_line, passphrase_file, remove),
                _ => panic!("not encrypt"),
            }
        }

        #[test]
        fn encrypt_refuses_its_old_argument_and_names_the_new_way_to_remove() {
            let (given, _, _) = encrypt_parts(&["encrypt", "hunter2"]);
            let err = refuse_encrypt_argument(given.as_deref()).unwrap_err();
            assert!(err.to_string().contains("shell history"), "{err}");

            let (given, _, _) = encrypt_parts(&["encrypt", ""]);
            let err = refuse_encrypt_argument(given.as_deref()).unwrap_err();
            assert!(err.to_string().contains("--remove"), "{err}");
        }

        #[test]
        fn encrypt_asks_twice_or_removes_on_request() {
            let (given, file, remove) = encrypt_parts(&["encrypt"]);
            assert!(refuse_encrypt_argument(given.as_deref()).is_ok());
            let mut keys = Keyboard::typing(&["new one", "new one"]);
            let got = resolve_encrypt_target(file.as_deref(), remove, &mut |p| keys.ask(p));
            assert_eq!(got.unwrap().as_deref(), Some("new one"));

            let (_, file, remove) = encrypt_parts(&["encrypt", "--remove"]);
            let mut keys = Keyboard::typing(&[]);
            let got = resolve_encrypt_target(file.as_deref(), remove, &mut |p| keys.ask(p));
            assert_eq!(got.unwrap(), None);
            assert_eq!(keys.asked, 0);

            assert!(parse(&["encrypt", "--remove", "--passphrase-file", "secret"]).is_err());
        }
    }
}
