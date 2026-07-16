use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use bip39::Mnemonic;
use clap::Subcommand;
use helix_crypto::{CryptoScheme, KeyPair};

use crate::keyfile::KeyFile;

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
        /// Protect the key with a passphrase (AES-256-GCM + Argon2id)
        #[arg(long)]
        passphrase: Option<String>,
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
        /// Protect the restored key with a passphrase (AES-256-GCM + Argon2id)
        #[arg(long)]
        passphrase: Option<String>,
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
    },
    /// Change or add passphrase encryption on an existing wallet
    Encrypt {
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// New passphrase (leave empty to remove encryption)
        passphrase: String,
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
        /// Protect the imported key with a passphrase (AES-256-GCM + Argon2id)
        #[arg(long)]
        passphrase: Option<String>,
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

            let kf = match passphrase {
                Some(ref pass) => {
                    println!("Encrypting with AES-256-GCM + Argon2id...");
                    KeyFile::from_keypair_encrypted(&kp, pass)?
                }
                None => KeyFile::from_keypair_plain(&kp),
            };

            kf.save(&output)?;
            println!();
            println!("  Address    : {}", kf.address);
            println!("  Public key : {}...", &kf.public_key[..32]);
            println!("  Algorithm  : {}", kf.algo);
            println!("  Encryption : {}", kf.encryption);
            println!("  Saved to   : {}", output.display());
            println!();
            if passphrase.is_none() {
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

            let kf = match passphrase {
                Some(ref pass) => KeyFile::from_keypair_encrypted(&kp, pass)?,
                None => KeyFile::from_keypair_plain(&kp),
            };
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

        WalletCmd::Address { key } => {
            let kf = KeyFile::load(&key)?;
            println!("{}", kf.address);
        }

        WalletCmd::ImportNodeKey { from, output, passphrase } => {
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

            let kf = match passphrase {
                Some(ref pass) => {
                    println!("Encrypting with AES-256-GCM + Argon2id...");
                    KeyFile::from_keypair_encrypted(&kp, pass)?
                }
                None => KeyFile::from_keypair_plain(&kp),
            };

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

        WalletCmd::Encrypt { key, passphrase } => {
            let kf = KeyFile::load(&key)?;
            let pass = if kf.is_encrypted() {
                print!("Current passphrase: ");
                Some(rpassword_prompt("Current passphrase: "))
            } else {
                None
            };
            let kp = kf.to_keypair(pass.as_deref())?;
            let new_kf = KeyFile::from_keypair_encrypted(&kp, &passphrase)?;
            new_kf.save(&key)?;
            println!("✓ Wallet re-encrypted at {}", key.display());
        }
    }
    Ok(())
}

fn rpassword_prompt(_prompt: &str) -> String {
    // For now, read from stdin (in production: use rpassword crate for hidden input)
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).unwrap();
    s.trim().to_string()
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
    #[test]
    fn a_corrupted_phrase_is_rejected_rather_than_restoring_a_stranger() {
        let mnemonic = Mnemonic::from_entropy(&random_seed()).unwrap();
        let mut words: Vec<&str> = mnemonic.words().collect();
        words.swap(0, 1);
        assert!(Mnemonic::parse_normalized(&words.join(" ")).is_err());
    }
}
