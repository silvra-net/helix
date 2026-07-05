use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use helix_crypto::{CryptoScheme, KeyPair};

use crate::keyfile::KeyFile;

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
            let kp = KeyPair::generate_for(scheme);

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
