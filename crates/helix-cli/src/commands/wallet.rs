use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;
use helix_crypto::KeyPair;

use crate::keyfile::KeyFile;

#[derive(Subcommand)]
pub enum WalletCmd {
    /// Generate a new ML-DSA keypair
    New {
        #[arg(short, long, default_value = "wallet.json")]
        output: PathBuf,
        /// Protect the key with a passphrase (AES-256-GCM + Argon2id)
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
}

pub async fn run(cmd: WalletCmd) -> Result<()> {
    match cmd {
        WalletCmd::New { output, passphrase } => {
            println!("Generating ML-DSA (Dilithium3) keypair...");
            let kp = KeyPair::generate();

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
