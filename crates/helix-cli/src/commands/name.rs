use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};

use crate::fee::price_and_sign;
use crate::keyfile::KeyFile;
use crate::commands::tx::rpassword_read;

#[derive(Subcommand)]
pub enum NameCmd {
    /// Register a human-readable name (e.g. `alice` -> alice.hlx)
    Register {
        /// Name to register (without the .hlx suffix)
        name: String,
        /// Wallet key file
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX (default: 10000)
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
    },
    /// Resolve a name to its owning address
    Resolve {
        /// Name to resolve (without the .hlx suffix)
        name: String,
    },
}

pub async fn run(cmd: NameCmd, node: &str) -> Result<()> {
    match cmd {
        NameCmd::Register { name, key, fee } => register(name, key, fee, node).await,
        NameCmd::Resolve { name } => resolve(name, node).await,
    }
}

async fn register(name: String, key_path: PathBuf, fee: Option<u64>, node: &str) -> Result<()> {
    let kf = KeyFile::load(&key_path)?;
    let kp = if kf.is_encrypted() {
        let pass = rpassword_read("Wallet passphrase: ")?;
        kf.to_keypair(Some(&pass))?
    } else {
        kf.to_keypair(None)?
    };
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;

    let nonce = super::fetch_nonce(node, &kf.address).await?;

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::RegisterName,
        from: from.clone(),
        to: None,
        amount: 0,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: name.as_bytes().to_vec(),
        crypto_version: kp.scheme,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };

    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("Registering name '{}.hlx' for {}", name, kf.address);
    println!("  Fee   : {} nano-HLX", tx.fee);
    println!("  Nonce : {}", nonce);

    let res = super::submit_tx(&tx, node).await?;
    println!();
    super::report_submitted(&res);
    Ok(())
}

async fn resolve(name: String, node: &str) -> Result<()> {
    let what = format!("resolve {}.hlx", name);
    let res = super::get_optional(node, &format!("/names/{}", name), &what)
        .await?
        .ok_or_else(|| anyhow!("{}.hlx is not registered on this chain", name))?;

    println!(
        "{}.hlx -> {}",
        res["name"].as_str().unwrap_or(&name),
        res["address"].as_str().unwrap_or("?")
    );
    Ok(())
}
