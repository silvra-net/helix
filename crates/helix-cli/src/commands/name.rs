use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};

use crate::keyfile::KeyFile;

const DEFAULT_FEE_NANO: u64 = 10_000; // 0.00001 HLX

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
        #[arg(long, default_value_t = DEFAULT_FEE_NANO)]
        fee: u64,
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

async fn register(name: String, key_path: PathBuf, fee: u64, node: &str) -> Result<()> {
    let kf = KeyFile::load(&key_path)?;
    let kp = if kf.is_encrypted() {
        let pass = rpassword_read("Wallet passphrase: ")?;
        kf.to_keypair(Some(&pass))?
    } else {
        kf.to_keypair(None)?
    };
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;

    let nonce = fetch_nonce(node, &kf.address).await.unwrap_or(0);

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::RegisterName,
        from: from.clone(),
        to: None,
        amount: 0,
        fee,
        nonce,
        data: name.as_bytes().to_vec(),
        crypto_version: kp.scheme,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };

    let signing_hash = tx.signing_hash();
    tx.signature = kp.sign(signing_hash.as_bytes())?;

    println!("Registering name '{}.hlx' for {}", name, kf.address);
    println!("  Fee   : {} nano-HLX", fee);
    println!("  Nonce : {}", nonce);

    let client = reqwest::Client::new();
    let res: serde_json::Value = client
        .post(format!("{}/transactions", node))
        .json(&tx)
        .send()
        .await?
        .json()
        .await?;

    if let Some(err) = res.get("error") {
        bail!("Transaction rejected: {}", err);
    }

    println!();
    println!("  Tx hash : {}", res["tx_hash"].as_str().unwrap_or("?"));
    println!("  Status  : {}", res["status"].as_str().unwrap_or("?"));
    Ok(())
}

async fn resolve(name: String, node: &str) -> Result<()> {
    let res: serde_json::Value = reqwest::get(format!("{}/names/{}", node, name))
        .await?
        .json()
        .await?;

    if let Some(err) = res.get("error") {
        bail!("{}", err);
    }

    println!(
        "{}.hlx -> {}",
        res["name"].as_str().unwrap_or(&name),
        res["address"].as_str().unwrap_or("?")
    );
    Ok(())
}

fn rpassword_read(_prompt: &str) -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

async fn fetch_nonce(node: &str, address: &str) -> Result<u64> {
    let res: serde_json::Value = reqwest::get(format!("{}/accounts/{}", node, address))
        .await?
        .json()
        .await?;
    Ok(res["nonce"].as_u64().unwrap_or(0))
}
