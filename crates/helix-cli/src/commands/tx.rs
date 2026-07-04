use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};

use crate::keyfile::KeyFile;

const NANO_PER_HLX: f64 = 1_000_000_000.0;
const DEFAULT_FEE_NANO: u64 = 10_000; // 0.00001 HLX

#[derive(Subcommand)]
pub enum TxCmd {
    /// Send HLX to an address
    Send {
        /// Recipient address
        to: String,
        /// Amount in HLX (e.g. 1.5)
        amount: f64,
        /// Wallet key file
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX (default: 10000)
        #[arg(long, default_value_t = DEFAULT_FEE_NANO)]
        fee: u64,
        /// Node nonce override (auto-fetched if omitted)
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Check transaction status
    Status {
        /// Transaction hash
        hash: String,
    },
}

pub async fn run(cmd: TxCmd, node: &str) -> Result<()> {
    match cmd {
        TxCmd::Send { to, amount, key, fee, nonce } => {
            send(to, amount, key, fee, nonce, node).await
        }
        TxCmd::Status { hash } => tx_status(hash, node).await,
    }
}

async fn send(
    to: String,
    amount_hlx: f64,
    key_path: PathBuf,
    fee: u64,
    nonce_override: Option<u64>,
    node: &str,
) -> Result<()> {
    let kf = KeyFile::load(&key_path)?;
    let kp = if kf.is_encrypted() {
        let pass = rpassword_read("Wallet passphrase: ")?;
        kf.to_keypair(Some(&pass))?
    } else {
        kf.to_keypair(None)?
    };
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
    let to_addr = Address::from_str(&to)
        .map_err(|e| anyhow::anyhow!("Invalid recipient address: {}", e))?;

    let amount_nano = (amount_hlx * NANO_PER_HLX) as u64;

    // Fetch current nonce from node if not provided
    let nonce = match nonce_override {
        Some(n) => n,
        None => fetch_nonce(node, &kf.address).await.unwrap_or(0),
    };

    // Build and sign transaction
    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        from: from.clone(),
        to: Some(to_addr),
        amount: amount_nano,
        fee,
        nonce,
        data: vec![],
        crypto_version: kp.scheme,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };

    let signing_hash = tx.signing_hash();
    tx.signature = kp.sign(signing_hash.as_bytes())?;

    println!("Sending {:.9} HLX to {}", amount_hlx, to);
    println!("  From  : {}", kf.address);
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

async fn tx_status(hash: String, node: &str) -> Result<()> {
    let res: serde_json::Value = reqwest::get(format!("{}/transactions/{}", node, hash))
        .await?
        .json()
        .await?;

    if let Some(err) = res.get("error") {
        bail!("Not found: {}", err);
    }

    println!("Transaction: {}", hash);
    println!("─────────────────────────────────────────");
    println!("  Status : {}", res["status"].as_str().unwrap_or("?"));
    println!("  Block  : #{}", res["block_height"]);
    Ok(())
}
