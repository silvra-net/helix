use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};

use crate::keyfile::KeyFile;

const DEFAULT_FEE_NANO: u64 = 10_000; // 0.00001 HLX

#[derive(Subcommand)]
pub enum IdentityCmd {
    /// Attest that another address belongs to a unique human (Proof of Personhood)
    Attest {
        /// Address to attest
        address: String,
        /// Wallet key file of the attester
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX (default: 10000)
        #[arg(long, default_value_t = DEFAULT_FEE_NANO)]
        fee: u64,
    },
    /// Show Proof of Personhood status for an address
    Status {
        /// Address to look up
        address: String,
    },
}

pub async fn run(cmd: IdentityCmd, node: &str) -> Result<()> {
    match cmd {
        IdentityCmd::Attest { address, key, fee } => attest(address, key, fee, node).await,
        IdentityCmd::Status { address } => status(address, node).await,
    }
}

async fn attest(address: String, key_path: PathBuf, fee: u64, node: &str) -> Result<()> {
    let kf = KeyFile::load(&key_path)?;
    let kp = if kf.is_encrypted() {
        let pass = rpassword_read("Wallet passphrase: ")?;
        kf.to_keypair(Some(&pass))?
    } else {
        kf.to_keypair(None)?
    };
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
    let to = Address::from_str(&address)
        .map_err(|e| anyhow::anyhow!("Invalid target address: {}", e))?;

    let nonce = fetch_nonce(node, &kf.address).await.unwrap_or(0);

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::RegisterIdentity,
        from: from.clone(),
        to: Some(to),
        amount: 0,
        fee,
        nonce,
        data: vec![],
        crypto_version: kp.scheme,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };

    let signing_hash = tx.signing_hash();
    tx.signature = kp.sign(signing_hash.as_bytes())?;

    println!("Attesting personhood for {}", address);
    println!("  Attester : {}", kf.address);
    println!("  Fee      : {} nano-HLX", fee);
    println!("  Nonce    : {}", nonce);

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

async fn status(address: String, node: &str) -> Result<()> {
    let res: serde_json::Value = reqwest::get(format!("{}/accounts/{}/personhood", node, address))
        .await?
        .json()
        .await?;

    if let Some(err) = res.get("error") {
        bail!("{}", err);
    }

    println!("Personhood status for {}:", address);
    println!("  {}", serde_json::to_string_pretty(&res["status"])?);
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
