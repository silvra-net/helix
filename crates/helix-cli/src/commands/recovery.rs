use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};

use crate::keyfile::KeyFile;

const DEFAULT_FEE_NANO: u64 = 10_000; // 0.00001 HLX

#[derive(Subcommand)]
pub enum RecoveryCmd {
    /// Register (or replace) your social-recovery guardian set (3-of-5 quorum)
    RegisterGuardians {
        /// Guardian addresses (3-10)
        #[arg(required = true, num_args = 1..)]
        guardians: Vec<String>,
        /// Wallet key file of the account owner
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX (default: 10000)
        #[arg(long, default_value_t = DEFAULT_FEE_NANO)]
        fee: u64,
    },
    /// As a registered guardian, approve rotating a lost account to a new public key
    Approve {
        /// Address being recovered
        target: String,
        /// New controlling public key (hex-encoded ML-DSA public key)
        new_public_key: String,
        /// Wallet key file of the guardian
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX (default: 10000)
        #[arg(long, default_value_t = DEFAULT_FEE_NANO)]
        fee: u64,
    },
    /// Show guardian set and any in-progress recovery vote for an address
    Status {
        /// Address to look up
        address: String,
    },
}

pub async fn run(cmd: RecoveryCmd, node: &str) -> Result<()> {
    match cmd {
        RecoveryCmd::RegisterGuardians { guardians, key, fee } => {
            register_guardians(guardians, key, fee, node).await
        }
        RecoveryCmd::Approve {
            target,
            new_public_key,
            key,
            fee,
        } => approve(target, new_public_key, key, fee, node).await,
        RecoveryCmd::Status { address } => status(address, node).await,
    }
}

async fn register_guardians(
    guardians: Vec<String>,
    key_path: PathBuf,
    fee: u64,
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

    for g in &guardians {
        Address::from_str(g).map_err(|e| anyhow::anyhow!("Invalid guardian address '{}': {}", g, e))?;
    }

    let nonce = fetch_nonce(node, &kf.address).await.unwrap_or(0);

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::RegisterGuardians,
        from: from.clone(),
        to: None,
        amount: 0,
        fee,
        nonce,
        data: guardians.join("\n").into_bytes(),
        crypto_version: kp.scheme,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };

    let signing_hash = tx.signing_hash();
    tx.signature = kp.sign(signing_hash.as_bytes())?;

    println!("Registering {} guardians for {}", guardians.len(), kf.address);
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

async fn approve(
    target: String,
    new_public_key_hex: String,
    key_path: PathBuf,
    fee: u64,
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
    let target_addr = Address::from_str(&target)
        .map_err(|e| anyhow::anyhow!("Invalid target address: {}", e))?;
    let new_key_bytes = hex::decode(&new_public_key_hex)
        .map_err(|e| anyhow::anyhow!("Invalid new public key hex: {}", e))?;

    let nonce = fetch_nonce(node, &kf.address).await.unwrap_or(0);

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::ApproveRecovery,
        from: from.clone(),
        to: Some(target_addr),
        amount: 0,
        fee,
        nonce,
        data: new_key_bytes,
        crypto_version: kp.scheme,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };

    let signing_hash = tx.signing_hash();
    tx.signature = kp.sign(signing_hash.as_bytes())?;

    println!("Approving recovery of {} to new key", target);
    println!("  Guardian : {}", kf.address);
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
    let guardians: serde_json::Value =
        reqwest::get(format!("{}/accounts/{}/guardians", node, address))
            .await?
            .json()
            .await?;
    let recovery: serde_json::Value =
        reqwest::get(format!("{}/accounts/{}/recovery", node, address))
            .await?
            .json()
            .await?;

    println!("Recovery status for {}:", address);
    if guardians.get("error").is_some() {
        println!("  Guardians: none registered");
    } else {
        println!(
            "  Guardians ({} of {}): {}",
            guardians["threshold"],
            guardians["guardians"].as_array().map(|a| a.len()).unwrap_or(0),
            serde_json::to_string(&guardians["guardians"])?
        );
    }
    if let Some(fp) = recovery.get("recovered_key_fingerprint").and_then(|v| v.as_str()) {
        println!("  Active recovery key fingerprint: {}", fp);
    }
    if let Some(approvals) = recovery.get("pending_approvals").and_then(|v| v.as_u64()) {
        println!(
            "  Pending recovery vote: {}/{} approvals",
            approvals,
            recovery["threshold"].as_u64().unwrap_or(0)
        );
    }
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
