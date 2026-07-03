use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};

use crate::keyfile::KeyFile;

const NANO_PER_HLX: f64 = 1_000_000_000.0;
const DEFAULT_FEE_NANO: u64 = 10_000; // 0.00001 HLX

#[derive(Subcommand)]
pub enum ContractCmd {
    /// Deploy a WASM contract — its exported `call` function becomes the entry point
    Deploy {
        /// Path to a compiled .wasm module
        wasm: PathBuf,
        /// Wallet key file (the deployer's address becomes the contract account)
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX (default: 10000)
        #[arg(long, default_value_t = DEFAULT_FEE_NANO)]
        fee: u64,
        /// Node nonce override (auto-fetched if omitted)
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Call a deployed contract's `call` entry point, optionally sending HLX with it
    Call {
        /// Contract address (as returned by `deploy`, i.e. the deployer's address)
        address: String,
        /// Amount in HLX to send along with the call (default: 0)
        #[arg(long, default_value_t = 0.0)]
        amount: f64,
        /// Wallet key file
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX — also doubles as the WASM execution fuel budget (default: 10000)
        #[arg(long, default_value_t = DEFAULT_FEE_NANO)]
        fee: u64,
        /// Node nonce override (auto-fetched if omitted)
        #[arg(long)]
        nonce: Option<u64>,
    },
}

pub async fn run(cmd: ContractCmd, node: &str) -> Result<()> {
    match cmd {
        ContractCmd::Deploy { wasm, key, fee, nonce } => deploy(wasm, key, fee, nonce, node).await,
        ContractCmd::Call { address, amount, key, fee, nonce } => {
            call(address, amount, key, fee, nonce, node).await
        }
    }
}

async fn deploy(
    wasm_path: PathBuf,
    key_path: PathBuf,
    fee: u64,
    nonce_override: Option<u64>,
    node: &str,
) -> Result<()> {
    let bytecode = std::fs::read(&wasm_path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", wasm_path.display(), e))?;

    let kf = KeyFile::load(&key_path)?;
    let kp = if kf.is_encrypted() {
        let pass = rpassword_read("Wallet passphrase: ")?;
        kf.to_keypair(Some(&pass))?
    } else {
        kf.to_keypair(None)?
    };
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;

    let nonce = match nonce_override {
        Some(n) => n,
        None => fetch_nonce(node, &kf.address).await.unwrap_or(0),
    };

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::DeployContract,
        from: from.clone(),
        to: None,
        amount: 0,
        fee,
        nonce,
        data: bytecode,
        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    let signing_hash = tx.signing_hash();
    tx.signature = kp.sign(signing_hash.as_bytes())?;

    println!("Deploying contract from {}", kf.address);
    println!("  Fee   : {} nano-HLX", fee);
    println!("  Nonce : {}", nonce);

    let res = submit(&tx, node).await?;
    println!();
    println!("  Contract address : {}", kf.address);
    println!("  Tx hash          : {}", res["tx_hash"].as_str().unwrap_or("?"));
    println!("  Status           : {}", res["status"].as_str().unwrap_or("?"));
    Ok(())
}

async fn call(
    address: String,
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
    let to_addr = Address::from_str(&address)
        .map_err(|e| anyhow::anyhow!("Invalid contract address: {}", e))?;

    let amount_nano = (amount_hlx * NANO_PER_HLX) as u64;
    let nonce = match nonce_override {
        Some(n) => n,
        None => fetch_nonce(node, &kf.address).await.unwrap_or(0),
    };

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::CallContract,
        from: from.clone(),
        to: Some(to_addr),
        amount: amount_nano,
        fee,
        nonce,
        data: vec![],
        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    let signing_hash = tx.signing_hash();
    tx.signature = kp.sign(signing_hash.as_bytes())?;

    println!("Calling contract {}", address);
    println!("  Amount: {:.9} HLX", amount_hlx);
    println!("  Fee   : {} nano-HLX (execution fuel budget)", fee);
    println!("  Nonce : {}", nonce);

    let res = submit(&tx, node).await?;
    println!();
    println!("  Tx hash : {}", res["tx_hash"].as_str().unwrap_or("?"));
    println!("  Status  : {}", res["status"].as_str().unwrap_or("?"));
    Ok(())
}

async fn submit(tx: &Transaction, node: &str) -> Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let res: serde_json::Value = client
        .post(format!("{}/transactions", node))
        .json(tx)
        .send()
        .await?
        .json()
        .await?;

    if let Some(err) = res.get("error") {
        bail!("Transaction rejected: {}", err);
    }
    Ok(res)
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
