use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};
use helix_executor::governance::{encode_proposal, encode_vote, GovernanceParam};

use crate::fee::price_and_sign;
use crate::keyfile::KeyFile;


#[derive(Clone, clap::ValueEnum)]
pub enum GovParamArg {
    MinValidatorStake,
    FuelPerFeeUnit,
}

impl From<GovParamArg> for GovernanceParam {
    fn from(v: GovParamArg) -> Self {
        match v {
            GovParamArg::MinValidatorStake => GovernanceParam::MinValidatorStake,
            GovParamArg::FuelPerFeeUnit => GovernanceParam::FuelPerFeeUnit,
        }
    }
}

#[derive(Subcommand)]
pub enum GovernanceCmd {
    /// Propose changing a protocol parameter (requires an active stake)
    Propose {
        /// Which parameter to change
        #[arg(value_enum)]
        param: GovParamArg,
        /// New value for the parameter
        new_value: u64,
        /// Wallet key file of the proposer
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX (default: 10000)
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
    },
    /// Cast a stake-weighted yes-vote on a pending proposal
    Vote {
        /// Proposal id
        proposal_id: u64,
        /// Wallet key file of the voter
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX (default: 10000)
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
    },
    /// Show a single proposal's status
    Show {
        /// Proposal id
        proposal_id: u64,
    },
    /// List all governance proposals
    List,
    /// Show current runtime-adjustable protocol parameters
    Params,
}

pub async fn run(cmd: GovernanceCmd, node: &str) -> Result<()> {
    match cmd {
        GovernanceCmd::Propose { param, new_value, key, fee } => {
            propose(param, new_value, key, fee, node).await
        }
        GovernanceCmd::Vote { proposal_id, key, fee } => vote(proposal_id, key, fee, node).await,
        GovernanceCmd::Show { proposal_id } => show(proposal_id, node).await,
        GovernanceCmd::List => list(node).await,
        GovernanceCmd::Params => params(node).await,
    }
}

async fn propose(
    param: GovParamArg,
    new_value: u64,
    key_path: PathBuf,
    fee: Option<u64>,
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

    let nonce = fetch_nonce(node, &kf.address).await.unwrap_or(0);

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::CreateProposal,
        from: from.clone(),
        to: None,
        amount: 0,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: encode_proposal(param.into(), new_value),
        crypto_version: kp.scheme,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("Creating governance proposal from {}", kf.address);
    println!("  New value : {}", new_value);
    println!("  Fee       : {} nano-HLX", tx.fee);
    println!("  Nonce     : {}", nonce);

    let res = submit(&tx, node).await?;
    println!();
    println!("  Tx hash : {}", res["tx_hash"].as_str().unwrap_or("?"));
    println!("  Status  : {}", res["status"].as_str().unwrap_or("?"));
    Ok(())
}

async fn vote(proposal_id: u64, key_path: PathBuf, fee: Option<u64>, node: &str) -> Result<()> {
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
        tx_type: TxType::VoteProposal,
        from: from.clone(),
        to: None,
        amount: 0,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: encode_vote(proposal_id),
        crypto_version: kp.scheme,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("Voting yes on proposal {} as {}", proposal_id, kf.address);
    println!("  Fee   : {} nano-HLX", tx.fee);
    println!("  Nonce : {}", nonce);

    let res = submit(&tx, node).await?;
    println!();
    println!("  Tx hash : {}", res["tx_hash"].as_str().unwrap_or("?"));
    println!("  Status  : {}", res["status"].as_str().unwrap_or("?"));
    Ok(())
}

async fn show(proposal_id: u64, node: &str) -> Result<()> {
    let res: serde_json::Value =
        reqwest::get(format!("{}/governance/proposals/{}", node, proposal_id))
            .await?
            .json()
            .await?;
    if let Some(err) = res.get("error") {
        bail!("{}", err);
    }
    print_proposal(&res);
    Ok(())
}

async fn list(node: &str) -> Result<()> {
    let res: serde_json::Value = reqwest::get(format!("{}/governance/proposals", node))
        .await?
        .json()
        .await?;
    let empty = Vec::new();
    let proposals = res["proposals"].as_array().unwrap_or(&empty);
    if proposals.is_empty() {
        println!("No governance proposals yet.");
        return Ok(());
    }
    for p in proposals {
        print_proposal(p);
        println!();
    }
    Ok(())
}

async fn params(node: &str) -> Result<()> {
    let res: serde_json::Value = reqwest::get(format!("{}/governance/params", node))
        .await?
        .json()
        .await?;
    println!("Current protocol parameters:");
    println!(
        "  min_validator_stake : {} HLX",
        res["min_validator_stake_hlx"].as_f64().unwrap_or(0.0)
    );
    println!(
        "  fuel_per_fee_unit   : {}",
        res["fuel_per_fee_unit"].as_u64().unwrap_or(0)
    );
    Ok(())
}

fn print_proposal(p: &serde_json::Value) {
    println!("Proposal #{}", p["id"]);
    println!("  Proposer   : {}", p["proposer"].as_str().unwrap_or("?"));
    println!("  Param      : {}", p["param"].as_str().unwrap_or("?"));
    println!("  New value  : {}", p["new_value"]);
    println!("  Created at : height {}", p["created_at_height"]);
    println!(
        "  Yes votes  : {} ({} HLX)",
        p["yes_votes"], p["yes_stake_hlx"].as_f64().unwrap_or(0.0)
    );
    println!("  Executed   : {}", p["executed"].as_bool().unwrap_or(false));
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
