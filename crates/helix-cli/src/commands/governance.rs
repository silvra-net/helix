use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};
use helix_executor::governance::{encode_proposal, encode_vote, GovernanceParam};

use crate::fee::price_and_sign;
use crate::keyfile::KeyFile;
use crate::commands::tx::rpassword_read;

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

/// Turn the number the operator typed into the number the chain stores, and say which unit it
/// was read as.
///
/// `min_validator_stake` is an HLX amount held in nano-HLX, exactly like `tx send`/`tx stake`
/// amounts; `fuel_per_fee_unit` is a bare count with no unit at all. This command used to take
/// a raw `u64` for both, so the two cases were indistinguishable at the prompt — and every
/// other money-taking command in this CLI reads HLX, while `governance params` *prints* HLX.
/// Typing the number you just read back was therefore wrong by a factor of a billion.
///
/// It failed safe (any plain HLX figure lands far below the `MIN_VALIDATOR_STAKE / 100` floor
/// and the proposal is rejected on execution), but only after costing a fee and a block —
/// confirmed live on 2026-07-22: `propose min-validator-stake 5000` was accepted into the
/// mempool, printed `New value : 5000`, and failed in block #22 with "below the minimum safe
/// floor 1000000000000". Safe is not the same as usable, and the one time this command matters
/// is the one time nobody has a spare block to burn.
fn on_chain_value(param: &GovParamArg, typed: f64) -> Result<(u64, String)> {
    match param {
        GovParamArg::MinValidatorStake => {
            let nano = crate::fee::hlx_to_nano(typed)?;
            Ok((nano, format!("{typed} HLX ({nano} nano-HLX)")))
        }
        GovParamArg::FuelPerFeeUnit => {
            if typed.fract() != 0.0 {
                bail!("fuel-per-fee-unit is a whole number, not {typed}");
            }
            if typed < 0.0 {
                bail!("fuel-per-fee-unit cannot be negative ({typed})");
            }
            if typed > u64::MAX as f64 {
                bail!("fuel-per-fee-unit {typed} is out of range");
            }
            let v = typed as u64;
            Ok((v, format!("{v} (unitless)")))
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
        /// New value: HLX for min-validator-stake, a plain count for fuel-per-fee-unit
        new_value: f64,
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
    new_value: f64,
    key_path: PathBuf,
    fee: Option<u64>,
    node: &str,
) -> Result<()> {
    // Before anything else, and before the passphrase prompt: a unit mistake should cost
    // nothing, not a fee and a block (see `on_chain_value`).
    let (new_value, shown) = on_chain_value(&param, new_value)?;

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
    println!("  New value : {}", shown);
    println!("  Fee       : {} nano-HLX", tx.fee);
    println!("  Nonce     : {}", nonce);
    println!();
    println!("  Note: creating a proposal does not vote on it. Cast your own vote with");
    println!("        `helix governance vote <id>` once the proposal is on-chain.");

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

async fn fetch_nonce(node: &str, address: &str) -> Result<u64> {
    let res: serde_json::Value = reqwest::get(format!("{}/accounts/{}", node, address))
        .await?
        .json()
        .await?;
    Ok(res["nonce"].as_u64().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_executor::genesis::MIN_VALIDATOR_STAKE;

    /// Ties the CLI's unit handling to the chain's own floor check rather than restating the
    /// conversion factor — a test that recomputes `typed * 1e9` would pass against any
    /// consistent mistake, including the one this replaced.
    #[test]
    fn a_stake_typed_in_hlx_clears_the_chains_floor() {
        // 1,000 HLX *is* the floor (`MIN_VALIDATOR_STAKE / 100`).
        let (at_floor, _) = on_chain_value(&GovParamArg::MinValidatorStake, 1000.0).unwrap();
        assert_eq!(at_floor, MIN_VALIDATOR_STAKE / 100);
        assert!(GovernanceParam::MinValidatorStake.validate(at_floor).is_ok());

        let (five_k, shown) = on_chain_value(&GovParamArg::MinValidatorStake, 5000.0).unwrap();
        assert!(GovernanceParam::MinValidatorStake.validate(five_k).is_ok());
        assert!(shown.contains("HLX"), "the unit must be visible before signing: {shown}");
    }

    /// The actual regression, stated as the chain sees it: the bare figure `governance params`
    /// prints is not a valid on-chain value, so the CLI must not pass it through untouched.
    #[test]
    fn the_figure_params_prints_is_not_itself_a_valid_on_chain_value() {
        assert!(
            GovernanceParam::MinValidatorStake.validate(5000).is_err(),
            "if a bare 5000 ever becomes valid, this command's unit handling needs rethinking"
        );
        let (converted, _) = on_chain_value(&GovParamArg::MinValidatorStake, 5000.0).unwrap();
        assert!(GovernanceParam::MinValidatorStake.validate(converted).is_ok());
    }

    #[test]
    fn fuel_per_fee_unit_stays_unitless() {
        let (v, shown) = on_chain_value(&GovParamArg::FuelPerFeeUnit, 5.0).unwrap();
        assert_eq!(v, 5);
        assert!(!shown.contains("HLX"), "no HLX scaling for a bare count: {shown}");
        assert!(on_chain_value(&GovParamArg::FuelPerFeeUnit, 2.5).is_err());
        assert!(on_chain_value(&GovParamArg::FuelPerFeeUnit, -1.0).is_err());
    }
}
