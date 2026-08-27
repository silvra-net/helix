use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};
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

    let nonce = super::fetch_nonce(node, &kf.address).await?;

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
        chain_id: super::resolve_chain_id(node).await?,

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
    super::report_submitted(&res);
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

    let nonce = super::fetch_nonce(node, &kf.address).await?;

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
        chain_id: super::resolve_chain_id(node).await?,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("Voting yes on proposal {} as {}", proposal_id, kf.address);
    println!("  Fee   : {} nano-HLX", tx.fee);
    println!("  Nonce : {}", nonce);

    let res = submit(&tx, node).await?;
    println!();
    super::report_submitted(&res);
    Ok(())
}

async fn show(proposal_id: u64, node: &str) -> Result<()> {
    let what = format!("look up proposal #{}", proposal_id);
    let res = super::get_optional(
        node,
        &format!("/governance/proposals/{}", proposal_id),
        &what,
    )
    .await?
    .ok_or_else(|| anyhow!("there is no proposal #{} on this chain", proposal_id))?;
    print_proposal(&res, chain_height(node).await);
    Ok(())
}

async fn list(node: &str) -> Result<()> {
    let res = super::get_json(node, "/governance/proposals", "list the proposals").await?;
    let empty = Vec::new();
    let proposals = res["proposals"].as_array().unwrap_or(&empty);
    if proposals.is_empty() {
        println!("No governance proposals yet.");
        return Ok(());
    }
    let height = chain_height(node).await;
    for p in proposals {
        print_proposal(p, height);
        println!();
    }
    Ok(())
}

async fn params(node: &str) -> Result<()> {
    let res = super::get_json(node, "/governance/params", "governance parameters").await?;
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

/// One proposal, printed so the two questions a voter actually has are answerable from it: how
/// much more yes-stake it needs, and whether voting is still open.
///
/// Neither used to be. "Yes votes: 1 (12000 HLX)" is a number with nothing to compare it to, and
/// the quorum denominator cannot be worked out client-side — it is frozen at proposal creation
/// precisely so a voter cannot unstake afterwards and shrink the bar behind them, so the chain's
/// *current* total stake gives a different, wrong, entirely plausible-looking answer. Same for the
/// deadline: `VOTING_PERIOD_BLOCKS` is a protocol constant no client knows, so an expired proposal
/// printed exactly like a live one. Both now come from the node (`quorum_stake_hlx`,
/// `expires_at_height`); `chain_height`, when known, turns the second into a plain verdict.
/// The chain's current height, or `None` if it cannot be had.
///
/// Best-effort on purpose: it decides only whether a proposal is *labelled* expired, and a
/// listing that fails because the status line could not be filled in would be a worse trade than
/// a listing that says "open" without knowing.
async fn chain_height(node: &str) -> Option<u64> {
    super::get_json(node, "/status", "read the chain height")
        .await
        .ok()
        .and_then(|v| v["height"].as_u64())
}

fn print_proposal(p: &serde_json::Value, chain_height: Option<u64>) {
    println!("Proposal #{}", p["id"]);
    println!("  Proposer   : {}", p["proposer"].as_str().unwrap_or("?"));
    println!("  Param      : {}", p["param"].as_str().unwrap_or("?"));
    println!("  New value  : {}", p["new_value"]);
    println!("  Created at : height {}", p["created_at_height"]);
    let yes = p["yes_stake_hlx"].as_f64().unwrap_or(0.0);
    match p["quorum_stake_hlx"].as_f64() {
        // Older node: it does not report the threshold, and inventing one would be worse than
        // leaving the figure bare.
        None => println!("  Yes votes  : {} ({} HLX)", p["yes_votes"], yes),
        Some(needed) => println!(
            "  Yes votes  : {} ({:.9} of {:.9} HLX needed)",
            p["yes_votes"], yes, needed
        ),
    }
    let executed = p["executed"].as_bool().unwrap_or(false);
    let expires = p["expires_at_height"].as_u64();
    let status = if executed {
        "passed".to_string()
    } else {
        match (expires, chain_height) {
            (Some(e), Some(h)) if h > e => format!("expired (voting closed at height {e})"),
            (Some(e), _) => format!("open until height {e}"),
            _ => "open".to_string(),
        }
    };
    println!("  Status     : {status}");
}

async fn submit(tx: &Transaction, node: &str) -> Result<serde_json::Value> {
    super::submit_tx(tx, node).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_executor::genesis::{MIN_VALIDATOR_STAKE, NANO_PER_HLX};

    /// Ties the CLI's unit handling to the chain's own floor check rather than restating the
    /// conversion factor — a test that recomputes `typed * 1e9` would pass against any
    /// consistent mistake, including the one this replaced.
    ///
    /// The figure typed at the floor is *derived* from `MIN_VALIDATOR_STAKE`, not written out.
    /// It used to be the literal `1000.0`, which was the floor only while the minimum was 100 k —
    /// lowering it to 10 k on 2026-08-26 turned this test red, and a test that goes red because a
    /// constant it claims not to restate has moved was restating it after all.
    #[test]
    fn a_stake_typed_in_hlx_clears_the_chains_floor() {
        // Governance may lower the minimum to a hundredth of the compiled-in value; typed in HLX,
        // that is what an operator would enter.
        let floor_hlx = (MIN_VALIDATOR_STAKE / 100) as f64 / NANO_PER_HLX as f64;

        let (at_floor, _) = on_chain_value(&GovParamArg::MinValidatorStake, floor_hlx).unwrap();
        assert_eq!(at_floor, MIN_VALIDATOR_STAKE / 100);
        assert!(GovernanceParam::MinValidatorStake.validate(at_floor).is_ok());

        let (above, shown) = on_chain_value(&GovParamArg::MinValidatorStake, floor_hlx * 5.0).unwrap();
        assert!(GovernanceParam::MinValidatorStake.validate(above).is_ok());
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
