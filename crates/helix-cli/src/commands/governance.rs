use anyhow::{anyhow, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};
use helix_executor::governance::{
    encode_proposal, encode_upgrade_proposal, encode_vote, GovernanceParam, MAX_UPGRADE_LEAD_BLOCKS,
    VOTING_PERIOD_BLOCKS,
};

use crate::fee::price_and_sign;
use crate::passphrase::Signer;

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
fn on_chain_value(param: &GovParamArg, typed: &str) -> Result<(u64, String)> {
    match param {
        GovParamArg::MinValidatorStake => {
            let amount: crate::fee::Hlx = typed.parse().map_err(anyhow::Error::msg)?;
            let nano = amount.nano();
            Ok((nano, format!("{amount} HLX ({nano} nano-HLX)")))
        }
        GovParamArg::FuelPerFeeUnit => {
            let typed = typed.trim();
            let v: u64 = typed
                .parse()
                .map_err(|_| anyhow!("fuel-per-fee-unit is a whole number, not {typed}"))?;
            Ok((v, format!("{v} (unitless)")))
        }
    }
}

#[derive(Subcommand)]
pub enum GovernanceCmd {
    /// Propose changing a protocol parameter (requires a stake of at least the chain's current
    /// minimum validator stake)
    Propose {
        /// Which parameter to change
        #[arg(value_enum)]
        param: GovParamArg,
        /// New value: HLX for min-validator-stake, a plain count for fuel-per-fee-unit
        new_value: String,
        #[command(flatten)]
        signer: Signer,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
    },
    /// Propose moving the chain to the next protocol version at a block height (requires a stake
    /// of at least the chain's current minimum validator stake)
    ///
    /// A node whose build does not execute that version stops before the activation height and
    /// waits there until it is updated; a node that does goes on under the new rules. No reset.
    ProposeUpgrade {
        /// The protocol version to move to — the chain's current one plus one
        version: u64,
        /// First block executed under the new version. At least one voting period (1000 blocks)
        /// after the proposal, at most 30 days ahead; leave the operators time to update
        #[arg(long)]
        at_height: u64,
        #[command(flatten)]
        signer: Signer,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
    },
    /// Cast a stake-weighted yes-vote on a pending proposal
    Vote {
        /// Proposal id
        proposal_id: u64,
        #[command(flatten)]
        signer: Signer,
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
        GovernanceCmd::Propose { param, new_value, signer, fee } => {
            propose(param, new_value, signer, fee, node).await
        }
        GovernanceCmd::ProposeUpgrade { version, at_height, signer, fee } => {
            propose_upgrade(version, at_height, signer, fee, node).await
        }
        GovernanceCmd::Vote { proposal_id, signer, fee } => {
            vote(proposal_id, signer, fee, node).await
        }
        GovernanceCmd::Show { proposal_id } => show(proposal_id, node).await,
        GovernanceCmd::List => list(node).await,
        GovernanceCmd::Params => params(node).await,
    }
}

async fn propose(
    param: GovParamArg,
    new_value: String,
    signer: Signer,
    fee: Option<u64>,
    node: &str,
) -> Result<()> {
    // Before anything else, and before the passphrase prompt: a unit mistake should cost
    // nothing, not a fee and a block (see `on_chain_value`).
    let (new_value, shown) = on_chain_value(&param, &new_value)?;

    let (kf, kp) = signer.unlock()?;
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
        public_key: Some(kp.public.clone()),
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

/// What the chain would refuse, said before anything is signed.
///
/// The executor checks the same three things (`execute_create_proposal`), and a refusal there
/// costs a fee and a block — the same reasoning as `on_chain_value`. Checked against the node's
/// `/status`, which is a read and not a promise: the transaction lands some blocks later, so the
/// earliest height carries a margin of a few blocks rather than the bare minimum.
fn upgrade_refusal(status: &serde_json::Value, version: u64, at_height: u64) -> Option<String> {
    let Some(current) = status["protocol_version"].as_u64() else {
        return Some(
            "this node does not report a protocol version — it predates protocol upgrades, and its \
             chain cannot schedule one"
                .to_string(),
        );
    };
    let height = status["height"].as_u64().unwrap_or(0);
    if let Some(u) = status.get("scheduled_upgrade").filter(|u| !u.is_null()) {
        return Some(format!(
            "an upgrade to protocol {} at block {} is already scheduled — one at a time",
            u["version"], u["height"]
        ));
    }
    if version != current + 1 {
        return Some(format!(
            "the chain runs protocol {current}; an upgrade names the next version, {}, not {version}",
            current + 1
        ));
    }
    // The proposal lands at `height + 1` at the soonest; give it a few blocks of travel.
    let earliest = height + 1 + UPGRADE_HEIGHT_MARGIN + VOTING_PERIOD_BLOCKS + 1;
    if at_height < earliest {
        return Some(format!(
            "block {at_height} comes before the vote can end: the chain is at {height}, a proposal is \
             open for {VOTING_PERIOD_BLOCKS} blocks — name block {earliest} or later, and leave the \
             operators time to update"
        ));
    }
    let latest = height + 1 + MAX_UPGRADE_LEAD_BLOCKS;
    if at_height > latest {
        return Some(format!(
            "block {at_height} is more than {MAX_UPGRADE_LEAD_BLOCKS} blocks (30 days at the \
             2-second target) ahead; the chain refuses it — name block {latest} or earlier"
        ));
    }
    None
}

/// Blocks between reading the chain's height and the proposal landing in one.
const UPGRADE_HEIGHT_MARGIN: u64 = 20;

async fn propose_upgrade(
    version: u64,
    at_height: u64,
    signer: Signer,
    fee: Option<u64>,
    node: &str,
) -> Result<()> {
    // Before the passphrase prompt: a refusal should cost nothing.
    let status = super::get_json(node, "/status", "read the chain's protocol version").await?;
    if let Some(reason) = upgrade_refusal(&status, version, at_height) {
        return Err(anyhow!("Not sent: {reason}"));
    }
    let height = status["height"].as_u64().unwrap_or(0);

    let (kf, kp) = signer.unlock()?;
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
        data: encode_upgrade_proposal(version, at_height),
        crypto_version: kp.scheme,
        chain_id: super::resolve_chain_id(node).await?,

        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("Proposing protocol upgrade from {}", kf.address);
    println!("  Version   : {version}");
    println!("  At height : {at_height} (the chain is at {height}, {} blocks from now)", at_height - height);
    println!("  Fee       : {} nano-HLX", tx.fee);
    println!("  Nonce     : {nonce}");
    println!();
    println!("  If it passes, every node whose build does not run protocol {version} stops before");
    println!("  block {at_height} and waits there until it is updated. Release that build first.");
    println!("  Creating a proposal does not vote on it: `helix governance vote <id>`.");

    let res = submit(&tx, node).await?;
    println!();
    super::report_submitted(&res);
    Ok(())
}

async fn vote(proposal_id: u64, signer: Signer, fee: Option<u64>, node: &str) -> Result<()> {
    let (kf, kp) = signer.unlock()?;
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
        public_key: Some(kp.public.clone()),
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
    // Older nodes do not report it; leaving the line out beats printing a version they never had.
    if let Some(version) = res["protocol_version"].as_u64() {
        println!("  protocol_version    : {version}");
    }
    if let Some(u) = res.get("scheduled_upgrade").filter(|u| !u.is_null()) {
        println!("{}", scheduled_upgrade_line(u));
    }
    Ok(())
}

/// The scheduled upgrade, and whether the build answering runs it — said as what it means for
/// that node, because a `false` there is a stop at a known height.
fn scheduled_upgrade_line(u: &serde_json::Value) -> String {
    let base = format!("  scheduled upgrade   : protocol {} from block {}", u["version"], u["height"]);
    match u["supported"].as_bool() {
        Some(false) => format!(
            "{base} — the node answering does NOT run it and stops before that block until updated"
        ),
        _ => base,
    }
}

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

/// One proposal, printed so the two questions a voter actually has are answerable from it: how
/// much more yes-stake it needs, and whether voting is still open.
///
/// Neither used to be. "Yes votes: 1 (12000 HLX)" is a number with nothing to compare it to, and
/// the quorum denominator cannot be worked out client-side — it is the largest total stake the
/// proposal has ever seen, which is neither the total at creation nor the total right now, so the
/// chain's *current* total stake gives a different, wrong, entirely plausible-looking answer.
/// (It said "frozen at proposal creation" until #208 made the denominator rise with stake that
/// arrives mid-vote; freezing guarded only against a voter unstaking afterwards, and left the
/// mirror image — stake created after the proposal counted in the numerator and in no
/// denominator — wide open. **The bar can therefore move upward while a proposal is open**, which
/// is the reason this is re-read with the proposal rather than cached beside it.) Same for the
/// deadline: `VOTING_PERIOD_BLOCKS` is a protocol constant no client knows, so an expired proposal
/// printed exactly like a live one. Both now come from the node (`quorum_stake_hlx`,
/// `expires_at_height`); `chain_height`, when known, turns the second into a plain verdict.
fn print_proposal(p: &serde_json::Value, chain_height: Option<u64>) {
    println!("Proposal #{}", p["id"]);
    println!("  Proposer   : {}", p["proposer"].as_str().unwrap_or("?"));
    println!("  Param      : {}", p["param"].as_str().unwrap_or("?"));
    println!("  New value  : {}", p["new_value"]);
    if let Some(at) = p["activation_height"].as_u64() {
        println!("  Takes effect at height {at}, if it passes");
    }
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
    use helix_executor::genesis::MIN_VALIDATOR_STAKE;
    use serde_json::json;

    /// What the chain would refuse is refused before signing — and what it accepts is let
    /// through. Every bound is checked on both sides, so a check that refuses everything fails here
    /// as surely as one that refuses nothing.
    #[test]
    fn an_upgrade_the_chain_would_refuse_is_not_signed() {
        let status = json!({ "height": 5000, "protocol_version": 1, "scheduled_upgrade": null });
        let earliest = 5000 + 1 + UPGRADE_HEIGHT_MARGIN + VOTING_PERIOD_BLOCKS + 1;
        let latest = 5000 + 1 + MAX_UPGRADE_LEAD_BLOCKS;

        assert_eq!(upgrade_refusal(&status, 2, earliest), None);
        assert_eq!(upgrade_refusal(&status, 2, latest), None);
        let skip = upgrade_refusal(&status, 3, earliest).unwrap();
        assert!(skip.contains("next version, 2"), "{skip}");
        assert!(upgrade_refusal(&status, 1, earliest).is_some(), "the current version is no upgrade");
        let early = upgrade_refusal(&status, 2, earliest - 1).unwrap();
        assert!(early.contains(&earliest.to_string()), "the refusal names the earliest block: {early}");
        let far = upgrade_refusal(&status, 2, latest + 1).unwrap();
        assert!(far.contains(&latest.to_string()), "the refusal names the latest block: {far}");

        let scheduled = json!({
            "height": 5000, "protocol_version": 1,
            "scheduled_upgrade": { "version": 2, "height": 9000, "supported": true },
        });
        let busy = upgrade_refusal(&scheduled, 2, earliest).unwrap();
        assert!(busy.contains("already scheduled"), "{busy}");

        let old_node = json!({ "height": 5000 });
        assert!(upgrade_refusal(&old_node, 2, earliest).unwrap().contains("predates"));
    }

    /// A build that does not run the scheduled version says so — that line is the one an operator
    /// must not miss.
    #[test]
    fn a_scheduled_upgrade_this_node_does_not_run_is_said_plainly() {
        let unsupported = json!({ "version": 2, "height": 9000, "supported": false });
        assert!(scheduled_upgrade_line(&unsupported).contains("does NOT run it"));
        let supported = json!({ "version": 2, "height": 9000, "supported": true });
        let line = scheduled_upgrade_line(&supported);
        assert!(line.contains("protocol 2 from block 9000") && !line.contains("NOT"), "{line}");
    }

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
        let floor = MIN_VALIDATOR_STAKE / 100;
        let floor_hlx = helix_core::fee::nano_as_hlx(floor);

        let (at_floor, _) = on_chain_value(&GovParamArg::MinValidatorStake, &floor_hlx).unwrap();
        assert_eq!(at_floor, MIN_VALIDATOR_STAKE / 100);
        assert!(GovernanceParam::MinValidatorStake.validate(at_floor).is_ok());

        let five_times = helix_core::fee::nano_as_hlx(floor * 5);
        let (above, shown) = on_chain_value(&GovParamArg::MinValidatorStake, &five_times).unwrap();
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
        let (converted, _) = on_chain_value(&GovParamArg::MinValidatorStake, "5000").unwrap();
        assert!(GovernanceParam::MinValidatorStake.validate(converted).is_ok());
    }

    #[test]
    fn fuel_per_fee_unit_stays_unitless() {
        let (v, shown) = on_chain_value(&GovParamArg::FuelPerFeeUnit, "5").unwrap();
        assert_eq!(v, 5);
        assert!(!shown.contains("HLX"), "no HLX scaling for a bare count: {shown}");
        assert!(on_chain_value(&GovParamArg::FuelPerFeeUnit, "2.5").is_err());
        assert!(on_chain_value(&GovParamArg::FuelPerFeeUnit, "-1").is_err());
    }
}
