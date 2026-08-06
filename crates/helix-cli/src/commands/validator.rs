use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum ValidatorCmd {
    /// Show a validator's delegation pool: delegated stake, commission rate, effective
    /// (self + delegated) stake
    Show {
        /// Validator address
        address: String,
    },
}

pub async fn run(cmd: ValidatorCmd, node: &str) -> Result<()> {
    match cmd {
        ValidatorCmd::Show { address } => show_pool(&address, node).await,
    }
}

async fn show_pool(address: &str, node: &str) -> Result<()> {
    let res = super::get_optional(
        node,
        &format!("/validators/{}/pool", address),
        "read the validator's delegation pool",
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("this chain has no record of {}", address))?;

    println!("Validator: {}", address);
    println!("─────────────────────────────────────────");
    println!("  Self-staked      : {} HLX", res["self_staked_hlx"]);
    if res["has_pool"].as_bool().unwrap_or(false) {
        println!("  Delegated stake  : {} HLX", res["delegated_stake_hlx"]);
        println!("  Effective stake  : {} HLX", res["effective_stake_hlx"]);
        let bps = res["commission_bps"].as_u64().unwrap_or(0);
        println!("  Commission       : {} bps ({:.2}%)", bps, bps as f64 / 100.0);
        println!("  Total shares     : {}", res["total_shares"]);
    } else {
        println!("  No delegation pool yet (no one has delegated to this address).");
    }
    Ok(())
}
