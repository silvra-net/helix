use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum ChainCmd {
    /// Show node status (height, hash, mempool)
    Status,
    /// Show latest block
    Latest,
    /// Get block by height
    Block { height: u64 },
}

pub async fn run(cmd: ChainCmd, node: &str) -> Result<()> {
    match cmd {
        ChainCmd::Status => show_status(node).await,
        ChainCmd::Latest => show_block_by_url(&format!("{}/blocks/latest", node)).await,
        ChainCmd::Block { height } => {
            show_block_by_url(&format!("{}/blocks/height/{}", node, height)).await
        }
    }
}

async fn show_status(node: &str) -> Result<()> {
    let res: serde_json::Value = reqwest::get(format!("{}/status", node))
        .await?
        .json()
        .await?;

    println!("Helix Node Status");
    println!("─────────────────────────────────────────");
    println!("  Version      : {}", res["version"].as_str().unwrap_or("?"));
    println!("  Height       : {}", res["height"]);
    println!("  Best hash    : {}", &res["best_hash"].as_str().unwrap_or("?")[..16]);
    println!("  Peers        : {}", res["peer_count"]);
    println!("  Mempool      : {} pending txs", res["mempool_size"]);
    println!("  Syncing      : {}", res["is_syncing"]);
    Ok(())
}

async fn show_block_by_url(url: &str) -> Result<()> {
    let res: serde_json::Value = reqwest::get(url).await?.json().await?;

    if let Some(err) = res.get("error") {
        anyhow::bail!("Error: {}", err);
    }

    println!("Block #{}", res["height"]);
    println!("─────────────────────────────────────────");
    println!("  Hash      : {}", res["hash"].as_str().unwrap_or("?"));
    println!("  Prev hash : {}", res["prev_hash"].as_str().unwrap_or("?"));
    println!("  Validator : {}", res["validator"].as_str().unwrap_or("?"));
    println!("  Timestamp : {}", res["timestamp"]);
    println!("  Txs       : {}", res["tx_count"]);
    Ok(())
}

pub async fn show_account(address: &str, node: &str) -> Result<()> {
    let res: serde_json::Value = reqwest::get(format!("{}/accounts/{}", node, address))
        .await?
        .json()
        .await?;

    if let Some(err) = res.get("error") {
        anyhow::bail!("Account not found: {}", err);
    }

    println!("Account: {}", address);
    println!("─────────────────────────────────────────");
    println!("  Balance  : {} HLX", res["balance_hlx"]);
    println!("  Staked   : {} HLX", res["staked_hlx"]);
    let unbonding = res["unbonding_stake_hlx"].as_f64().unwrap_or(0.0);
    if unbonding > 0.0 {
        println!("  Unbonding: {} HLX (unlocks at block #{})", unbonding, res["unbonding_unlock_height"]);
    }
    println!("  Nonce    : {}", res["nonce"]);
    Ok(())
}
