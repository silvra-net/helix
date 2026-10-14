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
        ChainCmd::Latest => show_block(node, "/blocks/latest", "the latest block").await,
        ChainCmd::Block { height } => {
            show_block(
                node,
                &format!("/blocks/height/{}", height),
                &format!("block #{}", height),
            )
            .await
        }
    }
}

async fn show_status(node: &str) -> Result<()> {
    let res = super::get_json(node, "/status", "node status").await?;

    println!("Helix Node Status");
    println!("─────────────────────────────────────────");
    println!("  Version      : {}", res["version"].as_str().unwrap_or("?"));
    println!("  Height       : {}", res["height"]);
    println!("  Best hash    : {}", short_hash(res["best_hash"].as_str()));
    println!("  Peers        : {}", res["peer_count"]);
    println!("  Mempool      : {} pending txs", res["mempool_size"]);
    println!("  Syncing      : {}", res["is_syncing"]);
    // What a fee is priced against, and which chain a signature is for — the two things someone
    // signing offline has to carry over from here (`tx send --offline`, `HELIX_CHAIN_ID`).
    if let Some(base_fee) = res["base_fee_per_byte"].as_u64() {
        println!("  Base fee     : {base_fee} nano-HLX per byte");
    }
    // Best effort: a node that cannot show its genesis is still worth a status line.
    if let Ok(Some(genesis)) = super::get_optional(node, "/blocks/height/0", "the genesis").await {
        if let Some(hash) = genesis["hash"].as_str() {
            println!("  Chain id     : {hash}");
        }
    }
    Ok(())
}

/// Shorten a hash for display without assuming there is one.
///
/// This was `&res["best_hash"].as_str().unwrap_or("?")[..16]`, which panics on its own fallback:
/// slicing `"?"` to sixteen bytes is out of bounds. `chain status` against anything that answered
/// without a `best_hash` therefore died with a byte-index panic instead of saying what was wrong
/// — and that is the command someone runs precisely when they are unsure the node is healthy.
fn short_hash(hash: Option<&str>) -> String {
    match hash {
        Some(h) if h.len() > 16 => format!("{}…", &h[..16]),
        Some(h) => h.to_string(),
        None => "?".to_string(),
    }
}

async fn show_block(node: &str, path: &str, what: &str) -> Result<()> {
    let res = super::get_optional(node, path, what)
        .await?
        .ok_or_else(|| anyhow::anyhow!("this chain has no {}", what))?;

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
    let res = super::get_optional(node, &format!("/accounts/{}", address), "look up the account")
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "this chain has no record of {} — it has never sent or received anything",
                address
            )
        })?;

    println!("Account: {}", address);
    println!("─────────────────────────────────────────");
    println!("  Balance  : {} HLX", res["balance_hlx"]);
    println!("  Staked   : {} HLX", res["staked_hlx"]);
    let unbonding = res["unbonding_stake_hlx"].as_f64().unwrap_or(0.0);
    if unbonding > 0.0 {
        println!("  Unbonding: {} HLX (unlocks at block #{})", unbonding, res["unbonding_unlock_height"]);
        // Unbonding funds can still shrink until they unlock, so name who can shrink them
        // rather than letting the amount read as merely illiquid.
        match res["unbonding_source"].as_str() {
            Some(validator) => println!("             still slashable if {} double-signs", validator),
            None => println!("             still slashable if you double-sign"),
        }
    }
    if let Some(unlock_height) = res["jailed_until"].as_u64() {
        println!("  Jailed   : downtime-jailed, can submit `tx unjail` at block #{unlock_height}");
    } else if let Some(missed) = res["missed_blocks"].as_u64() {
        println!("  Missed   : {}", downtime_debt_line(missed));
    }
    println!("  Nonce    : {}", res["nonce"]);

    let delegations = super::get_optional(
        node,
        &format!("/accounts/{}/delegations", address),
        "list the account's delegations",
    )
    .await?;
    if let Some(list) = delegations.as_ref().and_then(|d| d["delegations"].as_array()) {
        if !list.is_empty() {
            println!("  Delegations:");
            for d in list {
                println!("    → {} : {} HLX", d["validator"].as_str().unwrap_or("?"), d["value_hlx"]);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression: the fallback string was shorter than the slice taken from it.
    #[test]
    fn a_missing_hash_is_printed_rather_than_panicked_on() {
        assert_eq!(short_hash(None), "?");
        assert_eq!(short_hash(Some("")), "");
        assert_eq!(short_hash(Some("abc")), "abc");
    }

    #[test]
    fn a_real_hash_is_still_shortened() {
        let h = "0123456789abcdef0123456789abcdef";
        assert_eq!(short_hash(Some(h)), "0123456789abcdef…");
    }

    /// Exactly the display width is the boundary: shortening there would add an ellipsis
    /// promising characters that do not exist.
    #[test]
    fn a_hash_of_exactly_the_display_width_is_not_marked_as_truncated() {
        assert_eq!(short_hash(Some("0123456789abcdef")), "0123456789abcdef");
    }
}

/// What `missed_blocks` means since the downtime rule became a rate (#198): a debt, not a run of
/// misses — each block not signed adds `MISS_WEIGHT`, each signed one takes `PARTICIPATION_CREDIT`
/// off, and the validator is jailed at `DOWNTIME_JAIL_THRESHOLD_BLOCKS`. The line said
/// "consecutive blocks … (resets on the next one)" until 2026-10-14, which an operator would read
/// as harmless right after any signature.
fn downtime_debt_line(missed: u64) -> String {
    use helix_executor::state::{DOWNTIME_JAIL_THRESHOLD_BLOCKS, MISS_WEIGHT, PARTICIPATION_CREDIT};
    format!(
        "downtime debt {missed} of {DOWNTIME_JAIL_THRESHOLD_BLOCKS} — +{MISS_WEIGHT} per block not \
         signed, -{PARTICIPATION_CREDIT} per block signed; jailed at {DOWNTIME_JAIL_THRESHOLD_BLOCKS}"
    )
}

#[cfg(test)]
mod downtime_debt_line_tests {
    use super::downtime_debt_line;

    #[test]
    fn the_downtime_line_reads_as_a_debt_with_its_threshold() {
        let line = downtime_debt_line(42);
        assert!(line.contains("downtime debt 42 of 3600"), "{line}");
        assert!(line.contains("jailed at 3600"), "{line}");
        assert!(!line.contains("consecutive"), "the old reading: {line}");
    }
}
