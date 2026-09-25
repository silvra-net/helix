use anyhow::Result;
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};

use crate::fee::price_and_sign;
use crate::passphrase::Signer;

#[derive(Subcommand)]
pub enum RecoveryCmd {
    /// Register (or replace) your social-recovery guardian set (3-of-5 quorum)
    RegisterGuardians {
        /// Guardian addresses (3-10)
        #[arg(required = true, num_args = 1..)]
        guardians: Vec<String>,
        #[command(flatten)]
        signer: Signer,
        /// Fee in nano-HLX (default: 10000)
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
    },
    /// As a registered guardian, approve rotating a lost account to a new public key
    Approve {
        /// Address being recovered
        target: String,
        /// New controlling public key (hex-encoded ML-DSA public key)
        new_public_key: String,
        #[command(flatten)]
        signer: Signer,
        /// Fee in nano-HLX (default: 10000)
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
    },
    /// Show guardian set and any in-progress recovery vote for an address
    Status {
        /// Address to look up
        address: String,
    },
}

pub async fn run(cmd: RecoveryCmd, node: &str) -> Result<()> {
    match cmd {
        RecoveryCmd::RegisterGuardians { guardians, signer, fee } => {
            register_guardians(guardians, signer, fee, node).await
        }
        RecoveryCmd::Approve {
            target,
            new_public_key,
            signer,
            fee,
        } => approve(target, new_public_key, signer, fee, node).await,
        RecoveryCmd::Status { address } => status(address, node).await,
    }
}

async fn register_guardians(
    guardians: Vec<String>,
    signer: Signer,
    fee: Option<u64>,
    node: &str,
) -> Result<()> {
    let (kf, kp) = signer.unlock()?;
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;

    for g in &guardians {
        Address::from_str(g).map_err(|e| anyhow::anyhow!("Invalid guardian address '{}': {}", g, e))?;
    }

    let nonce = super::fetch_nonce(node, &kf.address).await?;

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::RegisterGuardians,
        from: from.clone(),
        to: None,
        amount: 0,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: guardians.join("\n").into_bytes(),
        crypto_version: kp.scheme,
        chain_id: super::resolve_chain_id(node).await?,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };

    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("Registering {} guardians for {}", guardians.len(), kf.address);
    println!("  Fee   : {} nano-HLX", tx.fee);
    println!("  Nonce : {}", nonce);

    let res = super::submit_tx(&tx, node).await?;
    println!();
    super::report_submitted(&res);
    Ok(())
}

async fn approve(
    target: String,
    new_public_key_hex: String,
    signer: Signer,
    fee: Option<u64>,
    node: &str,
) -> Result<()> {
    let (kf, kp) = signer.unlock()?;
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
    let target_addr = Address::from_str(&target)
        .map_err(|e| anyhow::anyhow!("Invalid target address: {}", e))?;
    let new_key_bytes = hex::decode(&new_public_key_hex)
        .map_err(|e| anyhow::anyhow!("Invalid new public key hex: {}", e))?;

    let nonce = super::fetch_nonce(node, &kf.address).await?;

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::ApproveRecovery,
        from: from.clone(),
        to: Some(target_addr),
        amount: 0,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: new_key_bytes,
        crypto_version: kp.scheme,
        chain_id: super::resolve_chain_id(node).await?,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };

    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("Approving recovery of {} to new key", target);
    println!("  Guardian : {}", kf.address);
    println!("  Fee      : {} nano-HLX", tx.fee);
    println!("  Nonce    : {}", nonce);

    let res = super::submit_tx(&tx, node).await?;
    println!();
    super::report_submitted(&res);
    Ok(())
}

async fn status(address: String, node: &str) -> Result<()> {
    // Both are legitimately absent for an account that never set recovery up, so a 404 here is
    // an answer rather than a failure — but anything else still has to be reported. Reading a
    // proxy error page as "no guardians registered" would tell someone their recovery set is
    // gone at the exact moment they are checking whether they can still get their wallet back.
    let guardians = super::get_optional(
        node,
        &format!("/accounts/{}/guardians", address),
        "read the guardian set",
    )
    .await?;
    let recovery = super::get_optional(
        node,
        &format!("/accounts/{}/recovery", address),
        "read the recovery status",
    )
    .await?;

    println!("Recovery status for {}:", address);
    match &guardians {
        None => println!("  Guardians: none registered"),
        Some(g) => println!(
            "  Guardians ({} of {}): {}",
            g["threshold"],
            g["guardians"].as_array().map(|a| a.len()).unwrap_or(0),
            serde_json::to_string(&g["guardians"])?
        ),
    }
    if let Some(recovery) = recovery {
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
    }
    Ok(())
}
