use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};

use crate::fee::{hlx_to_nano, price_and_sign};
use crate::keyfile::KeyFile;


#[derive(Subcommand)]
pub enum TxCmd {
    /// Send HLX to an address
    Send {
        /// Recipient address
        to: String,
        /// Amount in HLX (e.g. 1.5)
        amount: f64,
        /// Wallet key file
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        /// Node nonce override (auto-fetched if omitted)
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Lock HLX as validator stake
    Stake {
        /// Amount in HLX to stake
        amount: f64,
        /// Wallet key file
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Begin unbonding staked HLX (7-day lock before claimable)
    Unstake {
        /// Amount in HLX to unstake
        amount: f64,
        /// Wallet key file
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Claim unbonded stake back to liquid balance (after 7-day unbonding period)
    ClaimUnbonded {
        /// Wallet key file
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Delegate HLX to a validator's pool — earns a share of its block rewards without
    /// running a node, but grants no governance voting power (self-stake for that instead)
    Delegate {
        /// Validator address to delegate to
        validator: String,
        /// Amount in HLX to delegate
        amount: f64,
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Redeem a delegation's current HLX value (principal plus auto-compounded rewards,
    /// minus any slashing) into the same 7-day unbonding queue self-staking uses
    Undelegate {
        /// Validator address to undelegate from
        validator: String,
        /// Amount in HLX to undelegate (its current value, not raw shares)
        amount: f64,
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Move a delegation straight from one validator to another, with no unbonding wait —
    /// the stake keeps earning throughout. It stays slashable for the validator you left for
    /// 7 days, so switching away from one that has already misbehaved does not avoid the hit
    Redelegate {
        /// Validator address to move the delegation away from
        from_validator: String,
        /// Validator address to move it to
        to_validator: String,
        /// Amount in HLX to move (its current value, not raw shares)
        amount: f64,
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Set the commission rate this validator keeps from delegator rewards
    SetCommission {
        /// Commission in basis points (0-5000, i.e. 0%-50%)
        bps: u16,
        #[arg(short, long, default_value = "wallet.json")]
        key: PathBuf,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Check transaction status
    Status {
        /// Transaction hash
        hash: String,
    },
}

pub async fn run(cmd: TxCmd, node: &str) -> Result<()> {
    match cmd {
        TxCmd::Send { to, amount, key, fee, nonce } => {
            send(to, amount, key, fee, nonce, node).await
        }
        TxCmd::Stake { amount, key, fee, nonce } => {
            simple_amount_tx(TxType::Stake, amount, key, fee, nonce, node).await
        }
        TxCmd::Unstake { amount, key, fee, nonce } => {
            simple_amount_tx(TxType::Unstake, amount, key, fee, nonce, node).await
        }
        TxCmd::ClaimUnbonded { key, fee, nonce } => {
            zero_amount_tx(TxType::ClaimUnbonded, key, fee, nonce, node).await
        }
        TxCmd::Delegate { validator, amount, key, fee, nonce } => {
            targeted_amount_tx(TxType::Delegate, validator, amount, key, fee, nonce, node).await
        }
        TxCmd::Undelegate { validator, amount, key, fee, nonce } => {
            targeted_amount_tx(TxType::Undelegate, validator, amount, key, fee, nonce, node).await
        }
        TxCmd::Redelegate { from_validator, to_validator, amount, key, fee, nonce } => {
            redelegate(from_validator, to_validator, amount, key, fee, nonce, node).await
        }
        TxCmd::SetCommission { bps, key, fee, nonce } => {
            set_commission(bps, key, fee, nonce, node).await
        }
        TxCmd::Status { hash } => tx_status(hash, node).await,
    }
}

async fn send(
    to: String,
    amount_hlx: f64,
    key_path: PathBuf,
    fee: Option<u64>,
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
    let to_addr = Address::from_str(&to)
        .map_err(|e| anyhow::anyhow!("Invalid recipient address: {}", e))?;

    let amount_nano = hlx_to_nano(amount_hlx)?;

    // Fetch current nonce from node if not provided
    let nonce = match nonce_override {
        Some(n) => n,
        None => fetch_nonce(node, &kf.address).await.unwrap_or(0),
    };

    // Build and sign transaction
    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        from: from.clone(),
        to: Some(to_addr),
        amount: amount_nano,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: vec![],
        crypto_version: kp.scheme,

        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };

    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("Sending {:.9} HLX to {}", amount_hlx, to);
    println!("  From  : {}", kf.address);
    println!("  Fee   : {} nano-HLX", tx.fee);
    println!("  Nonce : {}", nonce);

    submit_tx(&tx, node).await
}

/// Stake / Unstake — sends `amount_hlx` to self (or zero `to`)
async fn simple_amount_tx(
    tx_type: TxType,
    amount_hlx: f64,
    key_path: PathBuf,
    fee: Option<u64>,
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
    let amount_nano = hlx_to_nano(amount_hlx)?;
    let nonce = match nonce_override {
        Some(n) => n,
        None => fetch_nonce(node, &kf.address).await.unwrap_or(0),
    };
    let mut tx = Transaction {
        version: 1,
        tx_type,
        from: from.clone(),
        to: None,
        amount: amount_nano,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: vec![],
        crypto_version: kp.scheme,
        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    submit_tx(&tx, node).await
}

/// Transactions with no amount (ClaimUnbonded, etc.)
async fn zero_amount_tx(
    tx_type: TxType,
    key_path: PathBuf,
    fee: Option<u64>,
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
    let nonce = match nonce_override {
        Some(n) => n,
        None => fetch_nonce(node, &kf.address).await.unwrap_or(0),
    };
    let mut tx = Transaction {
        version: 1,
        tx_type,
        from: from.clone(),
        to: None,
        amount: 0,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: vec![],
        crypto_version: kp.scheme,
        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    submit_tx(&tx, node).await
}

/// Delegate / Undelegate — sends `amount_hlx` (the delegation amount, or its current value
/// to redeem) to a named validator address.
async fn targeted_amount_tx(
    tx_type: TxType,
    validator: String,
    amount_hlx: f64,
    key_path: PathBuf,
    fee: Option<u64>,
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
    let validator_addr = Address::from_str(&validator)
        .map_err(|e| anyhow::anyhow!("Invalid validator address: {}", e))?;
    let amount_nano = hlx_to_nano(amount_hlx)?;
    let nonce = match nonce_override {
        Some(n) => n,
        None => fetch_nonce(node, &kf.address).await.unwrap_or(0),
    };
    let mut tx = Transaction {
        version: 1,
        tx_type,
        from: from.clone(),
        to: Some(validator_addr),
        amount: amount_nano,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: vec![],
        crypto_version: kp.scheme,
        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("  From      : {}", kf.address);
    println!("  Validator : {}", validator);
    println!("  Amount    : {:.9} HLX", amount_hlx);
    println!("  Fee       : {} nano-HLX", tx.fee);
    println!("  Nonce     : {}", nonce);

    submit_tx(&tx, node).await
}

async fn redelegate(
    from_validator: String,
    to_validator: String,
    amount_hlx: f64,
    key_path: PathBuf,
    fee: Option<u64>,
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
    let src = Address::from_str(&from_validator)
        .map_err(|e| anyhow::anyhow!("Invalid source validator address: {}", e))?;
    let dst = Address::from_str(&to_validator)
        .map_err(|e| anyhow::anyhow!("Invalid destination validator address: {}", e))?;
    let amount_nano = hlx_to_nano(amount_hlx)?;
    let nonce = match nonce_override {
        Some(n) => n,
        None => fetch_nonce(node, &kf.address).await.unwrap_or(0),
    };
    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::Redelegate,
        from: from.clone(),
        to: Some(dst),
        amount: amount_nano,
        fee: 0, // replaced by price_and_sign below
        nonce,
        // The destination rides in `to`; the source has to travel in `data` as its address
        // string — a transaction has only one `to` field and this is the one operation that
        // names two validators.
        data: src.to_string().into_bytes(),
        crypto_version: kp.scheme,
        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("  From      : {}", kf.address);
    println!("  Moving    : {} -> {}", from_validator, to_validator);
    println!("  Amount    : {:.9} HLX", amount_hlx);
    println!("  Fee       : {} nano-HLX", tx.fee);
    println!("  Nonce     : {}", nonce);
    println!();
    println!("  Note: this stake stays slashable for {} for 7 days.", from_validator);

    submit_tx(&tx, node).await
}

async fn set_commission(
    bps: u16,
    key_path: PathBuf,
    fee: Option<u64>,
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
    let nonce = match nonce_override {
        Some(n) => n,
        None => fetch_nonce(node, &kf.address).await.unwrap_or(0),
    };
    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::SetCommission,
        from: from.clone(),
        to: None,
        amount: 0,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: bps.to_le_bytes().to_vec(),
        crypto_version: kp.scheme,
        signature: Signature::from_bytes(vec![]),
        public_key: kp.public.clone(),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("  Validator  : {}", kf.address);
    println!("  Commission : {} bps ({:.2}%)", bps, bps as f64 / 100.0);
    println!("  Fee        : {} nano-HLX", tx.fee);
    println!("  Nonce      : {}", nonce);

    submit_tx(&tx, node).await
}

async fn submit_tx(tx: &Transaction, node: &str) -> Result<()> {
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

    println!("  Tx hash : {}", res["tx_hash"].as_str().unwrap_or("?"));
    println!("  Status  : {}", res["status"].as_str().unwrap_or("?"));
    Ok(())
}

/// Read a passphrase without echoing it.
///
/// Named `rpassword_read` and taking a `_prompt` it ignored, this used to be a plain
/// `stdin().read_line` — so every wallet passphrase was typed in clear text and left sitting in
/// the terminal's scrollback. The name described the intent; nothing implemented it.
pub(crate) fn rpassword_read(prompt: &str) -> Result<String> {
    Ok(rpassword::prompt_password(prompt)?.trim().to_string())
}

async fn fetch_nonce(node: &str, address: &str) -> Result<u64> {
    let res: serde_json::Value = reqwest::get(format!("{}/accounts/{}", node, address))
        .await?
        .json()
        .await?;
    Ok(res["nonce"].as_u64().unwrap_or(0))
}

async fn tx_status(hash: String, node: &str) -> Result<()> {
    let response = reqwest::get(format!("{}/transactions/{}", node, hash)).await?;
    // Whether the transaction exists is the HTTP status code's job, not the body's. Since
    // receipts landed, `error` in a 200 body is the executor's reason a real, committed
    // transaction failed — treating that as "not found" made `tx status` answer
    // "Not found: insufficient balance" for a transaction it had just located, denying the
    // transfer existed while quoting why it was rejected.
    let found = response.status().is_success();
    let res: serde_json::Value = response.json().await?;
    if !found {
        bail!(
            "Not found: {}",
            res["error"].as_str().unwrap_or("no such transaction")
        );
    }

    println!("Transaction: {}", hash);
    println!("─────────────────────────────────────────");
    println!("  Status : {}", res["status"].as_str().unwrap_or("?"));
    // The whole point of a receipt: a failed transfer still cost a fee, and the sender is owed
    // the reason rather than having to read the node's log.
    if let Some(reason) = res["error"].as_str() {
        println!("  Reason : {}", reason);
    }
    if let Some(height) = res["block_height"].as_u64() {
        println!("  Block  : #{}", height);
    }
    Ok(())
}

#[cfg(test)]
mod tx_status_tests {
    use super::*;
    use axum::{http::StatusCode, routing::get, Router};
    use serde_json::json;

    /// Serves one canned `/transactions/{hash}` response on a real socket, so `tx_status` is
    /// exercised through the same reqwest path it uses in production — including the HTTP
    /// status code, which is the whole thing under test here.
    async fn mock_node(code: StatusCode, body: serde_json::Value) -> String {
        let app = Router::new().route(
            "/transactions/:hash",
            get(move || {
                let body = body.clone();
                async move { (code, axum::Json(body)) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{}", addr)
    }

    /// The regression. A transaction the executor rejected comes back 200 with `status: failed`
    /// and `error` carrying the reason. `tx_status` treated any `error` field as "no such
    /// transaction" and bailed — so the one command a user runs to find out what happened to
    /// their transfer denied it existed, while quoting the reason it failed.
    #[tokio::test]
    async fn a_failed_transaction_is_reported_not_called_missing() {
        let node = mock_node(
            StatusCode::OK,
            json!({
                "status": "failed",
                "error": "insufficient balance: need 5000010820, have 0",
                "block_height": 19,
            }),
        )
        .await;

        let result = tx_status("ab".repeat(32), &node).await;
        assert!(
            result.is_ok(),
            "a located, failed transaction must not be reported as not found: {:?}",
            result.err()
        );
    }

    /// The other side of the same coin: a hash the node has never seen still has to fail loudly,
    /// or the fix would have traded one lie for another.
    #[tokio::test]
    async fn an_unknown_hash_still_reports_not_found() {
        let node = mock_node(
            StatusCode::NOT_FOUND,
            json!({ "error": "transaction not found" }),
        )
        .await;

        let err = tx_status("00".repeat(32), &node)
            .await
            .expect_err("an unknown hash must not report as a real transaction");
        assert!(err.to_string().contains("Not found"), "got: {}", err);
    }
}
