use anyhow::{bail, Context, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};

use crate::fee::{price_and_sign, Hlx};
use crate::passphrase::Signer;


#[derive(Subcommand)]
pub enum TxCmd {
    /// Send HLX to an address
    Send {
        /// Recipient address
        to: String,
        /// Amount in HLX (e.g. 1.5)
        amount: Hlx,
        #[command(flatten)]
        signer: Signer,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        /// Node nonce override (auto-fetched if omitted)
        #[arg(long)]
        nonce: Option<u64>,
        /// A note for the recipient, carried in the transfer: UTF-8, at most 256 bytes. An
        /// exchange that receives on one address tells deposits apart by it.
        #[arg(long)]
        memo: Option<String>,
        /// Sign without contacting any node and print the signed transaction as JSON instead of
        /// submitting it — for a key on a machine that is never online. Needs --nonce and --fee;
        /// signs for HELIX_CHAIN_ID, else the chain this release is for. Submit the output from
        /// an online machine with `helix tx submit`.
        #[arg(long, requires_all = ["nonce", "fee"])]
        offline: bool,
        /// With --offline: write the signed transaction to this file instead of stdout
        #[arg(long, requires = "offline")]
        output: Option<std::path::PathBuf>,
    },
    /// Submit a transaction signed elsewhere (`tx send --offline`): a JSON file, or `-` for stdin
    Submit {
        /// Path of the signed transaction, or `-` to read it from stdin
        file: String,
    },
    /// Lock HLX as validator stake
    Stake {
        /// Amount in HLX to stake
        amount: Hlx,
        #[command(flatten)]
        signer: Signer,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Begin unbonding staked HLX (7-day lock before claimable)
    Unstake {
        /// Amount in HLX to unstake
        amount: Hlx,
        #[command(flatten)]
        signer: Signer,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Rejoin the active validator set after being downtime-jailed — see `helix account
    /// <address>` for whether you're jailed and the height you can unjail from. Not
    /// automatic on purpose: submit this once your node is actually back and connected,
    /// not before, or you'll just get jailed again once the same downtime resumes counting.
    Unjail {
        #[command(flatten)]
        signer: Signer,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Claim unbonded stake back to liquid balance (after 7-day unbonding period)
    ClaimUnbonded {
        #[command(flatten)]
        signer: Signer,
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
        amount: Hlx,
        #[command(flatten)]
        signer: Signer,
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
        amount: Hlx,
        #[command(flatten)]
        signer: Signer,
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
        amount: Hlx,
        #[command(flatten)]
        signer: Signer,
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
        #[command(flatten)]
        signer: Signer,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long)]
        nonce: Option<u64>,
    },
    /// Pay this validator's own rewards to another address, e.g. a wallet whose key never
    /// touches the server. Your delegators' share is not affected.
    SetRewardAddress {
        /// Address the rewards go to
        #[arg(required_unless_present = "clear", conflicts_with = "clear")]
        address: Option<String>,
        /// Pay rewards to this validator's own address again
        #[arg(long)]
        clear: bool,
        #[command(flatten)]
        signer: Signer,
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
        TxCmd::Send { to, amount, signer, fee, nonce, memo, offline, output } => {
            let how = Delivery { offline, output };
            send(to, amount, memo, signer, fee, nonce, how, node).await
        }
        TxCmd::Submit { file } => submit_signed(&file, node).await,
        TxCmd::Stake { amount, signer, fee, nonce } => {
            simple_amount_tx(TxType::Stake, amount, signer, fee, nonce, node).await
        }
        TxCmd::Unstake { amount, signer, fee, nonce } => {
            simple_amount_tx(TxType::Unstake, amount, signer, fee, nonce, node).await
        }
        TxCmd::Unjail { signer, fee, nonce } => {
            zero_amount_tx(TxType::Unjail, signer, fee, nonce, node).await
        }
        TxCmd::ClaimUnbonded { signer, fee, nonce } => {
            zero_amount_tx(TxType::ClaimUnbonded, signer, fee, nonce, node).await
        }
        TxCmd::Delegate { validator, amount, signer, fee, nonce } => {
            targeted_amount_tx(TxType::Delegate, validator, amount, signer, fee, nonce, node).await
        }
        TxCmd::Undelegate { validator, amount, signer, fee, nonce } => {
            targeted_amount_tx(TxType::Undelegate, validator, amount, signer, fee, nonce, node)
                .await
        }
        TxCmd::Redelegate { from_validator, to_validator, amount, signer, fee, nonce } => {
            redelegate(from_validator, to_validator, amount, signer, fee, nonce, node).await
        }
        TxCmd::SetCommission { bps, signer, fee, nonce } => {
            set_commission(bps, signer, fee, nonce, node).await
        }
        TxCmd::SetRewardAddress { address, clear, signer, fee, nonce } => {
            set_reward_address(address, clear, signer, fee, nonce, node).await
        }
        TxCmd::Status { hash } => tx_status(hash, node).await,
    }
}

/// Where a signed transfer goes: to the node, or — offline — out as JSON for `tx submit`.
struct Delivery {
    offline: bool,
    output: Option<std::path::PathBuf>,
}

#[allow(clippy::too_many_arguments)]
async fn send(
    to: String,
    amount: Hlx,
    memo: Option<String>,
    signer: Signer,
    fee: Option<u64>,
    nonce_override: Option<u64>,
    how: Delivery,
    node: &str,
) -> Result<()> {
    // Checked before the wallet is unlocked, so a memo that cannot be sent never costs a
    // passphrase prompt.
    let data = memo_bytes(memo.as_deref())?;
    let (kf, kp) = signer.unlock()?;
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
    let to_addr = Address::from_str(&to)
        .map_err(|e| anyhow::anyhow!("Invalid recipient address: {}", e))?;

    let amount_nano = amount.nano();

    // Fetch current nonce from node if not provided (offline, clap has made --nonce required)
    let nonce = match nonce_override {
        Some(n) => n,
        None => super::fetch_nonce(node, &kf.address).await?,
    };
    let chain_id = if how.offline {
        super::offline_chain_id()?
    } else {
        super::resolve_chain_id(node).await?
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
        data,
        crypto_version: kp.scheme,
        chain_id,

        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
    };

    // Offline, `fee` is always given (clap), and a given fee is signed without asking anyone.
    price_and_sign(&mut tx, fee, &kp, node).await?;

    if how.offline {
        return deliver_offline(&tx, how.output.as_deref());
    }

    println!("Sending {} HLX to {}", amount, to);
    println!("  From  : {}", kf.address);
    println!("  Fee   : {} nano-HLX", tx.fee);
    println!("  Nonce : {}", nonce);
    if let Some(memo) = tx.memo() {
        println!("  Memo  : {memo}");
    }

    submit_tx(&tx, node).await
}

/// A memo as the bytes a transfer carries. The chain reads a transfer's `data` as its memo only
/// when it is UTF-8 of at most [`helix_core::MEMO_MAX_BYTES`] (`Transaction::memo`); anything
/// longer would still be signed, carried and paid for, and then shown to nobody — so it is
/// refused here instead, before anything is signed.
fn memo_bytes(memo: Option<&str>) -> Result<Vec<u8>> {
    let Some(memo) = memo else { return Ok(Vec::new()) };
    if memo.is_empty() {
        bail!("--memo is empty; leave it out to send without one");
    }
    if memo.len() > helix_core::MEMO_MAX_BYTES {
        bail!(
            "the memo is {} bytes; a memo holds at most {} (UTF-8 bytes, not characters)",
            memo.len(),
            helix_core::MEMO_MAX_BYTES
        );
    }
    Ok(memo.as_bytes().to_vec())
}

/// The signed transaction as the JSON body `POST /transactions` takes — exactly what
/// [`super::submit_tx`] would have sent. One line: its signature is 3,309 numbers.
fn signed_json(tx: &Transaction) -> Result<String> {
    Ok(serde_json::to_string(tx)?)
}

/// Write an offline-signed transfer out, and say on stderr what was signed. Stdout carries only
/// the JSON, so `helix tx send … --offline | helix tx submit -` works across a pipe.
fn deliver_offline(tx: &Transaction, output: Option<&std::path::Path>) -> Result<()> {
    let json = signed_json(tx)?;
    match output {
        Some(path) => {
            use std::io::Write;
            // A signed transaction is spendable by whoever submits it; overwriting another one
            // by accident would lose track of what was signed.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .with_context(|| {
                    format!("could not create {} (it must not exist yet)", path.display())
                })?;
            writeln!(file, "{json}")?;
        }
        None => println!("{json}"),
    }
    eprintln!("Signed offline — NOT submitted.");
    eprintln!("  Tx hash  : {}", tx.hash().to_hex());
    eprintln!("  From     : {}", tx.from);
    if let Some(to) = &tx.to {
        eprintln!("  To       : {to}");
    }
    eprintln!("  Amount   : {} HLX", helix_core::fee::nano_as_hlx(tx.amount));
    eprintln!("  Fee      : {} nano-HLX", tx.fee);
    eprintln!("  Nonce    : {}", tx.nonce);
    eprintln!("  Chain    : {}", tx.chain_id.to_hex());
    if let Some(memo) = tx.memo() {
        eprintln!("  Memo     : {memo}");
    }
    eprintln!(
        "  Size     : {} bytes in a block — the fee must be at least the chain's base fee per \
         byte times this",
        helix_core::fee::wallet_priced_size(tx)
    );
    if let Some(path) = output {
        eprintln!("  Written  : {}", path.display());
    }
    eprintln!("Submit it from an online machine with: helix tx submit <file>");
    Ok(())
}

/// Largest signed-transaction file `tx submit` reads. A transaction is bounded by the block size
/// (2 MB), and its JSON by about four times its bytes; anything bigger is not one.
const MAX_SIGNED_TX_JSON: u64 = 16 * 1024 * 1024;

/// Read a transaction signed elsewhere and check what can be checked without the chain: that it
/// parses, and that its signature verifies under the key it carries. A file damaged in transit
/// is refused here with that reason, not by a node with a less specific one. Whether the key may
/// sign for `from`, the nonce, the fee and the chain are the node's to judge.
fn read_signed(text: &str) -> Result<Transaction> {
    let tx: Transaction = serde_json::from_str(text.trim()).context(
        "this is not a signed Helix transaction (expected the JSON `tx send --offline` writes)",
    )?;
    tx.verify_own_signature().map_err(|e| {
        anyhow::anyhow!(
            "the transaction's signature does not verify ({e}) — the file was changed or damaged"
        )
    })?;
    Ok(tx)
}

async fn submit_signed(file: &str, node: &str) -> Result<()> {
    use std::io::Read;
    let mut text = String::new();
    if file == "-" {
        std::io::stdin().take(MAX_SIGNED_TX_JSON).read_to_string(&mut text)?;
    } else {
        std::fs::File::open(file)
            .with_context(|| format!("could not open {file}"))?
            .take(MAX_SIGNED_TX_JSON)
            .read_to_string(&mut text)
            .with_context(|| format!("could not read {file}"))?;
    }
    let tx = read_signed(&text)?;

    println!("Submitting {:?} signed offline", tx.tx_type);
    println!("  Tx hash : {}", tx.hash().to_hex());
    println!("  From    : {}", tx.from);
    if let Some(to) = &tx.to {
        println!("  To      : {to}");
    }
    println!("  Amount  : {} HLX", helix_core::fee::nano_as_hlx(tx.amount));
    println!("  Fee     : {} nano-HLX", tx.fee);
    println!("  Nonce   : {}", tx.nonce);
    if let Some(memo) = tx.memo() {
        println!("  Memo    : {memo}");
    }
    submit_tx(&tx, node).await
}

/// Stake / Unstake — sends `amount` to self (or zero `to`)
async fn simple_amount_tx(
    tx_type: TxType,
    amount: Hlx,
    signer: Signer,
    fee: Option<u64>,
    nonce_override: Option<u64>,
    node: &str,
) -> Result<()> {
    let (kf, kp) = signer.unlock()?;
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
    let amount_nano = amount.nano();
    let nonce = match nonce_override {
        Some(n) => n,
        None => super::fetch_nonce(node, &kf.address).await?,
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
        chain_id: super::resolve_chain_id(node).await?,
        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    submit_tx(&tx, node).await
}

/// Transactions with no amount (ClaimUnbonded, etc.)
async fn zero_amount_tx(
    tx_type: TxType,
    signer: Signer,
    fee: Option<u64>,
    nonce_override: Option<u64>,
    node: &str,
) -> Result<()> {
    let (kf, kp) = signer.unlock()?;
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
    let nonce = match nonce_override {
        Some(n) => n,
        None => super::fetch_nonce(node, &kf.address).await?,
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
        chain_id: super::resolve_chain_id(node).await?,
        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    submit_tx(&tx, node).await
}

/// Delegate / Undelegate — sends `amount` (the delegation amount, or its current value
/// to redeem) to a named validator address.
async fn targeted_amount_tx(
    tx_type: TxType,
    validator: String,
    amount: Hlx,
    signer: Signer,
    fee: Option<u64>,
    nonce_override: Option<u64>,
    node: &str,
) -> Result<()> {
    let (kf, kp) = signer.unlock()?;
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
    let validator_addr = Address::from_str(&validator)
        .map_err(|e| anyhow::anyhow!("Invalid validator address: {}", e))?;
    let amount_nano = amount.nano();
    let nonce = match nonce_override {
        Some(n) => n,
        None => super::fetch_nonce(node, &kf.address).await?,
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
        chain_id: super::resolve_chain_id(node).await?,
        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("  From      : {}", kf.address);
    println!("  Validator : {}", validator);
    println!("  Amount    : {} HLX", amount);
    println!("  Fee       : {} nano-HLX", tx.fee);
    println!("  Nonce     : {}", nonce);

    submit_tx(&tx, node).await
}

async fn redelegate(
    from_validator: String,
    to_validator: String,
    amount: Hlx,
    signer: Signer,
    fee: Option<u64>,
    nonce_override: Option<u64>,
    node: &str,
) -> Result<()> {
    let (kf, kp) = signer.unlock()?;
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
    let src = Address::from_str(&from_validator)
        .map_err(|e| anyhow::anyhow!("Invalid source validator address: {}", e))?;
    let dst = Address::from_str(&to_validator)
        .map_err(|e| anyhow::anyhow!("Invalid destination validator address: {}", e))?;
    let amount_nano = amount.nano();
    let nonce = match nonce_override {
        Some(n) => n,
        None => super::fetch_nonce(node, &kf.address).await?,
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
        chain_id: super::resolve_chain_id(node).await?,
        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("  From      : {}", kf.address);
    println!("  Moving    : {} -> {}", from_validator, to_validator);
    println!("  Amount    : {} HLX", amount);
    println!("  Fee       : {} nano-HLX", tx.fee);
    println!("  Nonce     : {}", nonce);
    println!();
    println!("  Note: this stake stays slashable for {} for 7 days.", from_validator);

    submit_tx(&tx, node).await
}

async fn set_commission(
    bps: u16,
    signer: Signer,
    fee: Option<u64>,
    nonce_override: Option<u64>,
    node: &str,
) -> Result<()> {
    let (kf, kp) = signer.unlock()?;
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
    let nonce = match nonce_override {
        Some(n) => n,
        None => super::fetch_nonce(node, &kf.address).await?,
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
        chain_id: super::resolve_chain_id(node).await?,
        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("  Validator  : {}", kf.address);
    println!("  Commission : {} bps ({:.2}%)", bps, bps as f64 / 100.0);
    println!("  Fee        : {} nano-HLX", tx.fee);
    println!("  Nonce      : {}", nonce);

    submit_tx(&tx, node).await
}

/// `SetRewardAddress` (#229). `--clear` is the same transaction pointed at the validator itself —
/// the chain has one rule for both, so the CLI does not invent a second.
async fn set_reward_address(
    address: Option<String>,
    clear: bool,
    signer: Signer,
    fee: Option<u64>,
    nonce_override: Option<u64>,
    node: &str,
) -> Result<()> {
    // Checked before the passphrase prompt: a typo should cost nobody a round of typing.
    let payout = match (&address, clear) {
        (Some(a), false) => Some(
            Address::from_str(a).map_err(|e| anyhow::anyhow!("Invalid reward address: {}", e))?,
        ),
        _ => None,
    };
    let (kf, kp) = signer.unlock()?;
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;
    let payout = payout.unwrap_or_else(|| from.clone());
    let nonce = match nonce_override {
        Some(n) => n,
        None => super::fetch_nonce(node, &kf.address).await?,
    };
    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::SetRewardAddress,
        from: from.clone(),
        to: Some(payout.clone()),
        amount: 0,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: vec![],
        crypto_version: kp.scheme,
        chain_id: super::resolve_chain_id(node).await?,
        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
    };
    price_and_sign(&mut tx, fee, &kp, node).await?;

    println!("  Validator  : {}", kf.address);
    if payout == from {
        println!("  Rewards to : this validator's own address");
    } else {
        println!("  Rewards to : {}", payout);
        println!("               Your own share and commission only — delegators keep theirs.");
    }
    println!("  Fee        : {} nano-HLX", tx.fee);
    println!("  Nonce      : {}", nonce);

    submit_tx(&tx, node).await
}

async fn submit_tx(tx: &Transaction, node: &str) -> Result<()> {
    let res = super::submit_tx(tx, node).await?;
    super::report_submitted(&res);
    Ok(())
}

/// The one command that talks to a node without going through `super::get_optional`, on purpose:
/// a 404 here carries information no shared helper can express. "Expired" and "never seen" are
/// both 404s and mean opposite things to a sender, so this path needs the body *and* the status,
/// not `Option<Value>`. Left deliberately, not overlooked.
async fn tx_status(hash: String, node: &str) -> Result<()> {
    let response = reqwest::get(format!("{}/transactions/{}", node, hash)).await?;
    // Whether the transaction exists is the HTTP status code's job, not the body's. Since
    // receipts landed, `error` in a 200 body is the executor's reason a real, committed
    // transaction failed — treating that as "not found" made `tx status` answer
    // "Not found: insufficient balance" for a transaction it had just located, denying the
    // transfer existed while quoting why it was rejected.
    let found = response.status().is_success();
    let body = super::read_body_capped(response).await?;
    let res: serde_json::Value = serde_json::from_str(&body).with_context(|| {
        format!("the node at {node} did not answer the receipt lookup with JSON")
    })?;
    if !found {
        // "Expired" and "never seen" are both 404s — the transaction is genuinely not on the
        // chain either way — but they mean opposite things to a sender, and only one of them
        // calls for resubmitting (backlog #156). Leading with "Not found" for an expiry would
        // deny a transaction that demonstrably existed and was accepted by this node.
        if res["status"].as_str() == Some("expired") {
            bail!(
                "Expired: {}",
                res["error"].as_str().unwrap_or("it was dropped from the pool before inclusion")
            );
        }
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
    if let Some(memo) = res["memo"].as_str() {
        println!("  Memo   : {}", memo);
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

    /// Backlog #156: an expired transaction must not be reported the way a mistyped hash is.
    /// Both are 404s, but only one of them means "this existed, we accepted it, and it aged out —
    /// send it again". Leading with "Not found" there denies a transaction the node did have.
    #[tokio::test]
    async fn an_expired_transaction_is_not_announced_as_not_found() {
        let node = mock_node(
            StatusCode::NOT_FOUND,
            json!({
                "hash": "ab".repeat(32),
                "status": "expired",
                "error": "transaction abab… expired before it was included in a block",
            }),
        )
        .await;

        let err = tx_status("ab".repeat(32), &node).await.unwrap_err().to_string();

        assert!(err.starts_with("Expired:"), "must lead with what happened: {err}");
        assert!(!err.contains("Not found"), "and must not also deny it existed: {err}");
    }

    /// The control: a hash the node never saw must still be reported as not found, or the
    /// distinction carries no information.
    #[tokio::test]
    async fn an_unknown_transaction_is_still_announced_as_not_found() {
        let node = mock_node(
            StatusCode::NOT_FOUND,
            json!({ "error": "transaction cdcd… not found" }),
        )
        .await;

        let err = tx_status("cd".repeat(32), &node).await.unwrap_err().to_string();

        assert!(err.starts_with("Not found:"), "{err}");
    }
}

#[cfg(test)]
mod command_tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        tx: TxCmd,
    }

    fn parse(args: &[&str]) -> std::result::Result<TxCmd, clap::Error> {
        Cli::try_parse_from(std::iter::once("tx").chain(args.iter().copied())).map(|c| c.tx)
    }

    #[test]
    fn an_address_or_clear_is_required_and_never_both() {
        let addr = "hlxbx7oYT7n1nidYCxLrk1LUQ93CTXFrGWNt";
        match parse(&["set-reward-address", addr]).expect("an address parses") {
            TxCmd::SetRewardAddress { address, clear, .. } => {
                assert_eq!(address.as_deref(), Some(addr));
                assert!(!clear);
            }
            _ => panic!("wrong command"),
        }
        match parse(&["set-reward-address", "--clear"]).expect("--clear parses") {
            TxCmd::SetRewardAddress { address, clear, .. } => {
                assert_eq!(address, None);
                assert!(clear);
            }
            _ => panic!("wrong command"),
        }
        // Neither: a bare command would otherwise quietly mean "clear", and a forgotten argument
        // must not send rewards back to the hot key.
        assert!(parse(&["set-reward-address"]).is_err());
        assert!(parse(&["set-reward-address", addr, "--clear"]).is_err());
    }

    const TO: &str = "hlxbx7oYT7n1nidYCxLrk1LUQ93CTXFrGWNt";

    /// Offline, nothing may be looked up — so the two things a node would otherwise supply are
    /// required, and `--output` means nothing without `--offline`.
    #[test]
    fn offline_needs_a_nonce_and_a_fee_and_output_needs_offline() {
        let full = ["send", TO, "1", "--offline", "--nonce", "0", "--fee", "10000"];
        assert!(parse(&full).is_ok());
        assert!(parse(&["send", TO, "1", "--offline", "--fee", "10000"]).is_err());
        assert!(parse(&["send", TO, "1", "--offline", "--nonce", "0"]).is_err());
        assert!(parse(&["send", TO, "1", "--output", "signed.json"]).is_err());
    }

    #[test]
    fn a_memo_is_refused_where_the_chain_would_show_nobody() {
        assert!(memo_bytes(None).unwrap().is_empty());
        assert_eq!(memo_bytes(Some("deposit 4711")).unwrap(), b"deposit 4711");
        assert!(memo_bytes(Some("")).is_err(), "an empty memo is a mistake, not a choice");
        let limit = "x".repeat(helix_core::MEMO_MAX_BYTES);
        assert!(memo_bytes(Some(&limit)).is_ok());
        assert!(memo_bytes(Some(&format!("{limit}x"))).is_err());
        // The limit is bytes: 86 euro signs are 258 of them.
        let euros = "€".repeat(helix_core::MEMO_MAX_BYTES / 3 + 1);
        let refused = memo_bytes(Some(&euros)).unwrap_err().to_string();
        assert!(refused.contains("bytes"), "{refused}");
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("helix-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The whole offline path against a node address nothing listens on: if signing asked
    /// anyone for anything — a nonce, a fee, which chain — it could not finish.
    #[tokio::test]
    async fn an_offline_transfer_is_signed_without_any_node_and_submits_as_written() {
        let dir = temp_dir("offline");
        let kp = helix_crypto::KeyPair::generate();
        let key = dir.join("cold.json");
        helix_crypto::keyfile::KeyFile::from_keypair_plain(&kp).save(&key).unwrap();
        let out = dir.join("signed.json");
        let signer = Signer { key, passphrase_file: None };
        let how = Delivery { offline: true, output: Some(out.clone()) };
        let amount: Hlx = "2.01".parse().unwrap();
        let dead_node = "http://127.0.0.1:1";

        let sent = send(TO.into(), amount, Some("deposit 4711".into()), signer, Some(12_000),
            Some(7), how, dead_node).await;
        let written = std::fs::read_to_string(&out);
        std::fs::remove_dir_all(&dir).ok();
        sent.expect("offline signing must not need a node");

        let tx = read_signed(&written.unwrap()).expect("what was written is a signed transaction");
        assert_eq!(tx.amount, 2_010_000_000);
        assert_eq!((tx.fee, tx.nonce), (12_000, 7));
        assert_eq!(tx.memo(), Some("deposit 4711"));
        assert_eq!(tx.to.as_ref().map(|a| a.to_string()).as_deref(), Some(TO));
        assert_eq!(tx.chain_id, helix_core::default_chain_id());
    }

    #[test]
    fn a_signed_transaction_that_was_changed_is_refused_before_it_is_sent() {
        let kp = helix_crypto::KeyPair::generate();
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: Address::from_public_key(&kp.public),
            to: Some(Address::from_str(TO).unwrap()),
            amount: 5,
            fee: 10_000,
            nonce: 0,
            data: b"a".to_vec(),
            crypto_version: kp.scheme,
            chain_id: helix_core::default_chain_id(),
            signature: Signature::from_bytes(vec![]),
            public_key: Some(kp.public.clone()),
        };
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();
        let json = signed_json(&tx).unwrap();
        assert_eq!(read_signed(&json).unwrap().hash(), tx.hash(), "it reads back as signed");

        let changed = json.replacen("\"amount\":5", "\"amount\":6", 1);
        assert_ne!(changed, json, "the premise: the amount was rewritten");
        let refused = read_signed(&changed).unwrap_err().to_string();
        assert!(refused.contains("does not verify"), "{refused}");
        assert!(read_signed("not json").is_err());
    }
}
