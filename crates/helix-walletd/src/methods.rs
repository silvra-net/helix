//! The RPC methods, with Bitcoin Core's names, parameters and answer shapes — what an exchange's
//! Bitcoin-family integration already calls.
//!
//! Where Helix differs, the answer says so rather than pretend:
//! - one transaction pays one recipient, so `sendmany` is refused with the reason;
//! - a block is final (BFT), so one confirmation is final; there are no reorganisations;
//! - a send the chain charged but did not apply, or one whose nonce another transaction used,
//!   shows `confirmations: -1` — as Bitcoin Core shows a conflicted transaction — so no client
//!   waiting for confirmations ever counts it as paid;
//! - `getblock` and `getrawtransaction` show accounts, not coins: a transaction's outputs (`vout`)
//!   are whom its execution credited, read from the block's balance record (#260) — a transfer
//!   that failed credited nobody and has none — and its input (`vin`) is the account it came from;
//! - a serialized block or transaction (`getblock` verbosity 0, `getrawtransaction` without
//!   `verbose`) is refused: Helix's are not in Bitcoin's format, and bytes no client can read
//!   would only look like an answer.

use serde::Serialize;

use crate::amount::Hlx;
use crate::daemon::Daemon;
use crate::ledger::{Category, Entry};
use crate::node::{parse_delta, BalanceChange};
use crate::rpc::{code, result, Params, RpcError, RpcResult};

pub const METHODS: &[&str] = &[
    "backupwallet",
    "estimatesmartfee",
    "getaddressinfo",
    "getbalance",
    "getbestblockhash",
    "getblock",
    "getblockchaininfo",
    "getblockcount",
    "getblockhash",
    "getconnectioncount",
    "getinfo",
    "getnetworkinfo",
    "getnewaddress",
    "getrawtransaction",
    "getreceivedbyaddress",
    "gettransaction",
    "getunconfirmedbalance",
    "getwalletinfo",
    "help",
    "keypoolrefill",
    "listsinceblock",
    "listtransactions",
    "ping",
    "sendmany",
    "sendtoaddress",
    "settxfee",
    "uptime",
    "validateaddress",
    "walletlock",
    "walletpassphrase",
];

/// Bitcoin Core's numeric version for this release, as `getinfo` and `getnetworkinfo` state it:
/// 0.20.2 → 200200.
pub fn version_number() -> u32 {
    version_of(env!("CARGO_PKG_VERSION"))
}

fn version_of(text: &str) -> u32 {
    let mut parts = text.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let (major, minor, patch) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    major * 1_000_000 + minor * 10_000 + patch * 100
}

/// Whom a transaction paid, as Bitcoin outputs: every account its execution credited — the
/// recipient of a transfer, whoever a contract paid — net, in the order the record names them.
/// A transaction that failed credited nobody and has none; the sender's own debit and the
/// validator's share of the fee are not payments. `changes` are the transaction's own entries.
pub fn payouts<'a>(changes: impl Iterator<Item = &'a BalanceChange>) -> Result<Vec<(String, i128)>, RpcError> {
    let mut out: Vec<(String, i128)> = Vec::new();
    for c in changes.filter(|c| c.kind == "transaction" || c.kind == "contract") {
        let delta = parse_delta(&c.delta_nano).map_err(misc)?;
        match out.iter_mut().find(|(account, _)| *account == c.account) {
            Some((_, total)) => *total += delta,
            None => out.push((c.account.clone(), delta)),
        }
    }
    out.retain(|(_, total)| *total > 0);
    Ok(out)
}

#[derive(Serialize)]
struct ScriptPubKey {
    asm: String,
    hex: String,
    #[serde(rename = "reqSigs")]
    req_sigs: u32,
    /// A Helix address is a hash of a public key — Bitcoin's `pubkeyhash`, in kind if not in bytes.
    #[serde(rename = "type")]
    kind: &'static str,
    address: String,
    addresses: Vec<String>,
}

#[derive(Serialize)]
struct Vout {
    value: Hlx,
    n: u32,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKey,
}

#[derive(Serialize)]
struct Vin {
    address: String,
    sequence: u32,
}

#[derive(Serialize)]
struct RawTx {
    txid: String,
    hash: String,
    version: u32,
    locktime: u32,
    vin: Vec<Vin>,
    vout: Vec<Vout>,
    fee: Hlx,
    #[serde(skip_serializing_if = "Option::is_none")]
    blockhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmations: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocktime: Option<u64>,
    helix_type: String,
    /// `applied`, `failed`, `unknown` (no outcome recorded) or `pending`.
    helix_status: String,
    helix_nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    helix_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    helix_memo: Option<String>,
}

/// What a transaction is, from wherever it was read.
struct TxFacts<'a> {
    hash: &'a str,
    from: &'a str,
    tx_type: String,
    nonce: u64,
    status: &'a str,
    error: Option<String>,
    memo: Option<String>,
    fee_nano: &'a str,
    /// `(hash, height, milliseconds)` of the block holding it; `None` while it waits in the pool.
    block: Option<(&'a str, u64, u64)>,
}

/// Confirmations of a block at `height`: the wallet's tip counts, and a block the node already
/// has but the wallet has not read yet is one — a block is final.
fn block_confirmations(height: u64, scanned: u64) -> i64 {
    (scanned.max(height) - height + 1) as i64
}

fn raw_tx(daemon: &Daemon, facts: TxFacts, paid: Vec<(String, i128)>, scanned: u64) -> Result<RawTx, RpcError> {
    let fee = facts.fee_nano.parse::<i128>().map_err(|_| misc(format!("fee_nano {:?} is not a number", facts.fee_nano)))?;
    let vout = paid
        .into_iter()
        .enumerate()
        .map(|(n, (address, value))| Vout {
            value: daemon.shown(value),
            n: n as u32,
            script_pub_key: ScriptPubKey {
                asm: String::new(),
                hex: String::new(),
                req_sigs: 1,
                kind: "pubkeyhash",
                address: address.clone(),
                addresses: vec![address],
            },
        })
        .collect();
    let (blockhash, confirmations, time) = match facts.block {
        Some((hash, height, millis)) => (Some(hash.to_string()), Some(block_confirmations(height, scanned)), Some(millis / 1000)),
        None => (None, None, None),
    };
    Ok(RawTx {
        txid: facts.hash.to_string(),
        hash: facts.hash.to_string(),
        version: 1,
        locktime: 0,
        vin: vec![Vin { address: facts.from.to_string(), sequence: u32::MAX }],
        vout,
        fee: daemon.rate(fee),
        blockhash,
        confirmations,
        time,
        blocktime: time,
        helix_type: facts.tx_type,
        helix_status: facts.status.to_string(),
        helix_nonce: facts.nonce,
        helix_error: facts.error,
        helix_memo: facts.memo,
    })
}

fn no_record(what: &str) -> RpcError {
    RpcError::new(
        code::MISC,
        format!(
            "the node has no record of what {what} paid — its block is older than the node's balance \
             record (0.20.2, executed by this node itself)"
        ),
    )
}

/// `verbose`/`verbosity` as Bitcoin Core takes it: a number, or `true`/`false`.
fn verbosity(params: &Params, index: usize, name: &str, default: u8) -> Result<u8, RpcError> {
    match params.get(index, name).map(|raw| raw.get().trim().to_string()) {
        None => Ok(default),
        Some(v) if v == "true" => Ok(1),
        Some(v) if v == "false" => Ok(0),
        Some(v) => v.parse::<u8>().map_err(|_| RpcError::new(code::TYPE, format!("{name} must be a number or true/false"))),
    }
}

fn misc(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(code::MISC, e.to_string())
}

fn node_error(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(code::NOT_CONNECTED, format!("the Helix node did not answer: {e}"))
}

#[derive(Serialize)]
struct TxEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    category: &'static str,
    amount: Hlx,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<Hlx>,
    confirmations: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    blockhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blockheight: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blockindex: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocktime: Option<u64>,
    txid: String,
    walletconflicts: Vec<String>,
    time: u64,
    timereceived: u64,
    #[serde(rename = "bip125-replaceable")]
    replaceable: &'static str,
    trusted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    abandoned: Option<bool>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    helix_sweep: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    helix_error: Option<String>,
}

fn confirmations(entry: &Entry, scanned: u64) -> i64 {
    if entry.failed.is_some() || entry.abandoned {
        return -1;
    }
    match entry.height {
        Some(h) if h <= scanned => (scanned - h + 1) as i64,
        Some(_) => 0,
        None => 0,
    }
}

fn category(c: Category) -> &'static str {
    match c {
        Category::Receive => "receive",
        Category::Send => "send",
        Category::Generate => "generate",
    }
}

fn tx_entry(daemon: &Daemon, entry: &Entry, scanned: u64) -> TxEntry {
    let keys = daemon.keys.lock().expect("keys");
    let confirmations = confirmations(entry, scanned);
    let is_send = entry.category == Category::Send;
    TxEntry {
        address: Some(entry.address.clone()),
        category: category(entry.category),
        amount: daemon.shown(entry.amount),
        label: if is_send { None } else { Some(keys.label(&entry.address).unwrap_or("").to_string()) },
        vout: 0,
        fee: is_send.then(|| daemon.shown(entry.fee)),
        confirmations,
        blockhash: entry.blockhash.clone(),
        blockheight: entry.height,
        blockindex: entry.height.map(|_| 0),
        blocktime: entry.blocktime,
        txid: entry.txid.clone(),
        walletconflicts: Vec::new(),
        time: entry.time,
        timereceived: entry.time,
        replaceable: "no",
        trusted: confirmations >= 0,
        abandoned: is_send.then_some(entry.abandoned),
        helix_sweep: entry.sweep,
        helix_error: entry.failed.clone(),
    }
}

fn label_filter(params: &Params) -> Result<Option<String>, RpcError> {
    Ok(params.string(0, "label")?.filter(|l| l != "*"))
}

pub async fn call(daemon: &Daemon, method: &str, params: &Params, started: std::time::Instant) -> RpcResult {
    match method {
        "ping" => result(&()),
        "uptime" => result(&started.elapsed().as_secs()),
        "help" => result(&METHODS.join("\n")),

        "getblockcount" => result(&daemon.scanned_height()),
        "getbestblockhash" => {
            let (_, hash) = daemon.ledger.scanned().map_err(misc)?.unwrap_or_default();
            result(&hash)
        }
        "getblockhash" => {
            let height = params.u64(0, "height")?.ok_or_else(|| RpcError::new(code::INVALID_PARAMETER, "height is required"))?;
            if height > daemon.scanned_height() {
                return Err(RpcError::new(code::INVALID_PARAMETER, "Block height out of range"));
            }
            let header = daemon.node.header(height).await.map_err(node_error)?;
            result(&header.hash)
        }
        "getblockchaininfo" => {
            #[derive(Serialize)]
            struct Info {
                chain: String,
                blocks: u64,
                headers: u64,
                bestblockhash: String,
                initialblockdownload: bool,
                verificationprogress: f64,
                warnings: String,
            }
            let sync = daemon.sync.read().expect("sync").clone();
            let (blocks, hash) = daemon.ledger.scanned().map_err(misc)?.unwrap_or_default();
            let headers = sync.node_tip.max(blocks);
            let network = daemon.keys.lock().expect("keys").meta.network.clone();
            result(&Info {
                chain: network,
                blocks,
                headers,
                bestblockhash: hash,
                initialblockdownload: sync.node_syncing || blocks + 2 < headers,
                verificationprogress: if headers == 0 { 1.0 } else { blocks as f64 / headers as f64 },
                warnings: sync.halted.unwrap_or_default(),
            })
        }
        "getnetworkinfo" => {
            #[derive(Serialize)]
            struct Info {
                version: u32,
                subversion: String,
                protocolversion: u32,
                connections: u64,
                networkactive: bool,
                relayfee: Hlx,
                warnings: String,
            }
            let sync = daemon.sync.read().expect("sync").clone();
            result(&Info {
                version: version_number(),
                subversion: format!("/helix-walletd:{}/helix:{}/", env!("CARGO_PKG_VERSION"), sync.node_version),
                protocolversion: 1,
                connections: sync.peer_count,
                networkactive: sync.node_reachable,
                relayfee: daemon.rate(sync.base_fee_per_byte as i128 * 1000),
                warnings: sync.halted.unwrap_or_default(),
            })
        }
        "getconnectioncount" => result(&daemon.sync.read().expect("sync").peer_count),
        // Removed from Bitcoin Core in 0.16 and still called by many Bitcoin-family integrations.
        "getinfo" => {
            #[derive(Serialize)]
            struct Info {
                version: u32,
                protocolversion: u32,
                walletversion: u32,
                balance: Hlx,
                blocks: u64,
                timeoffset: i64,
                connections: u64,
                proxy: String,
                /// No proof of work: always 1, the least Bitcoin has.
                difficulty: f64,
                testnet: bool,
                keypoololdest: u64,
                keypoolsize: usize,
                #[serde(skip_serializing_if = "Option::is_none")]
                unlocked_until: Option<u64>,
                paytxfee: Hlx,
                relayfee: Hlx,
                errors: String,
            }
            let balance = daemon.balance()?;
            let sync = daemon.sync.read().expect("sync").clone();
            let paytxfee = daemon.paytxfee.read().expect("paytxfee").unwrap_or(0);
            let mut keys = daemon.keys.lock().expect("keys");
            result(&Info {
                version: version_number(),
                protocolversion: 1,
                walletversion: 1,
                balance: daemon.shown(balance as i128),
                blocks: daemon.scanned_height(),
                timeoffset: 0,
                connections: sync.peer_count,
                proxy: String::new(),
                difficulty: 1.0,
                testnet: keys.meta.network != "main",
                keypoololdest: 0,
                keypoolsize: keys.pool_size(),
                unlocked_until: keys.unlocked_until(),
                paytxfee: daemon.rate(paytxfee as i128),
                relayfee: daemon.rate(sync.base_fee_per_byte as i128 * 1000),
                errors: sync.halted.unwrap_or_default(),
            })
        }
        "getblock" => {
            let hash = params.required_string(0, "blockhash")?;
            let verbosity = verbosity(params, 1, "verbosity", 1)?;
            if verbosity == 0 {
                return Err(RpcError::new(
                    code::INVALID_PARAMETER,
                    "verbosity 0 (the serialized block) is not offered: a Helix block is not in Bitcoin's \
                     format — call getblock with verbosity 1 or 2",
                ));
            }
            let scanned = daemon.scanned_height();
            let height = daemon
                .node
                .height_of(&hash)
                .await
                .map_err(node_error)?
                .filter(|h| *h <= scanned)
                .ok_or_else(|| RpcError::new(code::INVALID_ADDRESS, "Block not found"))?;
            let block = daemon.node.block_at(height).await.map_err(node_error)?;
            let next = if height < scanned { Some(daemon.node.header(height + 1).await.map_err(node_error)?.hash) } else { None };
            #[derive(Serialize)]
            #[serde(untagged)]
            enum BlockTx {
                Id(String),
                Full(Box<RawTx>),
            }
            let mut tx = Vec::with_capacity(block.transactions.len());
            for (index, t) in block.transactions.iter().enumerate() {
                if verbosity == 1 {
                    tx.push(BlockTx::Id(t.hash.clone()));
                    continue;
                }
                let changes = block.balance_changes.as_ref().ok_or_else(|| no_record("this block's transactions"))?;
                let paid = payouts(changes.iter().filter(|c| c.tx_index == Some(index as u32)))?;
                let facts = TxFacts {
                    hash: &t.hash,
                    from: &t.from,
                    tx_type: format!("{:?}", t.tx_type),
                    nonce: t.nonce,
                    status: &t.status,
                    error: t.error.clone(),
                    memo: t.memo.clone(),
                    fee_nano: &t.fee_nano,
                    block: Some((&block.hash, block.height, block.timestamp)),
                };
                tx.push(BlockTx::Full(Box::new(raw_tx(daemon, facts, paid, scanned)?)));
            }
            #[derive(Serialize)]
            struct BlockInfo {
                hash: String,
                confirmations: i64,
                height: u64,
                version: u32,
                #[serde(rename = "versionHex")]
                version_hex: &'static str,
                merkleroot: String,
                time: u64,
                mediantime: u64,
                /// No proof of work: always 1.
                difficulty: f64,
                #[serde(rename = "nTx")]
                n_tx: usize,
                #[serde(skip_serializing_if = "Option::is_none")]
                previousblockhash: Option<String>,
                #[serde(skip_serializing_if = "Option::is_none")]
                nextblockhash: Option<String>,
                tx: Vec<BlockTx>,
            }
            result(&BlockInfo {
                confirmations: block_confirmations(block.height, scanned),
                height: block.height,
                version: 1,
                version_hex: "00000001",
                merkleroot: block.merkle_root.clone().unwrap_or_default(),
                time: block.timestamp / 1000,
                mediantime: block.timestamp / 1000,
                difficulty: 1.0,
                n_tx: block.transactions.len(),
                previousblockhash: (block.height > 0).then(|| block.prev_hash.clone()),
                nextblockhash: next,
                hash: block.hash,
                tx,
            })
        }
        "getrawtransaction" => {
            let txid = params.required_string(0, "txid")?;
            if verbosity(params, 1, "verbose", 0)? == 0 {
                return Err(RpcError::new(
                    code::INVALID_PARAMETER,
                    "the serialized transaction (verbose=false) is not offered: a Helix transaction is not \
                     in Bitcoin's format — call getrawtransaction <txid> true",
                ));
            }
            let detail = daemon
                .node
                .transaction(&txid)
                .await
                .map_err(node_error)?
                .ok_or_else(|| RpcError::new(code::INVALID_ADDRESS, "No such mempool or blockchain transaction"))?;
            // The chain as this wallet has read it, as every other answer here: a block the node
            // already holds but the wallet has not read yet is not yet in it — otherwise `getblock`
            // on the `blockhash` given here would answer "Block not found" for a moment.
            let scanned = daemon.scanned_height();
            let block = match (&detail.block_hash, detail.block_height) {
                (Some(hash), Some(height)) if height <= scanned => Some((hash.as_str(), height, detail.timestamp.unwrap_or(0))),
                _ => None,
            };
            // Waiting in the pool, it has paid nobody yet — and may never: a Helix transaction can
            // fail when it executes. Its outputs appear with the block that applied it.
            let paid = match (&block, &detail.balance_changes) {
                (None, _) => Vec::new(),
                (Some(_), Some(changes)) => payouts(changes.iter())?,
                (Some(_), None) => return Err(no_record("this transaction")),
            };
            let facts = TxFacts {
                hash: &detail.hash,
                from: &detail.from,
                tx_type: detail.tx_type.clone(),
                nonce: detail.nonce,
                status: if block.is_some() { &detail.status } else { "pending" },
                error: if block.is_some() { detail.error.clone() } else { None },
                memo: detail.memo.clone(),
                fee_nano: &detail.fee_nano,
                block,
            };
            result(&raw_tx(daemon, facts, paid, scanned)?)
        }

        "getwalletinfo" => {
            #[derive(Serialize)]
            struct Info {
                walletname: String,
                walletversion: u32,
                format: &'static str,
                balance: Hlx,
                unconfirmed_balance: Hlx,
                immature_balance: Hlx,
                txcount: usize,
                keypoolsize: usize,
                #[serde(skip_serializing_if = "Option::is_none")]
                unlocked_until: Option<u64>,
                paytxfee: Hlx,
                private_keys_enabled: bool,
                avoid_reuse: bool,
                scanning: bool,
                descriptors: bool,
                helix_hot_address: String,
                helix_birth_height: u64,
            }
            let balance = daemon.balance()?;
            let txcount = daemon.ledger.entries().map_err(misc)?.len();
            let paytxfee = daemon.paytxfee.read().expect("paytxfee").unwrap_or(0);
            let mut keys = daemon.keys.lock().expect("keys");
            result(&Info {
                walletname: String::new(),
                walletversion: 1,
                format: "helix",
                balance: daemon.shown(balance as i128),
                unconfirmed_balance: daemon.shown(0),
                immature_balance: daemon.shown(0),
                txcount,
                keypoolsize: keys.pool_size(),
                unlocked_until: keys.unlocked_until(),
                paytxfee: daemon.rate(paytxfee as i128),
                private_keys_enabled: true,
                avoid_reuse: false,
                scanning: false,
                descriptors: false,
                helix_hot_address: keys.meta.hot_address.clone(),
                helix_birth_height: keys.meta.birth_height,
            })
        }

        "getbalance" => {
            if let Some(dummy) = params.string(0, "dummy")? {
                if dummy != "*" && !dummy.is_empty() {
                    return Err(RpcError::new(code::INVALID_PARAMETER, "dummy first argument must be excluded or set to \"*\""));
                }
            }
            result(&daemon.shown(daemon.balance()? as i128))
        }
        "getunconfirmedbalance" => result(&daemon.shown(0)),

        "getnewaddress" => {
            let label = params.string(0, "label")?.unwrap_or_default();
            let address = tokio::task::block_in_place(|| daemon.keys.lock().expect("keys").new_address(&label))
                .map_err(|e| {
                    let c = match e {
                        crate::keys::KeyError::PoolEmpty => code::KEYPOOL_RAN_OUT,
                        crate::keys::KeyError::Locked => code::UNLOCK_NEEDED,
                        _ => code::WALLET,
                    };
                    RpcError::new(c, e.to_string())
                })?;
            result(&address)
        }
        "validateaddress" => {
            #[derive(Serialize)]
            struct Valid {
                isvalid: bool,
                #[serde(skip_serializing_if = "Option::is_none")]
                address: Option<String>,
                #[serde(rename = "scriptPubKey", skip_serializing_if = "Option::is_none")]
                script_pub_key: Option<String>,
                #[serde(skip_serializing_if = "Option::is_none")]
                isscript: Option<bool>,
                #[serde(skip_serializing_if = "Option::is_none")]
                iswitness: Option<bool>,
                #[serde(skip_serializing_if = "Option::is_none")]
                error: Option<String>,
            }
            let address = params.required_string(0, "address")?;
            result(&match helix_crypto::Address::from_str(&address) {
                Ok(a) => Valid {
                    isvalid: true,
                    address: Some(a.to_string()),
                    script_pub_key: Some(String::new()),
                    isscript: Some(false),
                    iswitness: Some(false),
                    error: None,
                },
                Err(e) => Valid { isvalid: false, address: None, script_pub_key: None, isscript: None, iswitness: None, error: Some(e.to_string()) },
            })
        }
        "getaddressinfo" => {
            #[derive(Serialize)]
            struct Info {
                address: String,
                ismine: bool,
                iswatchonly: bool,
                solvable: bool,
                isscript: bool,
                iswitness: bool,
                ischange: bool,
                label: String,
                labels: Vec<String>,
                #[serde(skip_serializing_if = "Option::is_none")]
                timestamp: Option<u64>,
            }
            let address = params.required_string(0, "address")?;
            let parsed = helix_crypto::Address::from_str(&address)
                .map_err(|e| RpcError::new(code::INVALID_ADDRESS, format!("Invalid address: {e}")))?
                .to_string();
            let keys = daemon.keys.lock().expect("keys");
            let label = keys.label(&parsed).unwrap_or("").to_string();
            let timestamp = keys.issued().find(|i| i.address == parsed).map(|i| i.time);
            let ismine = keys.is_mine(&parsed);
            result(&Info {
                ischange: parsed == keys.meta.hot_address,
                address: parsed,
                ismine,
                iswatchonly: false,
                solvable: ismine,
                isscript: false,
                iswitness: false,
                labels: vec![label.clone()],
                label,
                timestamp,
            })
        }
        "getreceivedbyaddress" => {
            let address = params.required_string(0, "address")?;
            let minconf = params.u64(1, "minconf")?.unwrap_or(1) as i64;
            if !daemon.keys.lock().expect("keys").is_mine(&address) {
                return Err(RpcError::new(code::WALLET, "Address not found in wallet"));
            }
            let scanned = daemon.scanned_height();
            let total: i128 = daemon
                .ledger
                .entries()
                .map_err(misc)?
                .iter()
                .filter(|e| e.category == Category::Receive && e.address == address && confirmations(e, scanned) >= minconf)
                .map(|e| e.amount)
                .sum();
            result(&daemon.shown(total))
        }

        "listsinceblock" => {
            let since = match params.string(0, "blockhash")?.filter(|h| !h.is_empty()) {
                Some(hash) => Some(
                    daemon
                        .node
                        .height_of(&hash)
                        .await
                        .map_err(node_error)?
                        .ok_or_else(|| RpcError::new(code::INVALID_ADDRESS, "Block not found"))?,
                ),
                None => None,
            };
            let target = params.u64(1, "target_confirmations")?.unwrap_or(1);
            if target < 1 {
                return Err(RpcError::new(code::INVALID_PARAMETER, "Invalid parameter"));
            }
            let scanned = daemon.scanned_height();
            let entries = daemon.ledger.entries().map_err(misc)?;
            let transactions: Vec<TxEntry> = entries
                .iter()
                .filter(|e| match (e.height, since) {
                    (None, _) => !e.abandoned,
                    (Some(_), None) => true,
                    (Some(h), Some(s)) => h > s,
                })
                .map(|e| tx_entry(daemon, e, scanned))
                .collect();
            let last = (scanned + 1).saturating_sub(target);
            let lastblock = daemon.node.header(last).await.map_err(node_error)?.hash;
            #[derive(Serialize)]
            struct Since {
                transactions: Vec<TxEntry>,
                removed: Vec<TxEntry>,
                lastblock: String,
            }
            result(&Since { transactions, removed: Vec::new(), lastblock })
        }
        "listtransactions" => {
            let label = label_filter(params)?;
            let count = params.u64(1, "count")?.unwrap_or(10) as usize;
            let skip = params.u64(2, "skip")?.unwrap_or(0) as usize;
            let scanned = daemon.scanned_height();
            let entries = daemon.ledger.entries().map_err(misc)?;
            let chosen: Vec<&Entry> = {
                let keys = daemon.keys.lock().expect("keys");
                entries
                    .iter()
                    .filter(|e| match &label {
                        None => true,
                        Some(l) => e.category != Category::Send && keys.label(&e.address) == Some(l.as_str()),
                    })
                    .collect()
            };
            let end = chosen.len().saturating_sub(skip);
            let start = end.saturating_sub(count);
            let list: Vec<TxEntry> = chosen[start..end].iter().map(|e| tx_entry(daemon, e, scanned)).collect();
            result(&list)
        }
        "gettransaction" => {
            let txid = params.required_string(0, "txid")?;
            let entries = daemon.ledger.by_txid(&txid).map_err(misc)?;
            if entries.is_empty() {
                return Err(RpcError::new(code::INVALID_ADDRESS, "Invalid or non-wallet transaction id"));
            }
            let scanned = daemon.scanned_height();
            let first = &entries[0];
            let details: Vec<TxEntry> = entries.iter().map(|e| tx_entry(daemon, e, scanned)).collect();
            let sends = entries.iter().filter(|e| e.category == Category::Send);
            let fee: Option<Hlx> = entries.iter().any(|e| e.category == Category::Send).then(|| daemon.shown(sends.map(|e| e.fee).sum()));
            #[derive(Serialize)]
            struct Tx {
                amount: Hlx,
                #[serde(skip_serializing_if = "Option::is_none")]
                fee: Option<Hlx>,
                confirmations: i64,
                #[serde(skip_serializing_if = "Option::is_none")]
                blockhash: Option<String>,
                #[serde(skip_serializing_if = "Option::is_none")]
                blockheight: Option<u64>,
                #[serde(skip_serializing_if = "Option::is_none")]
                blockindex: Option<u32>,
                #[serde(skip_serializing_if = "Option::is_none")]
                blocktime: Option<u64>,
                txid: String,
                walletconflicts: Vec<String>,
                time: u64,
                timereceived: u64,
                #[serde(rename = "bip125-replaceable")]
                replaceable: &'static str,
                trusted: bool,
                details: Vec<TxEntry>,
                hex: String,
            }
            let confirmations = confirmations(first, scanned);
            result(&Tx {
                amount: daemon.shown(entries.iter().map(|e| e.amount).sum()),
                fee,
                confirmations,
                blockhash: first.blockhash.clone(),
                blockheight: first.height,
                blockindex: first.height.map(|_| 0),
                blocktime: first.blocktime,
                txid: first.txid.clone(),
                walletconflicts: Vec::new(),
                time: first.time,
                timereceived: first.time,
                replaceable: "no",
                trusted: confirmations >= 0,
                details,
                hex: String::new(),
            })
        }

        "sendtoaddress" => {
            let address = params.required_string(0, "address")?;
            let raw = params.get(1, "amount").ok_or_else(|| RpcError::new(code::INVALID_PARAMETER, "amount is required"))?;
            let amount = daemon.parse_amount(raw)?;
            let subtract = params.bool(4, "subtractfeefromamount")?.unwrap_or(false);
            let txid = daemon.send(&address, amount, subtract).await?;
            result(&txid)
        }
        "sendmany" => Err(RpcError::new(
            code::WALLET,
            "sendmany is not supported: a Helix transaction pays exactly one recipient — call \
             sendtoaddress once per recipient",
        )),
        "estimatesmartfee" => {
            #[derive(Serialize)]
            struct Estimate {
                feerate: Hlx,
                blocks: u64,
            }
            let base = daemon.sync.read().expect("sync").base_fee_per_byte;
            let base = if base == 0 { daemon.node.status().await.map_err(node_error)?.base_fee_per_byte } else { base };
            // Per kB, as Bitcoin Core states a fee rate.
            result(&Estimate { feerate: daemon.rate(base as i128 * 1000), blocks: 1 })
        }
        // A fee rate sends pay at least, per kB, until the wallet restarts (`paytxfee` in helix.conf
        // sets it at start); 0 goes back to the going fee. Never above `maxtxfee`.
        "settxfee" => {
            let raw = params.get(0, "amount").ok_or_else(|| RpcError::new(code::INVALID_PARAMETER, "amount is required"))?;
            let per_kb = daemon.parse_amount(raw)?;
            if per_kb > daemon.opts.max_fee {
                return Err(RpcError::new(
                    code::INVALID_PARAMETER,
                    format!("txfee cannot be more than wallet max tx fee ({} HLX)", daemon.rate(daemon.opts.max_fee as i128).literal()),
                ));
            }
            *daemon.paytxfee.write().expect("paytxfee") = (per_kb > 0).then_some(per_kb);
            result(&true)
        }

        "walletpassphrase" => {
            let passphrase = params.required_string(0, "passphrase")?;
            let timeout = params.u64(1, "timeout")?.ok_or_else(|| RpcError::new(code::INVALID_PARAMETER, "timeout is required"))?;
            if timeout == 0 {
                return Err(RpcError::new(code::INVALID_PARAMETER, "Timeout cannot be zero"));
            }
            tokio::task::block_in_place(|| daemon.keys.lock().expect("keys").unlock(&passphrase, timeout)).map_err(|e| {
                let c = match e {
                    crate::keys::KeyError::WrongPassphrase => code::PASSPHRASE_INCORRECT,
                    crate::keys::KeyError::NotEncrypted => code::WRONG_ENC_STATE,
                    _ => code::WALLET,
                };
                RpcError::new(c, e.to_string())
            })?;
            result(&())
        }
        "walletlock" => {
            daemon.keys.lock().expect("keys").lock().map_err(|e| RpcError::new(code::WRONG_ENC_STATE, e.to_string()))?;
            result(&())
        }
        "keypoolrefill" => {
            let size = params.u64(0, "newsize")?.unwrap_or(daemon.opts.keypool as u64) as usize;
            if !daemon.keys.lock().expect("keys").is_unlocked() {
                return Err(RpcError::new(code::UNLOCK_NEEDED, crate::keys::KeyError::Locked.to_string()));
            }
            // One key at a time, each made outside the lock: an encrypted key costs an Argon2id
            // derivation, and the wallet keeps answering meanwhile.
            loop {
                let maker = daemon.keys.lock().expect("keys").maker(size);
                let Some(maker) = maker else { break };
                let address = tokio::task::block_in_place(|| maker.make()).map_err(|e| RpcError::new(code::WALLET, e.to_string()))?;
                daemon.keys.lock().expect("keys").adopt(address);
            }
            result(&())
        }
        "backupwallet" => {
            let destination = params.required_string(0, "destination")?;
            daemon
                .keys
                .lock()
                .expect("keys")
                .backup(std::path::Path::new(&destination))
                .map_err(|e| RpcError::new(code::WALLET, e.to_string()))?;
            result(&())
        }

        _ => Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::pending_entry;

    /// What a client waiting for confirmations sees: a send that did not go through must never
    /// reach one confirmation, or an exchange books a withdrawal that was never paid.
    #[test]
    fn a_send_that_did_not_go_through_never_counts_as_confirmed() {
        let mut e = pending_entry("t", "hlxA", -5, -1, false);
        assert_eq!(confirmations(&e, 100), 0, "pending");
        e.height = Some(98);
        assert_eq!(confirmations(&e, 100), 3, "in block 98 at tip 100");
        e.failed = Some("insufficient balance".into());
        assert_eq!(confirmations(&e, 100), -1, "charged but not applied");
        e.failed = None;
        e.height = None;
        e.abandoned = true;
        assert_eq!(confirmations(&e, 100), -1, "its nonce went to another transaction");
    }

    fn change(account: &str, kind: &str, delta: i128) -> BalanceChange {
        BalanceChange { tx_index: Some(0), account: account.into(), kind: kind.into(), delta_nano: delta.to_string() }
    }

    /// A block scanner credits whatever a `vout` names. So a transaction's outputs are whom its
    /// execution credited, from the record — never what it asked for: a failed transfer has none.
    #[test]
    fn a_transaction_pays_only_whom_its_execution_credited() {
        let applied = [change("A", "transaction", -1_005), change("B", "transaction", 1_000), change("V", "reward", 5)];
        assert_eq!(payouts(applied.iter()).unwrap(), vec![("B".to_string(), 1_000)], "the validator's share is no payment");
        let failed = [change("A", "transaction", -5), change("V", "reward", 5)];
        assert!(payouts(failed.iter()).unwrap().is_empty(), "a failed transfer paid nobody");
        let contract = [change("A", "transaction", -9), change("B", "contract", 300), change("C", "contract", 200), change("B", "contract", 1)];
        assert_eq!(payouts(contract.iter()).unwrap(), vec![("B".to_string(), 301), ("C".to_string(), 200)]);
        let to_self = [change("A", "transaction", -1_005), change("A", "transaction", 1_000)];
        assert!(payouts(to_self.iter()).unwrap().is_empty(), "a transfer to oneself only cost the fee");
    }

    /// Bitcoin Core 0.21.1 reports 210100; integrations compare the number, not the text.
    #[test]
    fn the_version_number_is_bitcoin_cores_form() {
        assert_eq!(version_of("0.20.2"), 200_200);
        assert_eq!(version_of("0.21.1"), 210_100);
        assert_eq!(version_of("1.2.3"), 1_020_300);
    }
}
