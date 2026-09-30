//! The RPC methods, with Bitcoin Core's names, parameters and answer shapes — what an exchange's
//! Bitcoin-family integration already calls.
//!
//! Where Helix differs, the answer says so rather than pretend:
//! - one transaction pays one recipient, so `sendmany` is refused with the reason;
//! - a block is final (BFT), so one confirmation is final; there are no reorganisations;
//! - a send the chain charged but did not apply, or one whose nonce another transaction used,
//!   shows `confirmations: -1` — as Bitcoin Core shows a conflicted transaction — so no client
//!   waiting for confirmations ever counts it as paid.

use serde::Serialize;

use crate::amount::{self, Hlx};
use crate::daemon::Daemon;
use crate::ledger::{Category, Entry};
use crate::rpc::{code, result, Params, RpcError, RpcResult};

pub const METHODS: &[&str] = &[
    "backupwallet",
    "estimatesmartfee",
    "getaddressinfo",
    "getbalance",
    "getbestblockhash",
    "getblockchaininfo",
    "getblockcount",
    "getblockhash",
    "getconnectioncount",
    "getnetworkinfo",
    "getnewaddress",
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
    "uptime",
    "validateaddress",
    "walletlock",
    "walletpassphrase",
];

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
        amount: Hlx(entry.amount),
        label: if is_send { None } else { Some(keys.label(&entry.address).unwrap_or("").to_string()) },
        vout: 0,
        fee: is_send.then_some(Hlx(entry.fee)),
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
                warnings: String,
            }
            let sync = daemon.sync.read().expect("sync").clone();
            result(&Info {
                version: 1,
                subversion: format!("/helix-walletd:{}/helix:{}/", env!("CARGO_PKG_VERSION"), sync.node_version),
                protocolversion: 1,
                connections: sync.peer_count,
                networkactive: sync.node_reachable,
                warnings: sync.halted.unwrap_or_default(),
            })
        }
        "getconnectioncount" => result(&daemon.sync.read().expect("sync").peer_count),

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
            let mut keys = daemon.keys.lock().expect("keys");
            result(&Info {
                walletname: String::new(),
                walletversion: 1,
                format: "helix",
                balance: Hlx(balance as i128),
                unconfirmed_balance: Hlx(0),
                immature_balance: Hlx(0),
                txcount,
                keypoolsize: keys.pool_size(),
                unlocked_until: keys.unlocked_until(),
                paytxfee: Hlx(0),
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
            result(&Hlx(daemon.balance()? as i128))
        }
        "getunconfirmedbalance" => result(&Hlx(0)),

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
            result(&Hlx(total))
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
            let fee: Option<Hlx> = entries.iter().any(|e| e.category == Category::Send).then(|| Hlx(sends.map(|e| e.fee).sum()));
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
                amount: Hlx(entries.iter().map(|e| e.amount).sum()),
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
            let amount = amount::parse(raw).map_err(|e| RpcError::new(code::TYPE, e))?;
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
            result(&Estimate { feerate: Hlx(base as i128 * 1000), blocks: 1 })
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
}
