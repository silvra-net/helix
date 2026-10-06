//! What the wallet knows happened: every receive and send of its addresses, the balance of each,
//! and the transactions it has signed that no block holds yet.
//!
//! Built by reading blocks from the wallet's birth height on. **Amounts come only from each
//! block's `balance_changes` (#260)** — the exact movement of every liquid balance, contract
//! payments included — and the transactions only say what kind of movement it was. A block without
//! that record stops the scan: showing it would mean missing deposits, and missing a deposit is
//! the one thing a deposit wallet may not do.
//!
//! Everything a block changes is written in one transaction, so a crash leaves the ledger at the
//! end of a block, never inside one. The ledger is derived state: deleted, it is rebuilt from the
//! birth height.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::node::{parse_delta, Block};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const ENTRIES: TableDefinition<u64, &[u8]> = TableDefinition::new("entries");
const TXIDS: TableDefinition<&str, &[u8]> = TableDefinition::new("txids");
const BALANCES: TableDefinition<&str, u64> = TableDefinition::new("balances");
const PENDING: TableDefinition<&str, &[u8]> = TableDefinition::new("pending");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Receive,
    Send,
    /// A validator reward paid to a wallet address.
    Generate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub txid: String,
    pub category: Category,
    /// Receive: the wallet address paid. Send: the destination.
    pub address: String,
    /// Nano-HLX: positive received, negative sent.
    pub amount: i128,
    /// Nano-HLX, zero or negative: the fee a send paid.
    pub fee: i128,
    /// `None` while no block holds it.
    pub height: Option<u64>,
    pub blockhash: Option<String>,
    /// Seconds.
    pub blocktime: Option<u64>,
    /// Seconds, when the wallet first knew of it.
    pub time: u64,
    /// A send the chain charged but did not apply, with the reason.
    pub failed: Option<String>,
    /// A sweep: a move to the hot address from one of the wallet's own — nothing left the wallet
    /// but the fee. A payment to one of the wallet's deposit addresses is not one: it is a send and,
    /// for that address, a receive, as Bitcoin Core lists a payment to the wallet's own address.
    pub sweep: bool,
    /// A send that can never apply: its nonce went to another transaction.
    pub abandoned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    Send,
    Sweep,
}

/// A transaction this wallet signed, recorded before it was submitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub txid: String,
    pub kind: PendingKind,
    pub from: String,
    pub nonce: u64,
    /// Value leaving `from` (amount + fee), nano-HLX.
    pub outflow: u64,
    /// What leaves the wallet as a whole: amount + fee for a send, the fee for a sweep.
    pub wallet_outflow: u64,
    /// The signed transaction as `POST /transactions` takes it, to submit again if it expires.
    pub signed: String,
    pub entry_seq: u64,
    pub submitted: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockOutcome {
    pub received: usize,
    pub settled: usize,
    /// Wallet addresses that received something in this block.
    pub paid: Vec<String>,
    /// Every wallet transaction the block wrote an entry for, once each, in block order — what
    /// `walletnotify` is run for.
    pub txids: Vec<String>,
}

impl BlockOutcome {
    fn touched(&mut self, txid: &str) {
        if !self.txids.iter().any(|t| t == txid) {
            self.txids.push(txid.to_string());
        }
    }
}

pub struct Ledger {
    db: Database,
}

fn json<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("ledger records serialize")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Ledger> {
        let db = Database::create(path).with_context(|| format!("could not open {}", path.display()))?;
        let w = db.begin_write()?;
        {
            w.open_table(META)?;
            w.open_table(ENTRIES)?;
            w.open_table(TXIDS)?;
            w.open_table(BALANCES)?;
            w.open_table(PENDING)?;
        }
        w.commit()?;
        Ok(Ledger { db })
    }

    /// The last block read: `(height, hash)`.
    pub fn scanned(&self) -> Result<Option<(u64, String)>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(META)?;
        let Some(v) = t.get("scanned")? else { return Ok(None) };
        Ok(Some(serde_json::from_slice(v.value())?))
    }

    /// Start the ledger just below the wallet's birth: the next block read is `height + 1`.
    pub fn start_at(&self, height: u64, hash: &str) -> Result<()> {
        if self.scanned()?.is_some() {
            return Ok(());
        }
        let w = self.db.begin_write()?;
        w.open_table(META)?.insert("scanned", json(&(height, hash.to_string())).as_slice())?;
        w.commit()?;
        Ok(())
    }

    fn next_seq(meta: &mut redb::Table<&str, &[u8]>) -> Result<u64> {
        let seq = match meta.get("next_seq")? {
            Some(v) => serde_json::from_slice::<u64>(v.value())?,
            None => 0,
        };
        meta.insert("next_seq", json(&(seq + 1)).as_slice())?;
        Ok(seq)
    }

    fn put_entry(
        entries: &mut redb::Table<u64, &[u8]>,
        txids: &mut redb::Table<&str, &[u8]>,
        entry: &Entry,
    ) -> Result<()> {
        entries.insert(entry.seq, json(entry).as_slice())?;
        let mut seqs: Vec<u64> = match txids.get(entry.txid.as_str())? {
            Some(v) => serde_json::from_slice(v.value())?,
            None => Vec::new(),
        };
        if !seqs.contains(&entry.seq) {
            seqs.push(entry.seq);
        }
        txids.insert(entry.txid.as_str(), json(&seqs).as_slice())?;
        Ok(())
    }

    /// Record a transaction this wallet is about to submit, with the entry it will show as.
    /// Written before the submission, so a crash between the two leaves a transaction the wallet
    /// knows about and submits again — never one out there that it forgot.
    pub fn record_pending(&self, mut entry: Entry, mut pending: Pending) -> Result<Entry> {
        let w = self.db.begin_write()?;
        {
            let mut meta = w.open_table(META)?;
            let mut entries = w.open_table(ENTRIES)?;
            let mut txids = w.open_table(TXIDS)?;
            let mut pend = w.open_table(PENDING)?;
            entry.seq = Self::next_seq(&mut meta)?;
            pending.entry_seq = entry.seq;
            Self::put_entry(&mut entries, &mut txids, &entry)?;
            pend.insert(pending.txid.as_str(), json(&pending).as_slice())?;
        }
        w.commit()?;
        Ok(entry)
    }

    pub fn pending(&self) -> Result<Vec<Pending>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(PENDING)?;
        let mut out = Vec::new();
        for item in t.iter()? {
            let (_, v) = item?;
            out.push(serde_json::from_slice(v.value())?);
        }
        Ok(out)
    }

    /// A pending transaction that can never apply: its nonce was used by another.
    pub fn abandon(&self, txid: &str) -> Result<()> {
        let w = self.db.begin_write()?;
        {
            let mut pend = w.open_table(PENDING)?;
            let mut entries = w.open_table(ENTRIES)?;
            let pending: Option<Pending> = match pend.get(txid)? {
                Some(v) => Some(serde_json::from_slice(v.value())?),
                None => None,
            };
            if let Some(p) = pending {
                let mut entry: Option<Entry> = match entries.get(p.entry_seq)? {
                    Some(v) => Some(serde_json::from_slice(v.value())?),
                    None => None,
                };
                if let Some(e) = entry.as_mut() {
                    e.abandoned = true;
                    entries.insert(e.seq, json(e).as_slice())?;
                }
                pend.remove(txid)?;
            }
        }
        w.commit()?;
        Ok(())
    }

    /// Forget a transaction the node refused at submission: it never went anywhere, so neither
    /// its pending record nor its entry stays.
    pub fn discard(&self, txid: &str) -> Result<()> {
        let w = self.db.begin_write()?;
        {
            let mut pend = w.open_table(PENDING)?;
            let mut entries = w.open_table(ENTRIES)?;
            let mut txids = w.open_table(TXIDS)?;
            let seq = match pend.get(txid)? {
                Some(v) => Some(serde_json::from_slice::<Pending>(v.value())?.entry_seq),
                None => None,
            };
            if let Some(seq) = seq {
                entries.remove(seq)?;
                let remaining: Vec<u64> = match txids.get(txid)? {
                    Some(v) => serde_json::from_slice::<Vec<u64>>(v.value())?.into_iter().filter(|s| *s != seq).collect(),
                    None => Vec::new(),
                };
                if remaining.is_empty() {
                    txids.remove(txid)?;
                } else {
                    txids.insert(txid, json(&remaining).as_slice())?;
                }
                pend.remove(txid)?;
            }
        }
        w.commit()?;
        Ok(())
    }

    /// The entry of a send this wallet gave up on, if `txid` names one. A block that holds the
    /// transaction settles it: the block is what happened, while giving up was the wallet's reading
    /// of a nonce — and a withdrawal that paid must never go on showing `confirmations: -1`.
    fn abandoned_send(
        entries: &redb::Table<u64, &[u8]>,
        txids: &redb::Table<&str, &[u8]>,
        txid: &str,
    ) -> Result<Option<Entry>> {
        let seqs: Vec<u64> = match txids.get(txid)? {
            Some(v) => serde_json::from_slice(v.value())?,
            None => return Ok(None),
        };
        for seq in seqs {
            if let Some(v) = entries.get(seq)? {
                let entry: Entry = serde_json::from_slice(v.value())?;
                if entry.category == Category::Send && entry.abandoned {
                    return Ok(Some(entry));
                }
            }
        }
        Ok(None)
    }

    /// Read one block into the ledger. `hot` is the wallet's hot address, `is_mine` names all of
    /// its addresses. The block must follow the last one read.
    pub fn apply_block(&self, block: &Block, hot: &str, is_mine: impl Fn(&str) -> bool) -> Result<BlockOutcome> {
        let (last_height, last_hash) = self.scanned()?.ok_or_else(|| anyhow!("the ledger has no starting block"))?;
        if block.height != last_height + 1 {
            bail!("block {} does not follow the last block read ({last_height})", block.height);
        }
        if block.prev_hash != last_hash {
            bail!(
                "block {} does not build on block {last_height} as this wallet read it ({} vs {last_hash}) \
                 — the node is on another chain than the one this wallet was made on",
                block.height,
                block.prev_hash
            );
        }
        let changes = block.balance_changes.as_ref().ok_or_else(|| {
            anyhow!(
                "the node has no record of what block {} did to balances — it must run 0.20.2 or \
                 later and have executed the block itself (synced from genesis, not from a checkpoint)",
                block.height
            )
        })?;
        let blocktime = block.timestamp / 1000;
        let mut outcome = BlockOutcome::default();

        // Every movement of a wallet address in this block, by transaction.
        let mut moved: BTreeMap<(Option<u32>, String, String), i128> = BTreeMap::new();
        let mut per_account: BTreeMap<String, i128> = BTreeMap::new();
        for c in changes.iter().filter(|c| is_mine(&c.account)) {
            let delta = parse_delta(&c.delta_nano)?;
            *moved.entry((c.tx_index, c.account.clone(), c.kind.clone())).or_default() += delta;
            *per_account.entry(c.account.clone()).or_default() += delta;
        }

        let w = self.db.begin_write()?;
        {
            let mut meta = w.open_table(META)?;
            let mut entries = w.open_table(ENTRIES)?;
            let mut txids = w.open_table(TXIDS)?;
            let mut balances = w.open_table(BALANCES)?;
            let mut pend = w.open_table(PENDING)?;

            for (index, tx) in block.transactions.iter().enumerate() {
                let index = index as u32;
                let from_mine = is_mine(&tx.from);
                let to = tx.to.clone().unwrap_or_default();
                let to_mine = !to.is_empty() && is_mine(&to);
                // A sweep moves value to the hot address from one of the wallet's own: nothing
                // leaves the wallet but the fee, and nobody was paid. A payment from the wallet to
                // one of its deposit addresses — one customer of an exchange paying another — is a
                // send and a receive: the receiving customer is credited by the receive.
                let is_sweep = from_mine && to == hot;
                let delta_of = |account: &str, kind: &str| {
                    moved.get(&(Some(index), account.to_string(), kind.to_string())).copied().unwrap_or(0)
                };

                if from_mine {
                    let amount = Block::tx_amount(tx)? as i128;
                    let from_delta = delta_of(&tx.from, "transaction");
                    let failed = match tx.status.as_str() {
                        "applied" => None,
                        "failed" => Some(tx.error.clone().unwrap_or_else(|| "failed".into())),
                        // No outcome recorded: the balance says which. An applied transfer moved
                        // amount and fee; a failed one only the fee.
                        _ if from_delta == -(amount + Block::tx_fee(tx)? as i128) => None,
                        _ => Some("the transaction was charged its fee but not applied".into()),
                    };
                    let fee_paid = if failed.is_some() { -from_delta } else { Block::tx_fee(tx)? as i128 };
                    let sweep = is_sweep;
                    let pending: Option<Pending> = match pend.get(tx.hash.as_str())? {
                        Some(v) => Some(serde_json::from_slice(v.value())?),
                        None => None,
                    };
                    let mut entry = match &pending {
                        Some(p) => match entries.get(p.entry_seq)? {
                            Some(v) => serde_json::from_slice::<Entry>(v.value())?,
                            None => bail!("pending {} names entry {} which is missing", p.txid, p.entry_seq),
                        },
                        None => match Self::abandoned_send(&entries, &txids, &tx.hash)? {
                            Some(mut given_up) => {
                                given_up.abandoned = false;
                                given_up
                            }
                            None => Entry {
                                seq: Self::next_seq(&mut meta)?,
                                txid: tx.hash.clone(),
                                category: Category::Send,
                                address: to.clone(),
                                amount: if sweep { 0 } else { -amount },
                                fee: 0,
                                height: None,
                                blockhash: None,
                                blocktime: None,
                                time: blocktime,
                                failed: None,
                                sweep,
                                abandoned: false,
                            },
                        },
                    };
                    entry.height = Some(block.height);
                    entry.blockhash = Some(block.hash.clone());
                    entry.blocktime = Some(blocktime);
                    entry.fee = -fee_paid;
                    entry.failed = failed;
                    Self::put_entry(&mut entries, &mut txids, &entry)?;
                    if pending.is_some() {
                        pend.remove(tx.hash.as_str())?;
                    }
                    outcome.settled += 1;
                    outcome.touched(&tx.hash);
                }

                if to_mine && !is_sweep {
                    let received = delta_of(&to, "transaction");
                    if received > 0 {
                        let entry = Entry {
                            seq: Self::next_seq(&mut meta)?,
                            txid: tx.hash.clone(),
                            category: Category::Receive,
                            address: to.clone(),
                            amount: received,
                            fee: 0,
                            height: Some(block.height),
                            blockhash: Some(block.hash.clone()),
                            blocktime: Some(blocktime),
                            time: blocktime,
                            failed: None,
                            sweep: false,
                            abandoned: false,
                        };
                        Self::put_entry(&mut entries, &mut txids, &entry)?;
                        outcome.received += 1;
                        outcome.paid.push(to.clone());
                        outcome.touched(&tx.hash);
                    }
                }
            }

            // Payments a contract made to a wallet address, and rewards.
            for ((tx_index, account, kind), delta) in &moved {
                let (category, txid) = match (kind.as_str(), tx_index) {
                    ("contract", Some(i)) => {
                        let tx = block.transactions.get(*i as usize).ok_or_else(|| {
                            anyhow!("block {}: a contract payment names transaction {i}, which is not there", block.height)
                        })?;
                        (Category::Receive, tx.hash.clone())
                    }
                    ("reward", Some(i)) => (
                        Category::Generate,
                        block.transactions.get(*i as usize).map(|t| t.hash.clone()).unwrap_or_default(),
                    ),
                    ("reward", None) => (Category::Generate, format!("reward-{}", block.hash)),
                    _ => continue,
                };
                if *delta <= 0 {
                    continue;
                }
                let entry = Entry {
                    seq: Self::next_seq(&mut meta)?,
                    txid,
                    category,
                    address: account.clone(),
                    amount: *delta,
                    fee: 0,
                    height: Some(block.height),
                    blockhash: Some(block.hash.clone()),
                    blocktime: Some(blocktime),
                    time: blocktime,
                    failed: None,
                    sweep: false,
                    abandoned: false,
                };
                Self::put_entry(&mut entries, &mut txids, &entry)?;
                outcome.touched(&entry.txid);
                if category == Category::Receive {
                    outcome.received += 1;
                    outcome.paid.push(account.clone());
                }
            }

            for (account, delta) in &per_account {
                let before = balances.get(account.as_str())?.map(|v| v.value()).unwrap_or(0) as i128;
                let after = before + delta;
                if after < 0 || after > u64::MAX as i128 {
                    bail!(
                        "block {}: {account} would go from {before} to {after} nano-HLX — the ledger \
                         missed a block of its history; delete ledger.redb to read it again from the \
                         wallet's birth",
                        block.height
                    );
                }
                balances.insert(account.as_str(), after as u64)?;
            }
            meta.insert("scanned", json(&(block.height, block.hash.clone())).as_slice())?;
        }
        w.commit()?;
        Ok(outcome)
    }

    pub fn balance(&self, address: &str) -> Result<u64> {
        let r = self.db.begin_read()?;
        let t = r.open_table(BALANCES)?;
        Ok(t.get(address)?.map(|v| v.value()).unwrap_or(0))
    }

    pub fn balances(&self) -> Result<Vec<(String, u64)>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(BALANCES)?;
        let mut out = Vec::new();
        for item in t.iter()? {
            let (k, v) = item?;
            out.push((k.value().to_string(), v.value()));
        }
        Ok(out)
    }

    pub fn entries(&self) -> Result<Vec<Entry>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(ENTRIES)?;
        let mut out = Vec::new();
        for item in t.iter()? {
            let (_, v) = item?;
            out.push(serde_json::from_slice(v.value())?);
        }
        Ok(out)
    }

    pub fn by_txid(&self, txid: &str) -> Result<Vec<Entry>> {
        let r = self.db.begin_read()?;
        let txids = r.open_table(TXIDS)?;
        let entries = r.open_table(ENTRIES)?;
        let Some(v) = txids.get(txid)? else { return Ok(Vec::new()) };
        let seqs: Vec<u64> = serde_json::from_slice(v.value())?;
        let mut out = Vec::new();
        for seq in seqs {
            if let Some(v) = entries.get(seq)? {
                out.push(serde_json::from_slice(v.value())?);
            }
        }
        Ok(out)
    }
}

/// A new entry for a transaction about to be submitted; `seq` is set by `record_pending`.
pub fn pending_entry(txid: &str, address: &str, amount: i128, fee: i128, sweep: bool) -> Entry {
    Entry {
        seq: 0,
        txid: txid.to_string(),
        category: Category::Send,
        address: address.to_string(),
        amount,
        fee,
        height: None,
        blockhash: None,
        blocktime: None,
        time: now_secs(),
        failed: None,
        sweep,
        abandoned: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOT: &str = "hlxHot";
    const DEP: &str = "hlxDeposit";
    const EXT: &str = "hlxOutside";

    fn ledger(name: &str) -> (Ledger, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("helix-walletd-ledger-{name}-{}.redb", rand::random::<u64>()));
        let l = Ledger::open(&path).unwrap();
        l.start_at(10, "h10").unwrap();
        (l, path)
    }

    fn mine(a: &str) -> bool {
        a == HOT || a == DEP
    }

    fn tx(hash: &str, from: &str, to: &str, amount: u64, fee: u64, status: &str) -> serde_json::Value {
        json!({ "hash": hash, "from": from, "to": to, "amount_nano": amount.to_string(), "fee_nano": fee.to_string(),
                "tx_type": "Transfer", "nonce": 0, "status": status })
    }

    fn change(tx_index: Option<u32>, account: &str, kind: &str, delta: i128) -> serde_json::Value {
        json!({ "tx_index": tx_index, "tx_hash": null, "account": account, "kind": kind, "delta_nano": delta.to_string() })
    }

    fn block(height: u64, txs: Vec<serde_json::Value>, changes: Option<Vec<serde_json::Value>>) -> Block {
        let mut b = json!({ "hash": format!("h{height}"), "height": height, "timestamp": 1_790_000_000_000u64 + height * 2000,
                            "prev_hash": format!("h{}", height - 1), "transactions": txs });
        if let Some(c) = changes {
            b["balance_changes"] = json!(c);
        }
        serde_json::from_value(b).unwrap()
    }

    #[test]
    fn a_deposit_is_a_receive_and_its_balance_is_exact() {
        let (l, path) = ledger("deposit");
        let b = block(11, vec![tx("t1", EXT, DEP, 7_000_000_001, 5_000, "applied")],
            Some(vec![change(Some(0), EXT, "transaction", -7_000_005_001), change(Some(0), DEP, "transaction", 7_000_000_001)]));
        let outcome = l.apply_block(&b, HOT, mine).unwrap();
        assert_eq!((outcome.received, outcome.paid.clone()), (1, vec![DEP.to_string()]));
        assert_eq!(outcome.txids, vec!["t1".to_string()], "what walletnotify is run for");
        let e = &l.by_txid("t1").unwrap()[0];
        assert_eq!((e.category, e.address.as_str(), e.amount, e.height), (Category::Receive, DEP, 7_000_000_001, Some(11)));
        assert_eq!(l.balance(DEP).unwrap(), 7_000_000_001);
        assert_eq!(l.scanned().unwrap(), Some((11, "h11".to_string())));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_sweep_settles_its_pending_record_and_leaves_only_the_fee_behind() {
        let (l, path) = ledger("sweep");
        l.apply_block(&block(11, vec![tx("t1", EXT, DEP, 1_000, 5, "applied")],
            Some(vec![change(Some(0), EXT, "transaction", -1_005), change(Some(0), DEP, "transaction", 1_000)])), HOT, mine).unwrap();
        l.record_pending(pending_entry("s1", HOT, 0, -10, true), Pending {
            txid: "s1".into(), kind: PendingKind::Sweep, from: DEP.into(), nonce: 0, outflow: 1_000,
            wallet_outflow: 10, signed: "{}".into(), entry_seq: 0, submitted: 0 }).unwrap();
        assert_eq!(l.pending().unwrap().len(), 1);
        let outcome = l.apply_block(&block(12, vec![tx("s1", DEP, HOT, 990, 10, "applied")],
            Some(vec![change(Some(0), DEP, "transaction", -1_000), change(Some(0), HOT, "transaction", 990)])), HOT, mine).unwrap();
        assert!(l.pending().unwrap().is_empty());
        assert_eq!(outcome.txids, vec!["s1".to_string()], "a settled send is a wallet transaction too");
        let e = &l.by_txid("s1").unwrap()[0];
        assert_eq!((e.category, e.amount, e.fee, e.sweep, e.height), (Category::Send, 0, -10, true, Some(12)));
        assert_eq!((l.balance(DEP).unwrap(), l.balance(HOT).unwrap()), (0, 990));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_send_the_chain_charged_but_did_not_apply_is_marked_failed_with_the_fee_it_cost() {
        let (l, path) = ledger("failed");
        l.apply_block(&block(11, vec![tx("t1", EXT, HOT, 1_000, 5, "applied")],
            Some(vec![change(Some(0), EXT, "transaction", -1_005), change(Some(0), HOT, "transaction", 1_000)])), HOT, mine).unwrap();
        let mut failed = tx("w1", HOT, EXT, 5_000, 7, "failed");
        failed["error"] = json!("insufficient balance");
        l.apply_block(&block(12, vec![failed, tx("w2", HOT, EXT, 100, 7, "applied")],
            Some(vec![change(Some(0), HOT, "transaction", -7), change(Some(1), HOT, "transaction", -107), change(Some(1), EXT, "transaction", 100)])), HOT, mine).unwrap();
        let f = &l.by_txid("w1").unwrap()[0];
        assert_eq!((f.fee, f.failed.as_deref()), (-7, Some("insufficient balance")));
        let ok = &l.by_txid("w2").unwrap()[0];
        assert_eq!((ok.amount, ok.fee, ok.failed.clone()), (-100, -7, None));
        assert_eq!(l.balance(HOT).unwrap(), 1_000 - 7 - 107);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_contract_paying_a_deposit_address_is_a_receive_under_the_calling_transaction() {
        let (l, path) = ledger("contract");
        let mut call = tx("c1", EXT, "hlxContract", 0, 9, "applied");
        call["tx_type"] = json!("CallContract");
        let outcome = l.apply_block(&block(11, vec![call],
            Some(vec![change(Some(0), EXT, "transaction", -9), change(Some(0), DEP, "contract", 300)])), HOT, mine).unwrap();
        assert_eq!(outcome.txids, vec!["c1".to_string()]);
        let e = &l.by_txid("c1").unwrap()[0];
        assert_eq!((e.category, e.address.as_str(), e.amount), (Category::Receive, DEP, 300));
        assert_eq!(l.balance(DEP).unwrap(), 300);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_block_without_its_balance_record_stops_the_ledger_instead_of_missing_deposits() {
        let (l, path) = ledger("norecord");
        let err = l.apply_block(&block(11, vec![tx("t1", EXT, DEP, 1, 1, "applied")], None), HOT, mine).unwrap_err();
        assert!(err.to_string().contains("0.20.2"), "{err}");
        assert_eq!(l.scanned().unwrap(), Some((10, "h10".to_string())), "nothing read");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_block_from_another_chain_is_refused() {
        let (l, path) = ledger("fork");
        let mut b = block(11, vec![], Some(vec![]));
        b.prev_hash = "somewhere-else".into();
        assert!(l.apply_block(&b, HOT, mine).unwrap_err().to_string().contains("another chain"));
        assert!(l.apply_block(&block(12, vec![], Some(vec![])), HOT, mine).is_err(), "a gap is refused too");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_balance_that_would_go_negative_says_the_history_is_incomplete() {
        let (l, path) = ledger("negative");
        let err = l.apply_block(&block(11, vec![tx("w1", HOT, EXT, 5, 1, "applied")],
            Some(vec![change(Some(0), HOT, "transaction", -6), change(Some(0), EXT, "transaction", 5)])), HOT, mine).unwrap_err();
        assert!(err.to_string().contains("missed a block"), "{err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_refused_submission_leaves_nothing_behind() {
        let (l, path) = ledger("discard");
        l.record_pending(pending_entry("w1", EXT, -5, -1, false), Pending {
            txid: "w1".into(), kind: PendingKind::Send, from: HOT.into(), nonce: 0, outflow: 6,
            wallet_outflow: 6, signed: "{}".into(), entry_seq: 0, submitted: 0 }).unwrap();
        l.discard("w1").unwrap();
        assert!(l.pending().unwrap().is_empty());
        assert!(l.by_txid("w1").unwrap().is_empty());
        assert!(l.entries().unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    /// A withdrawal to one of the wallet's own deposit addresses — one customer of an exchange
    /// paying another — is a send and a receive, as Bitcoin Core lists a payment to the wallet's
    /// own address: the receiving customer is credited by the receive. Read with the wallet's own
    /// pending record and without one (a wallet restored from a backup), the same.
    #[test]
    fn a_send_to_one_of_the_wallets_deposit_addresses_is_a_send_and_a_receive() {
        for with_pending in [true, false] {
            let (l, path) = ledger(if with_pending { "internal-pending" } else { "internal-restored" });
            l.apply_block(&block(11, vec![tx("t1", EXT, HOT, 10_000, 5, "applied")],
                Some(vec![change(Some(0), EXT, "transaction", -10_005), change(Some(0), HOT, "transaction", 10_000)])), HOT, mine).unwrap();
            if with_pending {
                l.record_pending(pending_entry("i1", DEP, -3_000, -7, false), Pending {
                    txid: "i1".into(), kind: PendingKind::Send, from: HOT.into(), nonce: 0, outflow: 3_007,
                    wallet_outflow: 7, signed: "{}".into(), entry_seq: 0, submitted: 0 }).unwrap();
            }
            let outcome = l.apply_block(&block(12, vec![tx("i1", HOT, DEP, 3_000, 7, "applied")],
                Some(vec![change(Some(0), HOT, "transaction", -3_007), change(Some(0), DEP, "transaction", 3_000)])), HOT, mine).unwrap();
            assert_eq!(outcome.paid, vec![DEP.to_string()], "the deposit address counts as paid");
            let mut entries = l.by_txid("i1").unwrap();
            entries.sort_by_key(|e| e.amount);
            let got: Vec<_> = entries.iter().map(|e| (e.category, e.address.as_str(), e.amount, e.fee, e.sweep)).collect();
            assert_eq!(got, vec![
                (Category::Send, DEP, -3_000, -7, false),
                (Category::Receive, DEP, 3_000, 0, false),
            ], "pending record: {with_pending}");
            assert_eq!((l.balance(HOT).unwrap(), l.balance(DEP).unwrap()), (6_993, 3_000));
            let _ = std::fs::remove_file(path);
        }
    }

    /// A sweep — a deposit address to the hot address — stays a sweep: a send of nothing but its
    /// fee, and no receive, because nobody was paid.
    #[test]
    fn a_sweep_to_the_hot_address_has_no_receive() {
        let (l, path) = ledger("sweep-no-receive");
        l.apply_block(&block(11, vec![tx("t1", EXT, DEP, 1_000, 5, "applied")],
            Some(vec![change(Some(0), EXT, "transaction", -1_005), change(Some(0), DEP, "transaction", 1_000)])), HOT, mine).unwrap();
        l.apply_block(&block(12, vec![tx("s1", DEP, HOT, 990, 10, "applied")],
            Some(vec![change(Some(0), DEP, "transaction", -1_000), change(Some(0), HOT, "transaction", 990)])), HOT, mine).unwrap();
        let entries = l.by_txid("s1").unwrap();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!((entries[0].category, entries[0].amount, entries[0].sweep), (Category::Send, 0, true));
        let _ = std::fs::remove_file(path);
    }

    /// A withdrawal the wallet gave up on — its nonce looked spent — that a block then holds is
    /// what the block says: one entry, in that block, not abandoned. Two entries with the first one
    /// abandoned would show the paid withdrawal as `confirmations: -1` for good (`gettransaction`
    /// reads the first), which is how an exchange comes to pay it twice.
    #[test]
    fn a_block_holding_a_send_the_wallet_gave_up_on_settles_it() {
        let (l, path) = ledger("given-up");
        l.apply_block(&block(11, vec![tx("t1", EXT, HOT, 10_000, 5, "applied")],
            Some(vec![change(Some(0), EXT, "transaction", -10_005), change(Some(0), HOT, "transaction", 10_000)])), HOT, mine).unwrap();
        l.record_pending(pending_entry("w1", EXT, -5_000, -7, false), Pending {
            txid: "w1".into(), kind: PendingKind::Send, from: HOT.into(), nonce: 0, outflow: 5_007,
            wallet_outflow: 5_007, signed: "{}".into(), entry_seq: 0, submitted: 0 }).unwrap();
        l.abandon("w1").unwrap();
        assert!(l.by_txid("w1").unwrap()[0].abandoned, "precondition: given up");
        let outcome = l.apply_block(&block(12, vec![tx("w1", HOT, EXT, 5_000, 7, "applied")],
            Some(vec![change(Some(0), HOT, "transaction", -5_007), change(Some(0), EXT, "transaction", 5_000)])), HOT, mine).unwrap();
        assert_eq!(outcome.txids, vec!["w1".to_string()], "walletnotify runs for it");
        let entries = l.by_txid("w1").unwrap();
        assert_eq!(entries.len(), 1, "one withdrawal, one entry: {entries:?}");
        let e = &entries[0];
        assert_eq!((e.abandoned, e.height, e.amount, e.fee, e.failed.clone()), (false, Some(12), -5_000, -7, None));
        assert_eq!(l.balance(HOT).unwrap(), 4_993);
        let _ = std::fs::remove_file(path);
    }
}
