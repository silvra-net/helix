//! The wallet at work: reading blocks into the ledger, sweeping deposits to the hot address,
//! sending, and seeing every transaction it signed through to a block.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, RwLock};

use anyhow::{anyhow, bail, Context, Result};
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Hash, KeyPair, Signature};

use crate::amount::{Decimals, Hlx};
use crate::keys::{KeyError, Keys};
use crate::ledger::{pending_entry, Ledger, Pending, PendingKind};
use crate::node::{Node, Submit, TxState};
use crate::notify::Notifier;
use crate::rpc::{code, RpcError};

#[derive(Debug, Clone)]
pub struct Options {
    /// A deposit address is swept once it holds at least this, nano-HLX.
    pub sweep_min: u64,
    /// Addresses an encrypted wallet keeps made ahead, to hand out while locked.
    pub keypool: usize,
    /// Blocks read per tick at most.
    pub scan_batch: u64,
    /// Sweeps signed per tick at most (each decrypts one key).
    pub sweeps_per_tick: usize,
    /// Run for every change to a wallet transaction (`walletnotify`).
    pub walletnotify: Option<String>,
    /// Run when the wallet's view of the chain moves on (`blocknotify`).
    pub blocknotify: Option<String>,
    /// A fee rate sends pay at least, nano-HLX per kB (`paytxfee`, and `settxfee` at runtime).
    pub paytxfee: Option<u64>,
    /// No transaction is signed with a larger fee (`maxtxfee`), nano-HLX.
    pub max_fee: u64,
    /// Decimals amounts are written and read with (`amountdecimals`).
    pub decimals: Decimals,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            sweep_min: 100_000,
            keypool: 100,
            scan_batch: 500,
            sweeps_per_tick: 10,
            walletnotify: None,
            blocknotify: None,
            paytxfee: None,
            max_fee: helix_core::fee::WALLET_AUTO_FEE_CEILING_NANO,
            decimals: Decimals::Nine,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SyncState {
    pub node_tip: u64,
    pub node_syncing: bool,
    pub peer_count: u64,
    pub node_version: String,
    pub base_fee_per_byte: u64,
    /// Why the ledger stopped reading blocks, if it did.
    pub halted: Option<String>,
    /// The last time the node answered.
    pub node_reachable: bool,
}

pub struct Daemon {
    pub node: Node,
    pub keys: Mutex<Keys>,
    pub ledger: Ledger,
    pub chain_id: Hash,
    pub opts: Options,
    pub sync: RwLock<SyncState>,
    /// The fee rate sends pay at least, nano-HLX per kB: `paytxfee`, changed by `settxfee`.
    pub paytxfee: RwLock<Option<u64>>,
    notifier: Notifier,
    send_lock: tokio::sync::Mutex<()>,
}

fn key_error(e: KeyError) -> RpcError {
    let c = match e {
        KeyError::Locked => code::UNLOCK_NEEDED,
        KeyError::PoolEmpty => code::KEYPOOL_RAN_OUT,
        KeyError::WrongPassphrase => code::PASSPHRASE_INCORRECT,
        KeyError::NotEncrypted => code::WRONG_ENC_STATE,
        KeyError::Other(_) => code::WALLET,
    };
    RpcError::new(c, e.to_string())
}

fn misc(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(code::MISC, e.to_string())
}

fn sign(tx: &mut Transaction, kp: &KeyPair) -> Result<()> {
    tx.public_key = Some(kp.public.clone());
    tx.signature = kp.sign(tx.signing_hash().as_bytes()).map_err(|e| anyhow!("signing failed: {e}"))?;
    Ok(())
}

fn transfer(from: &Address, to: &Address, nonce: u64, chain_id: Hash, kp: &KeyPair) -> Transaction {
    Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        from: from.clone(),
        to: Some(to.clone()),
        amount: 0,
        fee: 0,
        nonce,
        data: Vec::new(),
        crypto_version: kp.scheme,
        chain_id,
        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
    }
}

/// How a send to `to` stands in the ledger until a block holds it, and what it takes out of the
/// wallet as a whole. A send to one of the wallet's own addresses keeps its value in the wallet —
/// only the fee leaves — but only a send to the hot address is a sweep: one to a deposit address
/// pays that address's customer, shows its amount, and the block adds the receive (#265).
fn send_record(txid: &str, to: &str, hot: &str, internal: bool, amount: u64, fee: u64) -> (crate::ledger::Entry, u64) {
    let sweep = to == hot;
    let shown = if sweep { 0 } else { -(amount as i128) };
    let wallet_outflow = if internal { fee } else { amount + fee };
    (pending_entry(txid, to, shown, -(fee as i128), sweep), wallet_outflow)
}

/// The fee `tx` pays at `base_fee_per_byte`, by the wallets' one rule — headroom over the base
/// fee, refused above 1 HLX (a node that reports an absurd base fee is not someone whose word
/// spends an exchange's money). A `rate` the operator set (`paytxfee`/`settxfee`, nano-HLX per kB)
/// is paid if it comes to more; nothing above `max_fee` (`maxtxfee`) is ever signed.
///
/// **Priced on the signed transaction.** A signature is 3,309 bytes, and the base fee is charged
/// per byte: pricing `tx` before it is signed undercharged by exactly that, and the node refused
/// every sweep ("Fee below the block base fee: got 4268, need at least 5443") — found on a real
/// node, not by a unit test. So a copy is signed first and priced; amount and fee are fixed-width,
/// so setting them afterwards does not change the size.
fn fee_for(tx: &Transaction, kp: &KeyPair, base_fee_per_byte: u64, rate: Option<u64>, max_fee: u64) -> Result<u64> {
    let mut signed = tx.clone();
    sign(&mut signed, kp)?;
    let size = helix_core::fee::wallet_priced_size(&signed);
    let auto = helix_core::fee::wallet_auto_fee(base_fee_per_byte, size).map_err(|e| anyhow!("{e}"))?;
    let chosen = match rate {
        Some(per_kb) => auto.max(per_kb.saturating_mul(size).div_ceil(1000)),
        None => auto,
    };
    if chosen > max_fee {
        bail!(
            "the fee would be {} HLX, above maxtxfee ({} HLX)",
            Hlx::exact(chosen as i128).literal(),
            Hlx::exact(max_fee as i128).literal()
        );
    }
    Ok(chosen)
}

impl Daemon {
    /// Open the wallet in `dir` against `node`. Refuses a node on another chain.
    pub async fn open(dir: &Path, node: Node, opts: Options) -> Result<Daemon> {
        let keys = Keys::open(dir)?;
        let chain_id = Hash::from_hex(&keys.meta.chain_id)
            .map_err(|_| anyhow!("wallet.json names a malformed chain id {:?}", keys.meta.chain_id))?;
        let genesis = node.header(0).await.context("could not read the node's genesis block")?;
        if genesis.hash != keys.meta.chain_id {
            bail!(
                "the node at {} is on the chain with genesis {}, and this wallet signs for {} — \
                 refusing to run a wallet against another chain",
                node.url(),
                genesis.hash,
                keys.meta.chain_id
            );
        }
        let ledger = Ledger::open(&dir.join("ledger.redb"))?;
        if ledger.scanned()?.is_none() {
            let birth = node.header(keys.meta.birth_height).await?;
            ledger.start_at(birth.height, &birth.hash)?;
        }
        Ok(Daemon {
            node,
            keys: Mutex::new(keys),
            ledger,
            chain_id,
            paytxfee: RwLock::new(opts.paytxfee),
            notifier: Notifier::new(opts.walletnotify.clone(), opts.blocknotify.clone()),
            opts,
            sync: RwLock::new(SyncState::default()),
            send_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// An amount as answers write it: in the wallet's decimals, never shown in the exchange's
    /// favour (a credit not larger, a debit not smaller).
    pub fn shown(&self, nano: i128) -> Hlx {
        Hlx::down(nano, self.opts.decimals)
    }

    /// A fee rate as answers write it: never shown below what is charged.
    pub fn rate(&self, nano: i128) -> Hlx {
        Hlx::up(nano, self.opts.decimals)
    }

    /// An amount from a request, in the wallet's decimals.
    pub fn parse_amount(&self, raw: &serde_json::value::RawValue) -> Result<u64, RpcError> {
        crate::amount::parse(raw, self.opts.decimals).map_err(|e| RpcError::new(code::TYPE, e))
    }

    pub fn hot_address(&self) -> String {
        self.keys.lock().expect("keys").meta.hot_address.clone()
    }

    pub fn scanned_height(&self) -> u64 {
        self.ledger.scanned().ok().flatten().map(|(h, _)| h).unwrap_or(0)
    }

    /// One round of the background work. Errors reaching the node end the round and are
    /// reported through `sync`; nothing here gives up for good.
    pub async fn tick(&self) {
        let status = match self.node.status().await {
            Ok(s) => s,
            Err(e) => {
                self.sync.write().expect("sync").node_reachable = false;
                tracing::warn!(err = %e, "the node did not answer");
                return;
            }
        };
        {
            let mut sync = self.sync.write().expect("sync");
            sync.node_reachable = true;
            sync.node_tip = status.height;
            sync.node_syncing = status.is_syncing;
            sync.peer_count = status.peer_count;
            sync.node_version = status.version.clone();
            sync.base_fee_per_byte = status.base_fee_per_byte;
        }
        if let Err(e) = self.scan(status.height).await {
            let message = e.to_string();
            let mut sync = self.sync.write().expect("sync");
            if sync.halted.as_deref() != Some(message.as_str()) {
                tracing::error!(%message, "stopped reading blocks");
            }
            sync.halted = Some(message);
            return;
        }
        self.sync.write().expect("sync").halted = None;
        if let Err(e) = self.check_pending().await {
            tracing::warn!(err = %e, "could not check pending transactions");
        }
        if !status.is_syncing {
            if let Err(e) = self.sweep(status.base_fee_per_byte).await {
                tracing::warn!(err = %e, "sweeping stopped for this round");
            }
        }
        // One address made ahead per round, encrypted outside the lock.
        let maker = {
            let mut keys = self.keys.lock().expect("keys");
            if keys.meta.encrypted { keys.maker(self.opts.keypool) } else { None }
        };
        if let Some(maker) = maker {
            match tokio::task::block_in_place(|| maker.make()) {
                Ok(address) => self.keys.lock().expect("keys").adopt(address),
                Err(e) => tracing::warn!(err = %e, "could not make an address ahead"),
            }
        }
    }

    async fn scan(&self, tip: u64) -> Result<()> {
        let (mut height, _) = self.ledger.scanned()?.ok_or_else(|| anyhow!("the ledger has no start"))?;
        let until = tip.min(height + self.opts.scan_batch);
        let mut newest: Option<String> = None;
        while height < until {
            let block = self.node.block_at(height + 1).await?;
            let outcome = {
                let mut keys = self.keys.lock().expect("keys");
                let hot = keys.meta.hot_address.clone();
                let outcome = self.ledger.apply_block(&block, &hot, |a| keys.is_mine(a))?;
                // An address that has been paid counts as handed out, whatever the issued log
                // says — after a restore from an older backup it must not be handed out again.
                for address in &outcome.paid {
                    keys.mark_issued(address, "")?;
                }
                outcome
            };
            if outcome.received > 0 || outcome.settled > 0 {
                tracing::info!(height = block.height, received = outcome.received, settled = outcome.settled, "wallet activity");
            }
            for txid in &outcome.txids {
                self.notifier.wallet_tx(txid, Some((&block.hash, block.height)));
            }
            height = block.height;
            newest = Some(block.hash);
        }
        // Once per round, with the newest block: catching up a thousand blocks does not start a
        // thousand commands.
        if let Some(hash) = newest {
            self.notifier.block(&hash);
        }
        Ok(())
    }

    /// Submit again what expired unincluded; give up on what another transaction's nonce
    /// replaced. What applied or failed is settled by the scan, from the block itself.
    async fn check_pending(&self) -> Result<()> {
        for p in self.ledger.pending()? {
            match self.node.tx_state(&p.txid).await? {
                TxState::Pending | TxState::Applied | TxState::Failed(_) => {}
                TxState::Expired | TxState::Unknown => {
                    let account = self.node.account(&p.from).await?;
                    if account.nonce > p.nonce {
                        // Its nonce is spent — by another transaction, or by this one, in a block the
                        // node applied after it answered that it knows no such transaction. Asked one
                        // after the other, the pool and the account are not one snapshot, and a
                        // withdrawal that paid would be given up as `confirmations: -1`: the one
                        // answer that makes an exchange pay it again. So it is given up only once the
                        // wallet has read every block of the state that spent the nonce — had this
                        // transaction been in one of them, reading it would have settled it.
                        if self.scanned_height() < account.state_height {
                            continue;
                        }
                        tracing::warn!(txid = %p.txid, nonce = p.nonce, "abandoned: another transaction used its nonce");
                        self.ledger.abandon(&p.txid)?;
                        self.notifier.wallet_tx(&p.txid, None);
                    } else {
                        let tx: Transaction = serde_json::from_str(&p.signed)?;
                        match self.node.submit(&tx).await {
                            Ok(()) => tracing::info!(txid = %p.txid, "submitted again"),
                            Err(e) => tracing::warn!(txid = %p.txid, err = ?e, "could not submit again"),
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Move what deposit addresses hold to the hot address, so sends draw from one balance.
    async fn sweep(&self, base_fee_per_byte: u64) -> Result<()> {
        let (hot, unlocked) = {
            let mut keys = self.keys.lock().expect("keys");
            (keys.meta.hot_address.clone(), keys.is_unlocked())
        };
        if !unlocked {
            return Ok(());
        }
        let busy: HashSet<String> = self.ledger.pending()?.into_iter().map(|p| p.from).collect();
        let candidates: Vec<(String, u64)> = self
            .ledger
            .balances()?
            .into_iter()
            .filter(|(a, b)| a != &hot && *b >= self.opts.sweep_min && !busy.contains(a))
            .take(self.opts.sweeps_per_tick)
            .collect();
        let hot_address = Address::from_str(&hot).map_err(|e| anyhow!("hot address: {e}"))?;
        for (address, balance) in candidates {
            let account = self.node.account(&address).await?;
            if account.balance < balance {
                tracing::warn!(%address, ledger = balance, node = account.balance, "the node holds less than the ledger — not sweeping");
                continue;
            }
            let from = Address::from_str(&address).map_err(|e| anyhow!("{address}: {e}"))?;
            let access = self.keys.lock().expect("keys").access(&address).map_err(|e| anyhow!("{e}"))?;
            let signed = tokio::task::block_in_place(|| -> Result<Option<Transaction>> {
                let kp = access.pair()?;
                let mut tx = transfer(&from, &hot_address, account.nonce, self.chain_id, &kp);
                // A sweep moves nothing out of the wallet; it pays the going fee, not `paytxfee`.
                let fee = fee_for(&tx, &kp, base_fee_per_byte, None, self.opts.max_fee)?;
                if balance <= fee {
                    return Ok(None);
                }
                tx.fee = fee;
                tx.amount = balance - fee;
                sign(&mut tx, &kp)?;
                Ok(Some(tx))
            })?;
            let Some(tx) = signed else { continue };
            let txid = tx.hash().to_hex();
            self.ledger.record_pending(
                pending_entry(&txid, &hot, 0, -(tx.fee as i128), true),
                Pending {
                    txid: txid.clone(),
                    kind: PendingKind::Sweep,
                    from: address.clone(),
                    nonce: tx.nonce,
                    outflow: tx.amount + tx.fee,
                    wallet_outflow: tx.fee,
                    signed: serde_json::to_string(&tx)?,
                    entry_seq: 0,
                    submitted: 0,
                },
            )?;
            match self.node.submit(&tx).await {
                Ok(()) => {
                    tracing::info!(%address, %txid, amount = tx.amount, fee = tx.fee, "swept");
                    self.notifier.wallet_tx(&txid, None);
                }
                Err(Submit::Refused(reason)) => {
                    tracing::warn!(%address, %reason, "the node refused a sweep");
                    self.ledger.discard(&txid)?;
                }
                Err(Submit::Unreachable(e)) => tracing::warn!(%address, err = %e, "sweep not confirmed submitted; will retry"),
            }
        }
        Ok(())
    }

    /// Nano-HLX the wallet can spend: every address's balance, less what its own pending
    /// transactions take out of it.
    pub fn balance(&self) -> Result<u64, RpcError> {
        let held: i128 = self.ledger.balances().map_err(misc)?.iter().map(|(_, b)| *b as i128).sum();
        let pending: i128 = self.ledger.pending().map_err(misc)?.iter().map(|p| p.wallet_outflow as i128).sum();
        Ok((held - pending).max(0) as u64)
    }

    /// Send `amount` nano-HLX from the hot address. Returns the transaction id.
    pub async fn send(&self, to: &str, amount: u64, subtract_fee: bool) -> Result<String, RpcError> {
        let to_address = Address::from_str(to).map_err(|e| RpcError::new(code::INVALID_ADDRESS, format!("Invalid Helix address: {e}")))?;
        if amount == 0 {
            return Err(RpcError::new(code::TYPE, "Invalid amount for send"));
        }
        let _one_at_a_time = self.send_lock.lock().await;
        {
            let sync = self.sync.read().expect("sync");
            if sync.node_syncing {
                return Err(RpcError::new(code::IN_INITIAL_DOWNLOAD, "the node is still syncing — try again when it has caught up"));
            }
        }
        let (hot, internal) = {
            let keys = self.keys.lock().expect("keys");
            (keys.meta.hot_address.clone(), keys.is_mine(to))
        };
        let hot_address = Address::from_str(&hot).map_err(misc)?;
        let pending = self.ledger.pending().map_err(misc)?;
        let account = self.node.account(&hot).await.map_err(|e| RpcError::new(code::NOT_CONNECTED, e.to_string()))?;
        let nonce = pending
            .iter()
            .filter(|p| p.from == hot)
            .map(|p| p.nonce + 1)
            .max()
            .unwrap_or(0)
            .max(account.nonce);
        let base_fee = self.node.status().await.map_err(|e| RpcError::new(code::NOT_CONNECTED, e.to_string()))?.base_fee_per_byte;
        let rate = *self.paytxfee.read().expect("paytxfee");

        let tx = tokio::task::block_in_place(|| -> Result<Transaction, RpcError> {
            let mut keys = self.keys.lock().expect("keys");
            let kp = keys.hot().map_err(key_error)?;
            let mut tx = transfer(&hot_address, &to_address, nonce, self.chain_id, kp);
            let fee = fee_for(&tx, kp, base_fee, rate, self.opts.max_fee).map_err(|e| RpcError::new(code::WALLET, format!("not sent: {e}")))?;
            let amount = if subtract_fee {
                amount.checked_sub(fee).filter(|a| *a > 0).ok_or_else(|| {
                    RpcError::new(code::WALLET, "the amount does not cover the fee it should pay")
                })?
            } else {
                amount
            };
            tx.amount = amount;
            tx.fee = fee;
            sign(&mut tx, kp).map_err(misc)?;
            Ok(tx)
        })?;

        let spendable = self.ledger.balance(&hot).map_err(misc)? as i128
            - pending.iter().filter(|p| p.from == hot).map(|p| p.outflow as i128).sum::<i128>();
        let needed = (tx.amount + tx.fee) as i128;
        if spendable < needed {
            let waiting: i128 = self
                .ledger
                .balances()
                .map_err(misc)?
                .into_iter()
                .filter(|(a, _)| a != &hot)
                .map(|(_, b)| b as i128)
                .sum();
            let hint = if spendable + waiting >= needed {
                " — deposits that would cover it are waiting to be swept to the hot address, which \
                 happens within seconds while the wallet is unlocked"
            } else {
                ""
            };
            return Err(RpcError::new(
                code::INSUFFICIENT_FUNDS,
                format!(
                    "Insufficient funds: the hot address can spend {} HLX, this send needs {} HLX{hint}",
                    Hlx::exact(spendable.max(0)).literal(),
                    Hlx::exact(needed).literal()
                ),
            ));
        }

        let txid = tx.hash().to_hex();
        let (entry, wallet_outflow) = send_record(&txid, to, &hot, internal, tx.amount, tx.fee);
        self.ledger
            .record_pending(
                entry,
                Pending {
                    txid: txid.clone(),
                    kind: PendingKind::Send,
                    from: hot.clone(),
                    nonce: tx.nonce,
                    outflow: tx.amount + tx.fee,
                    wallet_outflow,
                    signed: serde_json::to_string(&tx).map_err(misc)?,
                    entry_seq: 0,
                    submitted: 0,
                },
            )
            .map_err(misc)?;
        match self.node.submit(&tx).await {
            Ok(()) => {
                self.notifier.wallet_tx(&txid, None);
                Ok(txid)
            }
            Err(Submit::Refused(reason)) => {
                self.ledger.discard(&txid).map_err(misc)?;
                Err(RpcError::new(code::VERIFY_REJECTED, format!("the node refused the transaction: {reason}")))
            }
            // Recorded, so it is submitted again until a block holds it or its nonce is spent.
            Err(Submit::Unreachable(e)) => {
                tracing::warn!(%txid, err = %e, "send recorded but not confirmed submitted; will retry");
                self.notifier.wallet_tx(&txid, None);
                Ok(txid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
    use std::sync::Arc;

    const CHAIN: &str = "abababababababababababababababababababababababababababababababab";

    /// A node that has forgotten a transaction — it left the pool unincluded — while the sender's
    /// account stands at `nonce` as of block `state_height`; it counts what is submitted to it.
    fn forgetful_node(nonce: Arc<AtomicU64>, state_height: Arc<AtomicU64>, submits: Arc<AtomicU64>) -> axum::Router {
        use axum::routing::{get, post};
        let genesis = serde_json::json!({ "hash": CHAIN, "height": 0, "timestamp": 0, "prev_hash": "00".repeat(32) });
        axum::Router::new()
            .route("/blocks/height/:h/header", get(move || {
                let genesis = genesis.clone();
                async move { axum::Json(genesis) }
            }))
            .route("/accounts/:a", get(move || {
                let (nonce, state_height) = (nonce.clone(), state_height.clone());
                async move {
                    axum::Json(serde_json::json!({ "balance_nano": "0", "nonce": nonce.load(SeqCst), "state_height": state_height.load(SeqCst) }))
                }
            }))
            .route("/transactions/:h", get(|| async {
                (axum::http::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({ "status": "expired" })))
            }))
            .route("/transactions", post(move || {
                let submits = submits.clone();
                async move {
                    submits.fetch_add(1, SeqCst);
                    axum::Json(serde_json::json!({}))
                }
            }))
    }

    /// Until a block holds it, a send to a deposit address of the wallet shows its amount and takes
    /// only the fee out of the wallet; a send to the hot address is a sweep; a send outside takes
    /// amount and fee.
    #[test]
    fn a_send_inside_the_wallet_keeps_its_value_and_only_a_send_to_the_hot_address_is_a_sweep() {
        let (to_deposit, out) = send_record("t", "hlxDeposit", "hlxHot", true, 3_000, 7);
        assert_eq!((to_deposit.amount, to_deposit.fee, to_deposit.sweep, out), (-3_000, -7, false, 7));
        let (to_hot, out) = send_record("t", "hlxHot", "hlxHot", true, 3_000, 7);
        assert_eq!((to_hot.amount, to_hot.sweep, out), (0, true, 7));
        let (outside, out) = send_record("t", "hlxElsewhere", "hlxHot", false, 3_000, 7);
        assert_eq!((outside.amount, outside.sweep, out), (-3_000, false, 3_007));
    }

    /// The pool and the account are asked one after the other, and a block can land between the
    /// answers: "no such transaction", then "its nonce is spent" — spent by this very withdrawal.
    /// Given up then, a withdrawal that paid shows `confirmations: -1`, and an exchange pays it
    /// again. It is given up only once the wallet has read the block that spent the nonce.
    #[tokio::test]
    async fn a_send_whose_nonce_went_in_a_block_the_wallet_has_not_read_is_not_given_up() {
        let dir = std::env::temp_dir().join(format!("helix-walletd-given-up-{}", rand::random::<u64>()));
        let hot = Keys::create(&dir, "test", CHAIN, 0, None).unwrap().meta.hot_address.clone();
        // The wallet has read the chain up to block 5.
        Ledger::open(&dir.join("ledger.redb")).unwrap().start_at(5, "h5").unwrap();
        let (nonce, state_height, submits) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(5)), Arc::new(AtomicU64::new(0)));
        let node = Node::in_process(forgetful_node(nonce.clone(), state_height.clone(), submits.clone()));
        let daemon = Daemon::open(&dir, node, Options::default()).await.unwrap();
        let kp = KeyPair::generate();
        let from = Address::from_str(&hot).unwrap();
        let to = Address::from_public_key(&KeyPair::generate().public);
        let signed = serde_json::to_string(&transfer(&from, &to, 0, daemon.chain_id, &kp)).unwrap();
        let txid = "cd".repeat(32);
        daemon.ledger.record_pending(pending_entry(&txid, &to.to_string(), -5_000, -7, false), Pending {
            txid: txid.clone(), kind: PendingKind::Send, from: hot.clone(), nonce: 0, outflow: 5_007,
            wallet_outflow: 5_007, signed, entry_seq: 0, submitted: 0 }).unwrap();

        // Its nonce unspent: the pool lost it, so it is submitted again.
        daemon.check_pending().await.unwrap();
        assert_eq!(submits.load(SeqCst), 1, "the stand-in must answer as a node that lost the transaction");
        assert_eq!(daemon.ledger.pending().unwrap().len(), 1);

        // Spent as of block 7, and the wallet has read up to 5: block 6 or 7 may hold this very
        // withdrawal.
        nonce.store(1, SeqCst);
        state_height.store(7, SeqCst);
        daemon.check_pending().await.unwrap();
        assert_eq!(daemon.ledger.pending().unwrap().len(), 1, "given up on a nonce spent in a block the wallet has not read");
        assert!(!daemon.ledger.by_txid(&txid).unwrap()[0].abandoned);

        // Spent as of a block the wallet has read: that block did not hold it, or reading it would
        // have settled it. Given up.
        state_height.store(5, SeqCst);
        daemon.check_pending().await.unwrap();
        assert!(daemon.ledger.pending().unwrap().is_empty(), "a send whose nonce another transaction took is given up");
        assert!(daemon.ledger.by_txid(&txid).unwrap()[0].abandoned);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What the node charges is the base fee times the bytes the block carries of the *signed*
    /// transaction; the wallet's fee must cover that for a first transaction (key carried) and a
    /// later one (key dropped, #243).
    #[test]
    fn the_fee_covers_the_base_fee_of_the_signed_transaction() {
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let to = Address::from_public_key(&KeyPair::generate().public);
        for (nonce, base) in [(0u64, 1u64), (0, 7), (5, 1), (5, 3)] {
            let mut tx = transfer(&from, &to, nonce, Hash::ZERO, &kp);
            let fee = fee_for(&tx, &kp, base, None, u64::MAX).unwrap();
            tx.fee = fee;
            tx.amount = 123_456_789;
            sign(&mut tx, &kp).unwrap();
            let charged = base * helix_core::fee::wallet_priced_size(&tx);
            assert!(fee >= charged, "nonce {nonce}, base {base}: fee {fee} under the {charged} the node charges");
            if nonce == 0 {
                assert!(fee >= base * tx.size_bytes(), "a first transaction carries its key and pays for it");
            }
        }
    }

    /// `paytxfee` raises a send's fee to its rate when that comes to more than the going fee, and
    /// nothing above `maxtxfee` is ever signed — the operator's ceiling, as in Bitcoin Core.
    #[test]
    fn paytxfee_raises_the_fee_and_maxtxfee_caps_it() {
        let kp = KeyPair::generate();
        let from = Address::from_public_key(&kp.public);
        let to = Address::from_public_key(&KeyPair::generate().public);
        let tx = transfer(&from, &to, 0, Hash::ZERO, &kp);
        let mut signed = tx.clone();
        sign(&mut signed, &kp).unwrap();
        let size = helix_core::fee::wallet_priced_size(&signed);
        let auto = fee_for(&tx, &kp, 1, None, u64::MAX).unwrap();
        assert_eq!(fee_for(&tx, &kp, 1, Some(1), u64::MAX).unwrap(), auto, "a rate below the going fee changes nothing");
        let per_kb = 1_000_000;
        assert_eq!(fee_for(&tx, &kp, 1, Some(per_kb), u64::MAX).unwrap(), (per_kb * size).div_ceil(1000));
        let err = fee_for(&tx, &kp, 1, Some(1_000_000_000), helix_core::fee::WALLET_AUTO_FEE_CEILING_NANO).unwrap_err();
        assert!(err.to_string().contains("maxtxfee"), "{err}");
        assert!(fee_for(&tx, &kp, 1, None, auto - 1).is_err(), "the going fee is capped too");
    }
}
