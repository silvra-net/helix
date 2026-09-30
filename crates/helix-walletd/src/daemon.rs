//! The wallet at work: reading blocks into the ledger, sweeping deposits to the hot address,
//! sending, and seeing every transaction it signed through to a block.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, RwLock};

use anyhow::{anyhow, bail, Context, Result};
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Hash, KeyPair, Signature};

use crate::keys::{KeyError, Keys};
use crate::ledger::{pending_entry, Ledger, Pending, PendingKind};
use crate::node::{Node, Submit, TxState};
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
}

impl Default for Options {
    fn default() -> Self {
        Options { sweep_min: 100_000, keypool: 100, scan_batch: 500, sweeps_per_tick: 10 }
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

/// The fee `tx` pays at `base_fee_per_byte`, by the wallets' one rule — headroom over the base
/// fee, refused above 1 HLX (a node that reports an absurd base fee is not someone whose word
/// spends an exchange's money).
///
/// **Priced on the signed transaction.** A signature is 3,309 bytes, and the base fee is charged
/// per byte: pricing `tx` before it is signed undercharged by exactly that, and the node refused
/// every sweep ("Fee below the block base fee: got 4268, need at least 5443") — found on a real
/// node, not by a unit test. So a copy is signed first and priced; amount and fee are fixed-width,
/// so setting them afterwards does not change the size.
fn fee_for(tx: &Transaction, kp: &KeyPair, base_fee_per_byte: u64) -> Result<u64> {
    let mut signed = tx.clone();
    sign(&mut signed, kp)?;
    helix_core::fee::wallet_auto_fee(base_fee_per_byte, helix_core::fee::wallet_priced_size(&signed))
        .map_err(|e| anyhow!("{e}"))
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
            opts,
            sync: RwLock::new(SyncState::default()),
            send_lock: tokio::sync::Mutex::new(()),
        })
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
        while height < until {
            let block = self.node.block_at(height + 1).await?;
            let outcome = {
                let mut keys = self.keys.lock().expect("keys");
                let outcome = self.ledger.apply_block(&block, |a| keys.is_mine(a))?;
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
            height = block.height;
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
                        tracing::warn!(txid = %p.txid, nonce = p.nonce, "abandoned: another transaction used its nonce");
                        self.ledger.abandon(&p.txid)?;
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
                let fee = fee_for(&tx, &kp, base_fee_per_byte)?;
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
                Ok(()) => tracing::info!(%address, %txid, amount = tx.amount, fee = tx.fee, "swept"),
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

        let tx = tokio::task::block_in_place(|| -> Result<Transaction, RpcError> {
            let mut keys = self.keys.lock().expect("keys");
            let kp = keys.hot().map_err(key_error)?;
            let mut tx = transfer(&hot_address, &to_address, nonce, self.chain_id, kp);
            let fee = fee_for(&tx, kp, base_fee).map_err(|e| RpcError::new(code::WALLET, format!("not sent: {e}")))?;
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
                    crate::amount::Hlx(spendable.max(0)).literal(),
                    crate::amount::Hlx(needed).literal()
                ),
            ));
        }

        let txid = tx.hash().to_hex();
        let wallet_outflow = if internal { tx.fee } else { tx.amount + tx.fee };
        self.ledger
            .record_pending(
                pending_entry(&txid, to, if internal { 0 } else { -(tx.amount as i128) }, -(tx.fee as i128), internal),
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
            Ok(()) => Ok(txid),
            Err(Submit::Refused(reason)) => {
                self.ledger.discard(&txid).map_err(misc)?;
                Err(RpcError::new(code::VERIFY_REJECTED, format!("the node refused the transaction: {reason}")))
            }
            // Recorded, so it is submitted again until a block holds it or its nonce is spent.
            Err(Submit::Unreachable(e)) => {
                tracing::warn!(%txid, err = %e, "send recorded but not confirmed submitted; will retry");
                Ok(txid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let fee = fee_for(&tx, &kp, base).unwrap();
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
}
