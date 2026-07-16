use helix_core::{transaction::Amount, Transaction, TxType};
use helix_crypto::{Hash, PublicKey};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("Transaction {0} already in mempool")]
    AlreadyExists(String),
    #[error("Nonce already pending: a transaction from {from} with nonce {nonce} is already in the mempool")]
    NoncePending { from: String, nonce: u64 },
    #[error("Mempool full (max {0} transactions)")]
    Full(usize),
    #[error("Fee too low: got {got}, minimum {min}")]
    FeeTooLow { got: Amount, min: Amount },
    #[error(
        "Fee below the block base fee: got {got}, need at least {need} \
         ({size_bytes} bytes × {base_fee_per_byte} nano-HLX/byte)"
    )]
    BelowBaseFee {
        got: Amount,
        need: Amount,
        size_bytes: u64,
        base_fee_per_byte: u64,
    },
    #[error("Invalid transaction: {0}")]
    Invalid(String),
}

pub type MempoolResult<T> = Result<T, MempoolError>;

const DEFAULT_MAX_SIZE: usize = 10_000;
const DEFAULT_MIN_FEE: Amount = 1_000; // 1000 nano-HLX
/// A tx that sits in the pool longer than this without being committed is
/// dropped, freeing its (sender, nonce) slot. Without this, a tx that can
/// never be included (insufficient balance, unfillable nonce gap ahead of it)
/// blocks that slot forever whenever the pool isn't full enough to trigger
/// fee-based eviction.
const DEFAULT_TTL: Duration = Duration::from_secs(30 * 60);

/// Fee-prioritized transaction pool.
/// Higher fee → included in next block first.
pub struct Mempool {
    /// fee (descending) → vec of tx hashes at that fee level
    by_fee: BTreeMap<std::cmp::Reverse<Amount>, Vec<String>>,
    /// hash → transaction
    by_hash: HashMap<String, Transaction>,
    /// (sender_address, nonce) → tx hash — prevents two txs with the same nonce
    /// from the same sender clogging the pool (only one can ever succeed)
    by_sender_nonce: HashMap<(String, u64), String>,
    /// hash → time of admission, used for TTL-based expiry
    entered_at: HashMap<String, Instant>,
    max_size: usize,
    min_fee: Amount,
    ttl: Duration,
    /// The EIP-1559 base fee (nano-HLX per tx byte) the next block will charge, mirrored from
    /// consensus via `set_base_fee_per_byte` after every commit. The pool holds a copy rather
    /// than reaching for chain state, which it has no access to.
    ///
    /// Without it, admission had only the flat `min_fee` to go on, and the two disagree badly:
    /// `min_fee` is 1000 nano while a plain ML-DSA-signed transfer is ~5.4 KB, so even at the
    /// base-fee *floor* it owes ~5410 nano. Every transaction paying between the two was
    /// admitted, gossiped, mined into a block, and only then rejected by `execute_transaction`
    /// for underpaying — burning a block slot to fail a transaction the pool could have turned
    /// away up front, with a clear reason, before the sender ever waited on it.
    base_fee_per_byte: u64,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            by_fee: BTreeMap::new(),
            by_hash: HashMap::new(),
            by_sender_nonce: HashMap::new(),
            entered_at: HashMap::new(),
            max_size: DEFAULT_MAX_SIZE,
            min_fee: DEFAULT_MIN_FEE,
            ttl: DEFAULT_TTL,
            base_fee_per_byte: helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
        }
    }

    /// Like `new()` but with custom limits — mainly useful for tests that need
    /// to exercise full-pool behavior without inserting thousands of transactions.
    pub fn with_limits(max_size: usize, min_fee: Amount) -> Self {
        Mempool {
            by_fee: BTreeMap::new(),
            by_hash: HashMap::new(),
            by_sender_nonce: HashMap::new(),
            entered_at: HashMap::new(),
            max_size,
            min_fee,
            ttl: DEFAULT_TTL,
            base_fee_per_byte: helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
        }
    }

    /// Like `with_limits` but also overrides the TTL — used by tests that need
    /// to exercise expiry without waiting `DEFAULT_TTL`.
    pub fn with_limits_and_ttl(max_size: usize, min_fee: Amount, ttl: Duration) -> Self {
        Mempool {
            by_fee: BTreeMap::new(),
            by_hash: HashMap::new(),
            by_sender_nonce: HashMap::new(),
            entered_at: HashMap::new(),
            max_size,
            min_fee,
            ttl,
            base_fee_per_byte: helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
        }
    }

    /// Like `new()` but with a custom TTL — lets deployments configure eviction
    /// timing (e.g. via `helix.toml`/`HELIX_MEMPOOL_TX_TTL_SECS`) without touching
    /// `max_size`/`min_fee`.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self::with_limits_and_ttl(DEFAULT_MAX_SIZE, DEFAULT_MIN_FEE, ttl)
    }

    /// Mirror the base fee the next block will charge, so admission can reject what execution
    /// would reject anyway. The node calls this from the same place it reseeds the consensus
    /// engine's own copy — at startup from the persisted tip, and after every commit.
    ///
    /// Only affects transactions admitted *after* it: a pool holding transactions priced for a
    /// lower base fee keeps them, and they fail at execution as they did before. Re-pricing the
    /// existing pool on every commit would be the thorough thing, but the fee moves at most
    /// ±12.5% per block and a stale transaction expires on its own (`ttl`) — not worth walking
    /// the whole pool every 2 seconds.
    pub fn set_base_fee_per_byte(&mut self, base_fee_per_byte: u64) {
        self.base_fee_per_byte = base_fee_per_byte;
    }

    pub fn base_fee_per_byte(&self) -> u64 {
        self.base_fee_per_byte
    }

    /// Drop all transactions that have been sitting in the pool longer than `ttl`.
    /// Called lazily from `add()`/`take()` rather than on a background timer.
    fn evict_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .entered_at
            .iter()
            .filter(|(_, &t)| now.duration_since(t) >= self.ttl)
            .map(|(h, _)| h.clone())
            .collect();
        for hash in expired {
            self.entered_at.remove(&hash);
            if let Some(tx) = self.by_hash.remove(&hash) {
                if let Some(bucket) = self.by_fee.get_mut(&std::cmp::Reverse(tx.fee)) {
                    bucket.retain(|h| h != &hash);
                    if bucket.is_empty() {
                        self.by_fee.remove(&std::cmp::Reverse(tx.fee));
                    }
                }
                self.by_sender_nonce.remove(&(tx.from.to_string(), tx.nonce));
            }
        }
    }

    pub fn add(&mut self, tx: Transaction) -> MempoolResult<()> {
        self.add_inner(tx, None)
    }

    /// Like `add`, but for a sender whose control was ever rotated by social-recovery
    /// guardian quorum: `recovery_key` (looked up via `ChainState::recovery_key` by the
    /// caller, which alone has chain-state access) is the active override key that must
    /// have produced the signature. Without this, `add`'s plain `verify_signature` would
    /// reject every transaction from a recovered account outright — the new key never
    /// hashes to the (unchanged) address by design — and `execute_transaction`'s equally
    /// recovery-aware check would never be reachable for it. `recovery_key: None` behaves
    /// exactly like `add`.
    pub fn add_with_recovery_key(
        &mut self,
        tx: Transaction,
        recovery_key: Option<&PublicKey>,
    ) -> MempoolResult<()> {
        self.add_inner(tx, recovery_key)
    }

    fn add_inner(&mut self, tx: Transaction, recovery_key: Option<&PublicKey>) -> MempoolResult<()> {
        self.evict_expired();

        if tx.fee < self.min_fee {
            return Err(MempoolError::FeeTooLow {
                got: tx.fee,
                min: self.min_fee,
            });
        }

        // Mirrors `execute_transaction`'s base-fee check, including its exemption: double-sign
        // evidence carries two full votes (~16 KB) and pays a flat reporter fee that the base
        // fee exceeds even at the floor, so charging it here would reject every slashing report
        // at the pool — silently disabling slashing, exactly as a fee-0 evidence tx once did.
        // The two checks must agree; if they ever drift, this pool starts either admitting
        // transactions that cannot execute or refusing ones that could.
        if tx.tx_type != TxType::SubmitDoubleSignEvidence {
            let size_bytes = tx.size_bytes();
            let need = self.base_fee_per_byte.saturating_mul(size_bytes);
            if tx.fee < need {
                return Err(MempoolError::BelowBaseFee {
                    got: tx.fee,
                    need,
                    size_bytes,
                    base_fee_per_byte: self.base_fee_per_byte,
                });
            }
        }

        let hash = tx.hash().to_hex();

        if self.by_hash.contains_key(&hash) {
            return Err(MempoolError::AlreadyExists(hash));
        }

        // Reject if a different tx from the same sender at the same nonce is already pending.
        // Two txs with the same (from, nonce) cannot both succeed; admitting both wastes
        // block space and degrades UX.
        let sender_nonce_key = (tx.from.to_string(), tx.nonce);
        if self.by_sender_nonce.contains_key(&sender_nonce_key) {
            return Err(MempoolError::NoncePending {
                from: tx.from.to_string(),
                nonce: tx.nonce,
            });
        }

        // Verify signature before accepting — and, crucially, before the full-pool
        // eviction check below. A tx with an invalid signature is rejected outright
        // and must never be allowed to trigger eviction of a real, already-admitted
        // tx: `fee` is a self-declared, unverified field at this point, so without
        // this ordering an attacker could submit unsigned/garbage-signature txs with
        // an inflated fee to have `evict_lowest_fee()` discard a legitimate tx, then
        // have their own (never-admitted) tx rejected here — a free way to grind
        // down other users' pending transactions.
        tx.verify_signature_with_recovery_key(recovery_key)
            .map_err(|e| MempoolError::Invalid(e.to_string()))?;

        if self.by_hash.len() >= self.max_size {
            // Pool is full: only admit this tx if it strictly outbids the cheapest
            // tx currently held, evicting that one to make room. Otherwise a
            // sustained flood of just-above-min-fee spam could permanently lock
            // out legitimate higher-fee transactions.
            let lowest_fee = self.by_fee.keys().next_back().map(|r| r.0);
            match lowest_fee {
                Some(lowest) if tx.fee > lowest => self.evict_lowest_fee(),
                _ => return Err(MempoolError::Full(self.max_size)),
            }
        }

        self.by_fee
            .entry(std::cmp::Reverse(tx.fee))
            .or_default()
            .push(hash.clone());

        self.by_sender_nonce.insert(sender_nonce_key, hash.clone());
        self.entered_at.insert(hash.clone(), Instant::now());
        self.by_hash.insert(hash, tx);
        Ok(())
    }

    /// Take up to `max_count` highest-fee transactions for block inclusion.
    /// Does NOT remove them — call `remove_committed` after the block is finalized.
    ///
    /// TXs are sorted by (sender, nonce) after the fee-priority pass so that a
    /// sender's sequential nonces always land in the correct order in the block.
    /// Without this, nonce N+1 arriving before N would be dropped by the executor.
    pub fn take(&mut self, max_count: usize) -> Vec<Transaction> {
        self.evict_expired();
        let mut result = Vec::with_capacity(max_count);
        'outer: for hashes in self.by_fee.values() {
            for hash in hashes {
                if result.len() >= max_count {
                    break 'outer;
                }
                if let Some(tx) = self.by_hash.get(hash) {
                    result.push(tx.clone());
                }
            }
        }
        // Within a sender, nonces must be strictly ascending — sort to guarantee that.
        result.sort_by(|a, b| {
            a.from.to_string().cmp(&b.from.to_string()).then_with(|| a.nonce.cmp(&b.nonce))
        });
        result
    }

    /// Remove transactions that were committed in a block
    pub fn remove_committed(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            let key = hash.to_hex();
            if let Some(tx) = self.by_hash.remove(&key) {
                let bucket = self.by_fee.get_mut(&std::cmp::Reverse(tx.fee));
                if let Some(bucket) = bucket {
                    bucket.retain(|h| h != &key);
                    if bucket.is_empty() {
                        self.by_fee.remove(&std::cmp::Reverse(tx.fee));
                    }
                }
                self.by_sender_nonce.remove(&(tx.from.to_string(), tx.nonce));
            }
            self.entered_at.remove(&key);
        }
    }

    /// Remove the single cheapest transaction currently in the pool, making room
    /// for one new admission. No-op if the pool is empty.
    fn evict_lowest_fee(&mut self) {
        let lowest_key = match self.by_fee.keys().next_back().copied() {
            Some(k) => k,
            None => return,
        };
        let hash = {
            let bucket = self.by_fee.get_mut(&lowest_key).expect("key just observed to exist");
            bucket.remove(0)
        };
        if self.by_fee.get(&lowest_key).is_some_and(|b| b.is_empty()) {
            self.by_fee.remove(&lowest_key);
        }
        if let Some(tx) = self.by_hash.remove(&hash) {
            self.by_sender_nonce.remove(&(tx.from.to_string(), tx.nonce));
        }
        self.entered_at.remove(&hash);
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.by_hash.contains_key(&hash.to_hex())
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_core::{Transaction, TxType};
    use helix_crypto::{Address, KeyPair, Signature};

    /// Fees here are ~10k nano and up, not the ~1k `min_fee` suggests, because a real
    /// ML-DSA-signed transfer is ~5.4 KB and owes ~5410 nano at the base-fee floor alone. This
    /// suite used to build every transaction with `fee: 5_000` — over the flat minimum, under
    /// what the chain charges — so each one would have been admitted here and then rejected at
    /// execution. Nothing caught it because these tests never reach the executor. Keep test fees
    /// above the floor; a value that only clears `min_fee` describes a transaction that cannot
    /// actually be spent.
    fn make_tx(keypair: &KeyPair, fee: Amount, nonce: u64) -> Transaction {
        let addr = Address::from_public_key(&keypair.public);
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: addr.clone(),
            to: Some(addr),
            amount: 1_000_000,
            fee,
            nonce,
            data: vec![],
            crypto_version: keypair.scheme,
            signature: Signature::from_bytes(vec![0u8; 32]),
            public_key: keypair.public.clone(),
        };
        let hash = tx.signing_hash();
        tx.signature = keypair.sign(hash.as_bytes()).unwrap();
        tx
    }

    #[test]
    fn test_add_and_take() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let mut pool = Mempool::new();

        // Two TXs from same sender — must come out in nonce order (not fee order)
        let tx_lo = make_tx(&kp1, 10_000, 0);
        let tx_hi = make_tx(&kp1, 20_000, 1);
        pool.add(tx_lo).unwrap();
        pool.add(tx_hi).unwrap();

        // TX from a second sender (higher fee) also in pool
        let tx_other = make_tx(&kp2, 40_000, 0);
        pool.add(tx_other).unwrap();

        assert_eq!(pool.len(), 3);

        let taken = pool.take(10);
        assert_eq!(taken.len(), 3);

        // kp1's TXs must be consecutive and nonce-ordered (0 before 1)
        let kp1_addr = Address::from_public_key(&kp1.public).to_string();
        let kp1_taken: Vec<_> = taken.iter().filter(|t| t.from.to_string() == kp1_addr).collect();
        assert_eq!(kp1_taken[0].nonce, 0);
        assert_eq!(kp1_taken[1].nonce, 1);
    }

    #[test]
    fn test_fee_too_low_rejected() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();
        let tx = make_tx(&kp, 500, 0); // below 1000 min
        assert!(matches!(pool.add(tx), Err(MempoolError::FeeTooLow { .. })));
    }

    /// The gap this whole field closes: a fee comfortably above the flat `min_fee` but below
    /// what the block will actually charge for the transaction's size. It used to be admitted,
    /// gossiped, and mined, only to be rejected by the executor — the sender waited on a
    /// transaction that could never land. 5000 is not a strawman: it is what every test in this
    /// file used to pass.
    #[test]
    fn a_fee_over_the_flat_minimum_but_under_the_base_fee_is_rejected_up_front() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();
        let tx = make_tx(&kp, 5_000, 0);
        let size = tx.size_bytes();
        // Clears `min_fee` (1000) — the old code let it straight in — but a 1-nano/byte floor
        // already costs more than this.
        assert!(5_000 < size, "premise: the floor alone outprices this fee");

        let err = pool.add(tx).unwrap_err();
        assert!(
            matches!(err, MempoolError::BelowBaseFee { need, .. } if need == size),
            "{err:?}"
        );
    }

    /// The pool's base-fee check must agree with `execute_transaction`'s, exemption included.
    /// Double-sign evidence carries two full votes and pays a flat reporter fee the base fee
    /// dwarfs, so charging it here would reject every slashing report at admission — which is
    /// exactly how slashing was silently dead once before, when the evidence tx paid fee 0 and
    /// `min_fee` turned it away on every node including the reporter's own.
    #[test]
    fn double_sign_evidence_is_exempt_from_the_base_fee_like_it_is_at_execution() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        let mut tx = make_tx(&kp, 10_000, 0);
        tx.tx_type = TxType::SubmitDoubleSignEvidence;
        // Stand in for the ~16 KB of two signed votes a real report carries.
        tx.data = vec![0u8; 16_000];
        let hash = tx.signing_hash();
        tx.signature = kp.sign(hash.as_bytes()).unwrap();

        assert!(
            tx.fee < tx.size_bytes(),
            "premise: the reporter fee is below what the base fee would charge for this size"
        );
        assert!(pool.add(tx).is_ok(), "a slashing report must never be priced out of the pool");
    }

    /// A rising base fee has to actually bite: the pool mirrors consensus, so what it accepts
    /// must move with it rather than staying frozen at the floor it started on.
    #[test]
    fn raising_the_base_fee_tightens_what_the_pool_accepts() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();
        let tx = make_tx(&kp, 10_000, 0);
        let size = tx.size_bytes();

        assert!(pool.add(tx.clone()).is_ok(), "affordable at the floor");

        pool.remove_committed(&[tx.hash()]);
        pool.set_base_fee_per_byte(2);
        let err = pool.add(tx).unwrap_err();
        assert!(
            matches!(err, MempoolError::BelowBaseFee { need, .. } if need == size * 2),
            "the same fee must stop clearing once the byte price doubles: {err:?}"
        );
    }

    #[test]
    fn test_nonce_ordering_preserved() {
        // Submitting nonces out of order should still produce them sorted in take()
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        // Insert nonce 2 first, then 0, then 1 — all same fee
        for nonce in [2u64, 0, 1] {
            pool.add(make_tx(&kp, 10_000, nonce)).unwrap();
        }
        let taken = pool.take(10);
        assert_eq!(taken.iter().map(|t| t.nonce).collect::<Vec<_>>(), vec![0, 1, 2]);
    }

    #[test]
    fn test_remove_committed() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();
        let tx = make_tx(&kp, 10_000, 0);
        let hash = tx.hash();
        pool.add(tx).unwrap();
        assert_eq!(pool.len(), 1);
        pool.remove_committed(&[hash]);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_double_nonce_rejected() {
        // Two different txs (different fees → different hashes) from the same sender
        // at the same nonce: the second must be rejected so block space is not wasted.
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        let tx1 = make_tx(&kp, 10_000, 0);
        let tx2 = make_tx(&kp, 12_000, 0); // same sender, same nonce, higher fee

        pool.add(tx1).unwrap();
        assert!(matches!(
            pool.add(tx2),
            Err(MempoolError::NoncePending { .. })
        ));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_double_nonce_slot_freed_after_commit() {
        // After the first tx is committed, a new tx at the same nonce should be accepted
        // (edge case: a re-submission after a failed block inclusion).
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        let tx = make_tx(&kp, 10_000, 0);
        let hash = tx.hash();
        pool.add(tx).unwrap();
        pool.remove_committed(&[hash]);

        let tx2 = make_tx(&kp, 12_000, 0);
        assert!(pool.add(tx2).is_ok(), "slot should be free after commit");
    }

    #[test]
    fn test_full_pool_evicts_cheapest_tx_for_higher_fee() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let kp3 = KeyPair::generate();
        let mut pool = Mempool::with_limits(2, 1_000);

        let cheap = make_tx(&kp1, 10_000, 0);
        let cheap_hash = cheap.hash();
        let mid = make_tx(&kp2, 12_000, 0);
        pool.add(cheap).unwrap();
        pool.add(mid).unwrap();
        assert_eq!(pool.len(), 2);

        // Pool is full, but this tx outbids the cheapest (5_000) — must evict it.
        let expensive = make_tx(&kp3, 14_000, 0);
        pool.add(expensive).unwrap();

        assert_eq!(pool.len(), 2);
        assert!(!pool.contains(&cheap_hash), "cheapest tx should have been evicted");

        // Evicted sender's nonce slot must be freed too.
        let resubmit = make_tx(&kp1, 16_000, 0);
        assert!(pool.add(resubmit).is_ok());
    }

    #[test]
    fn test_full_pool_rejects_tx_that_does_not_outbid_cheapest() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let kp3 = KeyPair::generate();
        let mut pool = Mempool::with_limits(2, 1_000);

        pool.add(make_tx(&kp1, 10_000, 0)).unwrap();
        pool.add(make_tx(&kp2, 12_000, 0)).unwrap();

        // Equal to the cheapest fee — must not evict, must reject as Full.
        let tx = make_tx(&kp3, 10_000, 0);
        assert!(matches!(pool.add(tx), Err(MempoolError::Full(2))));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_full_pool_invalid_signature_does_not_evict_existing_tx() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let attacker_kp = KeyPair::generate();
        let mut pool = Mempool::with_limits(2, 1_000);

        let cheap = make_tx(&kp1, 10_000, 0);
        let cheap_hash = cheap.hash();
        pool.add(cheap).unwrap();
        pool.add(make_tx(&kp2, 12_000, 0)).unwrap();
        assert_eq!(pool.len(), 2);

        // Would outbid the cheapest tx (5_000) on fee alone, but the signature is
        // garbage — must be rejected as Invalid without evicting anything.
        let mut forged = make_tx(&attacker_kp, 100_000, 0);
        forged.signature = Signature::from_bytes(vec![0u8; 32]);
        assert!(matches!(pool.add(forged), Err(MempoolError::Invalid(_))));

        assert_eq!(pool.len(), 2);
        assert!(pool.contains(&cheap_hash), "cheapest tx must survive a forged eviction attempt");
    }

    #[test]
    fn test_expired_tx_evicted_and_nonce_slot_freed() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::with_limits_and_ttl(100, 1_000, Duration::from_millis(1));

        let stuck = make_tx(&kp, 10_000, 0);
        pool.add(stuck).unwrap();
        assert_eq!(pool.len(), 1);

        std::thread::sleep(Duration::from_millis(10));

        // A resubmission at the same (sender, nonce) would normally be rejected
        // with NoncePending — but the stuck tx is past its TTL, so add() must
        // evict it first and admit the new one.
        let resubmit = make_tx(&kp, 12_000, 0);
        pool.add(resubmit).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_take_also_evicts_expired() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::with_limits_and_ttl(100, 1_000, Duration::from_millis(1));
        pool.add(make_tx(&kp, 10_000, 0)).unwrap();

        std::thread::sleep(Duration::from_millis(10));

        let taken = pool.take(10);
        assert!(taken.is_empty(), "expired tx must not be included in take()");
        assert_eq!(pool.len(), 0);
    }
}
