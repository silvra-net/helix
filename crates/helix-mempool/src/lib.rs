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

/// Tip-prioritized transaction pool.
/// Higher tip → included in next block first.
pub struct Mempool {
    /// tip (descending) → vec of tx hashes at that tip level
    by_tip: BTreeMap<std::cmp::Reverse<Amount>, Vec<String>>,
    /// hash → transaction
    by_hash: HashMap<String, Transaction>,
    /// (sender_address, nonce) → tx hash — prevents two txs with the same nonce
    /// from the same sender clogging the pool (only one can ever succeed)
    by_sender_nonce: HashMap<(String, u64), String>,
    /// hash → the tip it was filed under in `by_tip`. Kept explicitly because the tip is
    /// computed from `base_fee_per_byte` as it stood at *admission*, and that moves: recomputing
    /// the key at removal time would look in the wrong bucket for anything admitted under a
    /// different base fee, leaving the entry behind forever.
    tip_of: HashMap<String, Amount>,
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
            by_tip: BTreeMap::new(),
            by_hash: HashMap::new(),
            by_sender_nonce: HashMap::new(),
            tip_of: HashMap::new(),
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
            by_tip: BTreeMap::new(),
            by_hash: HashMap::new(),
            by_sender_nonce: HashMap::new(),
            tip_of: HashMap::new(),
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
            by_tip: BTreeMap::new(),
            by_hash: HashMap::new(),
            by_sender_nonce: HashMap::new(),
            tip_of: HashMap::new(),
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

    /// What including `tx` actually pays the block's validator: its fee minus the base-fee
    /// portion, which is burned rather than earned (`distribute_fee` in `helix-executor`
    /// splits it exactly this way).
    ///
    /// This — not `tx.fee` — is what the pool prioritizes by. Sorting on the total fee ranked a
    /// large transaction paying its base fee and nothing more (tip 0, validator earns nothing)
    /// above a small one tipping well, because the burned part scales with size. That is the
    /// pool preferring precisely the transactions that don't pay the validator. Ethereum sorts
    /// by effective priority fee for the same reason.
    ///
    /// `SubmitDoubleSignEvidence` is exempt from the base fee at execution, so none of its fee
    /// is burned and all of it tips — the exemption needs no special case here beyond not
    /// subtracting a base fee that is never charged. Getting this wrong would sink slashing
    /// reports to the bottom of every block: their flat reporter fee minus a base fee on ~16 KB
    /// would saturate to tip 0. Same trap as the admission check above.
    fn tip(&self, tx: &Transaction) -> Amount {
        if tx.tx_type == TxType::SubmitDoubleSignEvidence {
            tx.fee
        } else {
            tx.fee
                .saturating_sub(self.base_fee_per_byte.saturating_mul(tx.size_bytes()))
        }
    }

    /// Remove a transaction from every index it appears in. The `by_tip` bucket is found via
    /// the recorded `tip_of` key rather than a fresh computation — see that field's note.
    fn detach(&mut self, hash: &str) {
        self.entered_at.remove(hash);
        if let Some(tip) = self.tip_of.remove(hash) {
            let key = std::cmp::Reverse(tip);
            if let Some(bucket) = self.by_tip.get_mut(&key) {
                bucket.retain(|h| h != hash);
                if bucket.is_empty() {
                    self.by_tip.remove(&key);
                }
            }
        }
        if let Some(tx) = self.by_hash.remove(hash) {
            self.by_sender_nonce.remove(&(tx.from.to_string(), tx.nonce));
        }
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
            self.detach(&hash);
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

        let tip = self.tip(&tx);

        if self.by_hash.len() >= self.max_size {
            // Pool is full: only admit this tx if it strictly outbids the cheapest
            // tx currently held, evicting that one to make room. Otherwise a
            // sustained flood of just-above-min-fee spam could permanently lock
            // out legitimate higher-fee transactions.
            let lowest_tip = self.by_tip.keys().next_back().map(|r| r.0);
            match lowest_tip {
                Some(lowest) if tip > lowest => self.evict_lowest_tip(),
                _ => return Err(MempoolError::Full(self.max_size)),
            }
        }

        self.by_tip
            .entry(std::cmp::Reverse(tip))
            .or_default()
            .push(hash.clone());

        self.by_sender_nonce.insert(sender_nonce_key, hash.clone());
        self.tip_of.insert(hash.clone(), tip);
        self.entered_at.insert(hash.clone(), Instant::now());
        self.by_hash.insert(hash, tx);
        Ok(())
    }

    /// Take up to `max_count` highest-tip transactions for block inclusion.
    /// Does NOT remove them — call `remove_committed` after the block is finalized.
    ///
    /// TXs are sorted by (sender, nonce) after the fee-priority pass so that a
    /// sender's sequential nonces always land in the correct order in the block.
    /// Without this, nonce N+1 arriving before N would be dropped by the executor.
    pub fn take(&mut self, max_count: usize) -> Vec<Transaction> {
        self.evict_expired();
        let mut result = Vec::with_capacity(max_count);
        'outer: for hashes in self.by_tip.values() {
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
            self.detach(&hash.to_hex());
        }
    }

    /// Remove the single lowest-tipping transaction currently in the pool, making room
    /// for one new admission. No-op if the pool is empty.
    fn evict_lowest_tip(&mut self) {
        let lowest_key = match self.by_tip.keys().next_back().copied() {
            Some(k) => k,
            None => return,
        };
        let hash = match self.by_tip.get(&lowest_key).and_then(|b| b.first()).cloned() {
            Some(h) => h,
            None => return,
        };
        self.detach(&hash);
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
        make_tx_with_data(keypair, fee, nonce, 0)
    }

    /// `data_len` pads the transaction to a chosen size — what the base fee, and so the tip,
    /// is charged against.
    fn make_tx_with_data(keypair: &KeyPair, fee: Amount, nonce: u64, data_len: usize) -> Transaction {
        let addr = Address::from_public_key(&keypair.public);
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: addr.clone(),
            to: Some(addr),
            amount: 1_000_000,
            fee,
            nonce,
            data: vec![0u8; data_len],
            crypto_version: keypair.scheme,
            signature: Signature::from_bytes(vec![0u8; 32]),
            public_key: keypair.public.clone(),
        };
        let hash = tx.signing_hash();
        tx.signature = keypair.sign(hash.as_bytes()).unwrap();
        tx
    }

    /// Price a transaction of `data_len` bytes at exactly its base fee at the floor: the whole
    /// fee burns and the validator earns nothing by including it.
    fn make_zero_tip_tx(keypair: &KeyPair, nonce: u64, data_len: usize) -> Transaction {
        let size = make_tx_with_data(keypair, 0, nonce, data_len).size_bytes();
        let tx = make_tx_with_data(keypair, size, nonce, data_len);
        assert_eq!(tx.size_bytes(), size, "fee is fixed-width, so pricing must not resize the tx");
        tx
    }

    /// Price a transaction at its base fee at the floor plus `tip`.
    fn make_tipping_tx(keypair: &KeyPair, nonce: u64, tip: Amount) -> Transaction {
        let size = make_tx(keypair, 0, nonce).size_bytes();
        make_tx(keypair, size + tip, nonce)
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

    /// The reason this pool sorts by tip at all. The burned part of a fee scales with the
    /// transaction's size, so ranking by total fee put a big transaction that pays its base fee
    /// and nothing more — validator earns zero — ahead of a small one tipping well. The pool
    /// systematically preferred the transactions that don't pay the validator.
    #[test]
    fn a_big_transaction_paying_only_its_base_fee_ranks_below_a_small_one_that_tips() {
        let big_kp = KeyPair::generate();
        let small_kp = KeyPair::generate();
        let mut pool = Mempool::new();

        let big = make_zero_tip_tx(&big_kp, 0, 20_000);
        let small = make_tipping_tx(&small_kp, 0, 5_000);
        assert!(
            big.fee > small.fee,
            "premise: the zero-tip tx pays the higher TOTAL fee — that's what used to win"
        );
        let small_hash = small.hash();

        pool.add(big).unwrap();
        pool.add(small).unwrap();

        let taken = pool.take(1);
        assert_eq!(taken.len(), 1);
        assert_eq!(
            taken[0].hash(),
            small_hash,
            "the block slot must go to the tx that actually pays the validator"
        );
    }

    /// Same inversion, on the eviction path: a full pool must keep what earns the validator
    /// most, not what carries the largest headline fee.
    #[test]
    fn a_full_pool_evicts_by_tip_not_by_total_fee() {
        let big_kp = KeyPair::generate();
        let small_kp = KeyPair::generate();
        let mut pool = Mempool::with_limits(1, 1_000);

        let big = make_zero_tip_tx(&big_kp, 0, 20_000);
        let big_hash = big.hash();
        pool.add(big).unwrap();

        let small = make_tipping_tx(&small_kp, 0, 5_000);
        let small_hash = small.hash();
        pool.add(small).expect("a real tip must outbid a zero tip, whatever the totals say");

        assert!(!pool.contains(&big_hash), "the zero-tip tx should have been evicted");
        assert!(pool.contains(&small_hash));
    }

    /// Slashing evidence pays no base fee at execution, so its whole fee tips and its ~16 KB
    /// must not push it down the queue. Subtracting a base fee that is never charged would
    /// saturate its tip to 0 and sink every report to the back of the block — the same trap
    /// that already killed slashing at the fee-0 stage and again at admission.
    #[test]
    fn slashing_evidence_tips_its_whole_fee_and_is_not_sunk_by_its_size() {
        let reporter = KeyPair::generate();
        let other = KeyPair::generate();
        let mut pool = Mempool::new();

        let mut evidence = make_tx_with_data(&reporter, 10_000, 0, 16_000);
        evidence.tx_type = TxType::SubmitDoubleSignEvidence;
        let hash = evidence.signing_hash();
        evidence.signature = reporter.sign(hash.as_bytes()).unwrap();
        assert!(
            evidence.fee < evidence.size_bytes(),
            "premise: a base fee on this size would wipe out the whole reporter fee"
        );
        let evidence_hash = evidence.hash();

        pool.add(evidence).unwrap();
        pool.add(make_tipping_tx(&other, 0, 5_000)).unwrap();

        let taken = pool.take(1);
        assert_eq!(
            taken[0].hash(),
            evidence_hash,
            "a slashing report tipping 10k must outrank a transfer tipping 5k"
        );
    }

    /// The tip is computed from the base fee as it stood at admission, and the base fee moves.
    /// Recomputing it at removal time would look in a bucket the tx was never filed under and
    /// leave the index entry behind forever.
    #[test]
    fn a_tx_is_fully_removed_even_after_the_base_fee_moved_under_it() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        let tx = make_tx(&kp, 20_000, 0);
        let hash = tx.hash();
        pool.add(tx).unwrap();

        pool.set_base_fee_per_byte(2);
        pool.remove_committed(&[hash]);

        assert_eq!(pool.len(), 0);
        assert!(pool.by_tip.is_empty(), "a stale index entry survived the removal");
        assert!(pool.tip_of.is_empty());
        assert!(pool.entered_at.is_empty());
        assert!(pool.by_sender_nonce.is_empty());
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
