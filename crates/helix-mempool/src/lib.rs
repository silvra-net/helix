use helix_core::{transaction::Amount, Transaction, TxType};
use helix_crypto::{Address, Hash, PublicKey};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
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
    #[error("Signed for a different chain: transaction {theirs}, this chain {ours}")]
    ForeignChain { theirs: String, ours: String },
    #[error(
        "Nonce already spent: {from} is on nonce {account_nonce}, this transaction signs nonce \
         {nonce} — it can never be applied"
    )]
    NonceSpent { from: String, nonce: u64, account_nonce: u64 },
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

/// How many recently expired transaction hashes to remember, so a sender can be told their
/// transaction expired rather than that it was never seen (backlog #156).
///
/// A hash is 32 bytes, so this is a few tens of kilobytes for a window that comfortably outlasts
/// the TTL itself at any realistic rate — during the 2026-08-04 stall the pool turned over about
/// thirty transactions per half hour. It is deliberately a bounded ring rather than a complete
/// record: remembering everything forever to answer a question about the past is how a mempool
/// becomes an archive. What falls out of the ring simply answers as before.
const EXPIRED_MEMORY: usize = 4096;

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
    /// Hashes recently dropped for exceeding the TTL, newest last (backlog #156).
    ///
    /// Without this, a transaction that expired and one that never arrived are the same answer —
    /// "not found" — and so is a typo in the hash. That is at its worst exactly when it matters
    /// most: during a stall, every transaction a user sends expires after the TTL with no block to
    /// go into, and nothing anywhere tells them. Only expiry is recorded here; a transaction that
    /// made it into a block is answerable from the store, and one replaced or evicted for a low
    /// tip was never promised anything.
    expired: VecDeque<String>,
    expired_set: HashSet<String>,
    max_size: usize,
    min_fee: Amount,
    /// Addresses whose `ProbationHeartbeat` is admitted without a fee — see `is_fee_exempt`.
    /// Mirrored from committed state by the node; empty on a pool that nobody updates, which
    /// makes the default strict rather than permissive.
    fee_exempt_probationers: HashSet<Address>,
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
            expired: VecDeque::new(),
            expired_set: HashSet::new(),
            max_size: DEFAULT_MAX_SIZE,
            min_fee: DEFAULT_MIN_FEE,
            ttl: DEFAULT_TTL,
            base_fee_per_byte: helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
            fee_exempt_probationers: HashSet::new(),
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
            expired: VecDeque::new(),
            expired_set: HashSet::new(),
            max_size,
            min_fee,
            ttl: DEFAULT_TTL,
            base_fee_per_byte: helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
            fee_exempt_probationers: HashSet::new(),
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
            expired: VecDeque::new(),
            expired_set: HashSet::new(),
            max_size,
            min_fee,
            ttl,
            base_fee_per_byte: helix_core::fee::INITIAL_BASE_FEE_PER_BYTE,
            fee_exempt_probationers: HashSet::new(),
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
        if self.is_fee_exempt(tx) {
            tx.fee
        } else {
            tx.fee
                .saturating_sub(self.base_fee_per_byte.saturating_mul(tx.size_bytes()))
        }
    }

    /// Whether `tx` pays no base fee at execution, so this pool must neither charge it one nor
    /// subtract one when ranking it. There are exactly two such transactions, and both are
    /// consensus-safety public goods that a fee would silently switch off:
    ///
    ///  - `SubmitDoubleSignEvidence`: ~16 KB of self-proving evidence against a flat reporter
    ///    fee. Charging it would sink every slashing report to the bottom of every block.
    ///  - `ProbationHeartbeat` from an address this pool has been told is on probation and still
    ///    owes its proof (see `set_fee_exempt_probationers`): an operator who staked their whole
    ///    balance has nothing to pay with, and a liveness proof nobody can afford is a gate
    ///    nobody passes — the failure mode backlog #141 already lived through three times. The
    ///    sender set is what bounds it: small, mirrored from committed state, and every member
    ///    has `min_validator_stake` locked up. A heartbeat from anyone else pays like any other
    ///    transaction.
    ///
    /// The mirrored set may lag the chain by a block. That is harmless in the strict direction
    /// (a stale member's transaction simply fails at execution, costing nothing) and is why the
    /// executor re-derives the condition itself rather than trusting this.
    fn is_fee_exempt(&self, tx: &Transaction) -> bool {
        match tx.tx_type {
            TxType::SubmitDoubleSignEvidence => true,
            TxType::ProbationHeartbeat => self.fee_exempt_probationers.contains(&tx.from),
            _ => false,
        }
    }

    /// Mirror the set of validators currently serving probation without a recorded liveness
    /// proof, so admission can let their (fee-free) heartbeats through. Called from the same
    /// place as `set_base_fee_per_byte` — startup and after every commit.
    pub fn set_fee_exempt_probationers(&mut self, probationers: HashSet<Address>) {
        self.fee_exempt_probationers = probationers;
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
            self.remember_expired(hash);
        }
    }

    /// Drop every held transaction whose nonce the sender has already spent on chain.
    ///
    /// Such a transaction can never be applied again — its nonce is consumed, and the hash that
    /// identifies it commits to that nonce, so no later state makes it valid. Leaving it in the
    /// pool is not merely wasteful: it will be packed into a block, rejected by the executor, and
    /// burn no fee doing so, which is exactly how the same stake transaction landed in two blocks
    /// on 2026-09-02 (#185).
    ///
    /// Dropped, not skipped, and deliberately: skipping would re-examine the same dead transaction
    /// on every block for the full TTL while it holds its `(sender, nonce)` slot against a real
    /// replacement. These are not counted as expired (#156) — the sender is not owed "your
    /// transaction timed out" for one whose nonce they themselves spent elsewhere; the chain can
    /// answer for the transaction that did go through.
    fn drop_spent_nonces(&mut self, account_nonce: &dyn Fn(&str) -> Option<u64>) {
        let spent: Vec<String> = self
            .by_hash
            .iter()
            .filter(|(_, tx)| {
                account_nonce(&tx.from.to_string()).is_some_and(|current| tx.nonce < current)
            })
            .map(|(hash, _)| hash.clone())
            .collect();
        for hash in spent {
            self.detach(&hash);
        }
    }

    /// Records a hash as recently expired, evicting the oldest once the ring is full (#156).
    fn remember_expired(&mut self, hash: String) {
        if !self.expired_set.insert(hash.clone()) {
            return;
        }
        self.expired.push_back(hash);
        if self.expired.len() > EXPIRED_MEMORY {
            if let Some(oldest) = self.expired.pop_front() {
                self.expired_set.remove(&oldest);
            }
        }
    }

    /// Whether this transaction was recently dropped for sitting in the pool past its TTL
    /// (backlog #156).
    ///
    /// `false` is deliberately not "it never expired": beyond the ring's window the answer is
    /// simply unknown, which is what callers reported before this existed. Everything it does say
    /// is true — it never turns a transaction that is still pending, or one that made it into a
    /// block, into an expiry.
    pub fn expired_recently(&self, hash: &Hash) -> bool {
        self.expired_set.contains(&hash.to_hex())
    }

    pub fn add(
        &mut self,
        tx: Transaction,
        chain_id: Hash,
        account_nonce: Option<u64>,
    ) -> MempoolResult<()> {
        self.add_inner(tx, None, chain_id, account_nonce)
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
        chain_id: Hash,
        account_nonce: Option<u64>,
    ) -> MempoolResult<()> {
        self.add_inner(tx, recovery_key, chain_id, account_nonce)
    }

    fn add_inner(
        &mut self,
        tx: Transaction,
        recovery_key: Option<&PublicKey>,
        chain_id: Hash,
        account_nonce: Option<u64>,
    ) -> MempoolResult<()> {
        self.evict_expired();

        // Both fee gates below have to agree with `execute_transaction`'s, or this pool starts
        // either admitting transactions that cannot execute or — far worse, and the reason both
        // exemptions exist — refusing ones that could. `fee_exempt` is that shared answer.
        let fee_exempt = self.is_fee_exempt(&tx);

        if tx.fee < self.min_fee && !fee_exempt {
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
        if !fee_exempt {
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

        // Another chain's transaction cannot execute here, so holding it wastes a pool slot and,
        // once a proposer packs it, block space — for free, since a transaction that fails this
        // check burns no fee. Found live: with only the executor's check in place, a transaction
        // carrying a foreign chain id was accepted, gossiped, included in a block and *then*
        // rejected. `chain_id` is passed in rather than stored because the caller already holds
        // chain state and a stored copy is one more thing that can be stale.
        //
        // Placed with the signature check and before the eviction branch below, for the reason
        // spelled out there: anything rejected here must never be able to evict an admitted
        // transaction first.
        if tx.chain_id != chain_id {
            return Err(MempoolError::ForeignChain {
                theirs: tx.chain_id.to_hex(),
                ours: chain_id.to_hex(),
            });
        }

        // A nonce the sender has already spent can never be applied — no ordering, no later
        // arrival, nothing rescues it. Without this check the executor is the only thing that
        // says so, and it says so *from inside a block*: the transaction is admitted, gossiped,
        // packed by a proposer, and rejected on execution — where it burns no fee, so the whole
        // round trip is free and repeatable. Found live on 2026-08-27: one stake transaction
        // mined into five separate blocks over 13,000 heights, failing identically each time,
        // because a wallet kept resubmitting the byte-identical signed transaction.
        //
        // Only *below* the account's nonce is refused. A nonce above it is a normal queued
        // transaction waiting for its predecessors, which this pool is built to hold (see
        // `pending_for_block`'s per-sender nonce ordering). `account_nonce` is an `Option` and a
        // parameter, not a stored field, for the same reason `chain_id` is: the caller holds the
        // chain state, a stored copy is one more thing that can go stale, and a required
        // parameter makes the compiler ask every call site where its answer comes from. `None`
        // means the caller has no chain state to answer with — the node's own self-built
        // transactions, whose nonce it read from that state one line earlier.
        if let Some(account_nonce) = account_nonce {
            if tx.nonce < account_nonce {
                return Err(MempoolError::NonceSpent {
                    from: tx.from.to_string(),
                    nonce: tx.nonce,
                    account_nonce,
                });
            }
        }

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
    ///
    /// See [`Mempool::take_within`] for what `account_nonce` is and why it is a parameter.
    pub fn take(
        &mut self,
        max_count: usize,
        account_nonce: &dyn Fn(&str) -> Option<u64>,
    ) -> Vec<Transaction> {
        self.take_within(max_count, u64::MAX, account_nonce)
    }

    /// Like [`Mempool::take`], but also stops once the selected transactions would exceed
    /// `max_bytes` of serialized size.
    ///
    /// Counting transactions alone was not a bound on anything that matters. A plain transfer
    /// serializes to ~5.4 KB — ML-DSA signatures and public keys dominate — so the 1000-transaction
    /// cap allowed a 5.2 MB block, past the 4 MB gossipsub transmit limit. Such a block cannot be
    /// broadcast at all: the proposal is never delivered, no peer votes on it, the round times out,
    /// and the next proposer draws the same transactions from the same mempool and fails the same
    /// way. A permanent stall, reachable by anyone willing to submit ~800 transactions, whose only
    /// visible symptom is a climbing round number.
    ///
    /// A transaction that is *itself* larger than `max_bytes` would otherwise wedge the pool
    /// forever, so the first one is always taken: a block containing it can still be produced, and
    /// the alternative is a transaction that is admitted and can never be mined.
    ///
    /// `account_nonce` answers "what nonce is this sender on right now", straight from committed
    /// chain state, and is consulted here and not only at admission because a nonce can be spent
    /// *while a transaction sits in the pool*. That is not hypothetical: on 2026-09-02 one stake
    /// transaction was packed into blocks 54822 and 54824 with the same hash — applied the first
    /// time, rejected the second with `nonce mismatch: expected 1, got 0` — because nothing between
    /// admission and selection re-asked. The admission check (`add_inner`) cannot cover this: it
    /// runs once, and the pool's whole purpose is to hold transactions across the interval in which
    /// the answer changes.
    ///
    /// Like the admission check, only a nonce *below* the account's is refused. A nonce above it is
    /// a normal queued transaction waiting for its predecessors. It is a `&dyn Fn` parameter rather
    /// than stored state for the reason `chain_id` and the admission `account_nonce` are: the
    /// caller holds the chain state, a stored copy is one more thing that can go stale, and a
    /// required parameter makes the compiler ask every call site where its answer comes from.
    pub fn take_within(
        &mut self,
        max_count: usize,
        max_bytes: u64,
        account_nonce: &dyn Fn(&str) -> Option<u64>,
    ) -> Vec<Transaction> {
        self.evict_expired();
        self.drop_spent_nonces(account_nonce);
        let mut result = Vec::with_capacity(max_count.min(1024));
        let mut bytes = 0u64;
        'outer: for hashes in self.by_tip.values() {
            for hash in hashes {
                if result.len() >= max_count {
                    break 'outer;
                }
                if let Some(tx) = self.by_hash.get(hash) {
                    let size = tx.size_bytes();
                    // Skip rather than stop: a single oversized transaction low in the tip order
                    // must not shut the gate on everything cheaper behind it.
                    if !result.is_empty() && bytes.saturating_add(size) > max_bytes {
                        continue;
                    }
                    bytes = bytes.saturating_add(size);
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

    /// Every distinct sender currently holding a transaction in the pool.
    ///
    /// Exists so a caller can look up exactly the account nonces `take_within` will ask about,
    /// under its own lock, and hand them over as a plain map — rather than holding the chain-state
    /// lock across the pool lock to answer the question lazily. Two locks held at once in one
    /// order is a deadlock waiting for the second place that takes them in the other.
    pub fn senders(&self) -> Vec<String> {
        let mut seen: HashSet<String> = HashSet::new();
        for tx in self.by_hash.values() {
            seen.insert(tx.from.to_string());
        }
        seen.into_iter().collect()
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

    /// #185. The admission check (`a_transaction_whose_nonce_is_already_spent_is_refused`) fires
    /// once, on the way in. A nonce can be spent *while a transaction waits in the pool* — the
    /// sender resubmits, a peer gossips a copy, the first copy is mined — and nothing re-asked
    /// before the pool handed it to the next proposer. Live on 2026-09-02: one stake transaction
    /// packed into blocks 54822 and 54824, applied the first time and rejected the second.
    #[test]
    fn a_transaction_whose_nonce_the_sender_has_since_spent_is_not_packed_again() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        let tx = make_tx(&kp, 10_000, 0);
        let sender = tx.from.to_string();
        let hash = tx.hash();
        // Admitted legitimately: at this moment the account really is on nonce 0.
        pool.add(tx, Hash::ZERO, Some(0)).expect("premise: the pool accepts it while the nonce is live");
        assert!(pool.contains(&hash));

        // The chain moves on — this exact transaction applied in a block.
        let taken = pool.take(10, &|addr| (addr == sender).then_some(1));

        assert!(
            taken.is_empty(),
            "a transaction whose nonce the chain has already consumed must not be offered for \
             inclusion again: it burns no fee when the executor rejects it, so the round trip is \
             free and endlessly repeatable"
        );
        assert!(
            !pool.contains(&hash),
            "and it must be dropped, not merely skipped — it can never become valid again, and \
             holding it keeps its (sender, nonce) slot against a real replacement"
        );
    }

    /// The positive control for the sweep above, and the reason it compares `<` and never `!=`:
    /// a nonce *above* the account's is an ordinary queued transaction waiting for the ones in
    /// front of it. Dropping those would break every wallet that sends two transactions in a row.
    #[test]
    fn a_transaction_queued_ahead_of_its_predecessors_survives_the_sweep() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        let tx = make_tx(&kp, 10_000, 5);
        let sender = tx.from.to_string();
        let hash = tx.hash();
        pool.add(tx, Hash::ZERO, Some(3)).expect("a future nonce is a normal queued transaction");

        let taken = pool.take(10, &|addr| (addr == sender).then_some(3));

        assert_eq!(taken.len(), 1, "a transaction waiting for its predecessors must still be offered");
        assert!(pool.contains(&hash), "and must stay in the pool");
    }

    /// A caller with no chain state to answer from — the node's own self-built transactions —
    /// must not have its pool quietly emptied. `None` means "no answer", not "nonce zero".
    #[test]
    fn without_an_account_nonce_the_sweep_drops_nothing() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        let hash = {
            let tx = make_tx(&kp, 10_000, 0);
            let h = tx.hash();
            pool.add(tx, Hash::ZERO, None).unwrap();
            h
        };

        assert_eq!(pool.take(10, &|_| None).len(), 1);
        assert!(pool.contains(&hash));
    }

    /// Found live on 2026-08-11, minutes after 0.11.0 went out, and not by any test here.
    ///
    /// The executor refuses a foreign chain's transaction (#174), so nothing unsafe could happen —
    /// but with only that check in place, one submitted with `HELIX_CHAIN_ID` set to a dead chain's
    /// hash was accepted by the pool, gossiped to peers, packed into block 351 and *then* rejected.
    /// A transaction that fails that check burns no fee, so the whole round trip was free: pool
    /// slot, bandwidth and block space, for nothing. The pool is where it has to stop.
    #[test]
    fn a_transaction_for_another_chain_never_enters_the_pool() {
        let kp = KeyPair::generate();
        let ours = Hash::digest(b"this chain");
        let mut pool = Mempool::new();

        let mut tx = make_tx(&kp, 10_000, 0);
        tx.chain_id = Hash::digest(b"some other chain");
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();

        let err = pool.add(tx, ours, None).expect_err("a foreign chain's tx must not be admitted");
        assert!(
            matches!(err, MempoolError::ForeignChain { .. }),
            "and it must say so rather than blaming the signature: {err}",
        );
        assert_eq!(pool.len(), 0, "nothing may be held");
    }

    /// The positive control. Without it the test above passes just as well if `add` had started
    /// refusing everything.
    #[test]
    fn a_transaction_for_this_chain_still_enters_the_pool() {
        let kp = KeyPair::generate();
        let ours = Hash::digest(b"this chain");
        let mut pool = Mempool::new();

        let mut tx = make_tx(&kp, 10_000, 0);
        tx.chain_id = ours;
        tx.signature = kp.sign(tx.signing_hash().as_bytes()).unwrap();

        pool.add(tx, ours, None).expect("our own chain's transaction belongs in the pool");
        assert_eq!(pool.len(), 1);
    }

    /// Packing must stop at a byte budget, not only at a transaction count.
    ///
    /// The count cap bounded nothing that matters: at ~5.4 KB per transfer, 1000 transactions is a
    /// 5.2 MB block, larger than gossipsub will transmit. Such a block reaches no peer, collects no
    /// vote, times its round out, and is rebuilt identically by the next proposer from the same
    /// mempool — a permanent stall whose only symptom is a climbing round number.
    #[test]
    fn packing_stops_at_the_byte_budget_not_just_the_count() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::with_limits(1_000, 1_000);
        for nonce in 0..20 {
            pool.add(make_tx(&kp, 10_000 + nonce, nonce), Hash::ZERO, None).unwrap();
        }

        let one = make_tx(&kp, 10_000, 0).size_bytes();
        // Room for five and a bit — the sixth must not be squeezed in.
        let taken = pool.take_within(1_000, one * 5 + one / 2, &|_| None);

        assert_eq!(taken.len(), 5, "the budget, not the count, has to decide");
        let packed: u64 = taken.iter().map(|t| t.size_bytes()).sum();
        assert!(packed <= one * 5 + one / 2, "packed {packed} bytes over budget");
    }

    /// The control. A budget so tight that nothing fits must still produce a block containing the
    /// first transaction, or a transaction larger than the budget is admitted to the pool and can
    /// never be mined out of it — the pool wedges and every later transaction starves behind it.
    #[test]
    fn a_transaction_larger_than_the_whole_budget_is_still_taken() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::with_limits(1_000, 1_000);
        pool.add(make_tx(&kp, 10_000, 0), Hash::ZERO, None).unwrap();

        let taken = pool.take_within(1_000, 1, &|_| None);
        assert_eq!(taken.len(), 1, "the first transaction always goes in, budget or not");
    }

    /// The other control: the count limit has to keep working. A fix that only ever consulted bytes
    /// would pass the test above and quietly let a block hold ten thousand tiny transactions.
    #[test]
    fn the_count_limit_still_applies_under_a_generous_budget() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::with_limits(1_000, 1_000);
        for nonce in 0..20 {
            pool.add(make_tx(&kp, 10_000 + nonce, nonce), Hash::ZERO, None).unwrap();
        }

        assert_eq!(pool.take_within(7, u64::MAX, &|_| None).len(), 7);
    }

    /// `take` is the same selection with no byte budget — existing callers must be unaffected.
    #[test]
    fn take_is_take_within_without_a_byte_budget() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::with_limits(1_000, 1_000);
        for nonce in 0..6 {
            pool.add(make_tx(&kp, 10_000 + nonce, nonce), Hash::ZERO, None).unwrap();
        }
        let plain: Vec<_> = pool.take(4, &|_| None).iter().map(|t| t.hash()).collect();
        let budgeted: Vec<_> = pool.take_within(4, u64::MAX, &|_| None).iter().map(|t| t.hash()).collect();
        assert_eq!(plain, budgeted);
    }

    /// Backlog #156: a transaction dropped for sitting past its TTL must be answerable as
    /// *expired*, not as never seen. During a stall this is every transaction a user sends —
    /// there is no block for it to enter, so it waits out the TTL and vanishes silently.
    #[test]
    fn a_transaction_dropped_for_age_is_remembered_as_expired() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::with_ttl(Duration::from_millis(1));
        let tx = make_tx(&kp, 10_000, 0);
        let hash = tx.hash();
        pool.add(tx, Hash::ZERO, None).unwrap();

        std::thread::sleep(Duration::from_millis(5));
        // Expiry is lazy — any pool operation drives it, as in production.
        let _ = pool.take(10, &|_| None);

        assert!(!pool.contains(&hash), "precondition: it really was dropped");
        assert!(pool.expired_recently(&hash), "and the sender must be able to learn why");
    }

    /// The control that keeps `expired_recently` honest: a transaction still waiting has not
    /// expired, and reporting it as such would tell a user to resend something already in flight.
    #[test]
    fn a_pending_transaction_is_not_reported_as_expired() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();
        let tx = make_tx(&kp, 10_000, 0);
        let hash = tx.hash();
        pool.add(tx, Hash::ZERO, None).unwrap();

        assert!(pool.contains(&hash));
        assert!(!pool.expired_recently(&hash));
    }

    /// And one nobody ever submitted must stay unknown — otherwise the answer means nothing.
    #[test]
    fn an_unknown_transaction_is_not_reported_as_expired() {
        let kp = KeyPair::generate();
        let pool = Mempool::new();
        assert!(!pool.expired_recently(&make_tx(&kp, 10_000, 0).hash()));
    }

    /// The memory is a bounded ring, not an archive: past its capacity the oldest entries fall out
    /// and answer as they did before this existed. Pinned so nobody later assumes it is complete.
    #[test]
    fn the_expiry_memory_stays_bounded() {
        let mut pool = Mempool::new();
        for i in 0..(EXPIRED_MEMORY + 100) {
            pool.remember_expired(format!("{i:064x}"));
        }
        assert_eq!(pool.expired.len(), EXPIRED_MEMORY, "the ring must not grow without bound");
        assert_eq!(pool.expired_set.len(), EXPIRED_MEMORY, "and its index must track it exactly");
        assert!(!pool.expired_set.contains(&format!("{:064x}", 0)), "oldest entries fall out");
    }

    /// The gate a probation heartbeat has to clear before it can ever reach a block, and the one
    /// that nearly swallowed it: `min_fee` is checked before the base fee and knows nothing about
    /// exemptions, so a fee-0 heartbeat was refused here and never made it on-chain — the pool
    /// silently reinstating exactly the unpassable gate backlog #141 spent three attempts on.
    /// Same class as the fee-0 slashing report that once disabled slashing.
    #[test]
    fn a_probationers_free_heartbeat_is_admitted_and_a_strangers_is_not() {
        let probationer = KeyPair::generate();
        let stranger = KeyPair::generate();
        let mut pool = Mempool::new();
        pool.set_fee_exempt_probationers(
            [Address::from_public_key(&probationer.public)].into_iter().collect(),
        );

        assert!(
            pool.add(make_heartbeat(&probationer, 0, 0), Hash::ZERO, None).is_ok(),
            "a probationer with nothing liquid must still get its proof into the pool",
        );

        assert!(
            pool.add(make_heartbeat(&stranger, 0, 0), Hash::ZERO, None).is_err(),
            "but the exemption must not be a free lane for everyone else",
        );
    }

    /// The pool ranks by what a transaction actually pays the validator, and an exempt one burns
    /// nothing — so subtracting a base fee it never owes would sink it to tip 0 and park it at
    /// the bottom of every block. Admission alone is not enough; it has to be includable too.
    #[test]
    fn an_exempt_heartbeat_is_not_ranked_as_if_it_paid_a_base_fee() {
        let probationer = KeyPair::generate();
        let addr = Address::from_public_key(&probationer.public);
        let mut pool = Mempool::new();
        pool.set_fee_exempt_probationers([addr].into_iter().collect());

        let hb = make_heartbeat(&probationer, 0, 0);
        assert_eq!(pool.tip(&hb), 0, "a fee-0 heartbeat tips nothing — but must not underflow");

        let paying = make_heartbeat(&probationer, 7_000, 1);
        assert_eq!(
            pool.tip(&paying),
            7_000,
            "and none of an exempt transaction's fee is burned, so all of it tips",
        );
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
            chain_id: helix_crypto::Hash::ZERO,
            signature: Signature::from_bytes(vec![0u8; 32]),
            public_key: keypair.public.clone(),
        };
        let hash = tx.signing_hash();
        tx.signature = keypair.sign(hash.as_bytes()).unwrap();
        tx
    }

    /// A signed heartbeat. Built as one from the start rather than by patching `tx_type` onto a
    /// transfer — the signature covers the type, so patching it afterwards produces a transaction
    /// the pool rejects for the wrong reason and a test that proves nothing.
    fn make_heartbeat(keypair: &KeyPair, fee: Amount, nonce: u64) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::ProbationHeartbeat,
            from: Address::from_public_key(&keypair.public),
            to: None,
            amount: 0,
            fee,
            nonce,
            data: vec![],
            crypto_version: keypair.scheme,
            chain_id: helix_crypto::Hash::ZERO,
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
        pool.add(tx_lo, Hash::ZERO, None).unwrap();
        pool.add(tx_hi, Hash::ZERO, None).unwrap();

        // TX from a second sender (higher fee) also in pool
        let tx_other = make_tx(&kp2, 40_000, 0);
        pool.add(tx_other, Hash::ZERO, None).unwrap();

        assert_eq!(pool.len(), 3);

        let taken = pool.take(10, &|_| None);
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
        assert!(matches!(pool.add(tx, Hash::ZERO, None), Err(MempoolError::FeeTooLow { .. })));
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

        let err = pool.add(tx, Hash::ZERO, None).unwrap_err();
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
        assert!(pool.add(tx, Hash::ZERO, None).is_ok(), "a slashing report must never be priced out of the pool");
    }

    /// A rising base fee has to actually bite: the pool mirrors consensus, so what it accepts
    /// must move with it rather than staying frozen at the floor it started on.
    #[test]
    fn raising_the_base_fee_tightens_what_the_pool_accepts() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();
        let tx = make_tx(&kp, 10_000, 0);
        let size = tx.size_bytes();

        assert!(pool.add(tx.clone(), Hash::ZERO, None).is_ok(), "affordable at the floor");

        pool.remove_committed(&[tx.hash()]);
        pool.set_base_fee_per_byte(2);
        let err = pool.add(tx, Hash::ZERO, None).unwrap_err();
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

        pool.add(big, Hash::ZERO, None).unwrap();
        pool.add(small, Hash::ZERO, None).unwrap();

        let taken = pool.take(1, &|_| None);
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
        pool.add(big, Hash::ZERO, None).unwrap();

        let small = make_tipping_tx(&small_kp, 0, 5_000);
        let small_hash = small.hash();
        pool.add(small, Hash::ZERO, None).expect("a real tip must outbid a zero tip, whatever the totals say");

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

        pool.add(evidence, Hash::ZERO, None).unwrap();
        pool.add(make_tipping_tx(&other, 0, 5_000), Hash::ZERO, None).unwrap();

        let taken = pool.take(1, &|_| None);
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
        pool.add(tx, Hash::ZERO, None).unwrap();

        pool.set_base_fee_per_byte(2);
        pool.remove_committed(&[hash]);

        assert_eq!(pool.len(), 0);
        assert!(pool.by_tip.is_empty(), "a stale index entry survived the removal");
        assert!(pool.tip_of.is_empty());
        assert!(pool.entered_at.is_empty());
        assert!(pool.by_sender_nonce.is_empty());
    }

    /// A nonce the sender has already spent can never execute, and the executor alone saying so
    /// is not enough: a rejection *inside a block* burns no fee, so the transaction is admitted,
    /// gossiped, packed and rejected — for free, again and again. Found live on 2026-08-27: one
    /// stake transaction mined into five separate blocks across 13,000 heights, failing
    /// identically each time, because a wallet kept resubmitting the byte-identical bytes.
    #[test]
    fn a_transaction_signing_an_already_spent_nonce_is_refused_at_the_pool() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        let result = pool.add(make_tx(&kp, 10_000, 3), Hash::ZERO, Some(5));

        assert!(
            matches!(result, Err(MempoolError::NonceSpent { nonce: 3, account_nonce: 5, .. })),
            "a nonce below the account's own can never be applied, so it must not take a pool \
             slot: got {result:?}"
        );
        assert_eq!(pool.len(), 0);
    }

    /// The other side of the same rule, and the reason it is `<` and not `!=`: a nonce *ahead* of
    /// the account is an ordinary queued transaction waiting for its predecessors, which this pool
    /// is built to hold and order (`take` sorts per sender by nonce). Refusing those would break
    /// every wallet that submits two transactions in a row.
    #[test]
    fn a_nonce_ahead_of_the_account_is_still_admitted() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        pool.add(make_tx(&kp, 10_000, 5), Hash::ZERO, Some(5)).expect("the account's own nonce");
        pool.add(make_tx(&kp, 10_000, 6), Hash::ZERO, Some(5)).expect("the one queued behind it");

        assert_eq!(pool.len(), 2);
    }

    /// `None` means the caller holds no chain state to answer with — the node's own self-built
    /// transactions, whose nonce it read from that state a line earlier. It must not be read as
    /// "nonce 0", which would make every check vacuous in the other direction.
    #[test]
    fn without_an_account_nonce_the_check_does_not_fire() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        pool.add(make_tx(&kp, 10_000, 3), Hash::ZERO, None).expect("no state, no verdict");

        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_nonce_ordering_preserved() {
        // Submitting nonces out of order should still produce them sorted in take()
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();

        // Insert nonce 2 first, then 0, then 1 — all same fee
        for nonce in [2u64, 0, 1] {
            pool.add(make_tx(&kp, 10_000, nonce), Hash::ZERO, None).unwrap();
        }
        let taken = pool.take(10, &|_| None);
        assert_eq!(taken.iter().map(|t| t.nonce).collect::<Vec<_>>(), vec![0, 1, 2]);
    }

    #[test]
    fn test_remove_committed() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::new();
        let tx = make_tx(&kp, 10_000, 0);
        let hash = tx.hash();
        pool.add(tx, Hash::ZERO, None).unwrap();
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

        pool.add(tx1, Hash::ZERO, None).unwrap();
        assert!(matches!(
            pool.add(tx2, Hash::ZERO, None),
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
        pool.add(tx, Hash::ZERO, None).unwrap();
        pool.remove_committed(&[hash]);

        let tx2 = make_tx(&kp, 12_000, 0);
        assert!(pool.add(tx2, Hash::ZERO, None).is_ok(), "slot should be free after commit");
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
        pool.add(cheap, Hash::ZERO, None).unwrap();
        pool.add(mid, Hash::ZERO, None).unwrap();
        assert_eq!(pool.len(), 2);

        // Pool is full, but this tx outbids the cheapest (5_000) — must evict it.
        let expensive = make_tx(&kp3, 14_000, 0);
        pool.add(expensive, Hash::ZERO, None).unwrap();

        assert_eq!(pool.len(), 2);
        assert!(!pool.contains(&cheap_hash), "cheapest tx should have been evicted");

        // Evicted sender's nonce slot must be freed too.
        let resubmit = make_tx(&kp1, 16_000, 0);
        assert!(pool.add(resubmit, Hash::ZERO, None).is_ok());
    }

    #[test]
    fn test_full_pool_rejects_tx_that_does_not_outbid_cheapest() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let kp3 = KeyPair::generate();
        let mut pool = Mempool::with_limits(2, 1_000);

        pool.add(make_tx(&kp1, 10_000, 0), Hash::ZERO, None).unwrap();
        pool.add(make_tx(&kp2, 12_000, 0), Hash::ZERO, None).unwrap();

        // Equal to the cheapest fee — must not evict, must reject as Full.
        let tx = make_tx(&kp3, 10_000, 0);
        assert!(matches!(pool.add(tx, Hash::ZERO, None), Err(MempoolError::Full(2))));
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
        pool.add(cheap, Hash::ZERO, None).unwrap();
        pool.add(make_tx(&kp2, 12_000, 0), Hash::ZERO, None).unwrap();
        assert_eq!(pool.len(), 2);

        // Would outbid the cheapest tx (5_000) on fee alone, but the signature is
        // garbage — must be rejected as Invalid without evicting anything.
        let mut forged = make_tx(&attacker_kp, 100_000, 0);
        forged.signature = Signature::from_bytes(vec![0u8; 32]);
        assert!(matches!(pool.add(forged, Hash::ZERO, None), Err(MempoolError::Invalid(_))));

        assert_eq!(pool.len(), 2);
        assert!(pool.contains(&cheap_hash), "cheapest tx must survive a forged eviction attempt");
    }

    #[test]
    fn test_expired_tx_evicted_and_nonce_slot_freed() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::with_limits_and_ttl(100, 1_000, Duration::from_millis(1));

        let stuck = make_tx(&kp, 10_000, 0);
        pool.add(stuck, Hash::ZERO, None).unwrap();
        assert_eq!(pool.len(), 1);

        std::thread::sleep(Duration::from_millis(10));

        // A resubmission at the same (sender, nonce) would normally be rejected
        // with NoncePending — but the stuck tx is past its TTL, so add() must
        // evict it first and admit the new one.
        let resubmit = make_tx(&kp, 12_000, 0);
        pool.add(resubmit, Hash::ZERO, None).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_take_also_evicts_expired() {
        let kp = KeyPair::generate();
        let mut pool = Mempool::with_limits_and_ttl(100, 1_000, Duration::from_millis(1));
        pool.add(make_tx(&kp, 10_000, 0), Hash::ZERO, None).unwrap();

        std::thread::sleep(Duration::from_millis(10));

        let taken = pool.take(10, &|_| None);
        assert!(taken.is_empty(), "expired tx must not be included in take()");
        assert_eq!(pool.len(), 0);
    }
}
