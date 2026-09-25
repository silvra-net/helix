use helix_crypto::{Address, CryptoResult, CryptoScheme, Hash, PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// HLX amounts are stored in nano-HLX (1 HLX = 1_000_000_000 nHLX)
pub type Amount = u64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxType {
    /// Transfer HLX between addresses
    Transfer,
    /// Lock HLX as validator stake
    Stake,
    /// Unlock staked HLX (subject to unbonding period)
    Unstake,
    /// Register a Proof of Personhood identity
    RegisterIdentity,
    /// Register a human-readable name (e.g. `alice.hlx`)
    RegisterName,
    /// Register (or replace) an address's social-recovery guardian set
    RegisterGuardians,
    /// A guardian approves rotating another address's controlling public key
    ApproveRecovery,
    /// Deploy a WASM smart contract
    DeployContract,
    /// Call a deployed smart contract
    CallContract,
    /// Propose a stake-weighted governance change to a protocol parameter
    CreateProposal,
    /// Vote yes on a pending governance proposal
    VoteProposal,
    /// Submit a ZK-STARK proof of personhood for a registered commitment.
    ///
    /// `data` field carries the bincode-serialized `PersonhoodProofPayload`:
    ///   - `commitment: [u8; 16]`   — the public commitment C = secret^(2^63)
    ///   - `proof_bytes: Vec<u8>`   — the winterfell STARK proof bytes
    ///   - `authority_signature`    — the network's personhood authority's signature over
    ///     `commitment`, proving it was issued to a verified unique human (see
    ///     `PersonhoodProofPayload`'s doc comment for why the ZK proof alone isn't enough)
    ProvePersonhood,
    /// Release unbonded stake to the liquid balance after the unbonding period has elapsed.
    ///
    /// No payload (`data` is empty). The executor checks `unbonding_unlock_height` against
    /// the current block height; fails if no unbonding is pending or the lock hasn't expired.
    ClaimUnbonded,
    /// Owner-initiated cancellation of `tx.from`'s own pending (not-yet-finalized)
    /// `RecoveryRequest`. No payload (`data` is empty). Without this, a single guardian
    /// approving a bogus key (and never reaching threshold) permanently blocks the owner
    /// from ever changing their guardian set again, since `RegisterGuardians` refuses to run
    /// while any recovery request is pending and there was previously no way to clear one
    /// short of reaching quorum. Signed normally by the owner's current key — this only ever
    /// applies to sub-threshold requests, and `recovery_key` (the post-recovery signing
    /// override) is only set once a request finalizes, so the account's original key is
    /// still the sole valid signer here.
    CancelRecoveryRequest,
    /// Reports a validator's proven double-sign: two conflicting BFT votes (same
    /// validator/height/round/vote-type, different block hashes). `tx.data` carries the
    /// bincode-serialized `helix_consensus::DoubleSignEvidence`. Anyone may submit this —
    /// both votes carry their own independently-verifiable signatures, so the evidence
    /// proves itself regardless of who reports it or whether `tx.from` witnessed the
    /// original double-sign firsthand.
    ///
    /// This is deliberately a transaction (applied identically by every node through the
    /// normal, already-deterministic `execute_transaction` path) rather than validator-local
    /// state: the double-sign is still *detected* locally (each node's live BFT vote
    /// processing notices a conflict independently), but turning that local detection
    /// directly into a slash — instead of reporting it on-chain and letting execution decide
    /// — meant a node that only received a block passively (P2P gossip or sync, never
    /// processing the live votes itself) never accumulated that evidence and silently skipped
    /// the slash that active participants applied: the same validator set diverging on
    /// `staked` amounts between nodes, with no `state_root` anywhere to ever detect it.
    SubmitDoubleSignEvidence,
    /// Delegate `tx.amount` of liquid HLX to the validator named in `tx.to`, in exchange for
    /// pool shares (see `ChainState::validator_pools`). Unlike self-staking (`TxType::Stake`),
    /// delegation earns a proportional cut of that validator's block rewards without running
    /// a node — but grants no governance voting power (see `TxType::CreateProposal`'s doc
    /// comment on why voting weight stays tied to `AccountState::staked` alone).
    Delegate,
    /// Redeem `tx.amount` (denominated in HLX, converted to shares internally) of `tx.from`'s
    /// delegation to the validator named in `tx.to`. The HLX value (principal plus any
    /// auto-compounded rewards, minus any slashing since delegating) moves into `tx.from`'s
    /// own `unbonding_stake` — the same unbonding queue and `TxType::ClaimUnbonded` used by
    /// self-staking, so delegated funds are just as slashable during the wait and claimed the
    /// same way. "Just as slashable" is enforced, not aspirational: the queue records which
    /// pool the capital came out of (`AccountState::unbonding_source`) precisely so that
    /// undelegating between a validator's double-sign and the evidence transaction that proves
    /// it cannot escape the slash.
    Undelegate,
    /// Move `tx.amount` (denominated in HLX) of `tx.from`'s delegation straight from the
    /// validator named in `tx.data` (as a UTF-8 address string) to the one named in `tx.to`,
    /// with no unbonding wait: the stake keeps earning throughout, at the source until this
    /// transaction and at the destination afterward. Switching validators otherwise costs a
    /// full 7-day round trip through `Undelegate` + `ClaimUnbonded` + `Delegate`, which is a
    /// steep price for the one action the network most wants a delegator to take freely —
    /// walking away from a validator they no longer trust.
    ///
    /// Skipping the queue must not skip the *slashing window*, or this would be a strictly
    /// better escape hatch than undelegating (instant, and the stake keeps earning). So the
    /// moved capital stays slashable for the **source** validator for a full `UNBONDING_PERIOD`
    /// even while it sits in and earns from the destination's pool — recorded as a
    /// `state::Redelegation` under the source. A slash of the source in that window burns the
    /// redelegator's own shares at the destination, leaving the destination's other delegators
    /// untouched.
    ///
    /// Redelegating capital that is *itself* still inside such a window is rejected (no
    /// A→B→C hopping): each hop would otherwise have to keep every earlier source's claim
    /// alive on the same stake, and the honest use case — leaving a validator you no longer
    /// trust — needs exactly one hop.
    Redelegate,
    /// `tx.from` (a validator with an existing or new delegation pool) sets the commission
    /// rate it keeps from delegator rewards. `tx.data` carries the new rate as 2
    /// little-endian bytes (basis points, 0-10000). Capped well below 100% (see
    /// `MAX_COMMISSION_BPS`) — not because a validator can't legitimately choose to reward
    /// delegators poorly, but because an *uncapped* rate lets a validator advertise a low
    /// commission to attract delegators, then raise it to 100% after the fact and keep every
    /// future reward, with delegators locked in until they notice and unbond.
    SetCommission,
    /// `tx.from` explicitly rejoins the active validator set after being downtime-jailed
    /// (see `ChainState::jailed_until`). No payload. Deliberately not automatic — jailing
    /// exists so a validator that goes dark stops silently counting toward quorum forever
    /// (see `helix_core::CommitSig`'s doc comment); auto-rejoining the instant a node comes
    /// back would undo that with the same downtime recurring every time the same flaky
    /// connection drops again. Requires `jailed_until <= current height` (the minimum jail
    /// window has actually elapsed) and that `tx.from` still meets `min_validator_stake` —
    /// jailing never touches stake itself, only eligibility.
    Unjail,
    /// `tx.from`, a validator serving its probation epoch, proves that a node is actually
    /// running the key it staked from (backlog #132/#141). No payload. Recorded in
    /// `ChainState::probation_seen`, which is what `rotate_active_validators` promotes on — a
    /// staked address with no node behind it (a "phantom") never sends one, so it never joins
    /// the quorum and can never freeze a small validator set.
    ///
    /// A transaction, deliberately, after three attempts to read the same fact out of the
    /// consensus stream failed. A probationer holds zero voting power, so its precommit
    /// completes no quorum and is never awaited; giving it reserved proposer turns instead let
    /// a joiner that was behind build its own chain at its slot height and split the network
    /// (measured 2026-07-31: two different blocks at height 225, chain stalled an epoch later).
    /// A transaction has no delivery window to miss — it sits in the mempool until some block
    /// includes it — and it touches neither the proposer schedule nor quorum, so it cannot
    /// fork anything.
    ///
    /// **Base-fee-exempt, but only while it is the one thing the sender needs.** An operator
    /// who stakes exactly `min_validator_stake` has no liquid balance left to pay a fee with,
    /// and a liveness proof nobody can afford is a gate nobody can pass — the failure mode
    /// #141 already lived through once. The exemption is bounded by the same condition that
    /// makes the transaction meaningful at all: `tx.from` is in `probationary_validators` and
    /// is not yet in `probation_seen`. That is at most one free transaction per probationer
    /// per epoch, from an address with `min_validator_stake` locked up. Anyone else sending
    /// one pays the full base fee like any other transaction, so there is no free lane here
    /// (compare `SubmitDoubleSignEvidence`, the other exempt type).
    ProbationHeartbeat,
    /// `tx.from` names where its validator rewards are paid: `tx.to` (#229). `tx.to == tx.from`
    /// clears it, and rewards go to `tx.from` again. No amount, no payload.
    ///
    /// What moves is the validator's **own** share only — the part of each block reward and
    /// tip that belongs to its self-stake, plus its commission. Delegators' share still goes
    /// into the pool, which is looked up by the validator, never by the payout address: a
    /// validator cannot use this to divert what its delegators earn.
    ///
    /// Why it exists: the signing key sits on a server, and rewards credited to it are liquid
    /// funds on the one machine an attacker most wants. Paying them to a wallet whose key never
    /// touches that server takes them out of reach. It used to be the node setting
    /// `HELIX_REWARD_ADDRESS` — local configuration deciding state, which every other node
    /// could not know: in a multi-validator network it had to be ignored (and silently was),
    /// and on a sole validator it made every follower compute a different state. On-chain,
    /// every node applies the same payout, and delegators can see where it goes.
    SetRewardAddress,
}

/// Payload embedded in `Transaction::data` for `TxType::ProvePersonhood`.
/// The STARK proof alone only shows knowledge of *some* secret matching `commitment` —
/// `helix_zkp::prove_personhood` will happily generate one for any secret the caller picks,
/// so without `authority_signature` anyone could self-issue unlimited "verified" identities
/// for free. `authority_signature` is one of the network's configured personhood authorities
/// (see `ChainState::personhood_authorities`) vouching that `commitment` was actually issued
/// to a real, uniquely-verified human by whatever off-chain process that authority runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonhoodProofPayload {
    /// C = secret^(2^63) mod p, as 16-byte little-endian f128 field element.
    pub commitment: [u8; 16],
    /// Serialized winterfell STARK proof bytes.
    pub proof_bytes: Vec<u8>,
    /// The personhood authority's signature over `personhood_authority_preimage(commitment,
    /// claimant)` — i.e. bound to the claiming address (`Transaction::from`), not the bare
    /// commitment. The binding is what stops front-running: `commitment`, `proof_bytes` and
    /// this signature all become public the moment the tx hits the mempool, and the STARK
    /// circuit never ties them to any address, so if the authority signed only the commitment,
    /// a bystander could lift the whole payload out of a pending tx and submit it from their
    /// own address first, stealing the verification. Signing over the address instead means an
    /// authority-issued payload is usable only from the exact address it was issued to.
    pub authority_signature: Signature,
    /// Which scheme the authority signed with — mirrors `BlockHeader::crypto_version`/
    /// `Vote::crypto_version`, supports migration.
    pub authority_crypto_version: CryptoScheme,
}

/// The exact bytes a personhood authority signs to vouch that `commitment` was issued to the
/// unique human who controls `claimant`. Binding the signature to the claiming address (rather
/// than the bare 16-byte commitment) is what prevents a mempool observer from copying an
/// authority-signed payload out of someone else's pending `ProvePersonhood` transaction and
/// claiming the verification from their own address first. The domain tag keeps this preimage
/// from ever colliding with a transaction, block-header, or vote signing preimage.
pub fn personhood_authority_preimage(commitment: &[u8; 16], claimant: &Address) -> Vec<u8> {
    let addr = claimant.as_str().as_bytes();
    let mut msg = Vec::with_capacity(b"helix-personhood-authority-v1:".len() + commitment.len() + addr.len());
    msg.extend_from_slice(b"helix-personhood-authority-v1:");
    msg.extend_from_slice(commitment);
    msg.extend_from_slice(addr);
    msg
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Protocol version — allows future tx format upgrades
    pub version: u32,
    pub tx_type: TxType,
    pub from: Address,
    pub to: Option<Address>,
    /// Amount in nano-HLX
    pub amount: Amount,
    /// Fee in nano-HLX (70% burned, 30% to validator)
    pub fee: Amount,
    /// Monotonically increasing per-account counter (replay protection)
    pub nonce: u64,
    /// Arbitrary payload: contract bytecode, call data, identity proof, etc.
    pub data: Vec<u8>,
    /// Which PQC signature scheme was used to produce `signature`.
    /// Included in the signing hash so this field cannot be flipped post-signing.
    /// Defaults to `CryptoScheme::MlDsa` for backward-compatible deserialization.
    #[serde(default)]
    pub crypto_version: CryptoScheme,
    /// Genesis hash of the chain this transaction is valid on — Helix's answer to EIP-155.
    ///
    /// Without it a signature commits to an intent ("send 110,000 to X, nonce 0") and to nothing
    /// about *where*, so the same signed bytes spend on every Helix chain that ever existed. That
    /// is not theoretical: the three validator fundings of 2026-08-07 came out byte-identical to
    /// those of the 2026-08-05 reset, same hashes, because the intent was the same and ML-DSA signs
    /// deterministically. On a devnet that is folklore. With a testnet beside a mainnet it is a
    /// theft vector, and it cannot be fixed retroactively — a chain cannot start honouring a field
    /// its history never signed.
    ///
    /// The genesis hash rather than a configured number, and deliberately: a separate parameter is
    /// something you forget to change during a reset, which is exactly the mistake that locked
    /// three operators out on 2026-08-08 with `DEFAULT_GENESIS_HASH`. This one cannot go stale
    /// without the chain itself changing, because it *is* the chain's identity.
    ///
    /// Carried on the wire instead of folded silently into the preimage, so a mismatch can be
    /// reported as what it is. The alternative fails as "invalid signature", which is the same
    /// class of unreadable diagnosis as #166 and the stale-genesis lockout — true, useless, and
    /// pointing at the wrong repair.
    pub chain_id: Hash,
    /// Detached signature over the canonical hash of this tx
    pub signature: Signature,
    /// The key that produced `signature` — or `None`, once the chain knows it (#243).
    ///
    /// An address is a one-way truncation of a hash of its key, so a verifier has to be handed the
    /// key from somewhere, and an ML-DSA key is 1952 bytes: more than a third of a plain transfer.
    /// It does not have to be handed over every time. The first transaction an address signs
    /// records the key it derives from (`ChainState::account_keys`), and from then on a node that
    /// admits a transaction from that address stores it without the key, so blocks — proposed,
    /// committed, stored and synced — carry each key once instead of once per transaction.
    ///
    /// Wallets keep attaching it: they cannot know whether the chain has seen them yet, and a key
    /// the chain already knows costs nothing but bytes on the way in. Gossip keeps it too (see
    /// `Mempool`), so every transaction a node forwards can still be checked against nothing but
    /// its own bytes (#225).
    ///
    /// Neither the signature (`signing_hash`) nor the transaction id (`hash`) covers it, so
    /// stripping it changes neither. The block does: its merkle leaves are [`Self::leaf_hash`],
    /// over the full bytes.
    pub public_key: Option<PublicKey>,
}

impl Transaction {
    /// Canonical hash: BLAKE3 over all fields except signature and public_key.
    /// This is what gets signed.
    pub fn signing_hash(&self) -> Hash {
        let payload = bincode::serialize(&TxPayload {
            version: self.version,
            tx_type: &self.tx_type,
            from: &self.from,
            to: &self.to,
            amount: self.amount,
            fee: self.fee,
            nonce: self.nonce,
            data: &self.data,
            crypto_version: self.crypto_version,
            chain_id: &self.chain_id,
        })
        .expect("serialization is infallible for fixed types");
        // Domain tag separates a transaction signature from a block-header or vote
        // signature. The payload itself is canonical bincode (length-prefixed), so the
        // tag + payload has no cross-encoding ambiguity.
        Hash::digest_many(&[b"helix-tx-v1:", &payload])
    }

    /// The transaction id — what a wallet is told at submission and watches for, and what the
    /// mempool, receipts and indices key on: the signed payload plus the signature.
    ///
    /// Deliberately not the public key (#243). A node strips a key the chain already knows before
    /// the transaction goes into a block, and an id that covered the key would change on the way:
    /// the wallet would wait for a hash no block ever carries, and the pool could not recognise the
    /// committed copy of its own transaction to remove it. The signature stays in, so two signings
    /// of the same intent remain two transactions, as they always were.
    pub fn hash(&self) -> Hash {
        let signed = self.signing_hash();
        Hash::digest_many(&[b"helix-txid-v1:", signed.as_bytes(), self.signature.as_bytes()])
    }

    /// The merkle leaf a block commits to: every byte of the transaction, key or no key.
    ///
    /// Not [`Self::hash`], because that is the same for both forms while executing them is not —
    /// the base fee is charged per byte (`size_bytes`). A header that committed only to ids would
    /// let anyone who relays a block re-attach or strip keys without changing its hash, and every
    /// node that received that copy would burn a different fee and compute a different state.
    pub fn leaf_hash(&self) -> Hash {
        let payload = bincode::serialize(self).expect("serialization is infallible");
        Hash::digest_many(&[b"helix-txleaf-v1:", &payload])
    }

    /// Serialized on-wire size in bytes — the unit the EIP-1559 base fee is charged against
    /// (`fee::base_fee_per_byte × size_bytes` is burned; see `crate::fee`). Deterministic
    /// canonical bincode, identical on every node, so it is safe to use in consensus.
    pub fn size_bytes(&self) -> u64 {
        bincode::serialized_size(self).expect("serialization is infallible")
    }

    /// Checks the signature against the key the transaction carries, as if the chain knew nothing
    /// about its sender — so a transaction without a key fails. What a wallet can check about its
    /// own transaction; a node checks with [`Self::signing_key`].
    pub fn verify_signature(&self) -> CryptoResult<()> {
        self.verify_signature_with_recovery_key(None)
    }

    /// Same check as `verify_signature`, but for a `from` address whose control was ever
    /// rotated by social-recovery guardian quorum (see `execute_approve_recovery`),
    /// `recovery_key` is the active override key: it must have produced the signature,
    /// and the normal "public key derives the address" rule is intentionally skipped,
    /// since that's the whole point of a recovered account. `recovery_key: None` (the
    /// common case) falls back to the plain address-derivation + signature check.
    pub fn verify_signature_with_recovery_key(&self, recovery_key: Option<&PublicKey>) -> CryptoResult<()> {
        let key = self.signing_key(recovery_key, None)?;
        self.verify_signature_under(key)
    }

    /// The key this transaction's signature has to verify under, given what the chain knows about
    /// `from`: `recovery_key`, the active override if the account was socially recovered, and
    /// `recorded_key`, the key the address derives from if the chain has seen it sign (#243).
    ///
    /// An attached key is held to exactly the rule it always was: it must be the recovery key, or
    /// else derive `from` — otherwise anyone could sign with their own key under a victim's
    /// address, since the signature check alone only proves possession of *some* key. A
    /// transaction without one borrows the chain's: the recovery key if there is one, else the
    /// recorded key. The recorded key is checked against `from` as well, which costs one hash and
    /// means the registry is never the only thing standing between a key and an address.
    ///
    /// Cheap — no signature is verified — and **dependent on chain state**: a recovery key is set
    /// and replaced by transactions, and a key is recorded by one, so a node one block behind can
    /// see an honest transaction fail here. A failure says the transaction is not admissible
    /// *here, now*; it does not say its author lied.
    pub fn signing_key<'a>(
        &'a self,
        recovery_key: Option<&'a PublicKey>,
        recorded_key: Option<&'a PublicKey>,
    ) -> CryptoResult<&'a PublicKey> {
        let Some(attached) = &self.public_key else {
            if let Some(active_key) = recovery_key {
                return Ok(active_key);
            }
            return match recorded_key {
                Some(key) if Address::from_public_key(key) == self.from => Ok(key),
                Some(_) => Err(helix_crypto::CryptoError::InvalidAddress(
                    "the key on record for the sender does not derive its address".to_string(),
                )),
                None => Err(helix_crypto::CryptoError::InvalidAddress(
                    "no public key attached, and the chain has none on record for the sender".to_string(),
                )),
            };
        };
        match recovery_key {
            Some(active_key) => {
                if attached.as_bytes() != active_key.as_bytes() {
                    return Err(helix_crypto::CryptoError::InvalidAddress(
                        "public key does not match the active recovery key".to_string(),
                    ));
                }
            }
            None => {
                if Address::from_public_key(attached) != self.from {
                    return Err(helix_crypto::CryptoError::InvalidAddress(
                        "public key does not match sender address".to_string(),
                    ));
                }
            }
        }
        Ok(attached)
    }

    /// The first half of [`Self::verify_signature_with_recovery_key`]: is the attached key
    /// entitled to sign for `from`? See [`Self::signing_key`], of which this is the case where the
    /// chain has no key on record.
    pub fn verify_sender_key(&self, recovery_key: Option<&PublicKey>) -> CryptoResult<()> {
        self.signing_key(recovery_key, None).map(|_| ())
    }

    /// The second half: does the signature verify against the key **this transaction carries**?
    /// A function of the transaction's own bytes and nothing else — no chain state, no
    /// configuration — so a failure is something no honest node can have produced. It is also
    /// the expensive half (a full ML-DSA or SLH-DSA verification), which is why a peer that sends
    /// such transactions is worth holding to it (the node charges the author, #225).
    ///
    /// A transaction without a key fails: there is nothing of its own to check it against.
    pub fn verify_own_signature(&self) -> CryptoResult<()> {
        let key = self.public_key.as_ref().ok_or_else(|| {
            helix_crypto::CryptoError::InvalidPublicKey("the transaction carries no public key".to_string())
        })?;
        self.verify_signature_under(key)
    }

    /// Does the signature verify under `key`? The expensive step, with the key chosen by the
    /// caller — [`Self::signing_key`] for a node, the attached one for [`Self::verify_own_signature`].
    pub fn verify_signature_under(&self, key: &PublicKey) -> CryptoResult<()> {
        let hash = self.signing_hash();
        helix_crypto::verify_with_scheme(self.crypto_version, key, hash.as_bytes(), &self.signature)
    }

    /// Drops the attached key when it is the one the chain would use anyway — the recovery key if
    /// the sender has one, else the key on record — and reports whether it did (#243).
    ///
    /// Byte comparison only, so it changes nothing a verifier decides: [`Self::signing_key`] on the
    /// stripped transaction returns exactly the key that was removed. A key the chain does not
    /// know, or a different one, stays attached — the transaction is then judged on it as before.
    pub fn strip_key_the_chain_knows(
        &mut self,
        recovery_key: Option<&PublicKey>,
        recorded_key: Option<&PublicKey>,
    ) -> bool {
        let known = recovery_key.or(recorded_key);
        match (&self.public_key, known) {
            (Some(attached), Some(known)) if attached.as_bytes() == known.as_bytes() => {
                self.public_key = None;
                true
            }
            _ => false,
        }
    }
}

/// The signable subset of a transaction (excludes sig and pubkey).
/// `crypto_version` is included so the scheme cannot be flipped post-signing.
#[derive(Serialize)]
struct TxPayload<'a> {
    version: u32,
    tx_type: &'a TxType,
    from: &'a Address,
    to: &'a Option<Address>,
    amount: Amount,
    fee: Amount,
    nonce: u64,
    data: &'a [u8],
    crypto_version: CryptoScheme,
    chain_id: &'a Hash,
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::KeyPair;

    fn build_tx(from: Address, keypair: &KeyPair) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from,
            to: None,
            amount: 100,
            fee: 1,
            nonce: 0,
            data: vec![],
            crypto_version: keypair.scheme,
            chain_id: Hash::ZERO,
            signature: Signature::from_bytes(vec![]),
            public_key: Some(keypair.public.clone()),
        };
        tx.signature = keypair.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
    }

    /// The measurement that produced backlog #174, turned into a test.
    ///
    /// On 2026-08-07 the three validator fundings came out with hashes byte-identical to the ones
    /// from the 2026-08-05 reset — same amounts, same nonces, same keys, and ML-DSA signs
    /// deterministically, so the same intent produced the same bytes. Nothing distinguished the
    /// two chains, which is what made every one of those signatures replayable on the other.
    #[test]
    fn the_same_intent_signed_for_two_chains_produces_two_different_signatures() {
        let keypair = KeyPair::generate();
        let address = Address::from_public_key(&keypair.public);

        let mut on_chain_a = build_tx(address.clone(), &keypair);
        on_chain_a.chain_id = Hash::digest(b"chain A genesis");
        on_chain_a.signature = keypair.sign(on_chain_a.signing_hash().as_bytes()).unwrap();

        let mut on_chain_b = on_chain_a.clone();
        on_chain_b.chain_id = Hash::digest(b"chain B genesis");
        on_chain_b.signature = keypair.sign(on_chain_b.signing_hash().as_bytes()).unwrap();

        assert_ne!(
            on_chain_a.signing_hash(),
            on_chain_b.signing_hash(),
            "identical intent on two chains must not sign to the same bytes — that was #174",
        );
        assert_ne!(on_chain_a.hash(), on_chain_b.hash(), "and the tx ids must differ too");

        // Both are individually valid. The chain id does not make a signature good or bad; it makes
        // it *belong somewhere*, and refusing the foreign one is the executor's job.
        assert!(on_chain_a.verify_signature().is_ok());
        assert!(on_chain_b.verify_signature().is_ok());
    }

    /// The field has to be inside the signature, not merely beside it. If it were not, an attacker
    /// could take a transaction signed for a worthless chain, rewrite the id, and submit it to a
    /// valuable one — which is the whole attack restated.
    #[test]
    fn rewriting_the_chain_id_after_signing_invalidates_the_signature() {
        let keypair = KeyPair::generate();
        let address = Address::from_public_key(&keypair.public);

        let mut tx = build_tx(address, &keypair);
        tx.chain_id = Hash::digest(b"the chain it was signed for");
        tx.signature = keypair.sign(tx.signing_hash().as_bytes()).unwrap();
        assert!(tx.verify_signature().is_ok(), "premise: it is valid where it was signed");

        tx.chain_id = Hash::digest(b"a chain worth stealing on");
        assert!(
            tx.verify_signature().is_err(),
            "the chain id must be covered by the signature, or it is decoration",
        );
    }

    #[test]
    fn verify_signature_accepts_matching_key_and_address() {
        let keypair = KeyPair::generate();
        let address = Address::from_public_key(&keypair.public);
        let tx = build_tx(address, &keypair);
        assert!(tx.verify_signature().is_ok());
    }

    #[test]
    fn verify_signature_rejects_spoofed_from_address() {
        // Attacker signs with their own key but claims a victim's address as `from`.
        let attacker = KeyPair::generate();
        let victim = KeyPair::generate();
        let victim_address = Address::from_public_key(&victim.public);
        let tx = build_tx(victim_address, &attacker);
        assert!(tx.verify_signature().is_err());
    }

    /// #225 splits the check so a caller can tell *which* half failed — a spoofed `from` is
    /// the state-dependent half, a signature that fails under the transaction's own key is the
    /// state-independent one. Both halves must still add up to the whole.
    #[test]
    fn a_spoofed_from_fails_the_key_half_and_passes_the_signature_half() {
        let attacker = KeyPair::generate();
        let victim = Address::from_public_key(&KeyPair::generate().public);
        let tx = build_tx(victim, &attacker);
        assert!(tx.verify_sender_key(None).is_err());
        assert!(
            tx.verify_own_signature().is_ok(),
            "the attacker's signature is genuinely theirs"
        );
        assert!(tx.verify_signature_with_recovery_key(None).is_err());
    }

    #[test]
    fn a_forged_signature_passes_the_key_half_and_fails_the_signature_half() {
        let keypair = KeyPair::generate();
        let mut tx = build_tx(Address::from_public_key(&keypair.public), &keypair);
        tx.signature = keypair.sign(b"some other message").unwrap();
        assert!(tx.verify_sender_key(None).is_ok());
        assert!(tx.verify_own_signature().is_err());
        assert!(tx.verify_signature_with_recovery_key(None).is_err());
    }

    /// #243, the premise everything else rests on: a node may strip the key without the sender
    /// losing track of the transaction. The id the wallet was told must be the id the block
    /// carries, and the pool must recognise the committed copy of what it holds.
    #[test]
    fn stripping_the_key_keeps_the_signature_and_the_id() {
        let keypair = KeyPair::generate();
        let tx = build_tx(Address::from_public_key(&keypair.public), &keypair);
        let mut stripped = tx.clone();
        assert!(stripped.strip_key_the_chain_knows(None, Some(&keypair.public)));
        assert!(stripped.public_key.is_none());

        assert_eq!(tx.signing_hash(), stripped.signing_hash());
        assert_eq!(tx.hash(), stripped.hash(), "the id must not depend on the key");
        assert_ne!(tx.leaf_hash(), stripped.leaf_hash(), "the bytes a block commits to must");
        assert!(stripped.size_bytes() + 1900 < tx.size_bytes(), "and the point is the bytes");

        let key = stripped.signing_key(None, Some(&keypair.public)).unwrap();
        assert!(stripped.verify_signature_under(key).is_ok());
    }

    /// The signature still distinguishes two signings of the same intent, as it did when the id
    /// was a hash of everything.
    #[test]
    fn the_id_still_covers_the_signature() {
        let keypair = KeyPair::generate();
        let tx = build_tx(Address::from_public_key(&keypair.public), &keypair);
        let mut resigned = tx.clone();
        resigned.signature = Signature::from_bytes(vec![7; 32]);
        assert_ne!(tx.hash(), resigned.hash());
    }

    /// Only a key the chain would use anyway may go. Anything else stays attached and is judged
    /// on its own — stripping must never turn a transaction the chain would refuse into one it
    /// resolves differently.
    #[test]
    fn only_the_key_the_chain_would_use_is_stripped() {
        let owner = KeyPair::generate();
        let other = KeyPair::generate();
        let tx = build_tx(Address::from_public_key(&owner.public), &owner);

        let mut unknown = tx.clone();
        assert!(!unknown.strip_key_the_chain_knows(None, None), "nothing on record");
        assert!(unknown.public_key.is_some());

        let mut different = tx.clone();
        assert!(!different.strip_key_the_chain_knows(None, Some(&other.public)));
        assert!(different.public_key.is_some());

        // Recovered: the recovery key is what counts, and the original key — though on record —
        // is no longer entitled to sign, so a transaction carrying it must keep it and fail.
        let mut recovered = tx.clone();
        assert!(!recovered.strip_key_the_chain_knows(Some(&other.public), Some(&owner.public)));
        assert!(recovered.signing_key(Some(&other.public), Some(&owner.public)).is_err());
    }

    /// Without an attached key the chain's decides: the recovery key before the recorded one,
    /// and nothing at all when the chain knows none.
    #[test]
    fn a_stripped_transaction_resolves_the_key_the_chain_holds() {
        let owner = KeyPair::generate();
        let rescuer = KeyPair::generate();
        let mut tx = build_tx(Address::from_public_key(&owner.public), &owner);
        tx.public_key = None;

        assert!(tx.signing_key(None, None).is_err(), "no key anywhere");
        assert!(tx.verify_signature().is_err(), "a wallet-side check has nothing to go on");
        assert!(tx.verify_own_signature().is_err());
        assert_eq!(tx.signing_key(None, Some(&owner.public)).unwrap(), &owner.public);
        assert_eq!(
            tx.signing_key(Some(&rescuer.public), Some(&owner.public)).unwrap(),
            &rescuer.public,
            "a recovered account signs with its recovery key, whatever is on record",
        );
        assert!(
            tx.verify_signature_under(tx.signing_key(Some(&rescuer.public), Some(&owner.public)).unwrap())
                .is_err(),
            "and the original key's signature no longer counts",
        );
    }

    /// The registry is not the only thing between a key and an address: a recorded key that does
    /// not derive the sender is refused, so a corrupted or mistaken entry cannot authorise it.
    #[test]
    fn a_recorded_key_must_derive_the_sender() {
        let owner = KeyPair::generate();
        let impostor = KeyPair::generate();
        let mut tx = build_tx(Address::from_public_key(&owner.public), &impostor);
        tx.public_key = None;
        assert!(tx.signing_key(None, Some(&impostor.public)).is_err());
    }
}
