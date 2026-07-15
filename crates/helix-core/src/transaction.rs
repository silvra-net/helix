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
    /// same way.
    Undelegate,
    /// `tx.from` (a validator with an existing or new delegation pool) sets the commission
    /// rate it keeps from delegator rewards. `tx.data` carries the new rate as 2
    /// little-endian bytes (basis points, 0-10000). Capped well below 100% (see
    /// `MAX_COMMISSION_BPS`) — not because a validator can't legitimately choose to reward
    /// delegators poorly, but because an *uncapped* rate lets a validator advertise a low
    /// commission to attract delegators, then raise it to 100% after the fact and keep every
    /// future reward, with delegators locked in until they notice and unbond.
    SetCommission,
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
    /// Detached signature over the canonical hash of this tx
    pub signature: Signature,
    /// Full public key (needed for sig verification + address derivation)
    pub public_key: PublicKey,
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
        })
        .expect("serialization is infallible for fixed types");
        // Domain tag separates a transaction signature from a block-header or vote
        // signature. The payload itself is canonical bincode (length-prefixed), so the
        // tag + payload has no cross-encoding ambiguity.
        Hash::digest_many(&[b"helix-tx-v1:", &payload])
    }

    /// Full transaction hash (includes signature — unique tx identifier)
    pub fn hash(&self) -> Hash {
        let payload = bincode::serialize(self).expect("serialization is infallible");
        Hash::digest(&payload)
    }

    pub fn verify_signature(&self) -> CryptoResult<()> {
        self.verify_signature_with_recovery_key(None)
    }

    /// Same check as `verify_signature`, but for a `from` address whose control was ever
    /// rotated by social-recovery guardian quorum (see `execute_approve_recovery`),
    /// `recovery_key` is the active override key: it must have produced the signature,
    /// and the normal "public key derives the address" rule is intentionally skipped,
    /// since that's the whole point of a recovered account. `recovery_key: None` (the
    /// common case) falls back to the plain address-derivation + signature check.
    ///
    /// Mempool admission must use this — not `verify_signature` — for any tx whose sender
    /// has a recovery key set, or `execute_transaction`'s equally recovery-aware
    /// `verify_tx_signature` check is unreachable: every such tx would already have been
    /// rejected before it ever reached the executor.
    pub fn verify_signature_with_recovery_key(&self, recovery_key: Option<&PublicKey>) -> CryptoResult<()> {
        match recovery_key {
            Some(active_key) => {
                if self.public_key.as_bytes() != active_key.as_bytes() {
                    return Err(helix_crypto::CryptoError::InvalidAddress(
                        "public key does not match the active recovery key".to_string(),
                    ));
                }
            }
            None => {
                // The attached public key must actually derive the claimed sender address —
                // otherwise anyone could sign with their own key while setting `from` to a
                // victim's address, since the ML-DSA check alone only proves key possession.
                if Address::from_public_key(&self.public_key) != self.from {
                    return Err(helix_crypto::CryptoError::InvalidAddress(
                        "public key does not match sender address".to_string(),
                    ));
                }
            }
        }
        let hash = self.signing_hash();
        helix_crypto::verify_with_scheme(
            self.crypto_version,
            &self.public_key,
            hash.as_bytes(),
            &self.signature,
        )
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
            signature: Signature::from_bytes(vec![]),
            public_key: keypair.public.clone(),
        };
        tx.signature = keypair.sign(tx.signing_hash().as_bytes()).unwrap();
        tx
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
}
