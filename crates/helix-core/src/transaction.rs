use helix_crypto::{Address, CryptoResult, Hash, PublicKey, Signature};
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
    ProvePersonhood,
}

/// Payload embedded in `Transaction::data` for `TxType::ProvePersonhood`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonhoodProofPayload {
    /// C = secret^(2^63) mod p, as 16-byte little-endian f128 field element.
    pub commitment: [u8; 16],
    /// Serialized winterfell STARK proof bytes.
    pub proof_bytes: Vec<u8>,
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
    /// ML-DSA detached signature over the canonical hash of this tx
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
        })
        .expect("serialization is infallible for fixed types");
        Hash::digest(&payload)
    }

    /// Full transaction hash (includes signature — unique tx identifier)
    pub fn hash(&self) -> Hash {
        let payload = bincode::serialize(self).expect("serialization is infallible");
        Hash::digest(&payload)
    }

    pub fn verify_signature(&self) -> CryptoResult<()> {
        // The attached public key must actually derive the claimed sender address —
        // otherwise anyone could sign with their own key while setting `from` to a
        // victim's address, since the ML-DSA check alone only proves key possession.
        if Address::from_public_key(&self.public_key) != self.from {
            return Err(helix_crypto::CryptoError::InvalidAddress(
                "public key does not match sender address".to_string(),
            ));
        }
        let hash = self.signing_hash();
        helix_crypto::verify(&self.public_key, hash.as_bytes(), &self.signature)
    }
}

/// The signable subset of a transaction (excludes sig and pubkey)
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
