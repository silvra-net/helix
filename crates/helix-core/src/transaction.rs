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
    /// Deploy a WASM smart contract
    DeployContract,
    /// Call a deployed smart contract
    CallContract,
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
