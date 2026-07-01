use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid hex encoding: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;
