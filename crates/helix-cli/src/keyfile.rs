use std::path::Path;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use helix_crypto::{Address, KeyPair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

/// On-disk wallet format — supports both plaintext (devnet) and encrypted (mainnet)
#[derive(Serialize, Deserialize)]
pub struct KeyFile {
    pub address: String,
    pub public_key: String,
    pub algo: String,
    /// Encryption mode: "plaintext" or "aes256gcm-argon2"
    pub encryption: String,
    /// Encrypted secret key (hex). If encryption="plaintext", stored as raw hex.
    pub secret_key: String,
    /// Argon2 salt (only set when encrypted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_salt: Option<String>,
    /// AES-GCM nonce (only set when encrypted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl KeyFile {
    /// Create an unencrypted key file (devnet)
    pub fn from_keypair_plain(kp: &KeyPair) -> Self {
        let address = Address::from_public_key(&kp.public);
        KeyFile {
            address: address.to_string(),
            public_key: kp.public.to_hex(),
            algo: "ML-DSA-Dilithium3".to_string(),
            encryption: "plaintext".to_string(),
            secret_key: hex::encode(kp.secret.as_bytes()),
            kdf_salt: None,
            nonce: None,
        }
    }

    /// Create an AES-256-GCM encrypted key file with Argon2id key derivation
    pub fn from_keypair_encrypted(kp: &KeyPair, passphrase: &str) -> Result<Self> {
        let address = Address::from_public_key(&kp.public);
        let sk_bytes = kp.secret.as_bytes().to_vec();

        // Argon2id key derivation: passphrase → 32-byte AES key
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(passphrase.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("KDF error: {}", e))?;
        let key_bytes = hash.hash.unwrap();
        let key_bytes = key_bytes.as_bytes();
        if key_bytes.len() < 32 {
            bail!("KDF output too short");
        }

        // AES-256-GCM encryption
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes[..32]);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, sk_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;

        Ok(KeyFile {
            address: address.to_string(),
            public_key: kp.public.to_hex(),
            algo: "ML-DSA-Dilithium3".to_string(),
            encryption: "aes256gcm-argon2id".to_string(),
            secret_key: hex::encode(&ciphertext),
            kdf_salt: Some(salt.to_string()),
            nonce: Some(hex::encode(nonce)),
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("Key file not found: {}", path.display());
        }
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    /// Recover the KeyPair, decrypting if needed
    pub fn to_keypair(&self, passphrase: Option<&str>) -> Result<KeyPair> {
        let sk_bytes = match self.encryption.as_str() {
            "plaintext" => hex::decode(&self.secret_key)?,

            "aes256gcm-argon2id" => {
                let pass = passphrase
                    .ok_or_else(|| anyhow::anyhow!("Passphrase required for encrypted wallet"))?;
                let salt_str = self
                    .kdf_salt
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("Missing KDF salt"))?;
                let nonce_hex = self
                    .nonce
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("Missing nonce"))?;

                // Re-derive key from passphrase
                let salt = SaltString::from_b64(salt_str)
                    .map_err(|e| anyhow::anyhow!("Invalid salt: {}", e))?;
                let argon2 = Argon2::default();
                let hash = argon2
                    .hash_password(pass.as_bytes(), &salt)
                    .map_err(|e| anyhow::anyhow!("KDF error: {}", e))?;
                let key_bytes = hash.hash.unwrap();
                let key_bytes = key_bytes.as_bytes();

                // Decrypt
                let key = Key::<Aes256Gcm>::from_slice(&key_bytes[..32]);
                let cipher = Aes256Gcm::new(key);
                let nonce_bytes = hex::decode(nonce_hex)?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                let ciphertext = hex::decode(&self.secret_key)?;
                cipher
                    .decrypt(nonce, ciphertext.as_slice())
                    .map_err(|_| anyhow::anyhow!("Decryption failed — wrong passphrase?"))?
            }

            other => bail!("Unknown encryption format: {}", other),
        };

        let pk_bytes = hex::decode(&self.public_key)?;
        Ok(KeyPair {
            public: PublicKey::from_bytes(pk_bytes),
            secret: SecretKey::from_bytes(sk_bytes),
        })
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryption != "plaintext"
    }
}
