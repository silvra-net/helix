use std::path::Path;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Result};
use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use serde::{Deserialize, Serialize};

use crate::{Address, CryptoScheme, KeyPair};

/// Human-readable algo strings stored in `KeyFile::algo` — the on-disk name for
/// each `CryptoScheme`, so a wallet file records which scheme to reconstruct on load.
const ALGO_ML_DSA: &str = "ML-DSA-65";
const ALGO_SPHINCS_PLUS: &str = "SLH-DSA-SHA2-192s";

/// Argon2id parameters for encrypting a key file. Well above the OWASP interactive-login
/// minimum (19 MiB / t=2), since a leaked wallet or validator key file is a high-value,
/// offline-crackable target. Persisted per file (see `KeyFile::kdf_params`) so raising these
/// for new files never breaks decryption of ones written with older parameters.
const ARGON2_M_COST_KIB: u32 = 65_536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const DERIVED_KEY_LEN: usize = 32;

/// Argon2id cost parameters recorded alongside an encrypted key file so the exact same
/// derivation can be reproduced on load, regardless of what the current defaults are.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    fn current() -> Self {
        KdfParams { m_cost: ARGON2_M_COST_KIB, t_cost: ARGON2_T_COST, p_cost: ARGON2_P_COST }
    }

    /// The parameters `Argon2::default()` used before per-file params were recorded —
    /// the fallback for a key file that predates the `kdf_params` field.
    fn legacy_default() -> Self {
        let d = Params::DEFAULT;
        KdfParams { m_cost: d.m_cost(), t_cost: d.t_cost(), p_cost: d.p_cost() }
    }

    fn build_argon2(&self) -> Result<Argon2<'static>> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(DERIVED_KEY_LEN))
            .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {}", e))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

fn algo_name(scheme: CryptoScheme) -> &'static str {
    match scheme {
        CryptoScheme::MlDsa => ALGO_ML_DSA,
        CryptoScheme::SphincsPlus => ALGO_SPHINCS_PLUS,
    }
}

fn scheme_from_algo(algo: &str) -> Result<CryptoScheme> {
    match algo {
        ALGO_ML_DSA => Ok(CryptoScheme::MlDsa),
        ALGO_SPHINCS_PLUS => Ok(CryptoScheme::SphincsPlus),
        other => bail!("Unknown key algorithm in wallet file: {}", other),
    }
}

/// Unified on-disk key format — used by both the `hlx` CLI (wallets) and `helix-node`
/// (validator identity). Supports plaintext (devnet) and passphrase-encrypted (mainnet)
/// storage. Moved here from `helix-cli` (2026-07-05) so node and CLI share one format
/// instead of the node using a separate raw-bytes file. The node's old raw-bytes
/// fallback (pre-2026-07-05 key files) was removed on 2026-07-13 once no known key
/// file still used it — `hlx wallet import-node-key` (`WalletCmd::ImportNodeKey` in
/// helix-cli) still knows how to convert an old file to this format if one turns up.
#[derive(Serialize, Deserialize)]
pub struct KeyFile {
    pub address: String,
    pub public_key: String,
    pub algo: String,
    /// Encryption mode: "plaintext" or "aes256gcm-argon2id"
    pub encryption: String,
    /// Encrypted secret key (hex). If encryption="plaintext", stored as raw hex.
    pub secret_key: String,
    /// Argon2 salt (only set when encrypted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_salt: Option<String>,
    /// AES-GCM nonce (only set when encrypted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Argon2id cost parameters used to derive the encryption key (only set when encrypted).
    /// Absent on files written before per-file params existed — those used `Argon2::default()`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_params: Option<KdfParams>,
}

impl KeyFile {
    /// Create an unencrypted key file (devnet)
    pub fn from_keypair_plain(kp: &KeyPair) -> Self {
        let address = Address::from_public_key(&kp.public);
        KeyFile {
            address: address.to_string(),
            public_key: kp.public.to_hex(),
            algo: algo_name(kp.scheme).to_string(),
            encryption: "plaintext".to_string(),
            secret_key: hex::encode(kp.secret.as_bytes()),
            kdf_salt: None,
            nonce: None,
            kdf_params: None,
        }
    }

    /// Create an AES-256-GCM encrypted key file with Argon2id key derivation
    pub fn from_keypair_encrypted(kp: &KeyPair, passphrase: &str) -> Result<Self> {
        let address = Address::from_public_key(&kp.public);
        let sk_bytes = kp.secret.as_bytes().to_vec();

        // Argon2id key derivation: passphrase → 32-byte AES key, using the current
        // (hardened) parameters, which are recorded in the file for reproducible decryption.
        let kdf_params = KdfParams::current();
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = kdf_params.build_argon2()?;
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
            algo: algo_name(kp.scheme).to_string(),
            encryption: "aes256gcm-argon2id".to_string(),
            secret_key: hex::encode(&ciphertext),
            kdf_salt: Some(salt.to_string()),
            nonce: Some(hex::encode(nonce)),
            kdf_params: Some(kdf_params),
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

    /// Parse from an already-read string (node loader reads the file itself to also
    /// support the legacy raw-bytes fallback — see `helix-node::load_or_create_keypair`).
    pub fn from_json_str(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
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

                // Re-derive key from passphrase, using the exact parameters recorded in the
                // file (or the legacy default for files written before params were stored).
                let salt = SaltString::from_b64(salt_str)
                    .map_err(|e| anyhow::anyhow!("Invalid salt: {}", e))?;
                let argon2 = self
                    .kdf_params
                    .unwrap_or_else(KdfParams::legacy_default)
                    .build_argon2()?;
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
        let scheme = scheme_from_algo(&self.algo)?;
        Ok(KeyPair::from_raw(scheme, sk_bytes, pk_bytes)?)
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryption != "plaintext"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_keyfile_round_trips_with_hardened_params() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public);
        let file = KeyFile::from_keypair_encrypted(&kp, "correct horse battery staple").unwrap();

        // The hardened parameters are recorded in the file, not left implicit.
        let params = file.kdf_params.expect("encrypted file must record its KDF params");
        assert_eq!(params.m_cost, ARGON2_M_COST_KIB);
        assert_eq!(params.t_cost, ARGON2_T_COST);
        assert!(params.m_cost > KdfParams::legacy_default().m_cost, "must be stronger than the old default");

        let restored = file.to_keypair(Some("correct horse battery staple")).unwrap();
        assert_eq!(Address::from_public_key(&restored.public), addr);
        assert_eq!(restored.secret.as_bytes(), kp.secret.as_bytes());
    }

    #[test]
    fn encrypted_keyfile_rejects_wrong_passphrase() {
        let kp = KeyPair::generate();
        let file = KeyFile::from_keypair_encrypted(&kp, "right").unwrap();
        assert!(file.to_keypair(Some("wrong")).is_err());
    }

    #[test]
    fn legacy_encrypted_file_without_params_still_decrypts_via_default() {
        // Simulate a file written before per-file params existed: encrypt with the legacy
        // default params and then drop the recorded params, forcing the load-time fallback.
        let kp = KeyPair::generate();
        let mut file = KeyFile::from_keypair_encrypted(&kp, "pw").unwrap();
        // Re-derive under legacy default so the ciphertext matches params-absent decryption.
        let legacy = {
            let salt = SaltString::from_b64(file.kdf_salt.as_deref().unwrap()).unwrap();
            let argon2 = KdfParams::legacy_default().build_argon2().unwrap();
            let hash = argon2.hash_password(b"pw", &salt).unwrap();
            let key_bytes = hash.hash.unwrap();
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes.as_bytes()[..32]));
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let ct = cipher.encrypt(&nonce, kp.secret.as_bytes()).unwrap();
            (hex::encode(&ct), hex::encode(nonce))
        };
        file.secret_key = legacy.0;
        file.nonce = Some(legacy.1);
        file.kdf_params = None; // pretend it's an old file

        let restored = file.to_keypair(Some("pw")).unwrap();
        assert_eq!(restored.secret.as_bytes(), kp.secret.as_bytes());
    }
}
