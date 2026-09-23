use std::path::Path;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Result};
use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use serde::{Deserialize, Serialize};

use crate::{Address, CryptoScheme, KeyPair, PublicKey};

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
///
/// **Every way of reading one checks it** (`#[serde(try_from)]`, not a check in `load`): a
/// file whose `address` is not the address of its `public_key` does not become a `KeyFile` at
/// all — see `check_plaintext_fields` for why that field is the one worth attacking.
#[derive(Serialize, Deserialize)]
#[serde(try_from = "KeyFileOnDisk")]
pub struct KeyFile {
    /// A cache of `Address::from_public_key(public_key)`, stored in plaintext so a wallet can
    /// show it without being unlocked. Checked on every read, never trusted on its own.
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

/// A key file as it stands on disk, before anything has checked it. Deserialization lands
/// here first and becomes a `KeyFile` only through `TryFrom` — the field list is repeated on
/// purpose, and a field added to one without the other fails to compile rather than slip past.
#[derive(Deserialize)]
struct KeyFileOnDisk {
    address: String,
    public_key: String,
    algo: String,
    encryption: String,
    secret_key: String,
    kdf_salt: Option<String>,
    nonce: Option<String>,
    kdf_params: Option<KdfParams>,
}

impl TryFrom<KeyFileOnDisk> for KeyFile {
    type Error = anyhow::Error;

    fn try_from(f: KeyFileOnDisk) -> Result<Self> {
        let kf = KeyFile {
            address: f.address,
            public_key: f.public_key,
            algo: f.algo,
            encryption: f.encryption,
            secret_key: f.secret_key,
            kdf_salt: f.kdf_salt,
            nonce: f.nonce,
            kdf_params: f.kdf_params,
        };
        kf.check_plaintext_fields()?;
        Ok(kf)
    }
}

impl KeyFile {
    /// The checks that need no passphrase: the scheme is one this build knows, the public key
    /// is a well-formed key of that scheme, and the address is the one that key hashes to.
    ///
    /// **Why the address.** It sits in plaintext beside the encrypted secret, and `hlx wallet
    /// address`, `hlx wallet info` and the desktop wallet all showed it straight from the file.
    /// Nothing compared it with the key, so anyone able to write the file — passphrase or not —
    /// could put their own address there, and from then on every payment the owner asked for
    /// went to them. Checked here on every read, and again in `to_keypair`.
    ///
    /// **The limit, stated because it is real:** a *matching* forged pair of `public_key` and
    /// `address` passes this — anything checkable without the secret is forgeable without it.
    /// That pair is caught when the wallet is unlocked, where `KeyPair::from_raw` requires the
    /// public key to be the one the secret derives. An address shown *without* unlocking is only
    /// as trustworthy as the file it was read from.
    fn check_plaintext_fields(&self) -> Result<CryptoScheme> {
        let scheme = scheme_from_algo(&self.algo)?;
        let public = PublicKey::from_hex(&self.public_key)
            .map_err(|e| anyhow::anyhow!("Wallet file's public key is not valid hex: {}", e))?;
        if !public.is_valid_for(scheme) {
            bail!("Wallet file's public key is not a valid {} key", self.algo);
        }
        // Deliberately not naming the address the key hashes to: if `public_key` was the field
        // that got rewritten, that address is the attacker's, and this message would hand it out.
        match Address::from_str(&self.address) {
            Ok(stated) if stated == Address::from_public_key(&public) => Ok(scheme),
            _ => bail!(
                "The address in this wallet file ({}) does not belong to the key stored in it — \
                 the file has been altered or damaged. Do not use that address or give it to \
                 anyone. Restore the wallet from its recovery phrase (`hlx wallet restore`) or \
                 from a backup.",
                self.address
            ),
        }
    }

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
        Self::from_json_str(&std::fs::read_to_string(path)?)
    }

    /// Parse from an already-read string (the node reads its key file itself, so its errors
    /// can name the path — see `helix-node::load_or_create_keypair_with`).
    ///
    /// Parsed and checked as two steps, so a refusal reads as its reason rather than as a JSON
    /// syntax error "at line 1 column 4127". It is the same `TryFrom` serde runs.
    pub fn from_json_str(s: &str) -> Result<Self> {
        let raw: KeyFileOnDisk = serde_json::from_str(s)?;
        KeyFile::try_from(raw)
    }

    /// Recover the KeyPair, decrypting if needed
    ///
    /// The address this file shows is checked against the key before anything is decrypted,
    /// and the key against the decrypted secret by `KeyPair::from_raw` — so a `KeyPair` handed
    /// out here is always the one the address belongs to. Checked here and not only on read:
    /// the fields are public, and this is the step that hands out a signing key.
    pub fn to_keypair(&self, passphrase: Option<&str>) -> Result<KeyPair> {
        let scheme = self.check_plaintext_fields()?;
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

    /// Rewrite one or more plaintext fields the way someone with write access to the file —
    /// but not its passphrase — would: edit the JSON on disk and leave everything else alone.
    fn tampered(file: &KeyFile, edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut v = serde_json::to_value(file).unwrap();
        edit(&mut v);
        v.to_string()
    }

    #[test]
    fn a_rewritten_address_is_refused_before_anyone_can_read_it() {
        // The attack: `address` sits in plaintext beside the encrypted key, and `hlx wallet
        // address` / the desktop wallet showed it without ever touching the key. Swapping it
        // for the attacker's address needs no passphrase, and every payment the owner asks for
        // from then on goes to the attacker.
        let owner = KeyPair::generate();
        let attacker = Address::from_public_key(&KeyPair::generate().public);
        let file = KeyFile::from_keypair_encrypted(&owner, "pw").unwrap();
        let json = tampered(&file, |v| v["address"] = attacker.to_string().into());

        // Every way into a `KeyFile` refuses it — including plain serde, so a future caller
        // that deserializes directly cannot step around the check (#203's shape: a guarantee
        // that lives in one caller is a guarantee until the second caller).
        assert!(KeyFile::from_json_str(&json).is_err());
        assert!(serde_json::from_str::<KeyFile>(&json).is_err());
        let path = std::env::temp_dir().join(format!(
            "helix-keyfile-tamper-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, &json).unwrap();
        let loaded = KeyFile::load(&path);
        std::fs::remove_file(&path).ok();
        let err = loaded
            .err()
            .expect("a file whose address is not its key's must not load");
        assert!(err.to_string().contains("does not belong to"), "{err}");

        // Positive control: the untouched file loads, so the refusal above is about the edit.
        assert!(KeyFile::from_json_str(&serde_json::to_string(&file).unwrap()).is_ok());
    }

    #[test]
    fn an_address_changed_in_memory_does_not_survive_unlocking() {
        // `to_keypair` checks on its own rather than trusting that its `KeyFile` came through
        // deserialization — the fields are public, and this is the step that hands out a key.
        let owner = KeyPair::generate();
        let mut file = KeyFile::from_keypair_plain(&owner);
        file.address = Address::from_public_key(&KeyPair::generate().public).to_string();
        assert!(file.to_keypair(None).is_err());
    }

    #[test]
    fn rewriting_address_and_public_key_together_is_caught_when_the_wallet_is_unlocked() {
        // The stronger edit: replace the public key *and* the address with a matching pair, so
        // the plaintext fields agree with each other. Without the passphrase nothing can tell —
        // anything checkable without the secret is forgeable without it (that limit is real and
        // stays documented). With it, the decrypted secret disagrees, and the wallet must refuse
        // to open rather than open on the attacker's address.
        for scheme in [CryptoScheme::MlDsa, CryptoScheme::SphincsPlus] {
            let owner = KeyPair::generate_for(scheme);
            let attacker = KeyPair::generate_for(scheme);
            let file = KeyFile::from_keypair_encrypted(&owner, "pw").unwrap();
            let json = tampered(&file, |v| {
                v["public_key"] = attacker.public.to_hex().into();
                v["address"] = Address::from_public_key(&attacker.public)
                    .to_string()
                    .into();
            });
            let loaded = KeyFile::from_json_str(&json)
                .expect("self-consistent plaintext fields cannot be told apart without the secret");
            assert!(
                loaded.to_keypair(Some("pw")).is_err(),
                "{scheme:?}: the owner's passphrase opened a wallet that shows the attacker's address"
            );
            // Positive control: the same passphrase opens the untouched file.
            assert!(file.to_keypair(Some("pw")).is_ok(), "{scheme:?}");
        }
    }

    #[test]
    fn a_file_for_an_unknown_scheme_or_a_malformed_key_does_not_load() {
        let kp = KeyPair::generate();
        let file = KeyFile::from_keypair_plain(&kp);
        for (what, json) in [
            (
                "unknown algo",
                tampered(&file, |v| v["algo"] = "ML-DSA-Dilithium3".into()),
            ),
            (
                "truncated key",
                tampered(&file, |v| {
                    let pk = v["public_key"].as_str().unwrap().to_string();
                    v["public_key"] = pk[..pk.len() - 2].to_string().into();
                }),
            ),
            (
                "address not an address",
                tampered(&file, |v| v["address"] = "hlx".into()),
            ),
        ] {
            assert!(KeyFile::from_json_str(&json).is_err(), "{what} loaded");
        }
    }
}
