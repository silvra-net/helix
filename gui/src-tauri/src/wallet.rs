//! Wallet lifecycle: create (with a 24-word recovery phrase), restore, and unlock — all against
//! the real `KeyFile` on-disk format and `KeyPair` derivation the CLI and node use. Pure over a
//! `&Path` so it is unit-testable without Tauri; the command layer resolves the app-data path.

use std::path::Path;

use bip39::Mnemonic;
use helix_crypto::{KeyFile, KeyPair};

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

/// Result of creating a wallet — the keypair to unlock with, its address, and the 24 words shown
/// exactly once. The words are never written to disk (that would be a second, unprotected copy of
/// the key); the frontend shows them and moves on.
pub struct Created {
    pub keypair: KeyPair,
    pub address: String,
    pub mnemonic: String,
}

/// Draw a fresh 32-byte ML-DSA seed (FIPS 204's ξ) from the OS CSPRNG — the seed *is* the key,
/// and 32 bytes is exactly the BIP39 entropy for 24 words.
fn random_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

pub fn exists_at(path: &Path) -> bool {
    path.exists()
}

pub fn is_encrypted_at(path: &Path) -> Result<bool, String> {
    Ok(KeyFile::load(path).map_err(e)?.is_encrypted())
}

/// Create a new ML-DSA wallet, save its `KeyFile` at `path` (encrypted iff a non-empty
/// passphrase is given), and return the keypair + address + recovery phrase.
pub fn create_at(path: &Path, passphrase: Option<&str>) -> Result<Created, String> {
    let seed = random_seed();
    let mnemonic = Mnemonic::from_entropy(&seed).map_err(e)?;
    let kp = KeyPair::from_mldsa_seed(&seed).map_err(e)?;
    let kf = encode(&kp, passphrase)?;
    kf.save(path).map_err(e)?;
    Ok(Created {
        address: kf.address.clone(),
        keypair: kp,
        mnemonic: mnemonic.to_string(),
    })
}

/// Rebuild a wallet from its 24-word recovery phrase and save it at `path`. BIP39's checksum
/// rejects a phrase with a word out of place rather than silently deriving a stranger's address.
pub fn restore_at(path: &Path, phrase: &str, passphrase: Option<&str>) -> Result<(KeyPair, String), String> {
    let mnemonic = Mnemonic::parse_normalized(phrase.trim())
        .map_err(|err| format!("that is not a valid 24-word recovery phrase ({err})"))?;
    let seed = mnemonic.to_entropy();
    let kp = KeyPair::from_mldsa_seed(&seed).map_err(e)?;
    let kf = encode(&kp, passphrase)?;
    kf.save(path).map_err(e)?;
    let address = kf.address.clone();
    Ok((kp, address))
}

/// Load and decrypt an existing wallet. `passphrase` is required iff the file is encrypted.
pub fn load_at(path: &Path, passphrase: Option<&str>) -> Result<(KeyPair, String), String> {
    let kf = KeyFile::load(path).map_err(e)?;
    let address = kf.address.clone();
    let kp = kf.to_keypair(passphrase).map_err(e)?;
    Ok((kp, address))
}

fn encode(kp: &KeyPair, passphrase: Option<&str>) -> Result<KeyFile, String> {
    match passphrase {
        Some(p) if !p.is_empty() => KeyFile::from_keypair_encrypted(kp, p).map_err(e),
        _ => Ok(KeyFile::from_keypair_plain(kp)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_crypto::Address;

    #[test]
    fn create_then_load_round_trips_the_same_address() {
        let dir = std::env::temp_dir().join(format!("helix-gui-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.json");

        let created = create_at(&path, None).unwrap();
        assert_eq!(created.mnemonic.split_whitespace().count(), 24);

        let (kp, address) = load_at(&path, None).unwrap();
        assert_eq!(address, created.address);
        assert_eq!(Address::from_public_key(&kp.public).to_string(), created.address);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The phrase must reproduce the exact wallet, and it must match the *other* implementation:
    /// Spark's `@scure/bip39` + `@noble/post-quantum` over the same seed. Pinned so the desktop
    /// wallet and the mobile app never derive different addresses from the same 24 words.
    #[test]
    fn derivation_matches_the_pinned_spark_vector() {
        let seed: Vec<u8> = (0u8..32).collect();
        let mnemonic = Mnemonic::from_entropy(&seed).unwrap();
        let words: Vec<&str> = mnemonic.words().collect();
        assert_eq!(&words[..3], &["abandon", "amount", "liar"]);

        let kp = KeyPair::from_mldsa_seed(&seed).unwrap();
        assert_eq!(
            Address::from_public_key(&kp.public).to_string(),
            "hlxZiWwobcPKCRx8qjZECjeitEufkor2NQ1S"
        );
    }
}
