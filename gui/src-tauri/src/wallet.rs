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

/// Re-derive the 24-word recovery phrase from a wallet on disk, re-authenticating with the
/// passphrase. The words are never stored, so this rebuilds them the same way `create_at` did:
/// the ML-DSA secret *is* the 32-byte seed, and 32 bytes is exactly the entropy for 24 words —
/// so `Mnemonic::from_entropy(seed)` reproduces the identical phrase. A wallet on a scheme with
/// no re-derivable seed (SPHINCS+) has no phrase; say so rather than emit garbage.
pub fn reveal_mnemonic_at(path: &Path, passphrase: Option<&str>) -> Result<String, String> {
    let kf = KeyFile::load(path).map_err(e)?;
    let kp = kf.to_keypair(passphrase).map_err(e)?;
    let seed = kp.secret.as_bytes();
    if seed.len() != 32 {
        return Err("this wallet has no 24-word recovery phrase (only ML-DSA wallets do)".into());
    }
    Ok(Mnemonic::from_entropy(seed).map_err(e)?.to_string())
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

    #[test]
    fn reveal_reproduces_the_exact_phrase_shown_at_creation() {
        let dir = std::env::temp_dir().join(format!("helix-gui-reveal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.json");

        // Encrypted so reveal has to re-authenticate with the passphrase, like the real flow.
        let created = create_at(&path, Some("hunter2")).unwrap();
        let revealed = reveal_mnemonic_at(&path, Some("hunter2")).unwrap();
        assert_eq!(revealed, created.mnemonic);
        assert!(reveal_mnemonic_at(&path, Some("wrong")).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wallet_file_whose_address_was_swapped_does_not_open() {
        // The attack, on the surface people use: someone with write access to the wallet file
        // but not its passphrase replaces the plaintext `address` with their own. `load_at`
        // returned that field as the wallet's address — after a successful unlock with the right
        // passphrase — so the receive screen showed the attacker's address as the owner's.
        let dir = std::env::temp_dir().join(format!("helix-gui-tamper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.json");
        let created = create_at(&path, Some("hunter2")).unwrap();

        let attacker = Address::from_public_key(&KeyPair::generate().public).to_string();
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v["address"] = attacker.clone().into();
        std::fs::write(&path, v.to_string()).unwrap();

        let err = load_at(&path, Some("hunter2"))
            .err()
            .expect("a swapped address must not open");
        // The refusal names the address the file claimed, never the one its key hashes to —
        // had the public key been the rewritten field, that one would be the attacker's.
        assert!(!err.contains(&created.address), "{err}");
        assert!(err.contains("does not belong to"), "{err}");
        // Not even "is this encrypted?" answers for such a file — nothing reads it as a wallet.
        assert!(is_encrypted_at(&path).is_err());

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
