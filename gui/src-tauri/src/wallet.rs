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

/// Give the wallet at `path` a new passphrase — its first, or a replacement — after opening it
/// with `current` (`None` for a wallet that has none).
///
/// Asking for the current passphrase even though the wallet is already unlocked is the point:
/// a window left open for a minute must not be enough to lock its owner out under a passphrase
/// they never chose. An empty `new` is refused — this is the way to protect a wallet, and
/// removing a passphrase stays with `helix wallet encrypt --remove`, out of reach of an
/// unattended window.
///
/// The new file is opened with the new passphrase and checked against the key before it
/// replaces the old one, and it replaces it in one step (`KeyFile::replace`: written beside it,
/// then renamed) — this file is the only copy of the key.
pub fn change_passphrase_at(path: &Path, current: Option<&str>, new: &str) -> Result<String, String> {
    if new.is_empty() {
        return Err("an empty passphrase protects nothing — nothing was changed".into());
    }
    let kf = KeyFile::load(path).map_err(e)?;
    // A wallet encrypted under the empty passphrase (the CLI made those until 2026-09-23) opens
    // with "" and nothing else; the frontend sends nothing for an empty field.
    let current = if kf.is_encrypted() { Some(current.unwrap_or("")) } else { None };
    let kp = kf
        .to_keypair(current)
        .map_err(|err| format!("the current passphrase does not open this wallet — nothing was changed ({err})"))?;
    let new_kf = KeyFile::from_keypair_encrypted(&kp, new).map_err(e)?;
    let reopened = new_kf.to_keypair(Some(new)).map_err(e)?;
    if reopened.public != kp.public {
        return Err("the re-encrypted wallet did not open to the same key — nothing was changed".into());
    }
    new_kf.replace(path).map_err(e)?;
    Ok(new_kf.address.clone())
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

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("helix-gui-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("wallet.json")
    }

    /// The case #226 left open: a wallet made without a passphrase gets one, from the app.
    #[test]
    fn a_wallet_without_a_passphrase_gets_one() {
        let path = scratch("pass-first");
        let created = create_at(&path, None).unwrap();
        assert!(!is_encrypted_at(&path).unwrap());

        assert_eq!(change_passphrase_at(&path, None, "hunter2").unwrap(), created.address);
        assert!(is_encrypted_at(&path).unwrap());
        assert!(load_at(&path, None).is_err(), "it must no longer open without one");
        let (kp, address) = load_at(&path, Some("hunter2")).unwrap();
        assert_eq!(address, created.address);
        assert_eq!(kp.public, created.keypair.public);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_passphrase_is_replaced_and_the_old_one_stops_working() {
        let path = scratch("pass-change");
        let created = create_at(&path, Some("old")).unwrap();
        change_passphrase_at(&path, Some("old"), "new").unwrap();
        assert!(load_at(&path, Some("old")).is_err());
        assert_eq!(load_at(&path, Some("new")).unwrap().1, created.address);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Every refusal leaves the file exactly as it was — byte for byte, because it is the only
    /// copy of the key.
    #[test]
    fn a_refused_change_leaves_the_file_untouched() {
        let path = scratch("pass-refused");
        create_at(&path, Some("old")).unwrap();
        let before = std::fs::read(&path).unwrap();

        let wrong = change_passphrase_at(&path, Some("not it"), "new").unwrap_err();
        assert!(wrong.contains("does not open"), "{wrong}");
        let missing = change_passphrase_at(&path, None, "new").unwrap_err();
        assert!(missing.contains("does not open"), "{missing}");
        let empty = change_passphrase_at(&path, Some("old"), "").unwrap_err();
        assert!(empty.contains("protects nothing"), "{empty}");

        assert_eq!(std::fs::read(&path).unwrap(), before);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A wallet the CLI encrypted under the empty passphrase before 2026-09-23 opens with ""
    /// alone — and the frontend sends nothing for an empty field.
    #[test]
    fn a_wallet_encrypted_under_the_empty_passphrase_can_be_given_a_real_one() {
        let path = scratch("pass-empty-old");
        let kp = KeyPair::generate();
        KeyFile::from_keypair_encrypted(&kp, "").unwrap().save(&path).unwrap();
        change_passphrase_at(&path, None, "hunter2").unwrap();
        assert_eq!(load_at(&path, Some("hunter2")).unwrap().0.public, kp.public);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
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
