//! The wallet's keys on disk.
//!
//! ```text
//! <wallet-dir>/wallet.json        what the wallet is: chain, network, birth height, hot address
//! <wallet-dir>/keys/<address>.json one helix `KeyFile` per key, owner-only, never overwritten
//! <wallet-dir>/issued.log         every deposit address ever handed out, appended and synced
//! ```
//!
//! Every key is a `helix_crypto::KeyFile` — the format the CLI and the node already use: an
//! address checked against its key on every read, and with a passphrase, AES-256-GCM under an
//! Argon2id key. No new format, no new cryptography.
//!
//! **A deposit address is handed out once.** `issued.log` is appended and synced *before* the
//! address is returned, so a crash between the two can at worst skip an address, never give the
//! same one to two customers. An address that has been paid counts as issued too — the ledger scan
//! marks it (`Keys::mark_issued`) — which covers a restore from a backup older than the log.
//!
//! An encrypted wallet can hand out addresses while locked, as Bitcoin Core does: keys are made
//! ahead into a pool while it is unlocked (each needs the passphrase to be encrypted), and
//! `getnewaddress` takes the next one.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use helix_crypto::{Address, KeyFile, KeyPair};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Meta {
    pub version: u32,
    /// `main` or `test` — what `getblockchaininfo` reports as `chain`.
    pub network: String,
    /// The genesis hash of the chain every transaction of this wallet signs.
    pub chain_id: String,
    /// The height at which the wallet was made. No key of it can have history before this, so
    /// the ledger starts here.
    pub birth_height: u64,
    pub hot_address: String,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Issued {
    pub address: String,
    pub label: String,
    pub time: u64,
}

struct Unlocked {
    passphrase: Zeroizing<String>,
    hot: KeyPair,
    until: Option<Instant>,
}

pub struct Keys {
    dir: PathBuf,
    pub meta: Meta,
    all: HashSet<String>,
    issued: BTreeMap<String, Issued>,
    pool: VecDeque<String>,
    unlocked: Option<Unlocked>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The wallet is encrypted and locked.
    Locked,
    /// Locked, and no address made ahead is left.
    PoolEmpty,
    WrongPassphrase,
    NotEncrypted,
    Other(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Locked => write!(f, "the wallet is locked — unlock it with walletpassphrase first"),
            KeyError::PoolEmpty => write!(
                f,
                "no pre-made address left while the wallet is locked — unlock it (walletpassphrase) \
                 so it can make more"
            ),
            KeyError::WrongPassphrase => write!(f, "the wallet passphrase entered was incorrect"),
            KeyError::NotEncrypted => write!(f, "the wallet is not encrypted"),
            KeyError::Other(e) => write!(f, "{e}"),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn owner_only_new(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

fn sync_dir(dir: &Path) {
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

impl Keys {
    /// Make a new wallet in `dir`, which must not hold one. With a passphrase every key is
    /// encrypted under it.
    pub fn create(dir: &Path, network: &str, chain_id: &str, birth_height: u64, passphrase: Option<&str>) -> Result<Keys> {
        if dir.join("wallet.json").exists() {
            bail!("{} already holds a wallet — refusing to make another over it", dir.display());
        }
        std::fs::create_dir_all(dir.join("keys")).with_context(|| format!("could not create {}", dir.display()))?;
        let hot = KeyPair::generate();
        let hot_address = Address::from_public_key(&hot.public).to_string();
        write_key(dir, &hot, passphrase)?;
        let meta = Meta {
            version: 1,
            network: network.to_string(),
            chain_id: chain_id.to_string(),
            birth_height,
            hot_address,
            encrypted: passphrase.is_some(),
        };
        let mut file = owner_only_new(&dir.join("wallet.json"))?;
        file.write_all(serde_json::to_string_pretty(&meta)?.as_bytes())?;
        file.sync_all()?;
        sync_dir(dir);
        Keys::open(dir)
    }

    pub fn open(dir: &Path) -> Result<Keys> {
        let meta_path = dir.join("wallet.json");
        let meta: Meta = serde_json::from_str(
            &std::fs::read_to_string(&meta_path).with_context(|| format!("no wallet at {}", dir.display()))?,
        )
        .with_context(|| format!("{} is not a wallet description", meta_path.display()))?;
        let mut all = HashSet::new();
        let mut made: Vec<(std::time::SystemTime, String)> = Vec::new();
        for entry in std::fs::read_dir(dir.join("keys"))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // Read through KeyFile, which checks the address against the key.
            let kf = KeyFile::load(&path).with_context(|| format!("unreadable key file {}", path.display()))?;
            if path.file_stem().and_then(|s| s.to_str()) != Some(kf.address.as_str()) {
                bail!("{} holds the key of {}, not of the address its name says", path.display(), kf.address);
            }
            made.push((std::fs::metadata(&path)?.modified()?, kf.address.clone()));
            all.insert(kf.address);
        }
        if !all.contains(&meta.hot_address) {
            bail!("the hot key {} is missing from {}", meta.hot_address, dir.join("keys").display());
        }
        let mut issued = BTreeMap::new();
        if let Ok(log) = std::fs::read_to_string(dir.join("issued.log")) {
            for line in log.lines().filter(|l| !l.trim().is_empty()) {
                let mut parts = line.splitn(3, '\t');
                let address = parts.next().unwrap_or_default().to_string();
                let time = parts.next().and_then(|t| t.parse().ok()).unwrap_or(0);
                let label = parts.next().unwrap_or_default().to_string();
                if !all.contains(&address) {
                    bail!("issued.log names {address}, whose key is not in this wallet");
                }
                issued.insert(address.clone(), Issued { address, label, time });
            }
        }
        made.sort();
        let pool = made
            .into_iter()
            .map(|(_, a)| a)
            .filter(|a| a != &meta.hot_address && !issued.contains_key(a))
            .collect();
        let mut keys = Keys { dir: dir.to_path_buf(), meta, all, issued, pool, unlocked: None };
        if !keys.meta.encrypted {
            let hot = keys.load_pair(&keys.meta.hot_address.clone(), None)?;
            keys.unlocked = Some(Unlocked { passphrase: Zeroizing::new(String::new()), hot, until: None });
        }
        Ok(keys)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn load_pair(&self, address: &str, passphrase: Option<&str>) -> Result<KeyPair> {
        let kf = KeyFile::load(&self.dir.join("keys").join(format!("{address}.json")))?;
        kf.to_keypair(passphrase)
    }

    fn expire(&mut self) {
        if let Some(u) = &self.unlocked {
            if u.until.is_some_and(|t| Instant::now() >= t) {
                self.unlocked = None;
            }
        }
    }

    pub fn is_unlocked(&mut self) -> bool {
        self.expire();
        self.unlocked.is_some()
    }

    /// Seconds since the epoch at which the wallet locks again, for `getwalletinfo`; 0 while
    /// locked; `None` for a wallet without a passphrase.
    pub fn unlocked_until(&mut self) -> Option<u64> {
        if !self.meta.encrypted {
            return None;
        }
        self.expire();
        Some(match &self.unlocked {
            Some(Unlocked { until: Some(t), .. }) => now_secs() + t.saturating_duration_since(Instant::now()).as_secs(),
            _ => 0,
        })
    }

    /// Unlock for `seconds`. The passphrase is checked by decrypting the hot key.
    pub fn unlock(&mut self, passphrase: &str, seconds: u64) -> Result<(), KeyError> {
        if !self.meta.encrypted {
            return Err(KeyError::NotEncrypted);
        }
        let hot = self
            .load_pair(&self.meta.hot_address.clone(), Some(passphrase))
            .map_err(|_| KeyError::WrongPassphrase)?;
        let until = Instant::now() + Duration::from_secs(seconds.min(100_000_000));
        self.unlocked = Some(Unlocked { passphrase: Zeroizing::new(passphrase.to_string()), hot, until: Some(until) });
        Ok(())
    }

    pub fn lock(&mut self) -> Result<(), KeyError> {
        if !self.meta.encrypted {
            return Err(KeyError::NotEncrypted);
        }
        self.unlocked = None;
        Ok(())
    }

    pub fn hot(&mut self) -> Result<&KeyPair, KeyError> {
        self.expire();
        self.unlocked.as_ref().map(|u| &u.hot).ok_or(KeyError::Locked)
    }

    /// The key of one of this wallet's addresses, decrypted for one signature.
    pub fn pair(&mut self, address: &str) -> Result<KeyPair, KeyError> {
        self.expire();
        if !self.all.contains(address) {
            return Err(KeyError::Other(format!("{address} is not an address of this wallet")));
        }
        let unlocked = self.unlocked.as_ref().ok_or(KeyError::Locked)?;
        let passphrase = if self.meta.encrypted { Some(unlocked.passphrase.as_str()) } else { None };
        self.load_pair(address, passphrase).map_err(|e| KeyError::Other(e.to_string()))
    }

    pub fn is_mine(&self, address: &str) -> bool {
        self.all.contains(address)
    }

    pub fn addresses(&self) -> impl Iterator<Item = &String> {
        self.all.iter()
    }

    pub fn issued(&self) -> impl Iterator<Item = &Issued> {
        self.issued.values()
    }

    pub fn label(&self, address: &str) -> Option<&str> {
        self.issued.get(address).map(|i| i.label.as_str())
    }

    pub fn pool_size(&self) -> usize {
        self.pool.len()
    }

    /// Hand out a deposit address: from the pool, or made now if the wallet can make one.
    pub fn new_address(&mut self, label: &str) -> Result<String, KeyError> {
        self.expire();
        let address = match self.pool.pop_front() {
            Some(a) => a,
            None => self.make_key().map_err(|e| match e {
                KeyError::Locked => KeyError::PoolEmpty,
                other => other,
            })?,
        };
        if let Err(e) = self.mark_issued(&address, label) {
            // Not recorded, so not handed out: back to the front of the pool.
            self.pool.push_front(address);
            return Err(KeyError::Other(e.to_string()));
        }
        Ok(address)
    }

    /// Record `address` as handed out — appended to `issued.log` and synced before this returns.
    pub fn mark_issued(&mut self, address: &str, label: &str) -> Result<()> {
        if self.issued.contains_key(address) || address == self.meta.hot_address {
            return Ok(());
        }
        let label = label.replace(['\t', '\n', '\r'], " ");
        let time = now_secs();
        let mut options = std::fs::OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut log = options.open(self.dir.join("issued.log"))?;
        writeln!(log, "{address}\t{time}\t{label}")?;
        log.sync_all()?;
        self.pool.retain(|a| a != address);
        self.issued.insert(address.to_string(), Issued { address: address.to_string(), label, time });
        Ok(())
    }

    fn make_key(&mut self) -> Result<String, KeyError> {
        let passphrase = match (&self.unlocked, self.meta.encrypted) {
            (Some(u), true) => Some(u.passphrase.to_string()),
            (Some(_), false) => None,
            (None, _) => return Err(KeyError::Locked),
        };
        let kp = KeyPair::generate();
        let address = write_key(&self.dir, &kp, passphrase.as_deref()).map_err(|e| KeyError::Other(e.to_string()))?;
        self.all.insert(address.clone());
        Ok(address)
    }

    /// Make keys ahead until the pool holds `target`. Only while the wallet can make keys; each
    /// encrypted key costs an Argon2id derivation, so callers bound `target`.
    pub fn refill(&mut self, target: usize) -> Result<usize, KeyError> {
        self.expire();
        let mut made = 0;
        while self.pool.len() < target {
            let address = self.make_key()?;
            self.pool.push_back(address);
            made += 1;
        }
        Ok(made)
    }

    /// Access to one key, to decrypt outside the lock. Only while the wallet is unlocked.
    pub fn access(&mut self, address: &str) -> Result<KeyAccess, KeyError> {
        self.expire();
        if !self.all.contains(address) {
            return Err(KeyError::Other(format!("{address} is not an address of this wallet")));
        }
        let unlocked = self.unlocked.as_ref().ok_or(KeyError::Locked)?;
        Ok(KeyAccess {
            path: self.dir.join("keys").join(format!("{address}.json")),
            passphrase: self.meta.encrypted.then(|| unlocked.passphrase.clone()),
        })
    }

    /// A maker for one more pooled key while the pool is short of `target` and the wallet can
    /// make keys; the key made is taken in with `adopt`.
    pub fn maker(&mut self, target: usize) -> Option<KeyMaker> {
        self.expire();
        if self.pool.len() >= target {
            return None;
        }
        let unlocked = self.unlocked.as_ref()?;
        Some(KeyMaker { dir: self.dir.clone(), passphrase: self.meta.encrypted.then(|| unlocked.passphrase.clone()) })
    }

    pub fn adopt(&mut self, address: String) {
        if self.all.insert(address.clone()) {
            self.pool.push_back(address);
        }
    }

    /// Write every key (as stored, encrypted or not) and the issued list into one new file.
    pub fn backup(&self, destination: &Path) -> Result<()> {
        let mut keys = Vec::new();
        for address in &self.all {
            let text = std::fs::read_to_string(self.dir.join("keys").join(format!("{address}.json")))?;
            keys.push(serde_json::from_str::<serde_json::Value>(&text)?);
        }
        let bundle = serde_json::json!({
            "helix_walletd_backup": 1,
            "meta": self.meta,
            "issued": self.issued.values().collect::<Vec<_>>(),
            "keys": keys,
        });
        let mut file = owner_only_new(destination).map_err(|e| {
            anyhow!("could not create {} (it must not exist yet): {e}", destination.display())
        })?;
        file.write_all(serde_json::to_string(&bundle)?.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }
}

/// What it takes to read one key, taken out of the lock: decrypting costs an Argon2id
/// derivation, and nothing else waiting on the wallet should wait on that.
pub struct KeyAccess {
    path: PathBuf,
    passphrase: Option<Zeroizing<String>>,
}

impl KeyAccess {
    pub fn pair(&self) -> Result<KeyPair> {
        KeyFile::load(&self.path)?.to_keypair(self.passphrase.as_deref().map(|p| p.as_str()))
    }
}

/// What it takes to make one key, taken out of the lock for the same reason.
pub struct KeyMaker {
    dir: PathBuf,
    passphrase: Option<Zeroizing<String>>,
}

impl KeyMaker {
    pub fn make(&self) -> Result<String> {
        write_key(&self.dir, &KeyPair::generate(), self.passphrase.as_deref().map(|p| p.as_str()))
    }
}

/// Write `kp` as `keys/<address>.json`, refusing to overwrite. Returns the address.
fn write_key(dir: &Path, kp: &KeyPair, passphrase: Option<&str>) -> Result<String> {
    let kf = match passphrase {
        Some(p) => KeyFile::from_keypair_encrypted(kp, p)?,
        None => KeyFile::from_keypair_plain(kp),
    };
    kf.save(&dir.join("keys").join(format!("{}.json", kf.address)))?;
    sync_dir(&dir.join("keys"));
    Ok(kf.address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("helix-walletd-keys-{name}-{}", rand::random::<u64>()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn an_address_is_never_handed_out_twice_across_restarts() {
        let dir = temp_dir("twice");
        let mut keys = Keys::create(&dir, "test", "ab", 7, None).unwrap();
        let a = keys.new_address("alice").unwrap();
        let b = keys.new_address("bob").unwrap();
        assert_ne!(a, b);
        drop(keys);
        let mut keys = Keys::open(&dir).unwrap();
        let c = keys.new_address("carol").unwrap();
        assert!(c != a && c != b, "a restart must not hand out an issued address again");
        assert_eq!(keys.label(&a), Some("alice"));
        assert!(keys.is_mine(&a) && keys.is_mine(&keys.meta.hot_address.clone()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pooled_address_is_handed_out_before_a_new_one_is_made() {
        let dir = temp_dir("pool");
        let mut keys = Keys::create(&dir, "test", "ab", 0, None).unwrap();
        assert_eq!(keys.refill(3).unwrap(), 3);
        let pooled: Vec<String> = keys.pool.iter().cloned().collect();
        let first = keys.new_address("").unwrap();
        assert_eq!(first, pooled[0]);
        assert_eq!(keys.pool_size(), 2);
        drop(keys);
        // The pool survives a restart minus what was issued.
        let keys = Keys::open(&dir).unwrap();
        assert_eq!(keys.pool_size(), 2);
        assert!(!keys.pool.contains(&first));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_locked_wallet_hands_out_pooled_addresses_and_then_says_why_it_cannot() {
        let dir = temp_dir("locked");
        let mut keys = Keys::create(&dir, "test", "ab", 0, Some("correct horse")).unwrap();
        assert_eq!(keys.hot().err(), Some(KeyError::Locked));
        assert_eq!(keys.unlock("wrong", 60), Err(KeyError::WrongPassphrase));
        keys.unlock("correct horse", 60).unwrap();
        keys.refill(1).unwrap();
        keys.lock().unwrap();
        let pooled = keys.new_address("").unwrap();
        assert!(keys.is_mine(&pooled));
        assert_eq!(keys.new_address(""), Err(KeyError::PoolEmpty));
        // Unlocked, it signs with any of its keys.
        keys.unlock("correct horse", 60).unwrap();
        let kp = keys.pair(&pooled).unwrap();
        assert_eq!(Address::from_public_key(&kp.public).to_string(), pooled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unlock_ends_when_its_time_is_up() {
        let dir = temp_dir("timeout");
        let mut keys = Keys::create(&dir, "test", "ab", 0, Some("pw")).unwrap();
        keys.unlock("pw", 0).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(!keys.is_unlocked());
        assert_eq!(keys.unlocked_until(), Some(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_wallet_is_not_made_over_the_first() {
        let dir = temp_dir("over");
        Keys::create(&dir, "test", "ab", 0, None).unwrap();
        assert!(Keys::create(&dir, "test", "ab", 0, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
