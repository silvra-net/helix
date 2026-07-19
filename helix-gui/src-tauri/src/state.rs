use std::sync::Mutex;

use helix_crypto::KeyPair;

/// The unlocked wallet, held **only** in the Rust backend.
///
/// The `KeyPair` carries the secret seed. It is never serialized to the webview: every command
/// hands the frontend addresses, amounts and statuses — never key bytes. The passphrase the
/// user types to unlock is a transient input that decrypts the on-disk `KeyFile` in memory here
/// and is then dropped; it is not stored. This is the entire reason the GUI is a Tauri app and
/// not a page served by the node (where signing would have to happen in the browser).
pub struct UnlockedWallet {
    pub keypair: KeyPair,
    pub address: String,
}

#[derive(Default)]
pub struct WalletState {
    pub inner: Mutex<Option<UnlockedWallet>>,
}

impl WalletState {
    /// Address of the currently-unlocked wallet, if any. Cloned out under a short lock so
    /// callers never hold the guard across an `.await`.
    pub fn address(&self) -> Option<String> {
        self.inner.lock().unwrap().as_ref().map(|w| w.address.clone())
    }
}
