// KeyFile lebt seit 2026-07-05 in helix-crypto (gemeinsam mit helix-node genutzt,
// siehe dort load_or_create_keypair) — hier nur Re-Export, damit bestehender
// CLI-Code (`crate::keyfile::KeyFile`) unverändert weiterfunktioniert.
pub use helix_crypto::KeyFile;
