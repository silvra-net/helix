use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use helix_crypto::{kem_encapsulate, KemCiphertext, KemEncapsulationKey, KemKeyPair};
use serde::{Deserialize, Serialize};

/// Wire protocol for the ML-KEM handshake exchanged over the session gossipsub topic.
///
/// Both messages include `from` and `to` peer IDs so peers can filter out
/// messages not addressed to them — gossipsub is broadcast, so all connected
/// validators see all handshake messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMsg {
    /// Initiator → Responder: "I want a session; here is my ML-KEM-768 encapsulation key."
    Hello {
        from: String,
        to: String,
        ek: Vec<u8>,
    },
    /// Responder → Initiator: ML-KEM-768 ciphertext encapsulating the shared secret.
    KemCt {
        from: String,
        to: String,
        ct: Vec<u8>,
    },
}

impl HandshakeMsg {
    pub fn to_peer(&self) -> &str {
        match self {
            HandshakeMsg::Hello { to, .. } | HandshakeMsg::KemCt { to, .. } => to,
        }
    }

    pub fn from_peer(&self) -> &str {
        match self {
            HandshakeMsg::Hello { from, .. } | HandshakeMsg::KemCt { from, .. } => from,
        }
    }
}

/// State of one established P2P session.
struct Session {
    key: [u8; 32],
    /// Monotonically increasing nonce for outbound messages.
    nonce_counter: u64,
}

/// Per-peer ML-KEM-768 session manager. Each successful handshake
/// establishes a 32-byte session key derived from the ML-KEM shared secret
/// via BLAKE3's domain-separated key derivation. Messages are then
/// encrypted with AES-256-GCM.
///
/// The session layer runs on top of the existing libp2p Noise transport (X25519),
/// giving layered post-quantum forward secrecy: an adversary who breaks X25519
/// in the future still cannot decrypt messages — the ML-KEM session key
/// is quantum-safe.
pub struct SessionManager {
    /// Pending outbound handshakes: peer_id_str → ephemeral key pair we sent the ek for
    pending: HashMap<String, KemKeyPair>,
    /// Established sessions keyed by peer ID string
    sessions: HashMap<String, Session>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            pending: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    /// Begin handshake as initiator: generate an ephemeral KEM key pair and
    /// return the encapsulation key (to send in a `HandshakeMsg::Hello`).
    pub fn initiate(&mut self, peer: &str) -> KemEncapsulationKey {
        let kp = KemKeyPair::generate();
        let ek = kp.encapsulation_key.clone();
        self.pending.insert(peer.to_string(), kp);
        ek
    }

    /// Process a `Hello` from a peer (we are the responder): encapsulate a
    /// shared secret to their key and return the ciphertext to send back.
    /// Also establishes the session on our side immediately.
    pub fn respond(&mut self, peer: &str, their_ek_bytes: &[u8]) -> Option<KemCiphertext> {
        let ek = KemEncapsulationKey::from_bytes(their_ek_bytes.to_vec());
        let (ct, raw_ss) = kem_encapsulate(&ek).ok()?;
        let key = blake3::derive_key("helix p2p session v1", &raw_ss);
        self.sessions.insert(peer.to_string(), Session { key, nonce_counter: 0 });
        Some(ct)
    }

    /// Process a `KemCt` from the responder (we are the initiator): decapsulate
    /// to recover the shared secret and complete the session.
    /// Returns `true` if the session was successfully established.
    pub fn complete(&mut self, peer: &str, ct_bytes: &[u8]) -> bool {
        if let Some(kp) = self.pending.remove(peer) {
            let ct = KemCiphertext::from_bytes(ct_bytes.to_vec());
            if let Ok(raw_ss) = kp.decapsulate(&ct) {
                let key = blake3::derive_key("helix p2p session v1", &raw_ss);
                self.sessions.insert(peer.to_string(), Session { key, nonce_counter: 0 });
                return true;
            }
        }
        false
    }

    pub fn has_session(&self, peer: &str) -> bool {
        self.sessions.contains_key(peer)
    }

    /// Encrypt `plaintext` for `peer`. Returns `[nonce(8) || aes-gcm-ciphertext]`.
    /// Returns `None` if no session is established for this peer.
    pub fn encrypt(&mut self, peer: &str, plaintext: &[u8]) -> Option<Vec<u8>> {
        let session = self.sessions.get_mut(peer)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&session.key));
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&session.nonce_counter.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, plaintext).ok()?;
        session.nonce_counter += 1;
        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&nonce_bytes[..8]);
        out.extend_from_slice(&ct);
        Some(out)
    }

    /// Decrypt a `[nonce(8) || aes-gcm-ciphertext]` from `peer`.
    /// Returns `None` if no session, the frame is too short, or authentication fails.
    pub fn decrypt(&self, peer: &str, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 8 {
            return None;
        }
        let session = self.sessions.get(peer)?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&data[..8]);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&session.key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        cipher.decrypt(nonce, &data[8..]).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_establishes_matching_session_keys() {
        let mut alice = SessionManager::new();
        let mut bob = SessionManager::new();

        // Alice initiates → sends ek to Bob
        let ek = alice.initiate("bob");

        // Bob responds → sends ct back to Alice, Bob's session is established
        let ct = bob.respond("alice", ek.as_bytes()).expect("respond should succeed");
        assert!(bob.has_session("alice"));

        // Alice completes → Alice's session is established
        assert!(alice.complete("bob", ct.as_bytes()));
        assert!(alice.has_session("bob"));
    }

    #[test]
    fn session_encrypt_decrypt_roundtrip() {
        let mut alice = SessionManager::new();
        let mut bob = SessionManager::new();

        let ek = alice.initiate("bob");
        let ct = bob.respond("alice", ek.as_bytes()).unwrap();
        alice.complete("bob", ct.as_bytes());

        let plaintext = b"helix vote round 42";
        let ciphertext = alice.encrypt("bob", plaintext).expect("alice should have bob session");
        let recovered = bob.decrypt("alice", &ciphertext).expect("bob should have alice session");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypt_without_session_returns_none() {
        let mut mgr = SessionManager::new();
        assert!(mgr.encrypt("unknown_peer", b"msg").is_none());
    }

    #[test]
    fn decrypt_with_wrong_session_fails() {
        let mut alice = SessionManager::new();
        let mut bob = SessionManager::new();
        let mut charlie = SessionManager::new();

        // Alice-Bob session
        let ek = alice.initiate("bob");
        let ct = bob.respond("alice", ek.as_bytes()).unwrap();
        alice.complete("bob", ct.as_bytes());

        // Alice-Charlie session (different key)
        let ek2 = alice.initiate("charlie");
        let ct2 = charlie.respond("alice", ek2.as_bytes()).unwrap();
        alice.complete("charlie", ct2.as_bytes());

        let ciphertext = alice.encrypt("bob", b"secret").unwrap();
        // Charlie cannot decrypt Alice's message intended for Bob
        assert!(charlie.decrypt("alice", &ciphertext).is_none());
    }
}
