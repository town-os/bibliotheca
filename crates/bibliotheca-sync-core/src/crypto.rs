//! AES-GCM-256 credential encryption at rest.
//!
//! The sync subsystem loads a 32-byte master key from either
//! `BIBLIOTHECA_SECRET_KEY` (hex string) or a file path supplied on
//! the daemon CLI. Without that key, sync is disabled: credential
//! writes return [`crate::error::Error::SyncDisabled`] and the
//! supervisor refuses to spawn workers.
//!
//! Encryption is one AES-GCM call per credential row. The nonce is
//! random per write and stored alongside the ciphertext. AAD is the
//! credential row id so that copies of encrypted blobs cannot be
//! transplanted between rows.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;

use crate::credentials::CredentialBlob;
use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Opaque 32-byte master key. Never logged or displayed.
#[derive(Clone)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Parse a hex string like
    /// `"deadbeef…"` (exactly 64 hex characters, 32 bytes).
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes =
            hex::decode(s.trim()).map_err(|e| Error::Crypto(format!("invalid hex: {e}")))?;
        if bytes.len() != KEY_LEN {
            return Err(Error::Crypto(format!(
                "secret key must be {KEY_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn from_raw(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        let mut b = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut b);
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// One-per-daemon-instance cipher over a [`SecretKey`].
#[derive(Clone)]
pub struct CredentialCipher {
    cipher: Aes256Gcm,
}

impl CredentialCipher {
    pub fn new(key: &SecretKey) -> Self {
        let k = Key::<Aes256Gcm>::from_slice(key.as_bytes());
        Self {
            cipher: Aes256Gcm::new(k),
        }
    }

    pub fn encrypt(&self, aad: &[u8], blob: &CredentialBlob) -> Result<(Vec<u8>, Vec<u8>)> {
        let plaintext = serde_json::to_vec(blob)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad,
                },
            )
            .map_err(|e| Error::Crypto(format!("encrypt: {e}")))?;
        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    pub fn decrypt(&self, aad: &[u8], nonce: &[u8], ct: &[u8]) -> Result<CredentialBlob> {
        if nonce.len() != NONCE_LEN {
            return Err(Error::Crypto(format!("nonce must be {NONCE_LEN} bytes")));
        }
        let nonce = Nonce::from_slice(nonce);
        let plaintext = self
            .cipher
            .decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|e| Error::Crypto(format!("decrypt: {e}")))?;
        let blob = serde_json::from_slice(&plaintext)?;
        Ok(blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_basic() {
        let k = SecretKey::random();
        let c = CredentialCipher::new(&k);
        let blob = CredentialBlob::Basic {
            username: "alice".into(),
            password: "hunter2".into(),
        };
        let (nonce, ct) = c.encrypt(b"row-id", &blob).unwrap();
        let got = c.decrypt(b"row-id", &nonce, &ct).unwrap();
        match got {
            CredentialBlob::Basic { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "hunter2");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn aad_mismatch_fails_closed() {
        let k = SecretKey::random();
        let c = CredentialCipher::new(&k);
        let blob = CredentialBlob::Token {
            token: "t".into(),
            refresh_token: None,
            expires_at: None,
        };
        let (nonce, ct) = c.encrypt(b"row-A", &blob).unwrap();
        assert!(c.decrypt(b"row-B", &nonce, &ct).is_err());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let k1 = SecretKey::random();
        let k2 = SecretKey::random();
        let c1 = CredentialCipher::new(&k1);
        let c2 = CredentialCipher::new(&k2);
        let (nonce, ct) = c1
            .encrypt(
                b"id",
                &CredentialBlob::Basic {
                    username: "u".into(),
                    password: "p".into(),
                },
            )
            .unwrap();
        assert!(c2.decrypt(b"id", &nonce, &ct).is_err());
    }

    #[test]
    fn hex_round_trip() {
        let k = SecretKey::random();
        let hx = hex::encode(k.as_bytes());
        let k2 = SecretKey::from_hex(&hx).unwrap();
        assert_eq!(k.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn hex_rejects_bad_length() {
        assert!(SecretKey::from_hex("deadbeef").is_err());
    }
}
