//! The single admin: one argon2id hash from the config and in-memory session tokens.
//!
//! Only `SHA-256(token)` is kept, so a memory dump of the map cannot be replayed as a cookie.
//! A restart signs the admin out.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use sha2::{Digest, Sha256};

use crate::domain::crypto::{self, random_bytes};
use crate::error::Error;

/// A session ends after this long without a request.
pub const IDLE_SECS: i64 = 12 * 3600;
pub const COOKIE: &str = "__Host-bitvault-admin";

pub struct AdminAuth {
    phc: String,
    /// `SHA-256(token)` → time of the last request that used it.
    sessions: Mutex<HashMap<[u8; 32], i64>>,
}

impl fmt::Debug for AdminAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminAuth(..)")
    }
}

fn key(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

impl AdminAuth {
    /// Hashes the configured password; the caller drops the plaintext.
    pub async fn from_password(pw: &str) -> Result<Self, Error> {
        Ok(Self { phc: crypto::hash_password(pw).await?, sessions: Mutex::new(HashMap::new()) })
    }

    /// A poisoned lock only means another request panicked; the map is still usable.
    fn lock(&self) -> MutexGuard<'_, HashMap<[u8; 32], i64>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new 256-bit session token as hex, or `None` for a wrong password.
    pub async fn sign_in(&self, pw: &str, now: i64) -> Option<String> {
        if !crypto::verify_password(pw, &self.phc).await {
            return None;
        }
        let token = hex::encode(random_bytes::<32>());
        let mut sessions = self.lock();
        sessions.retain(|_, seen| now.saturating_sub(*seen) <= IDLE_SECS);
        sessions.insert(key(&token), now);
        Some(token)
    }

    /// Whether `token` is a live session; a valid one is kept alive for another [`IDLE_SECS`].
    pub fn is_valid(&self, token: &str, now: i64) -> bool {
        let k = key(token);
        let mut sessions = self.lock();
        match sessions.get_mut(&k) {
            Some(seen) if now.saturating_sub(*seen) <= IDLE_SECS => {
                *seen = now.max(*seen);
                true
            }
            Some(_) => {
                sessions.remove(&k);
                false
            }
            None => false,
        }
    }

    pub fn sign_out(&self, token: &str) {
        self.lock().remove(&key(token));
    }
}
