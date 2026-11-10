//! Short-lived download grants for raw text, files and zips after an unlock, and creator tokens
//! for the page a web create lands on.
//!
//! Token = base64url without padding of `nonce (24) ‖ XChaCha20-Poly1305(payload)` under the
//! in-memory grant key. A grant's payload is `paste u64 ‖ expires_at i64 ‖ flag u8 (1 = data key
//! follows) ‖ dek (32)?`; a creator token's is `paste u64 ‖ expires_at i64`; all big-endian. Each
//! kind has its own AAD, so neither passes as the other. A restart makes a new key, which voids
//! every token.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::domain::crypto::{Dek, KEY_LEN, random_bytes};
use crate::domain::words::PasteId;
use crate::error::Error;

/// How long a grant stays valid.
pub const TTL_SECS: i64 = 600;

const NONCE_LEN: usize = 24;
// Binds the ciphertext to its purpose, so nothing else sealed under this key can pass as a grant.
const AAD: &[u8] = b"bitvault-grant-v1";
const CREATOR_AAD: &[u8] = b"bitvault-creator-v1";
// The longest real token (nonce, a payload with a key, tag) is 119 characters.
const MAX_TOKEN_LEN: usize = 128;

/// The 32-byte key grants are sealed with; held in memory only and never printed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GrantKey([u8; KEY_LEN]);

impl GrantKey {
    pub fn random() -> Self {
        Self(random_bytes())
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&self.0).into())
    }
}

impl fmt::Debug for GrantKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GrantKey(..)")
    }
}

fn seal(key: &GrantKey, aad: &[u8], payload: &[u8]) -> String {
    let nonce = random_bytes::<NONCE_LEN>();
    let sealed = match key.cipher().encrypt(&XNonce::from(nonce), Payload { msg: payload, aad }) {
        Ok(sealed) => sealed,
        Err(e) => panic!("sealing a token of at most 49 bytes cannot fail: {e:?}"),
    };
    let mut token = Vec::with_capacity(NONCE_LEN + sealed.len());
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&sealed);
    URL_SAFE_NO_PAD.encode(token)
}

/// The payload of a token sealed under `aad`, if it is well-formed and authentic.
fn open(key: &GrantKey, aad: &[u8], token: &str) -> Option<Zeroizing<Vec<u8>>> {
    if token.len() > MAX_TOKEN_LEN {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(token).ok()?;
    let (nonce, sealed) = raw.split_first_chunk::<NONCE_LEN>()?;
    key.cipher().decrypt(&XNonce::from(*nonce), Payload { msg: sealed, aad }).ok().map(Zeroizing::new)
}

/// Splits `paste ‖ expires_at` off a payload; `None` unless it names `paste` and is still valid at `now`.
fn live_for(payload: &[u8], paste: PasteId, now: i64) -> Option<&[u8]> {
    let (id, rest) = payload.split_first_chunk::<8>()?;
    let (expires_at, rest) = rest.split_first_chunk::<8>()?;
    (u64::from_be_bytes(*id) == paste.0 && now <= i64::from_be_bytes(*expires_at)).then_some(rest)
}

fn head(paste: PasteId, now: i64) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(17 + KEY_LEN));
    payload.extend_from_slice(&paste.0.to_be_bytes());
    payload.extend_from_slice(&now.saturating_add(TTL_SECS).to_be_bytes());
    payload
}

/// Issues a grant for `paste`, valid until `now + TTL_SECS`, optionally carrying its data key.
pub fn issue(key: &GrantKey, paste: PasteId, dek: Option<&Dek>, now: i64) -> String {
    let mut payload = head(paste, now);
    match dek {
        Some(dek) => {
            payload.push(1);
            payload.extend_from_slice(dek.as_bytes());
        }
        None => payload.push(0),
    }
    seal(key, AAD, &payload)
}

/// Checks a grant for `paste` at `now` and returns the data key it carries, if any.
/// Anything malformed, tampered, expired, voided by a restart or for another paste is
/// [`Error::GrantExpired`].
pub fn check(key: &GrantKey, token: &str, paste: PasteId, now: i64) -> Result<Option<Dek>, Error> {
    let payload = open(key, AAD, token).ok_or(Error::GrantExpired)?;
    match live_for(&payload, paste, now).and_then(<[u8]>::split_first) {
        Some((0, [])) => Ok(None),
        Some((1, bytes)) => Ok(Some(Dek::from_slice(bytes).ok_or(Error::GrantExpired)?)),
        _ => Err(Error::GrantExpired),
    }
}

/// Issues a creator token for `paste`, valid until `now + TTL_SECS`: it shows the paste once to
/// whoever just created it, without counting a read.
pub fn issue_creator(key: &GrantKey, paste: PasteId, now: i64) -> String {
    seal(key, CREATOR_AAD, &head(paste, now))
}

/// Whether `token` is a creator token for `paste` that is still valid at `now`.
pub fn check_creator(key: &GrantKey, token: &str, paste: PasteId, now: i64) -> bool {
    open(key, CREATOR_AAD, token).is_some_and(|payload| live_for(&payload, paste, now).is_some_and(<[u8]>::is_empty))
}
