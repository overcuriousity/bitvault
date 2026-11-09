//! Short-lived download grants for raw text, files and zips after an unlock.
//!
//! Token = base64url without padding of `nonce (24) ‖ XChaCha20-Poly1305(payload)` under the
//! in-memory grant key, where payload = `paste u64 ‖ expires_at i64 ‖ flag u8 (1 = data key
//! follows) ‖ dek (32)?`, all big-endian. A restart makes a new key, which voids every grant.

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

/// Issues a grant for `paste`, valid until `now + TTL_SECS`, optionally carrying its data key.
pub fn issue(key: &GrantKey, paste: PasteId, dek: Option<&Dek>, now: i64) -> String {
    let mut payload = Zeroizing::new(Vec::with_capacity(17 + KEY_LEN));
    payload.extend_from_slice(&paste.0.to_be_bytes());
    payload.extend_from_slice(&now.saturating_add(TTL_SECS).to_be_bytes());
    match dek {
        Some(dek) => {
            payload.push(1);
            payload.extend_from_slice(dek.as_bytes());
        }
        None => payload.push(0),
    }
    let nonce = random_bytes::<NONCE_LEN>();
    let sealed = match key.cipher().encrypt(&XNonce::from(nonce), Payload { msg: &payload, aad: AAD }) {
        Ok(sealed) => sealed,
        Err(e) => panic!("sealing a 49-byte grant cannot fail: {e:?}"),
    };
    let mut token = Vec::with_capacity(NONCE_LEN + sealed.len());
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&sealed);
    URL_SAFE_NO_PAD.encode(token)
}

/// Checks a grant for `paste` at `now` and returns the data key it carries, if any.
/// Anything malformed, tampered, expired or for another paste is `Forbidden`.
pub fn check(key: &GrantKey, token: &str, paste: PasteId, now: i64) -> Result<Option<Dek>, Error> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(Error::Forbidden);
    }
    let raw = URL_SAFE_NO_PAD.decode(token).map_err(|_| Error::Forbidden)?;
    let (nonce, sealed) = raw.split_first_chunk::<NONCE_LEN>().ok_or(Error::Forbidden)?;
    let payload = Zeroizing::new(
        key.cipher().decrypt(&XNonce::from(*nonce), Payload { msg: sealed, aad: AAD }).map_err(|_| Error::Forbidden)?,
    );
    let (id, rest) = payload.split_first_chunk::<8>().ok_or(Error::Forbidden)?;
    let (expires_at, rest) = rest.split_first_chunk::<8>().ok_or(Error::Forbidden)?;
    let dek = match rest.split_first() {
        Some((0, [])) => None,
        Some((1, bytes)) => Some(Dek::from_slice(bytes).ok_or(Error::Forbidden)?),
        _ => return Err(Error::Forbidden),
    };
    if u64::from_be_bytes(*id) != paste.0 || now > i64::from_be_bytes(*expires_at) {
        return Err(Error::Forbidden);
    }
    Ok(dek)
}
