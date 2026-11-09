//! The `BVC` container (versioned, chunked AEAD), envelope keys, password hashes and verifiers.
//!
//! Every integer in the format is big-endian. The browser code (`assets/js/crypto.js`) writes
//! and reads exactly this layout for alg 2.
//!
//! | Field        | Bytes    | Value                                                                 |
//! |--------------|----------|-----------------------------------------------------------------------|
//! | magic        | 3        | `"BVC"`                                                               |
//! | version      | 1        | `0x01`                                                                |
//! | alg          | 1        | 1 = XChaCha20-Poly1305 STREAM, 2 = AES-256-GCM chunked                |
//! | kdf          | 1        | 0 = none (key supplied), 1 = argon2id, 2 = PBKDF2-HMAC-SHA256         |
//! | kdf params   | 9, 4, 0  | argon2id: `m_kib` u32, `t` u32, `p` u8 · PBKDF2: iterations u32 · none |
//! | salt         | 16       | absent for kdf 0                                                      |
//! | nonce prefix | 19 or 7  | alg 1: 19 · alg 2: 7; random for every container                      |
//! | chunks       | …        | 65 536 plaintext bytes each (the last 0–65 536), each ‖ 16-byte tag   |
//!
//! Chunk `i` is sealed with nonce `prefix ‖ i (u32) ‖ last (u8: 1 on the final chunk, else 0)` and
//! the complete header bytes as associated data, so header edits, reordering, truncation and
//! extension all fail authentication. Empty plaintext is one empty final chunk. A plaintext that
//! is an exact multiple of 65 536 bytes ends with a full final chunk, never an extra empty one.
//!
//! Every password is normalised to Unicode NFC before any derivation or hash, here and in the browser.
//!
//! alg 2 keys: PBKDF2-HMAC-SHA256(password, salt, iterations) → 64 bytes; the first 32 are the
//! AES-256-GCM key and the last 32 the verifier HMAC key (WebCrypto `deriveBits(512)`).

use std::fmt;
use std::sync::{Arc, LazyLock};

use argon2::password_hash::phc::PasswordHash;
use argon2::{ARGON2ID_IDENT, Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use chacha20poly1305::aead::{AeadCore, AeadInOut, Nonce};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Error;

pub const MAGIC: [u8; 3] = *b"BVC";
pub const VERSION: u8 = 0x01;
pub const ALG_XCHACHA20_POLY1305: u8 = 1;
pub const ALG_AES256_GCM: u8 = 2;
pub const KDF_NONE: u8 = 0;
pub const KDF_ARGON2ID: u8 = 1;
pub const KDF_PBKDF2_SHA256: u8 = 2;
/// Plaintext bytes per chunk.
pub const CHUNK_LEN: usize = 65_536;
pub const TAG_LEN: usize = 16;
pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
/// The minimum PBKDF2 cost the server accepts for a browser (Secret) container.
pub const PBKDF2_ITERATIONS: u32 = 600_000;
/// The maximum, so a crafted container cannot make every reader spin for minutes.
pub const PBKDF2_MAX_ITERATIONS: u32 = 6_000_000;
/// The message the browser MACs with its verifier key to prove it knows a Secret paste's password.
pub const VERIFIER_CONTEXT: &[u8] = b"bitvault-delete";

const FIXED_LEN: usize = 6;
const CT_CHUNK_LEN: usize = CHUNK_LEN + TAG_LEN;
const XCHACHA_PREFIX_LEN: usize = 19;
const AES_GCM_PREFIX_LEN: usize = 7;
// Upper bounds on argon2id costs read from a header or PHC string, so a corrupt row cannot
// demand gigabytes or minutes.
const MAX_ARGON_M_KIB: u32 = 262_144;
const MAX_ARGON_T: u32 = 10;

/// Each argon2 derivation holds up to 64 MiB on the blocking pool, so only a few may run at once
/// however many requests arrive; the rest wait for a permit.
static ARGON_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(argon_slot_count())));

fn argon_slot_count() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from).clamp(1, 4)
}

#[cfg(feature = "test-hooks")]
static ARGON_IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "test-hooks")]
static ARGON_PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many argon2 derivations may run at once. Test-only.
#[cfg(feature = "test-hooks")]
pub fn argon_permits() -> usize {
    argon_slot_count()
}

/// The most argon2 derivations seen running at the same moment in this process. Test-only.
#[cfg(feature = "test-hooks")]
pub fn argon_peak_in_flight() -> usize {
    ARGON_PEAK.load(std::sync::atomic::Ordering::SeqCst)
}

/// Runs argon2 work on the blocking pool once a permit is free. The permit moves into the
/// closure, so it is released only when the derivation finishes, even if the caller gave up.
async fn run_argon<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T, Error> {
    let permit = Arc::clone(&ARGON_SLOTS).acquire_owned().await.map_err(Error::internal)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        #[cfg(feature = "test-hooks")]
        {
            use std::sync::atomic::Ordering::SeqCst;
            let now = ARGON_IN_FLIGHT.fetch_add(1, SeqCst) + 1;
            ARGON_PEAK.fetch_max(now, SeqCst);
            let out = work();
            ARGON_IN_FLIGHT.fetch_sub(1, SeqCst);
            out
        }
        #[cfg(not(feature = "test-hooks"))]
        work()
    })
    .await
    .map_err(Error::internal)
}

/// Bytes from the operating system's random number generator.
///
/// # Panics
/// If the operating system cannot supply randomness; no key may be made without it.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    if let Err(e) = SysRng.try_fill_bytes(&mut out) {
        panic!("the operating system random number generator failed: {e}");
    }
    out
}

/// A password's bytes in Unicode NFC, so the same password typed with composed or decomposed
/// characters (é as one code point or as e plus an accent) derives the same key. The browser
/// normalises the same way before PBKDF2.
pub fn password_bytes(password: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(password.nfc().collect::<String>().into_bytes())
}

/// A 32-byte data encryption key. Compared in constant time; never printed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; KEY_LEN]);

impl Dek {
    pub fn random() -> Self {
        Self(random_bytes())
    }

    /// The caller is responsible for zeroizing its own copy of `bytes`.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut dek = Self([0; KEY_LEN]);
        (bytes.len() == KEY_LEN).then(|| {
            dek.0.copy_from_slice(bytes);
            dek
        })
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek(..)")
    }
}

impl PartialEq for Dek {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Dek {}

/// argon2id costs: memory in KiB, passes and lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u8,
}

impl KdfParams {
    /// RFC 9106's second recommended option.
    pub const DEFAULT: Self = Self { m_kib: 65_536, t: 3, p: 1 };

    fn is_supported(self) -> bool {
        self.p >= 1
            && self.m_kib >= 8 * u32::from(self.p)
            && self.m_kib <= MAX_ARGON_M_KIB
            && (1..=MAX_ARGON_T).contains(&self.t)
    }
}

/// The parsed header of a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub alg: u8,
    pub kdf: u8,
    /// PBKDF2 iterations (kdf 2).
    pub iterations: Option<u32>,
    /// argon2id costs (kdf 1).
    pub argon: Option<KdfParams>,
}

/// A container split into its parts; `bytes` is the whole header, the associated data.
struct Parsed<'a> {
    header: Header,
    bytes: &'a [u8],
    salt: Option<[u8; SALT_LEN]>,
    prefix: &'a [u8],
    body: &'a [u8],
}

enum KdfSpec<'a> {
    None,
    Argon2id(KdfParams, &'a [u8; SALT_LEN]),
    #[cfg_attr(not(feature = "test-hooks"), allow(dead_code))]
    Pbkdf2(u32, &'a [u8; SALT_LEN]),
}

/// A chunk failed its tag; what that means depends on where the key came from.
struct AuthFailed;

fn build_header(alg: u8, kdf: KdfSpec<'_>) -> Vec<u8> {
    let mut h = Vec::with_capacity(FIXED_LEN + 9 + SALT_LEN + XCHACHA_PREFIX_LEN);
    h.extend_from_slice(&MAGIC);
    h.push(VERSION);
    h.push(alg);
    match kdf {
        KdfSpec::None => h.push(KDF_NONE),
        KdfSpec::Argon2id(params, salt) => {
            h.push(KDF_ARGON2ID);
            h.extend_from_slice(&params.m_kib.to_be_bytes());
            h.extend_from_slice(&params.t.to_be_bytes());
            h.push(params.p);
            h.extend_from_slice(salt);
        }
        KdfSpec::Pbkdf2(iterations, salt) => {
            h.push(KDF_PBKDF2_SHA256);
            h.extend_from_slice(&iterations.to_be_bytes());
            h.extend_from_slice(salt);
        }
    }
    if alg == ALG_AES256_GCM {
        h.extend_from_slice(&random_bytes::<AES_GCM_PREFIX_LEN>());
    } else {
        h.extend_from_slice(&random_bytes::<XCHACHA_PREFIX_LEN>());
    }
    h
}

/// The full header length implied by the first six bytes.
fn header_len(fixed: &[u8; FIXED_LEN]) -> Result<usize, Error> {
    let [m0, m1, m2, version, alg, kdf] = *fixed;
    if [m0, m1, m2] != MAGIC || version != VERSION {
        return Err(Error::UnsupportedFormat);
    }
    let prefix = match alg {
        ALG_XCHACHA20_POLY1305 => XCHACHA_PREFIX_LEN,
        ALG_AES256_GCM => AES_GCM_PREFIX_LEN,
        _ => return Err(Error::UnsupportedFormat),
    };
    let params = match kdf {
        KDF_NONE => 0,
        KDF_ARGON2ID => 9 + SALT_LEN,
        KDF_PBKDF2_SHA256 => 4 + SALT_LEN,
        _ => return Err(Error::UnsupportedFormat),
    };
    Ok(FIXED_LEN + params + prefix)
}

fn take<const N: usize>(cur: &mut &[u8]) -> Result<[u8; N], Error> {
    let (head, rest) = cur.split_first_chunk::<N>().ok_or(Error::UnsupportedFormat)?;
    *cur = rest;
    Ok(*head)
}

fn parse(container: &[u8]) -> Result<Parsed<'_>, Error> {
    let fixed = container.first_chunk::<FIXED_LEN>().ok_or(Error::UnsupportedFormat)?;
    let len = header_len(fixed)?;
    let (bytes, body) = container.split_at_checked(len).ok_or(Error::UnsupportedFormat)?;
    let [.., alg, kdf] = *fixed;
    let mut cur = bytes.get(FIXED_LEN..).ok_or(Error::UnsupportedFormat)?;
    let (argon, iterations) = match kdf {
        KDF_ARGON2ID => {
            let params = KdfParams {
                m_kib: u32::from_be_bytes(take(&mut cur)?),
                t: u32::from_be_bytes(take(&mut cur)?),
                p: u8::from_be_bytes(take(&mut cur)?),
            };
            if !params.is_supported() {
                return Err(Error::UnsupportedFormat);
            }
            (Some(params), None)
        }
        KDF_PBKDF2_SHA256 => {
            let iterations = u32::from_be_bytes(take(&mut cur)?);
            if iterations == 0 {
                return Err(Error::UnsupportedFormat);
            }
            (None, Some(iterations))
        }
        _ => (None, None),
    };
    let salt = if kdf == KDF_NONE { None } else { Some(take::<SALT_LEN>(&mut cur)?) };
    Ok(Parsed { header: Header { version: VERSION, alg, kdf, iterations, argon }, bytes, salt, prefix: cur, body })
}

/// Reads a container's header without decrypting anything.
pub fn parse_header(container: &[u8]) -> Result<Header, Error> {
    parse(container).map(|p| p.header)
}

fn chunk_nonce<A: AeadCore>(prefix: &[u8], counter: u32, last: bool) -> Option<Nonce<A>> {
    let mut nonce = Vec::with_capacity(prefix.len() + 5);
    nonce.extend_from_slice(prefix);
    nonce.extend_from_slice(&counter.to_be_bytes());
    nonce.push(u8::from(last));
    Nonce::<A>::try_from(nonce.as_slice()).ok()
}

/// Encrypts `buf` in place and appends its tag.
fn seal_chunk<A: AeadInOut>(
    cipher: &A,
    header: &[u8],
    prefix: &[u8],
    counter: u32,
    last: bool,
    buf: &mut Vec<u8>,
) -> Result<(), Error> {
    let nonce = chunk_nonce::<A>(prefix, counter, last).ok_or_else(|| Error::internal("bad nonce prefix length"))?;
    cipher.encrypt_in_place(&nonce, header, buf).map_err(|_| Error::internal("chunk encryption failed"))
}

/// Verifies and decrypts `buf` (chunk ‖ tag) in place, leaving the plaintext.
fn open_chunk<A: AeadInOut>(
    cipher: &A,
    header: &[u8],
    prefix: &[u8],
    counter: u32,
    last: bool,
    buf: &mut Vec<u8>,
) -> Result<(), AuthFailed> {
    let nonce = chunk_nonce::<A>(prefix, counter, last).ok_or(AuthFailed)?;
    cipher.decrypt_in_place(&nonce, header, buf).map_err(|_| AuthFailed)
}

fn seal_all<A: AeadInOut>(cipher: &A, header: &[u8], prefix_len: usize, plain: &[u8]) -> Result<Vec<u8>, Error> {
    let prefix = header.get(header.len().saturating_sub(prefix_len)..).unwrap_or_default();
    let count = plain.len().div_ceil(CHUNK_LEN).max(1);
    let mut out = Vec::with_capacity(header.len() + plain.len() + count * TAG_LEN);
    out.extend_from_slice(header);
    let mut buf = Zeroizing::new(Vec::with_capacity(CT_CHUNK_LEN));
    for (i, chunk) in plain.chunks(CHUNK_LEN).chain(plain.is_empty().then_some(&[][..])).enumerate() {
        let counter = u32::try_from(i).map_err(|_| Error::TooLarge)?;
        buf.clear();
        buf.extend_from_slice(chunk);
        seal_chunk(cipher, header, prefix, counter, i + 1 == count, &mut buf)?;
        out.extend_from_slice(&buf);
    }
    Ok(out)
}

fn open_body<A: AeadInOut>(cipher: &A, p: &Parsed<'_>) -> Result<Vec<u8>, AuthFailed> {
    let mut out = Zeroizing::new(Vec::with_capacity(p.body.len()));
    let mut buf = Zeroizing::new(Vec::with_capacity(CT_CHUNK_LEN));
    let mut rest = p.body;
    let mut counter = 0u32;
    loop {
        // Only the final chunk may be shorter than a full one, so length alone says which is last.
        let last = rest.len() <= CT_CHUNK_LEN;
        let (chunk, tail) = rest.split_at(if last { rest.len() } else { CT_CHUNK_LEN });
        buf.clear();
        buf.extend_from_slice(chunk);
        open_chunk(cipher, p.bytes, p.prefix, counter, last, &mut buf)?;
        out.extend_from_slice(&buf);
        if last {
            break;
        }
        rest = tail;
        counter = counter.checked_add(1).ok_or(AuthFailed)?;
    }
    Ok(std::mem::take(&mut *out))
}

fn xchacha(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

fn stored_auth_failure() -> Error {
    Error::internal("a stored container failed authentication")
}

fn require_key_container(p: &Parsed<'_>) -> Result<(), Error> {
    if p.header.alg == ALG_XCHACHA20_POLY1305 && p.header.kdf == KDF_NONE {
        Ok(())
    } else {
        Err(Error::UnsupportedFormat)
    }
}

/// Seals `plain` into an alg 1, kdf 0 container under `key`.
///
/// # Panics
/// Never for in-memory input: a chunk counter overflow needs 256 TiB of plaintext.
pub fn seal(key: &Dek, plain: &[u8]) -> Vec<u8> {
    let header = build_header(ALG_XCHACHA20_POLY1305, KdfSpec::None);
    match seal_all(&xchacha(&key.0), &header, XCHACHA_PREFIX_LEN, plain) {
        Ok(sealed) => sealed,
        Err(e) => panic!("sealing an in-memory buffer cannot fail: {e:?}"),
    }
}

/// Opens an alg 1, kdf 0 container. A failed tag means the stored bytes were altered.
pub fn open(key: &Dek, container: &[u8]) -> Result<Vec<u8>, Error> {
    let p = parse(container)?;
    require_key_container(&p)?;
    if p.body.is_empty() {
        return Err(Error::UnsupportedFormat);
    }
    open_body(&xchacha(&key.0), &p).map_err(|AuthFailed| stored_auth_failure())
}

/// Reads until `buf` holds `target` bytes or the reader ends.
async fn fill<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>, target: usize) -> std::io::Result<()> {
    let mut filled = buf.len();
    buf.resize(target, 0);
    while filled < target {
        match r.read(buf.get_mut(filled..).unwrap_or_default()).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                buf.truncate(filled);
                return Err(e);
            }
        }
    }
    buf.truncate(filled);
    Ok(())
}

/// Seals everything `r` yields into `w` as one alg 1, kdf 0 container, a chunk at a time.
/// Returns the number of plaintext bytes read.
pub async fn seal_stream<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    key: &Dek,
    mut r: R,
    mut w: W,
) -> Result<u64, Error> {
    let cipher = xchacha(&key.0);
    let header = build_header(ALG_XCHACHA20_POLY1305, KdfSpec::None);
    let prefix = header.get(header.len() - XCHACHA_PREFIX_LEN..).unwrap_or_default();
    w.write_all(&header).await?;
    let mut buf = Zeroizing::new(Vec::with_capacity(CT_CHUNK_LEN + 1));
    let mut total = 0u64;
    let mut counter = 0u32;
    loop {
        // One byte of look-ahead tells whether this chunk is the last.
        fill(&mut r, &mut buf, CHUNK_LEN + 1).await?;
        let carry = if buf.len() > CHUNK_LEN { buf.pop() } else { None };
        total += buf.len() as u64;
        seal_chunk(&cipher, &header, prefix, counter, carry.is_none(), &mut buf)?;
        w.write_all(&buf).await?;
        buf.clear();
        let Some(byte) = carry else { break };
        buf.push(byte);
        counter = counter.checked_add(1).ok_or(Error::TooLarge)?;
    }
    w.flush().await?;
    Ok(total)
}

async fn read_header<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<(), Error> {
    match r.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(Error::UnsupportedFormat),
        Err(e) => Err(e.into()),
    }
}

/// Opens an alg 1, kdf 0 container from `r` into `w`, a chunk at a time, and returns the number
/// of plaintext bytes written. Chunks before a failing one have already been written, so the
/// caller must treat an error as "discard everything written".
pub async fn open_stream<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    key: &Dek,
    mut r: R,
    mut w: W,
) -> Result<u64, Error> {
    let mut fixed = [0u8; FIXED_LEN];
    read_header(&mut r, &mut fixed).await?;
    let mut header = vec![0u8; header_len(&fixed)?];
    let (head, rest) = header.split_at_mut(FIXED_LEN);
    head.copy_from_slice(&fixed);
    read_header(&mut r, rest).await?;
    let p = parse(&header)?;
    require_key_container(&p)?;

    let cipher = xchacha(&key.0);
    let mut buf = Zeroizing::new(Vec::with_capacity(CT_CHUNK_LEN + 1));
    let mut total = 0u64;
    let mut counter = 0u32;
    loop {
        fill(&mut r, &mut buf, CT_CHUNK_LEN + 1).await?;
        if counter == 0 && buf.is_empty() {
            return Err(Error::UnsupportedFormat);
        }
        let carry = if buf.len() > CT_CHUNK_LEN { buf.pop() } else { None };
        open_chunk(&cipher, p.bytes, p.prefix, counter, carry.is_none(), &mut buf)
            .map_err(|AuthFailed| stored_auth_failure())?;
        total += buf.len() as u64;
        w.write_all(&buf).await?;
        buf.clear();
        let Some(byte) = carry else { break };
        buf.push(byte);
        counter = counter.checked_add(1).ok_or_else(stored_auth_failure)?;
    }
    w.flush().await?;
    Ok(total)
}

fn argon2id(params: KdfParams) -> Result<Argon2<'static>, Error> {
    let params = Params::new(params.m_kib, params.t, u32::from(params.p), Some(KEY_LEN))
        .map_err(|_| Error::UnsupportedFormat)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// argon2id(password, salt) → 32-byte key, on the blocking pool.
async fn derive_argon2id(
    password: &str,
    salt: [u8; SALT_LEN],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let argon = argon2id(params)?;
    let password = password_bytes(password);
    run_argon(move || {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        argon.hash_password_into(&password, &salt, key.as_mut_slice()).map_err(Error::internal)?;
        Ok(key)
    })
    .await?
}

/// Encrypts `dek` under a key derived from `password` (an alg 1, kdf 1 container).
pub async fn wrap_dek(password: &str, dek: &Dek, params: KdfParams) -> Result<Vec<u8>, Error> {
    if !params.is_supported() {
        return Err(Error::internal("argon2id parameters are outside the supported range"));
    }
    let salt = random_bytes::<SALT_LEN>();
    let key = derive_argon2id(password, salt, params).await?;
    let header = build_header(ALG_XCHACHA20_POLY1305, KdfSpec::Argon2id(params, &salt));
    seal_all(&xchacha(&key), &header, XCHACHA_PREFIX_LEN, &dek.0)
}

/// Recovers the data key; a failed tag means the password is wrong.
pub async fn unwrap_dek(password: &str, wrapped: &[u8]) -> Result<Dek, Error> {
    let p = parse(wrapped)?;
    let (Some(params), Some(salt)) = (p.header.argon, p.salt) else {
        return Err(Error::UnsupportedFormat);
    };
    if p.header.alg != ALG_XCHACHA20_POLY1305 || p.body.len() != KEY_LEN + TAG_LEN {
        return Err(Error::UnsupportedFormat);
    }
    let key = derive_argon2id(password, salt, params).await?;
    let plain = Zeroizing::new(open_body(&xchacha(&key), &p).map_err(|AuthFailed| Error::WrongPassword)?);
    Dek::from_slice(&plain).ok_or(Error::UnsupportedFormat)
}

/// An argon2id PHC string at [`KdfParams::DEFAULT`] with a random 16-byte salt.
pub async fn hash_password(password: &str) -> Result<String, Error> {
    let argon = argon2id(KdfParams::DEFAULT)?;
    let password = password_bytes(password);
    let salt = random_bytes::<SALT_LEN>();
    run_argon(move || argon.hash_password_with_salt(&password, &salt).map(|h| h.to_string()).map_err(Error::internal))
        .await?
}

/// Whether `password` matches an argon2id PHC string. Anything unparseable, or with costs above
/// the header caps, is a mismatch and is refused before any derivation.
pub async fn verify_password(password: &str, phc: &str) -> bool {
    let Ok(hash) = PasswordHash::new(phc) else { return false };
    let Ok(params) = Params::try_from(&hash) else { return false };
    let within_caps = u8::try_from(params.p_cost())
        .is_ok_and(|p| KdfParams { m_kib: params.m_cost(), t: params.t_cost(), p }.is_supported());
    if hash.algorithm != ARGON2ID_IDENT || !within_caps {
        return false;
    }
    let password = password_bytes(password);
    run_argon(move || Argon2::default().verify_password(&password, &hash).is_ok()).await.unwrap_or(false)
}

/// What the server stores for a Secret paste's delete verifier.
pub fn verifier_hash(v: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(v).into()
}

/// Constant-time check of a posted verifier against the stored hash.
pub fn verifier_matches(stored_hash: &[u8], given: &[u8; 32]) -> bool {
    stored_hash.ct_eq(&verifier_hash(given)).into()
}

fn browser_iterations_allowed(iterations: Option<u32>) -> bool {
    iterations.is_some_and(|i| (PBKDF2_ITERATIONS..=PBKDF2_MAX_ITERATIONS).contains(&i))
}

/// The longest browser (alg 2, kdf 2) container for `plain_len` bytes of plaintext: header,
/// plaintext and one tag per 64 KiB chunk, plus one for a possible empty final chunk.
pub const fn browser_container_max_len(plain_len: u64) -> u64 {
    let header = (FIXED_LEN + 4 + SALT_LEN + AES_GCM_PREFIX_LEN) as u64;
    let tags = (plain_len.div_ceil(CHUNK_LEN as u64) + 1).saturating_mul(TAG_LEN as u64);
    header.saturating_add(plain_len).saturating_add(tags)
}

/// Accepts only full-strength browser containers: alg 2, kdf 2, 600 000 to 6 000 000 iterations,
/// a non-empty body.
pub fn check_browser_container(container: &[u8]) -> Result<(), Error> {
    let p = parse(container)?;
    let strong = p.header.alg == ALG_AES256_GCM
        && p.header.kdf == KDF_PBKDF2_SHA256
        && browser_iterations_allowed(p.header.iterations)
        && p.body.len() >= TAG_LEN;
    if strong { Ok(()) } else { Err(Error::UnsupportedFormat) }
}

#[cfg(feature = "test-hooks")]
fn pbkdf2_keys(password: &str, salt: &[u8], iterations: u32) -> Zeroizing<[u8; 64]> {
    let mut okm = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<Sha256>(&password_bytes(password), salt, iterations, okm.as_mut_slice());
    okm
}

#[cfg(feature = "test-hooks")]
fn aes_gcm(okm: &[u8; 64]) -> Result<aes_gcm::Aes256Gcm, Error> {
    aes_gcm::Aes256Gcm::new_from_slice(okm.get(..KEY_LEN).unwrap_or_default()).map_err(Error::internal)
}

/// Opens a browser (alg 2) container the way the browser does. Test-only.
#[cfg(feature = "test-hooks")]
pub fn open_alg2(password: &str, container: &[u8]) -> Result<Vec<u8>, Error> {
    let p = parse(container)?;
    let (Some(iterations), Some(salt)) = (p.header.iterations, p.salt) else {
        return Err(Error::UnsupportedFormat);
    };
    // Only the upper cap applies here: tests decode deliberately weak containers too.
    if p.header.alg != ALG_AES256_GCM || p.body.is_empty() || iterations > PBKDF2_MAX_ITERATIONS {
        return Err(Error::UnsupportedFormat);
    }
    let okm = pbkdf2_keys(password, &salt, iterations);
    open_body(&aes_gcm(&okm)?, &p).map_err(|AuthFailed| Error::WrongPassword)
}

/// The delete verifier the browser sends: HMAC-SHA256(verifier key, "bitvault-delete"). Test-only.
#[cfg(feature = "test-hooks")]
pub fn browser_verifier(password: &str, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit as _, Mac};
    let okm = pbkdf2_keys(password, salt, PBKDF2_ITERATIONS);
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(okm.get(KEY_LEN..).unwrap_or_default()) else {
        unreachable!("HMAC accepts keys of any length");
    };
    mac.update(VERIFIER_CONTEXT);
    mac.finalize().into_bytes().into()
}

/// Builds a browser (alg 2) container at any iteration count, for tests of the server's checks.
#[cfg(feature = "test-hooks")]
pub fn seal_alg2_for_tests(password: &str, salt: &[u8; SALT_LEN], iterations: u32, plain: &[u8]) -> Vec<u8> {
    let okm = pbkdf2_keys(password, salt, iterations);
    let header = build_header(ALG_AES256_GCM, KdfSpec::Pbkdf2(iterations, salt));
    match aes_gcm(&okm).and_then(|cipher| seal_all(&cipher, &header, AES_GCM_PREFIX_LEN, plain)) {
        Ok(sealed) => sealed,
        Err(e) => panic!("sealing an in-memory buffer cannot fail: {e:?}"),
    }
}
