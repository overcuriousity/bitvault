#![allow(clippy::unwrap_used, clippy::expect_used)]

use bitvault::domain::crypto::{
    self, CHUNK_LEN, Dek, KdfParams, PBKDF2_ITERATIONS, TAG_LEN, check_browser_container, open, open_alg2,
    parse_header, seal, seal_alg2_for_tests,
};
use bitvault::error::Error;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const FAST: KdfParams = KdfParams { m_kib: 8, t: 1, p: 1 };
/// Byte length of a key-only (kdf 0) alg 1 header: magic, version, alg, kdf, 19-byte nonce prefix.
const KEY_HEADER_LEN: usize = 25;
const CT_CHUNK: usize = CHUNK_LEN + TAG_LEN;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn sealed_text_opens_with_the_same_key() {
    let key = Dek::random();
    let plain = b"the quick brown fox".to_vec();
    let sealed = seal(&key, &plain);
    assert_ne!(&sealed[KEY_HEADER_LEN..], &plain[..]);
    assert_eq!(open(&key, &sealed).unwrap(), plain);
}

#[test]
fn a_different_key_does_not_open_a_container() {
    let sealed = seal(&Dek::random(), b"hello");
    assert!(open(&Dek::random(), &sealed).is_err());
}

#[test]
fn empty_plaintext_round_trips() {
    let key = Dek::random();
    let sealed = seal(&key, b"");
    assert_eq!(sealed.len(), KEY_HEADER_LEN + TAG_LEN);
    assert_eq!(open(&key, &sealed).unwrap(), b"");
}

#[test]
fn exact_multiples_of_the_chunk_size_round_trip_without_an_extra_chunk() {
    let key = Dek::random();
    for chunks in 1..=3 {
        let plain = pattern(chunks * CHUNK_LEN);
        let sealed = seal(&key, &plain);
        assert_eq!(sealed.len(), KEY_HEADER_LEN + chunks * CT_CHUNK);
        assert_eq!(open(&key, &sealed).unwrap(), plain);
    }
    let plain = pattern(CHUNK_LEN + 1);
    let sealed = seal(&key, &plain);
    assert_eq!(sealed.len(), KEY_HEADER_LEN + CT_CHUNK + 1 + TAG_LEN);
    assert_eq!(open(&key, &sealed).unwrap(), plain);
}

#[test]
fn every_container_gets_a_fresh_nonce_prefix() {
    let key = Dek::random();
    let a = seal(&key, b"same");
    let b = seal(&key, b"same");
    assert_ne!(a[6..KEY_HEADER_LEN], b[6..KEY_HEADER_LEN]);
    assert_ne!(a, b);
}

#[derive(serde::Deserialize)]
struct Kat {
    key_hex: String,
    container_hex: String,
    plain_hex: String,
}

fn kat() -> (Dek, Vec<u8>, Vec<u8>) {
    let raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/crypto/alg1-v1.json")).unwrap();
    let kat: Kat = serde_json::from_str(&raw).unwrap();
    let key: [u8; 32] = hex::decode(kat.key_hex).unwrap().try_into().unwrap();
    (Dek::from_bytes(key), hex::decode(kat.container_hex).unwrap(), hex::decode(kat.plain_hex).unwrap())
}

#[test]
fn the_known_answer_vector_still_opens() {
    let (key, container, plain) = kat();
    assert!(plain.len() > CHUNK_LEN, "the vector must cross a chunk boundary");
    assert_eq!(open(&key, &container).unwrap(), plain);
}

#[test]
fn the_known_answer_vector_follows_the_documented_nonce_layout() {
    let (key, container, plain) = kat();
    let header = &container[..KEY_HEADER_LEN];
    assert_eq!(&header[..6], b"BVC\x01\x01\x00");
    let prefix = &header[6..];
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap();
    let chunk = |counter: u32, last: u8, ct: &[u8]| {
        let mut nonce = prefix.to_vec();
        nonce.extend_from_slice(&counter.to_be_bytes());
        nonce.push(last);
        cipher.decrypt(&XNonce::try_from(&nonce[..]).unwrap(), Payload { msg: ct, aad: header }).unwrap()
    };
    let body = &container[KEY_HEADER_LEN..];
    let first = chunk(0, 0, &body[..CT_CHUNK]);
    let second = chunk(1, 1, &body[CT_CHUNK..]);
    assert_eq!([first, second].concat(), plain);
}

#[test]
fn changing_any_header_byte_fails() {
    let key = Dek::random();
    let sealed = seal(&key, b"header bytes are authenticated");
    for i in 0..KEY_HEADER_LEN {
        let mut bad = sealed.clone();
        bad[i] ^= 0x01;
        assert!(open(&key, &bad).is_err(), "flipping header byte {i} was not detected");
    }
}

#[test]
fn an_unknown_version_algorithm_or_kdf_is_unsupported() {
    let key = Dek::random();
    let sealed = seal(&key, b"x");
    for (i, v) in [(0, b'X'), (3, 2), (4, 9), (5, 7)] {
        let mut bad = sealed.clone();
        bad[i] = v;
        assert!(matches!(open(&key, &bad), Err(Error::UnsupportedFormat)), "byte {i} = {v}");
        assert!(matches!(parse_header(&bad), Err(Error::UnsupportedFormat)), "byte {i} = {v}");
    }
}

#[test]
fn changing_a_chunk_byte_fails() {
    let key = Dek::random();
    let sealed = seal(&key, &pattern(200 * 1024));
    let mut bad = sealed.clone();
    bad[KEY_HEADER_LEN + CT_CHUNK + 100] ^= 0x80;
    assert!(open(&key, &bad).is_err());
}

#[test]
fn reordered_chunks_fail() {
    let key = Dek::random();
    let sealed = seal(&key, &pattern(200 * 1024));
    let body = &sealed[KEY_HEADER_LEN..];
    let (c1, c2, rest) = (&body[..CT_CHUNK], &body[CT_CHUNK..2 * CT_CHUNK], &body[2 * CT_CHUNK..]);
    let swapped = [&sealed[..KEY_HEADER_LEN], c2, c1, rest].concat();
    assert_eq!(swapped.len(), sealed.len());
    assert!(open(&key, &swapped).is_err());
}

#[test]
fn a_truncated_stream_fails() {
    let key = Dek::random();
    let sealed = seal(&key, &pattern(200 * 1024));
    let last_start = KEY_HEADER_LEN + 3 * CT_CHUNK;
    assert!(open(&key, &sealed[..last_start]).is_err());
    let exact = seal(&key, &pattern(2 * CHUNK_LEN));
    assert!(open(&key, &exact[..KEY_HEADER_LEN + CT_CHUNK]).is_err());
}

#[test]
fn an_extended_stream_fails() {
    let key = Dek::random();
    let sealed = seal(&key, &pattern(200 * 1024));
    let last = sealed[KEY_HEADER_LEN + 3 * CT_CHUNK..].to_vec();
    assert!(open(&key, &[sealed.clone(), last].concat()).is_err());
    let exact = seal(&key, &pattern(CHUNK_LEN));
    let copy = exact[KEY_HEADER_LEN..].to_vec();
    assert!(open(&key, &[exact, copy].concat()).is_err());
}

#[tokio::test]
async fn streaming_and_buffered_formats_are_identical() {
    let key = Dek::random();
    let plain = pattern(300 * 1024);
    let mut sealed = Vec::new();
    let read = crypto::seal_stream(&key, &plain[..], &mut sealed).await.unwrap();
    assert_eq!(read, plain.len() as u64);
    assert_eq!(open(&key, &sealed).unwrap(), plain);

    let buffered = seal(&key, &plain);
    let mut opened = Vec::new();
    let written = crypto::open_stream(&key, &buffered[..], &mut opened).await.unwrap();
    assert_eq!(written, plain.len() as u64);
    assert_eq!(opened, plain);
}

#[tokio::test]
async fn streaming_handles_empty_and_exact_chunk_inputs() {
    let key = Dek::random();
    for len in [0, CHUNK_LEN, 2 * CHUNK_LEN, 2 * CHUNK_LEN + 1] {
        let plain = pattern(len);
        let mut sealed = Vec::new();
        crypto::seal_stream(&key, &plain[..], &mut sealed).await.unwrap();
        assert_eq!(sealed.len(), seal(&key, &plain).len(), "length {len}");
        let mut opened = Vec::new();
        crypto::open_stream(&key, &sealed[..], &mut opened).await.unwrap();
        assert_eq!(opened, plain, "length {len}");
    }
}

#[tokio::test]
async fn streaming_open_detects_truncation_and_extension() {
    let key = Dek::random();
    let sealed = seal(&key, &pattern(2 * CHUNK_LEN));
    let truncated = &sealed[..KEY_HEADER_LEN + CT_CHUNK];
    assert!(crypto::open_stream(&key, truncated, tokio::io::sink()).await.is_err());
    let extended = [sealed.clone(), sealed[KEY_HEADER_LEN + CT_CHUNK..].to_vec()].concat();
    assert!(crypto::open_stream(&key, &extended[..], tokio::io::sink()).await.is_err());
    assert!(matches!(crypto::open_stream(&key, &sealed[..3], tokio::io::sink()).await, Err(Error::UnsupportedFormat)));
}

fn vm_hwm_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmHWM:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[tokio::test]
#[ignore = "streams 3 GiB; run in release with --ignored"]
async fn streaming_memory_stays_bounded() {
    use tokio::io::AsyncReadExt;
    const LEN: u64 = 3 << 30;
    let before = vm_hwm_kib();
    let key = Dek::random();
    let (writer, reader) = tokio::io::duplex(1 << 20);
    let source = tokio::io::repeat(0x5a).take(LEN);
    let (sealed, opened) =
        tokio::join!(crypto::seal_stream(&key, source, writer), crypto::open_stream(&key, reader, tokio::io::sink()));
    assert_eq!(sealed.unwrap(), LEN);
    assert_eq!(opened.unwrap(), LEN);
    let grown = vm_hwm_kib().saturating_sub(before);
    assert!(grown < 64 * 1024, "peak resident memory grew by {grown} KiB");
}

#[tokio::test]
async fn a_wrapped_key_unwraps_with_the_right_password() {
    let dek = Dek::random();
    let wrapped = crypto::wrap_dek("correct horse", &dek, FAST).await.unwrap();
    assert_eq!(crypto::unwrap_dek("correct horse", &wrapped).await.unwrap(), dek);
}

#[tokio::test]
async fn a_wrong_password_is_reported_as_such() {
    let wrapped = crypto::wrap_dek("correct horse", &Dek::random(), FAST).await.unwrap();
    assert!(matches!(crypto::unwrap_dek("battery staple", &wrapped).await, Err(Error::WrongPassword)));
}

#[tokio::test]
async fn a_malformed_wrapped_key_is_unsupported() {
    assert!(matches!(crypto::unwrap_dek("pw", b"not a container").await, Err(Error::UnsupportedFormat)));
    let content = seal(&Dek::random(), &[0; 32]);
    assert!(matches!(crypto::unwrap_dek("pw", &content).await, Err(Error::UnsupportedFormat)));
}

#[tokio::test]
async fn default_kdf_parameters_are_written_into_the_header() {
    assert_eq!(KdfParams::DEFAULT, KdfParams { m_kib: 65_536, t: 3, p: 1 });
    let wrapped = crypto::wrap_dek("pw", &Dek::random(), KdfParams::DEFAULT).await.unwrap();
    let h = parse_header(&wrapped).unwrap();
    assert_eq!((h.version, h.alg, h.kdf), (1, 1, 1));
    assert_eq!(h.argon, Some(KdfParams::DEFAULT));
    assert_eq!(h.iterations, None);
    assert_eq!(&wrapped[6..15], &[0, 1, 0, 0, 0, 0, 0, 3, 1]);
}

#[tokio::test]
async fn readonly_password_hashes_verify() {
    let phc = crypto::hash_password("open sesame").await.unwrap();
    assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"), "{phc}");
    assert!(crypto::verify_password("open sesame", &phc).await);
    assert!(!crypto::verify_password("open sesame!", &phc).await);
    assert!(!crypto::verify_password("open sesame", "not a phc string").await);
}

#[test]
fn verifier_comparison_is_exact() {
    let v = [7u8; 32];
    let stored = crypto::verifier_hash(&v);
    assert_ne!(stored, v);
    assert!(crypto::verifier_matches(&stored, &v));
    let mut off = v;
    off[31] ^= 0x01;
    assert!(!crypto::verifier_matches(&stored, &off));
    assert!(!crypto::verifier_matches(&stored[..31], &v));
}

#[test]
fn weak_browser_containers_are_refused() {
    let salt = [3u8; 16];
    let weak = seal_alg2_for_tests("pw", &salt, 1, b"secret");
    assert!(matches!(check_browser_container(&weak), Err(Error::UnsupportedFormat)));
    let weak = seal_alg2_for_tests("pw", &salt, PBKDF2_ITERATIONS - 1, b"secret");
    assert!(matches!(check_browser_container(&weak), Err(Error::UnsupportedFormat)));
    let server = seal(&Dek::random(), b"secret");
    assert!(matches!(check_browser_container(&server), Err(Error::UnsupportedFormat)));
    assert!(matches!(check_browser_container(b"BVC"), Err(Error::UnsupportedFormat)));
}

#[test]
fn a_full_strength_browser_container_is_accepted_and_opens_with_its_password() {
    let salt = [9u8; 16];
    let plain = pattern(CHUNK_LEN + 10);
    let container = seal_alg2_for_tests("hunter2", &salt, PBKDF2_ITERATIONS, &plain);
    check_browser_container(&container).unwrap();
    let h = parse_header(&container).unwrap();
    assert_eq!((h.alg, h.kdf, h.iterations, h.argon), (2, 2, Some(PBKDF2_ITERATIONS), None));
    assert_eq!(&container[6..10], &PBKDF2_ITERATIONS.to_be_bytes());
    assert_eq!(&container[10..26], &salt);
    assert_eq!(open_alg2("hunter2", &container).unwrap(), plain);
    assert!(matches!(open_alg2("hunter3", &container), Err(Error::WrongPassword)));
}

#[test]
fn browser_containers_detect_reordering_and_truncation() {
    let salt = [1u8; 16];
    let c = seal_alg2_for_tests("pw", &salt, 1000, &pattern(2 * CHUNK_LEN));
    // Header bytes: magic 3, version, alg and kdf 1 each, iterations 4, salt 16, nonce prefix 7.
    let header = 33;
    assert!(open_alg2("pw", &c[..header + CT_CHUNK]).is_err());
    let swapped = [&c[..header], &c[header + CT_CHUNK..], &c[header..header + CT_CHUNK]].concat();
    assert!(open_alg2("pw", &swapped).is_err());
    assert_eq!(open_alg2("pw", &c).unwrap(), pattern(2 * CHUNK_LEN));
}

#[test]
fn the_browser_verifier_is_an_hmac_under_the_second_half_of_the_pbkdf2_output() {
    let salt = [5u8; 16];
    let mut okm = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha256>(b"pw", &salt, PBKDF2_ITERATIONS, &mut okm);
    let mut mac = Hmac::<Sha256>::new_from_slice(&okm[32..]).unwrap();
    mac.update(b"bitvault-delete");
    let expected: [u8; 32] = mac.finalize().into_bytes().into();
    assert_eq!(crypto::browser_verifier("pw", &salt), expected);
    assert_ne!(crypto::browser_verifier("pw", &[6u8; 16]), expected);
}

#[test]
fn keys_do_not_print_their_bytes() {
    let key = Dek::from_bytes([0xab; 32]);
    let shown = format!("{key:?}");
    assert!(!shown.contains("ab") && !shown.contains("171"), "{shown}");
}

#[tokio::test]
async fn malformed_input_is_rejected_without_panicking() {
    use rand::RngExt;
    let key = Dek::random();
    let mut rng = rand::rng();
    let valid = seal(&key, &pattern(CHUNK_LEN + 50));
    for round in 0..300 {
        let len = rng.random_range(0..200);
        let mut junk: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        if round % 2 == 0 && junk.len() >= 6 {
            junk[..3].copy_from_slice(b"BVC");
            junk[3] = 1;
            junk[4] = rng.random_range(0..4);
            junk[5] = rng.random_range(0..4);
        }
        let _ = parse_header(&junk);
        assert!(open(&key, &junk).is_err());
        let _ = check_browser_container(&junk);
        assert!(crypto::open_stream(&key, &junk[..], tokio::io::sink()).await.is_err());

        let mut mutated = valid.clone();
        let cut = rng.random_range(0..mutated.len());
        mutated.truncate(cut);
        assert!(open(&key, &mutated).is_err());
    }
    let mut kdf1 = b"BVC\x01\x01\x01".to_vec();
    kdf1.extend_from_slice(&u32::MAX.to_be_bytes());
    kdf1.extend_from_slice(&u32::MAX.to_be_bytes());
    kdf1.push(1);
    kdf1.extend_from_slice(&[0; 16 + 19 + 16]);
    assert!(matches!(parse_header(&kdf1), Err(Error::UnsupportedFormat)));
    assert!(matches!(crypto::unwrap_dek("pw", &kdf1).await, Err(Error::UnsupportedFormat)));
}
