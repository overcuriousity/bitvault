#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bitvault::domain::crypto::Dek;
use bitvault::domain::grant::{self, GrantKey, TTL_SECS};
use bitvault::domain::words::PasteId;
use bitvault::error::Error;

const NOW: i64 = 1_800_000_000;

#[test]
fn a_grant_opens_the_paste_it_was_issued_for() {
    let key = GrantKey::random();
    let token = grant::issue(&key, PasteId(42), None, NOW);
    assert!(!token.contains('=') && !token.contains('+') && !token.contains('/'), "{token}");
    assert!(grant::check(&key, &token, PasteId(42), NOW).unwrap().is_none());
}

#[test]
fn a_grant_for_one_paste_does_not_open_another() {
    let key = GrantKey::random();
    let token = grant::issue(&key, PasteId(42), None, NOW);
    assert!(matches!(grant::check(&key, &token, PasteId(43), NOW), Err(Error::GrantExpired)));
}

#[test]
fn a_grant_expires_after_ten_minutes() {
    assert_eq!(TTL_SECS, 600);
    let key = GrantKey::random();
    let token = grant::issue(&key, PasteId(7), None, NOW);
    assert!(matches!(grant::check(&key, &token, PasteId(7), NOW + 601), Err(Error::GrantExpired)));
    assert!(grant::check(&key, &token, PasteId(7), NOW + 599).is_ok());
    assert!(grant::check(&key, &token, PasteId(7), NOW + 600).is_ok());
}

#[test]
fn a_grant_carries_the_data_key() {
    let key = GrantKey::random();
    let dek = Dek::random();
    let token = grant::issue(&key, PasteId(9), Some(&dek), NOW);
    assert_eq!(grant::check(&key, &token, PasteId(9), NOW).unwrap(), Some(dek));
}

#[test]
fn a_tampered_grant_is_refused() {
    let key = GrantKey::random();
    let token = grant::issue(&key, PasteId(9), Some(&Dek::random()), NOW);
    let mut raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
    for i in 0..raw.len() {
        raw[i] ^= 0x01;
        let bad = URL_SAFE_NO_PAD.encode(&raw);
        assert!(matches!(grant::check(&key, &bad, PasteId(9), NOW), Err(Error::GrantExpired)), "byte {i}");
        raw[i] ^= 0x01;
    }
    assert!(matches!(grant::check(&GrantKey::random(), &token, PasteId(9), NOW), Err(Error::GrantExpired)));
}

#[test]
fn malformed_grants_are_refused_without_panicking() {
    use rand::RngExt;
    let key = GrantKey::random();
    let mut rng = rand::rng();
    for token in ["", "=", "not base64!", "AAAA", &"A".repeat(10_000)] {
        assert!(matches!(grant::check(&key, token, PasteId(1), NOW), Err(Error::GrantExpired)), "{token}");
    }
    for _ in 0..500 {
        let len = rng.random_range(0..120);
        let bytes: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        let token = URL_SAFE_NO_PAD.encode(&bytes);
        assert!(matches!(grant::check(&key, &token, PasteId(1), NOW), Err(Error::GrantExpired)));
    }
}

#[test]
fn grant_keys_do_not_print_their_bytes() {
    let shown = format!("{:?}", GrantKey::random());
    assert_eq!(shown, "GrantKey(..)");
}

#[tokio::test]
async fn the_app_state_holds_a_grant_key() {
    let app = support::app().await;
    let token = grant::issue(&app.st.grant_key, PasteId(1), None, NOW);
    assert!(grant::check(&app.st.grant_key, &token, PasteId(1), NOW).is_ok());
}

#[test]
fn a_creator_token_opens_the_creator_view_of_its_paste_for_ten_minutes() {
    let key = GrantKey::random();
    let token = grant::issue_creator(&key, PasteId(42), NOW);
    assert!(!token.contains('=') && !token.contains('+') && !token.contains('/'), "{token}");
    assert!(grant::check_creator(&key, &token, PasteId(42), NOW));
    assert!(grant::check_creator(&key, &token, PasteId(42), NOW + 600));
    assert!(!grant::check_creator(&key, &token, PasteId(42), NOW + 601));
}

#[test]
fn a_creator_token_for_one_paste_does_not_open_another() {
    let key = GrantKey::random();
    let token = grant::issue_creator(&key, PasteId(42), NOW);
    assert!(!grant::check_creator(&key, &token, PasteId(43), NOW));
    assert!(!grant::check_creator(&GrantKey::random(), &token, PasteId(42), NOW));
}

#[test]
fn grants_and_creator_tokens_cannot_stand_in_for_each_other() {
    let key = GrantKey::random();
    let creator = grant::issue_creator(&key, PasteId(5), NOW);
    assert!(matches!(grant::check(&key, &creator, PasteId(5), NOW), Err(Error::GrantExpired)));
    for dek in [None, Some(Dek::random())] {
        let download = grant::issue(&key, PasteId(5), dek.as_ref(), NOW);
        assert!(!grant::check_creator(&key, &download, PasteId(5), NOW));
    }
}

#[test]
fn malformed_creator_tokens_are_refused_without_panicking() {
    let key = GrantKey::random();
    for token in ["", "=", "not base64!", "AAAA", &"A".repeat(10_000)] {
        assert!(!grant::check_creator(&key, token, PasteId(1), NOW), "{token}");
    }
    let mut raw = URL_SAFE_NO_PAD.decode(grant::issue_creator(&key, PasteId(1), NOW)).unwrap();
    for i in 0..raw.len() {
        raw[i] ^= 0x01;
        assert!(!grant::check_creator(&key, &URL_SAFE_NO_PAD.encode(&raw), PasteId(1), NOW), "byte {i}");
        raw[i] ^= 0x01;
    }
}
