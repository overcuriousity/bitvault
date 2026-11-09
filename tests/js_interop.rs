#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The browser format both ways: `alg2.json` is written by `assets/js/crypto.test.mjs`
//! (`node --test 'assets/js/*.test.mjs'`) and opened here; `rust-alg2.json` is written here once
//! and opened by the JavaScript tests.

mod support;

use std::path::PathBuf;

use axum::http::{StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bitvault::domain::crypto::{self, CHUNK_LEN, PBKDF2_ITERATIONS};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use support::app;

#[derive(Deserialize, Serialize)]
struct Case {
    container_b64: String,
    plain_b64: String,
}

#[derive(Deserialize)]
struct Decomposed {
    password_nfd: String,
    password_nfc: String,
    container_b64: String,
    plain_b64: String,
}

#[derive(Deserialize)]
struct JsFixture {
    password: String,
    container_b64: String,
    plain_b64: String,
    verifier_salt_hex: String,
    verifier_hex: String,
    cases: Vec<Case>,
    decomposed: Decomposed,
}

#[derive(Deserialize, Serialize)]
struct RustFixture {
    password: String,
    verifier_salt_hex: String,
    verifier_hex: String,
    cases: Vec<Case>,
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/js").join(name)
}

fn js_fixture() -> JsFixture {
    serde_json::from_str(&std::fs::read_to_string(fixture_path("alg2.json")).unwrap()).unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    B64.decode(s).unwrap()
}

fn salt(hex_value: &str) -> [u8; 16] {
    hex::decode(hex_value).unwrap().try_into().unwrap()
}

#[test]
fn containers_sealed_in_javascript_open_in_rust() {
    let f = js_fixture();
    let plain = crypto::open_alg2(&f.password, &b64(&f.container_b64)).unwrap();
    assert_eq!(plain, b64(&f.plain_b64));
    let envelope: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(envelope["files"][0], "a.png");
    let lens: Vec<usize> = f.cases.iter().map(|c| b64(&c.plain_b64).len()).collect();
    assert_eq!(lens, [0, CHUNK_LEN, CHUNK_LEN + 3], "empty, an exact chunk and a partial final chunk");
    for c in &f.cases {
        assert_eq!(crypto::open_alg2(&f.password, &b64(&c.container_b64)).unwrap(), b64(&c.plain_b64));
    }
    assert!(matches!(
        crypto::open_alg2("not the password", &b64(&f.container_b64)),
        Err(bitvault::error::Error::WrongPassword)
    ));
}

#[test]
fn a_container_sealed_in_javascript_with_a_decomposed_password_opens_in_rust_with_the_composed_one() {
    let d = js_fixture().decomposed;
    assert_ne!(d.password_nfd, d.password_nfc);
    assert_eq!(crypto::open_alg2(&d.password_nfc, &b64(&d.container_b64)).unwrap(), b64(&d.plain_b64));
    assert_eq!(crypto::open_alg2(&d.password_nfd, &b64(&d.container_b64)).unwrap(), b64(&d.plain_b64));
    let salt = [3; 16];
    assert_eq!(crypto::browser_verifier(&d.password_nfd, &salt), crypto::browser_verifier(&d.password_nfc, &salt));
}

#[test]
fn the_javascript_verifier_matches_the_rust_derivation() {
    let f = js_fixture();
    let rust = crypto::browser_verifier(&f.password, &salt(&f.verifier_salt_hex));
    assert_eq!(hex::encode(rust), f.verifier_hex);
}

#[test]
fn javascript_containers_pass_the_server_parameter_check() {
    let f = js_fixture();
    let container = b64(&f.container_b64);
    crypto::check_browser_container(&container).unwrap();
    let header = crypto::parse_header(&container).unwrap();
    assert_eq!((header.alg, header.kdf, header.iterations), (2, 2, Some(PBKDF2_ITERATIONS)));
    for c in &f.cases {
        let container = b64(&c.container_b64);
        crypto::check_browser_container(&container).unwrap();
        let plain_len = b64(&c.plain_b64).len() as u64;
        assert!(container.len() as u64 <= crypto::browser_container_max_len(plain_len));
    }
}

/// Written once and committed, so the JavaScript tests also open what Rust seals.
#[test]
fn containers_sealed_in_rust_are_kept_for_the_javascript_tests() {
    let path = fixture_path("rust-alg2.json");
    if !path.exists() {
        let password = "rust says hello ✓";
        let verifier_salt = [0x5a; 16];
        let plains = [Vec::new(), vec![0xa5; CHUNK_LEN], (0..=255u8).cycle().take(CHUNK_LEN + 17).collect()];
        let cases = plains
            .iter()
            .enumerate()
            .map(|(i, p)| Case {
                container_b64: B64.encode(crypto::seal_alg2_for_tests(password, &[i as u8; 16], PBKDF2_ITERATIONS, p)),
                plain_b64: B64.encode(p),
            })
            .collect();
        let fixture = RustFixture {
            password: password.into(),
            verifier_salt_hex: hex::encode(verifier_salt),
            verifier_hex: hex::encode(crypto::browser_verifier(password, &verifier_salt)),
            cases,
        };
        std::fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
    }
    let f: RustFixture = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    for c in &f.cases {
        assert_eq!(crypto::open_alg2(&f.password, &b64(&c.container_b64)).unwrap(), b64(&c.plain_b64));
    }
    assert_eq!(hex::encode(crypto::browser_verifier(&f.password, &salt(&f.verifier_salt_hex))), f.verifier_hex);
}

#[tokio::test]
async fn a_secret_paste_created_with_javascript_parts_deletes_with_its_verifier() {
    let app = app().await;
    let f = js_fixture();
    let content = b64(&f.container_b64);
    let file = b64(&f.cases[2].container_b64);
    // The field order create.js uses: every text field and the content before any file.
    let res = app
        .post_multipart(
            "/",
            &[
                ("privacy", None, b"secret"),
                ("expiry", None, b"1hour"),
                ("burn_after_reads", None, b"0"),
                ("content_container", Some("blob"), &content),
                ("verifier_salt", None, f.verifier_salt_hex.as_bytes()),
                ("verifier", None, f.verifier_hex.as_bytes()),
                ("file", Some(""), &file),
            ],
        )
        .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "{}", support::body_text(res).await);
    let location = res.headers()[header::LOCATION].to_str().unwrap().to_owned();
    let words = location.trim_start_matches('/');

    let html = support::body_text(app.get(&location).await).await;
    assert!(html.contains(&format!("data-verifier-salt=\"{}\"", f.verifier_salt_hex)));
    assert!(html.contains("js/secret.js"), "the secret page loads secret.js");
    let raw = app.get(&format!("/{words}/raw")).await;
    assert_eq!(raw.into_body().collect().await.unwrap().to_bytes(), content);
    let stored = app.get(&format!("/{words}/file/1")).await;
    assert_eq!(stored.status(), StatusCode::OK);
    assert_eq!(stored.into_body().collect().await.unwrap().to_bytes(), file);

    let wrong = hex::encode(crypto::browser_verifier("not the password", &salt(&f.verifier_salt_hex)));
    let res = app.post_form(&format!("/{words}/delete"), &format!("verifier={wrong}")).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = app.post_form(&format!("/{words}/delete"), &format!("verifier={}", f.verifier_hex)).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(app.get(&location).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_home_page_loads_create_js_and_states_the_secret_file_limit() {
    let app = support::app_with("[app]\nmax_secret_file_mb = 12\n").await;
    let html = support::body_text(app.get("/").await).await;
    assert!(html.contains("js/create.js"));
    assert!(html.contains("data-max-secret-mb=\"12\""));
    assert!(html.contains("id=\"create-notice\""));
}
