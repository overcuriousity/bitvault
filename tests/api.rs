#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bitvault::domain::crypto::{self, PBKDF2_ITERATIONS};
use bitvault::domain::expiry::Expiry;
use bitvault::domain::files::Staging;
use bitvault::domain::paste::{self, NewPaste, SecretParts};
use bitvault::domain::{self, Privacy};
use bytes::Bytes;
use futures_util::stream;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use support::{App, BOUNDARY, app, app_with, multipart_body};

const SECRET_PASSWORD: &str = "correct horse battery staple";
const VERIFIER_SALT: [u8; 16] = [7; 16];

/// A request as a script would send it: a Host header and nothing else, so no Origin and no cookie.
fn api(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder().method(method).uri(uri).header(header::HOST, "localhost:8080")
}

async fn send_json(app: &App, method: &str, uri: &str, body: &Value, headers: &[(&str, &str)]) -> Response<Body> {
    let mut r = api(method, uri).header(header::CONTENT_TYPE, "application/json");
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    app.send(r.body(Body::from(body.to_string())).unwrap()).await
}

async fn get(app: &App, uri: &str, headers: &[(&str, &str)]) -> Response<Body> {
    let mut r = api("GET", uri);
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    app.send(r.body(Body::empty()).unwrap()).await
}

async fn delete(app: &App, uri: &str, headers: &[(&str, &str)]) -> Response<Body> {
    let mut r = api("DELETE", uri);
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    app.send(r.body(Body::empty()).unwrap()).await
}

async fn post_multipart(app: &App, parts: &[(&str, Option<&str>, &[u8])]) -> Response<Body> {
    let r = api("POST", "/api/v1/pastes")
        .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .body(Body::from(multipart_body(parts)))
        .unwrap();
    app.send(r).await
}

async fn bytes_of(res: Response<Body>) -> Vec<u8> {
    res.into_body().collect().await.unwrap().to_bytes().to_vec()
}

async fn json_of(res: Response<Body>) -> Value {
    serde_json::from_slice(&bytes_of(res).await).unwrap()
}

async fn error_code(res: Response<Body>) -> String {
    let v = json_of(res).await;
    assert!(v["error"]["message"].as_str().is_some_and(|m| m.ends_with('.')), "{v}");
    v["error"]["code"].as_str().unwrap().to_owned()
}

/// Creates a paste through the API and returns its words.
async fn create(app: &App, body: Value) -> String {
    let res = send_json(app, "POST", "/api/v1/pastes", &body, &[]).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    json_of(res).await["words"].as_str().unwrap().to_owned()
}

fn plain(content: &str, privacy: Privacy) -> NewPaste {
    NewPaste {
        content: content.into(),
        privacy,
        expiry: Expiry::Hour24,
        burn_after_reads: 0,
        syntax: None,
        editable: false,
        password: None,
        secret: None,
    }
}

fn secret_paste(container: Vec<u8>) -> NewPaste {
    let verifier = crypto::browser_verifier(SECRET_PASSWORD, &VERIFIER_SALT);
    NewPaste {
        secret: Some(SecretParts { container, verifier_salt: VERIFIER_SALT, verifier }),
        ..plain("", Privacy::Secret)
    }
}

/// Created in the domain, so the create rate limit is left for the requests under test.
async fn public_with_file(app: &App) -> String {
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging
        .add("a.txt", "", stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"bytes"))]), u64::MAX)
        .await
        .unwrap();
    let new = NewPaste { editable: true, ..plain("x", Privacy::Public) };
    paste::create(&app.st, new, Some(staging), domain::now()).await.unwrap().words()
}

#[tokio::test]
async fn every_route_is_in_the_openapi_spec_and_vice_versa() {
    let app = app_with("[app]\neditable = true\n").await;
    let res = get(&app, "/api/v1/openapi.json", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let spec = json_of(res).await;
    let paths = spec["paths"].as_object().unwrap();
    let mut names: Vec<&str> = paths.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["/api/v1/health", "/api/v1/pastes", "/api/v1/pastes/{words}", "/api/v1/pastes/{words}/files/{position}"]
    );
    for (path, item) in paths {
        let documented: Vec<String> = item.as_object().unwrap().keys().map(|m| m.to_uppercase()).collect();
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            // A fresh paste per request, so a documented DELETE does not hide the next route.
            let words = public_with_file(&app).await;
            let uri = path.replace("{words}", &words).replace("{position}", "1");
            let r = api(method, &uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"content": "edited"}).to_string()))
                .unwrap();
            let status = app.send(r).await.status();
            if documented.iter().any(|m| m == method) {
                assert!(
                    status != StatusCode::NOT_FOUND && status != StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {path} answered {status}"
                );
            } else {
                assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path} is served but not documented");
            }
        }
    }
}

#[tokio::test]
async fn json_create_returns_201_with_words_and_url() {
    let app = app().await;
    let res = send_json(&app, "POST", "/api/v1/pastes", &json!({"content": "hello", "expiry": "1hour"}), &[]).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let v = json_of(res).await;
    let words = v["words"].as_str().unwrap();
    assert_eq!(words.split('-').count(), 3);
    assert_eq!(v["url"], format!("http://localhost:8080/{words}"));
    assert_eq!(v["privacy"], "unlisted");
    assert!(v["id"].as_u64().is_some());
    assert!(v["short_url"].is_null());
    let expires = v["expires_at"].as_i64().unwrap();
    assert!((expires - domain::now() - 3600).abs() < 60);
    let got = json_of(get(&app, &format!("/api/v1/pastes/{words}"), &[]).await).await;
    assert_eq!(got["content"], "hello");
    assert_eq!(got["encrypted"], false);
    let res = send_json(&app, "POST", "/api/v1/pastes", &json!({"content": "  "}), &[]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(res).await, "INVALID");
}

#[tokio::test]
async fn multipart_create_accepts_files() {
    let app = app().await;
    let res = post_multipart(
        &app,
        &[
            ("privacy", None, b"public"),
            ("content", None, b"with files"),
            ("file", Some("one.bin"), b"first file"),
            ("file", Some("two.bin"), b"second file"),
        ],
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let v = json_of(res).await;
    assert_eq!(v["privacy"], "public");
    let words = v["words"].as_str().unwrap();
    let res = get(&app, &format!("/api/v1/pastes/{words}/files/1"), &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(bytes_of(res).await, b"first file");
    let got = json_of(get(&app, &format!("/api/v1/pastes/{words}"), &[]).await).await;
    assert_eq!(got["files"][1]["name"], "two.bin");
    assert_eq!(got["files"][1]["url"], format!("http://localhost:8080/api/v1/pastes/{words}/files/2"));
    assert_eq!(get(&app, &format!("/api/v1/pastes/{words}/files/3"), &[]).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn multipart_header_blocks_are_capped_for_the_api_too() {
    let app = app().await;
    let mut body = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"content\"\r\nX-Junk: ").into_bytes();
    body.extend(vec![b'a'; 20 << 10]);
    body.extend(format!("\r\n\r\nx\r\n--{BOUNDARY}--\r\n").as_bytes());
    let r = api("POST", "/api/v1/pastes")
        .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .body(Body::from(body))
        .unwrap();
    let res = app.send(r).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error_code(res).await, "TOO_LARGE");
}

#[tokio::test]
async fn secret_cannot_be_created_through_the_api() {
    let app = app().await;
    let res = send_json(&app, "POST", "/api/v1/pastes", &json!({"content": "x", "privacy": "secret"}), &[]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(res).await, "INVALID");
    let res = post_multipart(&app, &[("privacy", None, b"secret"), ("file", Some("a"), b"x")]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(res).await, "INVALID");
    let secret_default = app_with("[app]\ndefault_privacy = \"secret\"\n").await;
    let res = send_json(&secret_default, "POST", "/api/v1/pastes", &json!({"content": "x"}), &[]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn private_pastes_need_the_password_header() {
    let app = app().await;
    let res = post_multipart(
        &app,
        &[
            ("privacy", None, b"private"),
            ("password", None, b"pw"),
            ("content", None, b"hidden text"),
            ("file", Some("a.txt"), b"hidden file"),
        ],
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let words = json_of(res).await["words"].as_str().unwrap().to_owned();
    let uri = format!("/api/v1/pastes/{words}");
    let res = get(&app, &uri, &[]).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(res).await, "PASSWORD_REQUIRED");
    let res = get(&app, &uri, &[("x-paste-password", "wrong")]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(res).await, "WRONG_PASSWORD");
    let res = get(&app, &uri, &[("x-paste-password", "pw")]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let v = json_of(res).await;
    assert_eq!(v["content"], "hidden text");
    assert_eq!(v["privacy"], "private");
    let file = format!("{uri}/files/1");
    let res = get(&app, &file, &[]).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(res).await, "PASSWORD_REQUIRED");
    let res = get(&app, &file, &[("x-paste-password", "pw")]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(bytes_of(res).await, b"hidden file");
}

#[tokio::test]
async fn the_api_needs_no_key() {
    let app = app().await;
    let res = send_json(&app, "POST", "/api/v1/pastes", &json!({"content": "no key"}), &[]).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let words = json_of(res).await["words"].as_str().unwrap().to_owned();
    let res = get(&app, &format!("/api/v1/pastes/{words}"), &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = get(&app, "/api/v1/health", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let v = json_of(res).await;
    assert_eq!(v["status"], "ok");
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn the_uploader_password_comes_from_its_header() {
    let app = app_with("[app]\nuploader_password = \"up\"\n").await;
    let res = send_json(&app, "POST", "/api/v1/pastes", &json!({"content": "x"}), &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(res).await, "FORBIDDEN");
    let res =
        send_json(&app, "POST", "/api/v1/pastes", &json!({"content": "x"}), &[("x-uploader-password", "nope")]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res =
        send_json(&app, "POST", "/api/v1/pastes", &json!({"content": "x"}), &[("x-uploader-password", "up")]).await;
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn delete_follows_the_privacy_rules() {
    let app = app().await;
    let public = create(&app, json!({"content": "x", "privacy": "public"})).await;
    assert_eq!(delete(&app, &format!("/api/v1/pastes/{public}"), &[]).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(get(&app, &format!("/api/v1/pastes/{public}"), &[]).await.status(), StatusCode::NOT_FOUND);

    let readonly = create(&app, json!({"content": "x", "privacy": "readonly", "password": "pw"})).await;
    let uri = format!("/api/v1/pastes/{readonly}");
    let res = delete(&app, &uri, &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(res).await, "FORBIDDEN");
    assert_eq!(delete(&app, &uri, &[("x-paste-password", "wrong")]).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(delete(&app, &uri, &[("x-paste-password", "pw")]).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(get(&app, &uri, &[]).await.status(), StatusCode::NOT_FOUND);

    let container = crypto::seal_alg2_for_tests(SECRET_PASSWORD, &[9; 16], PBKDF2_ITERATIONS, br#"{"text":"s"}"#);
    let secret = paste::create(&app.st, secret_paste(container), None, domain::now()).await.unwrap().words();
    let uri = format!("/api/v1/pastes/{secret}");
    let res = delete(&app, &uri, &[("x-paste-verifier", "abc")]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(res).await, "INVALID");
    let wrong = hex::encode([1u8; 32]);
    assert_eq!(delete(&app, &uri, &[("x-paste-verifier", &wrong)]).await.status(), StatusCode::FORBIDDEN);
    let verifier = hex::encode(crypto::browser_verifier(SECRET_PASSWORD, &VERIFIER_SALT));
    assert_eq!(delete(&app, &uri, &[("x-paste-verifier", &verifier)]).await.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_api_is_rate_limited_per_address() {
    let app = app().await;
    let mut limited = None;
    for _ in 0..31 {
        let res = send_json(&app, "POST", "/api/v1/pastes", &json!({"content": "x"}), &[]).await;
        if res.status() == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(res);
        }
    }
    let res = limited.expect("31 rapid creates were never limited");
    assert_eq!(error_code(res).await, "TOO_MANY_ATTEMPTS");
}

#[tokio::test]
async fn listing_off_hides_the_list_endpoint() {
    let app = app().await;
    let words = create(&app, json!({"content": "listed", "privacy": "public"})).await;
    create(&app, json!({"content": "not listed", "privacy": "unlisted"})).await;
    let res = get(&app, "/api/v1/pastes?page=1", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let v = json_of(res).await;
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["words"], words.as_str());
    assert!(items[0].get("content").is_none());

    let off = app_with("[app]\nlisting = false\n").await;
    let res = get(&off, "/api/v1/pastes", &[]).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(error_code(res).await, "NOT_FOUND");
}

#[tokio::test]
async fn secret_pastes_come_back_as_ciphertext() {
    let app = app().await;
    let container = crypto::seal_alg2_for_tests(SECRET_PASSWORD, &[9; 16], PBKDF2_ITERATIONS, br#"{"text":"s"}"#);
    let words = paste::create(&app.st, secret_paste(container.clone()), None, domain::now()).await.unwrap().words();
    let res = get(&app, &format!("/api/v1/pastes/{words}"), &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let v = json_of(res).await;
    assert_eq!(v["encrypted"], true);
    assert_eq!(v["privacy"], "secret");
    assert_eq!(STANDARD.decode(v["content"].as_str().unwrap()).unwrap(), container);
}

#[tokio::test]
async fn patch_edits_when_enabled() {
    let app = app_with("[app]\neditable = true\n").await;
    let words = create(&app, json!({"content": "before", "privacy": "public", "editable": true})).await;
    let uri = format!("/api/v1/pastes/{words}");
    let res = send_json(&app, "PATCH", &uri, &json!({"content": "after", "syntax": "rs"}), &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let v = json_of(get(&app, &uri, &[]).await).await;
    assert_eq!(v["content"], "after");
    assert_eq!(v["syntax"], "rs");

    let readonly =
        create(&app, json!({"content": "before", "privacy": "readonly", "password": "pw", "editable": true})).await;
    let uri = format!("/api/v1/pastes/{readonly}");
    let res = send_json(&app, "PATCH", &uri, &json!({"content": "after"}), &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = send_json(&app, "PATCH", &uri, &json!({"content": "after"}), &[("x-paste-password", "pw")]).await;
    assert_eq!(res.status(), StatusCode::OK);

    let off = support::app().await;
    let words = create(&off, json!({"content": "before", "privacy": "public", "editable": true})).await;
    let res = send_json(&off, "PATCH", &format!("/api/v1/pastes/{words}"), &json!({"content": "after"}), &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(res).await, "FORBIDDEN");
    let res = send_json(&app, "PATCH", "/api/v1/pastes/not-real-words", &json!({"content": 5}), &[]).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(res).await, "INVALID");
}

#[tokio::test]
async fn the_burning_read_returns_a_grant_for_the_files() {
    let app = app_with("[app]\neditable = true\n").await;
    let res = post_multipart(
        &app,
        &[
            ("privacy", None, b"public"),
            ("burn_after_reads", None, b"1"),
            ("editable", None, b"true"),
            ("content", None, b"read once"),
            ("file", Some("a.bin"), b"burned file"),
        ],
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let words = json_of(res).await["words"].as_str().unwrap().to_owned();
    let v = json_of(get(&app, &format!("/api/v1/pastes/{words}"), &[]).await).await;
    assert_eq!(v["burned"], true);
    assert_eq!(v["editable"], false);
    assert_eq!(v["content"], "read once");
    let grant = v["grant"].as_str().unwrap().to_owned();
    assert_eq!(get(&app, &format!("/api/v1/pastes/{words}"), &[]).await.status(), StatusCode::NOT_FOUND);
    let file = format!("/api/v1/pastes/{words}/files/1");
    let res = get(&app, &file, &[]).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(error_code(res).await, "NOT_FOUND");
    let res = get(&app, &file, &[("x-paste-grant", &grant)]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(bytes_of(res).await, b"burned file");
    let res = get(&app, &file, &[("x-paste-grant", "not-a-grant")]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_private_read_returns_a_grant_that_opens_the_files() {
    let app = app().await;
    let res = post_multipart(
        &app,
        &[
            ("privacy", None, b"private"),
            ("password", None, b"pw"),
            ("content", None, b"hidden text"),
            ("file", Some("a.txt"), b"hidden file"),
        ],
    )
    .await;
    let words = json_of(res).await["words"].as_str().unwrap().to_owned();
    let unlocked = json_of(get(&app, &format!("/api/v1/pastes/{words}"), &[("x-paste-password", "pw")]).await).await;
    let grant = unlocked["grant"].as_str().unwrap().to_owned();
    let res = get(&app, &format!("/api/v1/pastes/{words}/files/1"), &[("x-paste-grant", &grant)]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(bytes_of(res).await, b"hidden file");
    let public = create(&app, json!({"content": "x", "privacy": "public"})).await;
    let v = json_of(get(&app, &format!("/api/v1/pastes/{public}"), &[]).await).await;
    assert!(v.get("grant").is_none(), "only burning and password reads carry a grant");
}

#[tokio::test]
async fn an_expired_paste_has_no_files() {
    let app = app().await;
    let mut staging = Staging::new(&app.st.files_dir).unwrap();
    staging
        .add("a.txt", "", stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"old"))]), u64::MAX)
        .await
        .unwrap();
    let new = NewPaste { expiry: Expiry::Min1, ..plain("x", Privacy::Public) };
    let words = paste::create(&app.st, new, Some(staging), domain::now() - 120).await.unwrap().words();
    let res = get(&app, &format!("/api/v1/pastes/{words}/files/1"), &[]).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(get(&app, &format!("/api/v1/pastes/{words}"), &[]).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn creates_larger_than_the_regular_body_limit_are_accepted() {
    let app = app().await;
    let big = vec![b'z'; 3 << 20];
    let res = post_multipart(&app, &[("content", None, b"big"), ("file", Some("big.bin"), &big)]).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let words = json_of(res).await["words"].as_str().unwrap().to_owned();
    let res = get(&app, &format!("/api/v1/pastes/{words}/files/1"), &[]).await;
    assert_eq!(bytes_of(res).await.len(), big.len());
}

#[tokio::test]
async fn media_types_are_matched_case_insensitively() {
    let app = app().await;
    let r = api("POST", "/api/v1/pastes")
        .header(header::CONTENT_TYPE, "Application/JSON")
        .body(Body::from(json!({"content": "x"}).to_string()))
        .unwrap();
    assert_eq!(app.send(r).await.status(), StatusCode::CREATED);
    let r = api("POST", "/api/v1/pastes")
        .header(header::CONTENT_TYPE, format!("Multipart/Form-Data; boundary={BOUNDARY}"))
        .body(Body::from(multipart_body(&[("content", None, b"x")])))
        .unwrap();
    assert_eq!(app.send(r).await.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn delete_reads_only_the_proof_for_the_paste_level() {
    let app = app().await;
    let public = create(&app, json!({"content": "x", "privacy": "public"})).await;
    let res = delete(&app, &format!("/api/v1/pastes/{public}"), &[("x-paste-verifier", "not hex")]).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let readonly = create(&app, json!({"content": "x", "privacy": "readonly", "password": "pw"})).await;
    let headers = [("x-paste-verifier", "abc"), ("x-paste-password", "pw")];
    assert_eq!(delete(&app, &format!("/api/v1/pastes/{readonly}"), &headers).await.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn an_invalid_grant_is_forbidden_and_says_it_expired() {
    let app = app().await;
    let words = public_with_file(&app).await;
    let res = get(&app, &format!("/api/v1/pastes/{words}/files/1"), &[("x-paste-grant", "expired-or-forged")]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let v = json_of(res).await;
    assert_eq!(v["error"]["code"], "FORBIDDEN");
    assert!(v["error"]["message"].as_str().unwrap().contains("grant has expired"), "{v}");
}

#[tokio::test]
async fn a_patch_may_carry_a_whole_escaped_paste() {
    let app = app_with("[app]\neditable = true\n").await;
    let words = create(&app, json!({"content": "before", "privacy": "public", "editable": true})).await;
    let uri = format!("/api/v1/pastes/{words}");
    // A control character is one byte of text and six in JSON, so this body is about 6 MiB.
    let text = "\u{1}".repeat((1 << 20) - 64);
    let res = send_json(&app, "PATCH", &uri, &json!({"content": text}), &[]).await;
    assert_eq!(res.status(), StatusCode::OK, "{}", support::body_text(res).await);
    assert_eq!(json_of(get(&app, &uri, &[]).await).await["content"].as_str().unwrap().len(), text.len());
    let res = send_json(&app, "PATCH", &uri, &json!({"content": "x".repeat((1 << 20) + 1)}), &[]).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn the_editable_default_follows_the_server_setting() {
    let on = app_with("[app]\neditable = true\n").await;
    let words = create(&on, json!({"content": "x", "privacy": "public"})).await;
    assert_eq!(json_of(get(&on, &format!("/api/v1/pastes/{words}"), &[]).await).await["editable"], true);
    let words = create(&on, json!({"content": "x", "privacy": "public", "editable": false})).await;
    assert_eq!(json_of(get(&on, &format!("/api/v1/pastes/{words}"), &[]).await).await["editable"], false);
    let res = post_multipart(&on, &[("privacy", None, b"public"), ("content", None, b"x")]).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let words = json_of(res).await["words"].as_str().unwrap().to_owned();
    assert_eq!(json_of(get(&on, &format!("/api/v1/pastes/{words}"), &[]).await).await["editable"], true);
    let res =
        post_multipart(&on, &[("privacy", None, b"public"), ("editable", None, b"false"), ("content", None, b"x")])
            .await;
    let words = json_of(res).await["words"].as_str().unwrap().to_owned();
    assert_eq!(json_of(get(&on, &format!("/api/v1/pastes/{words}"), &[]).await).await["editable"], false);
}
