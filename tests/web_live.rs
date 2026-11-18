#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use bitvault::domain::crypto::{self, PBKDF2_ITERATIONS};
use bitvault::domain::expiry::Expiry;
use bitvault::domain::live::room::Timing;
use bitvault::domain::paste::{self, NewPaste, SecretParts, TEXT_LIMIT};
use bitvault::domain::{self, Privacy};
use serde_json::{Value, json};
use support::{App, SseFrame, SseReader, body_text};

const CONFIG: &str = "[app]\neditable = true\n";
const PASSWORD: &str = "live-pw-123";
/// A client secret no session has handed out.
const STRANGER: &str = "00112233445566778899aabbccddeeff";

fn timing() -> Timing {
    Timing {
        session_grace: Duration::from_secs(600),
        presence_grace: Duration::from_millis(100),
        peers_every: Duration::from_millis(20),
        ..Timing::default()
    }
}

async fn live_app() -> App {
    support::app_with_timing(CONFIG, timing()).await
}

fn new(content: &str, privacy: Privacy) -> NewPaste {
    NewPaste {
        content: content.into(),
        privacy,
        expiry: Expiry::Hour24,
        burn_after_reads: 0,
        syntax: None,
        editable: true,
        password: (privacy == Privacy::Private).then(|| PASSWORD.to_owned()),
        secret: None,
    }
}

async fn create_paste(app: &App, p: NewPaste) -> String {
    paste::create(&app.st, p, None, domain::now()).await.unwrap().words()
}

async fn create(app: &App, content: &str, privacy: Privacy) -> String {
    create_paste(app, new(content, privacy)).await
}

/// The address `n` streams claim to come from, through the trusted local proxy, so a test can
/// open more streams than one address may.
fn from(n: u32) -> String {
    let [_, a, b, c] = n.to_be_bytes();
    format!("10.{a}.{b}.{c}")
}

/// `GET /{w}/live/events` with `query` (without `?`), from address `n`, with these extra headers.
async fn connect_with(app: &App, w: &str, query: &str, n: u32, headers: &[(&str, &str)]) -> Response<Body> {
    let uri = if query.is_empty() { format!("/{w}/live/events") } else { format!("/{w}/live/events?{query}") };
    let mut r = app.req("GET", &uri).header("x-forwarded-for", from(n)).header(header::ACCEPT, "text/event-stream");
    for (name, value) in headers {
        r = r.header(*name, *value);
    }
    app.send(r.body(Body::empty()).unwrap()).await
}

async fn open_with(app: &App, w: &str, query: &str, n: u32, headers: &[(&str, &str)]) -> SseReader {
    let res = connect_with(app, w, query, n, headers).await;
    assert_eq!(res.status(), StatusCode::OK, "the stream did not open");
    SseReader::new(res)
}

async fn open(app: &App, w: &str, n: u32) -> SseReader {
    open_with(app, w, "", n, &[]).await
}

/// Opens a stream and reads its `init`; returns the reader and the init's data.
async fn join(app: &App, w: &str, n: u32) -> (SseReader, Value) {
    let mut s = open(app, w, n).await;
    let init = s.nth(0).await;
    assert_eq!(init.event, "init", "{init:?}");
    (s, init.json())
}

fn client(init: &Value) -> String {
    init["client"].as_str().unwrap().to_owned()
}

async fn post_raw(app: &App, w: &str, client: Option<&str>, body: impl Into<Body>) -> StatusCode {
    let mut r = app.req("POST", &format!("/{w}/live")).header(header::CONTENT_TYPE, "application/json");
    if let Some(c) = client {
        r = r.header("x-live-client", c);
    }
    app.send(r.body(body.into()).unwrap()).await.status()
}

async fn post(app: &App, w: &str, client: &str, msg: &Value) -> StatusCode {
    post_raw(app, w, Some(client), msg.to_string()).await
}

fn ops(frames: &[SseFrame]) -> Vec<&SseFrame> {
    frames.iter().filter(|f| f.event == "op").collect()
}

/// Unlocks the private paste `w` over the web and returns the grant its page carries.
async fn unlock(app: &App, w: &str) -> String {
    let res = app.post_form(&format!("/{w}/unlock"), &format!("password={PASSWORD}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    let link = html
        .split('"')
        .find(|s| s.starts_with(&format!("/{w}/raw?g=")))
        .unwrap_or_else(|| panic!("no raw link with a grant"))
        .to_owned();
    link.split_once("?g=").unwrap().1.to_owned()
}

#[tokio::test]
async fn init_then_ops() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let (mut a, init_a) = join(&app, &w, 1).await;
    assert_eq!(init_a["text"], "hello");
    assert_eq!(init_a["rev"], 0);
    assert_eq!(init_a["syntax"], Value::Null);
    assert!(init_a["peer"].is_u64());
    assert!(init_a["peers"].is_array());
    assert_eq!(a.frames[0].id.as_deref(), Some("0"));
    let (mut b, init_b) = join(&app, &w, 2).await;
    assert_eq!(init_b["text"], "hello");
    let edit = json!({"seq": 1, "base": 0, "op": [5, " world"], "pos": 11});
    assert_eq!(post(&app, &w, &client(&init_b), &edit).await, StatusCode::NO_CONTENT);
    for s in [&mut a, &mut b] {
        let op = s.next_named(1, "op").await;
        assert_eq!(op.id.as_deref(), Some("1"));
        assert_eq!(op.json(), json!({"rev": 1, "peer": init_b["peer"], "seq": 1, "op": [5, " world"]}));
    }
}

#[tokio::test]
async fn headers() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let res = connect_with(&app, &w, "", 1, &[("accept-encoding", "gzip")]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let h = res.headers();
    assert!(h[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/event-stream"), "{h:?}");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    assert_eq!(h["x-accel-buffering"], "no");
    assert!(!h.contains_key(header::CONTENT_ENCODING), "the stream was compressed: {h:?}");
}

#[tokio::test]
async fn the_secret_is_never_broadcast() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let (mut a, init_a) = join(&app, &w, 1).await;
    let (mut b, init_b) = join(&app, &w, 2).await;
    let secret_a = client(&init_a);
    assert_eq!(secret_a.len(), 32);
    assert!(secret_a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(secret_a, client(&init_b));
    assert_eq!(post(&app, &w, &secret_a, &json!({"pos": 3})).await, StatusCode::NO_CONTENT);
    assert_eq!(post(&app, &w, &secret_a, &json!({"syntax": "rs"})).await, StatusCode::NO_CONTENT);
    let edit = json!({"seq": 1, "base": 0, "op": ["> ", 5], "pos": 2});
    assert_eq!(post(&app, &w, &secret_a, &edit).await, StatusCode::NO_CONTENT);
    b.next_named(1, "op").await;
    b.next_named(1, "syntax").await;
    a.next_named(1, "op").await;
    for f in &b.frames {
        assert!(!f.data.contains(&secret_a), "A's secret on B's stream: {f:?}");
    }
    for f in &a.frames[1..] {
        assert!(!f.data.contains(&secret_a), "A's secret after its init: {f:?}");
    }
}

#[tokio::test]
async fn post_needs_the_secret() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let (_a, init) = join(&app, &w, 1).await;
    let me = client(&init);
    let caret = json!({"pos": 1}).to_string();
    assert_eq!(post_raw(&app, &w, None, caret.clone()).await, StatusCode::FORBIDDEN);
    assert_eq!(post_raw(&app, &w, Some(STRANGER), caret.clone()).await, StatusCode::FORBIDDEN);
    assert_eq!(post_raw(&app, &w, Some("not-hex"), caret).await, StatusCode::FORBIDDEN);
    // An operation that does not walk the text, and messages of no known shape.
    let short = json!({"seq": 1, "base": 0, "op": [2, "x"], "pos": 0});
    assert_eq!(post(&app, &w, &me, &short).await, StatusCode::UNPROCESSABLE_ENTITY);
    for bad in [json!({"op": [5]}), json!({}), json!({"pos": 1, "syntax": null}), json!({"syntax": "no-such-language"})]
    {
        assert_eq!(post(&app, &w, &me, &bad).await, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    assert_eq!(post_raw(&app, &w, Some(&me), "not json").await, StatusCode::UNPROCESSABLE_ENTITY);
    // Over the text limit, and over the body limit of the edits group.
    let big = json!({"seq": 1, "base": 0, "op": [5, "a".repeat(TEXT_LIMIT)], "pos": 0});
    assert_eq!(post(&app, &w, &me, &big).await, StatusCode::PAYLOAD_TOO_LARGE);
    let huge = format!("{{\"pos\": 1, \"x\": \"{}\"}}", "a".repeat(7 << 20));
    assert_eq!(post_raw(&app, &w, Some(&me), huge).await, StatusCode::PAYLOAD_TOO_LARGE);
    // The session took nothing of all that: a good edit still makes revision 1.
    let ok = json!({"seq": 1, "base": 0, "op": [5, "!"], "pos": 6});
    assert_eq!(post(&app, &w, &me, &ok).await, StatusCode::NO_CONTENT);
    let fixed = create_paste(&app, NewPaste { editable: false, ..new("fixed", Privacy::Public) }).await;
    assert_eq!(post(&app, &fixed, &me, &json!({"pos": 1})).await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reconnect_replays() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let (a, init_a) = join(&app, &w, 1).await;
    let (mut b, init_b) = join(&app, &w, 2).await;
    drop(a);
    let me = client(&init_b);
    let first = json!({"seq": 1, "base": 0, "op": [5, "!"], "pos": 6});
    let second = json!({"seq": 2, "base": 1, "op": ["> ", 6], "pos": 2});
    assert_eq!(post(&app, &w, &me, &first).await, StatusCode::NO_CONTENT);
    assert_eq!(post(&app, &w, &me, &second).await, StatusCode::NO_CONTENT);
    b.until(|f| ops(f).len() == 2).await;
    let query = format!("client={}", client(&init_a));
    let mut a = open_with(&app, &w, &query, 1, &[("last-event-id", "0")]).await;
    let frames = a.until(|f| f.iter().any(|x| x.event == "peers")).await;
    assert!(frames.iter().all(|f| f.event != "init"), "{frames:#?}");
    let replayed = ops(frames);
    assert_eq!(replayed.len(), 2, "{frames:#?}");
    assert_eq!(replayed[0].id.as_deref(), Some("1"));
    assert_eq!(replayed[1].id.as_deref(), Some("2"));
    assert_eq!(replayed[1].json()["op"], json!(["> ", 6]));
    // With only one of the two, the connect is a fresh join.
    let mut fresh = open_with(&app, &w, &query, 3, &[]).await;
    assert_eq!(fresh.nth(0).await.event, "init");
}

#[tokio::test]
async fn private_needs_a_grant_each_time() {
    let app = live_app().await;
    let w = create(&app, "private text", Privacy::Private).await;
    let other = create(&app, "other text", Privacy::Private).await;
    assert_eq!(connect_with(&app, &w, "", 1, &[]).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(connect_with(&app, &w, "g=made-up", 1, &[]).await.status(), StatusCode::FORBIDDEN);
    let wrong = unlock(&app, &other).await;
    assert_eq!(connect_with(&app, &w, &format!("g={wrong}"), 1, &[]).await.status(), StatusCode::FORBIDDEN);
    let g = unlock(&app, &w).await;
    let mut s = open_with(&app, &w, &format!("g={g}"), 1, &[]).await;
    let init = s.nth(0).await;
    assert_eq!(init.event, "init");
    assert_eq!(init.json()["text"], "private text");
    let known = format!("client={}", client(&init.json()));
    let res = connect_with(&app, &w, &known, 1, &[("last-event-id", "0")]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = connect_with(&app, &w, &format!("{known}&g={wrong}"), 1, &[("last-event-id", "0")]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    // The secret alone authorises a POST.
    assert_eq!(post(&app, &w, &client(&init.json()), &json!({"pos": 2})).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn private_stream_renews_the_grant() {
    let app = support::app_with_timing(CONFIG, Timing { grant_every: Duration::from_millis(50), ..timing() }).await;
    let w = create(&app, "private text", Privacy::Private).await;
    let g = unlock(&app, &w).await;
    let mut s = open_with(&app, &w, &format!("g={g}"), 1, &[]).await;
    let fresh = s.next_named(1, "grant").await.json()["g"].as_str().unwrap().to_owned();
    assert_ne!(fresh, g);
    let res = app.get(&format!("/{w}/raw?g={fresh}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_text(res).await, "private text");
    // And the stream keeps renewing.
    let again = s.next_named(s.frames.len(), "grant").await.json()["g"].as_str().unwrap().to_owned();
    assert_ne!(again, fresh);
}

#[tokio::test]
async fn full_is_an_event() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let mut streams = Vec::new();
    for n in 0..64 {
        streams.push(connect_with(&app, &w, "", n, &[]).await);
        assert_eq!(streams.last().unwrap().status(), StatusCode::OK);
    }
    let mut full = open(&app, &w, 64).await;
    let frames = full.read_to_end().await;
    assert_eq!(frames, [SseFrame { event: "full".into(), id: None, data: "{}".into() }]);
    // A stream that closes makes room: its guard went with it.
    streams.pop();
    let mut next = open(&app, &w, 65).await;
    assert_eq!(next.nth(0).await.event, "init");
}

#[tokio::test]
async fn cross_site_post_is_blocked() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let (_a, init) = join(&app, &w, 1).await;
    let r = Request::builder()
        .method("POST")
        .uri(format!("/{w}/live"))
        .header(header::HOST, &app.origin.0)
        .header(header::ORIGIN, "https://evil.example")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-live-client", client(&init))
        .body(Body::from(json!({"pos": 1}).to_string()))
        .unwrap();
    assert_eq!(app.send(r).await.status(), StatusCode::FORBIDDEN);
}

fn secret_paste() -> NewPaste {
    let pw = "correct horse battery staple";
    let salt = [7; 16];
    let container = crypto::seal_alg2_for_tests(pw, &[9; 16], PBKDF2_ITERATIONS, br#"{"text":"hi","files":[]}"#);
    NewPaste {
        secret: Some(SecretParts { container, verifier_salt: salt, verifier: crypto::browser_verifier(pw, &salt) }),
        ..new("", Privacy::Secret)
    }
}

async fn assert_no_routes(app: &App, w: &str) {
    assert_eq!(connect_with(app, w, "", 1, &[]).await.status(), StatusCode::NOT_FOUND, "{w}: stream");
    assert_eq!(post(app, w, STRANGER, &json!({"pos": 1})).await, StatusCode::NOT_FOUND, "{w}: post");
}

#[tokio::test]
async fn not_live_has_no_stream() {
    let app = live_app().await;
    let readonly = create(&app, "hello", Privacy::Readonly).await;
    let secret = create_paste(&app, secret_paste()).await;
    let burns = create_paste(&app, NewPaste { burn_after_reads: 2, ..new("hello", Privacy::Public) }).await;
    let fixed = create_paste(&app, NewPaste { editable: false, ..new("hello", Privacy::Public) }).await;
    for w in [&readonly, &secret, &burns, &fixed] {
        assert_no_routes(&app, w).await;
    }
    assert_no_routes(&app, "happy-apple-banana").await;
    let off = support::app_with_timing("[app]\neditable = true\nlive_edit = false\n", timing()).await;
    let w = create(&off, "hello", Privacy::Public).await;
    assert_no_routes(&off, &w).await;
}
