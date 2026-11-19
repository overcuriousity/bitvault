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
    let names: Vec<&str> = frames.iter().map(|f| f.event.as_str()).collect();
    assert_eq!(names, ["op", "op", "syntax", "peers"], "{frames:#?}");
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
async fn reconnect_takes_the_revision_from_the_query_too() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let (a, init_a) = join(&app, &w, 1).await;
    let (mut b, init_b) = join(&app, &w, 2).await;
    drop(a);
    let me = client(&init_b);
    assert_eq!(
        post(&app, &w, &me, &json!({"seq": 1, "base": 0, "op": [5, "!"], "pos": 6})).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(&app, &w, &me, &json!({"seq": 2, "base": 1, "op": [6, "?"], "pos": 7})).await,
        StatusCode::NO_CONTENT
    );
    b.until(|f| ops(f).len() == 2).await;
    let names = |frames: &[SseFrame]| frames.iter().map(|f| f.event.clone()).collect::<Vec<_>>();
    // `EventSource` cannot set the header on a stream the page builds itself, so `last` stands in.
    let query = format!("client={}&last=0", client(&init_a));
    let mut a = open_with(&app, &w, &query, 1, &[]).await;
    let frames = a.until(|f| f.iter().any(|x| x.event == "peers")).await;
    assert_eq!(names(frames), ["op", "op", "syntax", "peers"], "{frames:#?}");
    drop(a);
    // The browser's own `Last-Event-ID` wins over the query.
    let mut a = open_with(&app, &w, &query, 1, &[("last-event-id", "1")]).await;
    let frames = a.until(|f| f.iter().any(|x| x.event == "peers")).await;
    assert_eq!(names(frames), ["op", "syntax", "peers"], "{frames:#?}");
    assert_eq!(ops(frames)[0].id.as_deref(), Some("2"));
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

/// `GET /{w}/events` with `query` (without `?`), from address `n`.
async fn watch_with(app: &App, w: &str, query: &str, n: u32) -> Response<Body> {
    let uri = if query.is_empty() { format!("/{w}/events") } else { format!("/{w}/events?{query}") };
    let r = app.req("GET", &uri).header("x-forwarded-for", from(n)).header(header::ACCEPT, "text/event-stream");
    app.send(r.body(Body::empty()).unwrap()).await
}

async fn watch_query(app: &App, w: &str, query: &str, n: u32) -> SseReader {
    let res = watch_with(app, w, query, n).await;
    assert_eq!(res.status(), StatusCode::OK, "the watch stream did not open");
    SseReader::new(res)
}

async fn watch(app: &App, w: &str, n: u32) -> SseReader {
    watch_query(app, w, "", n).await
}

/// What the paste page at `w` puts inside its `#paste-text`.
async fn page_text(app: &App, w: &str, query_form: Option<&str>) -> String {
    let res = match query_form {
        Some(form) => app.post_form(&format!("/{w}/unlock"), form).await,
        None => app.get(&format!("/{w}")).await,
    };
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    let start = html.find("id=\"paste-text\">").unwrap_or_else(|| panic!("no #paste-text: {html}"));
    let rest = &html[start + "id=\"paste-text\">".len()..];
    rest[..rest.find("</pre>").unwrap()].to_owned()
}

async fn read_count(app: &App, w: &str) -> (u64, Option<i64>) {
    let id = bitvault::domain::words::parse(w).unwrap();
    let p = paste::meta(&app.st, id, domain::now()).await.unwrap();
    (p.read_count, p.last_read_at)
}

#[tokio::test]
async fn a_watcher_sees_live_and_content() {
    let app = live_app().await;
    let w = create_paste(&app, NewPaste { syntax: Some("rs".into()), ..new("fn main() {}\n", Privacy::Public) }).await;
    let inside = page_text(&app, &w, None).await;
    let mut s = watch(&app, &w, 1).await;
    let live = s.nth(0).await;
    assert_eq!((live.event.as_str(), live.json()), ("live", json!({"editors": 0})));
    let content = s.nth(1).await;
    assert_eq!(content.event, "content");
    let data = content.json();
    assert_eq!(data["highlighted"], true);
    // The page wraps the markup in `<code>`; the event carries the markup.
    assert_eq!(inside, format!("<code>{}</code>", data["html"].as_str().unwrap()));

    let (_a, init) = join(&app, &w, 2).await;
    let joined = s.next_named(2, "live").await;
    assert_eq!(joined.json(), json!({"editors": 1}));
    let edit = json!({"seq": 1, "base": 0, "op": [12, " // live", 1], "pos": 20});
    assert_eq!(post(&app, &w, &client(&init), &edit).await, StatusCode::NO_CONTENT);
    let from = s.frames.len();
    let fresh = s.next_named(from, "content").await;
    assert!(fresh.json()["html"].as_str().unwrap().contains("live"), "{fresh:?}");
}

#[tokio::test]
async fn pushed_text_is_not_a_read() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let before = read_count(&app, &w).await;
    let mut s = watch(&app, &w, 1).await;
    s.next_named(0, "content").await;
    let res = app.post_form(&format!("/{w}/edit"), "content=changed").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let pushed = s.next_named(2, "content").await;
    assert!(pushed.json()["html"].as_str().unwrap().contains("changed"));
    assert_eq!(read_count(&app, &w).await, before);
}

#[tokio::test]
async fn private_watch_needs_a_grant() {
    let app = support::app_with_timing(CONFIG, Timing { grant_every: Duration::from_millis(50), ..timing() }).await;
    let w = create(&app, "private text", Privacy::Private).await;
    let other = create(&app, "other text", Privacy::Private).await;
    assert_eq!(watch_with(&app, &w, "", 1).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(watch_with(&app, &w, "g=made-up", 1).await.status(), StatusCode::FORBIDDEN);
    let wrong = unlock(&app, &other).await;
    assert_eq!(watch_with(&app, &w, &format!("g={wrong}"), 1).await.status(), StatusCode::FORBIDDEN);
    let inside = page_text(&app, &w, Some(&format!("password={PASSWORD}"))).await;
    let g = unlock(&app, &w).await;
    let mut s = watch_query(&app, &w, &format!("g={g}"), 1).await;
    assert_eq!(s.nth(0).await.event, "live");
    let content = s.nth(1).await;
    assert_eq!(content.event, "content");
    assert_eq!(inside, format!("<code>{}</code>", content.json()["html"].as_str().unwrap()));
    // During a session too, the text goes only to a stream with a grant.
    let _editor = open_with(&app, &w, &format!("g={g}"), 2, &[]).await;
    assert_eq!(watch_with(&app, &w, "", 1).await.status(), StatusCode::FORBIDDEN);
    let fresh = s.next_named(2, "grant").await.json()["g"].as_str().unwrap().to_owned();
    assert_ne!(fresh, g);
    let res = app.get(&format!("/{w}/raw?g={fresh}")).await;
    assert_eq!(body_text(res).await, "private text");
}

async fn assert_no_watch(app: &App, w: &str) {
    assert_eq!(watch_with(app, w, "", 1).await.status(), StatusCode::NOT_FOUND, "{w}: watch stream");
}

#[tokio::test]
async fn not_live_has_no_watch_stream() {
    let app = live_app().await;
    let readonly = create(&app, "hello", Privacy::Readonly).await;
    let secret = create_paste(&app, secret_paste()).await;
    let burns = create_paste(&app, NewPaste { burn_after_reads: 2, ..new("hello", Privacy::Public) }).await;
    let fixed = create_paste(&app, NewPaste { editable: false, ..new("hello", Privacy::Public) }).await;
    for w in [&readonly, &secret, &burns, &fixed] {
        assert_no_watch(&app, w).await;
    }
    assert_no_watch(&app, "happy-apple-banana").await;
    // No stream burned a read.
    assert_eq!(read_count(&app, &burns).await.0, 0);
    let off = support::app_with_timing("[app]\neditable = true\nlive_edit = false\n", timing()).await;
    let w = create(&off, "hello", Privacy::Public).await;
    assert_no_watch(&off, &w).await;
}

#[tokio::test]
async fn the_17th_stream_from_one_address_is_429() {
    let app = live_app().await;
    let a = create(&app, "hello", Privacy::Public).await;
    let b = create(&app, "world", Privacy::Public).await;
    let mut streams = Vec::new();
    for i in 0..8 {
        let w = if i % 2 == 0 { &a } else { &b };
        let editor = connect_with(&app, w, "", 7, &[]).await;
        assert_eq!(editor.status(), StatusCode::OK);
        let watcher = watch_with(&app, w, "", 7).await;
        assert_eq!(watcher.status(), StatusCode::OK);
        streams.extend([editor, watcher]);
    }
    assert_eq!(watch_with(&app, &a, "", 7).await.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(connect_with(&app, &b, "", 7, &[]).await.status(), StatusCode::TOO_MANY_REQUESTS);
    // Another address is not affected, and a stream that closes frees a place.
    assert_eq!(watch_with(&app, &a, "", 8).await.status(), StatusCode::OK);
    streams.pop();
    assert_eq!(watch_with(&app, &a, "", 7).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_sends_gone() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let mut s = watch(&app, &w, 1).await;
    s.next_named(0, "content").await;
    let res = app.post_form(&format!("/{w}/delete"), "").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let frames = s.read_to_end().await;
    assert_eq!(frames.last().unwrap(), &SseFrame { event: "gone".into(), id: None, data: "{}".into() });
}

#[tokio::test]
async fn kind_flip_sends_reload() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let mut s = watch(&app, &w, 1).await;
    s.next_named(0, "content").await;
    let res = app.post_form(&format!("/{w}/edit"), "content=https%3A%2F%2Fexample.org%2F").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let reload = s.next_named(2, "reload").await;
    assert_eq!(reload.data, "{}");
    // The stream stays open: the flip back reloads again.
    let res = app.post_form(&format!("/{w}/edit"), "content=text+again").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let from = s.frames.len();
    s.next_named(from, "reload").await;
}

#[tokio::test]
async fn a_url_paste_sends_live_and_no_content() {
    let app = live_app().await;
    let w = create(&app, "https://example.org/", Privacy::Public).await;
    let mut s = watch(&app, &w, 1).await;
    assert_eq!(s.nth(0).await.event, "live");
    let (_a, _) = join(&app, &w, 2).await;
    let frames = s.until(|f| f.iter().any(|x| x.json() == json!({"editors": 1}))).await;
    assert!(frames.iter().all(|f| f.event == "live"), "{frames:#?}");
}

#[tokio::test]
async fn head_joins_no_room() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let mut s = watch(&app, &w, 1).await;
    s.next_named(0, "content").await;
    for uri in [format!("/{w}/live/events"), format!("/{w}/events")] {
        let res = app.send(app.req("HEAD", &uri).body(Body::empty()).unwrap()).await;
        assert_eq!(res.status(), StatusCode::OK, "{uri}");
        assert!(res.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/event-stream"));
        assert_eq!(body_text(res).await, "");
    }
    assert_eq!(app.st.rooms.sessions(), 0, "a HEAD started a session");
    let (_a, _) = join(&app, &w, 2).await;
    let frames = s.until(|f| f.iter().any(|x| x.event == "live" && x.json()["editors"] == 1)).await;
    let names: Vec<&str> = frames.iter().map(|f| f.event.as_str()).collect();
    assert_eq!(names, ["live", "content", "live"], "{frames:#?}");
}

#[tokio::test]
async fn close_all_ends_every_stream() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let (mut editor, _) = join(&app, &w, 1).await;
    let mut watcher = watch(&app, &w, 2).await;
    watcher.next_named(0, "content").await;
    bitvault::domain::live::room::close_all(&app.st);
    editor.read_to_end().await;
    watcher.read_to_end().await;
    assert_eq!(connect_with(&app, &w, "", 3, &[]).await.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(watch_with(&app, &w, "", 3).await.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn an_oversized_or_far_behind_edit_is_refused() {
    let app = live_app().await;
    let w = create(&app, &"a".repeat(2000), Privacy::Public).await;
    let (mut s, init) = join(&app, &w, 1).await;
    let me = client(&init);
    // More parts than any edit has.
    let mut parts: Vec<Value> = (0..2049).flat_map(|_| [json!(1), json!("x")]).collect();
    parts.truncate(4097);
    assert_eq!(parts.len(), 4097);
    let oversized = json!({"seq": 1, "base": 0, "op": parts, "pos": 0});
    assert_eq!(post(&app, &w, &me, &oversized).await, StatusCode::UNPROCESSABLE_ENTITY);
    // 300 revisions from the form, then an edit of 4000 parts made against the first text.
    let id = bitvault::domain::words::parse(&w).unwrap();
    let ip = "10.0.0.2".parse().unwrap();
    for n in 0..300 {
        let text = format!("{}{n}", "a".repeat(2000));
        paste::edit(&app.st, id, paste::Access::Anonymous, ip, text, None, domain::now()).await.unwrap();
        // Read as they come: a stream that falls behind by more than its channel holds ends.
        s.until(|f| ops(f).len() > n).await;
    }
    let pairs = |tail: usize| {
        let mut op: Vec<Value> = (0..2000).flat_map(|_| [json!(1), json!("x")]).collect();
        if tail > 0 {
            op.push(json!(tail));
        }
        op
    };
    let behind = json!({"seq": 1, "base": 0, "op": pairs(0), "pos": 0});
    assert_eq!(post(&app, &w, &me, &behind).await, StatusCode::UNPROCESSABLE_ENTITY);
    // Neither took a revision or the seq: the same edit against the current text is applied.
    assert_eq!(ops(&s.frames).last().unwrap().json()["rev"], 300);
    let current = json!({"seq": 1, "base": 300, "op": pairs(3), "pos": 0});
    assert_eq!(post(&app, &w, &me, &current).await, StatusCode::NO_CONTENT);
    let op = s.next_named(s.frames.len(), "op").await.json();
    assert_eq!((op["rev"].clone(), op["seq"].clone()), (json!(301), json!(1)));
}

/// `HEAD` on a stream route from address `n`.
async fn head(app: &App, uri: &str, n: u32) -> StatusCode {
    app.send(app.req("HEAD", uri).header("x-forwarded-for", from(n)).body(Body::empty()).unwrap()).await.status()
}

#[tokio::test]
async fn head_answers_as_a_get_would_without_taking_a_place() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    let routes = [format!("/{w}/live/events"), format!("/{w}/events")];
    let mut streams = Vec::new();
    for _ in 0..15 {
        streams.push(watch_with(&app, &w, "", 7).await);
    }
    // Many HEADs at 15 open streams take none of the last place.
    for _ in 0..20 {
        for uri in &routes {
            assert_eq!(head(&app, uri, 7).await, StatusCode::OK, "{uri}");
        }
    }
    let last = watch_with(&app, &w, "", 7).await;
    assert_eq!(last.status(), StatusCode::OK);
    for uri in &routes {
        assert_eq!(head(&app, uri, 7).await, StatusCode::TOO_MANY_REQUESTS, "{uri}");
        assert_eq!(head(&app, uri, 8).await, StatusCode::OK, "{uri}");
    }
    bitvault::domain::live::room::close_all(&app.st);
    for uri in &routes {
        assert_eq!(head(&app, uri, 8).await, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
    }
}

#[tokio::test]
async fn a_stream_opened_from_another_site_is_refused() {
    let app = live_app().await;
    let w = create(&app, "hello", Privacy::Public).await;
    for site in ["cross-site", "same-site"] {
        let site = [("sec-fetch-site", site)];
        assert_eq!(connect_with(&app, &w, "", 1, &site).await.status(), StatusCode::FORBIDDEN);
        let r = app.req("GET", &format!("/{w}/events")).header("x-forwarded-for", from(1)).header(site[0].0, site[0].1);
        assert_eq!(app.send(r.body(Body::empty()).unwrap()).await.status(), StatusCode::FORBIDDEN);
        let r = app.req("HEAD", &format!("/{w}/events")).header(site[0].0, site[0].1);
        assert_eq!(app.send(r.body(Body::empty()).unwrap()).await.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(app.st.rooms.sessions(), 0, "a refused stream started a session");
    for site in ["same-origin", "none"] {
        let mut s = open_with(&app, &w, "", 1, &[("sec-fetch-site", site)]).await;
        assert_eq!(s.nth(0).await.event, "init");
        let r =
            app.req("GET", &format!("/{w}/events")).header("x-forwarded-for", from(1)).header("sec-fetch-site", site);
        assert_eq!(app.send(r.body(Body::empty()).unwrap()).await.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn a_stream_whose_client_stops_reading_ends_and_frees_its_place() {
    let app = support::app_with_timing(CONFIG, Timing { stall: Duration::from_millis(200), ..timing() }).await;
    let w = create(&app, "hello", Privacy::Public).await;
    let uri = format!("/{w}/events");
    // Never read: each has `live` and `content` to send, and the second is never taken.
    let mut stalled = Vec::new();
    for _ in 0..16 {
        let res = watch_with(&app, &w, "", 7).await;
        assert_eq!(res.status(), StatusCode::OK);
        stalled.push(res);
    }
    assert_eq!(head(&app, &uri, 7).await, StatusCode::TOO_MANY_REQUESTS);
    let start = std::time::Instant::now();
    let ip = from(7).parse().unwrap();
    while app.st.rooms.streams_from(ip) > 0 {
        assert!(start.elapsed() < Duration::from_secs(10), "the stalled streams kept their places");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(start.elapsed() >= Duration::from_millis(150), "freed after only {:?}", start.elapsed());
    assert_eq!(head(&app, &uri, 7).await, StatusCode::OK);
    // A stalled stream ends once read again, after what it had been handed.
    let frames = SseReader::new(stalled.pop().unwrap()).read_to_end().await.to_vec();
    assert_eq!(frames.iter().map(|f| f.event.as_str()).collect::<Vec<_>>(), ["live"], "{frames:#?}");
}

/// The page of a files-only paste on `app`.
async fn files_only_page(app: &App) -> String {
    let mut staging = bitvault::domain::files::Staging::new(&app.st.files_dir).unwrap();
    let body = futures_util::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"bytes"))]);
    staging.add("a.txt", "", body, u64::MAX).await.unwrap();
    let w = paste::create(&app.st, new("", Privacy::Public), Some(staging), domain::now()).await.unwrap().words();
    let res = app.get(&format!("/{w}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    body_text(res).await
}

#[tokio::test]
async fn a_live_page_without_text_has_a_hidden_place_for_it() {
    let html = files_only_page(&live_app().await).await;
    assert!(html.contains(r#"<pre class="paste-text" id="paste-text" hidden><code></code></pre>"#), "{html}");
    let off = support::app_with_timing("[app]\neditable = true\nlive_edit = false\n", timing()).await;
    let html = files_only_page(&off).await;
    assert!(!html.contains("paste-text"), "{html}");
}
