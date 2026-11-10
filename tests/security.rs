#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, post};
use bitvault::ratelimit::{self, RateLimiter};
use bitvault::security::{self, ClientIp};
use bitvault::state::AppState;
use support::{App, app, app_with_routes, body_text};

fn test_routes() -> Router<AppState> {
    Router::new()
        .route("/test/sink", post(|_body: Bytes| async { StatusCode::OK }))
        .route("/test/ip", get(|ip: ClientIp| async move { ip.0.to_string() }))
        .route("/test/limited", get(|| async { "ok" }).layer(ratelimit::layer(Arc::new(RateLimiter::new(60, 2)))))
}

async fn app_with_test_routes(toml: &str) -> App {
    app_with_routes(toml, test_routes()).await
}

fn with_host(mut r: Request<Body>, host: &str) -> Request<Body> {
    r.headers_mut().insert(header::HOST, host.parse().unwrap());
    r
}

fn plain(r: axum::http::request::Builder) -> Request<Body> {
    r.body(Body::empty()).unwrap()
}

/// A POST with only the headers given, so each test controls Origin, Sec-Fetch-Site and Cookie.
fn bare_post(headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder().method("POST").uri("/test/sink").header(header::HOST, "localhost:8080");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    plain(b)
}

#[tokio::test]
async fn html_responses_carry_the_manifest_csp_and_headers() {
    let app = app().await;
    let res = app.get("/").await;
    assert_eq!(res.status(), StatusCode::OK);
    let h = res.headers();
    assert_eq!(h[header::CONTENT_SECURITY_POLICY], security::CSP);
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(h["cross-origin-opener-policy"], "same-origin");
    assert!(!h.contains_key(header::STRICT_TRANSPORT_SECURITY));
}

#[tokio::test]
async fn the_csp_is_sent_on_html_only() {
    let app = app_with_test_routes("").await;
    let res = app.send(plain(app.req("GET", "/test/ip"))).await;
    assert!(!res.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    assert_eq!(res.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
}

#[tokio::test]
async fn hsts_is_sent_when_the_public_url_is_https() {
    let app = app_with_test_routes("public_url = \"https://vault.example\"").await;
    let res = app.send(with_host(plain(app.req("GET", "/")), "vault.example")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::STRICT_TRANSPORT_SECURITY], "max-age=63072000");
}

#[tokio::test]
async fn a_foreign_host_gets_421() {
    let app = app().await;
    let res = app.send(with_host(plain(app.req("GET", "/")), "evil.example")).await;
    assert_eq!(res.status(), StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(body_text(res).await, "This server does not answer for that host name.");
}

#[tokio::test]
async fn the_short_host_is_accepted() {
    let app =
        app_with_test_routes("public_url = \"https://vault.example\"\n[app]\nshort_url = \"https://s.example\"").await;
    let res = app.send(with_host(plain(app.req("GET", "/")), "s.example")).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn cross_site_posts_are_refused() {
    let app = app_with_test_routes("").await;
    let res = app.send(bare_post(&[("origin", "https://evil.example")])).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_text(res).await, "This request came from another site and was blocked.");
}

#[tokio::test]
async fn origin_null_falls_back_to_sec_fetch_site() {
    let app = app_with_test_routes("").await;
    let same = app.send(bare_post(&[("origin", "null"), ("sec-fetch-site", "same-origin")])).await;
    assert_eq!(same.status(), StatusCode::OK);
    let cross = app.send(bare_post(&[("origin", "null"), ("sec-fetch-site", "cross-site")])).await;
    assert_eq!(cross.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn posts_without_origin_or_fetch_metadata_are_allowed_only_without_cookies() {
    let app = app_with_test_routes("").await;
    assert_eq!(app.send(bare_post(&[])).await.status(), StatusCode::OK);
    assert_eq!(app.send(bare_post(&[("cookie", "a=b")])).await.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn forwarded_for_is_trusted_only_from_trusted_proxies() {
    let app = app_with_test_routes("trusted_proxies = [\"127.0.0.1/32\"]").await;
    let r = plain(app.req("GET", "/test/ip").header("x-forwarded-for", "203.0.113.9"));
    assert_eq!(body_text(app.send(r).await).await, "203.0.113.9");

    let app = app_with_test_routes("trusted_proxies = []").await;
    let r = plain(app.req("GET", "/test/ip").header("x-forwarded-for", "203.0.113.9"));
    assert_eq!(body_text(app.send(r).await).await, "127.0.0.1");
}

#[tokio::test]
async fn forwarded_for_skips_trusted_hops_from_the_right() {
    let app = app_with_test_routes("trusted_proxies = [\"127.0.0.1/32\", \"10.0.0.0/8\"]").await;
    let r = plain(app.req("GET", "/test/ip").header("x-forwarded-for", "198.51.100.1, 203.0.113.9, 10.1.1.1"));
    assert_eq!(body_text(app.send(r).await).await, "203.0.113.9");
}

#[tokio::test]
async fn non_upload_routes_refuse_bodies_over_one_mebibyte() {
    let app = app_with_test_routes("").await;
    let r = app
        .req("POST", "/test/sink")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(vec![0u8; 3 << 19]))
        .unwrap();
    assert_eq!(app.send(r).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let r = app.req("POST", "/test/sink").body(Body::from(vec![0u8; 1 << 19])).unwrap();
    assert_eq!(app.send(r).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_rate_limit_layer_answers_429_after_the_burst() {
    let app = app_with_test_routes("").await;
    for _ in 0..2 {
        assert_eq!(app.send(plain(app.req("GET", "/test/limited"))).await.status(), StatusCode::OK);
    }
    let res = app.send(plain(app.req("GET", "/test/limited"))).await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_text(res).await, "Too many requests. Wait a minute and try again.");
}

#[test]
fn refunded_tokens_cost_nothing_and_addresses_are_separate() {
    let limiter = RateLimiter::new(10, 5);
    let a: IpAddr = "192.0.2.1".parse().unwrap();
    let b: IpAddr = "192.0.2.2".parse().unwrap();
    for _ in 0..20 {
        limiter.take(a).unwrap();
        limiter.refund(a);
    }
    for _ in 0..5 {
        limiter.take(a).unwrap();
    }
    assert!(limiter.take(a).is_err());
    assert!(limiter.take(b).is_ok());
}

#[test]
fn a_refund_never_raises_a_bucket_above_its_burst() {
    let limiter = RateLimiter::new(10, 2);
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    for _ in 0..10 {
        limiter.refund(ip);
    }
    assert!(limiter.take(ip).is_ok());
    assert!(limiter.take(ip).is_ok());
    assert!(limiter.take(ip).is_err());
}

#[test]
fn ipv6_clients_share_a_bucket_per_64_and_ipv4_stays_per_address() {
    let limiter = RateLimiter::new(10, 2);
    let first: IpAddr = "2001:db8:1:2::1".parse().unwrap();
    let same_64: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
    let next_64: IpAddr = "2001:db8:1:3::1".parse().unwrap();
    limiter.take(first).unwrap();
    limiter.take(same_64).unwrap();
    assert!(limiter.take(first).is_err());
    assert!(limiter.take(next_64).is_ok());

    let v4: IpAddr = "192.0.2.1".parse().unwrap();
    let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
    let neighbour: IpAddr = "192.0.2.2".parse().unwrap();
    limiter.take(v4).unwrap();
    limiter.take(mapped).unwrap();
    assert!(limiter.take(v4).is_err(), "a mapped IPv4 address counts as that address");
    assert!(limiter.take(neighbour).is_ok());
    assert_eq!(ratelimit::bucket_key(mapped), v4);
}

#[test]
fn take_consumes_a_token_and_refuses_when_empty() {
    let limiter = RateLimiter::new(60, 2);
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    assert!(limiter.take(ip).is_ok());
    assert!(limiter.take(ip).is_ok());
    assert!(limiter.take(ip).is_err());
}

#[tokio::test]
async fn limited_wraps_a_group_in_a_body_limit() {
    let router = security::limited(
        Router::new().route("/", post(|_b: Bytes| async { StatusCode::OK })),
        16,
        Duration::from_secs(5),
    );
    let res = tower::ServiceExt::oneshot(
        router,
        Request::builder().method("POST").uri("/").body(Body::from(vec![0u8; 64])).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_forwarded_host_cannot_stand_in_for_the_host_header() {
    let app = app_with_test_routes("").await;
    let r = plain(app.req("GET", "/test/ip").header("x-forwarded-host", "localhost:8080"));
    let res = app.send(with_host(r, "evil.example")).await;
    assert_eq!(res.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn an_unparseable_forwarded_hop_falls_back_to_the_peer() {
    let app = app_with_test_routes("trusted_proxies = [\"127.0.0.1/32\"]").await;
    let r = plain(app.req("GET", "/test/ip").header("x-forwarded-for", "198.51.100.1, 203.0.113.9:4000"));
    assert_eq!(body_text(app.send(r).await).await, "127.0.0.1");
}

/// Collects everything a fmt subscriber writes.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs on its own current-thread runtime inside a scoped subscriber, so nothing here depends on a
/// global subscriber or on what tests running in parallel have registered.
#[test]
fn request_traces_carry_the_path_but_never_the_query() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let app = app_with_test_routes("").await;
            // Callsites that parallel tests reached first cached "no interest"; ask again, now that
            // this thread's subscriber exists and the app is built.
            tracing::callsite::rebuild_interest_cache();
            let res = app.send(plain(app.req("GET", "/test/ip?g=GRANT-MUST-NOT-BE-LOGGED&x=1"))).await;
            assert_eq!(res.status(), StatusCode::OK);
        });
    });
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("path=/test/ip"), "{logs}");
    assert!(!logs.contains("GRANT-MUST-NOT-BE-LOGGED"), "{logs}");
}

/// Plain HTTP on a LAN address, with no `public_url`.
const PLAIN: &str = "insecure_http = true\nbind = \"0.0.0.0:8080\"\n";
const LAN_HOST: &str = "192.168.1.5:8080";

/// A POST to the sink on `host` carrying `origin`.
fn post_from(host: &str, origin: &str) -> Request<Body> {
    plain(Request::builder().method("POST").uri("/test/sink").header(header::HOST, host).header(header::ORIGIN, origin))
}

#[tokio::test]
async fn loopback_on_port_80_accepts_the_origin_browsers_send() {
    let app = app_with_test_routes("bind = \"127.0.0.1:80\"\n").await;
    // A browser leaves the default port out of both Host and Origin.
    for (host, origin) in [("localhost", "http://localhost"), ("127.0.0.1", "http://127.0.0.1")] {
        assert_eq!(app.send(post_from(host, origin)).await.status(), StatusCode::OK, "{origin}");
    }
    assert_eq!(app.send(post_from("localhost", "http://localhost:80")).await.status(), StatusCode::OK);
    for origin in ["http://localhost:8080", "https://localhost", "http://evil.example"] {
        assert_eq!(app.send(post_from("localhost", origin)).await.status(), StatusCode::FORBIDDEN, "{origin}");
    }
    // Any other port keeps needing it.
    let app = app_with_test_routes("").await;
    assert_eq!(app.send(post_from("localhost:8080", "http://localhost")).await.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn plain_http_answers_any_host_without_hsts() {
    let app = app_with_test_routes(PLAIN).await;
    for host in [LAN_HOST, "bitvault.lan", "localhost:8080"] {
        let res = app.send(with_host(plain(app.req("GET", "/")), host)).await;
        assert_eq!(res.status(), StatusCode::OK, "{host}");
        assert!(!res.headers().contains_key(header::STRICT_TRANSPORT_SECURITY), "{host}");
    }
}

#[tokio::test]
async fn the_referrer_policy_is_no_referrer_by_default_and_same_origin_over_plain_http() {
    let app = app().await;
    assert_eq!(app.get("/").await.headers()[header::REFERRER_POLICY], "no-referrer");
    let plain_app = app_with_test_routes(PLAIN).await;
    let res = plain_app.send(with_host(plain(plain_app.req("GET", "/")), LAN_HOST)).await;
    assert_eq!(res.headers()[header::REFERRER_POLICY], "same-origin");
}

#[tokio::test]
async fn plain_http_still_refuses_a_host_that_is_not_a_host_name() {
    let app = app_with_test_routes(PLAIN).await;
    for host in ["evil.example/x", "a\"b", "user@evil.example", "a b", ""] {
        let res = app.send(with_host(plain(app.req("GET", "/")), host)).await;
        assert_eq!(res.status(), StatusCode::MISDIRECTED_REQUEST, "{host:?}");
    }
}

#[tokio::test]
async fn plain_http_checks_the_origin_against_the_request_host() {
    let app = app_with_test_routes(PLAIN).await;
    let same = app.send(post_from(LAN_HOST, "http://192.168.1.5:8080")).await;
    assert_eq!(same.status(), StatusCode::OK);
    for origin in ["http://192.168.1.6:8080", "https://192.168.1.5:8080", "http://192.168.1.5", "http://evil.example"] {
        let res = app.send(post_from(LAN_HOST, origin)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{origin}");
    }
    let null = plain(
        Request::builder()
            .method("POST")
            .uri("/test/sink")
            .header(header::HOST, LAN_HOST)
            .header(header::ORIGIN, "null")
            .header("sec-fetch-site", "cross-site"),
    );
    assert_eq!(app.send(null).await.status(), StatusCode::FORBIDDEN);
    let cookie_only = plain(
        Request::builder().method("POST").uri("/test/sink").header(header::HOST, LAN_HOST).header("cookie", "a=b"),
    );
    assert_eq!(app.send(cookie_only).await.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn plain_http_with_a_public_url_also_accepts_its_origin_and_sends_no_hsts() {
    let app = app_with_test_routes("insecure_http = true\npublic_url = \"https://vault.example\"\n").await;
    let res = app.send(with_host(plain(app.req("GET", "/")), "vault.example")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!res.headers().contains_key(header::STRICT_TRANSPORT_SECURITY));
    assert_eq!(app.send(post_from(LAN_HOST, "https://vault.example")).await.status(), StatusCode::OK);
    assert_eq!(app.send(post_from(LAN_HOST, "http://192.168.1.5:8080")).await.status(), StatusCode::OK);
    assert_eq!(app.send(post_from(LAN_HOST, "http://evil.example")).await.status(), StatusCode::FORBIDDEN);
}
