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
fn the_failure_limiter_ignores_successes_and_separates_addresses() {
    let limiter = RateLimiter::new(10, 5);
    let a: IpAddr = "192.0.2.1".parse().unwrap();
    let b: IpAddr = "192.0.2.2".parse().unwrap();
    for _ in 0..20 {
        limiter.check(a).unwrap();
    }
    for _ in 0..5 {
        limiter.fail(a);
    }
    assert!(limiter.check(a).is_err());
    assert!(limiter.check(b).is_ok());
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
