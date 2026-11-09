//! Headers, host and origin checks, client address, and per-group body limits.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;
use tower_http::compression::CompressionLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::deployment::Deployment;
use crate::error::Error;

pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The caller's address: the TCP peer, or the right-most untrusted `X-Forwarded-For` hop when the peer is a trusted proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ClientIp>()
            .copied()
            .ok_or_else(|| Error::Internal("ClientIp requires the security layer and connection info.".into()))
    }
}

struct Ctx {
    dep: Arc<Deployment>,
    proxies: Vec<IpNet>,
}

fn peer(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .or_else(|| parts.extensions.get::<MockConnectInfo<SocketAddr>>().map(|c| c.0.ip()))
}

fn trusted(proxies: &[IpNet], ip: &IpAddr) -> bool {
    proxies.iter().any(|n| n.contains(ip))
}

fn resolve(parts: &Parts, proxies: &[IpNet]) -> Option<IpAddr> {
    let peer = peer(parts)?;
    if !trusted(proxies, &peer) {
        return Some(peer);
    }
    // Walk from the right: the first hop that is not a trusted proxy is the client. An entry that
    // does not parse cannot be vouched for, and anything left of it is attacker-controlled.
    let hops = parts
        .headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .collect::<Vec<_>>();
    for hop in hops.into_iter().rev() {
        match hop.trim().parse::<IpAddr>() {
            Ok(ip) if trusted(proxies, &ip) => {}
            Ok(ip) => return Some(ip),
            Err(_) => break,
        }
    }
    Some(peer)
}

async fn headers(State(ctx): State<Arc<Ctx>>, req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let is_html = h.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("text/html"));
    if is_html {
        h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    }
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    if ctx.dep.secure {
        h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=63072000"));
    }
    res
}

async fn host_check(State(ctx): State<Arc<Ctx>>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    // Only `Host` counts: a proxy-supplied X-Forwarded-Host could be forged by the client.
    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| parts.uri.authority().map(|a| a.as_str()));
    if !host.is_some_and(|h| ctx.dep.host_allowed(h)) {
        return (StatusCode::MISDIRECTED_REQUEST, "This server does not answer for that host name.").into_response();
    }
    if let Some(ip) = resolve(&parts, &ctx.proxies) {
        parts.extensions.insert(ClientIp(ip));
    }
    next.run(Request::from_parts(parts, body)).await
}

/// Cookie-authenticated writes must come from our own origin. Clients that send neither `Origin`
/// nor `Sec-Fetch-Site` (scripts, curl) pass only when they carry no cookie.
async fn origin_check(State(ctx): State<Arc<Ctx>>, req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    let h = req.headers();
    // `Referrer-Policy: no-referrer` makes browsers send `Origin: null` on same-origin form posts,
    // so "null" counts as absent and Sec-Fetch-Site decides.
    let origin = h.get(header::ORIGIN).and_then(|v| v.to_str().ok()).filter(|o| *o != "null");
    let site = h.get("sec-fetch-site").and_then(|v| v.to_str().ok());
    let allowed = match (origin, site) {
        (Some(o), _) if !ctx.dep.origin_allowed(o) => false,
        (_, Some(s)) => matches!(s, "same-origin" | "none"),
        (Some(_), None) => true,
        (None, None) => !h.contains_key(header::COOKIE),
    };
    if allowed {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "This request came from another site and was blocked.").into_response()
    }
}

/// Wraps the whole app, outermost first: header redaction, trace, response headers, host check, origin check, compression.
pub fn secure(router: Router, dep: Arc<Deployment>, proxies: Vec<IpNet>) -> Router {
    let ctx = Arc::new(Ctx { dep, proxies });
    router
        .layer(CompressionLayer::new())
        .layer(from_fn_with_state(ctx.clone(), origin_check))
        .layer(from_fn_with_state(ctx.clone(), host_check))
        .layer(from_fn_with_state(ctx, headers))
        .layer(TraceLayer::new_for_http())
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
            header::HeaderName::from_static("x-paste-password"),
            header::HeaderName::from_static("x-paste-verifier"),
            header::HeaderName::from_static("x-uploader-password"),
            header::HeaderName::from_static("x-paste-grant"),
        ]))
}

/// Caps one route group's request body and the time to produce its response headers.
pub fn limited(router: Router, body_bytes: usize, timeout: Duration) -> Router {
    router
        .layer(RequestBodyLimitLayer::new(body_bytes))
        .layer(DefaultBodyLimit::disable())
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, timeout))
}
