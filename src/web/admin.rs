//! Single-admin sign-in, the session extractor and the admin table.

use std::convert::Infallible;
use std::sync::Arc;

use askama::Template;
use axum::Form;
use axum::Router;
use axum::extract::{FromRequestParts, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use super::{DeletedQuery, Extras, Paged, TimeView, date, icon, page, page_with, privacy_label, render, size};
use crate::assets::Assets;
use crate::config::Config;
use crate::domain::admin::{COOKIE, PLAIN_COOKIE};
use crate::domain::expiry::{self, Expiry};
use crate::domain::{self, paste};
use crate::error::Error;
use crate::ratelimit::{self, RateLimiter};
use crate::security::ClientIp;
use crate::state::AppState;

/// Whether the request carries a valid admin session. Never fails: no session is `MaybeAdmin(false)`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaybeAdmin(pub bool);

/// The admin-session extractor of the plan's interface.
pub type AdminSession = MaybeAdmin;

impl FromRequestParts<AppState> for MaybeAdmin {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Infallible> {
        // The session layer has already checked (and slid) the session for this request.
        if let Some(found) = parts.extensions.get::<MaybeAdmin>() {
            return Ok(*found);
        }
        Ok(MaybeAdmin(valid(st, &parts.headers)))
    }
}

/// The session cookie's name in this mode; only that name is read.
fn cookie_name(st: &AppState) -> &'static str {
    if st.dep.plain_http { PLAIN_COOKIE } else { COOKIE }
}

fn token<'h>(st: &AppState, headers: &'h HeaderMap) -> Option<&'h str> {
    let name = cookie_name(st);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(name)?.strip_prefix('='))
        .filter(|t| !t.is_empty())
}

fn valid(st: &AppState, headers: &HeaderMap) -> bool {
    match (&st.admin, token(st, headers)) {
        (Some(auth), Some(t)) => auth.is_valid(t, domain::now()),
        _ => false,
    }
}

/// Marks the request with its session state and keeps admin responses out of every cache.
pub async fn session(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let admin = valid(&st, req.headers());
    req.extensions_mut().insert(MaybeAdmin(admin));
    let mut res = next.run(req).await;
    if admin {
        res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

/// The admin routes, or none at all when no admin password is configured.
pub fn routes(st: &AppState) -> Router<AppState> {
    if st.admin.is_none() {
        return Router::new();
    }
    let limiter = Arc::new(RateLimiter::new(10, 5));
    Router::new()
        .route("/admin", get(table))
        .route("/admin/sign-in", get(sign_in_form))
        .route("/admin/sign-in", post(sign_in).layer(ratelimit::layer(limiter)))
        .route("/admin/sign-out", post(sign_out))
}

#[derive(Template)]
#[template(path = "sign_in.html")]
struct SignIn {
    notice: Option<String>,
}

fn sign_in_page(st: &AppState, notice: Option<String>, status: StatusCode) -> Result<Response, Error> {
    let body = render(&SignIn { notice })?;
    Ok((status, page(st, false, "", "Sign in", body)?).into_response())
}

async fn sign_in_form(State(st): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Result<Response, Error> {
    if admin {
        return Ok(Redirect::to("/admin").into_response());
    }
    sign_in_page(&st, None, StatusCode::OK)
}

#[derive(Deserialize)]
struct SignInForm {
    #[serde(default)]
    password: String,
}

fn cookie(st: &AppState, value: &str, max_age: Option<u32>) -> Result<HeaderValue, Error> {
    let age = max_age.map(|a| format!("; Max-Age={a}")).unwrap_or_default();
    let secure = if st.dep.plain_http { "" } else { "; Secure" };
    let name = cookie_name(st);
    HeaderValue::from_str(&format!("{name}={value}; HttpOnly{secure}; SameSite=Lax; Path=/{age}"))
        .map_err(Error::internal)
}

async fn sign_in(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Form(form): Form<SignInForm>,
) -> Result<Response, Error> {
    let Some(auth) = st.admin.clone() else { return Err(Error::NotFound) };
    // Taken before the slow check so parallel guesses cannot outrun the limit; a right password
    // gets its token back.
    st.failures.take(ip)?;
    match auth.sign_in(&form.password, domain::now()).await {
        Some(token) => {
            st.failures.refund(ip);
            // A session cookie: the server ends the session after 12 idle hours.
            let mut res = Redirect::to("/admin").into_response();
            res.headers_mut().insert(header::SET_COOKIE, cookie(&st, &token, None)?);
            // The request carried no session yet, so the session layer does not add this.
            res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok(res)
        }
        None => {
            let notice = "That password is not right. Check it and try again.".to_owned();
            sign_in_page(&st, Some(notice), StatusCode::FORBIDDEN)
        }
    }
}

async fn sign_out(State(st): State<AppState>, headers: HeaderMap) -> Result<Response, Error> {
    if let (Some(auth), Some(t)) = (&st.admin, token(&st, &headers)) {
        auth.sign_out(t);
    }
    let mut res = Redirect::to("/").into_response();
    res.headers_mut().insert(header::SET_COOKIE, cookie(&st, "", Some(0))?);
    Ok(res)
}

struct Row {
    words: String,
    privacy: &'static str,
    kind: &'static str,
    size: String,
    files: usize,
    created: String,
    expires: Option<TimeView>,
    editable: bool,
    reads: u64,
    last_read: Option<TimeView>,
}

/// The non-secret effective settings, as term and value. Passwords only show whether they are set.
fn settings(cfg: &Config) -> Vec<(&'static str, String)> {
    let app = &cfg.app;
    let yes = |on: bool| if on { "on" } else { "off" }.to_owned();
    let expiry = |value: &str| Expiry::parse(value).map_or_else(|| value.to_owned(), |e| e.label().to_owned());
    let mb = |n: u64| format!("{n} MB");
    vec![
        ("Listing", yes(app.listing)),
        ("Editing by default", yes(app.editable)),
        ("Syntax highlighting", yes(app.highlight)),
        ("QR codes", yes(app.qr)),
        ("Read statistics", yes(app.read_stats)),
        ("Privacy levels", cfg.offered_levels().join(", ")),
        ("Default expiry", expiry(&app.default_expiry)),
        ("Longest expiry", expiry::max(app).label().to_owned()),
        ("Largest upload", mb(app.max_file_mb)),
        ("Largest secret file", mb(app.max_secret_file_mb)),
        ("Short address", app.short_url.clone().unwrap_or_else(|| "none".into())),
        ("Translate service", app.translate_url.clone().unwrap_or_else(|| "none".into())),
        ("Uploader password", yes(app.uploader_password.is_some())),
        ("Plain HTTP", yes(cfg.insecure_http)),
    ]
}

#[derive(Template)]
#[template(path = "admin.html")]
struct Table {
    rows: Vec<Row>,
    deleted: Option<String>,
    count: u64,
    newer: Option<u32>,
    older: Option<u32>,
    content_size: String,
    file_size: String,
    trash: String,
    version: &'static str,
    settings: Vec<(&'static str, String)>,
}

async fn table(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    Query(q): Query<DeletedQuery>,
    Paged(number): Paged,
) -> Result<Response, Error> {
    if !admin {
        return Ok(Redirect::to("/admin/sign-in").into_response());
    }
    let now = domain::now();
    let (pastes, totals) = tokio::try_join!(paste::list_all(&st, number, now), paste::totals(&st, now))?;
    let (newer, older) = super::neighbours(number, pastes.len());
    let rows = pastes
        .iter()
        .map(|p| Row {
            words: p.id.words(),
            privacy: privacy_label(p.privacy),
            kind: if p.kind == domain::Kind::Url { "Link" } else { "Text" },
            size: size(p.content_len + p.files.iter().map(|f| f.size).sum::<u64>()),
            files: p.files.len(),
            created: date(p.created_at),
            expires: TimeView::expiry(p.expires_at, now),
            editable: p.editable,
            reads: p.read_count,
            last_read: p.last_read_at.map(|t| TimeView::new(t, now, "ago")),
        })
        .collect();
    let body = render(&Table {
        count: totals.pastes,
        newer,
        older,
        rows,
        deleted: q.notice(),
        content_size: size(totals.content_bytes),
        file_size: size(totals.file_bytes),
        trash: icon("trash-2", super::IconSize::Row),
        version: env!("CARGO_PKG_VERSION"),
        settings: settings(&st.cfg),
    })?;
    let extras = Extras { js: vec![Assets::url("js/paste.js")], ..Extras::default() };
    Ok(page_with(&st, true, "admin", "Admin", body, extras)?.into_response())
}
