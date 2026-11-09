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

use super::{DeletedQuery, date, icon, page, privacy_label, render, size};
use crate::domain::admin::COOKIE;
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

fn token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(COOKIE)?.strip_prefix('='))
        .filter(|t| !t.is_empty())
}

fn valid(st: &AppState, headers: &HeaderMap) -> bool {
    match (&st.admin, token(headers)) {
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

fn cookie(value: &str, max_age: Option<u32>) -> Result<HeaderValue, Error> {
    let age = max_age.map(|a| format!("; Max-Age={a}")).unwrap_or_default();
    HeaderValue::from_str(&format!("{COOKIE}={value}; HttpOnly; Secure; SameSite=Lax; Path=/{age}"))
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
            res.headers_mut().insert(header::SET_COOKIE, cookie(&token, None)?);
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
    if let (Some(auth), Some(t)) = (&st.admin, token(&headers)) {
        auth.sign_out(t);
    }
    let mut res = Redirect::to("/").into_response();
    res.headers_mut().insert(header::SET_COOKIE, cookie("", Some(0))?);
    Ok(res)
}

struct Row {
    words: String,
    privacy: &'static str,
    kind: &'static str,
    size: String,
    files: usize,
    created: String,
    expires: String,
    reads: u64,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct Table {
    rows: Vec<Row>,
    deleted: Option<String>,
    count: usize,
    content_size: String,
    file_size: String,
    trash: String,
}

async fn table(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    Query(q): Query<DeletedQuery>,
) -> Result<Response, Error> {
    if !admin {
        return Ok(Redirect::to("/admin/sign-in").into_response());
    }
    let pastes = paste::list_all(&st, domain::now()).await?;
    let content: u64 = pastes.iter().map(|p| p.content.len() as u64).sum();
    let files: u64 = pastes.iter().flat_map(|p| &p.files).map(|f| f.size).sum();
    let rows = pastes
        .iter()
        .map(|p| Row {
            words: p.id.words(),
            privacy: privacy_label(p.privacy),
            kind: if p.kind == domain::Kind::Url { "Link" } else { "Text" },
            size: size(p.content.len() as u64 + p.files.iter().map(|f| f.size).sum::<u64>()),
            files: p.files.len(),
            created: date(p.created_at),
            expires: p.expires_at.map_or_else(|| "Never".to_owned(), date),
            reads: p.read_count,
        })
        .collect();
    let body = render(&Table {
        count: pastes.len(),
        rows,
        deleted: q.notice(),
        content_size: size(content),
        file_size: size(files),
        trash: icon("trash-2", super::IconSize::Row),
    })?;
    Ok(page(&st, true, "admin", "Admin", body)?.into_response())
}
