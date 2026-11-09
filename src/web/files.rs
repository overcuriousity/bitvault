//! File and zip downloads. `files::open` and `files::zip` apply no access rules, so
//! `paste::files_access` decides first (liveness and expiry, grants for private and burned
//! pastes); this module adds that secret pastes have no zip.

use std::net::IpAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use super::paste_id;
use crate::domain::crypto::Dek;
use crate::domain::files::{self, FileMeta, PLACEHOLDER_MIME};
use crate::domain::paste::{self, Access, Paste};
use crate::domain::words::PasteId;
use crate::domain::{self, Privacy};
use crate::error::Error;
use crate::security::ClientIp;
use crate::state::AppState;

/// Only these types are shown in the browser; anything else (SVG and HTML included, which can
/// carry script) is a download.
const INLINE_TYPES: [&str; 5] = ["image/png", "image/jpeg", "image/gif", "image/webp", "image/avif"];

pub fn inline_image(mime: &str) -> bool {
    INLINE_TYPES.contains(&mime)
}

#[derive(Debug, Default, Deserialize)]
pub struct GrantQuery {
    pub g: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/{words}/file/{position}", get(file)).route("/{words}/zip", get(zip))
}

/// The domain's file access rules, with a grant from the query string when there is one.
async fn access(st: &AppState, id: PasteId, ip: IpAddr, g: Option<String>) -> Result<(Paste, Option<Dek>), Error> {
    paste::files_access(st, id, g.map_or(Access::Anonymous, Access::Grant), ip, domain::now()).await
}

pub fn position(raw: &str) -> Result<u32, Error> {
    raw.parse().map_err(|_| Error::NotFound)
}

/// RFC 6266: an ASCII fallback plus the UTF-8 name, so no name can break out of the header.
fn disposition(kind: &str, name: &str) -> Result<HeaderValue, Error> {
    let fallback: String =
        name.chars().map(|c| if c.is_ascii_graphic() && !matches!(c, '"' | '\\' | '%') { c } else { '_' }).collect();
    let mut encoded = String::with_capacity(name.len());
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
            encoded.push(char::from(b));
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    HeaderValue::from_str(&format!("{kind}; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"))
        .map_err(Error::internal)
}

/// `GET /{words}/file/{position}`.
async fn file(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((words, position_raw)): Path<(String, String)>,
    Query(q): Query<GrantQuery>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let position = position(&position_raw)?;
    let (p, dek) = access(&st, id, ip, q.g).await?;
    let (meta, body) = files::open(&st, id, position, dek.as_ref()).await?;
    download(&p, &meta, body)
}

/// A file download: raster images inline, everything else (and every secret file, which is
/// ciphertext) as an attachment, never cached.
pub fn download(p: &Paste, meta: &FileMeta, body: Body) -> Result<Response, Error> {
    let (content_type, kind) = if p.privacy == Privacy::Secret {
        (PLACEHOLDER_MIME, "attachment")
    } else if inline_image(&meta.mime) {
        (meta.mime.as_str(), "inline")
    } else {
        (meta.mime.as_str(), "attachment")
    };
    let content_type = HeaderValue::from_str(content_type).unwrap_or(HeaderValue::from_static(PLACEHOLDER_MIME));
    let headers = [
        (header::CONTENT_TYPE, content_type),
        (header::CONTENT_DISPOSITION, disposition(kind, &meta.name)?),
        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
    ];
    // A body that fails to decrypt part-way ends in an error, so the client sees a broken transfer.
    Ok((headers, body).into_response())
}

/// `GET /{words}/zip`: every file of the paste; never for secret pastes, whose files only the
/// browser can open.
async fn zip(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(words): Path<String>,
    Query(q): Query<GrantQuery>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let (p, dek) = access(&st, id, ip, q.g).await?;
    if p.privacy == Privacy::Secret || p.files.is_empty() {
        return Err(Error::NotFound);
    }
    let body = files::zip(&st, id, dek.as_ref()).await?;
    let headers = [
        (header::CONTENT_TYPE, HeaderValue::from_static("application/zip")),
        (header::CONTENT_DISPOSITION, disposition("attachment", &format!("{}.zip", id.words()))?),
        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
    ];
    Ok((headers, body).into_response())
}
