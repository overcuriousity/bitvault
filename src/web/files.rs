//! File and zip downloads. `files::open` and `files::zip` apply no access rules, so every rule
//! is enforced here before they are called: liveness and expiry, grants for private and burned
//! pastes, and no zip for secret pastes.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use super::paste_id;
use crate::domain::crypto::Dek;
use crate::domain::files::{self, PLACEHOLDER_MIME};
use crate::domain::paste::{self, Paste};
use crate::domain::words::PasteId;
use crate::domain::{self, Privacy, grant};
use crate::error::Error;
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

/// The paste whose files may be served, and the data key to decrypt them with.
///
/// - A live paste of a plaintext level, or a secret paste (served as ciphertext): no grant needed.
/// - A private paste: a grant carrying its data key; without one, 401.
/// - A burned paste: only with a valid grant, within its ten minutes; otherwise not found.
async fn access(st: &AppState, id: PasteId, g: Option<&str>) -> Result<(Paste, Option<Dek>), Error> {
    let now = domain::now();
    let Some(token) = g else {
        let p = paste::meta(st, id, now).await?;
        if p.privacy == Privacy::Private {
            return Err(Error::PasswordRequired);
        }
        return Ok((p, None));
    };
    let dek = grant::check(&st.grant_key, token, id, now)?;
    let p = paste::meta_for_grant(st, id, now).await?;
    if p.privacy == Privacy::Private && dek.is_none() {
        return Err(Error::Forbidden);
    }
    Ok((p, dek))
}

fn position(raw: &str) -> Result<u32, Error> {
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
    Path((words, position_raw)): Path<(String, String)>,
    Query(q): Query<GrantQuery>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let position = position(&position_raw)?;
    let (p, dek) = access(&st, id, q.g.as_deref()).await?;
    let (meta, body) = files::open(&st, id, position, dek.as_ref()).await?;
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
    Path(words): Path<String>,
    Query(q): Query<GrantQuery>,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let (p, dek) = access(&st, id, q.g.as_deref()).await?;
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
