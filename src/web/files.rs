//! File and zip downloads. `files::open` and `files::zip` apply no access rules, so
//! `paste::files_access` decides first (liveness and expiry, grants for private and burned
//! pastes); this module adds that secret pastes have no zip.

use std::net::IpAddr;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use super::paste_id;
use crate::domain::crypto::Dek;
use crate::domain::files::{self, PLACEHOLDER_MIME};
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
    headers: HeaderMap,
) -> Result<Response, Error> {
    let id = paste_id(&words)?;
    let position = position(&position_raw)?;
    let (p, dek) = access(&st, id, ip, q.g).await?;
    download(&st, &p, id, position, dek.as_ref(), &headers).await
}

/// What a `Range` header asks for, against a file of known size.
#[derive(Debug, PartialEq, Eq)]
enum RangeAsk {
    /// No header, or one to ignore (multi-range, malformed): the full body.
    Full,
    /// The inclusive byte range to send.
    Part(u64, u64),
    Unsatisfiable,
}

fn parse_range(value: Option<&HeaderValue>, total: u64) -> RangeAsk {
    let Some(spec) = value.and_then(|v| v.to_str().ok()).and_then(|v| v.trim().strip_prefix("bytes=")) else {
        return RangeAsk::Full;
    };
    let Some((first, last)) = spec.trim().split_once('-') else { return RangeAsk::Full };
    let number = |s: &str| (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<u64>().ok());
    match (number(first.trim()), number(last.trim())) {
        (Some(Some(a)), Some(Some(b))) if a <= b => {
            if a >= total {
                RangeAsk::Unsatisfiable
            } else {
                RangeAsk::Part(a, b.min(total - 1))
            }
        }
        (Some(Some(a)), None) if last.trim().is_empty() => {
            if a >= total {
                RangeAsk::Unsatisfiable
            } else {
                RangeAsk::Part(a, total - 1)
            }
        }
        (None, Some(Some(n))) if first.trim().is_empty() => {
            if n == 0 || total == 0 {
                RangeAsk::Unsatisfiable
            } else {
                RangeAsk::Part(total.saturating_sub(n), total - 1)
            }
        }
        _ => RangeAsk::Full,
    }
}

/// A file download: raster images inline, everything else (and every secret file, which is
/// ciphertext) as an attachment, never cached. Files stored as-is get `Content-Length` and
/// single-range support; private files are decrypted on the way, so they get the plaintext
/// length and always the full body.
pub async fn download(
    st: &AppState,
    p: &Paste,
    id: PasteId,
    position: u32,
    dek: Option<&Dek>,
    req: &HeaderMap,
) -> Result<Response, Error> {
    let meta = files::meta(st, id, position).await?;
    let (content_type, kind) = if p.privacy == Privacy::Secret {
        (PLACEHOLDER_MIME, "attachment")
    } else if inline_image(&meta.mime) {
        (meta.mime.as_str(), "inline")
    } else {
        (meta.mime.as_str(), "attachment")
    };
    let content_type = HeaderValue::from_str(content_type).unwrap_or(HeaderValue::from_static(PLACEHOLDER_MIME));
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type);
    headers.insert(header::CONTENT_DISPOSITION, disposition(kind, &meta.name)?);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    if p.privacy == Privacy::Private {
        let (_, body) = files::open(st, id, position, dek).await?;
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.size));
        // A body that fails to decrypt part-way ends in an error, so the client sees a broken transfer.
        return Ok((headers, body).into_response());
    }
    let total = meta.size;
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    match parse_range(req.get(header::RANGE), total) {
        RangeAsk::Unsatisfiable => {
            headers.insert(
                header::CONTENT_RANGE,
                HeaderValue::try_from(format!("bytes */{total}")).map_err(Error::internal)?,
            );
            Ok((StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response())
        }
        RangeAsk::Part(a, b) => {
            let body = files::open_range(st, id, position, a, b).await?;
            headers.insert(
                header::CONTENT_RANGE,
                HeaderValue::try_from(format!("bytes {a}-{b}/{total}")).map_err(Error::internal)?,
            );
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(b - a + 1));
            Ok((StatusCode::PARTIAL_CONTENT, headers, body).into_response())
        }
        RangeAsk::Full => {
            let (_, body) = files::open(st, id, position, None).await?;
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(total));
            Ok((headers, body).into_response())
        }
    }
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
