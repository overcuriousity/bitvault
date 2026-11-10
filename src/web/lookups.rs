//! A per-address budget for paste lookups that find nothing.
//!
//! Three words are only 33 bits, so an address that keeps guessing could walk the unlisted pastes.
//! Each lookup reserves a token and gets it back unless it missed (404, or 422 from `/open`), so
//! people reading pastes that exist are never slowed, while a guesser runs dry after a few misses
//! and then gets 429 on every lookup until the bucket refills.

use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::Error;
use crate::security::ClientIp;
use crate::state::AppState;

pub async fn budget(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let Some(kind) = lookup_kind(req.method(), req.uri().path()) else {
        return next.run(req).await;
    };
    let Some(ClientIp(ip)) = req.extensions().get::<ClientIp>().copied() else {
        return next.run(req).await;
    };
    if st.lookups.take(ip).is_err() {
        return Error::TooManyAttempts.into_response();
    }
    let res = next.run(req).await;
    let missed = res.status() == StatusCode::NOT_FOUND
        || (kind == Kind::Open && res.status() == StatusCode::UNPROCESSABLE_ENTITY);
    if !missed {
        st.lookups.refund(ip);
    }
    res
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Path,
    Open,
}

fn lookup_kind(method: &Method, path: &str) -> Option<Kind> {
    if path == "/open" && method == Method::POST {
        return Some(Kind::Open);
    }
    let rest = path.strip_prefix("/api/v1/pastes/").unwrap_or_else(|| path.trim_start_matches('/'));
    let first = rest.split('/').next().unwrap_or_default();
    looks_like_words(first).then_some(Kind::Path)
}

/// Reserved paths have no hyphen, so a segment of three hyphen-joined letter runs is a lookup.
fn looks_like_words(segment: &str) -> bool {
    let mut parts = segment.split('-');
    let three = parts.by_ref().take(3).filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphabetic())).count();
    three == 3 && parts.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_three_word_paths_and_open_are_lookups() {
        let get = &Method::GET;
        assert!(lookup_kind(get, "/happy-apple-banana").is_some());
        assert!(lookup_kind(get, "/happy-apple-banana/raw").is_some());
        assert!(lookup_kind(get, "/Happy-Apple-Banana/file/1").is_some());
        assert!(lookup_kind(get, "/api/v1/pastes/happy-apple-banana/files/1").is_some());
        assert!(lookup_kind(&Method::POST, "/open") == Some(Kind::Open));
        for path in ["/", "/list", "/admin", "/api/v1/pastes", "/api/v1/health", "/nope", "/a-b", "/a-b-c-d", "/a--b"] {
            assert!(lookup_kind(get, path).is_none(), "{path}");
        }
        assert!(lookup_kind(get, "/open").is_none());
    }
}
