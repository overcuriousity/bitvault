//! Embedded static files served under a content-hashed path, so browsers can cache them forever.

use std::sync::OnceLock;

use axum::Router;
use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rust_embed::RustEmbed;
use sha2::{Digest, Sha256};

#[derive(RustEmbed)]
#[folder = "assets/"]
#[exclude = "*.test.mjs"]
pub struct Assets;

impl Assets {
    /// First 8 hex digits of the SHA-256 over every embedded path and file.
    pub fn hash() -> &'static str {
        static HASH: OnceLock<String> = OnceLock::new();
        HASH.get_or_init(|| {
            let mut paths: Vec<_> = Self::iter().collect();
            paths.sort();
            let mut h = Sha256::new();
            for p in paths {
                h.update(p.as_bytes());
                if let Some(f) = Self::get(&p) {
                    h.update(&f.data);
                }
            }
            hex::encode(h.finalize())[..8].to_owned()
        })
    }

    pub fn url(path: &str) -> String {
        debug_assert!(Self::get(path).is_some(), "unknown asset {path}");
        format!("/assets/{}/{path}", Self::hash())
    }
}

pub fn router() -> Router {
    Router::new().route("/assets/{hash}/{*path}", get(serve))
}

async fn serve(Path((hash, path)): Path<(String, String)>) -> Response {
    if hash != Assets::hash() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match Assets::get(&path) {
        Some(file) => (
            [
                (header::CONTENT_TYPE, mime_guess::from_path(&path).first_or_octet_stream().to_string()),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable".to_owned()),
            ],
            file.data.into_owned(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
