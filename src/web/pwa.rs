//! Web app manifest, service worker and offline page. The worker caches the shell's assets and
//! `/offline` only; pastes are never stored on the device.

use axum::Router;
use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use super::shell::{KIT_CSS, MODULES};
use super::{page, render};
use crate::assets::Assets;
use crate::error::Error;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/manifest.webmanifest", get(manifest))
        .route("/sw.js", get(service_worker))
        .route("/offline", get(offline))
}

async fn manifest(State(st): State<AppState>) -> Response {
    let title = &st.cfg.app.title;
    let body = serde_json::json!({
        "name": title,
        "short_name": title,
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "icons": [{ "src": Assets::url("icon.svg"), "sizes": "any", "type": "image/svg+xml" }],
    });
    ([(header::CONTENT_TYPE, "application/manifest+json")], body.to_string()).into_response()
}

fn shell_urls() -> Vec<String> {
    let fixed = [
        "vendor/oc/js/theme.js",
        "vendor/oc/htmx/htmx.min.js",
        "css/app.css",
        "css/syntax.css",
        "icon.svg",
        "vendor/oc/fonts/atkinson-next-400.woff2",
        "vendor/oc/fonts/atkinson-next-500.woff2",
        "vendor/oc/fonts/atkinson-next-600.woff2",
        "vendor/oc/fonts/jetbrains-mono-400.woff2",
    ];
    let mut urls: Vec<String> =
        KIT_CSS.iter().chain(MODULES.iter()).chain(fixed.iter()).map(|p| Assets::url(p)).collect();
    urls.push("/offline".into());
    urls
}

async fn service_worker() -> Response {
    let template = Assets::get("js/sw.js").map(|f| String::from_utf8_lossy(&f.data).into_owned()).unwrap_or_default();
    let body = template
        .replace("__VERSION__", &format!("bitvault-{}", Assets::hash()))
        .replace("__SHELL__", &serde_json::to_string(&shell_urls()).unwrap_or_else(|_| "[]".into()));
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")], body)
        .into_response()
}

#[derive(askama::Template)]
#[template(path = "offline.html")]
struct Offline;

/// Rendered as for a visitor even to the admin, because the service worker stores it.
async fn offline(State(st): State<AppState>) -> Result<Html<String>, Error> {
    page(&st, false, "", "Offline", render(&Offline)?)
}
