#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, Response, header};
use bitvault::config::Config;
use bitvault::state::AppState;
use tower::ServiceExt;

pub const BOUNDARY: &str = "bitvault-test-boundary";

pub struct App {
    pub router: Router,
    pub st: AppState,
    _dir: tempfile::TempDir,
}

pub async fn app() -> App {
    app_with("").await
}

/// Builds the app from a TOML config on a fresh data directory.
pub async fn app_with(toml: &str) -> App {
    app_with_routes(toml, Router::new()).await
}

/// Like [`app_with`], with test-only routes registered next to the app's own.
pub async fn app_with_routes(toml: &str, extra: Router<AppState>) -> App {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.toml");
    std::fs::write(&file, toml).unwrap();
    let mut cfg = bitvault::config::load(Some(&file)).unwrap();
    cfg.data_dir = Some(dir.path().join("data"));
    cfg.validate().unwrap();
    app_from(cfg, dir, extra).await
}

async fn app_from(cfg: Config, dir: tempfile::TempDir, extra: Router<AppState>) -> App {
    let pool = bitvault::db::open(&cfg.data_dir()).await.unwrap();
    let (router, st) = bitvault::app::build_with(cfg, pool, extra).unwrap();
    let router = router.layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))));
    App { router, st, _dir: dir }
}

impl App {
    pub async fn send(&self, r: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(r).await.unwrap()
    }

    pub fn req(&self, method: &str, uri: &str) -> axum::http::request::Builder {
        let mut b = Request::builder().method(method).uri(uri).header(header::HOST, "localhost:8080");
        if method != "GET" {
            b = b.header(header::ORIGIN, "http://localhost:8080");
        }
        b
    }

    pub async fn get(&self, uri: &str) -> Response<Body> {
        self.send(self.req("GET", uri).header(header::ACCEPT, "text/html").body(Body::empty()).unwrap()).await
    }

    pub async fn post_form(&self, uri: &str, form: &str) -> Response<Body> {
        let r = self
            .req("POST", uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("hx-request", "true")
            .body(Body::from(form.to_owned()))
            .unwrap();
        self.send(r).await
    }

    /// Each part is `(name, filename, bytes)`; a part without a filename is a plain field.
    pub async fn post_multipart(&self, uri: &str, parts: &[(&str, Option<&str>, &[u8])]) -> Response<Body> {
        let mut body = Vec::new();
        for (name, filename, bytes) in parts {
            body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
            match filename {
                Some(f) => body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                    )
                    .as_bytes(),
                ),
                None => body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
                ),
            }
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        let r = self
            .req("POST", uri)
            .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
            .body(Body::from(body))
            .unwrap();
        self.send(r).await
    }
}

pub async fn body_text(res: Response<Body>) -> String {
    String::from_utf8(axum::body::to_bytes(res.into_body(), 8 << 20).await.unwrap().to_vec()).unwrap()
}
