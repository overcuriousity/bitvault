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
    /// Sent as `Cookie` on every request once set, e.g. by [`App::sign_in_admin`].
    pub cookie: Option<String>,
    /// `(Host, Origin)` sent on every request; tests that configure a `public_url` change it.
    pub origin: (String, String),
    _dir: tempfile::TempDir,
}

/// The admin password of [`ADMIN_CONFIG`].
pub const ADMIN_PASSWORD: &str = "admin-pw-123";
pub const ADMIN_CONFIG: &str = "[app]\nadmin_password = \"admin-pw-123\"\n";

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
    let (router, st) = bitvault::app::build_with(cfg, pool, extra).await.unwrap();
    let router = router.layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))));
    App { router, st, cookie: None, origin: ("localhost:8080".into(), "http://localhost:8080".into()), _dir: dir }
}

impl App {
    pub async fn send(&self, r: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(r).await.unwrap()
    }

    pub fn req(&self, method: &str, uri: &str) -> axum::http::request::Builder {
        let mut b = Request::builder().method(method).uri(uri).header(header::HOST, &self.origin.0);
        if method != "GET" {
            b = b.header(header::ORIGIN, &self.origin.1);
        }
        if let Some(cookie) = &self.cookie {
            b = b.header(header::COOKIE, cookie);
        }
        b
    }

    /// Signs in with [`ADMIN_PASSWORD`] and keeps the session cookie for later requests.
    pub async fn sign_in_admin(&mut self) {
        let res = self.post_form("/admin/sign-in", &format!("password={ADMIN_PASSWORD}")).await;
        assert_eq!(res.status(), axum::http::StatusCode::SEE_OTHER, "admin sign-in failed");
        let set = res.headers()[header::SET_COOKIE].to_str().unwrap();
        self.cookie = Some(set.split(';').next().unwrap().to_owned());
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
        self.post_multipart_body(uri, Body::from(multipart_body(parts))).await
    }

    /// Posts an already-encoded multipart body (see [`multipart_body`]).
    pub async fn post_multipart_body(&self, uri: &str, body: Body) -> Response<Body> {
        let r = self
            .req("POST", uri)
            .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
            .body(body)
            .unwrap();
        self.send(r).await
    }
}

/// Encodes parts as `(name, filename, bytes)`, closing delimiter included.
pub fn multipart_body(parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut body = multipart_parts(parts);
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// Encodes parts without the closing delimiter, for bodies that continue.
pub fn multipart_parts(parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
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
            None => body
                .extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes()),
        }
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body
}

pub async fn body_text(res: Response<Body>) -> String {
    String::from_utf8(axum::body::to_bytes(res.into_body(), 8 << 20).await.unwrap().to_vec()).unwrap()
}

/// Configuration for the rendered-page gate: every external address the app may render.
pub const GATE_CONFIG: &str = "public_url = \"https://paste.example\"\n[app]\nshort_url = \"https://s.example\"\ntranslate_url = \"https://translate.example/t\"\nadmin_password = \"admin-pw-123\"\neditable = true\n";
/// The only absolute addresses a page may link to or load: the three configured in [`GATE_CONFIG`].
pub const GATE_ALLOWED_URLS: [&str; 3] = ["https://paste.example", "https://s.example", "https://translate.example/t"];

/// Panics with the offending snippet when a page carries inline code or an unconfigured external address.
pub fn assert_clean_html(body: &str) {
    fn snippet(body: &str, at: usize) -> &str {
        let start = body.floor_char_boundary(at.saturating_sub(40));
        let end = body.floor_char_boundary((at + 80).min(body.len()));
        &body[start..end]
    }
    for bad in ["style=", "hx-on", "confirm(", "alert(", "prompt("] {
        if let Some(at) = body.find(bad) {
            panic!("`{bad}` in page: ...{}...", snippet(body, at));
        }
    }
    let mut from = 0;
    while let Some(i) = body[from..].find("<script") {
        let at = from + i;
        let tag_end = body[at..].find('>').map_or(body.len(), |e| at + e);
        assert!(body[at..tag_end].contains("src="), "inline <script>: ...{}...", snippet(body, at));
        from = at + 1;
    }
    // ` on` + letters + `=` is an event-handler attribute; `data-on…` and text such as "one=" do not match
    // because attribute names start after whitespace and text rarely continues with `=` directly.
    for (at, _) in body.match_indices(" on") {
        let rest = &body[at + 3..];
        let letters = rest.bytes().take_while(u8::is_ascii_lowercase).count();
        if letters > 0 && rest.as_bytes().get(letters) == Some(&b'=') {
            panic!("event handler attribute: ...{}...", snippet(body, at));
        }
    }
    for attr in ["src=", "href=", "action="] {
        for (at, _) in body.match_indices(attr) {
            let rest = &body[at + attr.len()..];
            let Some(quote) = rest.chars().next().filter(|c| matches!(c, '"' | '\'')) else { continue };
            let value = rest[1..].split(quote).next().unwrap_or("");
            let external = value.starts_with("http://") || value.starts_with("https://");
            if external && !GATE_ALLOWED_URLS.iter().any(|ok| value.starts_with(ok)) {
                panic!("external address in `{attr}`: ...{}...", snippet(body, at));
            }
        }
    }
}
