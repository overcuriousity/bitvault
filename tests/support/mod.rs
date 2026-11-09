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
/// Only tag interiors are inspected, so escaped paste text such as `style=` is never flagged.
pub fn assert_clean_html(body: &str) {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        if body[i..].starts_with("<!--") {
            i = body[i..].find("-->").map_or(bytes.len(), |e| i + e + 3);
            continue;
        }
        let next = bytes.get(i + 1).copied().unwrap_or(0);
        if !(next.is_ascii_alphabetic() || next == b'/' || next == b'!') {
            i += 1;
            continue;
        }
        let (tag, end) = parse_tag(body, i);
        check_tag(body, i, &tag);
        i = end;
        if tag.name == "script" {
            let close = body[i..].to_ascii_lowercase().find("</script").map_or(bytes.len(), |e| i + e);
            let script = body[i..close].to_ascii_lowercase();
            for call in ["confirm(", "alert(", "prompt("] {
                assert!(!script.contains(call), "`{call}` in <script> body: {}", snippet(body, i));
            }
            i = close;
        }
    }
}

struct Tag {
    name: String,
    attrs: Vec<(String, String)>,
}

fn snippet(body: &str, at: usize) -> &str {
    let start = body.floor_char_boundary(at.saturating_sub(20));
    let end = body.floor_char_boundary((at + 100).min(body.len()));
    &body[start..end]
}

/// Parses the tag opening at `start` up to its closing `>`, honouring quoted values.
fn parse_tag(body: &str, start: usize) -> (Tag, usize) {
    let b = body.as_bytes();
    let mut i = start + 1;
    let name_start = i;
    while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'/' && b[i] != b'>' {
        i += 1;
    }
    let name = body[name_start..i].to_ascii_lowercase();
    let mut attrs = Vec::new();
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        if b[i] == b'>' {
            i += 1;
            break;
        }
        let a_start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        if i == a_start {
            i += 1;
            continue;
        }
        let attr = body[a_start..i].to_ascii_lowercase();
        let mut j = i;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        let mut value = String::new();
        if j < b.len() && b[j] == b'=' {
            j += 1;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len() && matches!(b[j], b'"' | b'\'') {
                let quote = b[j];
                let v_start = j + 1;
                j = v_start;
                while j < b.len() && b[j] != quote {
                    j += 1;
                }
                value = body[v_start..j].to_owned();
                j = (j + 1).min(b.len());
            } else {
                let v_start = j;
                while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'>' {
                    j += 1;
                }
                value = body[v_start..j].to_owned();
            }
            i = j;
        }
        attrs.push((attr, value));
    }
    (Tag { name, attrs }, i)
}

fn check_tag(body: &str, at: usize, tag: &Tag) {
    let here = || snippet(body, at).to_owned();
    for (attr, value) in &tag.attrs {
        let handler = attr.len() > 2 && attr.starts_with("on") && attr.bytes().all(|c| c.is_ascii_lowercase());
        assert!(attr != "style", "style attribute: {}", here());
        assert!(!handler, "event handler attribute `{attr}`: {}", here());
        assert!(!attr.starts_with("hx-on"), "hx-on attribute: {}", here());
        match attr.as_str() {
            "src" | "href" | "action" | "formaction" | "poster" | "data" => {
                check_url(value, tag.name == "img" && attr == "src", &here);
            }
            "srcset" => {
                for candidate in value.split(',') {
                    check_url(candidate.split_whitespace().next().unwrap_or(""), false, &here);
                }
            }
            "content" if tag.name == "meta" => {
                let refresh = tag.attrs.iter().any(|(n, v)| n == "http-equiv" && v.eq_ignore_ascii_case("refresh"));
                if refresh {
                    let lower = value.to_ascii_lowercase();
                    let url = lower.find("url=").map_or("", |p| value[p + 4..].trim_matches(['"', '\'', ' ']));
                    check_url(url, false, &here);
                }
            }
            _ => {}
        }
    }
    if tag.name == "script" {
        assert!(tag.attrs.iter().any(|(n, _)| n == "src"), "inline <script>: {}", here());
    }
}

fn check_url(raw: &str, data_ok: bool, here: &dyn Fn() -> String) {
    let value: String = raw.chars().filter(|c| !c.is_ascii_control() && *c != ' ').collect::<String>();
    let lower = value.to_ascii_lowercase();
    assert!(!lower.starts_with("javascript:"), "javascript: URL: {}", here());
    let scheme = lower.split_once(':').map(|(s, _)| s).filter(|s| {
        s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    });
    if scheme == Some("mailto") || (scheme == Some("data") && data_ok) {
        return;
    }
    if scheme.is_none() && !lower.starts_with("//") {
        return;
    }
    let allowed = GATE_ALLOWED_URLS
        .iter()
        .any(|ok| value.strip_prefix(ok).is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '#'])));
    assert!(allowed, "external address `{raw}`: {}", here());
}
