#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use bitvault::error::Error;
use bitvault::state::AppState;
use support::body_text;
use tower::ServiceExt;

async fn router(dir: &tempfile::TempDir) -> Router {
    let cfg = bitvault::config::Config { data_dir: Some(dir.path().to_owned()), ..Default::default() };
    let pool = bitvault::db::open(&cfg.data_dir()).await.unwrap();
    let extra: Router<AppState> =
        Router::new().route("/boom", get(|| async { Error::Invalid("Fix the name and try again.".into()) }));
    let (router, _) = bitvault::app::build_with(cfg, pool, extra).await.unwrap();
    router.layer(MockConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5000))))
}

async fn fetch(r: &Router, uri: &str, htmx: bool) -> (StatusCode, String) {
    let mut b = Request::builder().uri(uri).header(header::HOST, "localhost:8080");
    if htmx {
        b = b.header("hx-request", "true");
    }
    let res = r.clone().oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
    (res.status(), body_text(res).await)
}

#[tokio::test]
async fn an_error_page_renders_inside_the_shell() {
    let dir = tempfile::tempdir().unwrap();
    let r = router(&dir).await;
    let (status, html) = fetch(&r, "/nowhere", false).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(html.contains("<meta name=\"htmx-config\""));
    let (status, html) = fetch(&r, "/boom", false).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(html.contains("<meta name=\"htmx-config\"") && html.contains("Fix the name"));
}

#[tokio::test]
async fn an_htmx_error_is_a_notice_fragment_with_the_same_status() {
    let dir = tempfile::tempdir().unwrap();
    let r = router(&dir).await;
    for (uri, status) in [("/boom", StatusCode::UNPROCESSABLE_ENTITY), ("/nowhere", StatusCode::NOT_FOUND)] {
        let (got, html) = fetch(&r, uri, true).await;
        assert_eq!(got, status);
        assert!(html.contains("oc-notice") && !html.contains("<html"), "{html}");
    }
}

#[tokio::test]
async fn a_data_dir_that_is_a_file_names_the_directory_and_the_cause() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-a-dir");
    std::fs::write(&file, b"x").unwrap();
    let e = bitvault::db::open(&file).await.unwrap_err();
    let message = e.startup_message();
    assert_eq!(message, format!("Cannot open the data directory {}: Not a directory (os error 20).", file.display()));
}

#[test]
fn an_internal_start_up_error_shows_its_cause_to_the_operator() {
    let e = Error::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied"));
    assert_eq!(e.to_string(), "Something went wrong. Try again later.");
    assert_eq!(e.startup_message(), "BitVault could not start: Permission denied.");
}

#[test]
fn the_binary_prints_the_cause_when_start_up_fails() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-a-dir");
    std::fs::write(&file, b"x").unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, format!("data_dir = {:?}\n", file.display().to_string())).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bitvault"))
        .arg("--config")
        .arg(&config)
        .env_remove("STATE_DIRECTORY")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains(&format!("Cannot open the data directory {}: Not a directory", file.display())),
        "{stderr}"
    );
}
