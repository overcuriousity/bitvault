#![allow(clippy::unwrap_used, clippy::expect_used, clippy::result_large_err)]

mod support;

use std::path::Path;

use axum::http::{StatusCode, header};
use bitvault::assets::Assets;
use bitvault::config::{self, Config};
use bitvault::error::Error;
use support::{app, body_text};

// Jail tests set process-wide environment variables, so every test that loads a config takes this lock.
static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn from_toml(toml: &str) -> Result<Config, Error> {
    let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.toml");
    std::fs::write(&file, toml).unwrap();
    let cfg = config::load(Some(&file))?;
    cfg.validate()?;
    Ok(cfg)
}

fn invalid(toml: &str) -> String {
    match from_toml(toml) {
        Err(Error::Invalid(m)) => m,
        other => panic!("expected an Invalid error, got {other:?}"),
    }
}

#[test]
fn defaults_match_the_spec() {
    let cfg = from_toml("").unwrap();
    let a = &cfg.app;
    assert_eq!(cfg.bind.to_string(), "127.0.0.1:8080");
    assert_eq!(a.title, "BitVault");
    assert_eq!(a.default_privacy, "unlisted");
    assert_eq!(a.default_expiry, "24hour");
    assert_eq!(a.max_expiry, "1week");
    assert_eq!(a.max_file_mb, 2048);
    assert_eq!(a.max_secret_file_mb, 256);
    assert!(a.listing && !a.editable && !a.read_stats && a.highlight && a.qr);
    assert_eq!(a.privacy_levels, ["public", "unlisted", "readonly", "private", "secret"]);
    assert_eq!(
        a.expiry_choices,
        ["1min", "10min", "1hour", "24hour", "3days", "1week", "1month", "6months", "1year", "never"]
    );
    assert_eq!(cfg.trusted_proxies.len(), 2);
    assert!(a.admin_password.is_none() && a.uploader_password.is_none() && a.short_url.is_none());
}

#[test]
fn a_default_privacy_outside_the_offered_levels_is_rejected() {
    let m = invalid("[app]\nprivacy_levels = [\"public\"]\ndefault_privacy = \"secret\"\n");
    assert!(m.contains("default_privacy"), "{m}");
}

#[test]
fn a_max_expiry_of_never_requires_never_in_the_choices() {
    let m = invalid("[app]\nmax_expiry = \"never\"\nexpiry_choices = [\"1hour\", \"24hour\"]\n");
    assert!(m.contains("max_expiry"), "{m}");
}

#[test]
fn an_http_short_url_is_rejected() {
    let m = invalid("[app]\nshort_url = \"http://bv.example\"\n");
    assert!(m.contains("short_url"), "{m}");
}

#[test]
fn a_non_loopback_bind_needs_an_https_public_url() {
    assert!(from_toml("bind = \"0.0.0.0:8080\"\n").is_err());
    assert!(from_toml("bind = \"0.0.0.0:8080\"\npublic_url = \"http://vault.example\"\n").is_err());
    assert!(from_toml("bind = \"0.0.0.0:8080\"\npublic_url = \"https://vault.example\"\n").is_ok());
}

#[test]
fn environment_variables_override_the_file() {
    let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
    figment::Jail::expect_with(|jail| {
        jail.create_file("config.toml", "[app]\nlisting = true\n")?;
        jail.set_env("BITVAULT__APP__LISTING", "false");
        let cfg = config::load(Some(Path::new("config.toml"))).unwrap();
        assert!(!cfg.app.listing);
        Ok(())
    });
}

#[test]
fn secrets_can_come_from_files() {
    let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
    figment::Jail::expect_with(|jail| {
        jail.create_file("admin-secret", "s3cret-pass\n")?;
        jail.set_env("BITVAULT__APP__ADMIN_PASSWORD_FILE", "admin-secret");
        let cfg = config::load(None).unwrap();
        assert_eq!(cfg.app.admin_password.as_deref(), Some("s3cret-pass"));
        Ok(())
    });
}

#[tokio::test]
async fn the_home_page_renders_in_the_shell() {
    let a = app().await;
    let res = a.get("/").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/html"));
    let html = body_text(res).await;
    assert!(html.contains("<meta name=\"htmx-config\""));
    assert!(html.contains("data-theme"));
    assert!(!html.contains("style="));
}

#[tokio::test]
async fn assets_are_served_immutable_under_a_hashed_url() {
    let a = app().await;
    let url = Assets::url("vendor/oc/css/00-tokens.css");
    let res = a.get(&url).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers()[header::CACHE_CONTROL].to_str().unwrap().contains("immutable"));
    assert!(res.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/css"));

    let stale = url.replacen(url.split('/').nth(2).unwrap(), "00000000", 1);
    assert_eq!(a.get(&stale).await.status(), StatusCode::NOT_FOUND);
}
