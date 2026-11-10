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
fn a_non_loopback_bind_without_a_public_url_is_refused_unless_insecure_http_is_on() {
    let m = invalid("bind = \"0.0.0.0:8080\"\n");
    assert!(m.contains("public_url"), "{m}");
    let cfg = from_toml("insecure_http = true\nbind = \"0.0.0.0:8080\"\n").unwrap();
    assert!(cfg.insecure_http);
    assert!(!from_toml("").unwrap().insecure_http, "plain HTTP is off by default");
}

#[test]
fn an_http_public_url_is_refused_unless_insecure_http_is_on() {
    let lan = "bind = \"0.0.0.0:8080\"\npublic_url = \"http://vault.lan:8080\"\n";
    let m = invalid(lan);
    assert!(m.contains("public_url"), "{m}");
    assert!(from_toml(&format!("insecure_http = true\n{lan}")).is_ok());
}

#[test]
fn plain_http_cannot_make_secret_the_default_level() {
    let m = invalid("insecure_http = true\n[app]\ndefault_privacy = \"secret\"\n");
    assert!(m.contains("default_privacy") && m.contains("insecure_http"), "{m}");
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
fn text_from_the_environment_stays_text() {
    let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
    figment::Jail::expect_with(|jail| {
        // Read as values, these would be a number (without its leading zeros), a boolean and a list.
        jail.set_env("BITVAULT__APP__ADMIN_PASSWORD", "0012345678");
        jail.set_env("BITVAULT__APP__UPLOADER_PASSWORD", "true");
        jail.set_env("BITVAULT__APP__TITLE", "[2026]");
        jail.set_env("BITVAULT__APP__MAX_FILE_MB", "64");
        jail.set_env("BITVAULT__APP__EXPIRY_CHOICES", "[\"1hour\", \"24hour\", \"1week\"]");
        let cfg = config::load(None).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.app.admin_password.as_deref(), Some("0012345678"));
        assert_eq!(cfg.app.uploader_password.as_deref(), Some("true"));
        assert_eq!(cfg.app.title, "[2026]");
        assert_eq!(cfg.app.max_file_mb, 64);
        assert_eq!(cfg.app.expiry_choices, ["1hour", "24hour", "1week"]);
        Ok(())
    });
}

#[test]
fn the_parsed_environment_keys_are_the_keys_that_are_no_text() {
    use figment::providers::{Format, Toml};
    use figment::value::Value;
    // config.example.toml documents every key with its default.
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
    let example: Value = figment::Figment::from(Toml::file(example)).extract().unwrap();
    let mut found = Vec::new();
    let mut pending = vec![(String::new(), example)];
    while let Some((path, value)) = pending.pop() {
        match value {
            Value::Dict(_, dict) => pending
                .extend(dict.into_iter().map(|(k, v)| (if path.is_empty() { k } else { format!("{path}.{k}") }, v))),
            Value::String(..) => {}
            _ => found.push(path),
        }
    }
    found.sort();
    let mut parsed = config::PARSED_ENV_KEYS.to_vec();
    parsed.sort_unstable();
    assert_eq!(found, parsed);
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

#[test]
fn an_absurd_upload_limit_is_rejected() {
    assert!(invalid("[app]\nmax_file_mb = 2000000").contains("max_file_mb"));
    assert!(invalid("[app]\nmax_secret_file_mb = 2000000").contains("max_secret_file_mb"));
}

#[test]
fn the_long_expiries_are_accepted_but_not_offered_by_default() {
    let defaults = from_toml("").unwrap();
    for long in ["2years", "4years", "8years", "16years"] {
        assert!(!defaults.app.expiry_choices.iter().any(|c| c == long), "{long} must be opt-in");
    }
    let cfg = from_toml(
        "[app]\nexpiry_choices = [\"24hour\", \"1year\", \"2years\", \"4years\", \"8years\", \"16years\"]\nmax_expiry = \"16years\"\n",
    )
    .unwrap();
    assert_eq!(cfg.app.max_expiry, "16years");
}

#[test]
fn the_long_expiries_last_whole_years() {
    use bitvault::domain::expiry::Expiry;
    const YEAR: i64 = 365 * 24 * 3600;
    for (token, label, years) in
        [("2years", "2 years", 2), ("4years", "4 years", 4), ("8years", "8 years", 8), ("16years", "16 years", 16)]
    {
        let e = Expiry::parse(token).unwrap();
        assert_eq!((e.as_str(), e.label(), e.seconds()), (token, label, Some(years * YEAR)));
    }
}

#[test]
fn a_default_expiry_longer_than_max_expiry_is_rejected() {
    let m = invalid(
        "[app]\nexpiry_choices = [\"1hour\", \"1week\", \"1month\"]\ndefault_expiry = \"1month\"\nmax_expiry = \"1week\"\n",
    );
    assert!(m.contains("default_expiry"), "{m}");
}
