#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::{Response, StatusCode, header};
use bitvault::domain::crypto::{self, PBKDF2_ITERATIONS};
use bitvault::domain::expiry::Expiry;
use bitvault::domain::paste::{self, NewPaste, SecretParts};
use bitvault::domain::{self, Privacy};
use support::{App, GATE_CONFIG, app_with, assert_clean_html, body_text};

fn new(content: &str, privacy: Privacy) -> NewPaste {
    NewPaste {
        content: content.into(),
        privacy,
        expiry: Expiry::Hour24,
        burn_after_reads: 0,
        syntax: None,
        editable: false,
        password: None,
        secret: None,
    }
}

fn secret() -> NewPaste {
    let container = crypto::seal_alg2_for_tests("pw", &[9; 16], PBKDF2_ITERATIONS, br#"{"text":"hi","files":[]}"#);
    NewPaste {
        secret: Some(SecretParts {
            container,
            verifier_salt: [7; 16],
            verifier: crypto::browser_verifier("pw", &[7; 16]),
        }),
        ..new("", Privacy::Secret)
    }
}

async fn gate_app(extra: &str) -> App {
    let mut app = app_with(&format!("{GATE_CONFIG}{extra}")).await;
    app.origin = ("paste.example".into(), "https://paste.example".into());
    app
}

async fn create(app: &App, p: NewPaste) -> String {
    paste::create(&app.st, p, None, domain::now()).await.unwrap().words()
}

/// Checks the status, the CSP header and the page body; returns nothing because every page must pass alike.
async fn check(what: &str, res: Response<axum::body::Body>, status: StatusCode) {
    assert_eq!(res.status(), status, "{what}");
    assert_eq!(res.headers()[header::CONTENT_SECURITY_POLICY], bitvault::security::CSP, "{what}");
    let body = body_text(res).await;
    std::panic::catch_unwind(|| assert_clean_html(&body)).unwrap_or_else(|e| {
        let msg = e.downcast_ref::<String>().cloned().unwrap_or_default();
        panic!("{what}: {msg}");
    });
}

#[tokio::test]
async fn every_rendered_page_and_fragment_is_clean() {
    let empty = gate_app("").await;
    check("empty list", empty.get("/list").await, StatusCode::OK).await;

    let gated = gate_app("uploader_password = \"letmein\"\n").await;
    check("home with uploader password", gated.get("/").await, StatusCode::OK).await;

    let mut app = gate_app("").await;
    let public = create(&app, NewPaste { editable: true, ..new("hello there", Privacy::Public) }).await;
    let readonly = create(&app, NewPaste { password: Some("pw".into()), ..new("kept", Privacy::Readonly) }).await;
    let url = create(&app, new("https://example.com/target", Privacy::Unlisted)).await;
    let private = create(&app, NewPaste { password: Some("pw".into()), ..new("locked", Privacy::Private) }).await;
    let secret = create(&app, secret()).await;
    let burning = create(&app, NewPaste { burn_after_reads: 1, ..new("once", Privacy::Public) }).await;

    check("home", app.get("/").await, StatusCode::OK).await;
    check("list", app.get("/list").await, StatusCode::OK).await;
    let res = app.get(&format!("/{public}")).await;
    let html = body_text(res).await;
    for configured in ["https://translate.example/t", "https://s.example/", "https://paste.example/"] {
        assert!(html.contains(configured), "the gate must render {configured}");
    }
    assert_clean_html(&html);
    check("public paste", app.get(&format!("/{public}")).await, StatusCode::OK).await;
    check("readonly paste", app.get(&format!("/{readonly}")).await, StatusCode::OK).await;
    // A URL paste redirects; the redirect page is not HTML, so only its target is checked.
    assert_eq!(app.get(&format!("/{url}")).await.status(), StatusCode::FOUND);
    check("private locked", app.get(&format!("/{private}")).await, StatusCode::OK).await;
    let unlock = app.post_form(&format!("/{private}/unlock"), "password=pw").await;
    check("private unlocked", unlock, StatusCode::OK).await;
    check("secret shell", app.get(&format!("/{secret}")).await, StatusCode::OK).await;
    check("burned view", app.get(&format!("/{burning}")).await, StatusCode::OK).await;
    check("edit page", app.get(&format!("/{public}/edit")).await, StatusCode::OK).await;

    check("admin sign-in", app.get("/admin/sign-in").await, StatusCode::OK).await;
    app.sign_in_admin().await;
    check("admin", app.get("/admin").await, StatusCode::OK).await;
    app.cookie = None;

    check("guide", app.get("/guide").await, StatusCode::OK).await;
    check("docs", app.get("/docs").await, StatusCode::OK).await;
    check("offline", app.get("/offline").await, StatusCode::OK).await;
    check("not found", app.get("/nope").await, StatusCode::NOT_FOUND).await;
    check("open 422", app.post_form("/open", "words=happy+aple+banana").await, StatusCode::UNPROCESSABLE_ENTITY).await;
    let wrong = app.post_form(&format!("/{private}/unlock"), "password=nope").await;
    check("unlock 422", wrong, StatusCode::UNPROCESSABLE_ENTITY).await;
}
