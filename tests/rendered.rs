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
    let hostile = create(&app, new("hello style=\"x\" onclick=alert(1) <script>", Privacy::Public)).await;
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
    // A URL paste redirects with no HTML body, so only the status and security headers apply.
    let res = app.get(&format!("/{url}")).await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(res.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(res.headers()[header::REFERRER_POLICY], "no-referrer");
    check("private locked", app.get(&format!("/{private}")).await, StatusCode::OK).await;
    let unlock = app.post_form(&format!("/{private}/unlock"), "password=pw").await;
    check("private unlocked", unlock, StatusCode::OK).await;
    check("secret shell", app.get(&format!("/{secret}")).await, StatusCode::OK).await;
    let res = app.get(&format!("/{burning}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("That was the last read"), "burned branch must render");
    assert_clean_html(&html);
    let res = app.get(&format!("/{hostile}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("hello"), "hostile paste must render its text");
    assert_clean_html(&html);
    let wrong = app.post_form(&format!("/{readonly}/delete"), "password=wrong").await;
    check("delete page", wrong, StatusCode::FORBIDDEN).await;
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

fn panics(html: &str) -> bool {
    std::panic::catch_unwind(|| assert_clean_html(html)).is_err()
}

#[test]
fn the_scanner_rejects_inline_code_and_unlisted_addresses() {
    let bad = [
        "<p STYLE=\"x\">",
        "<img/onerror=x>",
        "<a\tonclick=\"x\">",
        "<a\nONCLICK = 'x'>",
        "<a hx-on:click=\"x\">",
        "<script>x</script>",
        "<script data-src=\"a.js\"></script>",
        "<script src=\"/a.js\">alert(1)</script>",
        "<a href=https://evil>",
        "<a HREF = \"https://evil.com\">",
        "<a href=\"//evil.com\">",
        "<a href=\"javascript:x\">",
        "<a href=\"JaVaScRiPt:x\">",
        "<img srcset=\"/a 1x, https://evil 2x\">",
        "<button formaction=\"https://evil\">",
        "<video poster=\"http://evil\">",
        "<meta http-equiv=\"refresh\" content=\"0; url=https://evil\">",
        "<a href=\"https://s.example.evil.com\">",
        "<a href=\"https://s.example.evil.com/x\">",
        "<a href=\"https://paste.example@evil.com\">",
        "<a href=\"data:text/html,x\">",
        "<img src=\"ftp://x\">",
    ];
    for html in bad {
        assert!(panics(html), "{html} must be rejected");
    }
}

#[test]
fn the_scanner_accepts_escaped_text_and_configured_addresses() {
    let good = [
        "<pre>style=&quot;x&quot; onclick=alert(1) &lt;script&gt;</pre>",
        "<p>alert(1) confirm(x) prompt(y) and 1 < 2 style=x</p>",
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1 1\"></svg>",
        "<a href=\"https://s.example/happy-apple-banana\">",
        "<a href=\"https://paste.example\">",
        "<a href=\"https://translate.example/t?from=x#y\">",
        "<a href=\"/relative?a=b:c\" data-oc-copy=\"https://anything\">",
        "<img src=\"data:image/png;base64,AAAA\">",
        "<a href=\"mailto:a@b.c\">",
        "<script src=\"/assets/a.js\"></script>",
        "<!-- <a href=\"https://evil\" style=\"x\"> -->",
        "<button data-on=\"x\" aria-label=\"one=two\">",
    ];
    for html in good {
        assert!(!panics(html), "{html} must pass");
    }
}
