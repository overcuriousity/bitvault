#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::{StatusCode, header};
use bitvault::domain::admin::AdminAuth;
use bitvault::domain::expiry::Expiry;
use bitvault::domain::paste::{self, NewPaste};
use bitvault::domain::{self, Privacy};
use support::{ADMIN_CONFIG, App, app, app_with, body_text};

fn new(content: &str, privacy: Privacy, password: Option<&str>) -> NewPaste {
    NewPaste {
        content: content.into(),
        privacy,
        expiry: Expiry::Hour24,
        burn_after_reads: 0,
        syntax: None,
        editable: false,
        password: password.map(Into::into),
        secret: None,
    }
}

async fn create(app: &App, p: NewPaste) -> String {
    paste::create(&app.st, p, None, domain::now()).await.unwrap().words()
}

#[tokio::test]
async fn without_an_admin_password_there_are_no_admin_routes_or_links() {
    let app = app().await;
    assert_eq!(app.get("/admin").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(app.get("/admin/sign-in").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(app.post_form("/admin/sign-in", "password=x").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(app.post_form("/admin/sign-out", "").await.status(), StatusCode::NOT_FOUND);
    assert!(!body_text(app.get("/").await).await.contains("Sign in"));
    assert!(app.st.admin.is_none());
}

#[tokio::test]
async fn admin_requires_sign_in() {
    let app = app_with(ADMIN_CONFIG).await;
    let res = app.get("/admin").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION], "/admin/sign-in");
    let html = body_text(app.get("/admin/sign-in").await).await;
    assert!(html.contains("autocomplete=\"current-password\""));
    assert!(!html.contains("username"));
    assert!(body_text(app.get("/").await).await.contains("Sign in"));
}

#[tokio::test]
async fn a_wrong_admin_password_is_refused_and_rate_limited() {
    let app = app_with(ADMIN_CONFIG).await;
    let res = app.post_form("/admin/sign-in", "password=wrong").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(res.headers().get(header::SET_COOKIE).is_none());
    assert!(body_text(res).await.contains("That password is not right. Check it and try again."));
    for _ in 0..4 {
        assert_eq!(app.post_form("/admin/sign-in", "password=wrong").await.status(), StatusCode::FORBIDDEN);
    }
    let res = app.post_form("/admin/sign-in", "password=admin-pw-123").await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn the_session_cookie_is_host_only_and_http_only() {
    let app = app_with(ADMIN_CONFIG).await;
    let res = app.post_form("/admin/sign-in", "password=admin-pw-123").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION], "/admin");
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with("__Host-bitvault-admin="), "{cookie}");
    for attr in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(cookie.contains(attr), "{cookie}");
    }
    assert!(!cookie.contains("Domain"));
}

#[tokio::test]
async fn the_admin_sees_every_paste_and_can_delete_a_private_one() {
    let mut app = app_with(ADMIN_CONFIG).await;
    let public = create(&app, new("a", Privacy::Public, None)).await;
    let private = create(&app, new("private words", Privacy::Private, Some("pw"))).await;
    let readonly = create(&app, new("guarded", Privacy::Readonly, Some("pw"))).await;
    app.sign_in_admin().await;
    let res = app.get("/admin").await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains(&public) && html.contains(&private));
    assert!(!html.contains("private words"));
    // Signed in, the delete form on a read-only paste's page needs no password.
    let page = body_text(app.get(&format!("/{readonly}")).await).await;
    let form = &page[page.find(&format!("action=\"/{readonly}/delete\"")).unwrap()..];
    assert!(!form[..form.find("</form>").unwrap()].contains("name=\"password\""));
    let res = app.post_form(&format!("/{private}/delete"), "next=admin").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION].to_str().unwrap().split('?').next(), Some("/admin"));
    assert_eq!(app.get(&format!("/{private}")).await.status(), StatusCode::NOT_FOUND);
    assert!(!body_text(app.get("/admin").await).await.contains(&private));
}

#[tokio::test]
async fn admin_responses_are_not_cached() {
    let mut app = app_with(ADMIN_CONFIG).await;
    let w = create(&app, new("a", Privacy::Public, None)).await;
    assert!(app.get("/").await.headers().get(header::CACHE_CONTROL).is_none());
    app.sign_in_admin().await;
    for uri in ["/admin", "/", &format!("/{w}")] {
        let res = app.get(uri).await;
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store", "{uri}");
    }
}

#[tokio::test]
async fn a_forged_session_cookie_is_not_a_session() {
    let mut app = app_with(ADMIN_CONFIG).await;
    app.cookie = Some(format!("__Host-bitvault-admin={}", "ab".repeat(32)));
    let res = app.get("/admin").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(res.headers().get(header::CACHE_CONTROL).is_none());
    let w = create(&app, new("guarded", Privacy::Readonly, Some("pw"))).await;
    assert_eq!(app.post_form(&format!("/{w}/delete"), "").await.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn signing_out_ends_the_session() {
    let mut app = app_with(ADMIN_CONFIG).await;
    app.sign_in_admin().await;
    assert_eq!(app.get("/admin").await.status(), StatusCode::OK);
    let res = app.post_form("/admin/sign-out", "").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(res.headers()[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
    assert_eq!(app.get("/admin").await.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn sessions_expire_after_twelve_idle_hours() {
    let auth = AdminAuth::from_password("pw").await.unwrap();
    assert!(auth.sign_in("nope", 0).await.is_none());
    let token = auth.sign_in("pw", 0).await.unwrap();
    assert_eq!(token.len(), 64);
    assert!(auth.is_valid(&token, 11 * 3600));
    // Use slides the window forward.
    assert!(auth.is_valid(&token, 22 * 3600));
    assert!(!auth.is_valid(&token, 22 * 3600 + 12 * 3600 + 1));
    let other = auth.sign_in("pw", 0).await.unwrap();
    auth.sign_out(&other);
    assert!(!auth.is_valid(&other, 1));
}
