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
    // Visitors are not invited to sign in; the page is reachable by its address.
    assert!(!body_text(app.get("/").await).await.contains("Sign in"));
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

#[tokio::test]
async fn the_admin_password_matches_in_either_unicode_form() {
    let app = app_with("[app]\nadmin_password = \"caf\\u00e9-admin\"\n").await;
    let typed: String = url::form_urlencoded::byte_serialize("cafe\u{301}-admin".as_bytes()).collect();
    let res = app.post_form("/admin/sign-in", &format!("password={typed}")).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn the_top_bar_shows_admin_and_sign_out_only_when_signed_in() {
    let mut app = app_with(ADMIN_CONFIG).await;
    let anonymous = body_text(app.get("/").await).await;
    assert!(!anonymous.contains("href=\"/admin\"") && !anonymous.contains("/admin/sign-out"));
    app.sign_in_admin().await;
    let html = body_text(app.get("/").await).await;
    assert!(html.contains("href=\"/admin\"") && html.contains("action=\"/admin/sign-out\""));
}

#[tokio::test]
async fn the_shell_links_the_guide_and_api_and_shows_the_version_footer() {
    let app = app().await;
    let html = body_text(app.get("/").await).await;
    assert!(html.contains("href=\"/guide\"") && html.contains("href=\"/docs\""));
    assert!(html.contains(&format!("BitVault {}", env!("CARGO_PKG_VERSION"))));
    assert!(!html.contains("https://github"));
    // The tab bar keeps to New, List and Guide; the API link is for wide screens only.
    let tabs = &html[html.find("class=\"oc-tabbar\"").unwrap()..];
    let tabs = &tabs[..tabs.find("</nav>").unwrap()];
    assert!(tabs.contains("href=\"/guide\"") && !tabs.contains("href=\"/docs\""));
    let unlisted = app_with("[app]\nlisting = false\n").await;
    assert!(!body_text(unlisted.get("/").await).await.contains("href=\"/list\""));
}

#[tokio::test]
async fn the_admin_page_shows_the_version_settings_editable_and_last_read() {
    let mut app =
        app_with("[app]\nadmin_password = \"admin-pw-123\"\nuploader_password = \"secret-up\"\neditable = true\n")
            .await;
    let words = create(&app, NewPaste { editable: true, ..new("a", Privacy::Public, None) }).await;
    assert_eq!(app.get(&format!("/{words}")).await.status(), StatusCode::OK);
    app.sign_in_admin().await;
    let html = body_text(app.get("/admin").await).await;
    assert!(html.contains(&format!("BitVault {}", env!("CARGO_PKG_VERSION"))));
    assert!(html.contains(">Settings<") && html.contains("Uploader password"));
    assert!(!html.contains("secret-up") && !html.contains("admin-pw-123"));
    assert!(html.contains(">Editable<") && html.contains(">Last read<"));
    assert!(html.contains("data-bv-relative=\"ago\""), "a read paste shows its last read as a relative time");
    assert!(html.contains("data-bv-relative=\"expires\""));
    assert!(html.contains("js/paste."), "the page loads the relative-time module");
}

/// [`ADMIN_CONFIG`] with plain HTTP on, reached as a LAN address.
async fn plain_admin_app() -> App {
    let mut app = app_with(&format!("insecure_http = true\nbind = \"0.0.0.0:8080\"\n{ADMIN_CONFIG}")).await;
    app.origin = ("192.168.1.5:8080".into(), "http://192.168.1.5:8080".into());
    app
}

#[tokio::test]
async fn over_plain_http_the_session_cookie_drops_secure_and_the_host_prefix() {
    let app = plain_admin_app().await;
    let res = app.post_form("/admin/sign-in", "password=admin-pw-123").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with("bitvault-admin="), "{cookie}");
    for attr in ["HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(cookie.contains(attr), "{cookie}");
    }
    assert!(!cookie.contains("Secure") && !cookie.contains("__Host-") && !cookie.contains("Domain"), "{cookie}");
}

#[tokio::test]
async fn signing_in_works_over_plain_http_and_the_secure_cookie_name_is_ignored() {
    let mut app = plain_admin_app().await;
    app.sign_in_admin().await;
    assert_eq!(app.get("/admin").await.status(), StatusCode::OK);
    let token = app.cookie.clone().unwrap().split_once('=').unwrap().1.to_owned();
    app.cookie = Some(format!("__Host-bitvault-admin={token}"));
    assert_eq!(app.get("/admin").await.status(), StatusCode::SEE_OTHER);
    let res = app.post_form("/admin/sign-out", "").await;
    let cleared = res.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cleared.starts_with("bitvault-admin=;") && cleared.contains("Max-Age=0"), "{cleared}");
}

#[tokio::test]
async fn over_https_the_plain_cookie_name_is_ignored() {
    let mut app = app_with(ADMIN_CONFIG).await;
    app.sign_in_admin().await;
    let token = app.cookie.clone().unwrap().split_once('=').unwrap().1.to_owned();
    app.cookie = Some(format!("bitvault-admin={token}"));
    assert_eq!(app.get("/admin").await.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn the_admin_settings_show_whether_plain_http_is_on() {
    let row = |on: &str| format!("<dt>Plain HTTP</dt><dd><span class=\"oc-value\">{on}</span></dd>");
    let mut app = app_with(ADMIN_CONFIG).await;
    app.sign_in_admin().await;
    let html = body_text(app.get("/admin").await).await;
    assert!(html.contains(&row("off")), "{html}");
    let mut plain = plain_admin_app().await;
    plain.sign_in_admin().await;
    let html = body_text(plain.get("/admin").await).await;
    assert!(html.contains(&row("on")), "{html}");
    assert!(html.contains("public, unlisted, readonly, private<"), "Secret is not offered over plain HTTP: {html}");
}

/// A native form post as a browser sends it over plain HTTP to a LAN address: the session cookie
/// and an Origin, but no Sec-Fetch-Site (the origin is not trustworthy).
async fn native_post(app: &App, uri: &str, origin: &str, form: &str) -> axum::http::Response<axum::body::Body> {
    let r = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::HOST, &app.origin.0)
        .header(header::ORIGIN, origin)
        .header(header::COOKIE, app.cookie.clone().unwrap())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(form.to_owned()))
        .unwrap();
    app.send(r).await
}

#[tokio::test]
async fn over_plain_http_signed_in_native_posts_with_their_origin_succeed() {
    let mut app = plain_admin_app().await;
    let w = create(&app, new("guarded", Privacy::Readonly, Some("pw"))).await;
    app.sign_in_admin().await;
    let origin = app.origin.1.clone();
    let res = native_post(&app, &format!("/{w}/delete"), &origin, "next=admin").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(app.get(&format!("/{w}")).await.status(), StatusCode::NOT_FOUND);
    let res = native_post(&app, "/admin/sign-out", &origin, "").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(res.headers()[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
}

/// Why plain HTTP sends `Referrer-Policy: same-origin`: under no-referrer the browser would send
/// `Origin: null`, which with a cookie and no Sec-Fetch-Site cannot be told from a cross-site post.
#[tokio::test]
async fn over_plain_http_a_signed_in_post_with_a_null_origin_is_refused() {
    let mut app = plain_admin_app().await;
    let w = create(&app, new("guarded", Privacy::Readonly, Some("pw"))).await;
    app.sign_in_admin().await;
    let res = native_post(&app, &format!("/{w}/delete"), "null", "next=admin").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(native_post(&app, "/admin/sign-out", "null", "").await.status(), StatusCode::FORBIDDEN);
}
