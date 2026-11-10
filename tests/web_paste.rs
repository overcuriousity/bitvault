#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::body::Body;
use axum::http::{StatusCode, header};
use bitvault::assets::Assets;
use bitvault::domain::crypto::{self, PBKDF2_ITERATIONS};
use bitvault::domain::expiry::Expiry;
use bitvault::domain::files::Staging;
use bitvault::domain::paste::{self, NewPaste, SecretParts};
use bitvault::domain::{self, Privacy};
use bytes::Bytes;
use futures_util::stream;
use http_body_util::BodyExt;
use support::{App, app, app_with, body_text};

const SECRET_PASSWORD: &str = "correct horse battery staple";
const VERIFIER_SALT: [u8; 16] = [7; 16];

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

fn with_password(content: &str, privacy: Privacy, password: &str) -> NewPaste {
    NewPaste { password: Some(password.into()), ..new(content, privacy) }
}

fn secret(burn_after_reads: u32) -> NewPaste {
    let container = crypto::seal_alg2_for_tests(
        SECRET_PASSWORD,
        &[9; 16],
        PBKDF2_ITERATIONS,
        br#"{"text":"hi","files":["a.txt"]}"#,
    );
    NewPaste {
        burn_after_reads,
        secret: Some(SecretParts {
            container,
            verifier_salt: VERIFIER_SALT,
            verifier: crypto::browser_verifier(SECRET_PASSWORD, &VERIFIER_SALT),
        }),
        ..new("", Privacy::Secret)
    }
}

fn one_chunk(data: &[u8]) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Unpin + use<> {
    stream::iter([Ok(Bytes::copy_from_slice(data))])
}

async fn create(app: &App, p: NewPaste) -> String {
    paste::create(&app.st, p, None, domain::now()).await.unwrap().words()
}

/// Creates a paste with one attachment named `name`.
async fn create_with_file(app: &App, p: NewPaste, name: &str, data: &[u8]) -> String {
    let mut staging = match p.privacy {
        Privacy::Private => Staging::new_private(&app.st.files_dir).unwrap(),
        _ => Staging::new(&app.st.files_dir).unwrap(),
    };
    if p.privacy == Privacy::Secret {
        staging.add_container(one_chunk(data), u64::MAX).await.unwrap();
    } else {
        staging.add(name, "", one_chunk(data), u64::MAX).await.unwrap();
    }
    paste::create(&app.st, p, Some(staging), domain::now()).await.unwrap().words()
}

async fn read_count(app: &App, words: &str) -> u64 {
    let id = bitvault::domain::words::parse(words).unwrap();
    paste::meta(&app.st, id, domain::now()).await.unwrap().read_count
}

async fn bytes_of(res: axum::http::Response<Body>) -> Vec<u8> {
    res.into_body().collect().await.unwrap().to_bytes().to_vec()
}

/// Every `href`/`src` value in `html` that carries a grant.
fn grant_links(html: &str) -> Vec<String> {
    html.split(['"', '\''])
        .filter(|s| s.starts_with('/') && s.contains("?g="))
        .map(|s| s.replace("&amp;", "&"))
        .collect()
}

fn grant_link(html: &str, part: &str) -> String {
    grant_links(html).into_iter().find(|l| l.contains(part)).unwrap_or_else(|| panic!("no grant link to {part}"))
}

async fn get_with(app: &App, uri: &str, name: &str, value: &str) -> axum::http::Response<Body> {
    app.send(app.req("GET", uri).header(name, value).body(Body::empty()).unwrap()).await
}

#[tokio::test]
async fn a_public_paste_page_shows_the_words_with_copy_buttons() {
    let app = app().await;
    let w = create(&app, new("hello there", Privacy::Public)).await;
    let res = app.get(&format!("/{w}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    for word in w.split('-') {
        assert!(html.contains(word), "{word}");
    }
    assert!(html.contains("hello there"));
    // The copied copy.js reads `data-oc-copy`: one per word plus the full address.
    assert!(html.matches("data-oc-copy=").count() >= 4, "{}", html.matches("data-oc-copy=").count());
    assert!(html.contains(&format!("data-oc-copy=\"http://localhost:8080/{w}\"")));
}

#[tokio::test]
async fn the_paste_view_is_full_width() {
    let app = app().await;
    let w = create(&app, new("wide", Privacy::Unlisted)).await;
    assert!(body_text(app.get(&format!("/{w}")).await).await.contains("class=\"paste-view"));
}

#[tokio::test]
async fn a_url_paste_redirects() {
    let app = app().await;
    let w = create(&app, new("https://example.com/target?q=1", Privacy::Public)).await;
    let res = app.get(&format!("/{w}")).await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(res.headers()[header::LOCATION], "https://example.com/target?q=1");
}

#[tokio::test]
async fn an_address_that_is_not_three_paste_words_is_not_found() {
    let app = app().await;
    assert_eq!(app.get("/favicon.ico").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(app.get("/happy-aple-banana").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(app.get("/happy-apple-banana/raw").await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_private_paste_asks_for_its_password_without_counting_a_read() {
    let app = app().await;
    let w =
        create_with_file(&app, with_password("quietly kept text", Privacy::Private, "pw"), "salary-report.pdf", b"x")
            .await;
    let res = app.get(&format!("/{w}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains(&format!("action=\"/{w}/unlock\"")));
    assert!(html.contains("autocomplete=\"current-password\""));
    assert!(!html.contains("quietly kept text"));
    // File names and sizes of a private paste are private too.
    assert!(!html.contains("salary-report"));
    assert!(grant_links(&html).is_empty());
    assert_eq!(read_count(&app, &w).await, 0);
}

#[tokio::test]
async fn unlocking_with_the_right_password_shows_content_and_grant_links() {
    let app = app().await;
    let w =
        create_with_file(&app, with_password("the plaintext", Privacy::Private, "pw"), "notes.txt", b"file body").await;
    let res = app.post_form(&format!("/{w}/unlock"), "password=pw").await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("the plaintext"));
    assert!(html.contains("notes.txt"));
    assert!(grant_links(&html).iter().all(|l| l.contains("?g=")));
    let file = grant_link(&html, "/file/1");
    let res = app.get(&file).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(bytes_of(res).await, b"file body");
    assert_eq!(app.get(&grant_link(&html, "/zip")).await.status(), StatusCode::OK);
    assert_eq!(read_count(&app, &w).await, 1);
}

#[tokio::test]
async fn a_wrong_password_answers_422_inline() {
    let app = app().await;
    let w = create(&app, with_password("x", Privacy::Private, "pw")).await;
    let res = app.post_form(&format!("/{w}/unlock"), "password=nope").await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = body_text(res).await;
    assert!(html.contains("That password does not open this paste. Check it and try again."));
    assert!(html.contains(&format!("action=\"/{w}/unlock\"")));
}

#[tokio::test]
async fn private_files_need_a_grant() {
    let app = app().await;
    let w = create_with_file(&app, with_password("x", Privacy::Private, "pw"), "a.txt", b"secret bytes").await;
    assert_eq!(app.get(&format!("/{w}/file/1")).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(app.get(&format!("/{w}/file/1?g=forged")).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(app.get(&format!("/{w}/zip")).await.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn private_raw_needs_a_grant_or_the_header() {
    let app = app().await;
    let w = create(&app, with_password("raw text", Privacy::Private, "pw")).await;
    assert_eq!(app.get(&format!("/{w}/raw")).await.status(), StatusCode::UNAUTHORIZED);
    let res = get_with(&app, &format!("/{w}/raw"), "x-paste-password", "pw").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "text/plain; charset=utf-8");
    assert_eq!(body_text(res).await, "raw text");
    let html = body_text(app.post_form(&format!("/{w}/unlock"), "password=pw").await).await;
    let res = app.get(&grant_link(&html, "/raw")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_text(res).await, "raw text");
}

#[tokio::test]
async fn a_secret_page_shell_does_not_count_a_read_but_raw_does() {
    let app = app().await;
    let w = create(&app, secret(0)).await;
    let html = body_text(app.get(&format!("/{w}")).await).await;
    assert!(html.contains("class=\"paste-text"));
    assert_eq!(read_count(&app, &w).await, 0);
    let res = app.get(&format!("/{w}/raw")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(read_count(&app, &w).await, 1);
}

#[tokio::test]
async fn secret_files_are_ciphertext_attachments_and_have_no_zip() {
    let app = app().await;
    let container = crypto::seal_alg2_for_tests(SECRET_PASSWORD, &[3; 16], PBKDF2_ITERATIONS, b"file");
    let w = create_with_file(&app, secret(0), "", &container).await;
    let res = app.get(&format!("/{w}/file/1")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "application/octet-stream");
    assert!(res.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().starts_with("attachment"));
    assert_eq!(bytes_of(res).await, container);
    assert_eq!(app.get(&format!("/{w}/zip")).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn only_raster_images_are_served_inline() {
    let app = app().await;
    let png = create_with_file(&app, new("", Privacy::Public), "photo.png", b"\x89PNG").await;
    let res = app.get(&format!("/{png}/file/1")).await;
    assert_eq!(res.headers()[header::CONTENT_TYPE], "image/png");
    assert!(res.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().starts_with("inline"));
    for name in ["drawing.svg", "page.html", "notes.txt"] {
        let w = create_with_file(&app, new("", Privacy::Public), name, b"<svg onload=alert(1)>").await;
        let res = app.get(&format!("/{w}/file/1")).await;
        let disposition = res.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().to_owned();
        assert!(disposition.starts_with("attachment"), "{name}: {disposition}");
        assert!(disposition.contains(name), "{disposition}");
        assert_eq!(res.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }
}

#[tokio::test]
async fn a_burning_view_still_lets_its_files_download_for_ten_minutes() {
    let app = app().await;
    let w =
        create_with_file(&app, NewPaste { burn_after_reads: 1, ..new("once", Privacy::Public) }, "a.txt", b"abc").await;
    let res = app.get(&format!("/{w}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("once"));
    let link = grant_link(&html, "/file/1");
    let res = app.get(&link).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(bytes_of(res).await, b"abc");
    assert_eq!(app.get(&format!("/{w}/file/1")).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(app.get(&format!("/{w}")).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(app.get(&format!("/{w}/raw")).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_burning_secret_raw_response_carries_a_grant_header() {
    let app = app().await;
    let container = crypto::seal_alg2_for_tests(SECRET_PASSWORD, &[3; 16], PBKDF2_ITERATIONS, b"file");
    let w = create_with_file(&app, secret(1), "", &container).await;
    let res = app.get(&format!("/{w}/raw")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let grant = res.headers()["x-bitvault-grant"].to_str().unwrap().to_owned();
    assert_eq!(app.get(&format!("/{w}/file/1")).await.status(), StatusCode::NOT_FOUND);
    let res = app.get(&format!("/{w}/file/1?g={grant}")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(bytes_of(res).await, container);
}

#[tokio::test]
async fn the_secret_page_exposes_the_verifier_salt_for_delete() {
    let app = app().await;
    let w = create(&app, secret(0)).await;
    let html = body_text(app.get(&format!("/{w}")).await).await;
    assert!(html.contains(&format!("data-verifier-salt=\"{}\"", hex::encode(VERIFIER_SALT))));
}

#[tokio::test]
async fn a_secret_paste_deletes_with_its_verifier() {
    let app = app().await;
    let w = create(&app, secret(0)).await;
    let res = app.post_form(&format!("/{w}/delete"), &format!("verifier={}", hex::encode([1u8; 32]))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let verifier = hex::encode(crypto::browser_verifier(SECRET_PASSWORD, &VERIFIER_SALT));
    let res = app.post_form(&format!("/{w}/delete"), &format!("verifier={verifier}")).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(app.get(&format!("/{w}")).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_is_a_post_and_takes_effect_immediately() {
    let app = app().await;
    let w = create(&app, new("bye", Privacy::Unlisted)).await;
    let html = body_text(app.get(&format!("/{w}")).await).await;
    assert!(html.contains(&format!("action=\"/{w}/delete\"")));
    assert!(html.contains("aria-label=\"Delete paste\""));
    assert_eq!(app.get(&format!("/{w}/delete")).await.status(), StatusCode::METHOD_NOT_ALLOWED);
    let res = app.post_form(&format!("/{w}/delete"), "").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let location = res.headers()[header::LOCATION].to_str().unwrap().to_owned();
    assert_eq!(location.split('?').next(), Some("/"));
    assert!(body_text(app.get(&location).await).await.contains(&format!("Deleted '{w}'")));
    assert_eq!(app.get(&format!("/{w}")).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deleting_a_readonly_or_private_paste_from_its_page_takes_the_password() {
    let app = app().await;
    for privacy in [Privacy::Readonly, Privacy::Private] {
        let w = create(&app, with_password("guarded", privacy, "pw")).await;
        let res = app.post_form(&format!("/{w}/delete"), "password=wrong").await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let html = body_text(res).await;
        assert!(html.contains("That password does not open this paste. Check it and try again."));
        assert!(html.contains(&format!("action=\"/{w}/delete\"")));
        let res = app.post_form(&format!("/{w}/delete"), "password=pw").await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(app.get(&format!("/{w}")).await.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn editing_a_readonly_paste_through_the_form_requires_its_password() {
    let app = app_with("[app]\neditable = true\n").await;
    let w = create(&app, NewPaste { editable: true, ..with_password("before", Privacy::Readonly, "pw") }).await;
    let res = app.get(&format!("/{w}/edit")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("before") && html.contains("name=\"password\""));
    let res = app.post_form(&format!("/{w}/edit"), "content=after&syntax=plain&password=wrong").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(body_text(res).await.contains("That password does not open this paste. Check it and try again."));
    let res = app.post_form(&format!("/{w}/edit"), "content=after&syntax=plain&password=pw").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION], format!("/{w}").as_str());
    assert!(body_text(app.get(&format!("/{w}")).await).await.contains("after"));
}

#[tokio::test]
async fn editing_is_not_offered_unless_both_switches_are_on() {
    let app = app().await;
    let w = create(&app, NewPaste { editable: true, ..new("x", Privacy::Public) }).await;
    assert_eq!(app.get(&format!("/{w}/edit")).await.status(), StatusCode::NOT_FOUND);
    assert!(!body_text(app.get(&format!("/{w}")).await).await.contains(&format!("/{w}/edit")));
    let on = app_with("[app]\neditable = true\n").await;
    let w = create(&on, new("x", Privacy::Public)).await;
    assert_eq!(on.get(&format!("/{w}/edit")).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_translate_link_appears_only_for_plaintext_text_pastes_when_configured() {
    let app = app_with("[app]\ntranslate_url = \"https://translate.example/t\"\n").await;
    let w = create(&app, new("bonjour", Privacy::Public)).await;
    let html = body_text(app.get(&format!("/{w}")).await).await;
    let link = format!("https://translate.example/t?from=http%3A%2F%2Flocalhost%3A8080%2F{w}%2Fraw");
    assert!(html.contains(&link), "{html}");
    let private = create(&app, with_password("bonjour", Privacy::Private, "pw")).await;
    let html = body_text(app.post_form(&format!("/{private}/unlock"), "password=pw").await).await;
    assert!(!html.contains("translate.example"));
    let secret = create(&app, secret(0)).await;
    assert!(!body_text(app.get(&format!("/{secret}")).await).await.contains("translate.example"));
    let plain = support::app().await;
    let w = create(&plain, new("bonjour", Privacy::Public)).await;
    assert!(!body_text(plain.get(&format!("/{w}")).await).await.contains("Translate"));
}

#[tokio::test]
async fn the_qr_dialog_contains_an_inline_svg() {
    let app = app().await;
    let w = create(&app, new("qr", Privacy::Public)).await;
    let html = body_text(app.get(&format!("/{w}")).await).await;
    assert!(html.contains("<dialog") && html.contains("class=\"qr\""));
    let off = app_with("[app]\nqr = false\n").await;
    let w = create(&off, new("qr", Privacy::Public)).await;
    let html = body_text(off.get(&format!("/{w}")).await).await;
    assert!(!html.contains("<dialog") && !html.contains("class=\"qr\""));
}

#[tokio::test]
async fn the_short_url_is_shown_when_configured() {
    let app = app_with("[app]\nshort_url = \"https://s.example\"\n").await;
    let w = create(&app, new("short", Privacy::Public)).await;
    let html = body_text(app.get(&format!("/{w}")).await).await;
    assert!(html.contains(&format!("data-oc-copy=\"https://s.example/{w}\"")));
    assert!(html.contains(&format!(">https://s.example/{w}<")));
}

#[tokio::test]
async fn read_stats_appear_only_when_enabled() {
    let app = app_with("[app]\nread_stats = true\n").await;
    let w = create(&app, new("stats", Privacy::Public)).await;
    assert!(body_text(app.get(&format!("/{w}")).await).await.contains("Reads"));
    let off = support::app().await;
    let w = create(&off, new("stats", Privacy::Public)).await;
    assert!(!body_text(off.get(&format!("/{w}")).await).await.contains("Reads"));
}

#[tokio::test]
async fn large_or_unhighlighted_content_is_rendered_plain() {
    let app = app().await;
    let small = create(&app, NewPaste { syntax: Some("rs".into()), ..new("fn main() {}", Privacy::Public) }).await;
    assert!(body_text(app.get(&format!("/{small}")).await).await.contains("hl-"));
    let big = "fn main() {}\n".repeat(50_000);
    let big = create(&app, NewPaste { syntax: Some("rs".into()), ..new(&big, Privacy::Public) }).await;
    assert!(!body_text(app.get(&format!("/{big}")).await).await.contains("hl-"));
    let off = app_with("[app]\nhighlight = false\n").await;
    let w = create(&off, NewPaste { syntax: Some("rs".into()), ..new("fn main() {}", Privacy::Public) }).await;
    assert!(!body_text(off.get(&format!("/{w}")).await).await.contains("hl-"));
}

#[tokio::test]
async fn code_just_over_the_highlight_limit_renders_plain_and_quickly() {
    let app = app().await;
    let line = "let x = vec![1, 2, 3]; // (((((a|b)*)*)*)*\n";
    let mut code = line.repeat(bitvault::web::paste::HIGHLIGHT_LIMIT / line.len() + 1);
    code.truncate(bitvault::web::paste::HIGHLIGHT_LIMIT + 1);
    let w = create(&app, NewPaste { syntax: Some("rs".into()), ..new(&code, Privacy::Public) }).await;
    let started = std::time::Instant::now();
    let html = body_text(app.get(&format!("/{w}")).await).await;
    assert!(started.elapsed() < std::time::Duration::from_secs(2), "{:?}", started.elapsed());
    assert!(!html.contains("hl-"));
    assert!(html.contains("let x = vec![1, 2, 3];"));
}

#[tokio::test]
async fn list_is_404_and_out_of_the_navigation_when_listing_is_off() {
    let app = app().await;
    let public = create(&app, new("listed", Privacy::Public)).await;
    let unlisted = create(&app, new("hidden", Privacy::Unlisted)).await;
    let html = body_text(app.get("/list").await).await;
    assert!(html.contains(&public) && !html.contains(&unlisted));
    let off = app_with("[app]\nlisting = false\n").await;
    assert_eq!(off.get("/list").await.status(), StatusCode::NOT_FOUND);
    assert!(!body_text(off.get("/").await).await.contains("href=\"/list\""));
}

#[tokio::test]
async fn docs_serves_swagger_from_vendored_files() {
    let html = body_text(app().await.get("/docs").await).await;
    assert!(html.contains(&Assets::url("vendor/swagger-ui/swagger-ui-bundle.js")));
    assert!(html.contains(&Assets::url("js/docs.js")));
    for tag in html.split("<script").skip(1) {
        let open = &tag[..tag.find('>').unwrap()];
        assert!(open.contains("src="), "<script{open}>");
    }
}

#[tokio::test]
async fn guide_renders_as_prose() {
    let html = body_text(app().await.get("/guide").await).await;
    assert!(html.contains("class=\"prose\""));
    let main = &html[html.find("<main").unwrap()..html.find("</main>").unwrap()];
    assert!(!main.contains("http://") && !main.contains("https://"));
}

#[tokio::test]
async fn the_app_is_installable_and_works_offline_without_caching_pastes() {
    let app = app().await;
    let res = app.get("/manifest.webmanifest").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "application/manifest+json");
    let sw = body_text(app.get("/sw.js").await).await;
    assert!(sw.contains("\"/offline\"") && !sw.contains("__SHELL__"));
    assert_eq!(app.get("/offline").await.status(), StatusCode::OK);
    assert!(body_text(app.get("/").await).await.contains("rel=\"manifest\""));
}

#[tokio::test]
async fn pages_carry_no_inline_styles_scripts_or_handlers() {
    let app = app_with("[app]\neditable = true\n").await;
    let w = create_with_file(&app, NewPaste { editable: true, ..new("x", Privacy::Public) }, "a.png", b"x").await;
    let private = create(&app, with_password("x", Privacy::Private, "pw")).await;
    let secret = create(&app, secret(0)).await;
    for uri in [format!("/{w}"), format!("/{w}/edit"), format!("/{private}"), format!("/{secret}"), "/list".into()] {
        let html = body_text(app.get(&uri).await).await;
        let main = &html[html.find("<main").unwrap()..html.find("</main>").unwrap()];
        for bad in ["style=", "<script", " onclick=", " onload=", "hx-on", "confirm(", "alert("] {
            assert!(!main.contains(bad), "{uri}: {bad}");
        }
    }
}

#[tokio::test]
async fn pages_that_show_paste_content_are_never_cached() {
    let app = app_with("[app]\neditable = true\n").await;
    let no_store = |res: &axum::http::Response<Body>, what: &str| {
        assert_eq!(res.headers().get(header::CACHE_CONTROL).map(|v| v.to_str().unwrap()), Some("no-store"), "{what}");
    };
    let public = create(&app, NewPaste { editable: true, ..new("plain", Privacy::Public) }).await;
    no_store(&app.get(&format!("/{public}")).await, "plaintext page");
    let burning = create(&app, NewPaste { burn_after_reads: 1, ..new("once", Privacy::Public) }).await;
    no_store(&app.get(&format!("/{burning}")).await, "burning read");
    no_store(&app.get(&format!("/{public}/edit")).await, "edit form");
    let private = create(&app, NewPaste { editable: true, ..with_password("decrypted", Privacy::Private, "pw") }).await;
    let res = app.post_form(&format!("/{private}/unlock"), "password=pw").await;
    no_store(&res, "unlocked page");
    let html = body_text(res).await;
    no_store(&app.get(&grant_link(&html, "/edit")).await, "private edit form");
    let secret = create(&app, secret(0)).await;
    no_store(&app.get(&format!("/{secret}")).await, "secret shell");
}

#[tokio::test]
async fn editing_without_a_password_asks_for_one() {
    let app = app_with("[app]\neditable = true\n").await;
    for privacy in [Privacy::Readonly, Privacy::Private] {
        let w = create(&app, NewPaste { editable: true, ..with_password("before", privacy, "pw") }).await;
        let res = app.post_form(&format!("/{w}/edit"), "content=after&syntax=plain&password=").await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let html = body_text(res).await;
        assert!(html.contains("Enter the password to change this paste."), "{privacy:?}");
        assert!(!html.contains("That password does not open this paste."));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_burst_of_parallel_wrong_passwords_gets_at_most_five_answers() {
    let app = std::sync::Arc::new(app().await);
    let w = create(&app, with_password("guarded", Privacy::Private, "right")).await;
    let start = std::sync::Arc::new(tokio::sync::Barrier::new(25));
    let tasks: Vec<_> = (0..25)
        .map(|_| {
            let (app, start, uri) = (app.clone(), start.clone(), format!("/{w}/raw"));
            tokio::spawn(async move {
                start.wait().await;
                get_with(&app, &uri, "x-paste-password", "wrong").await.status()
            })
        })
        .collect();
    let mut answered = 0;
    for t in tasks {
        match t.await.unwrap() {
            StatusCode::TOO_MANY_REQUESTS => {}
            StatusCode::FORBIDDEN => answered += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert!(answered <= 5, "{answered} of 25 parallel guesses were checked");
}

#[tokio::test]
async fn the_right_password_on_raw_is_never_limited() {
    let app = app().await;
    let w = create(&app, with_password("mine", Privacy::Private, "right")).await;
    for _ in 0..12 {
        assert_eq!(get_with(&app, &format!("/{w}/raw"), "x-paste-password", "right").await.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn head_requests_neither_count_a_read_nor_burn_the_paste() {
    let app = app_with("[app]\neditable = true\nread_stats = true\n").await;
    let w = create(&app, NewPaste { burn_after_reads: 1, editable: true, ..new("once", Privacy::Unlisted) }).await;
    for uri in [format!("/{w}"), format!("/{w}/raw"), format!("/{w}/edit"), format!("/api/v1/pastes/{w}")] {
        let res = app.send(app.req("HEAD", &uri).body(Body::empty()).unwrap()).await;
        assert_eq!(res.status(), StatusCode::OK, "{uri}");
        assert!(bytes_of(res).await.is_empty(), "{uri}");
    }
    assert_eq!(read_count(&app, &w).await, 0);
    let s = create(&app, secret(1)).await;
    let res = app.send(app.req("HEAD", &format!("/{s}/raw")).body(Body::empty()).unwrap()).await;
    assert_eq!(res.headers()[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(read_count(&app, &s).await, 0);
    assert_eq!(body_text(app.get(&format!("/{w}/raw")).await).await, "once");
    assert_eq!(app.get(&format!("/{w}/raw")).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_expired_grant_link_leads_back_to_the_paste() {
    let app = app_with("[app]\neditable = true\n").await;
    let w = create_with_file(
        &app,
        NewPaste { editable: true, ..with_password("x", Privacy::Private, "pw") },
        "a.txt",
        b"a",
    )
    .await;
    for uri in
        [format!("/{w}/raw?g=old"), format!("/{w}/file/1?g=old"), format!("/{w}/zip?g=old"), format!("/{w}/edit?g=old")]
    {
        let res = app.get(&uri).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{uri}");
        let html = body_text(res).await;
        assert!(html.contains("This link has expired. Open the paste again."), "{uri}: {html}");
        assert!(html.contains(&format!("href=\"/{w}\"")), "{uri}");
    }
}

#[tokio::test]
async fn an_edit_of_almost_a_mebibyte_of_text_is_saved_and_a_larger_one_refused() {
    let app = app_with("[app]\neditable = true\n").await;
    let w = create(&app, NewPaste { editable: true, ..new("small", Privacy::Public) }).await;
    // Every é is two bytes of text and six once form-encoded, so the body is about 3 MiB.
    let text = "é".repeat((1 << 19) - 8);
    let encoded: String = url::form_urlencoded::byte_serialize(text.as_bytes()).collect();
    assert!(encoded.len() > 3 * ((1 << 20) - 64));
    let res = app.post_form(&format!("/{w}/edit"), &format!("content={encoded}&syntax=plain")).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "{}", body_text(res).await);
    assert_eq!(body_text(app.get(&format!("/{w}/raw")).await).await, text);
    let over: String = url::form_urlencoded::byte_serialize("é".repeat((1 << 19) + 1).as_bytes()).collect();
    let res = app.post_form(&format!("/{w}/edit"), &format!("content={over}&syntax=plain")).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Every other form keeps the 1 MiB limit.
    let res = app.post_form(&format!("/{w}/delete"), &format!("password={}", "x".repeat(1 << 20))).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

fn id_of(words: &str) -> bitvault::domain::words::PasteId {
    bitvault::domain::words::parse(words).unwrap()
}

fn creator_cookie(app: &App, words: &str, now: i64) -> String {
    let token = bitvault::domain::grant::issue_creator(&app.st.grant_key, id_of(words), now);
    format!("{}={token}", support::CREATED_COOKIE)
}

fn set_cookie(res: &axum::http::Response<Body>) -> Option<String> {
    res.headers().get(header::SET_COOKIE).map(|v| v.to_str().unwrap().to_owned())
}

fn cleared(words: &str) -> String {
    format!("{}=; Path=/{words}; HttpOnly; SameSite=Lax; Max-Age=0", support::CREATED_COOKIE)
}

#[tokio::test]
async fn a_web_create_sets_a_creator_cookie_for_the_paste_path_only() {
    let app = app().await;
    let res = app.post_multipart("/", &[("content", None, b"hello")]).await;
    let (w, cookie) = support::created(&res);
    assert_eq!(res.headers()[header::LOCATION], format!("/{w}").as_str());
    let token = cookie.split_once('=').unwrap().1;
    assert!(bitvault::domain::grant::check_creator(&app.st.grant_key, token, id_of(&w), domain::now()));
    assert_eq!(set_cookie(&res).unwrap(), format!("{cookie}; Path=/{w}; HttpOnly; SameSite=Lax; Max-Age=600"));

    let mut secure = app_with("public_url = \"https://paste.example\"\n").await;
    secure.origin = ("paste.example".into(), "https://paste.example".into());
    let res = secure.post_multipart("/", &[("content", None, b"hello")]).await;
    let (w, cookie) = support::created(&res);
    let expected = format!("{cookie}; Path=/{w}; HttpOnly; SameSite=Lax; Max-Age=600; Secure");
    assert_eq!(set_cookie(&res).unwrap(), expected);
    let res = secure.get_with_cookie(&format!("/{w}"), &cookie).await;
    assert_eq!(set_cookie(&res).unwrap(), format!("{}; Secure", cleared(&w)));
}

#[tokio::test]
async fn creating_a_url_paste_shows_its_words_instead_of_redirecting() {
    let app = app().await;
    let res = app.post_multipart("/", &[("content", None, b"https://example.com/target?a=1&b=2")]).await;
    let (w, cookie) = support::created(&res);
    let res = app.get_with_cookie(&format!("/{w}"), &cookie).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("Paste created."), "{html}");
    for word in w.split('-') {
        assert!(html.contains(&format!("data-oc-copy=\"{word}\"")), "{word}");
    }
    assert!(html.contains(&format!("data-oc-copy=\"http://localhost:8080/{w}\"")));
    let link =
        "<a href=\"https://example.com/target?a=1&#38;b=2\" rel=\"noreferrer noopener\" data-bv-target>Go to URL</a>";
    assert!(html.contains(link), "{html}");
    assert_eq!(read_count(&app, &w).await, 0);
    assert_eq!(app.get(&format!("/{w}")).await.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn the_creator_view_is_single_use_and_clears_its_cookie() {
    let app = app().await;
    let res = app.post_multipart("/", &[("content", None, b"plain words")]).await;
    let (w, cookie) = support::created(&res);
    let res = app.get_with_cookie(&format!("/{w}"), &cookie).await;
    assert_eq!(set_cookie(&res).unwrap(), cleared(&w));
    assert!(body_text(res).await.contains("Paste created."));
    assert_eq!(read_count(&app, &w).await, 0);
    // The browser has dropped the cleared cookie, so the next visit is an ordinary read.
    let res = app.get(&format!("/{w}")).await;
    assert!(set_cookie(&res).is_none());
    let html = body_text(res).await;
    assert!(html.contains("plain words") && !html.contains("Paste created."), "{html}");
    assert_eq!(read_count(&app, &w).await, 1);
}

#[tokio::test]
async fn the_creator_view_does_not_burn_a_burn_after_one_paste() {
    let app = app().await;
    let res = app.post_multipart("/", &[("content", None, b"only once"), ("burn_after_reads", None, b"1")]).await;
    let (w, cookie) = support::created(&res);
    let html = body_text(app.get_with_cookie(&format!("/{w}"), &cookie).await).await;
    assert!(html.contains("only once") && html.contains("Paste created."), "{html}");
    assert!(!html.contains("That was the last read"));
    assert_eq!(read_count(&app, &w).await, 0);
    let html = body_text(app.get(&format!("/{w}")).await).await;
    assert!(html.contains("only once") && html.contains("That was the last read"), "{html}");
    assert!(!html.contains("Paste created."));
    assert_eq!(app.get(&format!("/{w}")).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(app.get_with_cookie(&format!("/{w}"), &cookie).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_forged_expired_or_misplaced_creator_cookie_is_ignored_and_cleared() {
    use bitvault::domain::grant;
    let app = app().await;
    let url = create(&app, new("https://example.com/target", Privacy::Unlisted)).await;
    let text = create(&app, new("plain words", Privacy::Unlisted)).await;
    let now = domain::now();
    let name = support::CREATED_COOKIE;
    let refused = [
        format!("{name}=forged"),
        format!("{name}="),
        creator_cookie(&app, &url, now - 601),
        format!("{name}={}", grant::issue(&app.st.grant_key, id_of(&url), None, now)),
        // Another paste's cookie, as if sent to this paste's path.
        creator_cookie(&app, &text, now),
    ];
    for cookie in &refused {
        let res = app.get_with_cookie(&format!("/{url}"), cookie).await;
        assert_eq!(res.status(), StatusCode::FOUND, "{cookie}");
        assert_eq!(res.headers()[header::LOCATION], "https://example.com/target");
        assert_eq!(set_cookie(&res).unwrap(), cleared(&url), "{cookie}");
    }
    assert_eq!(read_count(&app, &url).await, refused.len() as u64);
    let res = app.get_with_cookie(&format!("/{text}"), &creator_cookie(&app, &url, now)).await;
    assert_eq!(set_cookie(&res).unwrap(), cleared(&text));
    let html = body_text(res).await;
    assert!(html.contains("plain words") && !html.contains("Paste created."), "{html}");
    assert_eq!(read_count(&app, &text).await, 1);
}

#[tokio::test]
async fn without_the_cookie_a_url_paste_redirects_and_a_text_paste_counts() {
    let app = app().await;
    let res = app.post_multipart("/", &[("content", None, b"https://example.com/target")]).await;
    let (url, _) = support::created(&res);
    let res = app.post_multipart("/", &[("content", None, b"plain words")]).await;
    let (text, _) = support::created(&res);
    let res = app.get(&format!("/{url}")).await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert!(set_cookie(&res).is_none());
    let html = body_text(app.get(&format!("/{text}")).await).await;
    assert!(html.contains("plain words") && !html.contains("Paste created."), "{html}");
    assert_eq!((read_count(&app, &url).await, read_count(&app, &text).await), (1, 1));
    // The query transport is gone: a token in the address is just an unknown parameter.
    let c = creator_cookie(&app, &text, domain::now());
    let token = c.split_once('=').unwrap().1;
    let html = body_text(app.get(&format!("/{text}?c={token}")).await).await;
    assert!(!html.contains("Paste created."), "{html}");
    assert_eq!(read_count(&app, &text).await, 2);
}

#[tokio::test]
async fn url_pastes_have_a_page_with_view() {
    let app = app().await;
    let w = create(&app, new("https://example.com/target", Privacy::Public)).await;
    let res = app.get(&format!("/{w}?view")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let html = body_text(res).await;
    assert!(
        html.contains("href=\"https://example.com/target\" rel=\"noreferrer noopener\" data-bv-target>Go to URL</a>")
    );
    assert!(html.contains("data-oc-copy=\"https://example.com/target\""), "the target has a copy button");
    assert!(html.contains("data-oc-dialog-open=\"qr-dialog\""), "the page offers the QR code");
    assert!(!html.contains("Paste created."));
    assert_eq!(read_count(&app, &w).await, 1);
    let once = create(&app, NewPaste { burn_after_reads: 1, ..new("https://example.com/once", Privacy::Public) }).await;
    let html = body_text(app.get(&format!("/{once}?view")).await).await;
    assert!(html.contains("https://example.com/once") && html.contains("That was the last read"), "{html}");
    assert_eq!(app.get(&format!("/{once}")).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_creator_view_of_a_private_paste_shows_no_content() {
    let app = app().await;
    let parts: &[(&str, Option<&str>, &[u8])] = &[
        ("content", None, b"quietly kept text"),
        ("privacy", None, b"private"),
        ("password", None, b"pw"),
        ("file", Some("salary-report.pdf"), b"file body"),
    ];
    let res = app.post_multipart("/", parts).await;
    let (w, cookie) = support::created(&res);
    let res = app.get_with_cookie(&format!("/{w}"), &cookie).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("Paste created.") && html.contains("Encrypted. Open it with its password."), "{html}");
    assert!(!html.contains("quietly kept text"));
    assert!(!html.contains("salary-report"));
    for hidden in ["/raw", "/file/", "/zip"] {
        assert!(!html.contains(&format!("/{w}{hidden}")), "no {hidden} link without the password");
    }
    assert!(grant_links(&html).is_empty());
    assert!(html.contains(&format!("action=\"/{w}/delete\"")), "the creator can still delete it");
    assert_eq!(read_count(&app, &w).await, 0);
}

#[tokio::test]
async fn the_creator_view_carries_no_store() {
    let app = app().await;
    let res = app.post_multipart("/", &[("content", None, b"hello")]).await;
    let (w, cookie) = support::created(&res);
    let res = app.get_with_cookie(&format!("/{w}"), &cookie).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    assert!(body_text(res).await.contains("Paste created."));
}

#[tokio::test]
async fn the_creator_view_of_a_secret_paste_is_the_secret_shell() {
    let app = app().await;
    let w = create(&app, secret(1)).await;
    let res = app.get_with_cookie(&format!("/{w}"), &creator_cookie(&app, &w, domain::now())).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let html = body_text(res).await;
    assert!(html.contains("Paste created.") && html.contains("id=\"secret-open\""), "{html}");
    assert!(html.contains("js/secret.js"));
}
