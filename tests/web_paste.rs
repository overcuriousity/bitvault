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
