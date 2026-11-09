#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::{StatusCode, header};
use support::{app, app_with, body_text};

fn words_shape(location: &str) -> bool {
    let parts: Vec<&str> = location.strip_prefix('/').unwrap_or("").split('-').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase()))
}

#[tokio::test]
async fn the_form_offers_only_configured_privacy_levels_and_expiries() {
    let app = app_with("[app]\nprivacy_levels = [\"public\", \"unlisted\"]\n").await;
    let html = body_text(app.get("/").await).await;
    assert!(html.contains("value=\"public\""));
    assert!(!html.contains("value=\"private\""));
    let limited = app_with("[app]\nmax_expiry = \"24hour\"\n").await;
    let html = body_text(limited.get("/").await).await;
    assert!(html.contains("value=\"24hour\""));
    assert!(!html.contains("value=\"1week\""));
}

#[tokio::test]
async fn creating_a_text_paste_redirects_to_its_words() {
    let app = app().await;
    let res = app.post_multipart("/", &[("content", None, b"hello"), ("privacy", None, b"unlisted")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let location = res.headers()[header::LOCATION].to_str().unwrap();
    assert!(words_shape(location), "{location}");
}

#[tokio::test]
async fn the_uploader_password_is_required_when_configured() {
    let app = app_with("[app]\nuploader_password = \"letmein\"\n").await;
    let res = app.post_multipart("/", &[("content", None, b"hello")]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(body_text(res).await.contains("Enter the uploader password to create pastes."));
    let res = app.post_multipart("/", &[("uploader_password", None, b"letmein"), ("content", None, b"hello")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn the_uploader_password_matches_in_either_unicode_form() {
    // Configured composed (U+00E9), typed decomposed (e + U+0301).
    let app = app_with("[app]\nuploader_password = \"caf\\u00e9\"\n").await;
    let typed = "cafe\u{301}".as_bytes();
    let res = app.post_multipart("/", &[("uploader_password", None, typed), ("content", None, b"hello")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let res = app.post_multipart("/", &[("uploader_password", None, b"cafe"), ("content", None, b"hello")]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_secret_choice_is_disabled_until_create_js_enables_it() {
    let html = body_text(app().await.get("/").await).await;
    assert!(html.contains("<option value=\"secret\" disabled>Secret</option>"), "{html}");
    assert!(html.contains("<option value=\"unlisted\" selected>Unlisted</option>"));
    let script = String::from_utf8(bitvault::assets::Assets::get("js/create.js").unwrap().data.to_vec()).unwrap();
    assert!(script.contains("option[value=\"secret\"]')?.removeAttribute(\"disabled\")"));
}

#[tokio::test]
async fn the_password_field_never_has_a_name_for_secret_submissions() {
    let html = body_text(app().await.get("/").await).await;
    let at = html.find("id=\"secret-password\"").expect("secret password input");
    let start = html[..at].rfind('<').unwrap();
    let end = at + html[at..].find('>').unwrap();
    assert!(!html[start..end].contains("name="), "{}", &html[start..end]);
    assert!(html.contains("name=\"password\""));
}

#[tokio::test]
async fn text_fields_and_gates_come_before_the_file_input() {
    let html = body_text(app_with("[app]\nuploader_password = \"x\"\n").await.get("/").await).await;
    let file = html.find("type=\"file\"").unwrap();
    for name in ["name=\"content\"", "name=\"privacy\"", "name=\"uploader_password\"", "name=\"expiry\""] {
        assert!(html.find(name).unwrap() < file, "{name} must precede the file input");
    }
}

#[tokio::test]
async fn there_is_exactly_one_primary_button() {
    let html = body_text(app().await.get("/").await).await;
    assert_eq!(html.matches("oc-btn--primary").count(), 1);
    assert!(html.contains("Create paste"));
}

#[tokio::test]
async fn the_page_has_no_inline_styles_scripts_or_handlers() {
    let html = body_text(app().await.get("/").await).await;
    let body = &html[html.find("<main").unwrap()..html.find("</main>").unwrap()];
    for bad in ["style=", "<script", " onclick=", "hx-on", "alert("] {
        assert!(!body.contains(bad), "{bad}");
    }
}

#[tokio::test]
async fn opening_by_words_tolerates_spacing_and_case() {
    let app = app().await;
    let created = app.post_multipart("/", &[("content", None, b"hi")]).await;
    let location = created.headers()[header::LOCATION].to_str().unwrap().to_owned();
    let spaced = location.trim_start_matches('/').replace('-', "  ").to_uppercase();
    let res = app.post_form("/open", &format!("words={}", spaced.replace(' ', "+"))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["hx-redirect"], location.as_str());
}

#[tokio::test]
async fn opening_an_unknown_word_names_it_inline() {
    let res = app().await.post_form("/open", "words=happy+aple+banana").await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_text(res).await;
    assert!(
        body.contains("&quot;aple&quot; is not one of the paste words")
            || body.contains("\"aple\" is not one of the paste words")
    );
    assert!(!body.contains("alert("));
    assert!(!body.contains("<html"));
}

#[tokio::test]
async fn opening_a_well_formed_but_missing_paste_says_so() {
    let res = app().await.post_form("/open", "words=happy+apple+banana").await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("No paste has these words. Check them and try again."));
}
