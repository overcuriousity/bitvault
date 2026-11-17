#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use axum::http::StatusCode;
use support::{app, app_with, body_text};

#[tokio::test]
async fn the_page_renders_with_its_script_and_no_named_text_box() {
    let res = app().await.get("/enigma").await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("id=\"enigma-text\""));
    assert!(html.contains("js/enigma-page.js"));
    assert!(html.contains("name=\"intent\" value=\"create\""));
    let at = html.find("id=\"enigma-text\"").unwrap();
    let start = html[..at].rfind("<textarea").unwrap();
    let end = at + html[at..].find('>').unwrap();
    assert!(!html[start..end].contains("name="), "{}", &html[start..end]);
    let submit = html.find("id=\"enigma-submit\"").unwrap();
    let end = submit + html[submit..].find('>').unwrap();
    assert!(html[submit..end].contains("disabled"));
    // The result has its own copy button, hidden until the script has a result to copy.
    assert!(html.contains("id=\"enigma-result-copy\" aria-label=\"Copy result\""), "{html}");
}

#[tokio::test]
async fn secret_and_syntax_and_files_are_not_offered() {
    let html = body_text(app().await.get("/enigma").await).await;
    for absent in ["value=\"secret\"", "id=\"syntax\"", "type=\"file\"", "id=\"secret-password\""] {
        assert!(!html.contains(absent), "{absent}");
    }
}

#[tokio::test]
async fn the_default_privacy_is_preselected() {
    let app = app_with("[app]\ndefault_privacy = \"unlisted\"\n").await;
    let html = body_text(app.get("/enigma").await).await;
    assert!(html.contains("<option value=\"unlisted\" selected>Unlisted</option>"), "{html}");
}

#[tokio::test]
async fn a_secret_default_falls_back_to_unlisted() {
    let mut app = app_with("public_url = \"https://paste.example\"\n[app]\nprivacy_levels = [\"public\", \"unlisted\", \"secret\"]\ndefault_privacy = \"secret\"\n").await;
    app.origin = ("paste.example".into(), "https://paste.example".into());
    let html = body_text(app.get("/enigma").await).await;
    assert!(html.contains("<option value=\"unlisted\" selected>Unlisted</option>"), "{html}");
}

#[tokio::test]
async fn an_instance_with_only_secret_shows_no_form() {
    let mut app = app_with(
        "public_url = \"https://paste.example\"\n[app]\nprivacy_levels = [\"secret\"]\ndefault_privacy = \"secret\"\n",
    )
    .await;
    app.origin = ("paste.example".into(), "https://paste.example".into());
    let html = body_text(app.get("/enigma").await).await;
    assert!(!html.contains("id=\"enigma-form\""));
    assert!(html.contains("keeps Secret pastes only"));
}

#[tokio::test]
async fn a_result_that_reads_as_paste_words_is_kept_as_a_new_paste() {
    let app = app().await;
    let (words, _) = support::created(&app.post_multipart("/", &[("content", None, b"kept")]).await);
    let res = app.post_multipart("/", &[("content", None, words.as_bytes()), ("intent", None, b"create")]).await;
    let (created, _) = support::created(&res);
    assert_ne!(created, words);
}

#[tokio::test]
async fn every_page_links_to_the_enigma_in_its_footer() {
    let app = app().await;
    for path in ["/", "/guide", "/nope"] {
        let html = body_text(app.get(path).await).await;
        assert!(html.contains("<a href=\"/enigma\""), "{path}");
    }
    let html = body_text(app.get("/enigma").await).await;
    let link = html.find("<a href=\"/enigma\"").unwrap();
    let end = link + html[link..].find('>').unwrap();
    assert!(html[link..end].contains("aria-current=\"page\""));
}
