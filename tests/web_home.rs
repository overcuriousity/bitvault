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
async fn creating_a_text_paste_redirects_to_its_words_with_a_creator_cookie() {
    let app = app().await;
    let res = app.post_multipart("/", &[("content", None, b"hello"), ("privacy", None, b"unlisted")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let location = res.headers()[header::LOCATION].to_str().unwrap();
    assert!(words_shape(location), "{location}");
    let (words, cookie) = support::created(&res);
    let id = bitvault::domain::words::parse(&words).unwrap();
    let token = cookie.split_once('=').unwrap().1;
    assert!(bitvault::domain::grant::check_creator(&app.st.grant_key, token, id, bitvault::domain::now()));
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
    let (words, _) = support::created(&created);
    let spaced = words.replace('-', "  ").to_uppercase();
    let res = app.post_form("/open", &format!("words={}", spaced.replace(' ', "+"))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["hx-redirect"], format!("/{words}"));
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

#[tokio::test]
async fn the_long_expiries_are_offered_only_when_configured() {
    let html = body_text(app_with("[app]\nmax_expiry = \"never\"\n").await.get("/").await).await;
    assert!(!html.contains("value=\"2years\""), "long expiries are opt-in");
    let opted =
        app_with("[app]\nexpiry_choices = [\"24hour\", \"2years\", \"16years\", \"never\"]\nmax_expiry = \"never\"\n")
            .await;
    let html = body_text(opted.get("/").await).await;
    assert!(html.contains("<option value=\"2years\">2 years</option>"), "{html}");
    assert!(html.contains("<option value=\"16years\">16 years</option>"));
    let res = opted.post_multipart("/", &[("content", None, b"long"), ("expiry", None, b"16years")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn the_syntax_choice_defaults_to_automatic_and_keeps_plain_apart() {
    let app = app().await;
    let html = body_text(app.get("/").await).await;
    assert!(html.contains("<option value=\"auto\" selected>Automatic</option>"), "{html}");
    assert!(html.contains("<option value=\"plain\">Plain</option>"));
    let res = app.post_multipart("/", &[("content", None, b"a"), ("syntax", None, b"auto")]).await;
    let (auto, _) = support::created(&res);
    let res = app.post_multipart("/", &[("content", None, b"b"), ("syntax", None, b"plain")]).await;
    let (plain, _) = support::created(&res);
    let meta = |w: &str| {
        let id = bitvault::domain::words::parse(w).unwrap();
        bitvault::domain::paste::meta(&app.st, id, bitvault::domain::now())
    };
    assert_eq!(meta(&auto).await.unwrap().syntax, None);
    assert_eq!(meta(&plain).await.unwrap().syntax.as_deref(), Some("plain"));

    let off = body_text(app_with("[app]\nhighlight = false\n").await.get("/").await).await;
    assert!(!off.contains("value=\"auto\""));
    assert!(off.contains("<option value=\"plain\" selected>Plain</option>"));
}

#[tokio::test]
async fn allow_editing_is_offered_checked_only_when_the_server_allows_editing() {
    let off = body_text(app().await.get("/").await).await;
    assert!(!off.contains("name=\"editable\""));
    let on = app_with("[app]\neditable = true\n").await;
    let html = body_text(on.get("/").await).await;
    assert!(html.contains("<input type=\"checkbox\" name=\"editable\" value=\"on\" checked>"), "{html}");
    // An unchecked box sends nothing, which must mean "not editable" on the web form.
    let res = on.post_multipart("/", &[("content", None, b"x"), ("privacy", None, b"public")]).await;
    let (words, _) = support::created(&res);
    let id = bitvault::domain::words::parse(&words).unwrap();
    assert!(!bitvault::domain::paste::meta(&on.st, id, bitvault::domain::now()).await.unwrap().editable);
}

#[tokio::test]
async fn opening_a_paste_comes_before_the_create_form() {
    let html = body_text(app().await.get("/").await).await;
    let open = html.find("action=\"/open\"").unwrap();
    let create = html.find("id=\"create-form\"").unwrap();
    assert!(open < create);
    assert!(html.contains("list=\"word-list\""));
    assert!(html.contains("<datalist id=\"word-list\"></datalist>"));
    let src = bitvault::assets::Assets::url("bip39-english.txt");
    assert!(html.contains(&format!("data-words-src=\"{src}\"")), "{html}");
}

#[tokio::test]
async fn an_open_prefix_of_each_word_finds_the_paste() {
    let app = app().await;
    let res = app.post_multipart("/", &[("content", None, b"hi")]).await;
    let (words, _) = support::created(&res);
    let short: Vec<String> = words.split('-').map(|w| w.chars().take(4).collect()).collect();
    let res = app.post_form("/open", &format!("words={}", short.join("+"))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["hx-redirect"], format!("/{words}"));
}

#[tokio::test]
async fn privacy_levels_are_grouped_by_how_they_are_protected() {
    let html = body_text(app().await.get("/").await).await;
    let groups: Vec<usize> = ["No password", "Password", "Encrypted in your browser"]
        .iter()
        .map(|g| html.find(&format!("<optgroup label=\"{g}\">")).unwrap_or_else(|| panic!("{g}")))
        .collect();
    assert!(groups.windows(2).all(|w| w[0] < w[1]));
    let at = |v: &str| html.find(&format!("value=\"{v}\"")).unwrap();
    assert!(groups[0] < at("public") && at("unlisted") < groups[1]);
    assert!(groups[1] < at("readonly") && at("private") < groups[2]);
    assert!(groups[2] < at("secret"));
    let only = body_text(app_with("[app]\nprivacy_levels = [\"public\", \"unlisted\"]\n").await.get("/").await).await;
    assert!(only.contains("<optgroup label=\"No password\">"));
    assert!(!only.contains("<optgroup label=\"Password\">") && !only.contains("Encrypted in your browser"));
}

#[tokio::test]
async fn the_options_sit_in_a_summary_before_the_file_input() {
    let html = body_text(app().await.get("/").await).await;
    let details = html.find("<details class=\"bv-options\">").expect("closed options");
    let end = html.find("</details>").unwrap();
    let file = html.find("type=\"file\"").unwrap();
    assert!(end < file);
    for name in
        ["name=\"privacy\"", "name=\"password\"", "name=\"expiry\"", "name=\"burn_after_reads\"", "name=\"syntax\""]
    {
        let at = html.find(name).unwrap();
        assert!(details < at && at < end, "{name} belongs in the options");
    }
    assert!(html.find("name=\"content\"").unwrap() < details);
    assert!(
        html.contains("<span class=\"bv-options__summary\" id=\"options-summary\">Unlisted · 24 hours</span>"),
        "{html}"
    );
    let burning = app_with("[app]\ndefault_burn_after = 3\ndefault_privacy = \"public\"\n").await;
    let html = body_text(burning.get("/").await).await;
    assert!(html.contains(">Public · 24 hours · Burns after 3 reads</span>"), "{html}");
}

#[tokio::test]
async fn the_options_open_when_the_uploader_password_is_needed() {
    let html = body_text(app_with("[app]\nuploader_password = \"x\"\neditable = true\n").await.get("/").await).await;
    let details = html.find("<details class=\"bv-options\" open>").expect("open options");
    let end = html.find("</details>").unwrap();
    for name in ["name=\"uploader_password\"", "name=\"editable\""] {
        let at = html.find(name).unwrap();
        assert!(details < at && at < end, "{name} belongs in the options");
    }
}

#[tokio::test]
async fn the_content_is_focused_and_has_no_placeholder() {
    let html = body_text(app().await.get("/").await).await;
    let at = html.find("<textarea").unwrap();
    let tag = &html[at..at + html[at..].find('>').unwrap()];
    assert!(tag.contains(" autofocus"), "{tag}");
    assert!(!tag.contains("placeholder"), "{tag}");
    assert!(html.contains("data-max-file-mb=\"2048\"") && html.contains("data-max-secret-mb=\"256\""));
}

#[tokio::test]
async fn labels_link_to_their_guide_sections() {
    let html = body_text(app_with("[app]\neditable = true\n").await.get("/").await).await;
    for (id, field) in [
        ("privacy", "Privacy"),
        ("password", "Password"),
        ("expiry", "Expires after"),
        ("burn", "Burn after reads (0 is off)"),
        ("syntax", "Syntax"),
        ("files", "Files"),
        ("editing", "Allow editing"),
    ] {
        assert!(html.contains(&format!("href=\"/guide#{id}\" aria-label=\"Help: {field}\"")), "{id}");
    }
    assert!(html.contains("data-icon=\"circle-question-mark\""));
}
