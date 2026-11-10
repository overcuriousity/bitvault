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
async fn the_content_is_focused_with_an_address_as_its_example() {
    let html = body_text(app().await.get("/").await).await;
    let at = html.find("<textarea").unwrap();
    let tag = &html[at..at + html[at..].find('>').unwrap()];
    assert!(tag.contains(" autofocus"), "{tag}");
    // The example shows the words; the visible label says text belongs here as well.
    assert!(tag.contains("placeholder=\"apple-banana-cherry\""), "{tag}");
    assert!(html.contains("<label for=\"content\">Text, a link, or three words</label>"));
    assert!(html.contains("data-max-file-mb=\"2048\"") && html.contains("data-max-secret-mb=\"256\""));
}

#[tokio::test]
async fn labels_link_to_their_guide_sections() {
    let html = body_text(app_with("[app]\neditable = true\n").await.get("/").await).await;
    for (id, field) in [
        ("privacy", "Privacy"),
        ("password", "Password"),
        ("expiry", "Expires"),
        ("burn", "Burn after reads"),
        ("syntax", "Syntax"),
        ("files", "Files"),
        ("editing", "Allow editing"),
    ] {
        assert!(html.contains(&format!("href=\"/guide#{id}\" aria-label=\"Help: {field}\"")), "{id}");
    }
    assert!(html.contains("data-icon=\"circle-question-mark\""));
}

async fn plain_app() -> support::App {
    let mut app = app_with("insecure_http = true\nbind = \"0.0.0.0:8080\"\n").await;
    app.origin = ("192.168.1.5:8080".into(), "http://192.168.1.5:8080".into());
    app
}

#[tokio::test]
async fn over_plain_http_the_form_does_not_offer_secret() {
    let app = plain_app().await;
    let html = body_text(app.get("/").await).await;
    assert!(html.contains("value=\"private\""));
    assert!(!html.contains("value=\"secret\"") && !html.contains("Encrypted in your browser"), "{html}");
    assert!(!html.contains("id=\"secret-password\""), "no password field for a level that is not offered");
    let guide = body_text(app.get("/guide").await).await;
    assert!(!guide.contains("<h3>Secret</h3>"), "the guide follows the offered levels");
}

#[tokio::test]
async fn over_plain_http_a_secret_create_is_refused_before_any_file() {
    let app = plain_app().await;
    let parts: &[(&str, Option<&str>, &[u8])] = &[("privacy", None, b"secret"), ("file", Some("a"), b"x")];
    let res = app.post_multipart("/", parts).await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("Secret pastes need https."));
    let res = app.post_multipart("/", &[("content", None, b"hello"), ("privacy", None, b"unlisted")]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn one_box_carries_the_word_list_and_says_what_it_does() {
    let html = body_text(app().await.get("/").await).await;
    assert!(!html.contains("action=\"/open\""), "no second form for opening");
    let src = bitvault::assets::Assets::url("bip39-english.txt");
    assert!(html.contains(&format!("data-words-src=\"{src}\"")), "{html}");
    assert!(html.contains("aria-describedby=\"box-echo\""));
    assert!(html.contains("<p class=\"bv-hint\" id=\"box-echo\" aria-live=\"polite\"></p>"), "no prose until needed");
    let actions = html.find("id=\"box-submit\"").unwrap();
    assert!(actions < html.find("id=\"options\"").unwrap(), "the button sits right under the box");
    assert!(html.contains("id=\"box-keep\" name=\"intent\" value=\"create\" hidden>"));
}

#[tokio::test]
async fn the_options_are_open_as_rendered_with_their_summary_before_the_closed_file_field() {
    let html = body_text(app().await.get("/").await).await;
    // Open, so a browser without scripts always shows them; box.js folds them while not needed.
    let options = html.find("<details class=\"bv-options\" id=\"options\" open>").expect("open options");
    let attach = html.find("<details class=\"bv-attach\" id=\"attach\">").expect("closed file field");
    let file = html.find("type=\"file\"").unwrap();
    assert!(html.find("name=\"content\"").unwrap() < options);
    for name in
        ["name=\"privacy\"", "name=\"password\"", "name=\"expiry\"", "name=\"burn_after_reads\"", "name=\"syntax\""]
    {
        let at = html.find(name).unwrap();
        assert!(options < at && at < attach, "{name} sits with the options");
    }
    assert!(attach < file && file < html.rfind("</details>").unwrap());
    assert!(
        html.contains("<span class=\"bv-options__summary\" id=\"options-summary\">Unlisted · 24 hours</span>"),
        "{html}"
    );
    let burning = app_with("[app]\ndefault_burn_after = 3\ndefault_privacy = \"public\"\n").await;
    let html = body_text(burning.get("/").await).await;
    assert!(html.contains(">Public · 24 hours · Burns after 3 reads</span>"), "{html}");
}

#[tokio::test]
async fn the_uploader_password_sits_with_the_options() {
    let html = body_text(app_with("[app]\nuploader_password = \"x\"\neditable = true\n").await.get("/").await).await;
    let attach = html.find("id=\"attach\"").unwrap();
    for name in ["name=\"uploader_password\"", "name=\"editable\""] {
        assert!(html.find(name).unwrap() < attach, "{name} before the files");
    }
}

/// A create from the box with only `content`, as a browser without scripts sends it.
async fn post_box(
    app: &support::App,
    content: &str,
    extra: &[(&str, Option<&str>, &[u8])],
) -> axum::http::Response<axum::body::Body> {
    let mut parts: Vec<(&str, Option<&str>, &[u8])> = vec![("content", None, content.as_bytes())];
    parts.extend_from_slice(extra);
    app.post_multipart("/", &parts).await
}

#[tokio::test]
async fn the_words_of_a_paste_that_exists_open_it_instead_of_making_one() {
    let app = app().await;
    let (words, _) = support::created(&app.post_multipart("/", &[("content", None, b"kept")]).await);
    for typed in [words.replace('-', " "), words.replace('-', ""), format!("  {}  ", words.to_uppercase())] {
        let res = post_box(&app, &typed, &[]).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{typed}");
        assert_eq!(res.headers()[header::LOCATION], format!("/{words}"));
        assert!(res.headers().get(header::SET_COOKIE).is_none(), "opening is no create");
    }
}

#[tokio::test]
async fn words_are_kept_as_text_when_asked_when_files_come_with_them_or_when_no_paste_has_them() {
    let app = app().await;
    let (words, _) = support::created(&app.post_multipart("/", &[("content", None, b"kept")]).await);
    let kept = |res: &axum::http::Response<axum::body::Body>| support::created(res).0;
    assert_ne!(kept(&post_box(&app, &words, &[("intent", None, b"create")]).await), words);
    assert_ne!(kept(&post_box(&app, &words, &[("file", Some("a.txt"), b"x")]).await), words);
    let fresh = bitvault::domain::words::PasteId(7).words();
    let new = kept(&post_box(&app, &fresh, &[]).await);
    let id = bitvault::domain::words::parse(&new).unwrap();
    let paste = bitvault::domain::paste::meta(&app.st, id, bitvault::domain::now()).await.unwrap();
    assert_ne!(new, fresh);
    assert_eq!(paste.privacy, bitvault::domain::Privacy::Unlisted);
}

#[tokio::test]
async fn opening_from_the_box_needs_no_uploader_password_but_keeping_does() {
    let app = app_with("[app]\nuploader_password = \"up\"\n").await;
    let (words, _) = support::created(
        &app.post_multipart("/", &[("uploader_password", None, b"up"), ("content", None, b"kept")]).await,
    );
    let res = post_box(&app, &words, &[]).await;
    assert_eq!(res.headers()[header::LOCATION], format!("/{words}"));
    let res = post_box(&app, "just some text", &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_box_lookup_that_misses_spends_the_lookup_budget() {
    let app = app().await;
    support::created(&post_box(&app, &bitvault::domain::words::PasteId(1).words(), &[]).await);
    for n in 2..11 {
        let res = app.get(&format!("/{}", bitvault::domain::words::PasteId(n).words())).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{n}");
    }
    let res = app.get(&format!("/{}", bitvault::domain::words::PasteId(11).words())).await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    let res = post_box(&app, &bitvault::domain::words::PasteId(12).words(), &[]).await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "a dry budget refuses the box lookup too");
}
