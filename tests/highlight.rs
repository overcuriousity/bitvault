#![allow(clippy::unwrap_used, clippy::expect_used)]

use bitvault::domain::{highlight, qr};

const PROBED: [&str; 7] = [
    "--chart-cat-5",
    "--color-accent",
    "--color-success",
    "--color-warning",
    "--color-danger",
    "--color-fg-secondary",
    "--color-fg-muted",
];

#[test]
fn highlighted_output_uses_classes_and_never_inline_styles() {
    let html = highlight::render("fn main() { let x = 1; }\n", "rs").unwrap();
    assert!(html.contains("class=\"hl-"), "{html}");
    assert!(!html.contains("style="), "{html}");
}

#[test]
fn an_unknown_language_returns_nothing() {
    assert!(highlight::render("x", "no-such-language").is_none());
}

#[test]
fn rendered_html_escapes_the_source() {
    let html = highlight::render("<script>alert(1)</script>", "html").unwrap();
    assert!(html.contains("&lt;") && html.contains("&gt;"), "{html}");
    assert!(!html.contains("<script>"), "{html}");
}

#[test]
fn the_language_list_is_sorted_and_includes_rust() {
    let langs = highlight::languages();
    assert!(langs.iter().any(|(t, _)| t == "rs"));
    let names: Vec<String> = langs.iter().map(|(_, n)| n.to_lowercase()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn qr_svg_uses_current_color_and_no_literal_colour() {
    let svg = qr::svg("https://example.org/amber-otter-lamp").unwrap();
    assert!(svg.starts_with("<svg class=\"qr\""), "{svg}");
    assert!(svg.contains("currentColor"));
    assert!(!svg.contains("<?xml") && !svg.contains("width="));
    assert!(!svg.contains("rgb("));
    let bytes = svg.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'#' {
            assert!(!bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit), "{svg}");
        }
    }
}

#[test]
fn syntax_css_uses_only_the_probed_tokens() {
    let css = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/css/syntax.css")).unwrap();
    assert!(!css.contains("rgb(") && !css.contains("hsl("));
    let b = css.as_bytes();
    for (i, c) in b.iter().enumerate() {
        if *c == b'#' {
            assert!(!b.get(i + 1).is_some_and(u8::is_ascii_hexdigit), "hex colour in syntax.css");
        }
    }
    let mut n = 0;
    for part in css.split("var(").skip(1) {
        let name = part.split([')', ',']).next().unwrap().trim();
        assert!(PROBED.contains(&name), "{name} is not a probed token");
        n += 1;
    }
    assert!(n > 0);
}
