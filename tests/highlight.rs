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
fn qr_svg_is_styled_by_classes_and_has_no_literal_colour() {
    let svg = qr::svg("https://example.org/amber-otter-lamp").unwrap();
    assert!(svg.starts_with("<svg class=\"qr\""), "{svg}");
    assert!(svg.contains("class=\"qr-bg\"") && svg.contains("class=\"qr-fg\""));
    assert!(!svg.contains("<?xml") && !svg.split_once('>').unwrap().0.contains("width="));
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

#[test]
fn automatic_detection_recognises_common_first_lines() {
    for (first, then) in
        [("#!/usr/bin/env python", "print('hi')\n"), ("#!/bin/bash", "echo hi\n"), ("<?php", "echo 'hi';\n")]
    {
        let html = highlight::render_auto(&format!("{first}\n{then}")).unwrap_or_else(|| panic!("{first}"));
        assert!(html.contains("class=\"hl-"), "{first}: {html}");
    }
}

#[test]
fn automatic_detection_leaves_prose_plain() {
    assert!(highlight::render_auto("Dear team,\nthe meeting moved.\n").is_none());
    assert!(highlight::render_auto("").is_none());
}

#[test]
fn the_plain_token_never_highlights() {
    assert!(highlight::render("#!/bin/bash\necho hi\n", highlight::PLAIN).is_none());
    assert!(!highlight::languages().iter().any(|(t, n)| t == highlight::PLAIN || n == "Plain Text"));
}

#[test]
fn lines_are_wrapped_and_spans_reopened_across_line_breaks() {
    let wrapped = highlight::wrap_lines("a <span class=\"x\">b\nc</span> d\n\ne");
    assert_eq!(
        wrapped,
        "<span class=\"line\">a <span class=\"x\">b\n</span></span><span class=\"line\"><span class=\"x\">c</span> d\n</span><span class=\"line\">\n</span><span class=\"line\">e</span>"
    );
    assert_eq!(highlight::wrap_lines(""), "");
    assert_eq!(highlight::wrap_lines("a\n"), "<span class=\"line\">a\n</span>");
}

#[test]
fn highlighted_output_has_one_line_span_per_line() {
    let html = highlight::render("/* a\n b */\nfn x() {}\n", "rs").unwrap();
    assert_eq!(html.matches("<span class=\"line\">").count(), 3, "{html}");
    assert_eq!(html.matches("<span").count(), html.matches("</span>").count(), "{html}");
}

#[test]
fn a_long_first_line_is_not_searched_for_a_language() {
    let long = format!("#!/bin/bash {}\necho\n", "x".repeat(600));
    assert!(highlight::resolve(&long, None).is_none());
    assert!(highlight::resolve("#!/bin/bash\necho\n", None).is_some());
    assert!(highlight::resolve("#!/bin/bash\n", Some(highlight::PLAIN)).is_none());
}
