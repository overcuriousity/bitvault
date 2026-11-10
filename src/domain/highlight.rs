use std::sync::LazyLock;

use syntect::html::{ClassStyle, ClassedHTMLGenerator};
use syntect::parsing::{SyntaxReference, SyntaxSet};
use syntect::util::LinesWithEndings;

static SYNTAXES: LazyLock<SyntaxSet> = LazyLock::new(SyntaxSet::load_defaults_newlines);

static LANGUAGES: LazyLock<Vec<(String, String)>> = LazyLock::new(|| {
    let mut list: Vec<(String, String)> = SYNTAXES
        .syntaxes()
        .iter()
        .filter(|s| !s.hidden && s.name != "Plain Text")
        .map(|s| (s.file_extensions.first().cloned().unwrap_or_else(|| s.name.clone()), s.name.clone()))
        .collect();
    list.sort_by_key(|(_, name)| name.to_lowercase());
    list
});

/// The stored token for "Plain": never highlighted. A paste with no token is "Automatic".
pub const PLAIN: &str = "plain";

/// Selectable languages as (token, display name), sorted by name. Plain Text is left out:
/// the forms offer it as [`PLAIN`].
pub fn languages() -> &'static [(String, String)] {
    &LANGUAGES
}

/// Highlighted, HTML-escaped markup using `hl-` classes, or `None` for an unknown token.
pub fn render(text: &str, token: &str) -> Option<String> {
    if token == PLAIN {
        return None;
    }
    let syntax = SYNTAXES.find_syntax_by_token(token).or_else(|| SYNTAXES.find_syntax_by_extension(token))?;
    classed(text, syntax)
}

/// Like [`render`], with the language taken from the first line (a shebang, `<?php`, a mode
/// line); `None` when the first line names none.
pub fn render_auto(text: &str) -> Option<String> {
    let first = text.lines().next()?;
    let syntax = SYNTAXES.find_syntax_by_first_line(first).filter(|s| s.name != "Plain Text")?;
    classed(text, syntax)
}

fn classed(text: &str, syntax: &SyntaxReference) -> Option<String> {
    let mut generator =
        ClassedHTMLGenerator::new_with_class_style(syntax, &SYNTAXES, ClassStyle::SpacedPrefixed { prefix: "hl-" });
    for line in LinesWithEndings::from(text) {
        generator.parse_html_for_line_which_includes_newline(line).ok()?;
    }
    Some(generator.finalize())
}
