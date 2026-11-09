use std::sync::LazyLock;

use syntect::html::{ClassStyle, ClassedHTMLGenerator};
use syntect::parsing::SyntaxSet;
use syntect::util::LinesWithEndings;

static SYNTAXES: LazyLock<SyntaxSet> = LazyLock::new(SyntaxSet::load_defaults_newlines);

static LANGUAGES: LazyLock<Vec<(String, String)>> = LazyLock::new(|| {
    let mut list: Vec<(String, String)> = SYNTAXES
        .syntaxes()
        .iter()
        .filter(|s| !s.hidden)
        .map(|s| (s.file_extensions.first().cloned().unwrap_or_else(|| s.name.clone()), s.name.clone()))
        .collect();
    list.sort_by_key(|(_, name)| name.to_lowercase());
    list
});

/// Selectable languages as (token, display name), sorted by name.
pub fn languages() -> &'static [(String, String)] {
    &LANGUAGES
}

/// Highlighted, HTML-escaped markup using `hl-` classes, or `None` for an unknown token.
pub fn render(text: &str, token: &str) -> Option<String> {
    let syntax = SYNTAXES.find_syntax_by_token(token).or_else(|| SYNTAXES.find_syntax_by_extension(token))?;
    let mut generator =
        ClassedHTMLGenerator::new_with_class_style(syntax, &SYNTAXES, ClassStyle::SpacedPrefixed { prefix: "hl-" });
    for line in LinesWithEndings::from(text) {
        generator.parse_html_for_line_which_includes_newline(line).ok()?;
    }
    Some(generator.finalize())
}
