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

/// A language chosen for one paste, ready to render.
#[derive(Clone, Copy)]
pub struct Syntax(&'static SyntaxReference);

/// The first line is only searched for a mode line or shebang when it is this short, so a
/// crafted long line cannot make detection expensive.
const FIRST_LINE_LIMIT: usize = 512;

/// The language for `text`: the one named by `token`, or for an automatic one (`None`) the one
/// the first line names. `None` when there is nothing to highlight, which is cheap to find out
/// and so is decided before any work is queued.
pub fn resolve(text: &str, token: Option<&str>) -> Option<Syntax> {
    match token {
        Some(PLAIN) => None,
        Some(token) => SYNTAXES.find_syntax_by_token(token).or_else(|| SYNTAXES.find_syntax_by_extension(token)),
        None => {
            let first = text.lines().next().filter(|l| l.len() <= FIRST_LINE_LIMIT)?;
            SYNTAXES.find_syntax_by_first_line(first).filter(|s| s.name != "Plain Text")
        }
    }
    .map(Syntax)
}

/// Highlighted, HTML-escaped markup using `hl-` classes, with each line in `<span class="line">`;
/// `None` if the text cannot be parsed.
pub fn render_with(text: &str, syntax: Syntax) -> Option<String> {
    classed(text, syntax.0).map(|html| wrap_lines(&html))
}

/// Like [`render_with`] for a token; `None` for an unknown one.
pub fn render(text: &str, token: &str) -> Option<String> {
    render_with(text, resolve(text, Some(token))?)
}

/// Like [`render`], with the language taken from the first line (a shebang, `<?php`, a mode
/// line); `None` when the first line names none.
pub fn render_auto(text: &str) -> Option<String> {
    render_with(text, resolve(text, None)?)
}

const LINE_OPEN: &str = "<span class=\"line\">";

/// Wraps each line of `html` (escaped text, possibly with `<span>`s that run across lines) in
/// `<span class="line">`. Spans open at a line break are closed there and reopened on the next
/// line, so every line is well-formed on its own. Text ending in a line break gets no empty
/// line after it.
pub fn wrap_lines(html: &str) -> String {
    let mut out = String::with_capacity(html.len() + html.len() / 4);
    let mut open: Vec<&str> = Vec::new();
    let mut line = String::new();
    let mut has_content = false;
    let mut rest = html;
    let flush = |out: &mut String, line: &mut String, open: &[&str]| {
        out.push_str(LINE_OPEN);
        out.push_str(line);
        for _ in open {
            out.push_str("</span>");
        }
        out.push_str("</span>");
        line.clear();
        line.extend(open.iter().copied());
    };
    while let Some(i) = rest.find(['<', '\n']) {
        line.push_str(&rest[..i]);
        has_content |= i > 0;
        if rest.as_bytes()[i] == b'\n' {
            line.push('\n');
            flush(&mut out, &mut line, &open);
            has_content = false;
            rest = &rest[i + 1..];
        } else {
            let end = rest[i..].find('>').map_or(rest.len(), |e| i + e + 1);
            let tag = &rest[i..end];
            if tag.starts_with("</") {
                let closed = open.pop();
                if has_content {
                    line.push_str(tag);
                } else if let Some(closed) = closed {
                    // Closing a span reopened for this line, before any text: it cancels out.
                    line.truncate(line.len() - closed.len());
                }
            } else {
                open.push(tag);
                line.push_str(tag);
                has_content = true;
            }
            rest = &rest[end..];
        }
    }
    line.push_str(rest);
    if has_content || !rest.is_empty() {
        flush(&mut out, &mut line, &open);
    }
    out
}

fn classed(text: &str, syntax: &SyntaxReference) -> Option<String> {
    let mut generator =
        ClassedHTMLGenerator::new_with_class_style(syntax, &SYNTAXES, ClassStyle::SpacedPrefixed { prefix: "hl-" });
    for line in LinesWithEndings::from(text) {
        generator.parse_html_for_line_which_includes_newline(line).ok()?;
    }
    Some(generator.finalize())
}
