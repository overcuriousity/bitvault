pub mod errors;
pub mod home;
pub mod multipart;
pub mod shell;

use askama::Template;
use axum::response::Html;

use crate::error::Error;
use crate::state::AppState;

/// Wraps `body` (already-escaped HTML) in the page shell.
pub fn page(
    st: &AppState,
    admin: bool,
    current: &'static str,
    title: &str,
    body: String,
) -> Result<Html<String>, Error> {
    let layout = shell::Layout {
        title: title.to_owned(),
        current,
        body,
        admin,
        extra_css: Vec::new(),
        extra_js: Vec::new(),
        cfg: st.cfg.clone(),
    };
    layout.render().map(Html).map_err(Error::internal)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IconSize {
    Row,
    #[default]
    Tool,
    Tab,
}

/// The lucide icon inlined so it takes the surrounding text colour. An unknown name gives an
/// empty string, so a typo shows no icon rather than failing a request.
pub fn icon(name: &str, size: IconSize) -> String {
    let Some(file) = crate::assets::Assets::get(&format!("vendor/oc/icons/{name}.svg")) else {
        debug_assert!(false, "unknown icon {name}");
        return String::new();
    };
    let class = match size {
        IconSize::Row => "oc-icon oc-icon--row",
        IconSize::Tool => "oc-icon",
        IconSize::Tab => "oc-icon oc-icon--tab",
    };
    String::from_utf8_lossy(&file.data).trim_end().replacen(
        "class=\"oc-icon\"",
        &format!("class=\"{class}\" data-icon=\"{name}\""),
        1,
    )
}

/// Escapes text for an element body. Quotation marks stay as they are, which keeps messages
/// that quote the user's input readable in the source as well as on screen.
pub fn escape_text(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
