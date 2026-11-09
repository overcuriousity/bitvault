pub mod errors;
pub mod home;
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
