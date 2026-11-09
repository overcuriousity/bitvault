//! `GET /guide`: how to use this instance, as prose that follows its configuration.

use askama::Template;
use axum::Router;
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;

use super::admin::MaybeAdmin;
use super::{page, render};
use crate::domain::expiry;
use crate::error::Error;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/guide", get(guide))
}

#[derive(Template)]
#[template(path = "guide.html")]
struct Guide {
    cfg_title: String,
    levels: Vec<String>,
    listing: bool,
    editable: bool,
    highlight: bool,
    qr: bool,
    admin: bool,
    uploader_password: bool,
    /// `None` when pastes may be kept forever.
    max_expiry: Option<&'static str>,
    max_file_mb: u64,
    max_secret_file_mb: u64,
}

impl Guide {
    fn offers(&self, level: &str) -> bool {
        self.levels.iter().any(|l| l == level)
    }
}

async fn guide(State(st): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Result<Html<String>, Error> {
    let app = &st.cfg.app;
    let body = render(&Guide {
        cfg_title: app.title.clone(),
        levels: app.privacy_levels.clone(),
        listing: app.listing,
        editable: app.editable,
        highlight: app.highlight,
        qr: app.qr,
        admin: st.admin.is_some(),
        uploader_password: app.uploader_password.is_some(),
        max_expiry: Some(expiry::max(app)).filter(|e| e.seconds().is_some()).map(|e| e.label()),
        max_file_mb: app.max_file_mb,
        max_secret_file_mb: app.max_secret_file_mb,
    })?;
    page(&st, admin, "", "Guide", body)
}
