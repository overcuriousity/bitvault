//! `GET /list`: public pastes, newest first. Absent when `listing` is off.

use askama::Template;
use axum::Router;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;

use super::admin::MaybeAdmin;
use super::{Extras, PageQuery, TimeView, copy_icons, date, page_with, paste_urls, render};
use crate::assets::Assets;
use crate::domain::{self, paste};
use crate::error::Error;
use crate::security::BaseUrl;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/list", get(list))
}

struct Item {
    words: String,
    meta: String,
    /// `None` never expires.
    expires: Option<TimeView>,
    url: String,
}

#[derive(Template)]
#[template(path = "list.html")]
struct List {
    items: Vec<Item>,
    newer: Option<u32>,
    older: Option<u32>,
    icons: String,
}

fn files(n: usize) -> String {
    match n {
        0 => String::new(),
        1 => " · 1 file".to_owned(),
        n => format!(" · {n} files"),
    }
}

async fn list(
    State(st): State<AppState>,
    MaybeAdmin(admin): MaybeAdmin,
    base: BaseUrl,
    Query(q): Query<PageQuery>,
) -> Result<Html<String>, Error> {
    if !st.cfg.app.listing {
        return Err(Error::NotFound);
    }
    let number = q.number();
    let pastes = paste::list_public(&st, number, domain::now()).await?;
    let (newer, older) = super::neighbours(number, pastes.len());
    // Only addresses and dates: showing content here would let a list view read a paste
    // without counting it.
    let now = domain::now();
    let items = pastes
        .iter()
        .map(|p| {
            let words = p.id.words();
            Item {
                meta: format!("Created {}{}", date(p.created_at), files(p.files.len())),
                expires: TimeView::expiry(p.expires_at, now),
                url: paste_urls(&st, &base, &words).0,
                words,
            }
        })
        .collect();
    let body = render(&List { items, newer, older, icons: copy_icons() })?;
    let extras = Extras { js: vec![Assets::url("js/paste.js")], ..Extras::default() };
    page_with(&st, admin, "list", "Public pastes", body, extras)
}
