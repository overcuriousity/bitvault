//! `GET /list`: public pastes, newest first. Absent when `listing` is off.

use askama::Template;
use axum::Router;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use serde::Deserialize;

use super::admin::MaybeAdmin;
use super::{date, page, render};
use crate::domain::{self, paste};
use crate::error::Error;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/list", get(list))
}

#[derive(Deserialize)]
struct ListQuery {
    page: Option<u32>,
}

struct Item {
    words: String,
    meta: String,
}

#[derive(Template)]
#[template(path = "list.html")]
struct List {
    items: Vec<Item>,
    newer: Option<u32>,
    older: Option<u32>,
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
    Query(q): Query<ListQuery>,
) -> Result<Html<String>, Error> {
    if !st.cfg.app.listing {
        return Err(Error::NotFound);
    }
    let number = q.page.unwrap_or(1).max(1);
    let pastes = paste::list_public(&st, number, domain::now()).await?;
    let full = pastes.len() == paste::PAGE_SIZE as usize;
    // Only addresses and dates: showing content here would let a list view read a paste
    // without counting it.
    let items = pastes
        .iter()
        .map(|p| Item { words: p.id.words(), meta: format!("Created {}{}", date(p.created_at), files(p.files.len())) })
        .collect();
    let body = render(&List { items, newer: (number > 1).then(|| number - 1), older: full.then(|| number + 1) })?;
    page(&st, admin, "list", "Public pastes", body)
}
