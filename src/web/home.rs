use askama::Template;
use axum::Router;
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;

use super::page;
use crate::error::Error;
use crate::state::AppState;

#[derive(Template)]
#[template(path = "home.html")]
struct Home;

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(index))
}

async fn index(State(st): State<AppState>) -> Result<Html<String>, Error> {
    let body = Home.render().map_err(Error::internal)?;
    page(&st, false, "new", "New paste", body)
}
