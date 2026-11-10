//! `GET /docs`: the vendored Swagger UI on the generated OpenAPI document.

use axum::Router;
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;

use super::admin::MaybeAdmin;
use super::{Extras, page_with};
use crate::assets::Assets;
use crate::error::Error;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/docs", get(docs))
}

async fn docs(State(st): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Result<Html<String>, Error> {
    let body = include_str!("../../templates/docs.html").to_owned();
    let extras = Extras {
        css: vec![Assets::url("vendor/swagger-ui/swagger-ui.css"), Assets::url("css/swagger-overrides.css")],
        js: vec![Assets::url("js/docs.js")],
        // A UMD bundle, so a classic script: as a module its wrapper would find no global object.
        scripts: vec![Assets::url("vendor/swagger-ui/swagger-ui-bundle.js")],
    };
    page_with(&st, admin, "docs", "API", body, extras)
}
