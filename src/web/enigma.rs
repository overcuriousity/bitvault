use askama::Template;
use axum::Router;
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;

use super::admin::MaybeAdmin;
use super::home::{Options, create_options};
use super::{Extras, page_with, render};
use crate::assets::Assets;
use crate::config::Config;
use crate::domain::Privacy;
use crate::error::Error;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/enigma", get(enigma))
}

#[derive(Template)]
#[template(path = "enigma.html")]
struct Enigma {
    options: Option<Options>,
    copy_icons: String,
    create_icon: String,
}

pub(super) fn enigma_privacy(cfg: &Config) -> Option<Privacy> {
    Privacy::parse(&cfg.app.default_privacy).filter(|p| *p != Privacy::Secret && cfg.offers(*p)).or_else(|| {
        [Privacy::Unlisted, Privacy::Private, Privacy::Public, Privacy::Readonly].into_iter().find(|p| cfg.offers(*p))
    })
}

async fn enigma(State(st): State<AppState>, MaybeAdmin(admin): MaybeAdmin) -> Result<Html<String>, Error> {
    let options = enigma_privacy(&st.cfg).map(|privacy| create_options(&st.cfg, privacy, false, false));
    let body = render(&Enigma {
        options,
        copy_icons: super::copy_icons(),
        create_icon: super::icon("plus", super::IconSize::Tool),
    })?;
    let extras = Extras { js: vec![Assets::url("js/enigma-page.js")], ..Extras::default() };
    page_with(&st, admin, "enigma", "Enigma", body, extras)
}
