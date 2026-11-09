use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;
use sqlx::SqlitePool;

use crate::config::Config;
use crate::deployment::Deployment;
use crate::error::Error;
use crate::state::AppState;
use crate::{assets, web};

pub fn build(cfg: Config, pool: SqlitePool) -> Result<(Router, AppState), Error> {
    build_with(cfg, pool, Router::new())
}

/// Builds the router and state; `extra` holds routes a caller (or test) adds next to the app's own.
pub fn build_with(cfg: Config, pool: SqlitePool, extra: Router<AppState>) -> Result<(Router, AppState), Error> {
    cfg.validate()?;
    let dep = Deployment::from_config(&cfg)?;
    let files_dir = cfg.data_dir().join("files");
    std::fs::create_dir_all(&files_dir)?;
    let st = AppState { pool, cfg: Arc::new(cfg), dep: Arc::new(dep), files_dir };
    let router = Router::new()
        .merge(web::home::routes())
        .merge(extra)
        .fallback(web::errors::not_found)
        .layer(from_fn_with_state(st.clone(), web::errors::render))
        .with_state(st.clone())
        .merge(assets::router());
    Ok((router, st))
}
