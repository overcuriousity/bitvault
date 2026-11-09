use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn_with_state;
use sqlx::SqlitePool;

use crate::config::Config;
use crate::deployment::Deployment;
use crate::error::Error;
use crate::ratelimit::RateLimiter;
use crate::security;
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
    let st = AppState {
        pool,
        cfg: Arc::new(cfg),
        dep: Arc::new(dep),
        files_dir,
        failures: Arc::new(RateLimiter::new(10, 5)),
    };
    // Uploads get their own group (filled in by the paste routes) so only they may be large and slow.
    let uploads = security::limited(
        Router::new(),
        usize::try_from(st.cfg.app.max_file_mb.saturating_add(1).saturating_mul(1 << 20)).unwrap_or(usize::MAX),
        Duration::from_secs(3600),
    );
    let rest = Router::new()
        .merge(web::home::routes())
        .merge(extra)
        .fallback(web::errors::not_found)
        .layer(from_fn_with_state(st.clone(), web::errors::render))
        .with_state(st.clone());
    let rest = security::limited(rest, 1 << 20, Duration::from_secs(30));
    let router =
        security::secure(uploads.merge(rest).merge(assets::router()), st.dep.clone(), st.cfg.trusted_proxies.clone());
    Ok((router, st))
}
