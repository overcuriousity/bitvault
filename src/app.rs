use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware::{from_fn, from_fn_with_state};
use sqlx::SqlitePool;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::deployment::Deployment;
use crate::domain::admin::AdminAuth;
use crate::domain::files;
use crate::domain::grant::GrantKey;
use crate::error::Error;
use crate::ratelimit::RateLimiter;
use crate::security;
use crate::state::AppState;
use crate::{api, assets, web};

pub async fn build(cfg: Config, pool: SqlitePool) -> Result<(Router, AppState), Error> {
    build_with(cfg, pool, Router::new()).await
}

/// Builds the router and state; `extra` holds routes a caller (or test) adds next to the app's own.
/// File directories without a paste are removed first, before anything is served.
/// The admin password is hashed here and its plaintext dropped from the config.
pub async fn build_with(
    mut cfg: Config,
    pool: SqlitePool,
    extra: Router<AppState>,
) -> Result<(Router, AppState), Error> {
    cfg.validate()?;
    let admin = match cfg.app.admin_password.take().map(Zeroizing::new) {
        Some(pw) => Some(Arc::new(AdminAuth::from_password(&pw).await?)),
        None => None,
    };
    let dep = Deployment::from_config(&cfg)?;
    let files_dir = cfg.data_dir().join("files");
    std::fs::create_dir_all(&files_dir)?;
    let st = AppState {
        pool,
        cfg: Arc::new(cfg),
        dep: Arc::new(dep),
        files_dir,
        failures: Arc::new(RateLimiter::new(10, 5)),
        lookups: Arc::new(RateLimiter::new(20, 10)),
        grant_key: Arc::new(GrantKey::random()),
        redeemed: Arc::default(),
        admin,
    };
    files::remove_orphans(&st).await?;
    let api = api::routes()?;
    // Uploads get their own group so only they may be large and slow. The limits wrap the routes
    // themselves: a router merged in after `limited` would not get them.
    let uploads = Router::new()
        .merge(web::home::upload_routes())
        .merge(api.uploads)
        .layer(from_fn_with_state(st.clone(), web::errors::render))
        .layer(from_fn_with_state(st.clone(), web::admin::session))
        .with_state(st.clone());
    let uploads = security::limited(
        uploads,
        usize::try_from(st.cfg.app.max_file_mb.saturating_add(1).saturating_mul(1 << 20)).unwrap_or(usize::MAX),
        Duration::from_secs(3600),
    )
    .layer(from_fn(api::json_errors));
    // Edits carry a whole paste's text, which escaping can grow sixfold, like a JSON create.
    let edits = Router::new()
        .merge(web::paste::edit_routes())
        .merge(api.edits)
        .layer(from_fn_with_state(st.clone(), web::lookups::budget))
        .layer(from_fn_with_state(st.clone(), web::errors::render))
        .layer(from_fn_with_state(st.clone(), web::admin::session))
        .with_state(st.clone());
    let edits = security::limited(edits, api::JSON_LIMIT, Duration::from_secs(30)).layer(from_fn(api::json_errors));
    let rest = Router::new()
        .merge(web::home::routes())
        .merge(web::paste::routes())
        .merge(web::files::routes())
        .merge(web::list::routes())
        .merge(web::guide::routes())
        .merge(web::docs::routes())
        .merge(web::pwa::routes())
        .merge(web::admin::routes(&st))
        .merge(api.rest)
        .merge(extra)
        .fallback(web::errors::not_found)
        .layer(from_fn_with_state(st.clone(), web::lookups::budget))
        .layer(from_fn_with_state(st.clone(), web::errors::render))
        .layer(from_fn_with_state(st.clone(), web::admin::session))
        .with_state(st.clone());
    // Outside the limits, so their plain-text refusals under /api/ become JSON errors too.
    let rest = security::limited(rest, 1 << 20, Duration::from_secs(30)).layer(from_fn(api::json_errors));
    let router = security::secure(
        uploads.merge(edits).merge(rest).merge(assets::router()),
        st.dep.clone(),
        st.cfg.trusted_proxies.clone(),
    );
    Ok((router, st))
}
