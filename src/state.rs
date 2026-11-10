use std::path::PathBuf;
use std::sync::Arc;

use sqlx::SqlitePool;

use crate::config::Config;
use crate::deployment::Deployment;
use crate::domain::admin::AdminAuth;
use crate::domain::grant::GrantKey;
use crate::ratelimit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub cfg: Arc<Config>,
    pub dep: Arc<Deployment>,
    pub files_dir: PathBuf,
    /// Failed password and verifier attempts, 10 per minute with a burst of 5.
    pub failures: Arc<RateLimiter>,
    /// Paste lookups that found nothing, 20 per minute with a burst of 10.
    pub lookups: Arc<RateLimiter>,
    /// Seals download grants; random per process, so a restart voids outstanding grants.
    pub grant_key: Arc<GrantKey>,
    /// Present only when `admin_password` is configured; without it there are no admin routes.
    pub admin: Option<Arc<AdminAuth>>,
}
