use std::path::PathBuf;
use std::sync::Arc;

use sqlx::SqlitePool;

use crate::config::Config;
use crate::deployment::Deployment;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub cfg: Arc<Config>,
    pub dep: Arc<Deployment>,
    pub files_dir: PathBuf,
}
