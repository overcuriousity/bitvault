use std::path::Path;
use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

use crate::error::Error;

/// Opens `bitvault.sqlite` in `data_dir` (created with mode 0700) and applies the migrations.
pub async fn open(data_dir: &Path) -> Result<SqlitePool, Error> {
    create_private_dir(data_dir)?;
    let opts = SqliteConnectOptions::new()
        .filename(data_dir.join("bitvault.sqlite"))
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new().max_connections(8).connect_with(opts).await?;
    sqlx::migrate!("./migrations").run(&pool).await.map_err(Error::internal)?;
    Ok(pool)
}

fn create_private_dir(dir: &Path) -> Result<(), Error> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.exists() {
        // Listing it proves it is a directory we may use, with the reason when it is not.
        return std::fs::read_dir(dir)
            .map(drop)
            .map_err(|e| Error::Invalid(format!("Cannot open the data directory {}: {e}.", dir.display())));
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| Error::Invalid(format!("Cannot create the data directory {}: {e}.", dir.display())))
}
