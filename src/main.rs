use std::path::PathBuf;
use std::process::ExitCode;

use bitvault::{app, config, db};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "bitvault", version, about = "A self-hosted pastebin with three-word addresses")]
struct Cli {
    /// TOML config file; BITVAULT__SECTION__KEY environment variables override it.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), bitvault::error::Error> {
    let cfg = config::load(cli.config.as_deref())?;
    cfg.validate()?;
    let bind = cfg.bind;
    let pool = db::open(&cfg.data_dir()).await?;
    let (router, st) = app::build(cfg, pool).await?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| bitvault::error::Error::Invalid(format!("Cannot listen on {bind}: {e}.")))?;
    tracing::info!("Listening on {}", st.dep.origin);
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    spawn_watchdog();
    axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(bitvault::error::Error::internal)
}

fn spawn_watchdog() {
    let mut usec = 0;
    if !sd_notify::watchdog_enabled(false, &mut usec) {
        return;
    }
    let every = std::time::Duration::from_micros(usec / 2);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
        }
    });
}

async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return std::future::pending().await,
    };
    tokio::select! {
        _ = ctrl_c => {},
        _ = term.recv() => {},
    }
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
}
