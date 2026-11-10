use std::path::PathBuf;
use std::process::ExitCode;

use bitvault::domain::paste;
use bitvault::{app, config, db};
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// How long in-flight requests may finish after a stop signal; below `TimeoutStopSec` in
/// `deploy/bitvault.service`.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(25);

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
            e.log();
            eprintln!("{}", e.startup_message());
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
    if st.cfg.insecure_http {
        tracing::warn!("Plain HTTP is on: passwords and pastes travel unencrypted on the network.");
    }
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    spawn_watchdog();
    spawn_purge(st.clone());
    let (stopping, mut stopped) = tokio::sync::watch::channel(false);
    let server = axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(async move {
            shutdown().await;
            let _ = stopping.send(true);
        });
    // On a stop signal the server stops accepting and drains; requests still running after
    // DRAIN (an upload can run for an hour) are cut off, inside the unit's TimeoutStopSec.
    let deadline = async move {
        let _ = stopped.wait_for(|s| *s).await;
        tokio::time::sleep(DRAIN).await;
    };
    tokio::select! {
        served = std::future::IntoFuture::into_future(server) => served.map_err(bitvault::error::Error::internal),
        () = deadline => {
            tracing::warn!(seconds = DRAIN.as_secs(), "requests were still running after the drain time; stopping anyway");
            Ok(())
        }
    }
}

/// Removes expired pastes and pastes burned more than ten minutes ago, with their files.
fn spawn_purge(st: bitvault::state::AppState) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(std::time::Duration::from_secs(60));
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            match paste::purge(&st, bitvault::domain::now()).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(removed = n, "purged expired and burned pastes"),
                Err(e) => tracing::error!(error = %e, "the purge failed; it runs again in a minute"),
            }
        }
    });
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
