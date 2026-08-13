use std::{env, net::SocketAddr};

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod crash_ingest;
mod project_setup;

use project_setup::{ServerState, migrate, router};

#[derive(Parser)]
#[command(version, about = "CacheLane backend")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Subcommand)]
enum Command {
    Api,
    Ingest,
    Worker,
    Scheduler,
    Migrate,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .json()
        .init();

    match Cli::parse().command.unwrap_or(Command::Api) {
        Command::Api => serve("api", "CACHELANE_API_PORT", 8080).await?,
        Command::Ingest => serve("ingest", "CACHELANE_INGEST_PORT", 8081).await?,
        Command::Worker => wait_for_shutdown("worker").await?,
        Command::Scheduler => wait_for_shutdown("scheduler").await?,
        Command::Migrate => migrate(&required_env("DATABASE_URL")?).await?,
    }

    Ok(())
}

async fn serve(
    role: &'static str,
    port_variable: &str,
    default_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("CACHELANE_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var(port_variable)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default_port);
    let address: SocketAddr = format!("{host}:{port}").parse()?;
    let state = ServerState::from_environment(&host, role).await?;
    state.start_maintenance(role);
    let listener = tokio::net::TcpListener::bind(address).await?;

    info!(%address, role, "server started");
    axum::serve(
        listener,
        router(role, state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn required_env(name: &str) -> Result<String, std::io::Error> {
    env::var(name).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("missing required environment variable: {name}"),
        )
    })
}

async fn wait_for_shutdown(role: &'static str) -> Result<(), std::io::Error> {
    info!(role, "role started");
    tokio::signal::ctrl_c().await
}
