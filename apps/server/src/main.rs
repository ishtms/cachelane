use std::{env, net::SocketAddr};

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod alerts;
mod auth;
mod crash_ingest;
mod dashboard;
mod data_rules;
mod identifiers;
mod issues;
mod processor_runner;
mod project_setup;
mod reprocessing;
mod symbol_upload;
mod usage;
mod worker;

use project_setup::{ServerState, migrate, router};

#[derive(Parser)]
#[command(version, about = "FaultLane backend")]
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
    RepairIssue {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        issue_id: String,
    },
    ReconcileStorage {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        project_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .json()
        .init();

    match Cli::parse().command.unwrap_or(Command::Api) {
        Command::Api => serve("api", "FAULTLANE_API_PORT", 8080).await?,
        Command::Ingest => serve("ingest", "FAULTLANE_INGEST_PORT", 8081).await?,
        Command::Worker => {
            let processing = env::var("FAULTLANE_ISOLATED_PROCESSING_ENABLED")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
            match (processing, alerts::enabled_from_environment()) {
                (true, true) => tokio::select! {
                    result = worker::run() => result?,
                    result = alerts::run_worker() => result?,
                },
                (true, false) => worker::run().await?,
                (false, true) => alerts::run_worker().await?,
                (false, false) => wait_for_shutdown("worker").await?,
            }
        }
        Command::Scheduler => {
            if alerts::enabled_from_environment() {
                tokio::select! {
                    result = usage::run_scheduler() => result?,
                    result = alerts::run_scheduler() => result?,
                }
            } else {
                usage::run_scheduler().await?;
            }
        }
        Command::Migrate => migrate(&required_env("DATABASE_URL")?).await?,
        Command::RepairIssue {
            organization_id,
            project_id,
            issue_id,
        } => {
            let report = worker::repair_issue(
                &required_env("DATABASE_URL")?,
                &organization_id,
                &project_id,
                &issue_id,
            )
            .await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Command::ReconcileStorage {
            organization_id,
            project_id,
        } => {
            let report = usage::reconcile_storage(
                &required_env("DATABASE_URL")?,
                &organization_id,
                &project_id,
            )
            .await?;
            println!("{}", serde_json::to_string(&report)?);
        }
    }

    Ok(())
}

async fn serve(
    role: &'static str,
    port_variable: &str,
    default_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("FAULTLANE_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
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
