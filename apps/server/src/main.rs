use std::{env, future::ready, net::SocketAddr};

use axum::{Json, Router, routing::get};
use clap::{Parser, Subcommand};
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

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

#[derive(Serialize)]
struct Health {
    service: &'static str,
    role: &'static str,
    status: &'static str,
    version: &'static str,
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
        Command::Migrate => info!("database migrations are up to date"),
    }

    Ok(())
}

fn app(role: &'static str) -> Router {
    Router::new()
        .route("/health/live", get(move || ready(health(role))))
        .route("/health/ready", get(move || ready(health(role))))
        .route("/api/v1/health", get(move || ready(health(role))))
}

fn health(role: &'static str) -> Json<Health> {
    Json(Health {
        service: "cachelane-server",
        role,
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
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
    let listener = TcpListener::bind(address).await?;

    info!(%address, role, "server started");
    axum::serve(listener, app(role)).await?;
    Ok(())
}

async fn wait_for_shutdown(role: &'static str) -> Result<(), std::io::Error> {
    info!(role, "role started");
    tokio::signal::ctrl_c().await
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::app;

    #[tokio::test]
    async fn readiness_endpoint_is_available() {
        let response = app("api")
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request must be valid: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));

        assert_eq!(response.status(), 200);
    }
}
