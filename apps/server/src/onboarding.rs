use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use sqlx::{PgConnection, Row};

use crate::project_setup::ServerState;

const MAX_MISSING_SYMBOLS: usize = 100;

#[derive(Serialize)]
struct OnboardingView {
    state: &'static str,
    event: Option<EventView>,
    release: Option<ReleaseView>,
    missing_symbols: Vec<MissingSymbolView>,
    missing_symbols_truncated: bool,
    commands: OnboardingCommands,
    issue_path: Option<String>,
    diagnostic: Option<DiagnosticView>,
}

#[derive(Serialize)]
struct EventView {
    id: String,
    received_at: String,
    processing_state: String,
}

#[derive(Serialize)]
struct ReleaseView {
    id: Option<String>,
    version: String,
    platform: Option<String>,
    architecture: Option<String>,
    configuration: Option<String>,
}

#[derive(Serialize)]
struct MissingSymbolView {
    required_artifact: String,
    module: String,
    architecture: String,
    debug_id: String,
    code_id: Option<String>,
}

#[derive(Serialize)]
struct OnboardingCommands {
    check: &'static str,
    scan: &'static str,
    token_environment: &'static str,
    upload: Option<String>,
}

#[derive(Serialize)]
struct DiagnosticView {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

struct SelectedEvent {
    id: String,
    received_at: String,
    processing_state: String,
    retryable: bool,
    release_mapping_state: String,
    issue_id: Option<String>,
    release_id: Option<String>,
    release_version: Option<String>,
    observed_version: Option<String>,
    platform: Option<String>,
    architecture: Option<String>,
    configuration: Option<String>,
    readable: bool,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
pub(crate) enum OnboardingError {
    Unauthorized,
    Forbidden,
    NotFound,
    Unavailable,
    Internal,
}

impl IntoResponse for OnboardingError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication is required",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "operation is not allowed",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "resource was not found"),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "service is unavailable",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "request could not be completed",
            ),
        };
        no_store(status, &ErrorBody { code, message })
    }
}

pub(crate) async fn get_onboarding(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Response, OnboardingError> {
    if !state.onboarding_enabled() {
        return Err(OnboardingError::NotFound);
    }
    let actor = crate::auth::authorize_project(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ReadProject,
    )
    .await
    .map_err(map_authorization)?;
    let pool = state.control_pool().ok_or(OnboardingError::Internal)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| OnboardingError::Unavailable)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(|_| OnboardingError::Unavailable)?;
    sqlx::query("SET LOCAL statement_timeout = '2000ms'")
        .execute(&mut *transaction)
        .await
        .map_err(|_| OnboardingError::Unavailable)?;
    let project_slug: String = sqlx::query_scalar(
        "SELECT slug FROM projects WHERE id = $1::uuid AND organization_id = $2::uuid",
    )
    .bind(&actor.project_id)
    .bind(&actor.organization_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| OnboardingError::Unavailable)?
    .ok_or(OnboardingError::NotFound)?;
    let event = select_event(&mut transaction, &actor.organization_id, &actor.project_id).await?;
    let (missing_symbols, missing_symbols_truncated) = if let Some(event) = event.as_ref() {
        if event.readable {
            (Vec::new(), false)
        } else {
            load_missing_symbols(
                &mut transaction,
                &actor.organization_id,
                &actor.project_id,
                &event.id,
            )
            .await?
        }
    } else {
        (Vec::new(), false)
    };
    transaction
        .commit()
        .await
        .map_err(|_| OnboardingError::Unavailable)?;
    let view = onboarding_view(
        &actor.project_id,
        &project_slug,
        event.as_ref(),
        missing_symbols,
        missing_symbols_truncated,
    );
    Ok(no_store(StatusCode::OK, &view))
}

async fn select_event(
    connection: &mut PgConnection,
    organization_id: &str,
    project_id: &str,
) -> Result<Option<SelectedEvent>, OnboardingError> {
    let readable = sqlx::query(
        "SELECT e.id::text AS event_id, to_char(e.received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS received_at, e.processing_state, e.retryable, e.release_mapping_state, i.id::text AS issue_id, rel.id::text AS release_id, left(rel.version, 128) AS release_version, left(r.result #>> '{crash_context,build_version}', 128) AS observed_version, left(COALESCE(rel.platform, r.result #>> '{crash_context,platform,normalized}'), 32) AS platform, left(COALESCE(rel.architecture, r.result #>> '{crash_context,architecture}'), 32) AS architecture, left(COALESCE(rel.configuration, r.result #>> '{crash_context,build_configuration}'), 32) AS configuration, true AS readable FROM crash_events e JOIN issues i ON i.id = e.issue_id AND i.organization_id = e.organization_id AND i.project_id = e.project_id JOIN crash_processing_results r ON r.id = e.current_result_id AND r.organization_id = e.organization_id AND r.project_id = e.project_id AND r.event_id = e.id LEFT JOIN releases rel ON rel.id = e.release_id AND rel.organization_id = e.organization_id AND rel.project_id = e.project_id WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.processing_state = 'processed' AND jsonb_path_exists(r.result, '$.current.symbolication.threads[*].frames[*] ? (@.symbol_status == \"resolved\" && @.function != null && @.source_file != null && @.source_line != null)') ORDER BY e.received_at, e.id LIMIT 1",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| OnboardingError::Unavailable)?;
    if let Some(row) = readable {
        return Ok(Some(selected_event(&row)));
    }
    let row = sqlx::query(
        "SELECT e.id::text AS event_id, to_char(e.received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS received_at, e.processing_state, e.retryable, e.release_mapping_state, e.issue_id::text AS issue_id, rel.id::text AS release_id, left(rel.version, 128) AS release_version, left(r.result #>> '{crash_context,build_version}', 128) AS observed_version, left(COALESCE(rel.platform, r.result #>> '{crash_context,platform,normalized}'), 32) AS platform, left(COALESCE(rel.architecture, r.result #>> '{crash_context,architecture}'), 32) AS architecture, left(COALESCE(rel.configuration, r.result #>> '{crash_context,build_configuration}'), 32) AS configuration, false AS readable FROM crash_events e LEFT JOIN crash_processing_results r ON r.id = e.current_result_id AND r.organization_id = e.organization_id AND r.project_id = e.project_id AND r.event_id = e.id LEFT JOIN releases rel ON rel.id = e.release_id AND rel.organization_id = e.organization_id AND rel.project_id = e.project_id WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid ORDER BY e.received_at DESC, e.id DESC LIMIT 1",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| OnboardingError::Unavailable)?;
    Ok(row.as_ref().map(selected_event))
}

fn selected_event(row: &sqlx::postgres::PgRow) -> SelectedEvent {
    SelectedEvent {
        id: row.get("event_id"),
        received_at: row.get("received_at"),
        processing_state: row.get("processing_state"),
        retryable: row.get("retryable"),
        release_mapping_state: row.get("release_mapping_state"),
        issue_id: row.get("issue_id"),
        release_id: row.get("release_id"),
        release_version: row.get("release_version"),
        observed_version: row.get("observed_version"),
        platform: row.get("platform"),
        architecture: row.get("architecture"),
        configuration: row.get("configuration"),
        readable: row.get("readable"),
    }
}

async fn load_missing_symbols(
    connection: &mut PgConnection,
    organization_id: &str,
    project_id: &str,
    event_id: &str,
) -> Result<(Vec<MissingSymbolView>, bool), OnboardingError> {
    let rows = sqlx::query(
        "WITH event_scope AS (SELECT e.release_id, e.current_result_id FROM crash_events e WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.id = $3::uuid), candidates AS (SELECT w.required_artifact, left(w.module_name, 256) AS module_name, left(w.architecture, 32) AS architecture, left(w.debug_id, 128) AS debug_id, NULLIF(left(w.code_id, 128), '') AS code_id FROM crash_symbol_waiters w JOIN event_scope e ON e.current_result_id = w.result_id WHERE w.organization_id = $1::uuid AND w.project_id = $2::uuid AND w.event_id = $3::uuid UNION SELECT CASE WHEN m.artifact_type = 'pdb' THEN 'pdb' ELSE 'pe' END AS required_artifact, left(m.module_name, 256) AS module_name, left(m.architecture, 32) AS architecture, left(m.debug_id, 128) AS debug_id, NULLIF(left(m.code_id, 128), '') AS code_id FROM release_manifest_artifacts m JOIN event_scope e ON e.release_id = m.release_id WHERE m.organization_id = $1::uuid AND m.project_id = $2::uuid AND m.state IN ('missing', 'mismatch')) SELECT required_artifact, module_name, architecture, debug_id, code_id FROM candidates ORDER BY module_name, required_artifact, debug_id, code_id LIMIT 101",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(event_id)
    .fetch_all(connection)
    .await
    .map_err(|_| OnboardingError::Unavailable)?;
    let truncated = rows.len() > MAX_MISSING_SYMBOLS;
    Ok((
        rows.into_iter()
            .take(MAX_MISSING_SYMBOLS)
            .map(|row| MissingSymbolView {
                required_artifact: row.get("required_artifact"),
                module: row.get("module_name"),
                architecture: row.get("architecture"),
                debug_id: row.get("debug_id"),
                code_id: row.get("code_id"),
            })
            .collect(),
        truncated,
    ))
}

fn onboarding_view(
    project_id: &str,
    project_slug: &str,
    event: Option<&SelectedEvent>,
    missing_symbols: Vec<MissingSymbolView>,
    missing_symbols_truncated: bool,
) -> OnboardingView {
    let state = onboarding_state(event, !missing_symbols.is_empty());
    let release = event.and_then(release_view);
    let upload = release
        .as_ref()
        .map(|release| upload_command(project_slug, release));
    let issue_path = event.and_then(|event| {
        event
            .readable
            .then_some(event.issue_id.as_deref())
            .flatten()
            .map(|issue_id| format!("/projects/{project_id}/issues/{issue_id}"))
    });
    OnboardingView {
        state,
        event: event.map(|event| EventView {
            id: event.id.clone(),
            received_at: event.received_at.clone(),
            processing_state: event.processing_state.clone(),
        }),
        release,
        missing_symbols,
        missing_symbols_truncated,
        commands: OnboardingCommands {
            check: "faultlane unreal check '<project-root>' --package '<packaged-build-root>'",
            scan: "faultlane symbols scan '<symbol-root>'",
            token_environment: "$env:FAULTLANE_TOKEN = '<one-time-upload-token>'",
            upload,
        },
        issue_path,
        diagnostic: diagnostic(state, event),
    }
}

fn onboarding_state(event: Option<&SelectedEvent>, has_missing_symbols: bool) -> &'static str {
    let Some(event) = event else {
        return "waiting";
    };
    if event.readable {
        return "readable_issue";
    }
    match event.processing_state.as_str() {
        "received" | "stored" => "received",
        "awaiting_symbols" if has_missing_symbols => "missing_symbols",
        "failed" => "failed",
        "quarantined" => "quarantined",
        _ => "processing",
    }
}

fn release_view(event: &SelectedEvent) -> Option<ReleaseView> {
    let version = event
        .release_version
        .clone()
        .or_else(|| event.observed_version.clone())?;
    Some(ReleaseView {
        id: event.release_id.clone(),
        version,
        platform: event.platform.clone(),
        architecture: event.architecture.clone(),
        configuration: event.configuration.clone(),
    })
}

fn upload_command(project_slug: &str, release: &ReleaseView) -> String {
    let mut command = format!(
        "faultlane symbols upload '<symbol-root>' --project {} --release {}",
        powershell_literal(project_slug),
        powershell_literal(&release.version)
    );
    if let Some(architecture) = release.architecture.as_deref() {
        command.push_str(" --architecture ");
        command.push_str(&powershell_literal(architecture));
    }
    if let Some(configuration) = release.configuration.as_deref() {
        command.push_str(" --configuration ");
        command.push_str(&powershell_literal(configuration));
    }
    command
}

fn powershell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn diagnostic(state: &str, event: Option<&SelectedEvent>) -> Option<DiagnosticView> {
    match state {
        "missing_symbols" => Some(DiagnosticView {
            code: "matching_symbols_missing",
            message: "Upload the matching PE and PDB files for this release.",
            retryable: true,
        }),
        "failed" => Some(DiagnosticView {
            code: "processing_failed",
            message: "Crash processing failed. Check local service health before retrying.",
            retryable: event.is_some_and(|event| event.retryable),
        }),
        "quarantined" => Some(DiagnosticView {
            code: "crash_quarantined",
            message: "The crash was quarantined by a processing safety limit.",
            retryable: false,
        }),
        "processing" if event.is_some_and(|event| event.release_mapping_state == "ambiguous") => {
            Some(DiagnosticView {
                code: "release_ambiguous",
                message: "More than one release matches this crash metadata.",
                retryable: false,
            })
        }
        "processing" if event.is_some_and(|event| event.release_mapping_state == "missing") => {
            Some(DiagnosticView {
                code: "release_missing",
                message: "Prepare or upload the release artifacts to continue symbolication.",
                retryable: true,
            })
        }
        _ => None,
    }
}

fn map_authorization(error: crate::auth::AuthorizationError) -> OnboardingError {
    match error {
        crate::auth::AuthorizationError::Unauthorized => OnboardingError::Unauthorized,
        crate::auth::AuthorizationError::Forbidden => OnboardingError::Forbidden,
        crate::auth::AuthorizationError::NotFound => OnboardingError::NotFound,
        crate::auth::AuthorizationError::Unavailable => OnboardingError::Unavailable,
    }
}

fn no_store(status: StatusCode, value: &impl Serialize) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(value),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{ReleaseView, SelectedEvent, onboarding_state, powershell_literal, upload_command};

    fn event(state: &str, readable: bool) -> SelectedEvent {
        SelectedEvent {
            id: "event".to_owned(),
            received_at: "2026-08-16T00:00:00Z".to_owned(),
            processing_state: state.to_owned(),
            retryable: false,
            release_mapping_state: "matched".to_owned(),
            issue_id: readable.then(|| "issue".to_owned()),
            release_id: None,
            release_version: None,
            observed_version: None,
            platform: None,
            architecture: None,
            configuration: None,
            readable,
        }
    }

    #[test]
    fn maps_every_public_state_and_quotes_commands() {
        assert_eq!(onboarding_state(None, false), "waiting");
        assert_eq!(
            onboarding_state(Some(&event("stored", false)), false),
            "received"
        );
        assert_eq!(
            onboarding_state(Some(&event("parsed", false)), false),
            "processing"
        );
        assert_eq!(
            onboarding_state(Some(&event("awaiting_symbols", false)), false),
            "processing"
        );
        assert_eq!(
            onboarding_state(Some(&event("awaiting_symbols", false)), true),
            "missing_symbols"
        );
        assert_eq!(
            onboarding_state(Some(&event("failed", false)), false),
            "failed"
        );
        assert_eq!(
            onboarding_state(Some(&event("quarantined", false)), false),
            "quarantined"
        );
        assert_eq!(
            onboarding_state(Some(&event("processed", true)), false),
            "readable_issue"
        );
        assert_eq!(powershell_literal("a'b;$env:X"), "'a''b;$env:X'");
        let release = ReleaseView {
            id: None,
            version: "1.0;$env:X".to_owned(),
            platform: Some("windows".to_owned()),
            architecture: Some("x86_64".to_owned()),
            configuration: Some("Shipping".to_owned()),
        };
        assert_eq!(
            upload_command("project's", &release),
            "faultlane symbols upload '<symbol-root>' --project 'project''s' --release '1.0;$env:X' --architecture 'x86_64' --configuration 'Shipping'"
        );
    }
}
