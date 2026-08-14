use std::collections::BTreeMap;

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Row};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{crash_ingest::RawObjectError, project_setup::ServerState};

const DEFAULT_PAGE_SIZE: u16 = 50;
const MAX_PAGE_SIZE: u16 = 100;
const MAX_CURSOR_BYTES: usize = 1024;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_COMMENT_BYTES: usize = 8192;
const MAX_LOG_BYTES: usize = 64 * 1024;
const MAX_PROPERTIES: usize = 100;
const MAX_THREADS: usize = 128;
const MAX_FRAMES: usize = 256;
const MAX_INLINES: usize = 64;
const MAX_MISSING_SYMBOLS: usize = 100;
const MAX_HISTORY: usize = 50;
const MAX_DISTRIBUTIONS: usize = 20;

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
pub(crate) enum DashboardError {
    InvalidRequest,
    Forbidden,
    NotFound,
    ResultUnavailable,
    ArtifactUnavailable,
    Unavailable,
    Internal,
}

impl IntoResponse for DashboardError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request is invalid",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "operation is not allowed",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "resource was not found"),
            Self::ResultUnavailable => (
                StatusCode::CONFLICT,
                "result_unavailable",
                "the current processing result is unavailable",
            ),
            Self::ArtifactUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "artifact_unavailable",
                "the retained artifact is unavailable",
            ),
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
        no_store_json(status, &ErrorBody { code, message })
    }
}

struct ProjectScope {
    organization_id: String,
    project_id: String,
    project_slug: String,
}

#[derive(Serialize)]
struct ProjectOverview {
    generated_at: String,
    window: OverviewWindow,
    totals: OverviewTotals,
    events_over_time: Vec<TimeBucket>,
    top_issues: Vec<TopIssue>,
    releases: Vec<Distribution>,
    releases_truncated: bool,
    releases_other_count: i64,
    platforms: Vec<Distribution>,
    platforms_truncated: bool,
    platforms_other_count: i64,
    crash_types: Vec<Distribution>,
    crash_types_truncated: bool,
    crash_types_other_count: i64,
    symbolication: SymbolicationOverview,
    missing_symbol_count: i64,
    ingest: IngestHealth,
    processing: ProcessingHealth,
    observed_usage: ObservedUsage,
}

#[derive(Serialize)]
struct OverviewWindow {
    start: String,
    end: String,
    days: u8,
}

#[derive(Serialize)]
struct OverviewTotals {
    events: i64,
    issues: i64,
    new_issues: i64,
    regressed_issues: i64,
}

#[derive(Serialize)]
struct TimeBucket {
    day: String,
    count: i64,
}

#[derive(Serialize)]
struct TopIssue {
    issue_id: String,
    path: String,
    title: String,
    status: String,
    regression_state: String,
    event_count: i64,
    last_seen_at: String,
}

#[derive(Serialize)]
struct Distribution {
    key: String,
    label: String,
    count: i64,
    truncated: bool,
}

#[derive(Serialize)]
struct SymbolicationOverview {
    readable: i64,
    partial: i64,
    missing: i64,
    failed: i64,
    processing: i64,
    denominator: i64,
    success_percent: Option<f64>,
}

#[derive(Serialize)]
struct IngestHealth {
    last_received_at: Option<String>,
    events_in_window: i64,
    stored_or_received: i64,
}

#[derive(Serialize)]
struct ProcessingHealth {
    pending_jobs: i64,
    leased_jobs: i64,
    failed_jobs: i64,
    dead_jobs: i64,
    oldest_pending_at: Option<String>,
    states: Vec<Distribution>,
}

#[derive(Serialize)]
struct ObservedUsage {
    authoritative: bool,
    cycle_start: String,
    accepted_events: i64,
    retained_raw_bytes: i64,
    project_artifact_bytes: i64,
    organization_projects: i64,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventListQuery {
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Serialize)]
struct EventListResponse {
    items: Vec<EventSummary>,
    next_cursor: Option<String>,
    facets: EventFacets,
}

#[derive(Serialize)]
struct EventSummary {
    event_id: String,
    path: String,
    received_at: String,
    environment: String,
    processing_state: String,
    state_reason: Option<String>,
    release_id: Option<String>,
    release_version: Option<String>,
    crash_type: Option<String>,
    platform: Option<String>,
    architecture: Option<String>,
    engine_version: Option<String>,
    symbolication_state: String,
    comment_excerpt: Option<String>,
    comment_truncated: bool,
    metadata_truncated: bool,
    current_result_id: Option<String>,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct EventFacets {
    releases: Vec<Distribution>,
    releases_truncated: bool,
    releases_other_count: i64,
    platforms: Vec<Distribution>,
    platforms_truncated: bool,
    platforms_other_count: i64,
    architectures: Vec<Distribution>,
    architectures_truncated: bool,
    architectures_other_count: i64,
    environments: Vec<Distribution>,
    environments_truncated: bool,
    environments_other_count: i64,
    crash_types: Vec<Distribution>,
    crash_types_truncated: bool,
    crash_types_other_count: i64,
    processing_states: Vec<Distribution>,
    processing_states_truncated: bool,
    processing_states_other_count: i64,
    custom_context: Vec<ContextFacetGroup>,
}

#[derive(Serialize)]
struct ContextFacetGroup {
    key: String,
    values: Vec<Distribution>,
    values_truncated: bool,
    values_other_count: i64,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct EventDetail {
    event: EventSummary,
    crash_guid: Option<String>,
    crash_guid_truncated: bool,
    release_mapping: ReleaseMapping,
    classification: Option<ClassificationView>,
    error_message: Option<String>,
    error_message_truncated: bool,
    build_version: Option<String>,
    build_version_truncated: bool,
    build_configuration: Option<String>,
    build_configuration_truncated: bool,
    user_comment: Option<String>,
    user_comment_truncated: bool,
    game_data: Vec<PropertyView>,
    game_data_truncated: bool,
    system_context: Vec<PropertyView>,
    system_context_truncated: bool,
    log: Option<LogView>,
    threads: Vec<ThreadView>,
    threads_truncated: bool,
    missing_symbols: Vec<MissingSymbol>,
    missing_symbols_truncated: bool,
    remediation_command: Option<String>,
    processing_history: ProcessingHistory,
    raw_available: bool,
}

#[derive(Serialize)]
struct ReleaseMapping {
    state: String,
    release_id: Option<String>,
    candidate_release_ids: Vec<String>,
    candidate_release_ids_truncated: bool,
}

#[derive(Serialize)]
struct ClassificationView {
    crash_type: String,
    confidence: String,
    evidence: Vec<String>,
    signals: Vec<SignalView>,
    truncated: bool,
}

#[derive(Serialize)]
struct SignalView {
    kind: String,
    confidence: String,
    evidence: Vec<String>,
    truncated: bool,
}

#[derive(Serialize)]
struct PropertyView {
    name: String,
    name_truncated: bool,
    value: String,
    value_truncated: bool,
}

#[derive(Serialize)]
struct LogView {
    name: String,
    text: String,
    truncated: bool,
    invalid_utf8: bool,
    download_path: String,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ThreadView {
    thread_id: u64,
    faulting: bool,
    name: Option<String>,
    name_truncated: bool,
    unwind_status: String,
    unwind_status_truncated: bool,
    frames_truncated: bool,
    frames: Vec<FrameView>,
}

#[derive(Serialize)]
struct FrameView {
    instruction: String,
    module: Option<String>,
    module_relative: Option<String>,
    trust: String,
    symbol_status: String,
    function: Option<String>,
    source_file: Option<String>,
    source_line: Option<u64>,
    inlines: Vec<InlineView>,
    inlines_truncated: bool,
    truncated: bool,
}

#[derive(Serialize)]
struct InlineView {
    function: String,
    source_file: Option<String>,
    source_line: Option<u64>,
    truncated: bool,
}

#[derive(Serialize)]
struct MissingSymbol {
    required_artifact: String,
    module: String,
    architecture: String,
    debug_id: String,
    code_id: Option<String>,
    release_id: String,
    release_version: String,
    truncated: bool,
}

#[derive(Serialize)]
struct ProcessingHistory {
    results: Vec<ResultHistory>,
    results_truncated: bool,
    requests: Vec<RequestHistory>,
    requests_truncated: bool,
}

#[derive(Serialize)]
struct ResultHistory {
    result_id: String,
    schema_version: i32,
    processing_version: i32,
    data_rules_version: i64,
    checksum: String,
    created_at: String,
    current: bool,
}

#[derive(Serialize)]
struct RequestHistory {
    request_id: String,
    source: String,
    state: String,
    failure_code: Option<String>,
    created_at: String,
    completed_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    version: u8,
    kind: String,
    project_id: String,
    filter_hash: String,
    sort_at: String,
    id: String,
}

pub(crate) async fn get_overview(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Response, DashboardError> {
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ReadProject,
        true,
    )
    .await?;
    let pool = state.control_pool().ok_or(DashboardError::Internal)?;
    let mut transaction = pool.begin().await.map_err(|_| DashboardError::Internal)?;
    configure_read_transaction(&mut transaction).await?;
    let scope = transaction_scope(&mut transaction, &actor).await?;
    let overview = load_overview(&mut transaction, &scope).await?;
    transaction
        .commit()
        .await
        .map_err(|_| DashboardError::Internal)?;
    Ok(no_store_json(StatusCode::OK, &overview))
}

pub(crate) async fn list_issue_events(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((project_id, issue_id)): Path<(String, String)>,
    query: Result<Query<EventListQuery>, QueryRejection>,
) -> Result<Response, DashboardError> {
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ReadProject,
        true,
    )
    .await?;
    if !valid_uuid(&issue_id) {
        return Err(DashboardError::NotFound);
    }
    let Query(query) = query.map_err(|_| DashboardError::InvalidRequest)?;
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(DashboardError::InvalidRequest);
    }
    let kind = format!("issue_events:{issue_id}");
    let filter_hash = lower_hex(&Sha256::digest(issue_id.as_bytes()));
    let cursor = query
        .cursor
        .as_deref()
        .map(|value| decode_cursor(value, &kind, &project_id, &filter_hash))
        .transpose()?;
    let pool = state.control_pool().ok_or(DashboardError::Internal)?;
    let mut transaction = pool.begin().await.map_err(|_| DashboardError::Internal)?;
    configure_read_transaction(&mut transaction).await?;
    let scope = transaction_scope(&mut transaction, &actor).await?;
    require_issue(&mut transaction, &scope, &issue_id).await?;
    let mut items =
        load_event_summaries(&mut transaction, &scope, &issue_id, cursor.as_ref(), limit).await?;
    let has_next = items.len() > usize::from(limit);
    items.truncate(usize::from(limit));
    let next_cursor = if has_next {
        items
            .last()
            .map(|event| {
                encode_cursor(&CursorPayload {
                    version: 1,
                    kind,
                    project_id: scope.project_id.clone(),
                    filter_hash,
                    sort_at: event.received_at.clone(),
                    id: event.event_id.clone(),
                })
            })
            .transpose()?
    } else {
        None
    };
    let facets = load_event_facets(&mut transaction, &scope, &issue_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| DashboardError::Internal)?;
    Ok(no_store_json(
        StatusCode::OK,
        &EventListResponse {
            items,
            next_cursor,
            facets,
        },
    ))
}

pub(crate) async fn get_issue_event(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((project_id, issue_id, event_id)): Path<(String, String, String)>,
) -> Result<Response, DashboardError> {
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ReadProject,
        true,
    )
    .await?;
    if !valid_uuid(&issue_id) || !valid_uuid(&event_id) {
        return Err(DashboardError::NotFound);
    }
    let pool = state.control_pool().ok_or(DashboardError::Internal)?;
    let mut transaction = pool.begin().await.map_err(|_| DashboardError::Internal)?;
    configure_read_transaction(&mut transaction).await?;
    let scope = transaction_scope(&mut transaction, &actor).await?;
    let detail = load_event_detail(
        &mut transaction,
        &scope,
        &issue_id,
        &event_id,
        state.raw_artifact_download_enabled() && actor.allows(crate::auth::Permission::ReadRaw),
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| DashboardError::Internal)?;
    Ok(no_store_json(StatusCode::OK, &detail))
}

pub(crate) async fn download_log(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((project_id, issue_id, event_id)): Path<(String, String, String)>,
) -> Result<Response, DashboardError> {
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ReadProject,
        true,
    )
    .await?;
    if !valid_uuid(&issue_id) || !valid_uuid(&event_id) {
        return Err(DashboardError::NotFound);
    }
    let pool = state.control_pool().ok_or(DashboardError::Internal)?;
    let scope = project_scope(pool, &actor).await?;
    let row = sqlx::query(
        "SELECT e.crash_guid, r.result FROM crash_events e JOIN crash_processing_results r ON r.id = e.current_result_id AND r.organization_id = e.organization_id AND r.project_id = e.project_id AND r.event_id = e.id WHERE e.organization_id::text = $1 AND e.project_id::text = $2 AND e.issue_id::text = $3 AND e.id::text = $4",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&issue_id)
    .bind(&event_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| DashboardError::Internal)?
    .ok_or(DashboardError::NotFound)?;
    let result: Value = row.get("result");
    let crash_guid: Option<String> = row.get("crash_guid");
    faultlane_processing::validate_processing_result(&result, crash_guid.as_deref())
        .map_err(|_| DashboardError::ResultUnavailable)?;
    let log =
        project_log(&result, &project_id, &issue_id, &event_id)?.ok_or(DashboardError::NotFound)?;
    attachment_response(
        "text/plain; charset=utf-8",
        &format!("faultlane-event-{event_id}-log.txt"),
        Body::from(log.text),
        None,
    )
}

pub(crate) async fn download_raw(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((project_id, issue_id, event_id)): Path<(String, String, String)>,
) -> Result<Response, DashboardError> {
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ReadRaw,
        true,
    )
    .await?;
    if !state.raw_artifact_download_enabled() {
        return Err(DashboardError::NotFound);
    }
    if !valid_uuid(&issue_id) || !valid_uuid(&event_id) {
        return Err(DashboardError::NotFound);
    }
    let pool = state.control_pool().ok_or(DashboardError::Internal)?;
    let scope = project_scope(pool, &actor).await?;
    let row = sqlx::query(
        "SELECT o.object_key, o.byte_size, o.checksum FROM crash_events e JOIN crash_event_objects o ON o.id = e.raw_object_id AND o.organization_id = e.organization_id AND o.project_id = e.project_id AND o.lifecycle_state = 'stored' WHERE e.organization_id::text = $1 AND e.project_id::text = $2 AND e.issue_id::text = $3 AND e.id::text = $4",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&issue_id)
    .bind(&event_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| DashboardError::Internal)?
    .ok_or(DashboardError::NotFound)?;
    let object_key: String = row.get("object_key");
    let byte_size: i64 = row.get("byte_size");
    let expected_size =
        u64::try_from(byte_size).map_err(|_| DashboardError::ArtifactUnavailable)?;
    let checksum: Vec<u8> = row.get("checksum");
    let object = state
        .crash_ingest()
        .get_raw_object(&object_key, expected_size)
        .await
        .map_err(|error| match error {
            RawObjectError::Missing | RawObjectError::Invalid | RawObjectError::Unavailable => {
                DashboardError::ArtifactUnavailable
            }
        })?;
    crate::auth::audit(
        pool,
        &scope.organization_id,
        Some(&actor.actor.user_id),
        "raw_artifact.downloaded",
        "event",
        &event_id,
        "succeeded",
    )
    .await;
    let body = Body::from_stream(object.into_stream());
    attachment_response(
        "application/octet-stream",
        &format!("faultlane-event-{event_id}-raw.bundle"),
        body,
        Some((expected_size, &checksum)),
    )
}

async fn authorize(
    state: &ServerState,
    headers: &HeaderMap,
    project_id: &str,
    permission: crate::auth::Permission,
    require_dashboard: bool,
) -> Result<crate::auth::ProjectActor, DashboardError> {
    if require_dashboard && !state.dashboard_enabled() {
        return Err(DashboardError::NotFound);
    }
    crate::auth::authorize_project(state, headers, project_id, permission)
        .await
        .map_err(|error| match error {
            crate::auth::AuthorizationError::Forbidden => DashboardError::Forbidden,
            crate::auth::AuthorizationError::Unavailable => DashboardError::Unavailable,
            _ => DashboardError::NotFound,
        })
}

async fn project_scope(
    pool: &PgPool,
    actor: &crate::auth::ProjectActor,
) -> Result<ProjectScope, DashboardError> {
    let project_slug = sqlx::query_scalar::<_, String>(
        "SELECT slug FROM projects WHERE organization_id::text = $1 AND id::text = $2",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| DashboardError::Internal)?
    .ok_or(DashboardError::NotFound)?;
    Ok(ProjectScope {
        organization_id: actor.organization_id.clone(),
        project_id: actor.project_id.clone(),
        project_slug,
    })
}

async fn transaction_scope(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &crate::auth::ProjectActor,
) -> Result<ProjectScope, DashboardError> {
    let project_slug = sqlx::query_scalar::<_, String>(
        "SELECT slug FROM projects WHERE organization_id::text = $1 AND id::text = $2",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| DashboardError::Internal)?
    .ok_or(DashboardError::NotFound)?;
    Ok(ProjectScope {
        organization_id: actor.organization_id.clone(),
        project_id: actor.project_id.clone(),
        project_slug,
    })
}

async fn configure_read_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), DashboardError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut **transaction)
        .await
        .map_err(|_| DashboardError::Internal)?;
    sqlx::query("SET LOCAL statement_timeout = '2s'")
        .execute(&mut **transaction)
        .await
        .map_err(|_| DashboardError::Internal)?;
    Ok(())
}

async fn require_issue(
    connection: &mut PgConnection,
    scope: &ProjectScope,
    issue_id: &str,
) -> Result<(), DashboardError> {
    let found: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM issues WHERE organization_id::text = $1 AND project_id::text = $2 AND id::text = $3)",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    found.then_some(()).ok_or(DashboardError::NotFound)
}

#[allow(clippy::too_many_lines)]
async fn load_overview(
    connection: &mut PgConnection,
    scope: &ProjectScope,
) -> Result<ProjectOverview, DashboardError> {
    let clock = sqlx::query(
        "WITH current_clock AS (SELECT clock_timestamp() AS value), bounds AS (SELECT value, date_trunc('day', value AT TIME ZONE 'UTC') AS utc_day, date_trunc('month', value AT TIME ZONE 'UTC') AS utc_month FROM current_clock) SELECT to_char(value AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS generated_at, to_char(utc_day - interval '29 days', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS window_start, to_char(utc_day + interval '1 day', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS window_end, to_char(utc_month, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS cycle_start FROM bounds",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let generated_at: String = clock.get("generated_at");
    let window_start: String = clock.get("window_start");
    let window_end: String = clock.get("window_end");
    let cycle_start: String = clock.get("cycle_start");

    let totals = sqlx::query(
        "SELECT (SELECT count(*) FROM crash_events e WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.received_at >= $3::timestamptz AND e.received_at < $4::timestamptz) AS events, count(*) AS issues, count(*) FILTER (WHERE i.first_seen_at >= $3::timestamptz AND i.first_seen_at < $4::timestamptz) AS new_issues, count(*) FILTER (WHERE i.regression_state = 'regressed' AND i.last_seen_at >= $3::timestamptz AND i.last_seen_at < $4::timestamptz) AS regressed_issues FROM issues i WHERE i.organization_id = $1::uuid AND i.project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&window_start)
    .bind(&window_end)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let totals = OverviewTotals {
        events: totals.get("events"),
        issues: totals.get("issues"),
        new_issues: totals.get("new_issues"),
        regressed_issues: totals.get("regressed_issues"),
    };

    let events_over_time = sqlx::query(
        "WITH days AS (SELECT generate_series($3::timestamptz AT TIME ZONE 'UTC', ($4::timestamptz AT TIME ZONE 'UTC') - interval '1 day', interval '1 day') AS day) SELECT to_char(d.day, 'YYYY-MM-DD') AS day, count(e.id) AS count FROM days d LEFT JOIN crash_events e ON e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.received_at >= d.day AT TIME ZONE 'UTC' AND e.received_at < (d.day + interval '1 day') AT TIME ZONE 'UTC' GROUP BY d.day ORDER BY d.day",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&window_start)
    .bind(&window_end)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?
    .iter()
    .map(|row| TimeBucket {
        day: row.get("day"),
        count: row.get("count"),
    })
    .collect();

    let top_issues = sqlx::query(
        "SELECT id::text AS issue_id, title, status, regression_state, event_count, to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at FROM issues WHERE organization_id = $1::uuid AND project_id = $2::uuid AND status = 'open' ORDER BY event_count DESC, last_seen_at DESC, id DESC LIMIT 10",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?
    .iter()
    .map(|row| {
        let issue_id: String = row.get("issue_id");
        TopIssue {
            path: format!("/projects/{}/issues/{issue_id}", scope.project_id),
            issue_id,
            title: row.get("title"),
            status: row.get("status"),
            regression_state: row.get("regression_state"),
            event_count: row.get("event_count"),
            last_seen_at: row.get("last_seen_at"),
        }
    })
    .collect();

    let release_rows = sqlx::query(
        "SELECT COALESCE(r.id::text, 'unmapped') AS key, COALESCE(r.version, 'Unmapped') AS label, count(*) AS count, (sum(count(*)) OVER ())::bigint AS total_count FROM crash_events e LEFT JOIN releases r ON r.id = e.release_id AND r.organization_id = e.organization_id AND r.project_id = e.project_id WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.received_at >= $3::timestamptz AND e.received_at < $4::timestamptz GROUP BY r.id, r.version ORDER BY count DESC, label, key LIMIT 21",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&window_start)
    .bind(&window_end)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let (releases, releases_truncated, releases_other_count) = distribution_rows(&release_rows);

    let platform_rows = sqlx::query(
        "SELECT COALESCE(s.platform, 'unknown') || '/' || COALESCE(s.architecture, 'unknown') AS key, COALESCE(s.platform, 'Unknown') || ' / ' || COALESCE(s.architecture, 'unknown') AS label, count(*) AS count, (sum(count(*)) OVER ())::bigint AS total_count FROM crash_events e LEFT JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.received_at >= $3::timestamptz AND e.received_at < $4::timestamptz GROUP BY key, label ORDER BY count DESC, key LIMIT 21",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&window_start)
    .bind(&window_end)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let (platforms, platforms_truncated, platforms_other_count) = distribution_rows(&platform_rows);

    let crash_type_rows = sqlx::query(
        "SELECT COALESCE(s.crash_type, 'unknown') AS key, initcap(COALESCE(s.crash_type, 'unknown')) AS label, count(*) AS count, (sum(count(*)) OVER ())::bigint AS total_count FROM crash_events e LEFT JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.received_at >= $3::timestamptz AND e.received_at < $4::timestamptz GROUP BY key, label ORDER BY count DESC, key LIMIT 21",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&window_start)
    .bind(&window_end)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let (crash_types, crash_types_truncated, crash_types_other_count) =
        distribution_rows(&crash_type_rows);

    let symbolication = sqlx::query(
        "WITH states AS (SELECT CASE WHEN e.processing_state IN ('failed', 'quarantined') THEN 'failed' WHEN s.symbolication_state IS NOT NULL THEN s.symbolication_state WHEN e.processing_state = 'awaiting_symbols' THEN 'missing' ELSE 'processing' END AS state FROM crash_events e LEFT JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.received_at >= $3::timestamptz AND e.received_at < $4::timestamptz) SELECT count(*) FILTER (WHERE state = 'readable') AS readable, count(*) FILTER (WHERE state = 'partial') AS partial, count(*) FILTER (WHERE state = 'missing') AS missing, count(*) FILTER (WHERE state = 'failed') AS failed, count(*) FILTER (WHERE state = 'processing') AS processing FROM states",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&window_start)
    .bind(&window_end)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let readable: i64 = symbolication.get("readable");
    let partial: i64 = symbolication.get("partial");
    let missing: i64 = symbolication.get("missing");
    let denominator = readable + partial + missing;
    let symbolication = SymbolicationOverview {
        readable,
        partial,
        missing,
        failed: symbolication.get("failed"),
        processing: symbolication.get("processing"),
        denominator,
        success_percent: symbolication_success_percent(readable, partial, missing),
    };

    let missing_symbol_count = sqlx::query_scalar::<_, i64>(
        "WITH candidates AS (SELECT w.required_artifact, w.module_name, w.architecture, w.debug_id, NULLIF(w.code_id, '') AS code_id, w.release_id FROM crash_symbol_waiters w JOIN crash_events e ON e.id = w.event_id AND e.organization_id = w.organization_id AND e.project_id = w.project_id AND e.current_result_id = w.result_id WHERE w.organization_id = $1::uuid AND w.project_id = $2::uuid UNION SELECT CASE WHEN m.artifact_type = 'pdb' THEN 'pdb' ELSE 'pe' END AS required_artifact, m.module_name, m.architecture, m.debug_id, NULLIF(m.code_id, '') AS code_id, m.release_id FROM release_manifest_artifacts m JOIN crash_events e ON e.organization_id = m.organization_id AND e.project_id = m.project_id AND e.release_id = m.release_id AND e.current_result_id IS NOT NULL WHERE m.organization_id = $1::uuid AND m.project_id = $2::uuid AND m.state IN ('missing', 'mismatch')) SELECT count(*) FROM candidates",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;

    let ingest = sqlx::query(
        "SELECT CASE WHEN max(received_at) IS NULL THEN NULL ELSE to_char(max(received_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS last_received_at, count(*) FILTER (WHERE received_at >= $3::timestamptz AND received_at < $4::timestamptz) AS events_in_window, count(*) FILTER (WHERE processing_state IN ('received', 'stored')) AS stored_or_received FROM crash_events WHERE organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&window_start)
    .bind(&window_end)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let ingest = IngestHealth {
        last_received_at: ingest.get("last_received_at"),
        events_in_window: ingest.get("events_in_window"),
        stored_or_received: ingest.get("stored_or_received"),
    };

    let job_health = sqlx::query(
        "SELECT count(*) FILTER (WHERE state = 'pending') AS pending_jobs, count(*) FILTER (WHERE state = 'leased') AS leased_jobs, count(*) FILTER (WHERE state = 'failed') AS failed_jobs, count(*) FILTER (WHERE state = 'dead') AS dead_jobs, CASE WHEN min(available_at) FILTER (WHERE state = 'pending') IS NULL THEN NULL ELSE to_char(min(available_at) FILTER (WHERE state = 'pending') AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS oldest_pending_at FROM jobs WHERE organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let state_rows = sqlx::query(
        "SELECT processing_state AS key, initcap(replace(processing_state, '_', ' ')) AS label, count(*) AS count, (sum(count(*)) OVER ())::bigint AS total_count FROM crash_events WHERE organization_id = $1::uuid AND project_id = $2::uuid GROUP BY processing_state ORDER BY count DESC, processing_state LIMIT 21",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let (states, _, _) = distribution_rows(&state_rows);
    let processing = ProcessingHealth {
        pending_jobs: job_health.get("pending_jobs"),
        leased_jobs: job_health.get("leased_jobs"),
        failed_jobs: job_health.get("failed_jobs"),
        dead_jobs: job_health.get("dead_jobs"),
        oldest_pending_at: job_health.get("oldest_pending_at"),
        states,
    };

    let usage = sqlx::query(
        "SELECT count(e.id) AS accepted_events, COALESCE(sum(o.byte_size), 0)::bigint AS retained_raw_bytes, (SELECT COALESCE(sum(a.byte_size), 0)::bigint FROM (SELECT DISTINCT ao.id, ao.byte_size FROM release_manifest_artifacts m JOIN artifact_debug_images d ON d.id = m.debug_image_id AND d.organization_id = m.organization_id JOIN artifact_objects ao ON ao.id = d.object_id AND ao.organization_id = d.organization_id WHERE m.organization_id = $1::uuid AND m.project_id = $2::uuid AND m.state = 'available' AND ao.lifecycle_state = 'stored') a) AS project_artifact_bytes, (SELECT count(*) FROM projects p WHERE p.organization_id = $1::uuid) AS organization_projects FROM crash_events e JOIN crash_event_objects o ON o.id = e.raw_object_id AND o.organization_id = e.organization_id AND o.project_id = e.project_id AND o.lifecycle_state = 'stored' WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.received_at >= $3::timestamptz AND e.received_at < $3::timestamptz + interval '1 month'",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&cycle_start)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let observed_usage = ObservedUsage {
        authoritative: false,
        cycle_start,
        accepted_events: usage.get("accepted_events"),
        retained_raw_bytes: usage.get("retained_raw_bytes"),
        project_artifact_bytes: usage.get("project_artifact_bytes"),
        organization_projects: usage.get("organization_projects"),
    };

    Ok(ProjectOverview {
        generated_at,
        window: OverviewWindow {
            start: window_start,
            end: window_end,
            days: 30,
        },
        totals,
        events_over_time,
        top_issues,
        releases,
        releases_truncated,
        releases_other_count,
        platforms,
        platforms_truncated,
        platforms_other_count,
        crash_types,
        crash_types_truncated,
        crash_types_other_count,
        symbolication,
        missing_symbol_count,
        ingest,
        processing,
        observed_usage,
    })
}

fn distribution_rows(rows: &[sqlx::postgres::PgRow]) -> (Vec<Distribution>, bool, i64) {
    let truncated = rows.len() > MAX_DISTRIBUTIONS;
    let values = rows
        .iter()
        .take(MAX_DISTRIBUTIONS)
        .map(|row| {
            let (key, key_truncated) = truncate_text(&row.get::<String, _>("key"), 256);
            let (label, label_truncated) = truncate_text(&row.get::<String, _>("label"), 256);
            Distribution {
                key,
                label,
                count: row.get("count"),
                truncated: key_truncated || label_truncated,
            }
        })
        .collect::<Vec<_>>();
    let total = rows
        .first()
        .map_or(0, |row| row.get::<i64, _>("total_count"));
    let displayed = values.iter().map(|value| value.count).sum::<i64>();
    (values, truncated, total.saturating_sub(displayed).max(0))
}

async fn load_event_summaries(
    connection: &mut PgConnection,
    scope: &ProjectScope,
    issue_id: &str,
    cursor: Option<&CursorPayload>,
    limit: u16,
) -> Result<Vec<EventSummary>, DashboardError> {
    let rows = sqlx::query(
        "SELECT e.id::text AS event_id, to_char(e.received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS received_at, e.environment, e.processing_state, e.state_reason, e.release_id::text AS release_id, rel.version AS release_version, s.crash_type, s.platform, s.architecture, s.engine_version, s.user_comment, e.current_result_id::text AS current_result_id, CASE WHEN e.processing_state IN ('failed', 'quarantined') THEN 'failed' WHEN s.symbolication_state IS NOT NULL THEN s.symbolication_state WHEN e.processing_state = 'awaiting_symbols' THEN 'missing' ELSE 'processing' END AS symbolication_state FROM crash_events e LEFT JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id LEFT JOIN releases rel ON rel.id = e.release_id AND rel.organization_id = e.organization_id AND rel.project_id = e.project_id WHERE e.organization_id::text = $1 AND e.project_id::text = $2 AND e.issue_id::text = $3 AND ($4::timestamptz IS NULL OR (e.received_at, e.id) < ($4::timestamptz, $5::uuid)) ORDER BY e.received_at DESC, e.id DESC LIMIT $6",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .bind(cursor.map(|value| value.sort_at.as_str()))
    .bind(cursor.map(|value| value.id.as_str()))
    .bind(i64::from(limit) + 1)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    Ok(rows
        .iter()
        .map(|row| event_summary(row, &scope.project_id, issue_id))
        .collect())
}

fn event_summary(row: &sqlx::postgres::PgRow, project_id: &str, issue_id: &str) -> EventSummary {
    let event_id: String = row.get("event_id");
    let comment: Option<String> = row.get("user_comment");
    let (comment_excerpt, comment_truncated) = comment
        .as_deref()
        .map(|value| truncate_text(value, 240))
        .map_or((None, false), |(value, truncated)| (Some(value), truncated));
    let (environment, environment_truncated) =
        truncate_text(&row.get::<String, _>("environment"), 64);
    let (state_reason, state_reason_truncated) = optional_bounded(
        row.get::<Option<String>, _>("state_reason").as_deref(),
        MAX_TEXT_BYTES,
    );
    let (release_version, release_version_truncated) = optional_bounded(
        row.get::<Option<String>, _>("release_version").as_deref(),
        MAX_TEXT_BYTES,
    );
    let (crash_type, crash_type_truncated) = optional_bounded(
        row.get::<Option<String>, _>("crash_type").as_deref(),
        MAX_TEXT_BYTES,
    );
    let (platform, platform_truncated) = optional_bounded(
        row.get::<Option<String>, _>("platform").as_deref(),
        MAX_TEXT_BYTES,
    );
    let (architecture, architecture_truncated) = optional_bounded(
        row.get::<Option<String>, _>("architecture").as_deref(),
        MAX_TEXT_BYTES,
    );
    let (engine_version, engine_version_truncated) = optional_bounded(
        row.get::<Option<String>, _>("engine_version").as_deref(),
        MAX_TEXT_BYTES,
    );
    EventSummary {
        path: format!("/projects/{project_id}/issues/{issue_id}?event={event_id}"),
        event_id,
        received_at: row.get("received_at"),
        environment,
        processing_state: row.get("processing_state"),
        state_reason,
        release_id: row.get("release_id"),
        release_version,
        crash_type,
        platform,
        architecture,
        engine_version,
        symbolication_state: row.get("symbolication_state"),
        comment_excerpt,
        comment_truncated,
        metadata_truncated: environment_truncated
            || state_reason_truncated
            || release_version_truncated
            || crash_type_truncated
            || platform_truncated
            || architecture_truncated
            || engine_version_truncated,
        current_result_id: row.get("current_result_id"),
    }
}

#[allow(clippy::too_many_lines)]
async fn load_event_facets(
    connection: &mut PgConnection,
    scope: &ProjectScope,
    issue_id: &str,
) -> Result<EventFacets, DashboardError> {
    let releases = sqlx::query(
        "SELECT COALESCE(rel.id::text, 'unmapped') AS key, COALESCE(rel.version, 'Unmapped') AS label, count(*) AS count, (sum(count(*)) OVER ())::bigint AS total_count FROM crash_events e LEFT JOIN releases rel ON rel.id = e.release_id AND rel.organization_id = e.organization_id AND rel.project_id = e.project_id WHERE e.organization_id::text = $1 AND e.project_id::text = $2 AND e.issue_id::text = $3 GROUP BY rel.id, rel.version ORDER BY count DESC, label, key LIMIT 21",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let (releases, releases_truncated, releases_other_count) = distribution_rows(&releases);
    let platforms = sqlx::query(
        "SELECT COALESCE(s.platform, 'unknown') AS key, initcap(COALESCE(s.platform, 'unknown')) AS label, count(*) AS count, (sum(count(*)) OVER ())::bigint AS total_count FROM crash_events e LEFT JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id WHERE e.organization_id::text = $1 AND e.project_id::text = $2 AND e.issue_id::text = $3 GROUP BY key, label ORDER BY count DESC, key LIMIT 21",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let (platforms, platforms_truncated, platforms_other_count) = distribution_rows(&platforms);
    let architectures = sqlx::query(
        "SELECT COALESCE(s.architecture, 'unknown') AS key, COALESCE(s.architecture, 'Unknown') AS label, count(*) AS count, (sum(count(*)) OVER ())::bigint AS total_count FROM crash_events e LEFT JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id WHERE e.organization_id::text = $1 AND e.project_id::text = $2 AND e.issue_id::text = $3 GROUP BY key, label ORDER BY count DESC, key LIMIT 21",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let (architectures, architectures_truncated, architectures_other_count) =
        distribution_rows(&architectures);
    let environments = sqlx::query(
        "SELECT environment AS key, initcap(environment) AS label, count(*) AS count, (sum(count(*)) OVER ())::bigint AS total_count FROM crash_events WHERE organization_id::text = $1 AND project_id::text = $2 AND issue_id::text = $3 GROUP BY environment ORDER BY count DESC, environment LIMIT 21",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let (environments, environments_truncated, environments_other_count) =
        distribution_rows(&environments);
    let crash_types = sqlx::query(
        "SELECT COALESCE(s.crash_type, 'unknown') AS key, initcap(COALESCE(s.crash_type, 'unknown')) AS label, count(*) AS count, (sum(count(*)) OVER ())::bigint AS total_count FROM crash_events e LEFT JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id WHERE e.organization_id::text = $1 AND e.project_id::text = $2 AND e.issue_id::text = $3 GROUP BY key, label ORDER BY count DESC, key LIMIT 21",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let (crash_types, crash_types_truncated, crash_types_other_count) =
        distribution_rows(&crash_types);
    let processing_states = sqlx::query(
        "SELECT processing_state AS key, initcap(replace(processing_state, '_', ' ')) AS label, count(*) AS count, (sum(count(*)) OVER ())::bigint AS total_count FROM crash_events WHERE organization_id::text = $1 AND project_id::text = $2 AND issue_id::text = $3 GROUP BY processing_state ORDER BY count DESC, processing_state LIMIT 21",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let (processing_states, processing_states_truncated, processing_states_other_count) =
        distribution_rows(&processing_states);
    let context_rows = sqlx::query(
        "WITH counts AS (SELECT f.key, f.value, bool_or(f.value_truncated) AS value_truncated, count(*) AS count FROM crash_events e JOIN crash_event_context_facets f ON f.organization_id = e.organization_id AND f.project_id = e.project_id AND f.event_id = e.id AND f.result_id = e.current_result_id WHERE e.organization_id::text = $1 AND e.project_id::text = $2 AND e.issue_id::text = $3 GROUP BY f.key, f.value), ranked AS (SELECT key, value, value_truncated, count, row_number() OVER (PARTITION BY key ORDER BY count DESC, value) AS rank, sum(count) OVER (PARTITION BY key)::bigint AS total_count FROM counts) SELECT key, value, value_truncated, count, total_count FROM ranked WHERE rank <= 21 ORDER BY key, rank",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let custom_context = context_facet_groups(&context_rows);
    Ok(EventFacets {
        releases,
        releases_truncated,
        releases_other_count,
        platforms,
        platforms_truncated,
        platforms_other_count,
        architectures,
        architectures_truncated,
        architectures_other_count,
        environments,
        environments_truncated,
        environments_other_count,
        crash_types,
        crash_types_truncated,
        crash_types_other_count,
        processing_states,
        processing_states_truncated,
        processing_states_other_count,
        custom_context,
    })
}

fn context_facet_groups(rows: &[sqlx::postgres::PgRow]) -> Vec<ContextFacetGroup> {
    let mut grouped = BTreeMap::<String, Vec<&sqlx::postgres::PgRow>>::new();
    for row in rows {
        grouped.entry(row.get("key")).or_default().push(row);
    }
    grouped
        .into_iter()
        .map(|(key, rows)| {
            let values_truncated = rows.len() > MAX_DISTRIBUTIONS;
            let total_count = rows
                .first()
                .map_or(0, |row| row.get::<i64, _>("total_count"));
            let values = rows
                .iter()
                .take(MAX_DISTRIBUTIONS)
                .map(|row| {
                    let value: String = row.get("value");
                    Distribution {
                        key: value.clone(),
                        label: value,
                        count: row.get("count"),
                        truncated: row.get("value_truncated"),
                    }
                })
                .collect::<Vec<_>>();
            let visible_count = values.iter().map(|value| value.count).sum::<i64>();
            ContextFacetGroup {
                key,
                values,
                values_truncated,
                values_other_count: total_count.saturating_sub(visible_count),
            }
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
async fn load_event_detail(
    connection: &mut PgConnection,
    scope: &ProjectScope,
    issue_id: &str,
    event_id: &str,
    raw_artifact_download_enabled: bool,
) -> Result<EventDetail, DashboardError> {
    let row = sqlx::query(
        "SELECT e.id::text AS event_id, to_char(e.received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS received_at, e.environment, e.processing_state, e.state_reason, e.crash_guid, e.release_mapping_state, e.release_id::text AS release_id, rel.version AS release_version, rel.platform AS release_platform, rel.architecture AS release_architecture, rel.configuration AS release_configuration, e.current_result_id::text AS current_result_id, r.result, r.result #>> '{crash_context,crash_type}' AS crash_type, r.result #>> '{crash_context,platform,normalized}' AS platform, r.result #>> '{crash_context,architecture}' AS architecture, r.result #>> '{crash_context,engine_version}' AS engine_version, r.result #>> '{crash_context,user_comment}' AS user_comment, CASE WHEN e.processing_state IN ('failed', 'quarantined') THEN 'failed' WHEN r.result IS NOT NULL AND jsonb_path_exists(r.result, '$.current.symbolication.threads[*].frames[*] ? (@.symbol_status == \"resolved\")') AND jsonb_path_exists(r.result, '$.current.symbolication.modules[*] ? (@.status == \"missing_pe\" || @.status == \"missing_pdb\" || @.status == \"mismatched\" || @.status == \"missing_identity\")') THEN 'partial' WHEN r.result IS NOT NULL AND jsonb_path_exists(r.result, '$.current.symbolication.threads[*].frames[*] ? (@.symbol_status == \"resolved\")') THEN 'readable' WHEN e.processing_state = 'awaiting_symbols' OR (r.result IS NOT NULL AND jsonb_path_exists(r.result, '$.current.symbolication.modules[*] ? (@.status == \"missing_pe\" || @.status == \"missing_pdb\" || @.status == \"mismatched\" || @.status == \"missing_identity\")')) THEN 'missing' ELSE 'processing' END AS symbolication_state, EXISTS(SELECT 1 FROM crash_event_objects o WHERE o.id = e.raw_object_id AND o.organization_id = e.organization_id AND o.project_id = e.project_id AND o.lifecycle_state = 'stored') AS raw_available FROM crash_events e LEFT JOIN crash_processing_results r ON r.id = e.current_result_id AND r.organization_id = e.organization_id AND r.project_id = e.project_id AND r.event_id = e.id LEFT JOIN releases rel ON rel.id = e.release_id AND rel.organization_id = e.organization_id AND rel.project_id = e.project_id WHERE e.organization_id::text = $1 AND e.project_id::text = $2 AND e.issue_id::text = $3 AND e.id::text = $4",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .bind(event_id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?
    .ok_or(DashboardError::NotFound)?;
    let event = event_summary(&row, &scope.project_id, issue_id);
    let candidate_rows = sqlx::query(
        "SELECT release_id::text AS release_id FROM crash_event_release_candidates WHERE organization_id::text = $1 AND project_id::text = $2 AND event_id::text = $3 ORDER BY release_id LIMIT 101",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(event_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let candidate_release_ids_truncated = candidate_rows.len() > 100;
    let candidate_release_ids = candidate_rows
        .iter()
        .take(100)
        .map(|candidate| candidate.get("release_id"))
        .collect();
    let release_mapping = ReleaseMapping {
        state: row.get("release_mapping_state"),
        release_id: row.get("release_id"),
        candidate_release_ids,
        candidate_release_ids_truncated,
    };
    let result: Option<Value> = row.get("result");
    let result = result.ok_or(DashboardError::ResultUnavailable)?;
    let crash_guid: Option<String> = row.get("crash_guid");
    faultlane_processing::validate_processing_result(&result, crash_guid.as_deref())
        .map_err(|_| DashboardError::ResultUnavailable)?;
    let context = result
        .get("crash_context")
        .and_then(Value::as_object)
        .ok_or(DashboardError::ResultUnavailable)?;
    let (error_message, error_message_truncated) = optional_bounded(
        context.get("error_message").and_then(Value::as_str),
        MAX_TEXT_BYTES,
    );
    let (user_comment, user_comment_truncated) = optional_bounded(
        context.get("user_comment").and_then(Value::as_str),
        MAX_COMMENT_BYTES,
    );
    let (crash_guid, crash_guid_truncated) =
        optional_bounded(crash_guid.as_deref(), MAX_TEXT_BYTES);
    let (build_version, build_version_truncated) = optional_bounded(
        context.get("build_version").and_then(Value::as_str),
        MAX_TEXT_BYTES,
    );
    let (build_configuration, build_configuration_truncated) = optional_bounded(
        context.get("build_configuration").and_then(Value::as_str),
        MAX_TEXT_BYTES,
    );
    let (game_data, game_data_truncated) = property_views(context.get("game_data"))?;
    let (system_context, system_context_truncated) =
        property_views(context.get("system_metadata"))?;
    let classification = classification_view(result.get("classification"));
    let log = project_log(&result, &scope.project_id, issue_id, event_id)?;
    let (threads, threads_truncated) =
        thread_views(result.pointer("/current/symbolication/threads"))?;
    let (missing_symbols, missing_symbols_truncated) =
        load_missing_symbols(connection, scope, event_id).await?;
    let remediation_command = if missing_symbols.is_empty() {
        None
    } else {
        let release_version: Option<String> = row.get("release_version");
        let architecture: Option<String> = row.get("release_architecture");
        let configuration: Option<String> = row.get("release_configuration");
        release_version.map(|release| {
            remediation_command(
                &scope.project_slug,
                &release,
                architecture.as_deref(),
                configuration.as_deref(),
            )
        })
    };
    let processing_history = load_processing_history(
        connection,
        scope,
        event_id,
        row.get::<Option<String>, _>("current_result_id").as_deref(),
    )
    .await?;
    Ok(EventDetail {
        event,
        crash_guid,
        crash_guid_truncated,
        release_mapping,
        classification,
        error_message,
        error_message_truncated,
        build_version,
        build_version_truncated,
        build_configuration,
        build_configuration_truncated,
        user_comment,
        user_comment_truncated,
        game_data,
        game_data_truncated,
        system_context,
        system_context_truncated,
        log,
        threads,
        threads_truncated,
        missing_symbols,
        missing_symbols_truncated,
        remediation_command,
        processing_history,
        raw_available: raw_artifact_download_enabled && row.get("raw_available"),
    })
}

fn classification_view(value: Option<&Value>) -> Option<ClassificationView> {
    let object = value?.as_object()?;
    let crash_type = object.get("crash_type")?.as_str()?;
    let confidence = object.get("confidence")?.as_str()?;
    let (crash_type, crash_type_truncated) = truncate_text(crash_type, 128);
    let (confidence, confidence_truncated) = truncate_text(confidence, 128);
    let (evidence, evidence_truncated) = bounded_string_values(object.get("evidence")?, 32, 128)?;
    let signal_values = object.get("signals")?.as_array()?;
    let mut signals_truncated = signal_values.len() > 16;
    let signals = signal_values
        .iter()
        .take(16)
        .map(|signal| {
            let signal = signal.as_object()?;
            let (kind, kind_truncated) = truncate_text(signal.get("kind")?.as_str()?, 128);
            let (confidence, confidence_truncated) =
                truncate_text(signal.get("confidence")?.as_str()?, 128);
            let (evidence, evidence_truncated) =
                bounded_string_values(signal.get("evidence")?, 32, 128)?;
            let truncated = kind_truncated || confidence_truncated || evidence_truncated;
            signals_truncated |= truncated;
            Some(SignalView {
                kind,
                confidence,
                evidence,
                truncated,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(ClassificationView {
        crash_type,
        confidence,
        evidence,
        signals,
        truncated: crash_type_truncated
            || confidence_truncated
            || evidence_truncated
            || signals_truncated,
    })
}

fn bounded_string_values(
    value: &Value,
    maximum_count: usize,
    maximum_bytes: usize,
) -> Option<(Vec<String>, bool)> {
    let values = value.as_array()?;
    let mut truncated = values.len() > maximum_count;
    let bounded = values
        .iter()
        .take(maximum_count)
        .map(|value| {
            let (value, value_truncated) = truncate_text(value.as_str()?, maximum_bytes);
            truncated |= value_truncated;
            Some(value)
        })
        .collect::<Option<Vec<_>>>()?;
    Some((bounded, truncated))
}

fn property_views(value: Option<&Value>) -> Result<(Vec<PropertyView>, bool), DashboardError> {
    let values = value
        .and_then(Value::as_array)
        .ok_or(DashboardError::ResultUnavailable)?;
    let truncated = values.len() > MAX_PROPERTIES;
    let mut properties = Vec::with_capacity(values.len().min(MAX_PROPERTIES));
    for property in values.iter().take(MAX_PROPERTIES) {
        let property = property
            .as_object()
            .ok_or(DashboardError::ResultUnavailable)?;
        let name = property
            .get("name")
            .and_then(Value::as_str)
            .ok_or(DashboardError::ResultUnavailable)?;
        let value = property
            .get("value")
            .and_then(Value::as_str)
            .ok_or(DashboardError::ResultUnavailable)?;
        let (name, name_truncated) = truncate_text(name, 256);
        let (value, value_truncated) = truncate_text(value, MAX_TEXT_BYTES);
        properties.push(PropertyView {
            name,
            name_truncated,
            value,
            value_truncated,
        });
    }
    Ok((properties, truncated))
}

fn project_log(
    result: &Value,
    project_id: &str,
    issue_id: &str,
    event_id: &str,
) -> Result<Option<LogView>, DashboardError> {
    let Some(log) = result.get("log") else {
        return Ok(None);
    };
    if log.is_null() {
        return Ok(None);
    }
    let log = log.as_object().ok_or(DashboardError::ResultUnavailable)?;
    let tail = log
        .get("tail")
        .and_then(Value::as_object)
        .ok_or(DashboardError::ResultUnavailable)?;
    let name = log
        .get("name")
        .and_then(Value::as_str)
        .ok_or(DashboardError::ResultUnavailable)?;
    let text = tail
        .get("text")
        .and_then(Value::as_str)
        .ok_or(DashboardError::ResultUnavailable)?;
    let source_truncated = tail
        .get("truncated")
        .and_then(Value::as_bool)
        .ok_or(DashboardError::ResultUnavailable)?;
    let invalid_utf8 = tail
        .get("invalid_utf8")
        .and_then(Value::as_bool)
        .ok_or(DashboardError::ResultUnavailable)?;
    let (name, name_truncated) = truncate_text(name, 256);
    let (text, response_truncated) = truncate_text(text, MAX_LOG_BYTES);
    Ok(Some(LogView {
        name,
        text,
        truncated: name_truncated || source_truncated || response_truncated,
        invalid_utf8,
        download_path: format!(
            "/api/v1/projects/{project_id}/issues/{issue_id}/events/{event_id}/log"
        ),
    }))
}

fn thread_views(value: Option<&Value>) -> Result<(Vec<ThreadView>, bool), DashboardError> {
    let threads = value
        .and_then(Value::as_array)
        .ok_or(DashboardError::ResultUnavailable)?;
    let threads_truncated = threads.len() > MAX_THREADS;
    let mut views = Vec::with_capacity(threads.len().min(MAX_THREADS));
    for thread in threads.iter().take(MAX_THREADS) {
        let thread = thread
            .as_object()
            .ok_or(DashboardError::ResultUnavailable)?;
        let frames = thread
            .get("frames")
            .and_then(Value::as_array)
            .ok_or(DashboardError::ResultUnavailable)?;
        let mut frame_views = Vec::with_capacity(frames.len().min(MAX_FRAMES));
        for frame in frames.iter().take(MAX_FRAMES) {
            frame_views.push(frame_view(frame)?);
        }
        let (name, name_truncated) =
            optional_bounded(thread.get("name").and_then(Value::as_str), MAX_TEXT_BYTES);
        let (unwind_status, unwind_status_truncated) = truncate_text(
            thread
                .get("unwind_status")
                .and_then(Value::as_str)
                .ok_or(DashboardError::ResultUnavailable)?,
            128,
        );
        views.push(ThreadView {
            thread_id: thread
                .get("thread_id")
                .and_then(Value::as_u64)
                .ok_or(DashboardError::ResultUnavailable)?,
            faulting: thread
                .get("faulting")
                .and_then(Value::as_bool)
                .ok_or(DashboardError::ResultUnavailable)?,
            name,
            name_truncated,
            unwind_status,
            unwind_status_truncated,
            frames_truncated: thread
                .get("frames_truncated")
                .and_then(Value::as_bool)
                .ok_or(DashboardError::ResultUnavailable)?
                || frames.len() > MAX_FRAMES,
            frames: frame_views,
        });
    }
    Ok((views, threads_truncated))
}

fn frame_view(value: &Value) -> Result<FrameView, DashboardError> {
    let frame = value.as_object().ok_or(DashboardError::ResultUnavailable)?;
    let inlines = frame
        .get("inlines")
        .and_then(Value::as_array)
        .ok_or(DashboardError::ResultUnavailable)?;
    let mut inline_views = Vec::with_capacity(inlines.len().min(MAX_INLINES));
    for inline in inlines.iter().take(MAX_INLINES) {
        let inline = inline
            .as_object()
            .ok_or(DashboardError::ResultUnavailable)?;
        let (function, function_truncated) = truncate_text(
            inline
                .get("function")
                .and_then(Value::as_str)
                .ok_or(DashboardError::ResultUnavailable)?,
            MAX_TEXT_BYTES,
        );
        let (source_file, source_file_truncated) = optional_bounded(
            inline.get("source_file").and_then(Value::as_str),
            MAX_TEXT_BYTES,
        );
        inline_views.push(InlineView {
            function,
            source_file,
            source_line: inline.get("source_line").and_then(Value::as_u64),
            truncated: function_truncated || source_file_truncated,
        });
    }
    let (instruction, instruction_truncated) = truncate_text(
        frame
            .get("instruction")
            .and_then(Value::as_str)
            .ok_or(DashboardError::ResultUnavailable)?,
        128,
    );
    let (module, module_truncated) =
        optional_bounded(frame.get("module").and_then(Value::as_str), MAX_TEXT_BYTES);
    let (module_relative, module_relative_truncated) = optional_bounded(
        frame.get("module_relative").and_then(Value::as_str),
        MAX_TEXT_BYTES,
    );
    let (trust, trust_truncated) = truncate_text(
        frame
            .get("trust")
            .and_then(Value::as_str)
            .ok_or(DashboardError::ResultUnavailable)?,
        128,
    );
    let (symbol_status, symbol_status_truncated) = truncate_text(
        frame
            .get("symbol_status")
            .and_then(Value::as_str)
            .ok_or(DashboardError::ResultUnavailable)?,
        128,
    );
    let (function, function_truncated) = optional_bounded(
        frame.get("function").and_then(Value::as_str),
        MAX_TEXT_BYTES,
    );
    let (source_file, source_file_truncated) = optional_bounded(
        frame.get("source_file").and_then(Value::as_str),
        MAX_TEXT_BYTES,
    );
    let inlines_truncated = inlines.len() > MAX_INLINES;
    Ok(FrameView {
        instruction,
        module,
        module_relative,
        trust,
        symbol_status,
        function,
        source_file,
        source_line: frame.get("source_line").and_then(Value::as_u64),
        inlines: inline_views,
        inlines_truncated,
        truncated: instruction_truncated
            || module_truncated
            || module_relative_truncated
            || trust_truncated
            || symbol_status_truncated
            || function_truncated
            || source_file_truncated
            || inlines_truncated,
    })
}

async fn load_missing_symbols(
    connection: &mut PgConnection,
    scope: &ProjectScope,
    event_id: &str,
) -> Result<(Vec<MissingSymbol>, bool), DashboardError> {
    let rows = sqlx::query(
        "WITH event_scope AS (SELECT e.release_id, e.current_result_id FROM crash_events e WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.id = $3::uuid), candidates AS (SELECT w.required_artifact, w.module_name, w.architecture, w.debug_id, NULLIF(w.code_id, '') AS code_id, w.release_id FROM crash_symbol_waiters w JOIN event_scope e ON e.current_result_id = w.result_id WHERE w.organization_id = $1::uuid AND w.project_id = $2::uuid AND w.event_id = $3::uuid UNION SELECT CASE WHEN m.artifact_type = 'pdb' THEN 'pdb' ELSE 'pe' END AS required_artifact, m.module_name, m.architecture, m.debug_id, NULLIF(m.code_id, '') AS code_id, m.release_id FROM release_manifest_artifacts m JOIN event_scope e ON e.release_id = m.release_id WHERE m.organization_id = $1::uuid AND m.project_id = $2::uuid AND m.state IN ('missing', 'mismatch')) SELECT c.required_artifact, c.module_name, c.architecture, c.debug_id, c.code_id, c.release_id::text AS release_id, r.version AS release_version FROM candidates c JOIN releases r ON r.id = c.release_id AND r.organization_id = $1::uuid AND r.project_id = $2::uuid ORDER BY c.module_name, c.required_artifact, c.debug_id, c.code_id LIMIT 101",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(event_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let truncated = rows.len() > MAX_MISSING_SYMBOLS;
    let values = rows
        .iter()
        .take(MAX_MISSING_SYMBOLS)
        .map(|row| {
            let (module, module_truncated) =
                truncate_text(&row.get::<String, _>("module_name"), MAX_TEXT_BYTES);
            let (architecture, architecture_truncated) =
                truncate_text(&row.get::<String, _>("architecture"), 128);
            let (debug_id, debug_id_truncated) =
                truncate_text(&row.get::<String, _>("debug_id"), 256);
            let (code_id, code_id_truncated) =
                optional_bounded(row.get::<Option<String>, _>("code_id").as_deref(), 256);
            let (release_version, release_version_truncated) =
                truncate_text(&row.get::<String, _>("release_version"), MAX_TEXT_BYTES);
            MissingSymbol {
                required_artifact: row.get("required_artifact"),
                module,
                architecture,
                debug_id,
                code_id,
                release_id: row.get("release_id"),
                release_version,
                truncated: module_truncated
                    || architecture_truncated
                    || debug_id_truncated
                    || code_id_truncated
                    || release_version_truncated,
            }
        })
        .collect();
    Ok((values, truncated))
}

async fn load_processing_history(
    connection: &mut PgConnection,
    scope: &ProjectScope,
    event_id: &str,
    current_result_id: Option<&str>,
) -> Result<ProcessingHistory, DashboardError> {
    let result_rows = sqlx::query(
        "SELECT id::text AS result_id, schema_version, processing_version, data_rules_version, checksum, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at FROM crash_processing_results WHERE organization_id::text = $1 AND project_id::text = $2 AND event_id::text = $3 ORDER BY created_at DESC, id DESC LIMIT 51",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(event_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let results_truncated = result_rows.len() > MAX_HISTORY;
    let results = result_rows
        .iter()
        .take(MAX_HISTORY)
        .map(|row| {
            let result_id: String = row.get("result_id");
            ResultHistory {
                current: current_result_id == Some(result_id.as_str()),
                result_id,
                schema_version: row.get("schema_version"),
                processing_version: row.get("processing_version"),
                data_rules_version: row.get("data_rules_version"),
                checksum: lower_hex(&row.get::<Vec<u8>, _>("checksum")),
                created_at: row.get("created_at"),
            }
        })
        .collect();
    let request_rows = sqlx::query(
        "SELECT q.id::text AS request_id, q.source, x.state, x.failure_code, to_char(x.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, CASE WHEN x.completed_at IS NULL THEN NULL ELSE to_char(x.completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS completed_at FROM crash_reprocessing_request_events x JOIN crash_reprocessing_requests q ON q.id = x.request_id AND q.organization_id = x.organization_id AND q.project_id = x.project_id WHERE x.organization_id::text = $1 AND x.project_id::text = $2 AND x.event_id::text = $3 ORDER BY x.created_at DESC, q.id DESC LIMIT 51",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(event_id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| DashboardError::Internal)?;
    let requests_truncated = request_rows.len() > MAX_HISTORY;
    let requests = request_rows
        .iter()
        .take(MAX_HISTORY)
        .map(|row| RequestHistory {
            request_id: row.get("request_id"),
            source: row.get("source"),
            state: row.get("state"),
            failure_code: row.get("failure_code"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
        })
        .collect();
    Ok(ProcessingHistory {
        results,
        results_truncated,
        requests,
        requests_truncated,
    })
}

fn remediation_command(
    project_slug: &str,
    release: &str,
    architecture: Option<&str>,
    configuration: Option<&str>,
) -> String {
    let mut command = format!(
        "faultlane symbols upload {} --project {} --release {}",
        powershell_literal("<build-directory>"),
        powershell_literal(project_slug),
        powershell_literal(release)
    );
    if let Some(architecture) = architecture {
        command.push_str(" --architecture ");
        command.push_str(&powershell_literal(architecture));
    }
    if let Some(configuration) = configuration {
        command.push_str(" --configuration ");
        command.push_str(&powershell_literal(configuration));
    }
    command
}

fn powershell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn optional_bounded(value: Option<&str>, maximum: usize) -> (Option<String>, bool) {
    value
        .map(|value| truncate_text(value, maximum))
        .map_or((None, false), |(value, truncated)| (Some(value), truncated))
}

fn truncate_text(value: &str, maximum: usize) -> (String, bool) {
    if value.len() <= maximum {
        return (value.to_owned(), false);
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (value[..end].to_owned(), true)
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn symbolication_success_percent(readable: i64, partial: i64, missing: i64) -> Option<f64> {
    let successful = i128::from(readable) + i128::from(partial);
    let denominator = successful + i128::from(missing);
    if denominator <= 0 {
        return None;
    }
    let basis_points = (successful * 10_000 + denominator / 2) / denominator;
    u32::try_from(basis_points)
        .ok()
        .map(|value| f64::from(value) / 100.0)
}

fn encode_cursor(cursor: &CursorPayload) -> Result<String, DashboardError> {
    let bytes = serde_json::to_vec(&cursor).map_err(|_| DashboardError::Internal)?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(DashboardError::Internal);
    }
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_cursor(
    encoded: &str,
    kind: &str,
    project_id: &str,
    filter_hash: &str,
) -> Result<CursorPayload, DashboardError> {
    if encoded.is_empty() || encoded.len() > MAX_CURSOR_BYTES * 2 {
        return Err(DashboardError::InvalidRequest);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| DashboardError::InvalidRequest)?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(DashboardError::InvalidRequest);
    }
    let cursor: CursorPayload =
        serde_json::from_slice(&bytes).map_err(|_| DashboardError::InvalidRequest)?;
    if cursor.version != 1
        || cursor.kind != kind
        || cursor.project_id != project_id
        || cursor.filter_hash != filter_hash
        || !valid_uuid(&cursor.id)
        || OffsetDateTime::parse(&cursor.sort_at, &Rfc3339).is_err()
    {
        return Err(DashboardError::InvalidRequest);
    }
    Ok(cursor)
}

fn no_store_json(status: StatusCode, value: &impl Serialize) -> Response {
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

fn attachment_response(
    content_type: &'static str,
    filename: &str,
    body: Body,
    integrity: Option<(u64, &[u8])>,
) -> Result<Response, DashboardError> {
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .map_err(|_| DashboardError::Internal)?;
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Some((size, checksum)) = integrity {
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&size.to_string()).map_err(|_| DashboardError::Internal)?,
        );
        let digest = format!(
            "sha-256={}",
            base64::engine::general_purpose::STANDARD.encode(checksum)
        );
        headers.insert(
            "digest",
            HeaderValue::from_str(&digest).map_err(|_| DashboardError::Internal)?,
        );
    }
    Ok(response)
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
#[path = "dashboard_tests.rs"]
mod tests;
