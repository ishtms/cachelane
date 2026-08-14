use axum::{
    Json,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::project_setup::ServerState;

const DEFAULT_PAGE_SIZE: u16 = 50;
const MAX_PAGE_SIZE: u16 = 100;
const MAX_DETAIL_ROWS: usize = 100;
const MAX_CURSOR_BYTES: usize = 1024;
const MAX_SEARCH_BYTES: usize = 120;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssueListQuery {
    cursor: Option<String>,
    limit: Option<u16>,
    status: Option<String>,
    regression_state: Option<String>,
    release_id: Option<String>,
    crash_type: Option<String>,
    platform: Option<String>,
    architecture: Option<String>,
    engine_version: Option<String>,
    symbolication_state: Option<String>,
    first_seen_from: Option<String>,
    first_seen_to: Option<String>,
    last_seen_from: Option<String>,
    last_seen_to: Option<String>,
    query: Option<String>,
}

#[derive(Serialize)]
struct IssueFilterIdentity<'query> {
    status: Option<&'query str>,
    regression_state: Option<&'query str>,
    release_id: Option<&'query str>,
    crash_type: Option<&'query str>,
    platform: Option<&'query str>,
    architecture: Option<&'query str>,
    engine_version: Option<&'query str>,
    symbolication_state: Option<&'query str>,
    first_seen_from: Option<&'query str>,
    first_seen_to: Option<&'query str>,
    last_seen_from: Option<&'query str>,
    last_seen_to: Option<&'query str>,
    query: Option<&'query str>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueCursor {
    version: u8,
    project_id: String,
    filter_hash: String,
    last_seen_at: String,
    issue_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolveIssueRequest {
    release_id: String,
}

#[derive(Serialize)]
struct IssueListResponse {
    items: Vec<IssueSummary>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct IssueSummary {
    issue_id: String,
    path: String,
    title: String,
    fingerprint_algorithm: String,
    fingerprint_version: i32,
    fingerprint: String,
    status: String,
    regression_state: String,
    first_seen_at: String,
    last_seen_at: String,
    event_count: i64,
    representative_event_id: String,
    first_release_id: Option<String>,
    last_release_id: Option<String>,
    resolved_in_release_id: Option<String>,
    resolved_at: Option<String>,
    affected_release_count: i64,
}

#[derive(Serialize)]
struct IssueDetail {
    #[serde(flatten)]
    issue: IssueSummary,
    release_mapping: ReleaseMappingSummary,
    variants: Vec<VariantView>,
    variants_truncated: bool,
    releases: Vec<IssueReleaseView>,
    releases_truncated: bool,
}

#[derive(Serialize)]
struct ReleaseMappingSummary {
    matched: i64,
    missing: i64,
    ambiguous: i64,
}

#[derive(Serialize)]
struct VariantView {
    fingerprint: String,
    first_seen_at: String,
    last_seen_at: String,
    event_count: i64,
    representative_event_id: String,
}

#[derive(Serialize)]
struct IssueReleaseView {
    release_id: String,
    version: String,
    platform: String,
    architecture: String,
    configuration: String,
    build_timestamp: Option<String>,
    first_seen_at: String,
    last_seen_at: String,
    event_count: i64,
    representative_event_id: String,
}

#[derive(Serialize)]
struct ResolutionView {
    issue_id: String,
    status: String,
    regression_state: String,
    resolved_in_release_id: Option<String>,
    resolved_at: Option<String>,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

struct ProjectScope {
    organization_id: String,
    project_id: String,
}

#[derive(Debug)]
pub(crate) enum IssueError {
    InvalidRequest,
    NotFound,
    Internal,
}

impl IntoResponse for IssueError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request is invalid",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "resource was not found"),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "request could not be completed",
            ),
        };
        no_store(status, &ErrorBody { code, message })
    }
}

pub(crate) async fn list_issues(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    query: Result<Query<IssueListQuery>, QueryRejection>,
) -> Result<Response, IssueError> {
    authorize(&state, &headers)?;
    let Query(query) = query.map_err(|_| IssueError::InvalidRequest)?;
    let query = validate_list_query(query)?;
    if dashboard_filters_requested(&query) && !state.dashboard_enabled() {
        return Err(IssueError::NotFound);
    }
    let pool = state.control_pool().ok_or(IssueError::Internal)?;
    let mut transaction = pool.begin().await.map_err(|_| IssueError::Internal)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(|_| IssueError::Internal)?;
    sqlx::query("SET LOCAL statement_timeout = '2s'")
        .execute(&mut *transaction)
        .await
        .map_err(|_| IssueError::Internal)?;
    let scope = transaction_scope(&mut transaction, &project_id).await?;
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    let filter_hash = issue_filter_hash(&query)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|value| decode_issue_cursor(value, &scope.project_id, &filter_hash))
        .transpose()?;
    let search = query.query.as_deref().map(search_pattern);
    let rows = sqlx::query(
        "SELECT i.id::text AS issue_id, i.title, i.fingerprint_algorithm, i.fingerprint_version, i.fingerprint, i.status, i.regression_state, to_char(i.first_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS first_seen_at, to_char(i.last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, i.event_count, i.representative_event_id::text AS representative_event_id, i.first_release_id::text AS first_release_id, i.last_release_id::text AS last_release_id, i.resolved_in_release_id::text AS resolved_in_release_id, CASE WHEN i.resolved_at IS NULL THEN NULL ELSE to_char(i.resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS resolved_at, (SELECT count(*) FROM issue_releases ir WHERE ir.organization_id = i.organization_id AND ir.project_id = i.project_id AND ir.issue_id = i.id) AS affected_release_count FROM issues i WHERE i.organization_id = $1::uuid AND i.project_id = $2::uuid AND ($3::timestamptz IS NULL OR (i.last_seen_at, i.id) < ($3::timestamptz, $4::uuid)) AND ($5::text IS NULL OR i.status = $5) AND ($6::text IS NULL OR i.regression_state = $6) AND ($8::timestamptz IS NULL OR i.first_seen_at >= $8::timestamptz) AND ($9::timestamptz IS NULL OR i.first_seen_at < $9::timestamptz) AND ($10::timestamptz IS NULL OR i.last_seen_at >= $10::timestamptz) AND ($11::timestamptz IS NULL OR i.last_seen_at < $11::timestamptz) AND (($7::uuid IS NULL AND $12::text IS NULL AND $13::text IS NULL AND $14::text IS NULL AND $15::text IS NULL AND $16::text IS NULL) OR EXISTS (SELECT 1 FROM crash_events e LEFT JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id WHERE e.organization_id = i.organization_id AND e.project_id = i.project_id AND e.issue_id = i.id AND ($7::uuid IS NULL OR e.release_id = $7::uuid) AND ($12::text IS NULL OR s.crash_type = $12) AND ($13::text IS NULL OR s.platform = $13) AND ($14::text IS NULL OR s.architecture = $14) AND ($15::text IS NULL OR s.engine_version = $15) AND ($16::text IS NULL OR CASE WHEN e.processing_state IN ('failed', 'quarantined') THEN 'failed' WHEN s.symbolication_state IS NOT NULL THEN s.symbolication_state WHEN e.processing_state = 'awaiting_symbols' THEN 'missing' ELSE 'processing' END = $16))) AND ($17::text IS NULL OR i.title ILIKE $17 ESCAPE E'\\\\' OR EXISTS (SELECT 1 FROM crash_events e JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id WHERE e.organization_id = i.organization_id AND e.project_id = i.project_id AND e.issue_id = i.id AND s.search_text ILIKE $17 ESCAPE E'\\\\')) ORDER BY i.last_seen_at DESC, i.id DESC LIMIT $18",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(cursor.as_ref().map(|value| value.last_seen_at.as_str()))
    .bind(cursor.as_ref().map(|value| value.issue_id.as_str()))
    .bind(query.status.as_deref())
    .bind(query.regression_state.as_deref())
    .bind(query.release_id.as_deref())
    .bind(query.first_seen_from.as_deref())
    .bind(query.first_seen_to.as_deref())
    .bind(query.last_seen_from.as_deref())
    .bind(query.last_seen_to.as_deref())
    .bind(query.crash_type.as_deref())
    .bind(query.platform.as_deref())
    .bind(query.architecture.as_deref())
    .bind(query.engine_version.as_deref())
    .bind(query.symbolication_state.as_deref())
    .bind(search.as_deref())
    .bind(i64::from(limit) + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| IssueError::Internal)?;
    let mut items = rows
        .iter()
        .map(|row| issue_summary(row, &scope.project_id))
        .collect::<Vec<_>>();
    let has_next = items.len() > usize::from(limit);
    items.truncate(usize::from(limit));
    let next_cursor = if has_next {
        items
            .last()
            .map(|issue| {
                encode_issue_cursor(&IssueCursor {
                    version: 1,
                    project_id: scope.project_id.clone(),
                    filter_hash,
                    last_seen_at: issue.last_seen_at.clone(),
                    issue_id: issue.issue_id.clone(),
                })
            })
            .transpose()?
    } else {
        None
    };
    transaction
        .commit()
        .await
        .map_err(|_| IssueError::Internal)?;
    Ok(no_store(
        StatusCode::OK,
        &IssueListResponse { items, next_cursor },
    ))
}

pub(crate) async fn get_issue(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((project_id, issue_id)): Path<(String, String)>,
) -> Result<Response, IssueError> {
    authorize(&state, &headers)?;
    if !valid_uuid(&issue_id) {
        return Err(IssueError::NotFound);
    }
    let pool = state.control_pool().ok_or(IssueError::Internal)?;
    let mut transaction = pool.begin().await.map_err(|_| IssueError::Internal)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(|_| IssueError::Internal)?;
    let scope = transaction_scope(&mut transaction, &project_id).await?;
    let detail = load_issue_detail(&mut transaction, &scope, &issue_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| IssueError::Internal)?;
    Ok(no_store(StatusCode::OK, &detail))
}

pub(crate) async fn resolve_issue(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((project_id, issue_id)): Path<(String, String)>,
    payload: Result<Json<ResolveIssueRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, IssueError> {
    authorize(&state, &headers)?;
    let Json(request) = payload.map_err(|_| IssueError::InvalidRequest)?;
    if !valid_uuid(&issue_id) || !valid_uuid(&request.release_id) {
        return Err(IssueError::NotFound);
    }
    let pool = state.control_pool().ok_or(IssueError::Internal)?;
    let mut transaction = pool.begin().await.map_err(|_| IssueError::Internal)?;
    let scope = transaction_scope(&mut transaction, &project_id).await?;
    lock_issue(&mut transaction, &scope, &issue_id).await?;
    let resolution_timestamp = sqlx::query_scalar::<_, time::OffsetDateTime>(
        "SELECT build_timestamp FROM releases WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND build_timestamp IS NOT NULL",
    )
    .bind(&request.release_id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| IssueError::Internal)?
    .ok_or(IssueError::NotFound)?;
    let regressed =
        has_provably_later_release(&mut transaction, &scope, &issue_id, resolution_timestamp)
            .await?;
    let (status, regression_state) = if regressed {
        ("open", "regressed")
    } else {
        ("resolved", "resolved")
    };
    let row = sqlx::query(
        "UPDATE issues SET status = $4, regression_state = $5, resolved_in_release_id = $6::uuid, resolved_at = now(), updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 RETURNING id::text AS issue_id, status, regression_state, resolved_in_release_id::text AS resolved_in_release_id, to_char(resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS resolved_at",
    )
    .bind(&issue_id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(status)
    .bind(regression_state)
    .bind(&request.release_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| IssueError::Internal)?;
    let response = resolution_view(&row);
    transaction
        .commit()
        .await
        .map_err(|_| IssueError::Internal)?;
    Ok(no_store(StatusCode::OK, &response))
}

pub(crate) async fn reopen_issue(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((project_id, issue_id)): Path<(String, String)>,
) -> Result<Response, IssueError> {
    authorize(&state, &headers)?;
    if !valid_uuid(&issue_id) {
        return Err(IssueError::NotFound);
    }
    let pool = state.control_pool().ok_or(IssueError::Internal)?;
    let mut transaction = pool.begin().await.map_err(|_| IssueError::Internal)?;
    let scope = transaction_scope(&mut transaction, &project_id).await?;
    lock_issue(&mut transaction, &scope, &issue_id).await?;
    let regression_state = retained_regression_state(&mut transaction, &scope, &issue_id).await?;
    let row = sqlx::query(
        "UPDATE issues SET status = 'open', regression_state = $4, resolved_in_release_id = NULL, resolved_at = NULL, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 RETURNING id::text AS issue_id, status, regression_state, NULL::text AS resolved_in_release_id, NULL::text AS resolved_at",
    )
    .bind(&issue_id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(regression_state)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| IssueError::Internal)?;
    let response = resolution_view(&row);
    transaction
        .commit()
        .await
        .map_err(|_| IssueError::Internal)?;
    Ok(no_store(StatusCode::OK, &response))
}

fn validate_list_query(query: IssueListQuery) -> Result<IssueListQuery, IssueError> {
    if query
        .limit
        .is_some_and(|limit| limit == 0 || limit > MAX_PAGE_SIZE)
        || query.cursor.as_deref().is_some_and(|value| {
            value.is_empty() || value.len() > MAX_CURSOR_BYTES.saturating_mul(2)
        })
        || query
            .release_id
            .as_deref()
            .is_some_and(|value| !valid_uuid(value))
        || query
            .status
            .as_deref()
            .is_some_and(|value| !matches!(value, "open" | "resolved"))
        || query.regression_state.as_deref().is_some_and(|value| {
            !matches!(
                value,
                "new" | "ongoing" | "resolved" | "regressed" | "unknown"
            )
        })
        || [
            query.crash_type.as_deref(),
            query.platform.as_deref(),
            query.architecture.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| !valid_filter_token(value, 64))
        || query
            .engine_version
            .as_deref()
            .is_some_and(|value| !valid_filter_text(value, 128))
        || query.symbolication_state.as_deref().is_some_and(|value| {
            !matches!(
                value,
                "readable" | "partial" | "missing" | "failed" | "processing"
            )
        })
        || [
            query.first_seen_from.as_deref(),
            query.first_seen_to.as_deref(),
            query.last_seen_from.as_deref(),
            query.last_seen_to.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| OffsetDateTime::parse(value, &Rfc3339).is_err())
        || !valid_time_range(
            query.first_seen_from.as_deref(),
            query.first_seen_to.as_deref(),
        )
        || !valid_time_range(
            query.last_seen_from.as_deref(),
            query.last_seen_to.as_deref(),
        )
        || query.query.as_deref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_SEARCH_BYTES
                || value.chars().any(char::is_control)
        })
    {
        return Err(IssueError::InvalidRequest);
    }
    Ok(query)
}

fn dashboard_filters_requested(query: &IssueListQuery) -> bool {
    query.crash_type.is_some()
        || query.platform.is_some()
        || query.architecture.is_some()
        || query.engine_version.is_some()
        || query.symbolication_state.is_some()
        || query.first_seen_from.is_some()
        || query.first_seen_to.is_some()
        || query.last_seen_from.is_some()
        || query.last_seen_to.is_some()
        || query.query.is_some()
}

fn valid_filter_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-+.".contains(&byte)
        })
}

fn valid_filter_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn valid_time_range(from: Option<&str>, to: Option<&str>) -> bool {
    let (Some(from), Some(to)) = (from, to) else {
        return true;
    };
    let Ok(from) = OffsetDateTime::parse(from, &Rfc3339) else {
        return false;
    };
    let Ok(to) = OffsetDateTime::parse(to, &Rfc3339) else {
        return false;
    };
    from < to
}

fn issue_filter_hash(query: &IssueListQuery) -> Result<String, IssueError> {
    let identity = IssueFilterIdentity {
        status: query.status.as_deref(),
        regression_state: query.regression_state.as_deref(),
        release_id: query.release_id.as_deref(),
        crash_type: query.crash_type.as_deref(),
        platform: query.platform.as_deref(),
        architecture: query.architecture.as_deref(),
        engine_version: query.engine_version.as_deref(),
        symbolication_state: query.symbolication_state.as_deref(),
        first_seen_from: query.first_seen_from.as_deref(),
        first_seen_to: query.first_seen_to.as_deref(),
        last_seen_from: query.last_seen_from.as_deref(),
        last_seen_to: query.last_seen_to.as_deref(),
        query: query.query.as_deref(),
    };
    let bytes = serde_json::to_vec(&identity).map_err(|_| IssueError::Internal)?;
    Ok(lower_hex(&Sha256::digest(bytes)))
}

fn encode_issue_cursor(cursor: &IssueCursor) -> Result<String, IssueError> {
    let bytes = serde_json::to_vec(&cursor).map_err(|_| IssueError::Internal)?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(IssueError::Internal);
    }
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_issue_cursor(
    value: &str,
    project_id: &str,
    filter_hash: &str,
) -> Result<IssueCursor, IssueError> {
    if value.is_empty() || value.len() > MAX_CURSOR_BYTES.saturating_mul(2) {
        return Err(IssueError::InvalidRequest);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| IssueError::InvalidRequest)?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(IssueError::InvalidRequest);
    }
    let cursor: IssueCursor =
        serde_json::from_slice(&bytes).map_err(|_| IssueError::InvalidRequest)?;
    if cursor.version != 1
        || cursor.project_id != project_id
        || cursor.filter_hash != filter_hash
        || !valid_uuid(&cursor.issue_id)
        || OffsetDateTime::parse(&cursor.last_seen_at, &Rfc3339).is_err()
    {
        return Err(IssueError::InvalidRequest);
    }
    Ok(cursor)
}

fn search_pattern(value: &str) -> String {
    let mut pattern = String::with_capacity(value.len() + 2);
    pattern.push('%');
    for character in value.chars() {
        if matches!(character, '\\' | '%' | '_') {
            pattern.push('\\');
        }
        pattern.push(character);
    }
    pattern.push('%');
    pattern
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

fn authorize(state: &ServerState, headers: &HeaderMap) -> Result<(), IssueError> {
    if state.authorize_control(headers) {
        Ok(())
    } else {
        Err(IssueError::NotFound)
    }
}

async fn transaction_scope(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    project_id: &str,
) -> Result<ProjectScope, IssueError> {
    if !valid_uuid(project_id) {
        return Err(IssueError::NotFound);
    }
    let row = sqlx::query(
        "SELECT p.organization_id::text AS organization_id, p.id::text AS project_id FROM projects p JOIN organization_memberships m ON m.organization_id = p.organization_id AND m.role = 'owner' JOIN users u ON u.id = m.user_id WHERE u.bootstrap_subject = 'local-bootstrap' AND p.id::text = $1",
    )
    .bind(project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| IssueError::Internal)?
    .ok_or(IssueError::NotFound)?;
    Ok(ProjectScope {
        organization_id: row.get("organization_id"),
        project_id: row.get("project_id"),
    })
}

async fn lock_issue(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &ProjectScope,
    issue_id: &str,
) -> Result<(), IssueError> {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT id::text FROM issues WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 FOR UPDATE",
    )
    .bind(issue_id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| IssueError::Internal)?;
    found.map_or(Err(IssueError::NotFound), |_| Ok(()))
}

async fn retained_regression_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &ProjectScope,
    issue_id: &str,
) -> Result<&'static str, IssueError> {
    let row = sqlx::query(
        "SELECT count(*) AS releases, count(r.build_timestamp) AS timestamped, count(DISTINCT r.build_timestamp) AS distinct_timestamps FROM issue_releases ir JOIN releases r ON r.id = ir.release_id AND r.organization_id = ir.organization_id AND r.project_id = ir.project_id WHERE ir.organization_id::text = $1 AND ir.project_id::text = $2 AND ir.issue_id::text = $3",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| IssueError::Internal)?;
    let releases: i64 = row.get("releases");
    let timestamped: i64 = row.get("timestamped");
    let distinct: i64 = row.get("distinct_timestamps");
    Ok(
        if releases == 0 || timestamped != releases || distinct != releases {
            "unknown"
        } else if releases == 1 {
            "new"
        } else {
            "ongoing"
        },
    )
}

async fn has_provably_later_release(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &ProjectScope,
    issue_id: &str,
    resolution_timestamp: time::OffsetDateTime,
) -> Result<bool, IssueError> {
    let row = sqlx::query(
        "SELECT count(*) AS releases, count(r.build_timestamp) AS timestamped, count(DISTINCT r.build_timestamp) AS distinct_timestamps, max(r.build_timestamp) AS latest_timestamp FROM issue_releases ir JOIN releases r ON r.id = ir.release_id AND r.organization_id = ir.organization_id AND r.project_id = ir.project_id WHERE ir.organization_id::text = $1 AND ir.project_id::text = $2 AND ir.issue_id::text = $3",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| IssueError::Internal)?;
    let releases: i64 = row.get("releases");
    let timestamped: i64 = row.get("timestamped");
    let distinct: i64 = row.get("distinct_timestamps");
    let latest: Option<time::OffsetDateTime> = row.get("latest_timestamp");
    Ok(releases > 0
        && releases == timestamped
        && releases == distinct
        && latest.is_some_and(|timestamp| timestamp > resolution_timestamp))
}

async fn load_issue_detail(
    connection: &mut PgConnection,
    scope: &ProjectScope,
    issue_id: &str,
) -> Result<IssueDetail, IssueError> {
    let row = sqlx::query(
        "SELECT i.id::text AS issue_id, i.title, i.fingerprint_algorithm, i.fingerprint_version, i.fingerprint, i.status, i.regression_state, to_char(i.first_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS first_seen_at, to_char(i.last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, i.event_count, i.representative_event_id::text AS representative_event_id, i.first_release_id::text AS first_release_id, i.last_release_id::text AS last_release_id, i.resolved_in_release_id::text AS resolved_in_release_id, CASE WHEN i.resolved_at IS NULL THEN NULL ELSE to_char(i.resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS resolved_at, (SELECT count(*) FROM issue_releases ir WHERE ir.organization_id = i.organization_id AND ir.project_id = i.project_id AND ir.issue_id = i.id) AS affected_release_count FROM issues i WHERE i.id::text = $1 AND i.organization_id::text = $2 AND i.project_id::text = $3",
    )
    .bind(issue_id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| IssueError::Internal)?
    .ok_or(IssueError::NotFound)?;
    let issue = issue_summary(&row, &scope.project_id);
    let release_mapping = load_mapping_summary(connection, scope, issue_id).await?;
    let (variants, variants_truncated) = load_variants(connection, scope, issue_id).await?;
    let (releases, releases_truncated) = load_releases(connection, scope, issue_id).await?;
    Ok(IssueDetail {
        issue,
        release_mapping,
        variants,
        variants_truncated,
        releases,
        releases_truncated,
    })
}

async fn load_mapping_summary(
    connection: &mut PgConnection,
    scope: &ProjectScope,
    issue_id: &str,
) -> Result<ReleaseMappingSummary, IssueError> {
    let row = sqlx::query(
        "SELECT count(*) FILTER (WHERE release_mapping_state = 'matched') AS matched, count(*) FILTER (WHERE release_mapping_state = 'missing') AS missing, count(*) FILTER (WHERE release_mapping_state = 'ambiguous') AS ambiguous FROM crash_events WHERE organization_id::text = $1 AND project_id::text = $2 AND issue_id::text = $3",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| IssueError::Internal)?;
    Ok(ReleaseMappingSummary {
        matched: row.get("matched"),
        missing: row.get("missing"),
        ambiguous: row.get("ambiguous"),
    })
}

async fn load_variants(
    connection: &mut PgConnection,
    scope: &ProjectScope,
    issue_id: &str,
) -> Result<(Vec<VariantView>, bool), IssueError> {
    let rows = sqlx::query(
        "SELECT variant_fingerprint, to_char(first_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS first_seen_at, to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, event_count, representative_event_id::text AS representative_event_id FROM issue_variants WHERE organization_id::text = $1 AND project_id::text = $2 AND issue_id::text = $3 ORDER BY event_count DESC, variant_fingerprint LIMIT $4",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .bind(i64::try_from(MAX_DETAIL_ROWS + 1).unwrap_or(i64::MAX))
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| IssueError::Internal)?;
    let mut variants = rows
        .iter()
        .map(|row| VariantView {
            fingerprint: row.get("variant_fingerprint"),
            first_seen_at: row.get("first_seen_at"),
            last_seen_at: row.get("last_seen_at"),
            event_count: row.get("event_count"),
            representative_event_id: row.get("representative_event_id"),
        })
        .collect::<Vec<_>>();
    let truncated = variants.len() > MAX_DETAIL_ROWS;
    variants.truncate(MAX_DETAIL_ROWS);
    Ok((variants, truncated))
}

async fn load_releases(
    connection: &mut PgConnection,
    scope: &ProjectScope,
    issue_id: &str,
) -> Result<(Vec<IssueReleaseView>, bool), IssueError> {
    let rows = sqlx::query(
        "SELECT r.id::text AS release_id, r.version, r.platform, r.architecture, r.configuration, CASE WHEN r.build_timestamp IS NULL THEN NULL ELSE to_char(r.build_timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS build_timestamp, to_char(ir.first_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS first_seen_at, to_char(ir.last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, ir.event_count, ir.representative_event_id::text AS representative_event_id FROM issue_releases ir JOIN releases r ON r.id = ir.release_id AND r.organization_id = ir.organization_id AND r.project_id = ir.project_id WHERE ir.organization_id::text = $1 AND ir.project_id::text = $2 AND ir.issue_id::text = $3 ORDER BY r.build_timestamp DESC NULLS LAST, r.id LIMIT $4",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(issue_id)
    .bind(i64::try_from(MAX_DETAIL_ROWS + 1).unwrap_or(i64::MAX))
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| IssueError::Internal)?;
    let mut releases = rows
        .iter()
        .map(|row| IssueReleaseView {
            release_id: row.get("release_id"),
            version: row.get("version"),
            platform: row.get("platform"),
            architecture: row.get("architecture"),
            configuration: row.get("configuration"),
            build_timestamp: row.get("build_timestamp"),
            first_seen_at: row.get("first_seen_at"),
            last_seen_at: row.get("last_seen_at"),
            event_count: row.get("event_count"),
            representative_event_id: row.get("representative_event_id"),
        })
        .collect::<Vec<_>>();
    let truncated = releases.len() > MAX_DETAIL_ROWS;
    releases.truncate(MAX_DETAIL_ROWS);
    Ok((releases, truncated))
}

fn issue_summary(row: &sqlx::postgres::PgRow, project_id: &str) -> IssueSummary {
    let issue_id: String = row.get("issue_id");
    IssueSummary {
        path: format!("/api/v1/projects/{project_id}/issues/{issue_id}"),
        issue_id,
        title: row.get("title"),
        fingerprint_algorithm: row.get("fingerprint_algorithm"),
        fingerprint_version: row.get("fingerprint_version"),
        fingerprint: row.get("fingerprint"),
        status: row.get("status"),
        regression_state: row.get("regression_state"),
        first_seen_at: row.get("first_seen_at"),
        last_seen_at: row.get("last_seen_at"),
        event_count: row.get("event_count"),
        representative_event_id: row.get("representative_event_id"),
        first_release_id: row.get("first_release_id"),
        last_release_id: row.get("last_release_id"),
        resolved_in_release_id: row.get("resolved_in_release_id"),
        resolved_at: row.get("resolved_at"),
        affected_release_count: row.get("affected_release_count"),
    }
}

fn resolution_view(row: &sqlx::postgres::PgRow) -> ResolutionView {
    ResolutionView {
        issue_id: row.get("issue_id"),
        status: row.get("status"),
        regression_state: row.get("regression_state"),
        resolved_in_release_id: row.get("resolved_in_release_id"),
        resolved_at: row.get("resolved_at"),
    }
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
    use std::{env, error::Error};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use tower::ServiceExt;

    use super::{
        IssueCursor, IssueError, IssueListQuery, decode_issue_cursor, encode_issue_cursor,
        issue_filter_hash, search_pattern, valid_uuid, validate_list_query,
    };
    use crate::project_setup::{DATABASE_TEST_LOCK, ServerState, migrate, router};

    const SECRET: &str = "issue-api-secret-with-at-least-32-bytes";

    #[test]
    fn list_bounds_and_identifiers_are_strict() {
        assert!(valid_uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
        assert!(!valid_uuid("../../outside"));
        assert!(matches!(
            validate_list_query(IssueListQuery {
                limit: Some(101),
                ..IssueListQuery::default()
            }),
            Err(IssueError::InvalidRequest)
        ));
        assert_eq!(search_pattern("100%_safe\\path"), "%100\\%\\_safe\\\\path%");
        let query = IssueListQuery::default();
        let filter_hash =
            issue_filter_hash(&query).unwrap_or_else(|_| panic!("default filters must hash"));
        let cursor = encode_issue_cursor(&IssueCursor {
            version: 1,
            project_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            filter_hash: filter_hash.clone(),
            last_seen_at: "2026-01-01T00:00:00Z".to_owned(),
            issue_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
        })
        .unwrap_or_else(|_| panic!("valid cursor must encode"));
        assert!(
            decode_issue_cursor(
                &cursor,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                &filter_hash
            )
            .is_ok()
        );
        assert!(matches!(
            decode_issue_cursor(
                &cursor,
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                &filter_hash
            ),
            Err(IssueError::InvalidRequest)
        ));
        assert!(matches!(
            validate_list_query(IssueListQuery {
                regression_state: Some("guessed".to_owned()),
                ..IssueListQuery::default()
            }),
            Err(IssueError::InvalidRequest)
        ));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn issue_routes_are_bounded_tenant_scoped_and_manage_resolution()
    -> Result<(), Box<dyn Error>> {
        let Ok(database_url) = env::var("FAULTLANE_TEST_DATABASE_URL") else {
            return Ok(());
        };
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&database_url)
            .await?;
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await?;
        let owned = insert_scope(&pool, "local-bootstrap", "owned").await?;
        let outside = insert_scope(&pool, "outside-user", "outside").await?;
        let first = insert_issue(&pool, &owned, "first", 'a', "2026-01-02T00:00:00Z").await?;
        let second = insert_issue(&pool, &owned, "second", 'b', "2026-01-03T00:00:00Z").await?;
        let outside_issue =
            insert_issue(&pool, &outside, "outside", 'c', "2026-01-04T00:00:00Z").await?;
        let app = router("api", ServerState::issue_test(pool.clone(), SECRET));

        let first_page = app
            .clone()
            .oneshot(
                authorized(
                    Request::builder()
                        .uri(format!("/api/v1/projects/{}/issues?limit=1", owned.project)),
                )
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(first_page.status(), StatusCode::OK);
        assert_no_store(&first_page);
        let first_page = json_body(first_page).await?;
        assert_eq!(first_page["items"].as_array().map(Vec::len), Some(1));
        assert_eq!(first_page["items"][0]["issue_id"], second.issue_id);
        let cursor = first_page["next_cursor"]
            .as_str()
            .ok_or("first page must return a cursor")?;
        let second_page = app
            .clone()
            .oneshot(
                authorized(Request::builder().uri(format!(
                    "/api/v1/projects/{}/issues?limit=1&cursor={cursor}",
                    owned.project
                )))
                .body(Body::empty())?,
            )
            .await?;
        let second_page = json_body(second_page).await?;
        assert_eq!(second_page["items"][0]["issue_id"], first.issue_id);
        assert!(second_page["next_cursor"].is_null());

        for filter in [
            "status=open",
            "regression_state=new",
            &format!("release_id={}", owned.release),
            "crash_type=crash",
            "platform=windows",
            "architecture=x86_64",
            "engine_version=5.8.1",
            "symbolication_state=readable",
            "first_seen_from=2026-01-01T00%3A00%3A00Z",
            "last_seen_to=2026-01-04T00%3A00%3A00Z",
        ] {
            let response = app
                .clone()
                .oneshot(
                    authorized(Request::builder().uri(format!(
                        "/api/v1/projects/{}/issues?{filter}",
                        owned.project
                    )))
                    .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK, "filter: {filter}");
            assert_eq!(
                json_body(response).await?["items"].as_array().map(Vec::len),
                Some(2),
                "filter: {filter}"
            );
        }
        for (filter, expected_issue) in [
            (
                "query=second%3A%3ARoot%28%29",
                Some(second.issue_id.as_str()),
            ),
            ("query=second%20player", Some(second.issue_id.as_str())),
            ("query=%25", None),
            (
                "last_seen_to=2026-01-03T00%3A00%3A00Z",
                Some(first.issue_id.as_str()),
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    authorized(Request::builder().uri(format!(
                        "/api/v1/projects/{}/issues?{filter}",
                        owned.project
                    )))
                    .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK, "filter: {filter}");
            let body = json_body(response).await?;
            if let Some(expected_issue) = expected_issue {
                assert_eq!(
                    body["items"].as_array().map(Vec::len),
                    Some(1),
                    "filter: {filter}"
                );
                assert_eq!(body["items"][0]["issue_id"], expected_issue);
            } else {
                assert_eq!(body["items"].as_array().map(Vec::len), Some(0));
            }
        }
        let cross_filter_cursor = app
            .clone()
            .oneshot(
                authorized(Request::builder().uri(format!(
                    "/api/v1/projects/{}/issues?limit=1&status=open&cursor={cursor}",
                    owned.project
                )))
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(cross_filter_cursor.status(), StatusCode::BAD_REQUEST);
        assert_no_store(&cross_filter_cursor);

        sqlx::query(
            "UPDATE issues SET last_seen_at = '2026-01-03T00:00:00Z' WHERE id::text IN ($1, $2)",
        )
        .bind(&first.issue_id)
        .bind(&second.issue_id)
        .execute(&pool)
        .await?;
        let tied_page = app
            .clone()
            .oneshot(
                authorized(
                    Request::builder()
                        .uri(format!("/api/v1/projects/{}/issues?limit=1", owned.project)),
                )
                .body(Body::empty())?,
            )
            .await?;
        let tied_page = json_body(tied_page).await?;
        let tied_first_id = tied_page["items"][0]["issue_id"]
            .as_str()
            .ok_or("tied page must include an issue")?;
        let tied_cursor = tied_page["next_cursor"]
            .as_str()
            .ok_or("tied page must include a cursor")?;
        sqlx::query("UPDATE issues SET last_seen_at = '2026-02-01T00:00:00Z' WHERE id::text = $1")
            .bind(tied_first_id)
            .execute(&pool)
            .await?;
        let tied_second_page = app
            .clone()
            .oneshot(
                authorized(Request::builder().uri(format!(
                    "/api/v1/projects/{}/issues?limit=1&cursor={tied_cursor}",
                    owned.project
                )))
                .body(Body::empty())?,
            )
            .await?;
        let tied_second_page = json_body(tied_second_page).await?;
        assert_eq!(tied_second_page["items"].as_array().map(Vec::len), Some(1));
        assert_ne!(tied_second_page["items"][0]["issue_id"], tied_first_id);

        let detail = app
            .clone()
            .oneshot(
                authorized(Request::builder().uri(format!(
                    "/api/v1/projects/{}/issues/{}",
                    owned.project, first.issue_id
                )))
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(detail.status(), StatusCode::OK);
        assert_no_store(&detail);
        let detail = json_body(detail).await?;
        assert_eq!(detail["event_count"], 1);
        assert_eq!(detail["affected_release_count"], 1);
        assert_eq!(detail["release_mapping"]["matched"], 1);
        assert_eq!(detail["variants"].as_array().map(Vec::len), Some(1));
        assert_eq!(detail["releases"].as_array().map(Vec::len), Some(1));

        let event = app
            .clone()
            .oneshot(
                authorized(Request::builder().uri(format!(
                    "/api/v1/projects/{}/events/{}",
                    owned.project, first.event_id
                )))
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(event.status(), StatusCode::OK);
        let event = json_body(event).await?;
        assert_eq!(event["issue_id"], first.issue_id);
        assert_eq!(event["release_mapping_state"], "matched");
        assert_eq!(
            event["candidate_release_ids"],
            serde_json::json!([owned.release])
        );

        let older_release: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '0.9.0', 'windows', 'x86_64', 'Shipping', '2025-12-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&owned.organization)
        .bind(&owned.project)
        .fetch_one(&pool)
        .await?;
        let already_later = app
            .clone()
            .oneshot(
                authorized(Request::builder().method("PUT").uri(format!(
                    "/api/v1/projects/{}/issues/{}/resolution",
                    owned.project, first.issue_id
                )))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "release_id": &older_release
                }))?))?,
            )
            .await?;
        assert_eq!(already_later.status(), StatusCode::OK);
        let already_later = json_body(already_later).await?;
        assert_eq!(already_later["status"], "open");
        assert_eq!(already_later["regression_state"], "regressed");
        assert_eq!(already_later["resolved_in_release_id"], older_release);

        let cross_release = app
            .clone()
            .oneshot(
                authorized(Request::builder().method("PUT").uri(format!(
                    "/api/v1/projects/{}/issues/{}/resolution",
                    owned.project, first.issue_id
                )))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "release_id": outside.release
                }))?))?,
            )
            .await?;
        assert_eq!(cross_release.status(), StatusCode::NOT_FOUND);
        assert_no_store(&cross_release);

        let resolved = app
            .clone()
            .oneshot(
                authorized(Request::builder().method("PUT").uri(format!(
                    "/api/v1/projects/{}/issues/{}/resolution",
                    owned.project, first.issue_id
                )))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "release_id": owned.release
                }))?))?,
            )
            .await?;
        assert_eq!(resolved.status(), StatusCode::OK);
        let resolved = json_body(resolved).await?;
        assert_eq!(resolved["status"], "resolved");
        assert_eq!(resolved["regression_state"], "resolved");

        let reopened = app
            .clone()
            .oneshot(
                authorized(Request::builder().method("DELETE").uri(format!(
                    "/api/v1/projects/{}/issues/{}/resolution",
                    owned.project, first.issue_id
                )))
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(reopened.status(), StatusCode::OK);
        let reopened = json_body(reopened).await?;
        assert_eq!(reopened["status"], "open");
        assert_eq!(reopened["regression_state"], "new");
        assert!(reopened["resolved_in_release_id"].is_null());

        for response in [
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/projects/{}/issues", owned.project))
                        .body(Body::empty())?,
                )
                .await?,
            app.clone()
                .oneshot(
                    authorized(
                        Request::builder()
                            .uri(format!("/api/v1/projects/{}/issues", outside.project)),
                    )
                    .body(Body::empty())?,
                )
                .await?,
            app.clone()
                .oneshot(
                    authorized(Request::builder().uri(format!(
                        "/api/v1/projects/{}/issues/{}",
                        owned.project, outside_issue.issue_id
                    )))
                    .body(Body::empty())?,
                )
                .await?,
        ] {
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_no_store(&response);
        }
        let invalid_query = app
            .oneshot(
                authorized(Request::builder().uri(format!(
                    "/api/v1/projects/{}/issues?limit=101",
                    owned.project
                )))
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(invalid_query.status(), StatusCode::BAD_REQUEST);
        assert_no_store(&invalid_query);
        Ok(())
    }

    struct Scope {
        organization: String,
        project: String,
        ingest_key: String,
        release: String,
    }

    struct SeededIssue {
        issue_id: String,
        event_id: String,
    }

    async fn insert_scope(
        pool: &PgPool,
        bootstrap_subject: &str,
        suffix: &str,
    ) -> Result<Scope, sqlx::Error> {
        let user_id: String = sqlx::query_scalar(
            "INSERT INTO users (bootstrap_subject, email) VALUES ($1, $2) RETURNING id::text",
        )
        .bind(bootstrap_subject)
        .bind(format!("{suffix}@example.com"))
        .fetch_one(pool)
        .await?;
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
        )
        .bind(format!("{suffix} organization"))
        .bind(format!("{suffix}-organization"))
        .fetch_one(pool)
        .await?;
        sqlx::query(
            "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')",
        )
        .bind(&organization_id)
        .bind(user_id)
        .execute(pool)
        .await?;
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, $2, $3) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(format!("{suffix} project"))
        .bind(format!("{suffix}-project"))
        .fetch_one(pool)
        .await?;
        let ingest_key_id: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, $4) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(Sha256::digest(format!("{suffix}-key")).to_vec())
        .bind(suffix)
        .fetch_one(pool)
        .await?;
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '1.0.0', 'windows', 'x86_64', 'Shipping', '2026-01-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(pool)
        .await?;
        Ok(Scope {
            organization: organization_id,
            project: project_id,
            ingest_key: ingest_key_id,
            release: release_id,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn insert_issue(
        pool: &PgPool,
        scope: &Scope,
        suffix: &str,
        fingerprint_character: char,
        received_at: &str,
    ) -> Result<SeededIssue, sqlx::Error> {
        let object_id: String = sqlx::query_scalar(
            "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3, $4, 1, 'application/octet-stream') RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(format!("issue-test/{suffix}"))
        .bind(vec![0_u8; 32])
        .fetch_one(pool)
        .await?;
        let event_id: String = sqlx::query_scalar(
            "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, environment, processing_state, received_at) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'production', 'processed', $5::timestamptz) RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&scope.ingest_key)
        .bind(object_id)
        .bind(received_at)
        .fetch_one(pool)
        .await?;
        let result = json!({
            "crash_context": {
                "crash_type": "crash",
                "platform": {"normalized": "windows"},
                "architecture": "x86_64",
                "engine_version": "5.8.1",
                "error_message": format!("{suffix} access violation"),
                "user_comment": format!("{suffix} player report")
            },
            "current": {
                "symbolication": {
                    "modules": [{"module": format!("{suffix}.exe"), "status": "matched"}],
                    "threads": [{"frames": [{
                        "function": format!("{suffix}::Root()"),
                        "symbol_status": "resolved"
                    }]}]
                }
            }
        });
        let result_id: String = sqlx::query_scalar(
            "INSERT INTO crash_processing_results (id, organization_id, project_id, event_id, schema_version, processing_version, result, checksum) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, 1, 2, $4, $5) RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&event_id)
        .bind(result)
        .bind(Sha256::digest(format!("{suffix}-result")).to_vec())
        .fetch_one(pool)
        .await?;
        sqlx::query(
            "INSERT INTO crash_event_search (organization_id, project_id, event_id, result_id, search_text, crash_type, platform, architecture, engine_version, symbolication_state) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, 'crash', 'windows', 'x86_64', '5.8.1', 'readable')",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&event_id)
        .bind(&result_id)
        .bind(format!(
            "{suffix} access violation\u{1f}{suffix} player report\u{1f}{suffix}.exe\u{1f}{suffix}::Root()"
        ))
        .execute(pool)
        .await?;
        sqlx::query("UPDATE crash_events SET current_result_id = $2::uuid WHERE id::text = $1")
            .bind(&event_id)
            .bind(&result_id)
            .execute(pool)
            .await?;
        let fingerprint = fingerprint_character.to_string().repeat(64);
        let variant = if fingerprint_character == 'f' {
            "e".repeat(64)
        } else {
            "f".repeat(64)
        };
        let issue_id: String = sqlx::query_scalar(
            "INSERT INTO issues (id, organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint, title, regression_state, first_seen_at, last_seen_at, event_count, representative_event_id, first_release_id, last_release_id) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'stack', 1, $3, $4, 'new', $5::timestamptz, $5::timestamptz, 1, $6::uuid, $7::uuid, $7::uuid) RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&fingerprint)
        .bind(format!("{suffix} root"))
        .bind(received_at)
        .bind(&event_id)
        .bind(&scope.release)
        .fetch_one(pool)
        .await?;
        sqlx::query(
            "UPDATE crash_events SET issue_id = $2::uuid, release_id = $3::uuid, release_mapping_state = 'matched', grouping_state = 'grouped', fingerprint_algorithm = 'stack', fingerprint_version = 1, fingerprint = $4, variant_fingerprint = $5, grouping_quality = 100, grouped_at = $6::timestamptz WHERE id::text = $1",
        )
        .bind(&event_id)
        .bind(&issue_id)
        .bind(&scope.release)
        .bind(fingerprint)
        .bind(&variant)
        .bind(received_at)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO crash_event_release_candidates (organization_id, project_id, event_id, release_id) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&event_id)
        .bind(&scope.release)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO issue_variants (organization_id, project_id, issue_id, variant_fingerprint, first_seen_at, last_seen_at, event_count, representative_event_id) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::timestamptz, $5::timestamptz, 1, $6::uuid)",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&issue_id)
        .bind(variant)
        .bind(received_at)
        .bind(&event_id)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO issue_releases (organization_id, project_id, issue_id, release_id, first_seen_at, last_seen_at, event_count, representative_event_id) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::timestamptz, $5::timestamptz, 1, $6::uuid)",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&issue_id)
        .bind(&scope.release)
        .bind(received_at)
        .bind(&event_id)
        .execute(pool)
        .await?;
        Ok(SeededIssue { issue_id, event_id })
    }

    fn authorized(request: axum::http::request::Builder) -> axum::http::request::Builder {
        request.header(header::AUTHORIZATION, format!("Bootstrap {SECRET}"))
    }

    fn assert_no_store(response: &axum::response::Response) {
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }

    async fn json_body(response: axum::response::Response) -> Result<Value, Box<dyn Error>> {
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}
