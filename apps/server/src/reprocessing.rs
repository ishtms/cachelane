use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

use crate::project_setup::ServerState;

const DEFAULT_REQUEST_LIMIT: u16 = 100;
const MAX_REQUEST_LIMIT: u16 = 1_000;
const MAX_ACTIVE_MANUAL_REQUESTS: i64 = 5;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const MAX_SYMBOLICATOR_VERSION_BYTES: usize = 64;
const MAX_FAILURE_CODES: usize = 20;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateRequestBody {
    scope: ManualScope,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ManualScope {
    Event { event_id: String },
    Issue { issue_id: String },
    Release { release_id: String },
    Project,
    ParserVersion { parser_version: u32 },
    SymbolicatorVersion { symbolicator_version: String },
    FingerprintVersion { fingerprint_version: u32 },
}

#[derive(Serialize)]
struct RequestView {
    request_id: String,
    source: String,
    scope_kind: String,
    scope_value: Option<String>,
    state: String,
    cursor: Option<String>,
    limit: Option<i32>,
    selection_complete: bool,
    selection_truncated: bool,
    next_cursor: Option<String>,
    selected_count: i64,
    queued_count: i64,
    running_count: i64,
    completed_count: i64,
    failed_count: i64,
    failure_code: Option<String>,
    failure_codes: Vec<FailureCount>,
    failure_codes_truncated: bool,
    created_at: String,
    updated_at: String,
    completed_at: Option<String>,
}

#[derive(Serialize)]
struct FailureCount {
    code: String,
    count: i64,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

struct ProjectScope {
    organization: String,
    project: String,
    requester: String,
}

struct ValidatedRequest {
    scope_kind: &'static str,
    scope_value: Option<String>,
    cursor: Option<String>,
    limit: u16,
    fingerprint: [u8; 32],
}

#[derive(Debug)]
pub(crate) enum ReprocessingError {
    InvalidRequest,
    NotFound,
    Conflict,
    TooManyRequests,
    Internal,
}

impl IntoResponse for ReprocessingError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request is invalid",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "resource was not found"),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "idempotency key was already used for another request",
            ),
            Self::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                "reprocessing_limit_reached",
                "too many reprocessing requests are active",
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

pub(crate) async fn create_request(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    body: Result<Json<CreateRequestBody>, JsonRejection>,
) -> Result<Response, ReprocessingError> {
    authorize(&state, &headers)?;
    if !state.reprocessing_enabled() {
        return Err(ReprocessingError::NotFound);
    }
    let Json(body) = body.map_err(|_| ReprocessingError::InvalidRequest)?;
    let request = validate_request(body)?;
    let idempotency = idempotency_digest(&headers)?;
    let pool = state.control_pool().ok_or(ReprocessingError::Internal)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ReprocessingError::Internal)?;
    let scope = project_scope(&mut transaction, &project_id).await?;

    if let Some(row) = sqlx::query(
        "SELECT id::text AS request_id, scope_fingerprint FROM crash_reprocessing_requests WHERE organization_id::text = $1 AND project_id::text = $2 AND source = 'manual' AND idempotency_digest = $3",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(idempotency.as_slice())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ReprocessingError::Internal)?
    {
        let stored: Vec<u8> = row.get("scope_fingerprint");
        if stored.as_slice() != request.fingerprint {
            return Err(ReprocessingError::Conflict);
        }
        let request_id: String = row.get("request_id");
        let view = load_request(&mut transaction, &scope, &request_id).await?;
        transaction
            .commit()
            .await
            .map_err(|_| ReprocessingError::Internal)?;
        return Ok(no_store(StatusCode::ACCEPTED, &view));
    }

    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM crash_reprocessing_requests WHERE organization_id::text = $1 AND project_id::text = $2 AND source = 'manual' AND state IN ('pending', 'scheduling', 'running')",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ReprocessingError::Internal)?;
    if active >= MAX_ACTIVE_MANUAL_REQUESTS {
        return Err(ReprocessingError::TooManyRequests);
    }

    if let Some(cursor) = request.cursor.as_deref() {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM crash_events WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3)",
        )
        .bind(cursor)
        .bind(&scope.organization)
        .bind(&scope.project)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ReprocessingError::Internal)?;
        if !exists {
            return Err(ReprocessingError::NotFound);
        }
    }

    let request_id: String = sqlx::query_scalar(
        "INSERT INTO crash_reprocessing_requests (organization_id, project_id, source, scope_kind, scope_value, scope_fingerprint, idempotency_digest, requested_by_user_id, request_limit, input_cursor_event_id) VALUES ($1::uuid, $2::uuid, 'manual', $3, $4, $5, $6, $7::uuid, $8, $9::uuid) RETURNING id::text",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(request.scope_kind)
    .bind(&request.scope_value)
    .bind(request.fingerprint.as_slice())
    .bind(idempotency.as_slice())
    .bind(&scope.requester)
    .bind(i32::from(request.limit))
    .bind(&request.cursor)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ReprocessingError::Internal)?;
    let view = load_request(&mut transaction, &scope, &request_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ReprocessingError::Internal)?;
    Ok(no_store(StatusCode::ACCEPTED, &view))
}

pub(crate) async fn get_request(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((project_id, request_id)): Path<(String, String)>,
) -> Result<Response, ReprocessingError> {
    authorize(&state, &headers)?;
    if !valid_uuid(&request_id) {
        return Err(ReprocessingError::NotFound);
    }
    let pool = state.control_pool().ok_or(ReprocessingError::Internal)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ReprocessingError::Internal)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(|_| ReprocessingError::Internal)?;
    let scope = project_scope_read(&mut transaction, &project_id).await?;
    let view = load_request(&mut transaction, &scope, &request_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ReprocessingError::Internal)?;
    Ok(no_store(StatusCode::OK, &view))
}

pub(crate) async fn enqueue_artifact_request(
    connection: &mut PgConnection,
    organization_id: &str,
    project_id: &str,
    manifest_id: &str,
) -> Result<(), sqlx::Error> {
    let checksum: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT m.checksum FROM release_manifest_artifacts m JOIN releases r ON r.id = m.release_id AND r.organization_id = m.organization_id AND r.project_id = m.project_id WHERE m.id::text = $1 AND m.organization_id::text = $2 AND m.project_id::text = $3 AND m.state = 'available' FOR NO KEY UPDATE OF r",
    )
    .bind(manifest_id)
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(checksum) = checksum else {
        return Ok(());
    };
    let mut digest = Sha256::new();
    digest.update(b"artifact-v1\0");
    digest.update(manifest_id.as_bytes());
    digest.update(b"\0");
    digest.update(checksum);
    let digest: [u8; 32] = digest.finalize().into();
    sqlx::query(
        "INSERT INTO crash_reprocessing_requests (organization_id, project_id, source, scope_kind, scope_value, scope_fingerprint, idempotency_digest, selection_before) SELECT m.organization_id, m.project_id, 'automatic', 'artifact', m.id::text, $4, $4, clock_timestamp() FROM release_manifest_artifacts m WHERE m.id::text = $1 AND m.organization_id::text = $2 AND m.project_id::text = $3 AND m.state = 'available' ON CONFLICT (organization_id, project_id, source, idempotency_digest) DO NOTHING",
    )
    .bind(manifest_id)
    .bind(organization_id)
    .bind(project_id)
    .bind(digest.as_slice())
    .execute(connection)
    .await?;
    Ok(())
}

pub(crate) async fn enqueue_waiter_catchup_requests(
    connection: &mut PgConnection,
    organization_id: &str,
    project_id: &str,
    event_id: &str,
    result_id: &str,
) -> Result<(), sqlx::Error> {
    let release_id: Option<String> = sqlx::query_scalar(
        "SELECT r.id::text FROM crash_symbol_waiters w JOIN releases r ON r.id = w.release_id AND r.organization_id = w.organization_id AND r.project_id = w.project_id WHERE w.organization_id::text = $1 AND w.project_id::text = $2 AND w.event_id::text = $3 AND w.result_id::text = $4 ORDER BY r.id LIMIT 1 FOR NO KEY UPDATE OF r",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(event_id)
    .bind(result_id)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(release_id) = release_id else {
        return Ok(());
    };
    let manifest_id: Option<String> = sqlx::query_scalar(
        "SELECT m.id::text FROM crash_symbol_waiters w JOIN release_manifest_artifacts m ON m.organization_id = w.organization_id AND m.project_id = w.project_id AND m.release_id = w.release_id WHERE w.organization_id::text = $1 AND w.project_id::text = $2 AND w.event_id::text = $3 AND w.result_id::text = $4 AND w.release_id::text = $5 AND m.state = 'available' AND ((m.artifact_type = 'pdb' AND w.required_artifact = 'pdb' AND w.architecture = m.architecture AND w.debug_id = m.debug_id AND w.code_id = '') OR (m.artifact_type IN ('pe_executable', 'pe_dynamic_library') AND w.required_artifact = 'pe' AND w.module_name = lower(m.module_name) AND w.architecture = m.architecture AND w.debug_id = m.debug_id AND w.code_id = m.code_id)) ORDER BY m.id LIMIT 1",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(event_id)
    .bind(result_id)
    .bind(&release_id)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(manifest_id) = manifest_id else {
        return Ok(());
    };
    let digest: [u8; 32] = Sha256::digest(format!("waiter-v1:{manifest_id}:{result_id}")).into();
    sqlx::query(
        "INSERT INTO crash_reprocessing_requests (organization_id, project_id, source, scope_kind, scope_value, scope_fingerprint, idempotency_digest, selection_before) SELECT m.organization_id, m.project_id, 'automatic', 'artifact', m.id::text, $4, $4, clock_timestamp() FROM release_manifest_artifacts m WHERE m.id::text = $1 AND m.organization_id::text = $2 AND m.project_id::text = $3 AND m.state = 'available' ON CONFLICT (organization_id, project_id, source, idempotency_digest) DO NOTHING",
    )
    .bind(&manifest_id)
    .bind(organization_id)
    .bind(project_id)
    .bind(digest.as_slice())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

fn validate_request(body: CreateRequestBody) -> Result<ValidatedRequest, ReprocessingError> {
    let (scope_kind, scope_value, event_scope) = match &body.scope {
        ManualScope::Event { event_id } => {
            require_uuid(event_id)?;
            ("event", Some(event_id.to_ascii_lowercase()), true)
        }
        ManualScope::Issue { issue_id } => {
            require_uuid(issue_id)?;
            ("issue", Some(issue_id.to_ascii_lowercase()), false)
        }
        ManualScope::Release { release_id } => {
            require_uuid(release_id)?;
            ("release", Some(release_id.to_ascii_lowercase()), false)
        }
        ManualScope::Project => ("project", None, false),
        ManualScope::ParserVersion { parser_version } => {
            require_version(*parser_version)?;
            ("parser_version", Some(parser_version.to_string()), false)
        }
        ManualScope::SymbolicatorVersion {
            symbolicator_version,
        } => {
            if !valid_symbolicator_version(symbolicator_version) {
                return Err(ReprocessingError::InvalidRequest);
            }
            (
                "symbolicator_version",
                Some(symbolicator_version.clone()),
                false,
            )
        }
        ManualScope::FingerprintVersion {
            fingerprint_version,
        } => {
            require_version(*fingerprint_version)?;
            (
                "fingerprint_version",
                Some(fingerprint_version.to_string()),
                false,
            )
        }
    };
    let cursor = body
        .cursor
        .map(|value| {
            require_uuid(&value)?;
            Ok::<_, ReprocessingError>(value.to_ascii_lowercase())
        })
        .transpose()?;
    let limit = if event_scope {
        if cursor.is_some() || body.limit.is_some_and(|value| value != 1) {
            return Err(ReprocessingError::InvalidRequest);
        }
        1
    } else {
        body.limit.unwrap_or(DEFAULT_REQUEST_LIMIT)
    };
    if limit == 0 || limit > MAX_REQUEST_LIMIT {
        return Err(ReprocessingError::InvalidRequest);
    }
    let canonical = serde_json::to_vec(&(scope_kind, &scope_value, &cursor, limit))
        .map_err(|_| ReprocessingError::Internal)?;
    Ok(ValidatedRequest {
        scope_kind,
        scope_value,
        cursor,
        limit,
        fingerprint: Sha256::digest(canonical).into(),
    })
}

fn idempotency_digest(headers: &HeaderMap) -> Result<[u8; 32], ReprocessingError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_IDEMPOTENCY_KEY_BYTES
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .ok_or(ReprocessingError::InvalidRequest)?;
    Ok(Sha256::digest(key.as_bytes()).into())
}

async fn project_scope(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    project_id: &str,
) -> Result<ProjectScope, ReprocessingError> {
    if !valid_uuid(project_id) {
        return Err(ReprocessingError::NotFound);
    }
    let row = sqlx::query(
        "SELECT p.organization_id::text AS organization_id, p.id::text AS project_id, u.id::text AS user_id FROM projects p JOIN organization_memberships m ON m.organization_id = p.organization_id AND m.role = 'owner' JOIN users u ON u.id = m.user_id WHERE u.bootstrap_subject = 'local-bootstrap' AND p.id::text = $1 FOR UPDATE OF p",
    )
    .bind(project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ReprocessingError::Internal)?
    .ok_or(ReprocessingError::NotFound)?;
    Ok(ProjectScope {
        organization: row.get("organization_id"),
        project: row.get("project_id"),
        requester: row.get("user_id"),
    })
}

async fn project_scope_read(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    project_id: &str,
) -> Result<ProjectScope, ReprocessingError> {
    if !valid_uuid(project_id) {
        return Err(ReprocessingError::NotFound);
    }
    let row = sqlx::query(
        "SELECT p.organization_id::text AS organization_id, p.id::text AS project_id, u.id::text AS user_id FROM projects p JOIN organization_memberships m ON m.organization_id = p.organization_id AND m.role = 'owner' JOIN users u ON u.id = m.user_id WHERE u.bootstrap_subject = 'local-bootstrap' AND p.id::text = $1",
    )
    .bind(project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ReprocessingError::Internal)?
    .ok_or(ReprocessingError::NotFound)?;
    Ok(ProjectScope {
        organization: row.get("organization_id"),
        project: row.get("project_id"),
        requester: row.get("user_id"),
    })
}

async fn load_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &ProjectScope,
    request_id: &str,
) -> Result<RequestView, ReprocessingError> {
    let row = sqlx::query(
        "SELECT id::text AS request_id, source, scope_kind, scope_value, state, input_cursor_event_id::text AS cursor, request_limit, selection_complete, selection_truncated, next_cursor_event_id::text AS next_cursor, selected_count, queued_count, running_count, completed_count, failed_count, failure_code, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at, CASE WHEN completed_at IS NULL THEN NULL ELSE to_char(completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS completed_at FROM crash_reprocessing_requests WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3",
    )
    .bind(request_id)
    .bind(&scope.organization)
    .bind(&scope.project)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ReprocessingError::Internal)?
    .ok_or(ReprocessingError::NotFound)?;
    let mut failures = sqlx::query(
        "SELECT failure_code AS code, count(*) AS count FROM crash_reprocessing_request_events WHERE request_id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND failure_code IS NOT NULL GROUP BY failure_code ORDER BY count(*) DESC, failure_code LIMIT $4",
    )
    .bind(request_id)
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(i64::try_from(MAX_FAILURE_CODES + 1).map_err(|_| ReprocessingError::Internal)?)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ReprocessingError::Internal)?;
    let failure_codes_truncated = failures.len() > MAX_FAILURE_CODES;
    failures.truncate(MAX_FAILURE_CODES);
    Ok(RequestView {
        request_id: row.get("request_id"),
        source: row.get("source"),
        scope_kind: row.get("scope_kind"),
        scope_value: row.get("scope_value"),
        state: row.get("state"),
        cursor: row.get("cursor"),
        limit: row.get("request_limit"),
        selection_complete: row.get("selection_complete"),
        selection_truncated: row.get("selection_truncated"),
        next_cursor: row.get("next_cursor"),
        selected_count: row.get("selected_count"),
        queued_count: row.get("queued_count"),
        running_count: row.get("running_count"),
        completed_count: row.get("completed_count"),
        failed_count: row.get("failed_count"),
        failure_code: row.get("failure_code"),
        failure_codes: failures
            .iter()
            .map(|failure| FailureCount {
                code: failure.get("code"),
                count: failure.get("count"),
            })
            .collect(),
        failure_codes_truncated,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        completed_at: row.get("completed_at"),
    })
}

fn authorize(state: &ServerState, headers: &HeaderMap) -> Result<(), ReprocessingError> {
    if state.authorize_control(headers) {
        Ok(())
    } else {
        Err(ReprocessingError::NotFound)
    }
}

fn require_uuid(value: &str) -> Result<(), ReprocessingError> {
    if valid_uuid(value) {
        Ok(())
    } else {
        Err(ReprocessingError::InvalidRequest)
    }
}

fn require_version(value: u32) -> Result<(), ReprocessingError> {
    if value > 0 && i32::try_from(value).is_ok() {
        Ok(())
    } else {
        Err(ReprocessingError::InvalidRequest)
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

fn valid_symbolicator_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SYMBOLICATOR_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
}

fn no_store(status: StatusCode, value: &impl Serialize) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::{env, time::Duration};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use sqlx::{PgPool, Row, postgres::PgPoolOptions};
    use tokio::{sync::oneshot, time::timeout};
    use tower::ServiceExt;

    use super::{
        CreateRequestBody, ManualScope, enqueue_artifact_request, enqueue_waiter_catchup_requests,
        valid_symbolicator_version, validate_request,
    };
    use crate::project_setup::{DATABASE_TEST_LOCK, ServerState, migrate, router};

    const TEST_SECRET: &str = "reprocessing-secret-000000000000";

    #[test]
    fn manual_request_bounds_are_strict() {
        let event = CreateRequestBody {
            scope: ManualScope::Event {
                event_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            },
            cursor: None,
            limit: Some(1),
        };
        let validated = validate_request(event)
            .unwrap_or_else(|error| panic!("event request must be valid: {error:?}"));
        assert_eq!(validated.scope_kind, "event");
        assert_eq!(validated.limit, 1);

        let invalid = CreateRequestBody {
            scope: ManualScope::Project,
            cursor: None,
            limit: Some(1_001),
        };
        assert!(validate_request(invalid).is_err());
        assert!(valid_symbolicator_version("0.1.0+worker"));
        assert!(!valid_symbolicator_version("0.1.0 worker"));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn manual_request_api_is_idempotent_bounded_and_tenant_scoped_when_configured() {
        let Ok(database_url) = env::var("FAULTLANE_TEST_DATABASE_URL") else {
            return;
        };
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let project_id = insert_project(&pool, "local-bootstrap", "manual", "manual").await;
        let other_project = insert_project(&pool, "other-bootstrap", "other", "other").await;
        let state = ServerState::issue_test(pool, TEST_SECRET);
        let app = router("api", state);
        let body = json!({"scope": {"kind": "project"}, "limit": 25});
        let first = app
            .clone()
            .oneshot(authorized_post(&project_id, "manual-1", &body))
            .await
            .unwrap_or_else(|error| panic!("first request must run: {error}"));
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        assert_eq!(first.headers()["cache-control"], "no-store");
        let first = json_body(first).await;
        let request_id = first["request_id"]
            .as_str()
            .unwrap_or_else(|| panic!("request ID must exist"))
            .to_owned();
        assert_eq!(first["state"], "pending");
        assert_eq!(first["limit"], 25);

        let repeated = app
            .clone()
            .oneshot(authorized_post(&project_id, "manual-1", &body))
            .await
            .unwrap_or_else(|error| panic!("repeated request must run: {error}"));
        assert_eq!(repeated.status(), StatusCode::ACCEPTED);
        assert_eq!(json_body(repeated).await["request_id"], request_id);
        let conflict = app
            .clone()
            .oneshot(authorized_post(
                &project_id,
                "manual-1",
                &json!({"scope": {"kind": "parser_version", "parser_version": 1}}),
            ))
            .await
            .unwrap_or_else(|error| panic!("conflicting request must run: {error}"));
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        let fetched = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/projects/{project_id}/reprocessing/{request_id}"
                    ))
                    .header("authorization", format!("Bootstrap {TEST_SECRET}"))
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("GET request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("GET request must run: {error}"));
        assert_eq!(fetched.status(), StatusCode::OK);
        assert_eq!(fetched.headers()["cache-control"], "no-store");
        assert_eq!(json_body(fetched).await["request_id"], request_id);

        let cross_tenant = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/projects/{other_project}/reprocessing/{request_id}"
                    ))
                    .header("authorization", format!("Bootstrap {TEST_SECRET}"))
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("cross-tenant request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("cross-tenant request must run: {error}"));
        assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);
        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/projects/{project_id}/reprocessing/{request_id}"
                    ))
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("unauthorized request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("unauthorized request must run: {error}"));
        assert_eq!(unauthorized.status(), StatusCode::NOT_FOUND);

        for index in 2..=5 {
            let response = app
                .clone()
                .oneshot(authorized_post(
                    &project_id,
                    &format!("manual-{index}"),
                    &body,
                ))
                .await
                .unwrap_or_else(|error| panic!("bounded request must run: {error}"));
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }
        let limited = app
            .oneshot(authorized_post(&project_id, "manual-6", &body))
            .await
            .unwrap_or_else(|error| panic!("limited request must run: {error}"));
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn waiter_catchup_serializes_with_artifact_publication_when_configured() {
        let Ok(database_url) = env::var("FAULTLANE_TEST_DATABASE_URL") else {
            return;
        };
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let project = insert_project(&pool, "local-bootstrap", "race", "race").await;
        let scope = sqlx::query(
            "SELECT p.organization_id::text AS organization_id, m.user_id::text AS user_id FROM projects p JOIN organization_memberships m ON m.organization_id = p.organization_id WHERE p.id::text = $1 AND m.role = 'owner'",
        )
        .bind(&project)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("test scope must load: {error}"));
        let organization: String = scope.get("organization_id");
        let user: String = scope.get("user_id");
        let release: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration) VALUES ($1::uuid, $2::uuid, '9.9.9', 'windows', 'x86_64', 'Shipping') RETURNING id::text",
        )
        .bind(&organization)
        .bind(&project)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("test release must insert: {error}"));
        let ingest_key: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, '00000001') RETURNING id::text",
        )
        .bind(&organization)
        .bind(&project)
        .bind(Sha256::digest(b"reprocessing-race-ingest").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("test ingest key must insert: {error}"));
        let raw: String = sqlx::query_scalar(
            "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'reprocessing/race', $3, 1, 'application/octet-stream') RETURNING id::text",
        )
        .bind(&organization)
        .bind(&project)
        .bind(Sha256::digest(b"reprocessing-race-raw").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("test raw object must insert: {error}"));
        let event: String = sqlx::query_scalar(
            "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, environment, processing_state, state_reason, release_id, release_mapping_state, grouping_state) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'production', 'awaiting_symbols', 'matching_symbols_missing', $5::uuid, 'matched', 'disabled') RETURNING id::text",
        )
        .bind(&organization)
        .bind(&project)
        .bind(&ingest_key)
        .bind(&raw)
        .bind(&release)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("test event must insert: {error}"));
        let result: String = sqlx::query_scalar(
            "INSERT INTO crash_processing_results (id, organization_id, project_id, event_id, schema_version, processing_version, result, checksum) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, 1, 2, $4, $5) RETURNING id::text",
        )
        .bind(&organization)
        .bind(&project)
        .bind(&event)
        .bind(json!({"fixture": "race"}))
        .bind(Sha256::digest(b"reprocessing-race-result").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("test result must insert: {error}"));
        sqlx::query("UPDATE crash_events SET current_result_id = $2::uuid WHERE id::text = $1")
            .bind(&event)
            .bind(&result)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test event result must update: {error}"));
        let token: String = sqlx::query_scalar(
            "INSERT INTO artifact_upload_tokens (organization_id, project_id, created_by_user_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, '00000002') RETURNING id::text",
        )
        .bind(&organization)
        .bind(&project)
        .bind(&user)
        .bind(Sha256::digest(b"reprocessing-race-upload").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("test upload token must insert: {error}"));
        let manifest: String = sqlx::query_scalar(
            "INSERT INTO release_manifest_artifacts (release_id, organization_id, project_id, uploaded_by_user_id, upload_token_id, checksum, byte_size, artifact_type, module_name, architecture, debug_id, source_path, cli_version) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, 1, 'pdb', 'game.pdb', 'x86_64', 'DEBUG-RACE', 'game.pdb', '0.1.0') RETURNING id::text",
        )
        .bind(&release)
        .bind(&organization)
        .bind(&project)
        .bind(&user)
        .bind(&token)
        .bind(Sha256::digest(b"reprocessing-race-pdb").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("test manifest must insert: {error}"));

        let mut artifact_transaction = pool
            .begin()
            .await
            .unwrap_or_else(|error| panic!("artifact transaction must begin: {error}"));
        sqlx::query(
            "UPDATE release_manifest_artifacts SET state = 'available', uploaded_at = now() WHERE id::text = $1",
        )
        .bind(&manifest)
        .execute(&mut *artifact_transaction)
        .await
        .unwrap_or_else(|error| panic!("artifact must publish: {error}"));
        enqueue_artifact_request(
            &mut artifact_transaction,
            &organization,
            &project,
            &manifest,
        )
        .await
        .unwrap_or_else(|error| panic!("artifact request must enqueue: {error}"));

        let waiter_pool = pool.clone();
        let waiter_organization = organization.clone();
        let waiter_project = project.clone();
        let waiter_event = event.clone();
        let waiter_result = result.clone();
        let waiter_release = release.clone();
        let (inserted, inserted_rx) = oneshot::channel();
        let mut waiter_task = tokio::spawn(async move {
            let mut transaction = waiter_pool
                .begin()
                .await
                .unwrap_or_else(|error| panic!("waiter transaction must begin: {error}"));
            sqlx::query(
                "INSERT INTO crash_symbol_waiters (organization_id, project_id, event_id, result_id, release_id, required_artifact, module_name, architecture, debug_id) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 'pdb', 'game.exe', 'x86_64', 'DEBUG-RACE')",
            )
            .bind(&waiter_organization)
            .bind(&waiter_project)
            .bind(&waiter_event)
            .bind(&waiter_result)
            .bind(&waiter_release)
            .execute(&mut *transaction)
            .await
            .unwrap_or_else(|error| panic!("waiter must insert: {error}"));
            inserted
                .send(())
                .unwrap_or_else(|()| panic!("waiter insertion must signal"));
            enqueue_waiter_catchup_requests(
                &mut transaction,
                &waiter_organization,
                &waiter_project,
                &waiter_event,
                &waiter_result,
            )
            .await
            .unwrap_or_else(|error| panic!("catch-up request must enqueue: {error}"));
            transaction
                .commit()
                .await
                .unwrap_or_else(|error| panic!("waiter transaction must commit: {error}"));
        });
        inserted_rx
            .await
            .unwrap_or_else(|error| panic!("waiter insertion must be observed: {error}"));
        assert!(
            timeout(Duration::from_millis(100), &mut waiter_task)
                .await
                .is_err()
        );
        artifact_transaction
            .commit()
            .await
            .unwrap_or_else(|error| panic!("artifact transaction must commit: {error}"));
        timeout(Duration::from_secs(5), waiter_task)
            .await
            .unwrap_or_else(|error| panic!("catch-up must finish after publication: {error}"))
            .unwrap_or_else(|error| panic!("catch-up task must succeed: {error}"));
        let requests: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_reprocessing_requests WHERE project_id::text = $1 AND scope_value = $2",
        )
        .bind(&project)
        .bind(&manifest)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("race requests must load: {error}"));
        assert_eq!(requests, 2);

        sqlx::query("DELETE FROM crash_symbol_waiters")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("race waiters must reset: {error}"));
        sqlx::query("DELETE FROM crash_reprocessing_requests")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("race requests must reset: {error}"));
        sqlx::query(
            "UPDATE release_manifest_artifacts SET state = 'missing', uploaded_at = NULL WHERE id::text = $1",
        )
        .bind(&manifest)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("artifact state must reset: {error}"));

        let mut delayed_artifact = pool
            .begin()
            .await
            .unwrap_or_else(|error| panic!("delayed artifact transaction must begin: {error}"));
        sqlx::query(
            "UPDATE release_manifest_artifacts SET state = 'available', uploaded_at = now() WHERE id::text = $1",
        )
        .bind(&manifest)
        .execute(&mut *delayed_artifact)
        .await
        .unwrap_or_else(|error| panic!("delayed artifact must publish: {error}"));
        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut early_waiter = pool
            .begin()
            .await
            .unwrap_or_else(|error| panic!("early waiter transaction must begin: {error}"));
        sqlx::query(
            "INSERT INTO crash_symbol_waiters (organization_id, project_id, event_id, result_id, release_id, required_artifact, module_name, architecture, debug_id) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 'pdb', 'game.exe', 'x86_64', 'DEBUG-RACE')",
        )
        .bind(&organization)
        .bind(&project)
        .bind(&event)
        .bind(&result)
        .bind(&release)
        .execute(&mut *early_waiter)
        .await
        .unwrap_or_else(|error| panic!("early waiter must insert: {error}"));
        enqueue_waiter_catchup_requests(
            &mut early_waiter,
            &organization,
            &project,
            &event,
            &result,
        )
        .await
        .unwrap_or_else(|error| panic!("early catch-up must inspect publication: {error}"));
        early_waiter
            .commit()
            .await
            .unwrap_or_else(|error| panic!("early waiter must commit: {error}"));
        let catchups_before_publication: i64 =
            sqlx::query_scalar("SELECT count(*) FROM crash_reprocessing_requests")
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("early catch-up count must load: {error}"));
        assert_eq!(catchups_before_publication, 0);

        enqueue_artifact_request(&mut delayed_artifact, &organization, &project, &manifest)
            .await
            .unwrap_or_else(|error| panic!("delayed artifact request must enqueue: {error}"));
        delayed_artifact
            .commit()
            .await
            .unwrap_or_else(|error| panic!("delayed artifact must commit: {error}"));
        let waiter_in_snapshot: bool = sqlx::query_scalar(
            "SELECT w.created_at <= r.selection_before FROM crash_reprocessing_requests r JOIN crash_symbol_waiters w ON w.organization_id = r.organization_id AND w.project_id = r.project_id WHERE r.project_id::text = $1 AND r.scope_value = $2 AND w.event_id::text = $3",
        )
        .bind(&project)
        .bind(&manifest)
        .bind(&event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("delayed snapshot must load: {error}"));
        assert!(waiter_in_snapshot);

        let replacement_checksum = Sha256::digest(b"reprocessing-race-pdb-replacement").to_vec();
        let mut replacement = pool
            .begin()
            .await
            .unwrap_or_else(|error| panic!("replacement transaction must begin: {error}"));
        sqlx::query(
            "UPDATE release_manifest_artifacts SET checksum = $2, state = 'available', uploaded_at = now() WHERE id::text = $1",
        )
        .bind(&manifest)
        .bind(replacement_checksum)
        .execute(&mut *replacement)
        .await
        .unwrap_or_else(|error| panic!("replacement artifact must publish: {error}"));
        enqueue_artifact_request(&mut replacement, &organization, &project, &manifest)
            .await
            .unwrap_or_else(|error| panic!("replacement request must enqueue: {error}"));
        enqueue_artifact_request(&mut replacement, &organization, &project, &manifest)
            .await
            .unwrap_or_else(|error| panic!("replacement retry must deduplicate: {error}"));
        replacement
            .commit()
            .await
            .unwrap_or_else(|error| panic!("replacement artifact must commit: {error}"));
        let replacement_requests: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_reprocessing_requests WHERE project_id::text = $1 AND scope_value = $2",
        )
        .bind(&project)
        .bind(&manifest)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("replacement requests must load: {error}"));
        assert_eq!(replacement_requests, 2);
    }

    async fn insert_project(
        pool: &PgPool,
        subject: &str,
        organization_slug: &str,
        project_slug: &str,
    ) -> String {
        let user_id: String = sqlx::query_scalar(
            "INSERT INTO users (bootstrap_subject, email) VALUES ($1, $2) RETURNING id::text",
        )
        .bind(subject)
        .bind(format!("{subject}@example.com"))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("user must insert: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
        )
        .bind(organization_slug)
        .bind(organization_slug)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("organization must insert: {error}"));
        sqlx::query(
            "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')",
        )
        .bind(&organization_id)
        .bind(&user_id)
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("membership must insert: {error}"));
        sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, $2, $3) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(project_slug)
        .bind(project_slug)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("project must insert: {error}"))
    }

    fn authorized_post(project_id: &str, key: &str, body: &Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(format!("/api/v1/projects/{project_id}/reprocessing"))
            .header("authorization", format!("Bootstrap {TEST_SECRET}"))
            .header("idempotency-key", key)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap_or_else(|error| panic!("POST request must build: {error}"))
    }

    async fn json_body(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap_or_else(|error| panic!("response body must read: {error}"));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("response body must parse: {error}"))
    }
}
