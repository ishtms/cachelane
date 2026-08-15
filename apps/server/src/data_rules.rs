use std::collections::BTreeSet;

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

use crate::project_setup::ServerState;

const MAX_PATTERNS: usize = 32;
const MAX_PATTERN_BYTES: usize = 256;
const MAX_PATTERN_BYTES_TOTAL: usize = 4_096;
const MAX_INDEXED_KEYS: usize = 32;
const MAX_KEY_BYTES: usize = 128;
const MAX_FACET_VALUE_CHARS: usize = 512;
const REDACTED: &str = "[REDACTED]";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataRules {
    pub(crate) version: i64,
    patterns: Vec<String>,
    indexed_game_data_keys: Vec<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ContextFacet {
    pub(crate) key: String,
    pub(crate) value: String,
    pub(crate) value_truncated: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateDataRules {
    redaction_patterns: Vec<String>,
    indexed_game_data_keys: Vec<String>,
}

#[derive(Serialize)]
struct DataRulesView {
    version: i64,
    redaction_patterns: Vec<String>,
    indexed_game_data_keys: Vec<String>,
    can_edit: bool,
    reprocessing_request_id: Option<String>,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
pub(crate) enum DataRulesError {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Unavailable,
    Internal,
}

impl IntoResponse for DataRulesError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request is invalid",
            ),
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

pub(crate) async fn get_data_rules(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Response, DataRulesError> {
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ReadProject,
    )
    .await?;
    let pool = state.control_pool().ok_or(DataRulesError::Internal)?;
    let row = sqlx::query(
        "SELECT r.version, r.redaction_patterns, r.indexed_game_data_keys FROM projects p LEFT JOIN project_data_rules r ON r.organization_id = p.organization_id AND r.project_id = p.id WHERE p.organization_id::text = $1 AND p.id::text = $2",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| DataRulesError::Internal)?
    .ok_or(DataRulesError::NotFound)?;
    let rules = rules_from_row(&row).map_err(|()| DataRulesError::Internal)?;
    Ok(no_store(
        StatusCode::OK,
        &view(
            rules,
            actor.allows(crate::auth::Permission::ManageDataRules),
            None,
        ),
    ))
}

pub(crate) async fn update_data_rules(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    body: Result<Json<UpdateDataRules>, JsonRejection>,
) -> Result<Response, DataRulesError> {
    if std::env::var("FAULTLANE_DATA_RULE_EDITS_ENABLED")
        .is_ok_and(|value| value.eq_ignore_ascii_case("false"))
    {
        return Err(DataRulesError::NotFound);
    }
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ManageDataRules,
    )
    .await?;
    let Json(body) = body.map_err(|_| DataRulesError::InvalidRequest)?;
    let requested = validate_rules(body.redaction_patterns, body.indexed_game_data_keys)?;
    let pool = state.control_pool().ok_or(DataRulesError::Internal)?;
    let mut transaction = pool.begin().await.map_err(|_| DataRulesError::Internal)?;
    let project: Option<String> = sqlx::query_scalar(
        "SELECT id::text FROM projects WHERE organization_id::text = $1 AND id::text = $2 FOR UPDATE",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| DataRulesError::Internal)?;
    if project.is_none() {
        return Err(DataRulesError::NotFound);
    }
    let current = sqlx::query(
        "SELECT version, redaction_patterns, indexed_game_data_keys FROM project_data_rules WHERE organization_id::text = $1 AND project_id::text = $2",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| DataRulesError::Internal)?
    .map_or_else(|| Ok(DataRules::empty()), |row| rules_from_row(&row))
    .map_err(|()| DataRulesError::Internal)?;
    if current.patterns == requested.patterns
        && current.indexed_game_data_keys == requested.indexed_game_data_keys
    {
        transaction
            .commit()
            .await
            .map_err(|_| DataRulesError::Internal)?;
        return Ok(no_store(StatusCode::OK, &view(current, true, None)));
    }
    let version = current
        .version
        .checked_add(1)
        .ok_or(DataRulesError::Internal)?;
    sqlx::query(
        "INSERT INTO project_data_rules (organization_id, project_id, version, redaction_patterns, indexed_game_data_keys, updated_by_user_id) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid) ON CONFLICT (organization_id, project_id) DO UPDATE SET version = EXCLUDED.version, redaction_patterns = EXCLUDED.redaction_patterns, indexed_game_data_keys = EXCLUDED.indexed_game_data_keys, updated_by_user_id = EXCLUDED.updated_by_user_id, updated_at = now()",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .bind(version)
    .bind(&requested.patterns)
    .bind(&requested.indexed_game_data_keys)
    .bind(&actor.actor.user_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DataRulesError::Internal)?;
    let digest = rules_request_digest(&actor.project_id, version);
    let request_id: String = sqlx::query_scalar(
        "INSERT INTO crash_reprocessing_requests (organization_id, project_id, source, scope_kind, scope_value, scope_fingerprint, idempotency_digest, selection_before) VALUES ($1::uuid, $2::uuid, 'automatic', 'data_rules_version', $3, $4, $4, clock_timestamp()) ON CONFLICT (organization_id, project_id, source, idempotency_digest) DO UPDATE SET idempotency_digest = EXCLUDED.idempotency_digest RETURNING id::text",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .bind(version.to_string())
    .bind(digest.as_slice())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| DataRulesError::Internal)?;
    sqlx::query(
        "INSERT INTO audit_log (organization_id, actor_user_id, action, target_type, target_id, result) VALUES ($1::uuid, $2::uuid, 'project_data_rules.updated', 'project', $3, 'succeeded')",
    )
    .bind(&actor.organization_id)
    .bind(&actor.actor.user_id)
    .bind(&actor.project_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DataRulesError::Internal)?;
    transaction
        .commit()
        .await
        .map_err(|_| DataRulesError::Internal)?;
    Ok(no_store(
        StatusCode::ACCEPTED,
        &view(
            DataRules {
                version,
                ..requested
            },
            true,
            Some(request_id),
        ),
    ))
}

pub(crate) async fn lock_for_publication(
    connection: &mut PgConnection,
    organization_id: &str,
    project_id: &str,
) -> Result<DataRules, DataRulesError> {
    let row = sqlx::query(
        "SELECT r.version, r.redaction_patterns, r.indexed_game_data_keys FROM projects p LEFT JOIN project_data_rules r ON r.organization_id = p.organization_id AND r.project_id = p.id WHERE p.organization_id::text = $1 AND p.id::text = $2 FOR UPDATE OF p",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(connection)
    .await
    .map_err(|_| DataRulesError::Unavailable)?
    .ok_or(DataRulesError::NotFound)?;
    rules_from_row(&row).map_err(|()| DataRulesError::Internal)
}

pub(crate) fn redact_and_index(result: &mut Value, rules: &DataRules) -> Vec<ContextFacet> {
    if !rules.patterns.is_empty() {
        redact_crash_context(result, &rules.patterns);
        redact_log(result, &rules.patterns);
        redact_symbolication(result, &rules.patterns);
    }
    context_facets(result, &rules.indexed_game_data_keys)
}

impl DataRules {
    fn empty() -> Self {
        Self {
            version: 0,
            patterns: Vec::new(),
            indexed_game_data_keys: Vec::new(),
        }
    }
}

fn rules_from_row(row: &sqlx::postgres::PgRow) -> Result<DataRules, ()> {
    let version = row.get::<Option<i64>, _>("version").unwrap_or_default();
    let patterns = row
        .get::<Option<Vec<String>>, _>("redaction_patterns")
        .unwrap_or_default();
    let keys = row
        .get::<Option<Vec<String>>, _>("indexed_game_data_keys")
        .unwrap_or_default();
    let mut rules = validate_rules(patterns, keys).map_err(|_| ())?;
    rules.version = version;
    Ok(rules)
}

fn validate_rules(
    mut patterns: Vec<String>,
    mut keys: Vec<String>,
) -> Result<DataRules, DataRulesError> {
    if patterns.len() > MAX_PATTERNS
        || keys.len() > MAX_INDEXED_KEYS
        || patterns.iter().any(|pattern| {
            pattern.is_empty()
                || pattern.trim().is_empty()
                || REDACTED.contains(pattern)
                || pattern.len() > MAX_PATTERN_BYTES
                || pattern.chars().any(char::is_control)
        })
        || patterns.iter().map(String::len).sum::<usize>() > MAX_PATTERN_BYTES_TOTAL
        || keys.iter().any(|key| {
            key.is_empty()
                || key.len() > MAX_KEY_BYTES
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    {
        return Err(DataRulesError::InvalidRequest);
    }
    patterns.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    patterns.dedup();
    keys.sort();
    keys.dedup();
    Ok(DataRules {
        version: 0,
        patterns,
        indexed_game_data_keys: keys,
    })
}

fn redact_crash_context(result: &mut Value, patterns: &[String]) {
    let Some(context) = result
        .get_mut("crash_context")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    for field in [
        "error_message",
        "build_version",
        "engine_version",
        "architecture",
        "build_configuration",
        "command_line",
        "user_comment",
    ] {
        redact_field(context, field, patterns);
    }
    if let Some(platform) = context.get_mut("platform") {
        if let Some(original) = platform.get_mut("original") {
            redact_value(original, patterns);
        }
        if let Some(normalized) = platform.get_mut("normalized") {
            redact_value(normalized, patterns);
        }
    }
    redact_array_fields(context.get_mut("modules"), &["original"], patterns);
    redact_array_fields(
        context.get_mut("threads"),
        &["call_stack", "registers", "thread_name"],
        patterns,
    );
    redact_array_fields(context.get_mut("system_metadata"), &["value"], patterns);
    redact_array_fields(context.get_mut("game_data"), &["value"], patterns);
    redact_recursive(context.get_mut("unknown_fields"), patterns);
}

fn redact_log(result: &mut Value, patterns: &[String]) {
    if let Some(name) = result.pointer_mut("/log/name") {
        redact_value(name, patterns);
    }
    if let Some(text) = result.pointer_mut("/log/tail/text") {
        redact_value(text, patterns);
    }
}

fn redact_symbolication(result: &mut Value, patterns: &[String]) {
    let Some(threads) = result
        .pointer_mut("/current/symbolication/threads")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for thread in threads {
        let Some(frames) = thread.get_mut("frames").and_then(Value::as_array_mut) else {
            continue;
        };
        for frame in frames {
            if let Some(source_file) = frame.get_mut("source_file") {
                redact_value(source_file, patterns);
            }
            let Some(inlines) = frame.get_mut("inlines").and_then(Value::as_array_mut) else {
                continue;
            };
            for inline in inlines {
                if let Some(source_file) = inline.get_mut("source_file") {
                    redact_value(source_file, patterns);
                }
            }
        }
    }
}

fn redact_array_fields(value: Option<&mut Value>, fields: &[&str], patterns: &[String]) {
    let Some(values) = value.and_then(Value::as_array_mut) else {
        return;
    };
    for value in values {
        for field in fields {
            if let Some(value) = value.get_mut(*field) {
                redact_value(value, patterns);
            }
        }
    }
}

fn redact_recursive(value: Option<&mut Value>, patterns: &[String]) {
    let Some(value) = value else {
        return;
    };
    match value {
        Value::String(text) => redact_text(text, patterns),
        Value::Array(values) => {
            for value in values {
                redact_recursive(Some(value), patterns);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                redact_recursive(Some(value), patterns);
            }
        }
        _ => {}
    }
}

fn redact_field(object: &mut serde_json::Map<String, Value>, field: &str, patterns: &[String]) {
    if let Some(value) = object.get_mut(field) {
        redact_value(value, patterns);
    }
}

fn redact_value(value: &mut Value, patterns: &[String]) {
    if let Value::String(text) = value {
        redact_text(text, patterns);
    }
}

fn redact_text(text: &mut String, patterns: &[String]) {
    for pattern in patterns {
        if text.contains(pattern) {
            *text = text.replace(pattern, REDACTED);
        }
    }
}

fn context_facets(result: &Value, indexed_keys: &[String]) -> Vec<ContextFacet> {
    if indexed_keys.is_empty() {
        return Vec::new();
    }
    let allowed = indexed_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let Some(values) = result
        .pointer("/crash_context/game_data")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    values
        .iter()
        .filter_map(|value| {
            let key = value.get("name")?.as_str()?;
            let raw = value.get("value")?.as_str()?;
            if !allowed.contains(key) || raw.is_empty() {
                return None;
            }
            let value = raw.chars().take(MAX_FACET_VALUE_CHARS).collect::<String>();
            Some(ContextFacet {
                key: key.to_owned(),
                value_truncated: value.chars().count() < raw.chars().count(),
                value,
            })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn rules_request_digest(project_id: &str, version: i64) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"data-rules-v1\0");
    digest.update(project_id.as_bytes());
    digest.update(b"\0");
    digest.update(version.to_be_bytes());
    digest.finalize().into()
}

fn view(
    mut rules: DataRules,
    can_edit: bool,
    reprocessing_request_id: Option<String>,
) -> DataRulesView {
    if !can_edit {
        rules.patterns.clear();
    }
    DataRulesView {
        version: rules.version,
        redaction_patterns: rules.patterns,
        indexed_game_data_keys: rules.indexed_game_data_keys,
        can_edit,
        reprocessing_request_id,
    }
}

async fn authorize(
    state: &ServerState,
    headers: &HeaderMap,
    project_id: &str,
    permission: crate::auth::Permission,
) -> Result<crate::auth::ProjectActor, DataRulesError> {
    crate::auth::authorize_project(state, headers, project_id, permission)
        .await
        .map_err(|error| match error {
            crate::auth::AuthorizationError::Unauthorized => DataRulesError::Unauthorized,
            crate::auth::AuthorizationError::Forbidden => DataRulesError::Forbidden,
            crate::auth::AuthorizationError::Unavailable => DataRulesError::Unavailable,
            crate::auth::AuthorizationError::NotFound => DataRulesError::NotFound,
        })
}

fn no_store(status: StatusCode, value: &impl Serialize) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt as _;

    use super::{DataRulesError, redact_and_index, validate_rules};
    use crate::project_setup::{DATABASE_TEST_LOCK, ServerState, migrate, router};

    #[test]
    fn rules_are_bounded_and_canonical() {
        let rules = validate_rules(
            vec![
                "token".to_owned(),
                "long-token".to_owned(),
                "token".to_owned(),
            ],
            vec![
                "MapName".to_owned(),
                "Mode".to_owned(),
                "MapName".to_owned(),
            ],
        )
        .unwrap_or_else(|_| panic!("rules must be valid"));
        assert_eq!(rules.patterns, ["long-token", "token"]);
        assert_eq!(rules.indexed_game_data_keys, ["MapName", "Mode"]);

        let invalid = validate_rules(vec!["line\nbreak".to_owned()], Vec::new());
        assert!(matches!(invalid, Err(DataRulesError::InvalidRequest)));
        let invalid = validate_rules(vec!["REDACTED".to_owned()], Vec::new());
        assert!(matches!(invalid, Err(DataRulesError::InvalidRequest)));
        let invalid = validate_rules(vec!["   ".to_owned()], Vec::new());
        assert!(matches!(invalid, Err(DataRulesError::InvalidRequest)));
        let invalid = validate_rules(Vec::new(), vec!["bad key".to_owned()]);
        assert!(matches!(invalid, Err(DataRulesError::InvalidRequest)));
    }

    #[test]
    fn redaction_and_context_indexing_are_deterministic() {
        let rules = validate_rules(
            vec!["secret".to_owned(), "secret-token".to_owned()],
            vec!["MapName".to_owned()],
        )
        .unwrap_or_else(|_| panic!("rules must be valid"));
        let mut result = json!({
            "crash_context": {
                "crash_guid": "UECC-secret",
                "error_message": "secret-token and secret",
                "command_line": "-token=secret",
                "architecture": "x86_64-secret",
                "build_configuration": "Shipping-secret",
                "platform": {"original": "Win64-secret", "normalized": "windows-secret"},
                "modules": [{"original": "C:/secret/Game.exe", "normalized": "game"}],
                "threads": [],
                "system_metadata": [{"name": "Account", "value": "secret"}],
                "user_comment": "secret",
                "game_data": [
                    {"name": "MapName", "value": "Arena-secret"},
                    {"name": "Private", "value": "secret-token"}
                ],
                "unknown_fields": {"Private": "secret"}
            },
            "log": {"name": "secret.log", "tail": {"text": "secret-token", "truncated": false, "invalid_utf8": false}},
            "current": {"symbolication": {"threads": []}}
        });
        let facets = redact_and_index(&mut result, &rules);

        assert_eq!(
            result.pointer("/crash_context/crash_guid"),
            Some(&json!("UECC-secret"))
        );
        assert_eq!(
            result.pointer("/crash_context/error_message"),
            Some(&json!("[REDACTED] and [REDACTED]"))
        );
        assert_eq!(result.pointer("/log/tail/text"), Some(&json!("[REDACTED]")));
        assert_eq!(
            result.pointer("/crash_context/build_configuration"),
            Some(&json!("Shipping-[REDACTED]"))
        );
        assert_eq!(
            result.pointer("/crash_context/platform/normalized"),
            Some(&json!("windows-[REDACTED]"))
        );
        assert_eq!(facets.len(), 1);
        assert_eq!(facets[0].key, "MapName");
        assert_eq!(facets[0].value, "Arena-[REDACTED]");

        let first = result.clone();
        let second_facets = redact_and_index(&mut result, &rules);
        assert_eq!(result, first);
        assert_eq!(second_facets, facets);
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn owners_update_rules_idempotently_without_cross_tenant_visibility() {
        let database_url = std::env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
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
        let user_id: String = sqlx::query_scalar(
            "INSERT INTO users (bootstrap_subject, email) VALUES ('local-bootstrap', 'owner@example.com') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("owner must insert: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Owner org', 'owner-org') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("organization must insert: {error}"));
        sqlx::query(
            "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')",
        )
        .bind(&organization_id)
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("membership must insert: {error}"));
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Owner project', 'owner-project') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("project must insert: {error}"));
        let other_organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Other org', 'other-org') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("other organization must insert: {error}"));
        let other_project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Other project', 'other-project') RETURNING id::text",
        )
        .bind(&other_organization_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("other project must insert: {error}"));
        let state = ServerState::issue_test(pool.clone(), "data-rules-secret000000000000000");
        let body = json!({
            "redaction_patterns": ["test-secret"],
            "indexed_game_data_keys": ["MapName"]
        });
        let updated = request(
            &state,
            "PUT",
            &format!("/api/v1/projects/{project_id}/data-rules"),
            Some(body.clone()),
        )
        .await;
        assert_eq!(updated.status(), axum::http::StatusCode::ACCEPTED);
        let updated = response_json(updated).await;
        assert_eq!(updated["version"], 1);
        assert_eq!(updated["can_edit"], true);
        assert!(updated["reprocessing_request_id"].is_string());

        let unchanged = request(
            &state,
            "PUT",
            &format!("/api/v1/projects/{project_id}/data-rules"),
            Some(body),
        )
        .await;
        assert_eq!(unchanged.status(), axum::http::StatusCode::OK);
        let requests: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_reprocessing_requests WHERE organization_id::text = $1 AND project_id::text = $2 AND scope_kind = 'data_rules_version'",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("request count must load: {error}"));
        assert_eq!(requests, 1);

        let invalid = request(
            &state,
            "PUT",
            &format!("/api/v1/projects/{project_id}/data-rules"),
            Some(json!({
                "redaction_patterns": ["bad\npattern"],
                "indexed_game_data_keys": []
            })),
        )
        .await;
        assert_eq!(invalid.status(), axum::http::StatusCode::BAD_REQUEST);
        let other = request(
            &state,
            "GET",
            &format!("/api/v1/projects/{other_project_id}/data-rules"),
            None,
        )
        .await;
        assert_eq!(other.status(), axum::http::StatusCode::NOT_FOUND);
    }

    async fn request(
        state: &ServerState,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> axum::response::Response {
        let mut request = Request::builder().method(method).uri(path).header(
            "authorization",
            "Bootstrap data-rules-secret000000000000000",
        );
        let body = if let Some(body) = body {
            request = request.header("content-type", "application/json");
            Body::from(body.to_string())
        } else {
            Body::empty()
        };
        router("api", state.clone())
            .oneshot(
                request
                    .body(body)
                    .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"))
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap_or_else(|error| panic!("response body must load: {error}"));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("response must be JSON: {error}"))
    }
}
