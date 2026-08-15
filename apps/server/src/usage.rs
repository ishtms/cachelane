use std::{
    env, fmt,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgPoolOptions};
use tracing::info;

use crate::project_setup::ServerState;

const OVERAGE_BLOCK_EVENTS: i64 = 100_000;
const OVERAGE_BLOCK_CENTS: i64 = 1_500;
const RAW_RESERVOIR_RATE: i32 = 100;
const RETENTION_BATCH_SIZE: i64 = 5_000;
const RETENTION_DRAIN_BUDGET: Duration = Duration::from_secs(30);
const STORAGE_RECONCILE_BATCH_SIZE: i64 = 5_000;
const RETENTION_EVENT_QUERY: &str = "SELECT e.usage_outcome, e.raw_retention_class, e.issue_id::text AS issue_id, e.release_id::text AS release_id, e.variant_fingerprint, e.raw_object_id::text AS object_id, raw.lifecycle_state AS raw_lifecycle_state, p.retain_all_raw, p.artifact_storage_limit_bytes FROM crash_events e JOIN crash_event_objects raw ON raw.id = e.raw_object_id AND raw.organization_id = e.organization_id AND raw.project_id = e.project_id JOIN project_usage_policies p ON p.organization_id = e.organization_id AND p.project_id = e.project_id WHERE e.id = $1::uuid AND e.organization_id = $2::uuid AND e.project_id = $3::uuid FOR UPDATE OF e, raw";
#[cfg(test)]
const RETENTION_EVENT_EXPLAIN_QUERY: &str = "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) SELECT e.usage_outcome, e.raw_retention_class, e.issue_id::text AS issue_id, e.release_id::text AS release_id, e.variant_fingerprint, e.raw_object_id::text AS object_id, raw.lifecycle_state AS raw_lifecycle_state, p.retain_all_raw, p.artifact_storage_limit_bytes FROM crash_events e JOIN crash_event_objects raw ON raw.id = e.raw_object_id AND raw.organization_id = e.organization_id AND raw.project_id = e.project_id JOIN project_usage_policies p ON p.organization_id = e.organization_id AND p.project_id = e.project_id WHERE e.id = $1::uuid AND e.organization_id = $2::uuid AND e.project_id = $3::uuid FOR UPDATE OF e, raw";

#[derive(Clone, Debug)]
struct UsagePolicy {
    version: i64,
    event_limit: i64,
    artifact_storage_limit_bytes: i64,
    project_limit: i32,
    normalized_retention_limit_days: i32,
    raw_retention_limit_days: i32,
    normalized_retention_days: i32,
    raw_retention_days: i32,
    courtesy_percent: i32,
    spend_cap_cents: Option<i64>,
    retain_all_raw: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Admission {
    pub(crate) cycle_start: String,
    pub(crate) policy_version: i64,
    pub(crate) outcome: &'static str,
    pub(crate) threshold: Option<&'static str>,
    pub(crate) accepted_events: i64,
    pub(crate) event_limit: i64,
    pub(crate) courtesy_limit: i64,
    pub(crate) usage_counted: bool,
    pub(crate) estimated: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateUsageSettings {
    spend_cap_cents: Option<i64>,
    retain_all_raw: bool,
    normalized_retention_days: i32,
    raw_retention_days: i32,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct UsageView {
    authoritative: bool,
    enforcement_enabled: bool,
    policy_version: i64,
    policy_state: &'static str,
    threshold: Option<&'static str>,
    cycle_start: String,
    cycle_end: String,
    accepted_events: i64,
    event_limit: i64,
    courtesy_limit: i64,
    accepted_raw_bytes: i64,
    accepted_symbol_bytes: i64,
    deleted_raw_bytes: i64,
    sampled_raw_events: i64,
    estimated_represented_events: i64,
    estimates_present: bool,
    retained_raw_bytes: i64,
    symbol_storage_bytes: i64,
    artifact_storage_bytes: i64,
    artifact_storage_limit_bytes: i64,
    organization_projects: i64,
    project_limit: i32,
    normalized_retention_days: i32,
    normalized_retention_limit_days: i32,
    raw_retention_days: i32,
    raw_retention_limit_days: i32,
    courtesy_percent: i32,
    paid_overages_enabled: bool,
    spend_cap_cents: Option<i64>,
    retain_all_raw: bool,
    can_edit: bool,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct StorageReconciliationReport {
    pub(crate) organization_id: String,
    pub(crate) project_id: String,
    pub(crate) deadlines_backfilled: i64,
    pub(crate) missing_deadlines: i64,
    pub(crate) previous_raw_bytes: i64,
    pub(crate) retained_raw_bytes: i64,
    pub(crate) raw_byte_drift: i64,
    pub(crate) previous_symbol_bytes: i64,
    pub(crate) retained_symbol_bytes: i64,
    pub(crate) symbol_byte_drift: i64,
}

#[derive(Debug)]
pub(crate) enum StorageReconcileError {
    InvalidIdentifier,
    NotFound,
    Database,
}

impl fmt::Display for StorageReconcileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "storage reconciliation identifier is invalid",
            Self::NotFound => "storage reconciliation project was not found",
            Self::Database => "storage reconciliation database operation failed",
        })
    }
}

impl std::error::Error for StorageReconcileError {}

#[derive(Clone, Copy, Debug)]
pub(crate) enum UsageError {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Unavailable,
    Internal,
}

impl IntoResponse for UsageError {
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

pub(crate) async fn get_usage(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Response, UsageError> {
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ReadProject,
    )
    .await?;
    let pool = state.control_pool().ok_or(UsageError::Internal)?;
    let mut transaction = pool.begin().await.map_err(|_| UsageError::Internal)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(|_| UsageError::Internal)?;
    let view = load_usage_view(
        &mut transaction,
        &actor.organization_id,
        &actor.project_id,
        actor.allows(crate::auth::Permission::ManageUsage),
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| UsageError::Internal)?;
    Ok(no_store(StatusCode::OK, &view))
}

pub(crate) async fn update_usage(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    body: Result<Json<UpdateUsageSettings>, JsonRejection>,
) -> Result<Response, UsageError> {
    if env::var("FAULTLANE_USAGE_POLICY_EDITS_ENABLED")
        .is_ok_and(|value| value.eq_ignore_ascii_case("false"))
    {
        return Err(UsageError::NotFound);
    }
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ManageUsage,
    )
    .await?;
    let Json(body) = body.map_err(|_| UsageError::InvalidRequest)?;
    if body
        .spend_cap_cents
        .is_some_and(|value| !(OVERAGE_BLOCK_CENTS..=10_000_000).contains(&value))
        || !(1..=3650).contains(&body.normalized_retention_days)
        || !(1..=3650).contains(&body.raw_retention_days)
    {
        return Err(UsageError::InvalidRequest);
    }
    let pool = state.control_pool().ok_or(UsageError::Internal)?;
    let mut transaction = pool.begin().await.map_err(|_| UsageError::Internal)?;
    let policy = lock_policy(&mut transaction, &actor.organization_id, &actor.project_id).await?;
    if body.normalized_retention_days > policy.normalized_retention_limit_days
        || body.raw_retention_days > policy.raw_retention_limit_days
    {
        return Err(UsageError::InvalidRequest);
    }
    if body.retain_all_raw {
        let retained =
            retained_artifact_bytes(&mut transaction, &actor.organization_id, &actor.project_id)
                .await?;
        if retained >= policy.artifact_storage_limit_bytes {
            return Err(UsageError::InvalidRequest);
        }
    }
    let changed = policy.spend_cap_cents != body.spend_cap_cents
        || policy.retain_all_raw != body.retain_all_raw
        || policy.normalized_retention_days != body.normalized_retention_days
        || policy.raw_retention_days != body.raw_retention_days;
    if changed {
        let updated = sqlx::query(
            "UPDATE project_usage_policies SET version = version + 1, spend_cap_cents = $4, retain_all_raw = $5, normalized_retention_days = $6, raw_retention_days = $7, updated_by_user_id = $8::uuid, updated_at = now() WHERE organization_id = $1::uuid AND project_id = $2::uuid AND version = $3",
        )
        .bind(&actor.organization_id)
        .bind(&actor.project_id)
        .bind(policy.version)
        .bind(body.spend_cap_cents)
        .bind(body.retain_all_raw)
        .bind(body.normalized_retention_days)
        .bind(body.raw_retention_days)
        .bind(&actor.actor.user_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| UsageError::Internal)?;
        if updated.rows_affected() != 1 {
            return Err(UsageError::Unavailable);
        }
        insert_current_policy_version(&mut transaction, &actor.organization_id, &actor.project_id)
            .await?;
        sqlx::query(
            "INSERT INTO audit_log (organization_id, actor_user_id, action, target_type, target_id, result) VALUES ($1::uuid, $2::uuid, 'project_usage.updated', 'project', $3, 'succeeded')",
        )
        .bind(&actor.organization_id)
        .bind(&actor.actor.user_id)
        .bind(&actor.project_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| UsageError::Internal)?;
    }
    let view = load_usage_view(
        &mut transaction,
        &actor.organization_id,
        &actor.project_id,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| UsageError::Internal)?;
    Ok(no_store(StatusCode::OK, &view))
}

pub(crate) async fn record_acceptance(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    event_id: &str,
    object_id: &str,
    raw_bytes: i64,
    enforcement_enabled: bool,
) -> Result<Admission, UsageError> {
    let policy = lock_policy(transaction, organization_id, project_id).await?;
    let cycle_start: String = sqlx::query_scalar(
        "SELECT to_char(date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD')",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    sqlx::query(
        "INSERT INTO usage_cycle_counters (organization_id, project_id, cycle_start) VALUES ($1::uuid, $2::uuid, $3::date) ON CONFLICT DO NOTHING",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(&cycle_start)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    let accepted: i64 = sqlx::query_scalar(
        "SELECT accepted_events FROM usage_cycle_counters WHERE organization_id = $1::uuid AND project_id = $2::uuid AND cycle_start = $3::date FOR UPDATE",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(&cycle_start)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    let next = accepted.checked_add(1).ok_or(UsageError::Internal)?;
    let outcome = admission_outcome(next, &policy, enforcement_enabled);
    let courtesy_limit = courtesy_limit(&policy);
    let threshold = threshold(next, &policy, outcome);
    sqlx::query(
        "UPDATE usage_cycle_counters SET accepted_events = accepted_events + 1, accepted_raw_bytes = accepted_raw_bytes + $4, updated_at = now() WHERE organization_id = $1::uuid AND project_id = $2::uuid AND cycle_start = $3::date",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(&cycle_start)
    .bind(raw_bytes)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    for (kind, source_id, quantity) in [
        ("accepted_event", event_id, 1_i64),
        ("raw_stored", object_id, raw_bytes),
    ] {
        sqlx::query(
            "INSERT INTO usage_ledger (organization_id, project_id, cycle_start, kind, source_id, quantity) VALUES ($1::uuid, $2::uuid, $3::date, $4, $5::uuid, $6)",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(&cycle_start)
        .bind(kind)
        .bind(source_id)
        .bind(quantity)
        .execute(&mut **transaction)
        .await
        .map_err(|_| UsageError::Unavailable)?;
    }
    set_raw_delete_after(
        transaction,
        organization_id,
        project_id,
        event_id,
        object_id,
        policy.raw_retention_days,
    )
    .await?;
    apply_storage_delta(transaction, organization_id, project_id, raw_bytes, 0).await?;
    sqlx::query(
        "UPDATE crash_events SET usage_cycle_start = $4::date, usage_policy_version = $5, usage_outcome = $6, usage_counted = true, usage_estimated = $7, usage_accepted_events = $8, raw_retention_class = CASE WHEN $6 = 'sampling' THEN 'pending' ELSE 'standard' END, raw_sampling_rate = CASE WHEN $6 = 'sampling' THEN $9 ELSE 1 END WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid",
    )
    .bind(event_id)
    .bind(organization_id)
    .bind(project_id)
    .bind(&cycle_start)
    .bind(policy.version)
    .bind(outcome)
    .bind(outcome == "sampling")
    .bind(next)
    .bind(RAW_RESERVOIR_RATE)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    Ok(Admission {
        cycle_start,
        policy_version: policy.version,
        outcome,
        threshold,
        accepted_events: next,
        event_limit: policy.event_limit,
        courtesy_limit,
        usage_counted: true,
        estimated: outcome == "sampling",
    })
}

pub(crate) async fn ensure_policy_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
) -> Result<(), UsageError> {
    lock_policy(transaction, organization_id, project_id)
        .await
        .map(|_| ())
}

pub(crate) async fn admission_for_event(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    event_id: &str,
    counted: bool,
) -> Result<Admission, UsageError> {
    let row = sqlx::query(
        "SELECT to_char(e.usage_cycle_start, 'YYYY-MM-DD') AS cycle_start, e.usage_policy_version, e.usage_outcome, e.usage_estimated, e.usage_accepted_events, p.event_limit, p.courtesy_percent, p.spend_cap_cents FROM crash_events e JOIN project_usage_policy_versions p ON p.organization_id = e.organization_id AND p.project_id = e.project_id AND p.version = e.usage_policy_version WHERE e.id = $1::uuid AND e.organization_id = $2::uuid AND e.project_id = $3::uuid",
    )
    .bind(event_id)
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?
    .ok_or(UsageError::NotFound)?;
    let policy = UsagePolicy {
        version: row.get("usage_policy_version"),
        event_limit: row.get("event_limit"),
        courtesy_percent: row.get("courtesy_percent"),
        spend_cap_cents: row.get("spend_cap_cents"),
        artifact_storage_limit_bytes: 1,
        project_limit: 1,
        normalized_retention_limit_days: 1,
        raw_retention_limit_days: 1,
        normalized_retention_days: 1,
        raw_retention_days: 1,
        retain_all_raw: false,
    };
    let accepted_events: i64 = row.get("usage_accepted_events");
    let outcome: String = row.get("usage_outcome");
    let outcome = stable_outcome(&outcome)?;
    Ok(Admission {
        cycle_start: row.get("cycle_start"),
        policy_version: policy.version,
        outcome,
        threshold: threshold(accepted_events, &policy, outcome),
        accepted_events,
        event_limit: policy.event_limit,
        courtesy_limit: courtesy_limit(&policy),
        usage_counted: counted,
        estimated: row.get("usage_estimated"),
    })
}

pub(crate) async fn record_symbol_stored(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    object_id: &str,
    byte_size: i64,
) -> Result<(), UsageError> {
    let cycle_start: String = sqlx::query_scalar(
        "SELECT to_char(date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD')",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    let inserted = sqlx::query(
        "INSERT INTO usage_ledger (organization_id, project_id, cycle_start, kind, source_id, quantity) VALUES ($1::uuid, $2::uuid, $3::date, 'symbol_stored', $4::uuid, $5) ON CONFLICT DO NOTHING",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(&cycle_start)
    .bind(object_id)
    .bind(byte_size)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    if inserted.rows_affected() == 1 {
        sqlx::query(
            "INSERT INTO usage_cycle_counters (organization_id, project_id, cycle_start, accepted_symbol_bytes) VALUES ($1::uuid, $2::uuid, $3::date, $4) ON CONFLICT (organization_id, project_id, cycle_start) DO UPDATE SET accepted_symbol_bytes = usage_cycle_counters.accepted_symbol_bytes + EXCLUDED.accepted_symbol_bytes, updated_at = now()",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(&cycle_start)
        .bind(byte_size)
        .execute(&mut **transaction)
        .await
        .map_err(|_| UsageError::Unavailable)?;
        apply_storage_delta(transaction, organization_id, project_id, 0, byte_size).await?;
    }
    Ok(())
}

pub(crate) async fn schedule_raw_retention(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    event_id: &str,
) -> Result<(), UsageError> {
    schedule_raw_retention_with_enforcement(
        transaction,
        organization_id,
        project_id,
        event_id,
        enforcement_enabled(),
    )
    .await
}

#[allow(clippy::too_many_lines)]
async fn schedule_raw_retention_with_enforcement(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    event_id: &str,
    enforce: bool,
) -> Result<(), UsageError> {
    let row = sqlx::query(RETENTION_EVENT_QUERY)
        .bind(event_id)
        .bind(organization_id)
        .bind(project_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| UsageError::Unavailable)?
        .ok_or(UsageError::NotFound)?;
    if row.get::<String, _>("raw_lifecycle_state") != "stored" {
        return Ok(());
    }
    if row.get::<String, _>("raw_retention_class") != "pending" {
        return Ok(());
    }
    if !enforce || row.get::<String, _>("usage_outcome") != "sampling" {
        return set_retention_class(
            transaction,
            organization_id,
            project_id,
            event_id,
            "standard",
        )
        .await;
    }
    if row.get::<bool, _>("retain_all_raw")
        && retained_artifact_bytes(transaction, organization_id, project_id).await?
            <= row.get::<i64, _>("artifact_storage_limit_bytes")
    {
        return set_retention_class(
            transaction,
            organization_id,
            project_id,
            event_id,
            "standard",
        )
        .await;
    }
    let Some(issue_id) = row.get::<Option<String>, _>("issue_id") else {
        return set_retention_class(transaction, organization_id, project_id, event_id, "novel")
            .await;
    };
    let issue = sqlx::query(
        "SELECT event_count, representative_event_id::text AS representative_event_id FROM issues WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid",
    )
    .bind(&issue_id)
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    if issue.get::<i64, _>("event_count") <= 1 {
        return set_retention_class(transaction, organization_id, project_id, event_id, "novel")
            .await;
    }
    if issue
        .get::<Option<String>, _>("representative_event_id")
        .as_deref()
        == Some(event_id)
    {
        return set_retention_class(
            transaction,
            organization_id,
            project_id,
            event_id,
            "representative",
        )
        .await;
    }
    let variant_first: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM crash_events prior WHERE prior.organization_id = $1::uuid AND prior.project_id = $2::uuid AND prior.issue_id = $3::uuid AND prior.variant_fingerprint = $4 AND (prior.received_at, prior.id) < (current.received_at, current.id)) FROM crash_events current WHERE current.id = $5::uuid AND current.organization_id = $1::uuid AND current.project_id = $2::uuid",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(&issue_id)
    .bind(row.get::<Option<String>, _>("variant_fingerprint"))
    .bind(event_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    if variant_first {
        return set_retention_class(
            transaction,
            organization_id,
            project_id,
            event_id,
            "variant",
        )
        .await;
    }
    let recent = sqlx::query(
        "SELECT e.id::text AS event_id, e.raw_object_id::text AS object_id FROM crash_events e JOIN crash_event_objects o ON o.id = e.raw_object_id AND o.organization_id = e.organization_id AND o.project_id = e.project_id WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.issue_id = $3::uuid AND e.release_id IS NOT DISTINCT FROM $4::uuid AND e.raw_retention_class = 'recent' AND o.lifecycle_state = 'stored' ORDER BY e.received_at DESC, e.id DESC LIMIT 3 FOR UPDATE OF e, o",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(&issue_id)
    .bind(row.get::<Option<String>, _>("release_id"))
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    if recent.len() < 3 {
        return set_retention_class(transaction, organization_id, project_id, event_id, "recent")
            .await;
    }
    let oldest = recent.last().ok_or(UsageError::Internal)?;
    let current_is_newer: bool = sqlx::query_scalar(
        "SELECT (current.received_at, current.id) > (oldest.received_at, oldest.id) FROM crash_events current JOIN crash_events oldest ON oldest.id = $4::uuid AND oldest.organization_id = current.organization_id AND oldest.project_id = current.project_id WHERE current.id = $1::uuid AND current.organization_id = $2::uuid AND current.project_id = $3::uuid",
    )
    .bind(event_id)
    .bind(organization_id)
    .bind(project_id)
    .bind(oldest.get::<String, _>("event_id"))
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    let (aged_event_id, aged_object_id) = if current_is_newer {
        (
            oldest.get::<String, _>("event_id"),
            oldest.get::<String, _>("object_id"),
        )
    } else {
        (event_id.to_owned(), row.get::<String, _>("object_id"))
    };
    if reservoir_selected(&aged_event_id) {
        set_retention_class(
            transaction,
            organization_id,
            project_id,
            &aged_event_id,
            "reservoir",
        )
        .await?;
    } else {
        enqueue_raw_deletion(
            transaction,
            organization_id,
            project_id,
            &aged_event_id,
            &aged_object_id,
            "deleting",
        )
        .await?;
    }
    if current_is_newer {
        set_retention_class(transaction, organization_id, project_id, event_id, "recent").await
    } else {
        Ok(())
    }
}

pub(crate) async fn record_raw_deleted(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    event_id: &str,
    object_id: &str,
    byte_size: i64,
) -> Result<(), UsageError> {
    let event = sqlx::query(
        "SELECT usage_outcome, raw_retention_class, raw_sampling_rate FROM crash_events WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid FOR UPDATE",
    )
    .bind(event_id)
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?
    .ok_or(UsageError::NotFound)?;
    let sampled = event.get::<String, _>("usage_outcome") == "sampling"
        && event.get::<String, _>("raw_retention_class") != "expired";
    let represented = if sampled {
        i64::from(event.get::<i32, _>("raw_sampling_rate"))
    } else {
        0
    };
    let cycle_start: String = sqlx::query_scalar(
        "SELECT to_char(date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD')",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    let inserted = sqlx::query(
        "INSERT INTO usage_ledger (organization_id, project_id, cycle_start, kind, source_id, quantity) VALUES ($1::uuid, $2::uuid, $3::date, 'raw_deleted', $4::uuid, $5) ON CONFLICT DO NOTHING",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(&cycle_start)
    .bind(object_id)
    .bind(byte_size)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    if inserted.rows_affected() == 1 {
        sqlx::query(
            "INSERT INTO usage_cycle_counters (organization_id, project_id, cycle_start, deleted_raw_bytes, sampled_raw_events, estimated_represented_events) VALUES ($1::uuid, $2::uuid, $3::date, $4, $5, $6) ON CONFLICT (organization_id, project_id, cycle_start) DO UPDATE SET deleted_raw_bytes = usage_cycle_counters.deleted_raw_bytes + EXCLUDED.deleted_raw_bytes, sampled_raw_events = usage_cycle_counters.sampled_raw_events + EXCLUDED.sampled_raw_events, estimated_represented_events = usage_cycle_counters.estimated_represented_events + EXCLUDED.estimated_represented_events, updated_at = now()",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(&cycle_start)
        .bind(byte_size)
        .bind(i64::from(sampled))
        .bind(represented)
        .execute(&mut **transaction)
        .await
        .map_err(|_| UsageError::Unavailable)?;
        apply_storage_delta(transaction, organization_id, project_id, -byte_size, 0).await?;
    }
    sqlx::query(
        "UPDATE crash_event_objects SET lifecycle_state = 'discarded', deleted_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND lifecycle_state IN ('deleting', 'discarded')",
    )
    .bind(object_id)
    .bind(organization_id)
    .bind(project_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    sqlx::query(
        "UPDATE crash_events SET raw_retention_class = CASE WHEN raw_retention_class = 'expired' THEN 'expired' ELSE 'discarded' END WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid",
    )
    .bind(event_id)
    .bind(organization_id)
    .bind(project_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    Ok(())
}

#[derive(Debug)]
pub(crate) enum SchedulerError {
    Configuration,
    Database,
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "scheduler configuration is invalid",
            Self::Database => "scheduler database is unavailable",
        })
    }
}

impl std::error::Error for SchedulerError {}

pub(crate) async fn run_scheduler() -> Result<(), SchedulerError> {
    let database_url = env::var("DATABASE_URL").map_err(|_| SchedulerError::Configuration)?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .map_err(|_| SchedulerError::Database)?;
    let mut interval = tokio::time::interval(Duration::from_mins(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if retention_v2_enabled() {
                    drain_expired_raw_v2(&pool, RETENTION_DRAIN_BUDGET).await?;
                } else {
                    schedule_expired_raw_legacy(&pool).await?;
                }
            },
            shutdown = tokio::signal::ctrl_c() => {
                shutdown.map_err(|_| SchedulerError::Configuration)?;
                return Ok(());
            }
        }
    }
}

async fn schedule_expired_raw_legacy(pool: &PgPool) -> Result<(), SchedulerError> {
    let mut transaction = pool.begin().await.map_err(|_| SchedulerError::Database)?;
    let rows = sqlx::query(
        "SELECT e.id::text AS event_id, e.organization_id::text AS organization_id, e.project_id::text AS project_id, e.raw_object_id::text AS object_id FROM crash_events e JOIN crash_event_objects o ON o.id = e.raw_object_id AND o.organization_id = e.organization_id AND o.project_id = e.project_id JOIN project_usage_policies p ON p.organization_id = e.organization_id AND p.project_id = e.project_id WHERE o.lifecycle_state = 'stored' AND e.received_at < now() - (p.raw_retention_days * interval '1 day') ORDER BY e.received_at, e.id FOR UPDATE OF e, o SKIP LOCKED LIMIT 100",
    )
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| SchedulerError::Database)?;
    for row in rows {
        enqueue_raw_deletion(
            &mut transaction,
            &row.get::<String, _>("organization_id"),
            &row.get::<String, _>("project_id"),
            &row.get::<String, _>("event_id"),
            &row.get::<String, _>("object_id"),
            "expired",
        )
        .await
        .map_err(|_| SchedulerError::Database)?;
    }
    transaction
        .commit()
        .await
        .map_err(|_| SchedulerError::Database)
}

async fn drain_expired_raw_v2(pool: &PgPool, budget: Duration) -> Result<i64, SchedulerError> {
    let started = Instant::now();
    let unreconciled_projects: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM project_storage_counters WHERE reconciled_at IS NULL",
    )
    .fetch_one(pool)
    .await
    .map_err(|_| SchedulerError::Database)?;
    if unreconciled_projects != 0 {
        info!(
            unreconciled_projects,
            "raw retention scheduling is waiting for storage reconciliation"
        );
        return Ok(0);
    }
    let mut scheduled = 0_i64;
    let mut batches = 0_i64;
    while started.elapsed() < budget {
        let claimed = schedule_expired_raw_v2_batch(pool, RETENTION_BATCH_SIZE).await?;
        scheduled = scheduled.saturating_add(claimed);
        batches = batches.saturating_add(1);
        if claimed < RETENTION_BATCH_SIZE {
            break;
        }
    }
    info!(
        scheduled,
        batches,
        duration_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
        "raw retention scheduling pass completed"
    );
    Ok(scheduled)
}

async fn schedule_expired_raw_v2_batch(
    pool: &PgPool,
    batch_size: i64,
) -> Result<i64, SchedulerError> {
    let scheduled = sqlx::query_scalar(
        "WITH candidates AS MATERIALIZED (SELECT o.id AS object_id, o.organization_id, o.project_id FROM crash_event_objects o WHERE o.lifecycle_state = 'stored' AND o.raw_delete_after <= now() ORDER BY o.raw_delete_after, o.id FOR UPDATE OF o SKIP LOCKED LIMIT $1), due AS MATERIALIZED (SELECT candidates.object_id, candidates.organization_id, candidates.project_id, e.id AS event_id FROM candidates JOIN project_storage_counters c ON c.organization_id = candidates.organization_id AND c.project_id = candidates.project_id AND c.reconciled_at IS NOT NULL JOIN crash_events e ON e.raw_object_id = candidates.object_id AND e.organization_id = candidates.organization_id AND e.project_id = candidates.project_id), claimed_objects AS (UPDATE crash_event_objects o SET lifecycle_state = 'deleting' FROM due d WHERE o.id = d.object_id AND o.organization_id = d.organization_id AND o.project_id = d.project_id AND o.lifecycle_state = 'stored' RETURNING o.id, o.organization_id, o.project_id), claimed_events AS (UPDATE crash_events e SET raw_retention_class = 'expired' FROM due d JOIN claimed_objects o ON o.id = d.object_id AND o.organization_id = d.organization_id AND o.project_id = d.project_id WHERE e.id = d.event_id AND e.organization_id = d.organization_id AND e.project_id = d.project_id RETURNING e.id AS event_id, e.organization_id, e.project_id, e.raw_object_id AS object_id), queued AS (INSERT INTO jobs (id, organization_id, project_id, event_id, job_type, payload, idempotency_key, priority) SELECT gen_random_uuid(), organization_id, project_id, event_id, 'delete_raw', jsonb_build_object('event_id', event_id::text, 'object_id', object_id::text), 'delete_raw:' || object_id::text, 50 FROM claimed_events ON CONFLICT (idempotency_key) DO UPDATE SET state = 'pending', attempt = 0, available_at = now(), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, updated_at = now() WHERE jobs.event_id = EXCLUDED.event_id AND jobs.state IN ('completed', 'failed', 'dead') RETURNING event_id) SELECT count(*)::bigint FROM claimed_events",
    )
    .bind(batch_size)
    .fetch_one(pool)
    .await
    .map_err(|_| SchedulerError::Database)?;
    Ok(scheduled)
}

pub(crate) async fn reconcile_storage(
    database_url: &str,
    organization_id: &str,
    project_id: &str,
) -> Result<StorageReconciliationReport, StorageReconcileError> {
    if !crate::identifiers::valid_uuid(organization_id)
        || !crate::identifiers::valid_uuid(project_id)
    {
        return Err(StorageReconcileError::InvalidIdentifier);
    }
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .map_err(|_| StorageReconcileError::Database)?;
    let project_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM projects WHERE organization_id = $1::uuid AND id = $2::uuid)",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(&pool)
    .await
    .map_err(|_| StorageReconcileError::Database)?;
    if !project_exists {
        return Err(StorageReconcileError::NotFound);
    }
    let deadlines_backfilled =
        backfill_raw_delete_after(&pool, organization_id, project_id).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| StorageReconcileError::Database)?;
    sqlx::query(
        "SELECT 1 FROM project_usage_policies WHERE organization_id = $1::uuid AND project_id = $2::uuid FOR UPDATE",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| StorageReconcileError::Database)?
    .ok_or(StorageReconcileError::NotFound)?;
    let previous = sqlx::query(
        "SELECT retained_raw_bytes, retained_symbol_bytes FROM project_storage_counters WHERE organization_id = $1::uuid AND project_id = $2::uuid FOR UPDATE",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| StorageReconcileError::Database)?
    .ok_or(StorageReconcileError::NotFound)?;
    let totals = sqlx::query(
        "SELECT (SELECT COALESCE(sum(byte_size), 0)::bigint FROM crash_event_objects WHERE organization_id = $1::uuid AND project_id = $2::uuid AND lifecycle_state IN ('stored', 'deleting')) AS retained_raw_bytes, (SELECT COALESCE(sum(objects.byte_size), 0)::bigint FROM (SELECT DISTINCT ao.id, ao.byte_size FROM release_manifest_artifacts m JOIN artifact_debug_images d ON d.id = m.debug_image_id AND d.organization_id = m.organization_id JOIN artifact_objects ao ON ao.id = d.object_id AND ao.organization_id = d.organization_id WHERE m.organization_id = $1::uuid AND m.project_id = $2::uuid AND m.state = 'available' AND ao.lifecycle_state = 'stored') objects) AS retained_symbol_bytes, (SELECT count(*)::bigint FROM crash_event_objects WHERE organization_id = $1::uuid AND project_id = $2::uuid AND raw_delete_after IS NULL) AS missing_deadlines",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| StorageReconcileError::Database)?;
    let missing_deadlines = totals.get::<i64, _>("missing_deadlines");
    if missing_deadlines != 0 {
        return Err(StorageReconcileError::Database);
    }
    let retained_raw_bytes = totals.get::<i64, _>("retained_raw_bytes");
    let retained_symbol_bytes = totals.get::<i64, _>("retained_symbol_bytes");
    sqlx::query(
        "UPDATE project_storage_counters SET retained_raw_bytes = $3, retained_symbol_bytes = $4, reconciled_at = now(), updated_at = now() WHERE organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(retained_raw_bytes)
    .bind(retained_symbol_bytes)
    .execute(&mut *transaction)
    .await
    .map_err(|_| StorageReconcileError::Database)?;
    transaction
        .commit()
        .await
        .map_err(|_| StorageReconcileError::Database)?;
    let previous_raw_bytes = previous.get::<i64, _>("retained_raw_bytes");
    let previous_symbol_bytes = previous.get::<i64, _>("retained_symbol_bytes");
    Ok(StorageReconciliationReport {
        organization_id: organization_id.to_owned(),
        project_id: project_id.to_owned(),
        deadlines_backfilled,
        missing_deadlines,
        previous_raw_bytes,
        retained_raw_bytes,
        raw_byte_drift: retained_raw_bytes.saturating_sub(previous_raw_bytes),
        previous_symbol_bytes,
        retained_symbol_bytes,
        symbol_byte_drift: retained_symbol_bytes.saturating_sub(previous_symbol_bytes),
    })
}

async fn backfill_raw_delete_after(
    pool: &PgPool,
    organization_id: &str,
    project_id: &str,
) -> Result<i64, StorageReconcileError> {
    let mut total = 0_i64;
    loop {
        let updated: i64 = sqlx::query_scalar(
            "WITH batch AS MATERIALIZED (SELECT o.id, e.received_at, p.raw_retention_days FROM crash_event_objects o JOIN crash_events e ON e.raw_object_id = o.id AND e.organization_id = o.organization_id AND e.project_id = o.project_id JOIN project_usage_policy_versions p ON p.organization_id = e.organization_id AND p.project_id = e.project_id AND p.version = e.usage_policy_version WHERE o.organization_id = $1::uuid AND o.project_id = $2::uuid AND o.raw_delete_after IS NULL ORDER BY o.id FOR UPDATE OF o SKIP LOCKED LIMIT $3), updated AS (UPDATE crash_event_objects o SET raw_delete_after = batch.received_at + (batch.raw_retention_days * interval '1 day') FROM batch WHERE o.id = batch.id AND o.organization_id = $1::uuid AND o.project_id = $2::uuid RETURNING 1) SELECT count(*)::bigint FROM updated",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(STORAGE_RECONCILE_BATCH_SIZE)
        .fetch_one(pool)
        .await
        .map_err(|_| StorageReconcileError::Database)?;
        total = total.saturating_add(updated);
        if updated < STORAGE_RECONCILE_BATCH_SIZE {
            return Ok(total);
        }
    }
}

async fn load_usage_view(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    can_edit: bool,
) -> Result<UsageView, UsageError> {
    let row = sqlx::query(
        "SELECT p.version, p.event_limit, p.artifact_storage_limit_bytes, p.project_limit, p.normalized_retention_limit_days, p.raw_retention_limit_days, p.normalized_retention_days, p.raw_retention_days, p.courtesy_percent, p.spend_cap_cents, p.retain_all_raw, to_char(current.cycle_start, 'YYYY-MM-DD') AS cycle_start, to_char((current.cycle_start + interval '1 month')::date, 'YYYY-MM-DD') AS cycle_end, COALESCE(c.accepted_events, 0)::bigint AS accepted_events, COALESCE(c.accepted_raw_bytes, 0)::bigint AS accepted_raw_bytes, COALESCE(c.accepted_symbol_bytes, 0)::bigint AS accepted_symbol_bytes, COALESCE(c.deleted_raw_bytes, 0)::bigint AS deleted_raw_bytes, COALESCE(c.sampled_raw_events, 0)::bigint AS sampled_raw_events, COALESCE(c.estimated_represented_events, 0)::bigint AS estimated_represented_events, (SELECT COALESCE(sum(o.byte_size), 0)::bigint FROM crash_event_objects o WHERE o.organization_id = p.organization_id AND o.project_id = p.project_id AND o.lifecycle_state IN ('stored', 'deleting')) AS retained_raw_bytes, (SELECT COALESCE(sum(objects.byte_size), 0)::bigint FROM (SELECT DISTINCT ao.id, ao.byte_size FROM release_manifest_artifacts m JOIN artifact_debug_images d ON d.id = m.debug_image_id AND d.organization_id = m.organization_id JOIN artifact_objects ao ON ao.id = d.object_id AND ao.organization_id = d.organization_id WHERE m.organization_id = p.organization_id AND m.project_id = p.project_id AND m.state = 'available' AND ao.lifecycle_state = 'stored') objects) AS symbol_storage_bytes, (SELECT count(*) FROM projects projects WHERE projects.organization_id = p.organization_id) AS organization_projects FROM project_usage_policies p CROSS JOIN LATERAL (SELECT date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC')::date AS cycle_start) current LEFT JOIN usage_cycle_counters c ON c.organization_id = p.organization_id AND c.project_id = p.project_id AND c.cycle_start = current.cycle_start WHERE p.organization_id = $1::uuid AND p.project_id = $2::uuid",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| UsageError::Internal)?
    .ok_or(UsageError::NotFound)?;
    let policy = policy_from_row(&row);
    let accepted_events: i64 = row.get("accepted_events");
    let enforcement_enabled = enforcement_enabled();
    let state = admission_outcome(accepted_events, &policy, enforcement_enabled);
    let retained_raw_bytes = row.get::<i64, _>("retained_raw_bytes");
    let symbol_storage_bytes = row.get::<i64, _>("symbol_storage_bytes");
    Ok(UsageView {
        authoritative: true,
        enforcement_enabled,
        policy_version: policy.version,
        policy_state: state,
        threshold: threshold(accepted_events, &policy, state),
        cycle_start: row.get("cycle_start"),
        cycle_end: row.get("cycle_end"),
        accepted_events,
        event_limit: policy.event_limit,
        courtesy_limit: courtesy_limit(&policy),
        accepted_raw_bytes: row.get("accepted_raw_bytes"),
        accepted_symbol_bytes: row.get("accepted_symbol_bytes"),
        deleted_raw_bytes: row.get("deleted_raw_bytes"),
        sampled_raw_events: row.get("sampled_raw_events"),
        estimated_represented_events: row.get("estimated_represented_events"),
        estimates_present: row.get::<i64, _>("estimated_represented_events") > 0,
        retained_raw_bytes,
        symbol_storage_bytes,
        artifact_storage_bytes: retained_raw_bytes.saturating_add(symbol_storage_bytes),
        artifact_storage_limit_bytes: policy.artifact_storage_limit_bytes,
        organization_projects: row.get("organization_projects"),
        project_limit: policy.project_limit,
        normalized_retention_days: policy.normalized_retention_days,
        normalized_retention_limit_days: policy.normalized_retention_limit_days,
        raw_retention_days: policy.raw_retention_days,
        raw_retention_limit_days: policy.raw_retention_limit_days,
        courtesy_percent: policy.courtesy_percent,
        paid_overages_enabled: policy.spend_cap_cents.is_some(),
        spend_cap_cents: policy.spend_cap_cents,
        retain_all_raw: policy.retain_all_raw,
        can_edit,
    })
}

async fn lock_policy(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
) -> Result<UsagePolicy, UsageError> {
    sqlx::query(
        "INSERT INTO project_usage_policies (organization_id, project_id) SELECT organization_id, id FROM projects WHERE organization_id = $1::uuid AND id = $2::uuid ON CONFLICT DO NOTHING",
    )
    .bind(organization_id)
    .bind(project_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    insert_current_policy_version(transaction, organization_id, project_id).await?;
    let row = sqlx::query(
        "SELECT version, event_limit, artifact_storage_limit_bytes, project_limit, normalized_retention_limit_days, raw_retention_limit_days, normalized_retention_days, raw_retention_days, courtesy_percent, spend_cap_cents, retain_all_raw FROM project_usage_policies WHERE organization_id = $1::uuid AND project_id = $2::uuid FOR UPDATE",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?
    .ok_or(UsageError::NotFound)?;
    Ok(policy_from_row(&row))
}

async fn insert_current_policy_version(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
) -> Result<(), UsageError> {
    sqlx::query(
        "INSERT INTO project_usage_policy_versions (organization_id, project_id, version, event_limit, artifact_storage_limit_bytes, project_limit, normalized_retention_limit_days, raw_retention_limit_days, normalized_retention_days, raw_retention_days, courtesy_percent, spend_cap_cents, retain_all_raw, updated_by_user_id, created_at) SELECT organization_id, project_id, version, event_limit, artifact_storage_limit_bytes, project_limit, normalized_retention_limit_days, raw_retention_limit_days, normalized_retention_days, raw_retention_days, courtesy_percent, spend_cap_cents, retain_all_raw, updated_by_user_id, updated_at FROM project_usage_policies WHERE organization_id = $1::uuid AND project_id = $2::uuid ON CONFLICT DO NOTHING",
    )
    .bind(organization_id)
    .bind(project_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    Ok(())
}

fn policy_from_row(row: &sqlx::postgres::PgRow) -> UsagePolicy {
    UsagePolicy {
        version: row.get("version"),
        event_limit: row.get("event_limit"),
        artifact_storage_limit_bytes: row.get("artifact_storage_limit_bytes"),
        project_limit: row.get("project_limit"),
        normalized_retention_limit_days: row.get("normalized_retention_limit_days"),
        raw_retention_limit_days: row.get("raw_retention_limit_days"),
        normalized_retention_days: row.get("normalized_retention_days"),
        raw_retention_days: row.get("raw_retention_days"),
        courtesy_percent: row.get("courtesy_percent"),
        spend_cap_cents: row.get("spend_cap_cents"),
        retain_all_raw: row.get("retain_all_raw"),
    }
}

fn policy_outcome(events: i64, policy: &UsagePolicy) -> &'static str {
    if events <= policy.event_limit {
        return "standard";
    }
    if let Some(cap) = policy.spend_cap_cents {
        let blocks = cap / OVERAGE_BLOCK_CENTS;
        let overage_events = blocks.saturating_mul(OVERAGE_BLOCK_EVENTS);
        if events <= policy.event_limit.saturating_add(overage_events) {
            return "overage";
        }
    }
    if events <= courtesy_limit(policy) {
        return "courtesy";
    }
    "sampling"
}

fn admission_outcome(events: i64, policy: &UsagePolicy, enforcement_enabled: bool) -> &'static str {
    if enforcement_enabled {
        policy_outcome(events, policy)
    } else {
        "standard"
    }
}

pub(crate) fn enforcement_enabled() -> bool {
    enforcement_from_env(
        env::var("FAULTLANE_USAGE_ENFORCEMENT_ENABLED")
            .ok()
            .as_deref(),
    )
}

pub(crate) fn retention_v2_enabled() -> bool {
    retention_v2_from_env(env::var("FAULTLANE_RETENTION_V2_ENABLED").ok().as_deref())
}

fn enforcement_from_env(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn retention_v2_from_env(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn courtesy_limit(policy: &UsagePolicy) -> i64 {
    policy.event_limit.saturating_add(
        policy
            .event_limit
            .saturating_mul(i64::from(policy.courtesy_percent))
            / 100,
    )
}

fn threshold(events: i64, policy: &UsagePolicy, outcome: &str) -> Option<&'static str> {
    if outcome == "sampling" {
        return Some("courtesy_exhausted");
    }
    let percent = i128::from(events).saturating_mul(100) / i128::from(policy.event_limit);
    if percent >= 100 {
        Some("100")
    } else if percent >= 90 {
        Some("90")
    } else if percent >= 70 {
        Some("70")
    } else {
        None
    }
}

fn stable_outcome(value: &str) -> Result<&'static str, UsageError> {
    match value {
        "standard" => Ok("standard"),
        "courtesy" => Ok("courtesy"),
        "overage" => Ok("overage"),
        "sampling" => Ok("sampling"),
        _ => Err(UsageError::Internal),
    }
}

fn reservoir_selected(event_id: &str) -> bool {
    let digest = Sha256::digest(event_id.as_bytes());
    u16::from_be_bytes([digest[0], digest[1]]) % u16::try_from(RAW_RESERVOIR_RATE).unwrap_or(100)
        == 0
}

async fn set_raw_delete_after(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    event_id: &str,
    object_id: &str,
    retention_days: i32,
) -> Result<(), UsageError> {
    let updated = sqlx::query(
        "UPDATE crash_event_objects o SET raw_delete_after = e.received_at + ($5::integer * interval '1 day') FROM crash_events e WHERE o.id = $1::uuid AND o.organization_id = $2::uuid AND o.project_id = $3::uuid AND e.id = $4::uuid AND e.organization_id = o.organization_id AND e.project_id = o.project_id AND e.raw_object_id = o.id AND o.raw_delete_after IS NULL",
    )
    .bind(object_id)
    .bind(organization_id)
    .bind(project_id)
    .bind(event_id)
    .bind(retention_days)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    if updated.rows_affected() != 1 {
        return Err(UsageError::Unavailable);
    }
    Ok(())
}

async fn apply_storage_delta(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    raw_delta: i64,
    symbol_delta: i64,
) -> Result<(), UsageError> {
    let updated = sqlx::query(
        "UPDATE project_storage_counters SET retained_raw_bytes = CASE WHEN reconciled_at IS NULL THEN retained_raw_bytes ELSE retained_raw_bytes + $3 END, retained_symbol_bytes = CASE WHEN reconciled_at IS NULL THEN retained_symbol_bytes ELSE retained_symbol_bytes + $4 END, updated_at = CASE WHEN reconciled_at IS NULL THEN updated_at ELSE now() END WHERE organization_id = $1::uuid AND project_id = $2::uuid AND (reconciled_at IS NULL OR retained_raw_bytes + $3 >= 0 AND retained_symbol_bytes + $4 >= 0)",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(raw_delta)
    .bind(symbol_delta)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    if updated.rows_affected() != 1 {
        return Err(UsageError::Unavailable);
    }
    Ok(())
}

async fn set_retention_class(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    event_id: &str,
    class: &str,
) -> Result<(), UsageError> {
    sqlx::query(
        "UPDATE crash_events SET raw_retention_class = $4 WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid",
    )
    .bind(event_id)
    .bind(organization_id)
    .bind(project_id)
    .bind(class)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    Ok(())
}

async fn enqueue_raw_deletion(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
    event_id: &str,
    object_id: &str,
    class: &str,
) -> Result<(), UsageError> {
    let updated = sqlx::query(
        "UPDATE crash_event_objects SET lifecycle_state = 'deleting' WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND lifecycle_state = 'stored'",
    )
    .bind(object_id)
    .bind(organization_id)
    .bind(project_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }
    set_retention_class(transaction, organization_id, project_id, event_id, class).await?;
    sqlx::query(
        "INSERT INTO jobs (id, organization_id, project_id, event_id, job_type, payload, idempotency_key, priority) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, 'delete_raw', jsonb_build_object('event_id', $3::text, 'object_id', $4::text), 'delete_raw:' || $4, 50) ON CONFLICT (idempotency_key) DO NOTHING",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(event_id)
    .bind(object_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| UsageError::Unavailable)?;
    Ok(())
}

async fn retained_artifact_bytes(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    project_id: &str,
) -> Result<i64, UsageError> {
    if retention_v2_enabled() {
        return sqlx::query_scalar(
            "SELECT retained_raw_bytes + retained_symbol_bytes FROM project_storage_counters WHERE organization_id = $1::uuid AND project_id = $2::uuid AND reconciled_at IS NOT NULL",
        )
        .bind(organization_id)
        .bind(project_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| UsageError::Internal)?
        .ok_or(UsageError::Unavailable);
    }
    sqlx::query_scalar(
        "SELECT (SELECT COALESCE(sum(byte_size), 0)::bigint FROM crash_event_objects WHERE organization_id = $1::uuid AND project_id = $2::uuid AND lifecycle_state IN ('stored', 'deleting')) + (SELECT COALESCE(sum(objects.byte_size), 0)::bigint FROM (SELECT DISTINCT ao.id, ao.byte_size FROM release_manifest_artifacts m JOIN artifact_debug_images d ON d.id = m.debug_image_id AND d.organization_id = m.organization_id JOIN artifact_objects ao ON ao.id = d.object_id AND ao.organization_id = d.organization_id WHERE m.organization_id = $1::uuid AND m.project_id = $2::uuid AND m.state = 'available' AND ao.lifecycle_state = 'stored') objects)",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| UsageError::Internal)
}

async fn authorize(
    state: &ServerState,
    headers: &HeaderMap,
    project_id: &str,
    permission: crate::auth::Permission,
) -> Result<crate::auth::ProjectActor, UsageError> {
    crate::auth::authorize_project(state, headers, project_id, permission)
        .await
        .map_err(|error| match error {
            crate::auth::AuthorizationError::Unauthorized => UsageError::Unauthorized,
            crate::auth::AuthorizationError::Forbidden => UsageError::Forbidden,
            crate::auth::AuthorizationError::Unavailable => UsageError::Unavailable,
            crate::auth::AuthorizationError::NotFound => UsageError::NotFound,
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
    use std::{error::Error, time::Instant};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use serde_json::{Value, json};
    use sqlx::{PgPool, Row, postgres::PgPoolOptions};
    use tower::ServiceExt as _;

    use super::{
        RETENTION_EVENT_EXPLAIN_QUERY, UsagePolicy, admission_outcome, courtesy_limit,
        enforcement_from_env, policy_outcome, reconcile_storage, record_acceptance,
        record_raw_deleted, record_symbol_stored, reservoir_selected, retention_v2_from_env,
        schedule_expired_raw_v2_batch, schedule_raw_retention_with_enforcement, threshold,
    };
    use crate::project_setup::{DATABASE_TEST_LOCK, ServerState, migrate, router};

    const SECRET: &str = "usage-test-secret-at-least-32-bytes";

    fn policy(spend_cap_cents: Option<i64>) -> UsagePolicy {
        UsagePolicy {
            version: 1,
            event_limit: 10,
            artifact_storage_limit_bytes: 100,
            project_limit: 1,
            normalized_retention_limit_days: 30,
            raw_retention_limit_days: 7,
            normalized_retention_days: 30,
            raw_retention_days: 7,
            courtesy_percent: 20,
            spend_cap_cents,
            retain_all_raw: false,
        }
    }

    #[test]
    fn quota_boundaries_require_an_explicit_spend_cap() {
        let free = policy(None);
        assert_eq!(courtesy_limit(&free), 12);
        assert_eq!(policy_outcome(10, &free), "standard");
        assert_eq!(policy_outcome(11, &free), "courtesy");
        assert_eq!(policy_outcome(12, &free), "courtesy");
        assert_eq!(policy_outcome(13, &free), "sampling");
        assert_eq!(threshold(7, &free, "standard"), Some("70"));
        assert_eq!(threshold(9, &free, "standard"), Some("90"));
        assert_eq!(threshold(10, &free, "standard"), Some("100"));
        assert_eq!(threshold(13, &free, "sampling"), Some("courtesy_exhausted"));

        let approved = policy(Some(1_500));
        assert_eq!(policy_outcome(11, &approved), "overage");
        assert_eq!(policy_outcome(100_010, &approved), "overage");
        assert_eq!(policy_outcome(100_011, &approved), "sampling");

        let too_small = policy(Some(1));
        assert_eq!(policy_outcome(11, &too_small), "courtesy");
        assert_eq!(admission_outcome(13, &free, false), "standard");
        assert!(!enforcement_from_env(None));
        assert!(!enforcement_from_env(Some("false")));
        assert!(enforcement_from_env(Some("TRUE")));
        assert!(!retention_v2_from_env(None));
        assert!(!retention_v2_from_env(Some("false")));
        assert!(retention_v2_from_env(Some("TRUE")));
    }

    #[test]
    fn repeated_raw_sampling_is_deterministic_and_bounded() {
        let selected = (0..10_000)
            .filter(|index| reservoir_selected(&format!("event-{index}")))
            .count();
        assert!((50..=150).contains(&selected));
        assert_eq!(
            reservoir_selected("stable-event"),
            reservoir_selected("stable-event")
        );
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    async fn owners_version_usage_settings_without_cross_tenant_access()
    -> Result<(), Box<dyn Error>> {
        let database_url = std::env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await?;
        let (user_id, organization_id, project_id) = seed_project(&pool).await?;
        let other_organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Other org', 'usage-other-org') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await?;
        let other_project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Other project', 'usage-other-project') RETURNING id::text",
        )
        .bind(&other_organization_id)
        .fetch_one(&pool)
        .await?;
        let state = ServerState::issue_test(pool.clone(), SECRET);

        let initial = request(&state, "GET", &project_id, None, true).await?;
        assert_eq!(initial.status(), StatusCode::OK);
        let initial = response_json(initial).await?;
        assert_eq!(initial["authoritative"], true);
        assert_eq!(initial["policy_version"], 1);
        assert_eq!(initial["accepted_events"], 0);
        assert_eq!(initial["paid_overages_enabled"], false);
        assert_eq!(initial["can_edit"], true);

        let invalid_cap = request(
            &state,
            "PUT",
            &project_id,
            Some(json!({
                "spend_cap_cents": 1499,
                "retain_all_raw": false,
                "normalized_retention_days": 30,
                "raw_retention_days": 7
            })),
            true,
        )
        .await?;
        assert_eq!(invalid_cap.status(), StatusCode::BAD_REQUEST);

        let body = json!({
            "spend_cap_cents": 1500,
            "retain_all_raw": true,
            "normalized_retention_days": 20,
            "raw_retention_days": 6
        });
        let updated = request(&state, "PUT", &project_id, Some(body.clone()), true).await?;
        assert_eq!(updated.status(), StatusCode::OK);
        let updated = response_json(updated).await?;
        assert_eq!(updated["policy_version"], 2);
        assert_eq!(updated["paid_overages_enabled"], true);
        assert_eq!(updated["spend_cap_cents"], 1500);
        assert_eq!(updated["retain_all_raw"], true);

        let unchanged = request(&state, "PUT", &project_id, Some(body), true).await?;
        assert_eq!(unchanged.status(), StatusCode::OK);
        assert_eq!(response_json(unchanged).await?["policy_version"], 2);
        let versions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM project_usage_policy_versions WHERE organization_id = $1::uuid AND project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(versions, 2);

        sqlx::query(
            "UPDATE organization_memberships SET role = 'admin' WHERE organization_id = $1::uuid AND user_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&user_id)
        .execute(&pool)
        .await?;
        let forbidden = request(
            &state,
            "PUT",
            &project_id,
            Some(json!({
                "spend_cap_cents": null,
                "retain_all_raw": false,
                "normalized_retention_days": 20,
                "raw_retention_days": 5
            })),
            true,
        )
        .await?;
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
        let readonly =
            response_json(request(&state, "GET", &project_id, None, true).await?).await?;
        assert_eq!(readonly["can_edit"], false);
        let outside = request(&state, "GET", &other_project_id, None, true).await?;
        assert_eq!(outside.status(), StatusCode::NOT_FOUND);
        let anonymous = request(&state, "GET", &project_id, None, false).await?;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn quota_pressure_retains_representatives_and_samples_repeated_raw()
    -> Result<(), Box<dyn Error>> {
        let database_url = std::env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await?;
        let (_, organization_id, project_id) = seed_project(&pool).await?;
        let mut transaction = pool.begin().await?;
        for _ in 0..2 {
            record_symbol_stored(
                &mut transaction,
                &organization_id,
                &project_id,
                "00000000-0000-4000-8000-000000000100",
                500,
            )
            .await
            .map_err(|_| "symbol usage must record")?;
        }
        transaction.commit().await?;
        let ingest_key_id: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, '11111111') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(vec![1_u8; 32])
        .fetch_one(&pool)
        .await?;
        let mut event_ids = vec![
            "00000000-0000-4000-8000-000000000001".to_owned(),
            "00000000-0000-4000-8000-000000000002".to_owned(),
            "00000000-0000-4000-8000-000000000003".to_owned(),
        ];
        let repeated_ids = (4_u64..10_000)
            .map(|value| format!("00000000-0000-4000-8000-{value:012x}"))
            .filter(|value| !reservoir_selected(value))
            .take(2)
            .collect::<Vec<_>>();
        if repeated_ids.len() != 2 {
            return Err("two non-reservoir event ids must exist".into());
        }
        event_ids.extend(repeated_ids);
        for (index, event_id) in event_ids.iter().enumerate() {
            let object_id: String = sqlx::query_scalar(
                "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3, $4, 100, 'application/octet-stream') RETURNING id::text",
            )
            .bind(&organization_id)
            .bind(&project_id)
            .bind(format!("usage-test-{index}"))
            .bind(vec![u8::try_from(index + 1)?; 32])
            .fetch_one(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, crash_guid, environment, received_at, usage_outcome, usage_counted, usage_estimated, usage_accepted_events, raw_retention_class, raw_sampling_rate) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, 'production', now() + ($7 * interval '1 second'), 'sampling', true, true, $8, 'pending', 100)",
            )
            .bind(event_id)
            .bind(&organization_id)
            .bind(&project_id)
            .bind(&ingest_key_id)
            .bind(&object_id)
            .bind(format!("usage-guid-{index}"))
            .bind(i32::try_from(index)?)
            .bind(i64::try_from(index + 1)?)
            .execute(&pool)
            .await?;
        }
        let issue_id: String = sqlx::query_scalar(
            "INSERT INTO issues (id, organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint, title, first_seen_at, last_seen_at, event_count, representative_event_id) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'stack', 1, $3, 'Repeated crash', now(), now(), 5, $4::uuid) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind("a".repeat(64))
        .bind(&event_ids[0])
        .fetch_one(&pool)
        .await?;
        sqlx::query(
            "UPDATE crash_events SET grouping_state = 'grouped', fingerprint_algorithm = 'stack', fingerprint_version = 1, fingerprint = $4, variant_fingerprint = $5, grouping_quality = 100, grouped_at = now(), issue_id = $6::uuid WHERE organization_id = $1::uuid AND project_id = $2::uuid AND id = ANY(ARRAY(SELECT value::uuid FROM unnest($3::text[]) AS values(value)))",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&event_ids)
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .bind(&issue_id)
        .execute(&pool)
        .await?;
        let mut transaction = pool.begin().await?;
        for index in [0, 4, 3, 2, 1] {
            schedule_raw_retention_with_enforcement(
                &mut transaction,
                &organization_id,
                &project_id,
                &event_ids[index],
                true,
            )
            .await
            .map_err(|_| "raw retention must schedule")?;
        }
        schedule_raw_retention_with_enforcement(
            &mut transaction,
            &organization_id,
            &project_id,
            event_ids.last().ok_or("latest event must exist")?,
            true,
        )
        .await
        .map_err(|_| "raw retention must be idempotent")?;
        transaction.commit().await?;

        let rows = sqlx::query(
            "SELECT e.id::text AS event_id, e.raw_retention_class, o.lifecycle_state FROM crash_events e JOIN crash_event_objects o ON o.id = e.raw_object_id WHERE e.project_id = $1::uuid ORDER BY e.received_at, e.id",
        )
        .bind(&project_id)
        .fetch_all(&pool)
        .await?;
        assert_eq!(
            rows[0].get::<String, _>("raw_retention_class"),
            "representative"
        );
        assert_eq!(rows[1].get::<String, _>("raw_retention_class"), "deleting");
        assert_eq!(rows[2].get::<String, _>("raw_retention_class"), "recent");
        assert_eq!(rows[3].get::<String, _>("raw_retention_class"), "recent");
        assert_eq!(rows[4].get::<String, _>("raw_retention_class"), "recent");
        assert_eq!(rows[1].get::<String, _>("lifecycle_state"), "deleting");
        let deletion_jobs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM jobs WHERE project_id = $1::uuid AND job_type = 'delete_raw' AND priority = 50",
        )
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(deletion_jobs, 1);

        let repeated_event_id = rows[1].get::<String, _>("event_id");
        let repeated_object_id: String =
            sqlx::query_scalar("SELECT raw_object_id::text FROM crash_events WHERE id = $1::uuid")
                .bind(&repeated_event_id)
                .fetch_one(&pool)
                .await?;
        reconcile_storage(&database_url, &organization_id, &project_id).await?;
        let mut transaction = pool.begin().await?;
        for _ in 0..2 {
            record_raw_deleted(
                &mut transaction,
                &organization_id,
                &project_id,
                &repeated_event_id,
                &repeated_object_id,
                100,
            )
            .await
            .map_err(|_| "sampled raw deletion must record")?;
        }
        transaction.commit().await?;

        let expired_event_id = &event_ids[2];
        let expired_object_id: String = sqlx::query_scalar(
            "WITH event AS (UPDATE crash_events SET raw_retention_class = 'expired' WHERE id = $1::uuid RETURNING raw_object_id) UPDATE crash_event_objects o SET lifecycle_state = 'deleting' FROM event WHERE o.id = event.raw_object_id RETURNING o.id::text",
        )
        .bind(expired_event_id)
        .fetch_one(&pool)
        .await?;
        let mut transaction = pool.begin().await?;
        record_raw_deleted(
            &mut transaction,
            &organization_id,
            &project_id,
            expired_event_id,
            &expired_object_id,
            100,
        )
        .await
        .map_err(|_| "expired raw deletion must record")?;
        transaction.commit().await?;

        let counters = sqlx::query(
            "SELECT accepted_symbol_bytes, deleted_raw_bytes, sampled_raw_events, estimated_represented_events FROM usage_cycle_counters WHERE project_id = $1::uuid",
        )
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(counters.get::<i64, _>("accepted_symbol_bytes"), 500);
        assert_eq!(counters.get::<i64, _>("deleted_raw_bytes"), 200);
        assert_eq!(counters.get::<i64, _>("sampled_raw_events"), 1);
        assert_eq!(counters.get::<i64, _>("estimated_represented_events"), 100);
        let classes = sqlx::query(
            "SELECT e.id::text AS event_id, e.raw_retention_class, o.lifecycle_state FROM crash_events e JOIN crash_event_objects o ON o.id = e.raw_object_id WHERE e.id = ANY(ARRAY(SELECT value::uuid FROM unnest($1::text[]) AS values(value)))",
        )
        .bind(vec![expired_event_id.clone(), repeated_event_id.clone()])
        .fetch_all(&pool)
        .await?;
        assert!(classes.iter().any(|row| {
            row.get::<String, _>("event_id") == *expired_event_id
                && row.get::<String, _>("raw_retention_class") == "expired"
                && row.get::<String, _>("lifecycle_state") == "discarded"
        }));
        assert!(classes.iter().any(|row| {
            row.get::<String, _>("event_id") == repeated_event_id
                && row.get::<String, _>("raw_retention_class") == "discarded"
                && row.get::<String, _>("lifecycle_state") == "discarded"
        }));
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn storage_counters_and_deadlines_reconcile_without_drift() -> Result<(), Box<dyn Error>>
    {
        let database_url = std::env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url).await?;
        migrate(&database_url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await?;
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await?;
        let (user_id, organization_id, project_id) = seed_project(&pool).await?;
        let ingest_key_id: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, '22222222') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(vec![2_u8; 32])
        .fetch_one(&pool)
        .await?;
        let object_id: String = sqlx::query_scalar(
            "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'retention/current', $3, 100, 'application/octet-stream') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(vec![3_u8; 32])
        .fetch_one(&pool)
        .await?;
        let event_id: String = sqlx::query_scalar(
            "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, crash_guid, environment, received_at) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'retention-current', 'production', '2026-08-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&ingest_key_id)
        .bind(&object_id)
        .fetch_one(&pool)
        .await?;
        let mut transaction = pool.begin().await?;
        record_acceptance(
            &mut transaction,
            &organization_id,
            &project_id,
            &event_id,
            &object_id,
            100,
            false,
        )
        .await
        .map_err(|_| "raw acceptance must update storage")?;
        transaction.commit().await?;

        let upload_token_id: String = sqlx::query_scalar(
            "INSERT INTO artifact_upload_tokens (organization_id, project_id, created_by_user_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, '33333333') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&user_id)
        .bind(vec![4_u8; 32])
        .fetch_one(&pool)
        .await?;
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration) VALUES ($1::uuid, $2::uuid, 'retention-1', 'windows', 'x86_64', 'shipping') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        let artifact_object_id: String = sqlx::query_scalar(
            "INSERT INTO artifact_objects (organization_id, object_key, checksum, byte_size) VALUES ($1::uuid, 'retention/symbol', $2, 500) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(vec![5_u8; 32])
        .fetch_one(&pool)
        .await?;
        let debug_image_id: String = sqlx::query_scalar(
            "INSERT INTO artifact_debug_images (organization_id, object_id, artifact_type, module_name, architecture, debug_id) VALUES ($1::uuid, $2::uuid, 'pdb', 'Game.pdb', 'x86_64', 'RETENTION1') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&artifact_object_id)
        .fetch_one(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO release_manifest_artifacts (release_id, organization_id, project_id, debug_image_id, uploaded_by_user_id, upload_token_id, checksum, byte_size, artifact_type, module_name, architecture, debug_id, source_path, cli_version, state, uploaded_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid, $7, 500, 'pdb', 'Game.pdb', 'x86_64', 'RETENTION1', 'Game.pdb', 'test', 'available', now())",
        )
        .bind(&release_id)
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&debug_image_id)
        .bind(&user_id)
        .bind(&upload_token_id)
        .bind(vec![5_u8; 32])
        .execute(&pool)
        .await?;
        let mut transaction = pool.begin().await?;
        for _ in 0..2 {
            record_symbol_stored(
                &mut transaction,
                &organization_id,
                &project_id,
                &artifact_object_id,
                500,
            )
            .await
            .map_err(|_| "symbol storage must update once")?;
        }
        transaction.commit().await?;

        let initial = sqlx::query(
            "SELECT retained_raw_bytes, retained_symbol_bytes, reconciled_at IS NOT NULL AS reconciled FROM project_storage_counters WHERE organization_id = $1::uuid AND project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(initial.get::<i64, _>("retained_raw_bytes"), 100);
        assert_eq!(initial.get::<i64, _>("retained_symbol_bytes"), 500);
        assert!(initial.get::<bool, _>("reconciled"));
        let initial_deadline: String = sqlx::query_scalar(
            "SELECT to_char(raw_delete_after AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM crash_event_objects WHERE id = $1::uuid",
        )
        .bind(&object_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(initial_deadline, "2026-08-08T00:00:00Z");

        sqlx::query(
            "UPDATE project_usage_policies SET raw_retention_days = 1 WHERE organization_id = $1::uuid AND project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .execute(&pool)
        .await?;
        let legacy_object_id: String = sqlx::query_scalar(
            "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'retention/legacy', $3, 200, 'application/octet-stream') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(vec![6_u8; 32])
        .fetch_one(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, crash_guid, environment, received_at) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'retention-legacy', 'production', '2026-08-02T00:00:00Z')",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&ingest_key_id)
        .bind(&legacy_object_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            "UPDATE project_storage_counters SET retained_raw_bytes = 1, retained_symbol_bytes = 1, reconciled_at = NULL WHERE organization_id = $1::uuid AND project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .execute(&pool)
        .await?;
        assert_eq!(
            super::drain_expired_raw_v2(&pool, std::time::Duration::from_millis(10)).await?,
            0
        );
        let jobs_before_reconcile: i64 =
            sqlx::query_scalar("SELECT count(*) FROM jobs WHERE job_type = 'delete_raw'")
                .fetch_one(&pool)
                .await?;
        assert_eq!(jobs_before_reconcile, 0);
        let report = reconcile_storage(&database_url, &organization_id, &project_id).await?;
        assert_eq!(report.deadlines_backfilled, 1);
        assert_eq!(report.missing_deadlines, 0);
        assert_eq!(report.previous_raw_bytes, 1);
        assert_eq!(report.retained_raw_bytes, 300);
        assert_eq!(report.raw_byte_drift, 299);
        assert_eq!(report.previous_symbol_bytes, 1);
        assert_eq!(report.retained_symbol_bytes, 500);
        assert_eq!(report.symbol_byte_drift, 499);
        let deadlines = sqlx::query(
            "SELECT object_key, to_char(raw_delete_after AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS deadline FROM crash_event_objects WHERE project_id = $1::uuid ORDER BY object_key",
        )
        .bind(&project_id)
        .fetch_all(&pool)
        .await?;
        assert_eq!(deadlines[0].get::<String, _>("deadline"), initial_deadline);
        assert_eq!(
            deadlines[1].get::<String, _>("deadline"),
            "2026-08-09T00:00:00Z"
        );

        sqlx::query(
            "UPDATE crash_event_objects SET lifecycle_state = 'deleting' WHERE id = $1::uuid",
        )
        .bind(&object_id)
        .execute(&pool)
        .await?;
        sqlx::query("UPDATE crash_events SET raw_retention_class = 'expired' WHERE id = $1::uuid")
            .bind(&event_id)
            .execute(&pool)
            .await?;
        let mut gate = pool.begin().await?;
        sqlx::query(
            "SELECT 1 FROM project_storage_counters WHERE organization_id = $1::uuid AND project_id = $2::uuid FOR UPDATE",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&mut *gate)
        .await?;

        let deletion_pool = pool.clone();
        let deletion_organization_id = organization_id.clone();
        let deletion_project_id = project_id.clone();
        let deletion_event_id = event_id.clone();
        let deletion_object_id = object_id.clone();
        let deletion = tokio::spawn(async move {
            let mut transaction = deletion_pool
                .begin()
                .await
                .map_err(|_| "raw deletion transaction must start")?;
            for _ in 0..2 {
                record_raw_deleted(
                    &mut transaction,
                    &deletion_organization_id,
                    &deletion_project_id,
                    &deletion_event_id,
                    &deletion_object_id,
                    100,
                )
                .await
                .map_err(|_| "raw deletion must update once")?;
            }
            transaction
                .commit()
                .await
                .map_err(|_| "raw deletion transaction must commit")?;
            Ok::<(), &'static str>(())
        });

        let symbol_pool = pool.clone();
        let symbol_organization_id = organization_id.clone();
        let symbol_project_id = project_id.clone();
        let symbol_user_id = user_id.clone();
        let symbol_release_id = release_id.clone();
        let symbol_upload_token_id = upload_token_id.clone();
        let symbol = tokio::spawn(async move {
            let mut transaction = symbol_pool
                .begin()
                .await
                .map_err(|_| "symbol transaction must start")?;
            let object_id: String = sqlx::query_scalar(
                "INSERT INTO artifact_objects (organization_id, object_key, checksum, byte_size) VALUES ($1::uuid, 'retention/symbol-concurrent', $2, 500) RETURNING id::text",
            )
            .bind(&symbol_organization_id)
            .bind(vec![7_u8; 32])
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| "concurrent symbol object must store")?;
            let debug_image_id: String = sqlx::query_scalar(
                "INSERT INTO artifact_debug_images (organization_id, object_id, artifact_type, module_name, architecture, debug_id) VALUES ($1::uuid, $2::uuid, 'pdb', 'Game2.pdb', 'x86_64', 'RETENTION2') RETURNING id::text",
            )
            .bind(&symbol_organization_id)
            .bind(&object_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| "concurrent debug image must store")?;
            sqlx::query(
                "INSERT INTO release_manifest_artifacts (release_id, organization_id, project_id, debug_image_id, uploaded_by_user_id, upload_token_id, checksum, byte_size, artifact_type, module_name, architecture, debug_id, source_path, cli_version, state, uploaded_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid, $7, 500, 'pdb', 'Game2.pdb', 'x86_64', 'RETENTION2', 'Game2.pdb', 'test', 'available', now())",
            )
            .bind(&symbol_release_id)
            .bind(&symbol_organization_id)
            .bind(&symbol_project_id)
            .bind(&debug_image_id)
            .bind(&symbol_user_id)
            .bind(&symbol_upload_token_id)
            .bind(vec![7_u8; 32])
            .execute(&mut *transaction)
            .await
            .map_err(|_| "concurrent manifest must store")?;
            record_symbol_stored(
                &mut transaction,
                &symbol_organization_id,
                &symbol_project_id,
                &object_id,
                500,
            )
            .await
            .map_err(|_| "concurrent symbol counter must update")?;
            transaction
                .commit()
                .await
                .map_err(|_| "symbol transaction must commit")?;
            Ok::<(), &'static str>(())
        });

        let reconcile_database_url = database_url.clone();
        let reconcile_organization_id = organization_id.clone();
        let reconcile_project_id = project_id.clone();
        let concurrent_reconcile = tokio::spawn(async move {
            reconcile_storage(
                &reconcile_database_url,
                &reconcile_organization_id,
                &reconcile_project_id,
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        gate.commit().await?;
        deletion.await??;
        symbol.await??;
        concurrent_reconcile.await??;
        let final_totals = sqlx::query(
            "SELECT c.retained_raw_bytes, c.retained_symbol_bytes, (SELECT COALESCE(sum(byte_size), 0)::bigint FROM crash_event_objects WHERE organization_id = c.organization_id AND project_id = c.project_id AND lifecycle_state IN ('stored', 'deleting')) AS exact_raw_bytes, (SELECT COALESCE(sum(objects.byte_size), 0)::bigint FROM (SELECT DISTINCT ao.id, ao.byte_size FROM release_manifest_artifacts m JOIN artifact_debug_images d ON d.id = m.debug_image_id AND d.organization_id = m.organization_id JOIN artifact_objects ao ON ao.id = d.object_id AND ao.organization_id = d.organization_id WHERE m.organization_id = c.organization_id AND m.project_id = c.project_id AND m.state = 'available' AND ao.lifecycle_state = 'stored') objects) AS exact_symbol_bytes FROM project_storage_counters c WHERE c.organization_id = $1::uuid AND c.project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(final_totals.get::<i64, _>("retained_raw_bytes"), 200);
        assert_eq!(final_totals.get::<i64, _>("exact_raw_bytes"), 200);
        assert_eq!(final_totals.get::<i64, _>("retained_symbol_bytes"), 1_000);
        assert_eq!(final_totals.get::<i64, _>("exact_symbol_bytes"), 1_000);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    async fn default_retention_path_is_constant_at_one_million_raw_objects()
    -> Result<(), Box<dyn Error>> {
        let database_url = std::env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await?;
        let (_, organization_id, project_id) = seed_project(&pool).await?;
        let ingest_key_id: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, '44444444') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(vec![8_u8; 32])
        .fetch_one(&pool)
        .await?;
        let object_id: String = sqlx::query_scalar(
            "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'retention-million/target', $3, 1, 'application/octet-stream') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(vec![9_u8; 32])
        .fetch_one(&pool)
        .await?;
        let event_id: String = sqlx::query_scalar(
            "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, environment) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'production') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&ingest_key_id)
        .bind(&object_id)
        .fetch_one(&pool)
        .await?;
        let inserted: i64 = sqlx::query_scalar(
            "WITH generated AS MATERIALIZED (SELECT gen_random_uuid() AS object_id, gen_random_uuid() AS event_id, n FROM generate_series(1, 999999) AS values(n)), objects AS (INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) SELECT object_id, $1::uuid, $2::uuid, 'retention-million/' || n::text, decode(lpad(to_hex(n), 64, '0'), 'hex'), 1, 'application/octet-stream' FROM generated RETURNING id), events AS (INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, environment) SELECT generated.event_id, $1::uuid, $2::uuid, $3::uuid, generated.object_id, 'production' FROM generated JOIN objects ON objects.id = generated.object_id RETURNING 1) SELECT count(*)::bigint FROM events",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&ingest_key_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(inserted, 999_999);
        sqlx::query("ANALYZE crash_event_objects, crash_events")
            .execute(&pool)
            .await?;
        let plan_rows = sqlx::query(RETENTION_EVENT_EXPLAIN_QUERY)
            .bind(&event_id)
            .bind(&organization_id)
            .bind(&project_id)
            .fetch_all(&pool)
            .await?;
        let plan = plan_rows
            .iter()
            .map(|row| row.get::<String, _>("QUERY PLAN"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(plan.contains("crash_events_"), "{plan}");
        assert!(plan.contains("crash_event_objects_"), "{plan}");
        assert!(!plan.contains("Aggregate"), "{plan}");
        assert!(!plan.contains("Seq Scan on crash_event_objects"), "{plan}");
        assert!(!plan.contains("artifact_objects"), "{plan}");
        let mut transaction = pool.begin().await?;
        schedule_raw_retention_with_enforcement(
            &mut transaction,
            &organization_id,
            &project_id,
            &event_id,
            false,
        )
        .await
        .map_err(|_| "default retention path must complete")?;
        transaction.commit().await?;
        let class: String =
            sqlx::query_scalar("SELECT raw_retention_class FROM crash_events WHERE id = $1::uuid")
                .bind(&event_id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(class, "standard");
        println!("objects=1000000 plan=indexed default_path=standard\n{plan}");
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn concurrent_schedulers_drain_more_than_two_hundred_thousand_due_objects()
    -> Result<(), Box<dyn Error>> {
        let database_url = std::env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect(&database_url)
            .await?;
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await?;
        let (_, organization_id, first_project_id) = seed_project(&pool).await?;
        let second_project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Retention scale second', 'retention-scale-second') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await?;
        for (index, project_id) in [&first_project_id, &second_project_id]
            .into_iter()
            .enumerate()
        {
            let ingest_key_id: String = sqlx::query_scalar(
                "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, $4) RETURNING id::text",
            )
            .bind(&organization_id)
            .bind(project_id)
            .bind(vec![u8::try_from(index + 10)?; 32])
            .bind(format!("{index:08}"))
            .fetch_one(&pool)
            .await?;
            let inserted: i64 = sqlx::query_scalar(
                "WITH generated AS MATERIALIZED (SELECT gen_random_uuid() AS object_id, gen_random_uuid() AS event_id, n FROM generate_series(1, 100001) AS values(n)), objects AS (INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type, raw_delete_after) SELECT object_id, $1::uuid, $2::uuid, 'retention-scale/' || $2::text || '/' || n::text, decode(lpad(to_hex(n), 64, '0'), 'hex'), 1, 'application/octet-stream', now() - interval '1 minute' FROM generated RETURNING id), events AS (INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, environment, received_at) SELECT generated.event_id, $1::uuid, $2::uuid, $3::uuid, generated.object_id, 'production', now() - interval '8 days' FROM generated JOIN objects ON objects.id = generated.object_id RETURNING 1) SELECT count(*)::bigint FROM events",
            )
            .bind(&organization_id)
            .bind(project_id)
            .bind(&ingest_key_id)
            .fetch_one(&pool)
            .await?;
            assert_eq!(inserted, 100_001);
            let report = reconcile_storage(&database_url, &organization_id, project_id).await?;
            assert_eq!(report.retained_raw_bytes, 100_001);
            assert_eq!(report.missing_deadlines, 0);
        }
        sqlx::query("ANALYZE crash_event_objects, crash_events")
            .execute(&pool)
            .await?;
        let target_event_id: String = sqlx::query_scalar(
            "SELECT id::text FROM crash_events WHERE organization_id = $1::uuid AND project_id = $2::uuid ORDER BY id LIMIT 1",
        )
        .bind(&organization_id)
        .bind(&first_project_id)
        .fetch_one(&pool)
        .await?;
        let publication_plan_rows = sqlx::query(RETENTION_EVENT_EXPLAIN_QUERY)
            .bind(&target_event_id)
            .bind(&organization_id)
            .bind(&first_project_id)
            .fetch_all(&pool)
            .await?;
        let publication_plan = publication_plan_rows
            .iter()
            .map(|row| row.get::<String, _>("QUERY PLAN"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(publication_plan.contains("crash_events_"));
        assert!(publication_plan.contains("crash_event_objects_"));
        assert!(!publication_plan.contains("Aggregate"));
        assert!(!publication_plan.contains("Seq Scan on crash_event_objects"));
        assert!(!publication_plan.contains("artifact_objects"));
        let explain_rows = sqlx::query(
            "EXPLAIN (FORMAT TEXT) SELECT o.id FROM crash_event_objects o WHERE o.lifecycle_state = 'stored' AND o.raw_delete_after <= now() ORDER BY o.raw_delete_after, o.id FOR UPDATE OF o SKIP LOCKED LIMIT 5000",
        )
        .fetch_all(&pool)
        .await?;
        let explain = explain_rows
            .iter()
            .map(|row| row.get::<String, _>("QUERY PLAN"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(explain.contains("crash_event_objects_raw_due"), "{explain}");

        let started = Instant::now();
        let (first, second, third, fourth) = tokio::join!(
            drain_due_batches(pool.clone()),
            drain_due_batches(pool.clone()),
            drain_due_batches(pool.clone()),
            drain_due_batches(pool.clone())
        );
        let mut scheduled = first? + second? + third? + fourth?;
        loop {
            let remaining = schedule_expired_raw_v2_batch(&pool, 5_000).await?;
            scheduled = scheduled.saturating_add(remaining);
            if remaining == 0 {
                break;
            }
        }
        let elapsed = started.elapsed();
        assert_eq!(scheduled, 200_002);
        let elapsed_millis = i64::try_from(elapsed.as_millis())?.max(1);
        let throughput_per_second = scheduled.saturating_mul(1_000) / elapsed_millis;
        println!(
            "scheduled={scheduled} elapsed_ms={} throughput_per_second={throughput_per_second} plan=crash_event_objects_raw_due",
            elapsed.as_millis()
        );
        assert!(throughput_per_second > 2, "{throughput_per_second}");
        let state = sqlx::query(
            "SELECT (SELECT count(*) FROM crash_event_objects WHERE lifecycle_state = 'deleting') AS deleting_objects, (SELECT count(*) FROM crash_events WHERE raw_retention_class = 'expired') AS expired_events, (SELECT count(*) FROM jobs WHERE job_type = 'delete_raw') AS deletion_jobs, (SELECT count(DISTINCT idempotency_key) FROM jobs WHERE job_type = 'delete_raw') AS distinct_jobs, (SELECT COALESCE(sum(retained_raw_bytes), 0)::bigint FROM project_storage_counters WHERE organization_id = $1::uuid) AS retained_raw_bytes",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(state.get::<i64, _>("deleting_objects"), 200_002);
        assert_eq!(state.get::<i64, _>("expired_events"), 200_002);
        assert_eq!(state.get::<i64, _>("deletion_jobs"), 200_002);
        assert_eq!(state.get::<i64, _>("distinct_jobs"), 200_002);
        assert_eq!(state.get::<i64, _>("retained_raw_bytes"), 200_002);
        for project_id in [&first_project_id, &second_project_id] {
            let report = reconcile_storage(&database_url, &organization_id, project_id).await?;
            assert_eq!(report.raw_byte_drift, 0);
            assert_eq!(report.retained_raw_bytes, 100_001);
        }
        Ok(())
    }

    async fn drain_due_batches(pool: PgPool) -> Result<i64, super::SchedulerError> {
        let mut total = 0_i64;
        loop {
            let claimed = schedule_expired_raw_v2_batch(&pool, 5_000).await?;
            total = total.saturating_add(claimed);
            if claimed == 0 {
                return Ok(total);
            }
        }
    }

    async fn seed_project(pool: &PgPool) -> Result<(String, String, String), Box<dyn Error>> {
        let user_id: String = sqlx::query_scalar(
            "INSERT INTO users (bootstrap_subject, email) VALUES ('local-bootstrap', 'usage-owner@example.com') RETURNING id::text",
        )
        .fetch_one(pool)
        .await?;
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Usage org', 'usage-org') RETURNING id::text",
        )
        .fetch_one(pool)
        .await?;
        sqlx::query(
            "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')",
        )
        .bind(&organization_id)
        .bind(&user_id)
        .execute(pool)
        .await?;
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Usage project', 'usage-project') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(pool)
        .await?;
        Ok((user_id, organization_id, project_id))
    }

    async fn request(
        state: &ServerState,
        method: &str,
        project_id: &str,
        body: Option<Value>,
        authenticated: bool,
    ) -> Result<axum::response::Response, Box<dyn Error>> {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("/api/v1/projects/{project_id}/usage"));
        if authenticated {
            request = request.header(header::AUTHORIZATION, format!("Bootstrap {SECRET}"));
        }
        let body = if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        } else {
            Body::empty()
        };
        Ok(router("api", state.clone())
            .oneshot(request.body(body)?)
            .await?)
    }

    async fn response_json(response: axum::response::Response) -> Result<Value, Box<dyn Error>> {
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}
