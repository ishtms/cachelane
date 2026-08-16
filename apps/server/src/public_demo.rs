use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::Path as FilePath,
    sync::Arc,
};

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, KeyInit, Mac};
use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use sqlx::{PgConnection, Row};

use crate::{identifiers::valid_uuid, project_setup::ServerState};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_RATE_LIMIT: u32 = 120;
const MAX_RATE_LIMIT: u32 = 600;
const MAX_ISSUES: usize = 50;
const MAX_VARIANTS: usize = 32;
const MAX_RELEASES: usize = 32;
const MAX_THREADS: usize = 16;
const MAX_FRAMES: usize = 64;
const MAX_INLINES: usize = 16;
const MAX_MISSING_SYMBOLS: usize = 32;

#[derive(Clone, Default)]
pub(crate) struct PublicDemo {
    config: Option<Arc<PublicDemoConfig>>,
}

struct PublicDemoConfig {
    organization_id: String,
    project_id: String,
    rate_limit: u32,
    rate_secret: Arc<[u8]>,
    trusted_proxies: Arc<[IpNet]>,
}

impl PublicDemo {
    pub(crate) fn from_environment(role: &str) -> Result<Self, &'static str> {
        let enabled = env::var("FAULTLANE_PUBLIC_DEMO_ENABLED")
            .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
        if !enabled || role != "api" {
            return Ok(Self::default());
        }
        let organization_id = env::var("FAULTLANE_PUBLIC_DEMO_ORGANIZATION_ID")
            .map_err(|_| "public demo organization is required")?;
        let project_id = env::var("FAULTLANE_PUBLIC_DEMO_PROJECT_ID")
            .map_err(|_| "public demo project is required")?;
        if !valid_uuid(&organization_id) || !valid_uuid(&project_id) {
            return Err("public demo scope is invalid");
        }
        let rate_secret = env::var("FAULTLANE_RATE_LIMIT_SECRET")
            .map_err(|_| "public demo rate limit secret is required")?;
        if rate_secret.len() < 32 {
            return Err("public demo rate limit secret is invalid");
        }
        let rate_limit = env::var("FAULTLANE_PUBLIC_DEMO_RATE_LIMIT_PER_MINUTE")
            .ok()
            .map(|value| value.parse::<u32>())
            .transpose()
            .map_err(|_| "public demo rate limit is invalid")?
            .unwrap_or(DEFAULT_RATE_LIMIT);
        if !(1..=MAX_RATE_LIMIT).contains(&rate_limit) {
            return Err("public demo rate limit is invalid");
        }
        let trusted_proxies = env::var("FAULTLANE_TRUSTED_PROXY_CIDRS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::parse::<IpNet>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "public demo trusted proxies are invalid")?;
        Ok(Self {
            config: Some(Arc::new(PublicDemoConfig {
                organization_id,
                project_id,
                rate_limit,
                rate_secret: Arc::from(rate_secret.into_bytes()),
                trusted_proxies: Arc::from(trusted_proxies),
            })),
        })
    }

    #[cfg(test)]
    pub(crate) fn test(organization_id: &str, project_id: &str, rate_limit: u32) -> Self {
        Self {
            config: Some(Arc::new(PublicDemoConfig {
                organization_id: organization_id.to_owned(),
                project_id: project_id.to_owned(),
                rate_limit,
                rate_secret: Arc::from(&b"public-demo-test-rate-secret-32-bytes"[..]),
                trusted_proxies: Arc::from(Vec::<IpNet>::new()),
            })),
        }
    }
}

#[derive(Debug)]
pub(crate) enum PublicDemoError {
    InvalidRequest,
    NotFound,
    RateLimited { limit: u32 },
    Unavailable,
    Internal,
}

impl IntoResponse for PublicDemoError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request is invalid",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "resource was not found"),
            Self::RateLimited { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "public demo request limit exceeded",
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "demo_unavailable",
                "public demo is unavailable",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "request could not be completed",
            ),
        };
        let mut response = no_store_json(status, &ErrorBody { code, message });
        if let Self::RateLimited { limit } = self {
            set_rate_headers(response.headers_mut(), limit, 0);
        }
        response
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct DemoInfo {
    title: &'static str,
    engine: &'static str,
    synthetic: bool,
    read_only: bool,
    issue_count: i64,
    last_seen_at: Option<String>,
}

#[derive(Serialize)]
struct DemoIssueList {
    synthetic: bool,
    read_only: bool,
    items: Vec<DemoIssueSummary>,
    truncated: bool,
}

#[derive(Serialize)]
struct DemoIssueSummary {
    key: String,
    path: String,
    title: String,
    fingerprint: String,
    fingerprint_version: i32,
    status: String,
    regression_state: String,
    first_seen_at: String,
    last_seen_at: String,
    event_count: i64,
    affected_release_count: i64,
    symbolication_state: String,
    crash_type: Option<String>,
    reprocessed: bool,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct DemoIssueDetail {
    synthetic: bool,
    read_only: bool,
    #[serde(flatten)]
    issue: DemoIssueSummary,
    variants: Vec<DemoVariant>,
    variants_truncated: bool,
    releases: Vec<DemoRelease>,
    releases_truncated: bool,
    threads: Vec<DemoThread>,
    threads_truncated: bool,
    missing_symbols: Vec<DemoMissingSymbol>,
    missing_symbols_truncated: bool,
}

#[derive(Serialize)]
struct DemoVariant {
    fingerprint: String,
    first_seen_at: String,
    last_seen_at: String,
    event_count: i64,
}

#[derive(Serialize)]
struct DemoRelease {
    version: String,
    platform: String,
    architecture: String,
    configuration: String,
    first_seen_at: String,
    last_seen_at: String,
    event_count: i64,
}

#[derive(Serialize)]
struct DemoThread {
    thread_id: i64,
    faulting: bool,
    frames: Vec<DemoFrame>,
    frames_truncated: bool,
}

#[derive(Serialize)]
struct DemoFrame {
    module: Option<String>,
    function: Option<String>,
    source_file: Option<String>,
    source_line: Option<u64>,
    inlines: Vec<DemoInline>,
    inlines_truncated: bool,
}

#[derive(Serialize)]
struct DemoInline {
    function: String,
    source_file: Option<String>,
    source_line: Option<u64>,
}

#[derive(Serialize)]
struct DemoMissingSymbol {
    required_artifact: String,
    module: String,
    architecture: String,
}

struct DemoScope<'a> {
    organization_id: &'a str,
    project_id: &'a str,
}

pub(crate) async fn get_demo(
    State(state): State<ServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, PublicDemoError> {
    let (config, rate) = authorize_read(&state, peer.ip(), &headers).await?;
    let pool = state.control_pool().ok_or(PublicDemoError::Internal)?;
    let scope = configured_scope(pool, &config).await?;
    let row = sqlx::query(
        "SELECT count(*) AS issue_count, CASE WHEN max(last_seen_at) IS NULL THEN NULL ELSE to_char(max(last_seen_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS last_seen_at FROM issues WHERE organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(scope.organization_id)
    .bind(scope.project_id)
    .fetch_one(pool)
    .await
    .map_err(|_| PublicDemoError::Unavailable)?;
    let mut response = public_json(
        StatusCode::OK,
        &DemoInfo {
            title: "FaultLane UE 5.8 crash demo",
            engine: "Unreal Engine 5.8",
            synthetic: true,
            read_only: true,
            issue_count: row.get("issue_count"),
            last_seen_at: row.get("last_seen_at"),
        },
    );
    set_rate_headers(response.headers_mut(), config.rate_limit, rate);
    Ok(response)
}

pub(crate) async fn health(State(state): State<ServerState>) -> Result<Response, PublicDemoError> {
    let config = state
        .public_demo()
        .config
        .clone()
        .ok_or(PublicDemoError::Unavailable)?;
    let pool = state.control_pool().ok_or(PublicDemoError::Unavailable)?;
    configured_scope(pool, &config).await?;
    Ok(no_store_json(
        StatusCode::OK,
        &serde_json::json!({"status": "ready"}),
    ))
}

pub(crate) async fn list_issues(
    State(state): State<ServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, PublicDemoError> {
    let (config, rate) = authorize_read(&state, peer.ip(), &headers).await?;
    let pool = state.control_pool().ok_or(PublicDemoError::Internal)?;
    let scope = configured_scope(pool, &config).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| PublicDemoError::Unavailable)?;
    configure_read_transaction(&mut transaction).await?;
    let rows = sqlx::query(
        "SELECT i.id::text AS issue_id, i.title, i.fingerprint_version, i.fingerprint, i.status, i.regression_state, to_char(i.first_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS first_seen_at, to_char(i.last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, i.event_count, (SELECT count(*) FROM issue_releases ir WHERE ir.organization_id = i.organization_id AND ir.project_id = i.project_id AND ir.issue_id = i.id) AS affected_release_count, COALESCE(s.symbolication_state, CASE WHEN e.processing_state IN ('failed', 'quarantined') THEN 'failed' WHEN e.processing_state = 'awaiting_symbols' THEN 'missing' ELSE 'processing' END) AS symbolication_state, s.crash_type, COALESCE(r.processing_version > 1, false) AS reprocessed FROM issues i JOIN crash_events e ON e.id = i.representative_event_id AND e.organization_id = i.organization_id AND e.project_id = i.project_id LEFT JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id LEFT JOIN crash_processing_results r ON r.id = e.current_result_id AND r.organization_id = e.organization_id AND r.project_id = e.project_id AND r.event_id = e.id WHERE i.organization_id = $1::uuid AND i.project_id = $2::uuid ORDER BY i.last_seen_at DESC, i.id DESC LIMIT $3",
    )
    .bind(scope.organization_id)
    .bind(scope.project_id)
    .bind(i64::try_from(MAX_ISSUES + 1).map_err(|_| PublicDemoError::Internal)?)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| PublicDemoError::Internal)?;
    transaction
        .commit()
        .await
        .map_err(|_| PublicDemoError::Internal)?;
    let truncated = rows.len() > MAX_ISSUES;
    let items = rows
        .iter()
        .take(MAX_ISSUES)
        .map(issue_summary)
        .collect::<Vec<_>>();
    let mut response = public_json(
        StatusCode::OK,
        &DemoIssueList {
            synthetic: true,
            read_only: true,
            items,
            truncated,
        },
    );
    set_rate_headers(response.headers_mut(), config.rate_limit, rate);
    Ok(response)
}

pub(crate) async fn get_issue(
    State(state): State<ServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(issue_key): Path<String>,
) -> Result<Response, PublicDemoError> {
    let (fingerprint_version, fingerprint) = parse_issue_key(&issue_key)?;
    let (config, rate) = authorize_read(&state, peer.ip(), &headers).await?;
    let pool = state.control_pool().ok_or(PublicDemoError::Internal)?;
    let scope = configured_scope(pool, &config).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| PublicDemoError::Unavailable)?;
    configure_read_transaction(&mut transaction).await?;
    let row = sqlx::query(
        "SELECT i.id::text AS issue_id, i.title, i.fingerprint_version, i.fingerprint, i.status, i.regression_state, to_char(i.first_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS first_seen_at, to_char(i.last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, i.event_count, i.representative_event_id::text AS representative_event_id, (SELECT count(*) FROM issue_releases ir WHERE ir.organization_id = i.organization_id AND ir.project_id = i.project_id AND ir.issue_id = i.id) AS affected_release_count, COALESCE(s.symbolication_state, CASE WHEN e.processing_state IN ('failed', 'quarantined') THEN 'failed' WHEN e.processing_state = 'awaiting_symbols' THEN 'missing' ELSE 'processing' END) AS symbolication_state, s.crash_type, COALESCE(r.processing_version > 1, false) AS reprocessed, r.result FROM issues i JOIN crash_events e ON e.id = i.representative_event_id AND e.organization_id = i.organization_id AND e.project_id = i.project_id LEFT JOIN crash_event_search s ON s.organization_id = e.organization_id AND s.project_id = e.project_id AND s.event_id = e.id AND s.result_id = e.current_result_id LEFT JOIN crash_processing_results r ON r.id = e.current_result_id AND r.organization_id = e.organization_id AND r.project_id = e.project_id AND r.event_id = e.id WHERE i.organization_id = $1::uuid AND i.project_id = $2::uuid AND i.fingerprint_version = $3 AND i.fingerprint = $4",
    )
    .bind(scope.organization_id)
    .bind(scope.project_id)
    .bind(fingerprint_version)
    .bind(&fingerprint)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| PublicDemoError::Internal)?
    .ok_or(PublicDemoError::NotFound)?;
    let issue_id: String = row.get("issue_id");
    let representative_event_id: String = row.get("representative_event_id");
    let variants = load_variants(&mut transaction, &scope, &issue_id).await?;
    let releases = load_releases(&mut transaction, &scope, &issue_id).await?;
    let missing_symbols =
        load_missing_symbols(&mut transaction, &scope, &representative_event_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| PublicDemoError::Internal)?;
    let result: Option<Value> = row.get("result");
    let (threads, threads_truncated) = result.as_ref().map(public_threads).unwrap_or_default();
    let variants_truncated = variants.len() > MAX_VARIANTS;
    let releases_truncated = releases.len() > MAX_RELEASES;
    let missing_symbols_truncated = missing_symbols.len() > MAX_MISSING_SYMBOLS;
    let mut response = public_json(
        StatusCode::OK,
        &DemoIssueDetail {
            synthetic: true,
            read_only: true,
            issue: issue_summary(&row),
            variants: variants.into_iter().take(MAX_VARIANTS).collect(),
            variants_truncated,
            releases: releases.into_iter().take(MAX_RELEASES).collect(),
            releases_truncated,
            threads,
            threads_truncated,
            missing_symbols: missing_symbols
                .into_iter()
                .take(MAX_MISSING_SYMBOLS)
                .collect(),
            missing_symbols_truncated,
        },
    );
    set_rate_headers(response.headers_mut(), config.rate_limit, rate);
    Ok(response)
}

async fn authorize_read(
    state: &ServerState,
    peer: IpAddr,
    headers: &HeaderMap,
) -> Result<(Arc<PublicDemoConfig>, u32), PublicDemoError> {
    let config = state
        .public_demo()
        .config
        .clone()
        .ok_or(PublicDemoError::Unavailable)?;
    let source = source_ip(peer, headers, &config.trusted_proxies)?;
    let remaining = apply_rate_limit(state, &config, source).await?;
    Ok((config, remaining))
}

async fn configured_scope<'a>(
    pool: &sqlx::PgPool,
    config: &'a PublicDemoConfig,
) -> Result<DemoScope<'a>, PublicDemoError> {
    let configured = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM projects p JOIN organizations o ON o.id = p.organization_id WHERE p.id = $1::uuid AND p.organization_id = $2::uuid AND p.slug LIKE 'synthetic-demo-%' AND o.slug LIKE 'synthetic-demo-%')",
    )
    .bind(&config.project_id)
    .bind(&config.organization_id)
    .fetch_one(pool)
    .await
    .map_err(|_| PublicDemoError::Unavailable)?;
    if !configured {
        return Err(PublicDemoError::Unavailable);
    }
    Ok(DemoScope {
        organization_id: &config.organization_id,
        project_id: &config.project_id,
    })
}

async fn configure_read_transaction(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PublicDemoError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut **connection)
        .await
        .map_err(|_| PublicDemoError::Internal)?;
    sqlx::query("SET LOCAL statement_timeout = '2s'")
        .execute(&mut **connection)
        .await
        .map_err(|_| PublicDemoError::Internal)?;
    Ok(())
}

async fn apply_rate_limit(
    state: &ServerState,
    config: &PublicDemoConfig,
    source: IpAddr,
) -> Result<u32, PublicDemoError> {
    let pool = state.control_pool().ok_or(PublicDemoError::Internal)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| PublicDemoError::Unavailable)?;
    let bucket_start = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM date_trunc('minute', now())))::bigint",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| PublicDemoError::Unavailable)?;
    let mut mac =
        HmacSha256::new_from_slice(&config.rate_secret).map_err(|_| PublicDemoError::Internal)?;
    mac.update(b"public-demo");
    mac.update(source.to_string().as_bytes());
    let subject_hash = mac.finalize().into_bytes().to_vec();
    let count = sqlx::query_scalar::<_, i32>(
        "INSERT INTO ingest_rate_limits (organization_id, project_id, scope, subject_hash, bucket_start, expires_at, requests) VALUES ($1::uuid, $2::uuid, 'ip', $3, to_timestamp($4), to_timestamp($4) + interval '2 minutes', 1) ON CONFLICT (organization_id, project_id, scope, subject_hash, bucket_start) DO UPDATE SET requests = ingest_rate_limits.requests + 1 RETURNING requests",
    )
    .bind(&config.organization_id)
    .bind(&config.project_id)
    .bind(subject_hash)
    .bind(bucket_start)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| PublicDemoError::Unavailable)?;
    let count = u32::try_from(count).map_err(|_| PublicDemoError::Internal)?;
    if count > config.rate_limit {
        transaction
            .rollback()
            .await
            .map_err(|_| PublicDemoError::Unavailable)?;
        return Err(PublicDemoError::RateLimited {
            limit: config.rate_limit,
        });
    }
    transaction
        .commit()
        .await
        .map_err(|_| PublicDemoError::Unavailable)?;
    Ok(config.rate_limit.saturating_sub(count))
}

async fn load_variants(
    connection: &mut PgConnection,
    scope: &DemoScope<'_>,
    issue_id: &str,
) -> Result<Vec<DemoVariant>, PublicDemoError> {
    let rows = sqlx::query(
        "SELECT variant_fingerprint, to_char(first_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS first_seen_at, to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, event_count FROM issue_variants WHERE organization_id = $1::uuid AND project_id = $2::uuid AND issue_id = $3::uuid ORDER BY event_count DESC, variant_fingerprint LIMIT $4",
    )
    .bind(scope.organization_id)
    .bind(scope.project_id)
    .bind(issue_id)
    .bind(i64::try_from(MAX_VARIANTS + 1).map_err(|_| PublicDemoError::Internal)?)
    .fetch_all(connection)
    .await
    .map_err(|_| PublicDemoError::Internal)?;
    Ok(rows
        .iter()
        .map(|row| DemoVariant {
            fingerprint: row.get("variant_fingerprint"),
            first_seen_at: row.get("first_seen_at"),
            last_seen_at: row.get("last_seen_at"),
            event_count: row.get("event_count"),
        })
        .collect())
}

async fn load_releases(
    connection: &mut PgConnection,
    scope: &DemoScope<'_>,
    issue_id: &str,
) -> Result<Vec<DemoRelease>, PublicDemoError> {
    let rows = sqlx::query(
        "SELECT r.version, r.platform, r.architecture, r.configuration, to_char(ir.first_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS first_seen_at, to_char(ir.last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, ir.event_count FROM issue_releases ir JOIN releases r ON r.id = ir.release_id AND r.organization_id = ir.organization_id AND r.project_id = ir.project_id WHERE ir.organization_id = $1::uuid AND ir.project_id = $2::uuid AND ir.issue_id = $3::uuid ORDER BY ir.last_seen_at DESC, r.version LIMIT $4",
    )
    .bind(scope.organization_id)
    .bind(scope.project_id)
    .bind(issue_id)
    .bind(i64::try_from(MAX_RELEASES + 1).map_err(|_| PublicDemoError::Internal)?)
    .fetch_all(connection)
    .await
    .map_err(|_| PublicDemoError::Internal)?;
    Ok(rows
        .iter()
        .map(|row| DemoRelease {
            version: bounded(&row.get::<String, _>("version"), 128),
            platform: bounded(&row.get::<String, _>("platform"), 32),
            architecture: bounded(&row.get::<String, _>("architecture"), 32),
            configuration: bounded(&row.get::<String, _>("configuration"), 32),
            first_seen_at: row.get("first_seen_at"),
            last_seen_at: row.get("last_seen_at"),
            event_count: row.get("event_count"),
        })
        .collect())
}

async fn load_missing_symbols(
    connection: &mut PgConnection,
    scope: &DemoScope<'_>,
    event_id: &str,
) -> Result<Vec<DemoMissingSymbol>, PublicDemoError> {
    let rows = sqlx::query(
        "SELECT required_artifact, module_name, architecture FROM crash_symbol_waiters WHERE organization_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid ORDER BY module_name, required_artifact LIMIT $4",
    )
    .bind(scope.organization_id)
    .bind(scope.project_id)
    .bind(event_id)
    .bind(i64::try_from(MAX_MISSING_SYMBOLS + 1).map_err(|_| PublicDemoError::Internal)?)
    .fetch_all(connection)
    .await
    .map_err(|_| PublicDemoError::Internal)?;
    Ok(rows
        .iter()
        .map(|row| DemoMissingSymbol {
            required_artifact: row.get("required_artifact"),
            module: bounded(&row.get::<String, _>("module_name"), 128),
            architecture: bounded(&row.get::<String, _>("architecture"), 32),
        })
        .collect())
}

fn issue_summary(row: &sqlx::postgres::PgRow) -> DemoIssueSummary {
    let fingerprint_version: i32 = row.get("fingerprint_version");
    let fingerprint: String = row.get("fingerprint");
    let key = issue_key(fingerprint_version, &fingerprint);
    DemoIssueSummary {
        path: format!("/demo/issues/{key}"),
        key,
        title: bounded(&row.get::<String, _>("title"), 200),
        fingerprint,
        fingerprint_version,
        status: row.get("status"),
        regression_state: row.get("regression_state"),
        first_seen_at: row.get("first_seen_at"),
        last_seen_at: row.get("last_seen_at"),
        event_count: row.get("event_count"),
        affected_release_count: row.get("affected_release_count"),
        symbolication_state: row.get("symbolication_state"),
        crash_type: row
            .get::<Option<String>, _>("crash_type")
            .map(|value| bounded(&value, 64)),
        reprocessed: row.get("reprocessed"),
    }
}

fn public_threads(result: &Value) -> (Vec<DemoThread>, bool) {
    let Some(values) = result
        .pointer("/current/symbolication/threads")
        .and_then(Value::as_array)
    else {
        return (Vec::new(), false);
    };
    let truncated = values.len() > MAX_THREADS;
    let threads = values
        .iter()
        .take(MAX_THREADS)
        .filter_map(|thread| {
            let object = thread.as_object()?;
            let frames = object.get("frames")?.as_array()?;
            Some(DemoThread {
                thread_id: object.get("thread_id")?.as_i64()?,
                faulting: object
                    .get("faulting")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                frames: frames
                    .iter()
                    .take(MAX_FRAMES)
                    .filter_map(public_frame)
                    .collect(),
                frames_truncated: frames.len() > MAX_FRAMES,
            })
        })
        .collect();
    (threads, truncated)
}

fn public_frame(value: &Value) -> Option<DemoFrame> {
    let object = value.as_object()?;
    let inline_values = object
        .get("inlines")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    Some(DemoFrame {
        module: object
            .get("module")
            .and_then(Value::as_str)
            .map(|value| bounded(value, 128)),
        function: object
            .get("function")
            .and_then(Value::as_str)
            .map(|value| bounded(value, 256)),
        source_file: object
            .get("source_file")
            .and_then(Value::as_str)
            .and_then(safe_file_name),
        source_line: object.get("source_line").and_then(Value::as_u64),
        inlines: inline_values
            .iter()
            .take(MAX_INLINES)
            .filter_map(|inline| {
                let inline = inline.as_object()?;
                Some(DemoInline {
                    function: bounded(inline.get("function")?.as_str()?, 256),
                    source_file: inline
                        .get("source_file")
                        .and_then(Value::as_str)
                        .and_then(safe_file_name),
                    source_line: inline.get("source_line").and_then(Value::as_u64),
                })
            })
            .collect(),
        inlines_truncated: inline_values.len() > MAX_INLINES,
    })
}

fn safe_file_name(value: &str) -> Option<String> {
    let normalized = value.replace('\\', "/");
    let name = FilePath::new(&normalized).file_name()?.to_str()?;
    (!name.is_empty()).then(|| bounded(name, 128))
}

fn issue_key(version: i32, fingerprint: &str) -> String {
    format!("{version}-{fingerprint}")
}

fn parse_issue_key(value: &str) -> Result<(i32, String), PublicDemoError> {
    let (version, fingerprint) = value
        .split_once('-')
        .ok_or(PublicDemoError::InvalidRequest)?;
    let version = version
        .parse::<i32>()
        .map_err(|_| PublicDemoError::InvalidRequest)?;
    if version <= 0
        || fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(PublicDemoError::InvalidRequest);
    }
    Ok((version, fingerprint.to_owned()))
}

fn bounded(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn source_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> Result<IpAddr, PublicDemoError> {
    if !trusted_proxies
        .iter()
        .any(|network| network.contains(&peer))
    {
        return Ok(peer);
    }
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .ok_or(PublicDemoError::InvalidRequest)?;
    let mut chain = forwarded
        .split(',')
        .map(str::trim)
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| PublicDemoError::InvalidRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() || chain.len() > 16 {
        return Err(PublicDemoError::InvalidRequest);
    }
    chain.push(peer);
    chain
        .into_iter()
        .rev()
        .find(|address| {
            !trusted_proxies
                .iter()
                .any(|network| network.contains(address))
        })
        .ok_or(PublicDemoError::InvalidRequest)
}

fn public_json(status: StatusCode, value: &impl Serialize) -> Response {
    let mut response = no_store_json(status, value);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=15, stale-while-revalidate=30"),
    );
    response
}

fn no_store_json(status: StatusCode, value: &impl Serialize) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(value),
    )
        .into_response()
}

fn set_rate_headers(headers: &mut HeaderMap, limit: u32, remaining: u32) {
    if let Ok(value) = HeaderValue::from_str(&limit.to_string()) {
        headers.insert("ratelimit-limit", value);
    }
    if let Ok(value) = HeaderValue::from_str(&remaining.to_string()) {
        headers.insert("ratelimit-remaining", value);
    }
    headers.insert("ratelimit-reset", HeaderValue::from_static("60"));
}

#[cfg(test)]
#[path = "public_demo_tests.rs"]
mod tests;
