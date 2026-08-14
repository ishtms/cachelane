use std::{
    env, fmt,
    net::{IpAddr, SocketAddr},
    path::{Path as FilePath, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use faultlane_domain::ProcessingState;
use faultlane_unreal::{CrashRequestLimits, inspect_crash_envelope};
use futures_util::StreamExt;
use hmac::{Hmac, KeyInit, Mac};
use ipnet::IpNet;
use object_store::{
    ClientOptions, ObjectStore, ObjectStoreExt, PutPayload, RetryConfig, aws::AmazonS3Builder,
    memory::InMemory, path::Path as ObjectPath,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tokio::{fs, io::AsyncWriteExt, time::Instant};
use url::Url;

use crate::project_setup::{KeyScope, ServerState, StartupError};

const MAX_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MULTIPART_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const MAX_UPLOAD_SECONDS: u64 = 120;
const DEFAULT_PROJECT_LIMIT: u32 = 120;
const DEFAULT_IP_LIMIT: u32 = 60;
const MAX_QUERY_BYTES: usize = 2048;
const MAX_GUID_BYTES: usize = 128;
const MAX_RELEASE_CANDIDATES: usize = 100;
const RATE_LIMIT_PROJECT: &str = "project";
const RATE_LIMIT_IP: &str = "ip";
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub(crate) struct CrashIngest {
    pool: Option<PgPool>,
    objects: Arc<dyn ObjectStore>,
    spool_directory: Arc<PathBuf>,
    rate_secret: Arc<[u8]>,
    trusted_proxies: Arc<Vec<IpNet>>,
    project_limit: u32,
    ip_limit: u32,
    enabled: bool,
}

impl CrashIngest {
    pub(crate) fn postgres(pool: PgPool, role: &'static str) -> Result<Self, StartupError> {
        if role == "api" {
            let mut state = Self::disabled();
            state.pool = Some(pool);
            if env::var("FAULTLANE_DASHBOARD_ENABLED")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true"))
                && env::var("FAULTLANE_RAW_ARTIFACT_DOWNLOAD_ENABLED")
                    .is_ok_and(|value| value.eq_ignore_ascii_case("true"))
            {
                state.objects = configured_objects()?;
            }
            return Ok(state);
        }
        if role != "ingest" {
            return Ok(Self::disabled());
        }

        let objects = configured_objects()?;
        let spool_directory = env::var("FAULTLANE_INGEST_SPOOL_DIR")
            .map_or_else(|_| env::temp_dir().join("faultlane-ingest"), PathBuf::from);
        validate_spool_directory(&spool_directory)?;
        cleanup_stale_spools(&spool_directory)?;
        let rate_secret = required_env("FAULTLANE_RATE_LIMIT_SECRET")?;
        if rate_secret.len() < 32 {
            return Err(StartupError::IngestConfiguration);
        }
        let trusted_proxy_value = env::var("FAULTLANE_TRUSTED_PROXY_CIDRS").ok();
        let trusted_proxies = parse_cidrs(trusted_proxy_value.as_deref())?;
        let project_limit = parse_limit("FAULTLANE_PROJECT_RATE_LIMIT", DEFAULT_PROJECT_LIMIT)?;
        let ip_limit = parse_limit("FAULTLANE_IP_RATE_LIMIT", DEFAULT_IP_LIMIT)?;

        Ok(Self {
            pool: Some(pool),
            objects,
            spool_directory: Arc::new(spool_directory),
            rate_secret: Arc::from(rate_secret.into_bytes()),
            trusted_proxies: Arc::new(trusted_proxies),
            project_limit,
            ip_limit,
            enabled: true,
        })
    }

    fn disabled() -> Self {
        Self {
            pool: None,
            objects: Arc::new(InMemory::new()),
            spool_directory: Arc::new(env::temp_dir().join("faultlane-ingest-disabled")),
            rate_secret: Arc::from(&b"disabled-disabled-disabled-disabled"[..]),
            trusted_proxies: Arc::new(Vec::new()),
            project_limit: DEFAULT_PROJECT_LIMIT,
            ip_limit: DEFAULT_IP_LIMIT,
            enabled: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn memory() -> Self {
        Self::disabled()
    }

    #[cfg(test)]
    pub(crate) fn control_test(pool: PgPool) -> Self {
        Self {
            pool: Some(pool),
            ..Self::disabled()
        }
    }

    #[cfg(test)]
    pub(crate) fn control_test_with_objects(pool: PgPool, objects: Arc<dyn ObjectStore>) -> Self {
        Self {
            pool: Some(pool),
            objects,
            ..Self::disabled()
        }
    }

    #[cfg(test)]
    fn test(pool: PgPool, objects: Arc<dyn ObjectStore>, spool_directory: PathBuf) -> Self {
        validate_spool_directory(&spool_directory)
            .unwrap_or_else(|error| panic!("test spool directory must be valid: {error}"));
        Self {
            pool: Some(pool),
            objects,
            spool_directory: Arc::new(spool_directory),
            rate_secret: Arc::from(&b"test-rate-limit-secret-32-bytes-long"[..]),
            trusted_proxies: Arc::new(Vec::new()),
            project_limit: DEFAULT_PROJECT_LIMIT,
            ip_limit: DEFAULT_IP_LIMIT,
            enabled: true,
        }
    }

    fn pool(&self) -> Result<&PgPool, IngestError> {
        self.pool.as_ref().ok_or(IngestError::Unavailable)
    }

    pub(crate) async fn get_raw_object(
        &self,
        key: &str,
        expected_size: u64,
    ) -> Result<object_store::GetResult, RawObjectError> {
        let result = self
            .objects
            .get(&ObjectPath::from(key.to_owned()))
            .await
            .map_err(|error| {
                if matches!(error, object_store::Error::NotFound { .. }) {
                    RawObjectError::Missing
                } else {
                    RawObjectError::Unavailable
                }
            })?;
        let actual_size = result.meta.size;
        if actual_size != expected_size || actual_size > MAX_COMPRESSED_BYTES {
            return Err(RawObjectError::Invalid);
        }
        Ok(result)
    }

    pub(crate) fn start_maintenance(&self) {
        if !self.enabled {
            return;
        }
        let ingest = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_mins(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                reconcile_orphans(&ingest).await;
            }
        });
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RawObjectError {
    Unavailable,
    Missing,
    Invalid,
}

fn configured_objects() -> Result<Arc<dyn ObjectStore>, StartupError> {
    let object_store_endpoint = required_env("OBJECT_STORE_ENDPOINT")?;
    let object_store_bucket = required_env("OBJECT_STORE_BUCKET")?;
    let object_store_access_key =
        required_env("OBJECT_STORE_ACCESS_KEY").or_else(|_| required_env("MINIO_ROOT_USER"))?;
    let object_store_secret_key =
        required_env("OBJECT_STORE_SECRET_KEY").or_else(|_| required_env("MINIO_ROOT_PASSWORD"))?;
    let endpoint =
        Url::parse(&object_store_endpoint).map_err(|_| StartupError::IngestConfiguration)?;
    if endpoint.scheme() != "https"
        && !(endpoint.scheme() == "http"
            && endpoint
                .host_str()
                .and_then(|value| value.parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback()))
    {
        return Err(StartupError::IngestConfiguration);
    }
    let retry = RetryConfig {
        max_retries: 2,
        retry_timeout: Duration::from_secs(5),
        ..RetryConfig::default()
    };
    let objects = AmazonS3Builder::new()
        .with_bucket_name(object_store_bucket)
        .with_region(env::var("OBJECT_STORE_REGION").unwrap_or_else(|_| "us-east-1".into()))
        .with_endpoint(object_store_endpoint)
        .with_access_key_id(object_store_access_key)
        .with_secret_access_key(object_store_secret_key)
        .with_allow_http(endpoint.scheme() == "http")
        .with_virtual_hosted_style_request(false)
        .with_retry(retry)
        .with_client_options(
            ClientOptions::new()
                .with_allow_http(endpoint.scheme() == "http")
                .with_connect_timeout(Duration::from_secs(3))
                .with_timeout(Duration::from_secs(30)),
        )
        .build()
        .map_err(|_| StartupError::IngestConfiguration)?;
    Ok(Arc::new(objects))
}

#[derive(Default)]
pub(crate) struct UnrealQuery {
    app_id: String,
    app_version: String,
    app_environment: String,
    upload_type: String,
    user_id: String,
}

impl UnrealQuery {
    fn parse(raw: Option<&str>) -> Result<Self, IngestError> {
        let raw = raw.ok_or(IngestError::InvalidRequest)?;
        if raw.len() > MAX_QUERY_BYTES {
            return Err(IngestError::InvalidRequest);
        }
        let mut query = Self::default();
        let mut seen = std::collections::HashSet::new();
        for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            if !seen.insert(name.clone()) {
                return Err(IngestError::InvalidRequest);
            }
            match name.as_ref() {
                "AppID" => query.app_id = value.into_owned(),
                "AppVersion" => query.app_version = value.into_owned(),
                "AppEnvironment" => query.app_environment = value.into_owned(),
                "UploadType" => query.upload_type = value.into_owned(),
                "UserID" => query.user_id = value.into_owned(),
                _ => return Err(IngestError::InvalidRequest),
            }
        }
        Ok(query)
    }
}

#[derive(Serialize)]
struct AcceptedCrash {
    event_id: String,
    state: ProcessingState,
    deduplicated: bool,
    received_at: String,
    status_path: String,
}

#[derive(Serialize)]
struct EventState {
    event_id: String,
    project_id: String,
    environment: String,
    crash_guid: Option<String>,
    state: ProcessingState,
    reason: Option<String>,
    retryable: bool,
    retry_at: Option<String>,
    grouping_state: String,
    fingerprint_algorithm: Option<String>,
    fingerprint_version: Option<i32>,
    fingerprint: Option<String>,
    variant_fingerprint: Option<String>,
    grouping_quality: Option<i32>,
    issue_id: Option<String>,
    issue_path: Option<String>,
    release_mapping_state: String,
    release_id: Option<String>,
    candidate_release_ids: Vec<String>,
    candidate_release_ids_truncated: bool,
    received_at: String,
    updated_at: String,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

#[derive(Debug)]
pub(crate) enum IngestError {
    NotFound,
    InvalidRequest,
    RequestTooLarge,
    RateLimited { limit: u32, remaining: u32 },
    Unavailable,
    CommitUncertain,
    Internal,
}

impl IntoResponse for IngestError {
    fn into_response(self) -> Response {
        let (status, code, message, retryable) = match self {
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "resource was not found",
                false,
            ),
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid_crash_request",
                "crash request is invalid",
                false,
            ),
            Self::RequestTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "crash request exceeds the configured limit",
                false,
            ),
            Self::RateLimited { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "crash request rate limit exceeded",
                true,
            ),
            Self::Unavailable | Self::CommitUncertain => (
                StatusCode::SERVICE_UNAVAILABLE,
                "ingest_unavailable",
                "crash ingestion is temporarily unavailable",
                true,
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "request could not be completed",
                true,
            ),
        };
        let mut response = (
            status,
            Json(ErrorBody {
                code,
                message,
                retryable,
            }),
        )
            .into_response();
        set_no_store(response.headers_mut());
        if let Self::RateLimited { limit, remaining } = self {
            set_rate_headers(response.headers_mut(), limit, remaining);
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        response
    }
}

pub(crate) async fn submit_crash(
    State(state): State<ServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(key): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, IngestError> {
    let ingest = state.crash_ingest();
    let scope = state
        .resolve_ingest_scope(&key)
        .await
        .map_err(|_| IngestError::Internal)?
        .ok_or(IngestError::NotFound)?;
    if !ingest.enabled {
        return Err(IngestError::Unavailable);
    }
    let source_ip = source_ip(peer.ip(), &headers, &ingest.trusted_proxies)?;
    if !scope.allowed_cidrs.is_empty()
        && !scope
            .allowed_cidrs
            .iter()
            .any(|network| network.contains(&source_ip))
    {
        return Err(IngestError::NotFound);
    }
    let rate = apply_rate_limits(ingest, &scope, source_ip).await?;
    let query = UnrealQuery::parse(raw_query.as_deref())?;
    validate_request_headers(&headers, &query)?;

    let event_id = random_uuid()?;
    let object_id = random_uuid()?;
    let object_key = format!(
        "org/{}/project/{}/events/{event_id}/raw.bundle",
        scope.organization_id, scope.project_id
    );
    let spool_path = ingest
        .spool_directory
        .join(format!("faultlane-{event_id}.spool"));

    register_pending_object(ingest, &scope, &object_key).await?;

    let stored = store_request(ingest, &object_key, &spool_path, body).await;
    if stored.is_err() {
        let _ = fs::remove_file(&spool_path).await;
        cleanup_object(ingest, &scope, &object_key).await;
    }
    let stored = stored?;
    let manifest = inspect_spool(&spool_path).await;
    let _ = fs::remove_file(&spool_path).await;
    let manifest = match manifest {
        Ok(manifest) => manifest,
        Err(error) => {
            cleanup_object(ingest, &scope, &object_key).await;
            return Err(error);
        }
    };
    let crash_guid = usable_crash_guid(&manifest.directory_name, &manifest.archive_name);
    let accepted = persist_event(
        ingest,
        &scope,
        &event_id,
        &object_id,
        &object_key,
        &stored,
        crash_guid.as_deref(),
    )
    .await;
    let accepted = match accepted {
        Ok(value) => value,
        Err(IngestError::CommitUncertain) => return Err(IngestError::CommitUncertain),
        Err(error) => {
            cleanup_object(ingest, &scope, &object_key).await;
            return Err(error);
        }
    };
    if accepted.deduplicated {
        cleanup_object(ingest, &scope, &object_key).await;
    }
    let mut response = (StatusCode::ACCEPTED, Json(accepted)).into_response();
    set_no_store(response.headers_mut());
    set_rate_headers(response.headers_mut(), rate.limit, rate.remaining);
    Ok(response)
}

pub(crate) async fn get_event_state(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((project_id, event_id)): Path<(String, String)>,
) -> Result<Response, IngestError> {
    if !state.authorize_control(&headers) {
        return Err(IngestError::NotFound);
    }
    let pool = state.crash_ingest().pool()?;
    let row = sqlx::query(
        "SELECT e.id::text AS event_id, e.project_id::text AS project_id, e.environment, e.crash_guid, e.processing_state, e.state_reason, e.retryable, CASE WHEN e.retry_at IS NULL THEN NULL ELSE to_char(e.retry_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS retry_at, e.grouping_state, e.fingerprint_algorithm, e.fingerprint_version, e.fingerprint, e.variant_fingerprint, e.grouping_quality, e.issue_id::text AS issue_id, e.release_mapping_state, e.release_id::text AS release_id, ARRAY(SELECT c.release_id::text FROM crash_event_release_candidates c WHERE c.organization_id = e.organization_id AND c.project_id = e.project_id AND c.event_id = e.id ORDER BY c.release_id LIMIT 101) AS candidate_release_ids, to_char(e.received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS received_at, to_char(e.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at FROM crash_events e JOIN projects p ON p.id = e.project_id AND p.organization_id = e.organization_id JOIN organization_memberships m ON m.organization_id = p.organization_id AND m.role = 'owner' JOIN users u ON u.id = m.user_id WHERE u.bootstrap_subject = 'local-bootstrap' AND p.id::text = $1 AND e.id::text = $2",
    )
    .bind(&project_id)
    .bind(event_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| IngestError::Internal)?
    .ok_or(IngestError::NotFound)?;
    let issue_id: Option<String> = row.get("issue_id");
    let (candidate_release_ids, candidate_release_ids_truncated) =
        bounded_candidate_release_ids(row.get("candidate_release_ids"));
    let event = EventState {
        event_id: row.get("event_id"),
        project_id: row.get("project_id"),
        environment: row.get("environment"),
        crash_guid: row.get("crash_guid"),
        state: processing_state(&row.get::<String, _>("processing_state"))?,
        reason: row.get("state_reason"),
        retryable: row.get("retryable"),
        retry_at: row.get("retry_at"),
        grouping_state: row.get("grouping_state"),
        fingerprint_algorithm: row.get("fingerprint_algorithm"),
        fingerprint_version: row.get("fingerprint_version"),
        fingerprint: row.get("fingerprint"),
        variant_fingerprint: row.get("variant_fingerprint"),
        grouping_quality: row.get("grouping_quality"),
        issue_path: issue_id
            .as_ref()
            .map(|issue_id| format!("/api/v1/projects/{project_id}/issues/{issue_id}")),
        issue_id,
        release_mapping_state: row.get("release_mapping_state"),
        release_id: row.get("release_id"),
        candidate_release_ids,
        candidate_release_ids_truncated,
        received_at: row.get("received_at"),
        updated_at: row.get("updated_at"),
    };
    let mut response = (StatusCode::OK, Json(event)).into_response();
    set_no_store(response.headers_mut());
    Ok(response)
}

struct StoredRequest {
    checksum: Vec<u8>,
    byte_size: u64,
}

async fn store_request(
    ingest: &CrashIngest,
    object_key: &str,
    spool_path: &FilePath,
    body: Body,
) -> Result<StoredRequest, IngestError> {
    let mut spool = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(spool_path)
        .await
        .map_err(|_| IngestError::Unavailable)?;
    let location = ObjectPath::from(object_key.to_owned());
    let mut upload = ingest
        .objects
        .put_multipart(&location)
        .await
        .map_err(|_| IngestError::Unavailable)?;
    let mut stream = body.into_data_stream();
    let mut digest = Sha256::new();
    let mut byte_size = 0_u64;
    let mut part = Vec::with_capacity(MULTIPART_CHUNK_BYTES);
    let deadline = Instant::now() + Duration::from_secs(MAX_UPLOAD_SECONDS);

    loop {
        let Ok(next) = tokio::time::timeout_at(deadline, stream.next()).await else {
            let _ = upload.abort().await;
            return Err(IngestError::Unavailable);
        };
        let Some(chunk) = next else {
            break;
        };
        let Ok(chunk) = chunk else {
            let _ = upload.abort().await;
            return Err(IngestError::InvalidRequest);
        };
        let Some(next_size) = byte_size.checked_add(chunk.len() as u64) else {
            let _ = upload.abort().await;
            return Err(IngestError::RequestTooLarge);
        };
        byte_size = next_size;
        if byte_size > MAX_COMPRESSED_BYTES {
            let _ = upload.abort().await;
            return Err(IngestError::RequestTooLarge);
        }
        digest.update(&chunk);
        if spool.write_all(&chunk).await.is_err() {
            let _ = upload.abort().await;
            return Err(IngestError::Unavailable);
        }
        let mut remaining = chunk.as_ref();
        while !remaining.is_empty() {
            let count = (MULTIPART_CHUNK_BYTES - part.len()).min(remaining.len());
            part.extend_from_slice(&remaining[..count]);
            remaining = &remaining[count..];
            if part.len() == MULTIPART_CHUNK_BYTES {
                let payload = PutPayload::from(std::mem::take(&mut part));
                let result = tokio::time::timeout_at(deadline, upload.put_part(payload)).await;
                if !matches!(result, Ok(Ok(()))) {
                    let _ = upload.abort().await;
                    return Err(IngestError::Unavailable);
                }
                part = Vec::with_capacity(MULTIPART_CHUNK_BYTES);
            }
        }
    }
    if byte_size == 0 {
        let _ = upload.abort().await;
        return Err(IngestError::InvalidRequest);
    }
    if spool.sync_all().await.is_err() {
        let _ = upload.abort().await;
        return Err(IngestError::Unavailable);
    }
    if !part.is_empty() {
        let result =
            tokio::time::timeout_at(deadline, upload.put_part(PutPayload::from(part))).await;
        if !matches!(result, Ok(Ok(()))) {
            let _ = upload.abort().await;
            return Err(IngestError::Unavailable);
        }
    }
    let completed = tokio::time::timeout_at(deadline, upload.complete()).await;
    if !matches!(completed, Ok(Ok(_))) {
        let _ = upload.abort().await;
        return Err(IngestError::Unavailable);
    }
    Ok(StoredRequest {
        checksum: digest.finalize().to_vec(),
        byte_size,
    })
}

async fn inspect_spool(
    path: &FilePath,
) -> Result<faultlane_unreal::CrashRequestManifest, IngestError> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(path).map_err(|_| IngestError::Unavailable)?;
        inspect_crash_envelope(file, CrashRequestLimits::default())
            .map_err(|_| IngestError::InvalidRequest)
    })
    .await
    .map_err(|_| IngestError::Internal)?
}

async fn cleanup_object(ingest: &CrashIngest, scope: &KeyScope, object_key: &str) {
    let location = ObjectPath::from(object_key.to_owned());
    if ingest.objects.delete(&location).await.is_ok() {
        clear_orphan(ingest, object_key).await;
        return;
    }
    let Some(pool) = &ingest.pool else {
        return;
    };
    let _ = sqlx::query(
        "INSERT INTO ingest_orphan_objects (object_key, organization_id, project_id, attempts) VALUES ($1, $2::uuid, $3::uuid, 1) ON CONFLICT (object_key) DO UPDATE SET attempts = ingest_orphan_objects.attempts + 1, last_error_at = now()",
    )
    .bind(object_key)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .execute(pool)
    .await;
}

async fn register_pending_object(
    ingest: &CrashIngest,
    scope: &KeyScope,
    object_key: &str,
) -> Result<(), IngestError> {
    sqlx::query(
        "INSERT INTO ingest_orphan_objects (object_key, organization_id, project_id) VALUES ($1, $2::uuid, $3::uuid)",
    )
    .bind(object_key)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .execute(ingest.pool()?)
    .await
    .map_err(|_| IngestError::Unavailable)?;
    Ok(())
}

async fn clear_orphan(ingest: &CrashIngest, object_key: &str) {
    let Some(pool) = &ingest.pool else {
        return;
    };
    let _ = sqlx::query("DELETE FROM ingest_orphan_objects WHERE object_key = $1")
        .bind(object_key)
        .execute(pool)
        .await;
}

async fn reconcile_orphans(ingest: &CrashIngest) {
    let Some(pool) = &ingest.pool else {
        return;
    };
    let Ok(rows) = sqlx::query(
        "SELECT object_key FROM ingest_orphan_objects WHERE attempts > 0 OR created_at < now() - interval '1 hour' ORDER BY last_error_at, object_key LIMIT 16",
    )
    .fetch_all(pool)
    .await
    else {
        return;
    };
    for row in rows {
        let object_key: String = row.get("object_key");
        if ingest
            .objects
            .delete(&ObjectPath::from(object_key.clone()))
            .await
            .is_ok()
        {
            let _ = sqlx::query("DELETE FROM ingest_orphan_objects WHERE object_key = $1")
                .bind(object_key)
                .execute(pool)
                .await;
        } else {
            let _ = sqlx::query(
                "UPDATE ingest_orphan_objects SET attempts = attempts + 1, last_error_at = now() WHERE object_key = $1",
            )
            .bind(object_key)
            .execute(pool)
            .await;
        }
    }
}

async fn persist_event(
    ingest: &CrashIngest,
    scope: &KeyScope,
    event_id: &str,
    object_id: &str,
    object_key: &str,
    stored: &StoredRequest,
    crash_guid: Option<&str>,
) -> Result<AcceptedCrash, IngestError> {
    let pool = ingest.pool()?;
    let mut transaction = pool.begin().await.map_err(|_| IngestError::Unavailable)?;
    if let Some(guid) = crash_guid
        && let Some(row) = sqlx::query(
            "SELECT id::text AS event_id, processing_state, to_char(received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS received_at FROM crash_events WHERE project_id = $1::uuid AND crash_guid = $2",
        )
        .bind(&scope.project_id)
        .bind(guid)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| IngestError::Unavailable)?
    {
        transaction
            .rollback()
            .await
            .map_err(|_| IngestError::Unavailable)?;
        return Ok(accepted_response(
            row.get("event_id"),
            processing_state(&row.get::<String, _>("processing_state"))?,
            row.get("received_at"),
            true,
            &scope.project_id,
        ));
    }
    sqlx::query(
        "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, 'application/octet-stream')",
    )
    .bind(object_id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(object_key)
    .bind(&stored.checksum)
    .bind(i64::try_from(stored.byte_size).map_err(|_| IngestError::RequestTooLarge)?)
    .execute(&mut *transaction)
    .await
    .map_err(|_| IngestError::Unavailable)?;
    let row = sqlx::query(
        "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, crash_guid, environment, processing_state) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, $7, 'stored') ON CONFLICT (project_id, crash_guid) WHERE crash_guid IS NOT NULL DO NOTHING RETURNING to_char(received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS received_at",
    )
    .bind(event_id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&scope.key_id)
    .bind(object_id)
    .bind(crash_guid)
    .bind(&scope.environment)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| IngestError::Unavailable)?;
    let Some(row) = row else {
        transaction
            .rollback()
            .await
            .map_err(|_| IngestError::Unavailable)?;
        let existing = sqlx::query(
            "SELECT id::text AS event_id, processing_state, to_char(received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS received_at FROM crash_events WHERE project_id = $1::uuid AND crash_guid = $2",
        )
        .bind(&scope.project_id)
        .bind(crash_guid.ok_or(IngestError::Internal)?)
        .fetch_one(pool)
        .await
        .map_err(|_| IngestError::Unavailable)?;
        return Ok(accepted_response(
            existing.get("event_id"),
            processing_state(&existing.get::<String, _>("processing_state"))?,
            existing.get("received_at"),
            true,
            &scope.project_id,
        ));
    };
    sqlx::query(
        "INSERT INTO jobs (id, organization_id, project_id, event_id, job_type, payload, idempotency_key) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'process_crash', jsonb_build_object('event_id', $4::text), $5)",
    )
    .bind(random_uuid()?)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(event_id)
    .bind(format!("process_crash:{event_id}"))
    .execute(&mut *transaction)
    .await
    .map_err(|_| IngestError::Unavailable)?;
    sqlx::query("DELETE FROM ingest_orphan_objects WHERE object_key = $1")
        .bind(object_key)
        .execute(&mut *transaction)
        .await
        .map_err(|_| IngestError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| IngestError::CommitUncertain)?;
    Ok(accepted_response(
        event_id.to_owned(),
        ProcessingState::Stored,
        row.get("received_at"),
        false,
        &scope.project_id,
    ))
}

struct RateResult {
    limit: u32,
    remaining: u32,
}

async fn apply_rate_limits(
    ingest: &CrashIngest,
    scope: &KeyScope,
    source_ip: IpAddr,
) -> Result<RateResult, IngestError> {
    let pool = ingest.pool()?;
    let mut transaction = pool.begin().await.map_err(|_| IngestError::Unavailable)?;
    let bucket_start = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM date_trunc('minute', now())))::bigint",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| IngestError::Unavailable)?;
    let mut mac =
        HmacSha256::new_from_slice(&ingest.rate_secret).map_err(|_| IngestError::Internal)?;
    mac.update(source_ip.to_string().as_bytes());
    mac.update(&bucket_start.to_le_bytes());
    let ip_hash = mac.finalize().into_bytes().to_vec();
    let project_hash = Sha256::digest(scope.project_id.as_bytes()).to_vec();
    sqlx::query(
        "WITH expired AS (SELECT organization_id, project_id, scope, subject_hash, bucket_start FROM ingest_rate_limits WHERE expires_at <= now() ORDER BY expires_at LIMIT 128 FOR UPDATE SKIP LOCKED) DELETE FROM ingest_rate_limits limits USING expired WHERE limits.organization_id = expired.organization_id AND limits.project_id = expired.project_id AND limits.scope = expired.scope AND limits.subject_hash = expired.subject_hash AND limits.bucket_start = expired.bucket_start",
    )
    .execute(&mut *transaction)
    .await
    .map_err(|_| IngestError::Unavailable)?;
    let project_count = increment_rate(
        &mut transaction,
        scope,
        RATE_LIMIT_PROJECT,
        &project_hash,
        bucket_start,
    )
    .await?;
    let ip_count = increment_rate(
        &mut transaction,
        scope,
        RATE_LIMIT_IP,
        &ip_hash,
        bucket_start,
    )
    .await?;
    if project_count > ingest.project_limit || ip_count > ingest.ip_limit {
        transaction
            .rollback()
            .await
            .map_err(|_| IngestError::Unavailable)?;
        let limit = ingest.project_limit.min(ingest.ip_limit);
        return Err(IngestError::RateLimited {
            limit,
            remaining: 0,
        });
    }
    transaction
        .commit()
        .await
        .map_err(|_| IngestError::Unavailable)?;
    let limit = ingest.project_limit.min(ingest.ip_limit);
    Ok(RateResult {
        limit,
        remaining: ingest
            .project_limit
            .saturating_sub(project_count)
            .min(ingest.ip_limit.saturating_sub(ip_count)),
    })
}

async fn increment_rate(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &KeyScope,
    kind: &str,
    subject_hash: &[u8],
    bucket_start: i64,
) -> Result<u32, IngestError> {
    let count = sqlx::query_scalar::<_, i32>(
        "INSERT INTO ingest_rate_limits (organization_id, project_id, scope, subject_hash, bucket_start, expires_at, requests) VALUES ($1::uuid, $2::uuid, $3, $4, to_timestamp($5), to_timestamp($5) + interval '2 minutes', 1) ON CONFLICT (organization_id, project_id, scope, subject_hash, bucket_start) DO UPDATE SET requests = ingest_rate_limits.requests + 1 RETURNING requests",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(kind)
    .bind(subject_hash)
    .bind(bucket_start)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| IngestError::Unavailable)?;
    u32::try_from(count).map_err(|_| IngestError::Internal)
}

fn validate_request_headers(headers: &HeaderMap, query: &UnrealQuery) -> Result<(), IngestError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if content_type != Some("application/octet-stream") || query.upload_type != "crashreports" {
        return Err(IngestError::InvalidRequest);
    }
    let query_bytes = query.app_id.len()
        + query.app_version.len()
        + query.app_environment.len()
        + query.upload_type.len()
        + query.user_id.len();
    if query_bytes > MAX_QUERY_BYTES {
        return Err(IngestError::InvalidRequest);
    }
    if let Some(value) = headers.get(header::CONTENT_LENGTH) {
        let length = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(IngestError::InvalidRequest)?;
        if length > MAX_COMPRESSED_BYTES {
            return Err(IngestError::RequestTooLarge);
        }
    }
    Ok(())
}

fn source_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> Result<IpAddr, IngestError> {
    if !trusted_proxies
        .iter()
        .any(|network| network.contains(&peer))
    {
        return Ok(peer);
    }
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .ok_or(IngestError::InvalidRequest)?;
    let mut chain = forwarded
        .split(',')
        .map(str::trim)
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| IngestError::InvalidRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() || chain.len() > 16 {
        return Err(IngestError::InvalidRequest);
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
        .ok_or(IngestError::InvalidRequest)
}

fn usable_crash_guid(directory: &str, archive: &str) -> Option<String> {
    let valid = directory.starts_with("UECC-")
        && directory.len() <= MAX_GUID_BYTES
        && directory
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        && archive == format!("{directory}.uecrash");
    valid.then(|| directory.to_owned())
}

fn accepted_response(
    event_id: String,
    state: ProcessingState,
    received_at: String,
    deduplicated: bool,
    project_id: &str,
) -> AcceptedCrash {
    AcceptedCrash {
        status_path: format!("/api/v1/projects/{project_id}/events/{event_id}"),
        event_id,
        state,
        deduplicated,
        received_at,
    }
}

fn processing_state(value: &str) -> Result<ProcessingState, IngestError> {
    match value {
        "received" => Ok(ProcessingState::Received),
        "stored" => Ok(ProcessingState::Stored),
        "parsed" => Ok(ProcessingState::Parsed),
        "awaiting_symbols" => Ok(ProcessingState::AwaitingSymbols),
        "symbolicating" => Ok(ProcessingState::Symbolicating),
        "processed" => Ok(ProcessingState::Processed),
        "failed" => Ok(ProcessingState::Failed),
        "quarantined" => Ok(ProcessingState::Quarantined),
        _ => Err(IngestError::Internal),
    }
}

fn bounded_candidate_release_ids(mut candidates: Vec<String>) -> (Vec<String>, bool) {
    let truncated = candidates.len() > MAX_RELEASE_CANDIDATES;
    candidates.truncate(MAX_RELEASE_CANDIDATES);
    (candidates, truncated)
}

fn random_uuid() -> Result<String, IngestError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| IngestError::Internal)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

fn validate_spool_directory(path: &FilePath) -> Result<(), StartupError> {
    std::fs::create_dir_all(path).map_err(|_| StartupError::IngestConfiguration)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| StartupError::IngestConfiguration)?;
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| StartupError::IngestConfiguration)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(StartupError::IngestConfiguration);
    }
    Ok(())
}

fn cleanup_stale_spools(path: &FilePath) -> Result<(), StartupError> {
    let now = SystemTime::now();
    let entries = std::fs::read_dir(path).map_err(|_| StartupError::IngestConfiguration)?;
    for entry in entries.take(128) {
        let entry = entry.map_err(|_| StartupError::IngestConfiguration)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let metadata = entry
            .metadata()
            .map_err(|_| StartupError::IngestConfiguration)?;
        if metadata.is_file()
            && name.starts_with("faultlane-")
            && name.ends_with(".spool")
            && metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age >= Duration::from_hours(1))
        {
            std::fs::remove_file(entry.path()).map_err(|_| StartupError::IngestConfiguration)?;
        }
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String, StartupError> {
    env::var(name).map_err(|_| StartupError::IngestConfiguration)
}

fn parse_limit(name: &str, default: u32) -> Result<u32, StartupError> {
    let value = match env::var(name) {
        Ok(value) => value
            .parse::<u32>()
            .map_err(|_| StartupError::IngestConfiguration)?,
        Err(_) => default,
    };
    if value == 0 {
        return Err(StartupError::IngestConfiguration);
    }
    Ok(value)
}

fn parse_cidrs(value: Option<&str>) -> Result<Vec<IpNet>, StartupError> {
    value
        .unwrap_or_default()
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .map(|value| IpNet::from_str(value.trim()).map_err(|_| StartupError::IngestConfiguration))
        .collect()
}

fn set_no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
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

impl fmt::Debug for CrashIngest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrashIngest")
            .field("enabled", &self.enabled)
            .field("spool_directory", &self.spool_directory)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("project_limit", &self.project_limit)
            .field("ip_limit", &self.ip_limit)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        io::Write,
        net::{IpAddr, Ipv4Addr},
        path::PathBuf,
        sync::Arc,
    };

    #[cfg(unix)]
    use super::validate_spool_directory;
    use super::{
        CrashIngest, UnrealQuery, bounded_candidate_release_ids, random_uuid, source_ip,
        usable_crash_guid,
    };
    use crate::project_setup::{DATABASE_TEST_LOCK, ServerState, migrate, router};
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    };
    use flate2::{Compression, write::ZlibEncoder};
    use futures_util::TryStreamExt;
    use ipnet::IpNet;
    use object_store::{ObjectStore, ObjectStoreExt, memory::InMemory};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use sqlx::{PgPool, Row};
    use tower::ServiceExt;

    const SECRET: &str = "test-bootstrap-secret-at-least-32-bytes";

    #[test]
    fn accepts_only_matching_unreal_guid_names() {
        assert_eq!(
            usable_crash_guid(
                "UECC-Windows-0123456789ABCDEF_0000",
                "UECC-Windows-0123456789ABCDEF_0000.uecrash"
            )
            .as_deref(),
            Some("UECC-Windows-0123456789ABCDEF_0000")
        );
        assert!(usable_crash_guid("../UECC-secret", "../UECC-secret.uecrash").is_none());
        assert!(usable_crash_guid("UECC-safe", "other.uecrash").is_none());
    }

    #[test]
    fn ignores_forwarding_headers_from_untrusted_peers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.8"));
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(source_ip(peer, &headers, &[]).ok(), Some(peer));
        let trusted = vec![
            "127.0.0.0/8"
                .parse::<IpNet>()
                .unwrap_or_else(|error| panic!("test network must be valid: {error}")),
        ];
        assert_eq!(
            source_ip(peer, &headers, &trusted).ok(),
            "198.51.100.8".parse::<IpAddr>().ok()
        );

        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("192.0.2.1, 198.51.100.8"),
        );
        assert_eq!(
            source_ip(peer, &headers, &trusted).ok(),
            "198.51.100.8".parse::<IpAddr>().ok()
        );
        let trusted_chain = vec![
            "127.0.0.0/8"
                .parse::<IpNet>()
                .unwrap_or_else(|error| panic!("test network must be valid: {error}")),
            "198.51.100.0/24"
                .parse::<IpNet>()
                .unwrap_or_else(|error| panic!("test network must be valid: {error}")),
        ];
        assert_eq!(
            source_ip(peer, &headers, &trusted_chain).ok(),
            "192.0.2.1".parse::<IpAddr>().ok()
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_oversized_query_values() {
        assert!(
            UnrealQuery::parse(Some(
                "AppID=Game&AppVersion=1&AppEnvironment=Shipping&UploadType=crashreports&UserID=user"
            ))
            .is_ok()
        );
        assert!(UnrealQuery::parse(Some("UploadType=crashreports&Future=value")).is_err());
        assert!(
            UnrealQuery::parse(Some("UploadType=crashreports&UploadType=crashreports")).is_err()
        );
        assert!(UnrealQuery::parse(Some(&"a".repeat(super::MAX_QUERY_BYTES + 1))).is_err());
    }

    #[test]
    fn candidate_release_evidence_is_bounded() {
        let candidates = (0..=super::MAX_RELEASE_CANDIDATES)
            .map(|index| index.to_string())
            .collect();
        let (candidates, truncated) = bounded_candidate_release_ids(candidates);
        assert_eq!(candidates.len(), super::MAX_RELEASE_CANDIDATES);
        assert!(truncated);
    }

    #[cfg(unix)]
    #[test]
    fn secures_the_spool_directory() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;

        let directory = test_spool_directory()?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777))?;
        validate_spool_directory(&directory).map_err(|_| "spool directory must be valid")?;
        let mode = std::fs::metadata(&directory)?.permissions().mode() & 0o777;
        std::fs::remove_dir(&directory)?;
        assert_eq!(mode, 0o700);
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn persists_one_object_and_job_for_duplicate_requests_when_configured()
    -> Result<(), Box<dyn Error>> {
        let Ok(database_url) = std::env::var("FAULTLANE_TEST_DATABASE_URL") else {
            return Ok(());
        };
        let _guard = DATABASE_TEST_LOCK.lock().await;
        assert_isolated_database(&database_url);
        migrate(&database_url).await?;
        migrate(&database_url).await?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await?;
        let (project_id, key) = seed_project(&pool).await?;
        let objects = Arc::new(InMemory::new());
        let spool_directory = test_spool_directory()?;
        let ingest = CrashIngest::test(pool.clone(), objects.clone(), spool_directory.clone());
        let state = ServerState::ingest_test(pool.clone(), ingest, SECRET);
        let request = crash_request(
            "UECC-Windows-Synthetic",
            b"<FGenericCrashContext><RuntimeProperties /></FGenericCrashContext>",
        )?;

        let first = submit(&state, &key, request.clone()).await?;
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let first = json_body(first).await?;
        assert_eq!(first["deduplicated"], false);
        assert_eq!(first["state"], "stored");
        let event_id = first["event_id"]
            .as_str()
            .ok_or("event id must exist")?
            .to_owned();

        let second = submit(&state, &key, request.clone()).await?;
        assert_eq!(second.status(), StatusCode::ACCEPTED);
        let second = json_body(second).await?;
        assert_eq!(second["deduplicated"], true);
        assert_eq!(second["event_id"], event_id);
        assert_eq!(count(&pool, "crash_events").await?, 1);
        assert_eq!(count(&pool, "crash_event_objects").await?, 1);
        assert_eq!(count(&pool, "jobs").await?, 1);
        let stored_objects = objects.list(None).try_collect::<Vec<_>>().await?;
        assert_eq!(stored_objects.len(), 1);
        let raw = objects
            .get(&stored_objects[0].location)
            .await?
            .bytes()
            .await?;
        assert_eq!(raw.as_ref(), request);
        let stored = sqlx::query(
            "SELECT checksum, byte_size FROM crash_event_objects WHERE project_id = $1::uuid",
        )
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(
            stored.get::<Vec<u8>, _>("checksum"),
            Sha256::digest(&request).to_vec()
        );
        assert_eq!(
            stored.get::<i64, _>("byte_size"),
            i64::try_from(request.len())?
        );

        let concurrent_request = crash_request(
            "UECC-Windows-Concurrent",
            b"<FGenericCrashContext><RuntimeProperties /></FGenericCrashContext>",
        )?;
        let (left, right) = tokio::join!(
            submit(&state, &key, concurrent_request.clone()),
            submit(&state, &key, concurrent_request)
        );
        let left = json_body(left?).await?;
        let right = json_body(right?).await?;
        assert_eq!(left["event_id"], right["event_id"]);
        assert_ne!(left["deduplicated"], right["deduplicated"]);
        assert_eq!(count(&pool, "crash_events").await?, 2);
        assert_eq!(count(&pool, "crash_event_objects").await?, 2);
        assert_eq!(count(&pool, "jobs").await?, 2);
        assert_eq!(objects.list(None).try_collect::<Vec<_>>().await?.len(), 2);

        let state_response = router("api", state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/projects/{project_id}/events/{event_id}"))
                    .header(header::AUTHORIZATION, format!("Bootstrap {SECRET}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(state_response.status(), StatusCode::OK);
        let state_body = json_body(state_response).await?;
        assert_eq!(state_body["event_id"], event_id);
        assert_eq!(state_body["project_id"], project_id);
        assert_eq!(state_body["state"], "stored");
        assert!(!state_body.to_string().contains("object_key"));

        for processing_state in [
            "received",
            "stored",
            "parsed",
            "awaiting_symbols",
            "symbolicating",
            "processed",
            "failed",
            "quarantined",
        ] {
            let failed = processing_state == "failed";
            let quarantined = processing_state == "quarantined";
            sqlx::query(
                "UPDATE crash_events SET processing_state = $2, state_reason = CASE WHEN $3 THEN 'processing_failed' WHEN $4 THEN 'invalid_crash' ELSE NULL END, retryable = $3, retry_at = CASE WHEN $3 THEN now() + interval '1 minute' ELSE NULL END, updated_at = now() WHERE id = $1::uuid",
            )
            .bind(&event_id)
            .bind(processing_state)
            .bind(failed)
            .bind(quarantined)
            .execute(&pool)
            .await?;
            let body = get_state(&state, &project_id, &event_id).await?;
            assert_eq!(body["state"], processing_state);
            assert_eq!(body["retryable"], failed);
            if failed {
                assert_eq!(body["reason"], "processing_failed");
                assert!(body["retry_at"].is_string());
            } else if quarantined {
                assert_eq!(body["reason"], "invalid_crash");
                assert!(body["retry_at"].is_null());
            } else {
                assert!(body["reason"].is_null());
                assert!(body["retry_at"].is_null());
            }
        }
        sqlx::query(
            "UPDATE crash_events SET processing_state = 'stored', state_reason = NULL, retryable = false, retry_at = NULL WHERE id = $1::uuid",
        )
        .bind(&event_id)
        .execute(&pool)
        .await?;

        let other_project = random_uuid().map_err(|_| "test project id must generate")?;
        let isolated = router("api", state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/projects/{other_project}/events/{event_id}"
                    ))
                    .header(header::AUTHORIZATION, format!("Bootstrap {SECRET}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(isolated.status(), StatusCode::NOT_FOUND);

        let fallback = submit(
            &state,
            &key,
            crash_request("Windows-No-Guid", b"<FGenericCrashContext />")?,
        )
        .await?;
        assert_eq!(fallback.status(), StatusCode::ACCEPTED);
        let fallback = json_body(fallback).await?;
        let fallback_id = fallback["event_id"]
            .as_str()
            .ok_or("fallback event id must exist")?;
        let fallback_guid = sqlx::query_scalar::<_, Option<String>>(
            "SELECT crash_guid FROM crash_events WHERE id = $1::uuid",
        )
        .bind(fallback_id)
        .fetch_one(&pool)
        .await?;
        assert!(fallback_guid.is_none());

        let malformed = submit(&state, &key, b"not a crash request".to_vec()).await?;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(count(&pool, "crash_events").await?, 3);
        assert_eq!(objects.list(None).try_collect::<Vec<_>>().await?.len(), 3);
        assert!(std::fs::read_dir(&spool_directory)?.next().is_none());

        sqlx::query(
            "UPDATE project_ingest_keys SET allowed_cidrs = ARRAY['203.0.113.0/24'] WHERE project_id = $1::uuid",
        )
        .bind(&project_id)
        .execute(&pool)
        .await?;
        let denied = submit(
            &state,
            &key,
            crash_request("UECC-Windows-Denied", b"<FGenericCrashContext />")?,
        )
        .await?;
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
        assert_eq!(count(&pool, "crash_events").await?, 3);
        sqlx::query(
            "UPDATE project_ingest_keys SET allowed_cidrs = ARRAY['127.0.0.0/8'] WHERE project_id = $1::uuid",
        )
        .bind(&project_id)
        .execute(&pool)
        .await?;

        let mut limited = state.crash_ingest().clone();
        limited.project_limit = 6;
        limited.ip_limit = 6;
        let limited_state = ServerState::ingest_test(pool.clone(), limited, SECRET);
        let limited_response = submit(
            &limited_state,
            &key,
            crash_request("UECC-Windows-Limited", b"<FGenericCrashContext />")?,
        )
        .await?;
        assert_eq!(limited_response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            limited_response
                .headers()
                .get("ratelimit-remaining")
                .and_then(|value| value.to_str().ok()),
            Some("0")
        );
        assert_eq!(count(&pool, "crash_events").await?, 3);

        sqlx::query("DROP TRIGGER IF EXISTS faultlane_test_fail_job ON jobs")
            .execute(&pool)
            .await?;
        sqlx::query("DROP FUNCTION IF EXISTS faultlane_test_fail_job()")
            .execute(&pool)
            .await?;
        sqlx::query(
            "CREATE FUNCTION faultlane_test_fail_job() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced job failure'; END $$",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "CREATE TRIGGER faultlane_test_fail_job BEFORE INSERT ON jobs FOR EACH ROW EXECUTE FUNCTION faultlane_test_fail_job()",
        )
        .execute(&pool)
        .await?;
        let database_failure = submit(
            &state,
            &key,
            crash_request(
                "UECC-Windows-Database-Rollback",
                b"<FGenericCrashContext />",
            )?,
        )
        .await;
        sqlx::query("DROP TRIGGER faultlane_test_fail_job ON jobs")
            .execute(&pool)
            .await?;
        sqlx::query("DROP FUNCTION faultlane_test_fail_job()")
            .execute(&pool)
            .await?;
        let database_failure = database_failure?;
        assert_eq!(database_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(count(&pool, "crash_events").await?, 3);
        assert_eq!(count(&pool, "crash_event_objects").await?, 3);
        assert_eq!(count(&pool, "jobs").await?, 3);
        assert_eq!(count(&pool, "ingest_orphan_objects").await?, 0);
        assert_eq!(objects.list(None).try_collect::<Vec<_>>().await?.len(), 3);

        let blocked_spool = test_spool_directory()?;
        let unavailable = CrashIngest::test(pool.clone(), objects.clone(), blocked_spool.clone());
        std::fs::remove_dir(&blocked_spool)?;
        std::fs::write(&blocked_spool, b"blocked")?;
        let unavailable_state = ServerState::ingest_test(pool.clone(), unavailable, SECRET);
        let response = submit(
            &unavailable_state,
            &key,
            crash_request("UECC-Windows-Storage-Failure", b"<FGenericCrashContext />")?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(count(&pool, "crash_events").await?, 3);
        assert_eq!(count(&pool, "ingest_orphan_objects").await?, 0);
        std::fs::remove_file(&blocked_spool)?;

        pool.close().await;
        let response = submit(
            &state,
            &key,
            crash_request("UECC-Windows-Database-Failure", b"<FGenericCrashContext />")?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(objects.list(None).try_collect::<Vec<_>>().await?.len(), 3);
        std::fs::remove_dir(&spool_directory)?;
        Ok(())
    }

    async fn seed_project(pool: &PgPool) -> Result<(String, String), Box<dyn Error>> {
        let owner_id = sqlx::query_scalar::<_, String>(
            "INSERT INTO users (bootstrap_subject, email) VALUES ('local-bootstrap', 'owner@example.com') RETURNING id::text",
        )
        .fetch_one(pool)
        .await?;
        let organization_id = sqlx::query_scalar::<_, String>(
            "INSERT INTO organizations (name, slug) VALUES ('FaultLane Test', 'faultlane-test') RETURNING id::text",
        )
        .fetch_one(pool)
        .await?;
        sqlx::query(
            "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')",
        )
        .bind(&organization_id)
        .bind(&owner_id)
        .execute(pool)
        .await?;
        let project_id = sqlx::query_scalar::<_, String>(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Windows Game', 'windows-game') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(pool)
        .await?;
        let key = format!("clpk_{}", "1".repeat(64));
        sqlx::query(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix, environment, allowed_cidrs) VALUES ($1::uuid, $2::uuid, $3, '11111111', 'playtest', ARRAY['127.0.0.0/8'])",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(Sha256::digest(key.as_bytes()).to_vec())
        .execute(pool)
        .await?;
        Ok((project_id, key))
    }

    async fn submit(
        state: &ServerState,
        key: &str,
        body: Vec<u8>,
    ) -> Result<axum::response::Response, Box<dyn Error>> {
        Ok(router("ingest", state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/u/{key}?AppID=WindowsGame&AppVersion=1.0&AppEnvironment=Shipping&UploadType=crashreports&UserID="
                    ))
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(Body::from(body))?,
            )
            .await?)
    }

    async fn json_body(response: axum::response::Response) -> Result<Value, Box<dyn Error>> {
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn get_state(
        state: &ServerState,
        project_id: &str,
        event_id: &str,
    ) -> Result<Value, Box<dyn Error>> {
        let response = router("api", state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/projects/{project_id}/events/{event_id}"))
                    .header(header::AUTHORIZATION, format!("Bootstrap {SECRET}"))
                    .body(Body::empty())?,
            )
            .await?;
        if response.status() != StatusCode::OK {
            return Err("event state request failed".into());
        }
        json_body(response).await
    }

    async fn count(pool: &PgPool, table: &str) -> Result<i64, Box<dyn Error>> {
        let query = match table {
            "crash_events" => "SELECT count(*) FROM crash_events",
            "crash_event_objects" => "SELECT count(*) FROM crash_event_objects",
            "jobs" => "SELECT count(*) FROM jobs",
            "ingest_orphan_objects" => "SELECT count(*) FROM ingest_orphan_objects",
            _ => return Err("unsupported test table".into()),
        };
        Ok(sqlx::query_scalar(query).fetch_one(pool).await?)
    }

    fn test_spool_directory() -> Result<PathBuf, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "faultlane-296-{}",
            random_uuid().map_err(|_| "test spool id must generate")?
        ));
        std::fs::create_dir(&path)?;
        Ok(path)
    }

    fn crash_request(directory: &str, xml: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut expanded = Vec::new();
        expanded.extend_from_slice(b"CR1");
        write_ansi_field(&mut expanded, directory)?;
        write_ansi_field(&mut expanded, &format!("{directory}.uecrash"))?;
        let size_offset = expanded.len();
        write_i32(&mut expanded, 0);
        write_i32(&mut expanded, 1);
        write_i32(&mut expanded, 0);
        write_ansi_field(&mut expanded, "CrashContext.runtime-xml")?;
        write_i32(&mut expanded, i32::try_from(xml.len())?);
        expanded.extend_from_slice(xml);
        let expanded_size = i32::try_from(expanded.len())?;
        expanded[size_offset..size_offset + 4].copy_from_slice(&expanded_size.to_le_bytes());
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&expanded)?;
        Ok(encoder.finish()?)
    }

    fn write_ansi_field(output: &mut Vec<u8>, value: &str) -> Result<(), Box<dyn Error>> {
        if value.len() > 260 {
            return Err("test field is too long".into());
        }
        write_i32(output, 260);
        output.extend_from_slice(value.as_bytes());
        output.resize(output.len() + 260 - value.len(), 0);
        Ok(())
    }

    fn write_i32(output: &mut Vec<u8>, value: i32) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn assert_isolated_database(database_url: &str) {
        let database_name = database_url
            .rsplit('/')
            .next()
            .and_then(|value| value.split('?').next())
            .unwrap_or_default();
        assert!(
            database_name == "faultlane_296"
                || database_name.starts_with("faultlane_296_")
                || database_name == "faultlane_test"
        );
    }
}
