use std::{env, fmt, net::IpAddr, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxumPath, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, migrate::Migrator, postgres::PgPoolOptions};
use subtle::ConstantTimeEq;

const BOOTSTRAP_SUBJECT: &str = "local-bootstrap";
const INGEST_KEY_PREFIX: &str = "clpk_";
const INGEST_KEY_BYTES: usize = 32;
const DISPLAY_SUFFIX_BYTES: usize = 8;
const DEFAULT_ENVIRONMENT: &str = "production";
const MAX_NAME_BYTES: usize = 80;
const MAX_SLUG_BYTES: usize = 63;
const MAX_EMAIL_BYTES: usize = 254;
const HEX: &[u8; 16] = b"0123456789abcdef";
static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");
#[cfg(test)]
pub(crate) static DATABASE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone)]
pub(crate) struct ServerState {
    store: ProjectStore,
    bootstrap: BootstrapAuthorization,
    ingest_base_url: String,
    crash_ingest: crate::crash_ingest::CrashIngest,
    symbol_uploads: crate::symbol_upload::SymbolUploads,
}

impl ServerState {
    pub(crate) async fn from_environment(
        host: &str,
        role: &'static str,
    ) -> Result<Self, StartupError> {
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| StartupError::InvalidConfiguration("DATABASE_URL is required"))?;
        let bootstrap_enabled = env::var("CACHELANE_BOOTSTRAP_ENABLED")
            .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
        let bootstrap_secret = env::var("CACHELANE_BOOTSTRAP_SECRET").ok();
        let ingest_base_url =
            env::var("INGEST_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".to_owned());

        Self::postgres(
            &database_url,
            host,
            bootstrap_enabled,
            bootstrap_secret.as_deref(),
            &ingest_base_url,
            role,
        )
        .await
    }

    pub(crate) async fn postgres(
        database_url: &str,
        host: &str,
        bootstrap_enabled: bool,
        bootstrap_secret: Option<&str>,
        ingest_base_url: &str,
        role: &'static str,
    ) -> Result<Self, StartupError> {
        let bootstrap = BootstrapAuthorization::new(host, bootstrap_enabled, bootstrap_secret)?;
        let ingest_base_url = validate_ingest_base_url(ingest_base_url)?;
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await
            .map_err(|_| StartupError::DatabaseUnavailable)?;

        let symbol_uploads =
            crate::symbol_upload::SymbolUploads::postgres(pool.clone(), role, host)?;

        Ok(Self {
            store: ProjectStore::Postgres(pool.clone()),
            bootstrap,
            ingest_base_url,
            crash_ingest: crate::crash_ingest::CrashIngest::postgres(pool, role)?,
            symbol_uploads,
        })
    }

    #[cfg(test)]
    fn memory(secret: &str) -> Self {
        Self {
            store: ProjectStore::Memory(std::sync::Arc::new(std::sync::Mutex::new(
                MemoryStore::default(),
            ))),
            bootstrap: BootstrapAuthorization::new("127.0.0.1", true, Some(secret))
                .unwrap_or_else(|error| panic!("test authorization must be valid: {error}")),
            ingest_base_url: "http://127.0.0.1:8081".to_owned(),
            crash_ingest: crate::crash_ingest::CrashIngest::memory(),
            symbol_uploads: crate::symbol_upload::SymbolUploads::disabled(),
        }
    }

    #[cfg(test)]
    pub(crate) fn ingest_test(
        pool: PgPool,
        crash_ingest: crate::crash_ingest::CrashIngest,
        secret: &str,
    ) -> Self {
        Self {
            store: ProjectStore::Postgres(pool),
            bootstrap: BootstrapAuthorization::new("127.0.0.1", true, Some(secret))
                .unwrap_or_else(|error| panic!("test authorization must be valid: {error}")),
            ingest_base_url: "http://127.0.0.1:8081".to_owned(),
            crash_ingest,
            symbol_uploads: crate::symbol_upload::SymbolUploads::disabled(),
        }
    }

    #[cfg(test)]
    pub(crate) fn symbol_upload_test(
        pool: PgPool,
        symbol_uploads: crate::symbol_upload::SymbolUploads,
        secret: &str,
    ) -> Self {
        Self {
            store: ProjectStore::Postgres(pool),
            bootstrap: BootstrapAuthorization::new("127.0.0.1", true, Some(secret))
                .unwrap_or_else(|error| panic!("test authorization must be valid: {error}")),
            ingest_base_url: "http://127.0.0.1:8081".to_owned(),
            crash_ingest: crate::crash_ingest::CrashIngest::memory(),
            symbol_uploads,
        }
    }

    #[cfg(test)]
    fn add_outside_project(&self, project_id: &str) {
        let ProjectStore::Memory(store) = &self.store else {
            panic!("test state must use memory storage");
        };
        store
            .lock()
            .unwrap_or_else(|error| panic!("test store must be available: {error}"))
            .outside_projects
            .push(project_id.to_owned());
    }

    pub(crate) fn authorize_control(&self, headers: &HeaderMap) -> bool {
        self.bootstrap.authorize(headers).is_ok()
    }

    pub(crate) fn crash_ingest(&self) -> &crate::crash_ingest::CrashIngest {
        &self.crash_ingest
    }

    pub(crate) fn symbol_uploads(&self) -> &crate::symbol_upload::SymbolUploads {
        &self.symbol_uploads
    }

    pub(crate) fn start_maintenance(&self, role: &str) {
        if role == "ingest" {
            self.crash_ingest.start_maintenance();
        }
    }

    pub(crate) async fn resolve_ingest_scope(
        &self,
        key: &str,
    ) -> Result<Option<KeyScope>, StoreError> {
        if !valid_ingest_key(key) {
            return Ok(None);
        }
        self.store.resolve_key(&hash(key)).await
    }
}

#[derive(Debug)]
pub(crate) enum StartupError {
    InvalidConfiguration(&'static str),
    DatabaseUnavailable,
    MigrationFailed,
    IngestConfiguration,
    SymbolUploadConfiguration,
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => formatter.write_str(message),
            Self::DatabaseUnavailable => formatter.write_str("database is unavailable"),
            Self::MigrationFailed => formatter.write_str("database migration failed"),
            Self::IngestConfiguration => formatter.write_str("ingest configuration is invalid"),
            Self::SymbolUploadConfiguration => {
                formatter.write_str("symbol upload configuration is invalid")
            }
        }
    }
}

impl std::error::Error for StartupError {}

pub(crate) async fn migrate(database_url: &str) -> Result<(), StartupError> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .map_err(|_| StartupError::DatabaseUnavailable)?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|_| StartupError::MigrationFailed)
}

pub(crate) fn router(role: &'static str, state: ServerState) -> Router {
    let health = Router::new()
        .route("/health/live", get(move || async move { health(role) }))
        .route("/health/ready", get(move || async move { health(role) }))
        .route("/api/v1/health", get(move || async move { health(role) }));

    match role {
        "api" => health
            .route("/api/v1/setup", post(create_setup))
            .route("/api/v1/projects/{project_id}/setup", get(get_setup))
            .route(
                "/api/v1/projects/{project_id}/ingest-keys",
                post(rotate_ingest_key).layer(DefaultBodyLimit::max(4 * 1024)),
            )
            .route(
                "/api/v1/projects/{project_id}/ingest-keys/{key_id}",
                delete(revoke_ingest_key),
            )
            .route(
                "/api/v1/projects/{project_id}/ingest-keys/{key_id}/policy",
                patch(update_ingest_key_policy).layer(DefaultBodyLimit::max(4 * 1024)),
            )
            .route(
                "/api/v1/projects/{project_id}/events/{event_id}",
                get(crate::crash_ingest::get_event_state),
            )
            .route(
                "/api/v1/projects/{project_id}/artifact-upload-tokens",
                post(crate::symbol_upload::create_upload_token),
            )
            .route(
                "/api/v1/projects/{project_id}/artifact-upload-tokens/{token_id}",
                delete(crate::symbol_upload::revoke_upload_token),
            )
            .route(
                "/api/v1/projects/{project_slug}/artifact-uploads",
                post(crate::symbol_upload::negotiate_uploads)
                    .layer(DefaultBodyLimit::max(1024 * 1024)),
            )
            .route(
                "/api/v1/artifact-uploads/{upload_id}/parts",
                post(crate::symbol_upload::sign_part).layer(DefaultBodyLimit::max(4 * 1024)),
            )
            .route(
                "/api/v1/artifact-uploads/{upload_id}/parts/{part_number}",
                patch(crate::symbol_upload::record_part).layer(DefaultBodyLimit::max(4 * 1024)),
            )
            .route(
                "/api/v1/artifact-uploads/{upload_id}/complete",
                post(crate::symbol_upload::complete_upload),
            )
            .route(
                "/api/v1/releases/{release_id}/coverage",
                get(crate::symbol_upload::get_coverage),
            )
            .with_state(state),
        "ingest" => ingest_router(
            health
                .route("/u/{key}", post(crate::crash_ingest::submit_crash))
                .with_state(state),
        ),
        _ => health.with_state(state),
    }
}

#[cfg(not(test))]
fn ingest_router(router: Router) -> Router {
    router
}

#[cfg(test)]
fn ingest_router(router: Router) -> Router {
    use axum::extract::connect_info::MockConnectInfo;
    router.layer(MockConnectInfo(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        40000,
    ))))
}

#[derive(Serialize)]
struct Health {
    service: &'static str,
    role: &'static str,
    status: &'static str,
    version: &'static str,
}

fn health(role: &'static str) -> Json<Health> {
    Json(Health {
        service: "cachelane-server",
        role,
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Clone)]
struct BootstrapAuthorization {
    digest: Option<[u8; 32]>,
}

impl BootstrapAuthorization {
    fn new(host: &str, enabled: bool, secret: Option<&str>) -> Result<Self, StartupError> {
        if !enabled {
            return Ok(Self { digest: None });
        }

        let address = host.parse::<IpAddr>().map_err(|_| {
            StartupError::InvalidConfiguration(
                "bootstrap authentication requires an IP loopback host",
            )
        })?;
        if !address.is_loopback() {
            return Err(StartupError::InvalidConfiguration(
                "bootstrap authentication requires a loopback host",
            ));
        }
        let secret =
            secret
                .filter(|value| value.len() >= 32)
                .ok_or(StartupError::InvalidConfiguration(
                    "bootstrap authentication requires a 32-byte secret",
                ))?;

        Ok(Self {
            digest: Some(hash(secret)),
        })
    }

    fn authorize(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let expected = self.digest.as_ref().ok_or(ApiError::NotFound)?;
        let authorization = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bootstrap "))
            .ok_or(ApiError::Unauthorized)?;
        let actual = hash(authorization);

        if bool::from(actual.as_slice().ct_eq(expected.as_slice())) {
            Ok(())
        } else {
            Err(ApiError::Unauthorized)
        }
    }
}

#[derive(Deserialize)]
struct CreateSetupRequest {
    owner_email: String,
    organization_name: String,
    organization_slug: String,
    project_name: String,
    project_slug: String,
}

#[derive(Clone)]
struct ValidatedSetup {
    owner_email: String,
    organization_name: String,
    organization_slug: String,
    project_name: String,
    project_slug: String,
}

impl TryFrom<CreateSetupRequest> for ValidatedSetup {
    type Error = ApiError;

    fn try_from(request: CreateSetupRequest) -> Result<Self, Self::Error> {
        if !valid_email(&request.owner_email)
            || !valid_name(&request.organization_name)
            || !valid_slug(&request.organization_slug)
            || !valid_name(&request.project_name)
            || !valid_slug(&request.project_slug)
        {
            return Err(ApiError::InvalidRequest);
        }

        Ok(Self {
            owner_email: request.owner_email,
            organization_name: request.organization_name,
            organization_slug: request.organization_slug,
            project_name: request.project_name,
            project_slug: request.project_slug,
        })
    }
}

#[derive(Clone, Serialize)]
struct OrganizationView {
    id: String,
    name: String,
    slug: String,
}

#[derive(Clone, Serialize)]
struct ProjectView {
    id: String,
    name: String,
    slug: String,
}

#[derive(Clone, Serialize)]
struct IngestKeyView {
    id: String,
    display_suffix: String,
    environment: String,
    allowed_cidrs: Vec<String>,
    created_at: String,
    revoked_at: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPolicyRequest {
    environment: String,
    #[serde(default)]
    allowed_cidrs: Vec<String>,
}

#[derive(Clone)]
struct ValidatedKeyPolicy {
    environment: String,
    allowed_cidrs: Vec<String>,
}

impl Default for ValidatedKeyPolicy {
    fn default() -> Self {
        Self {
            environment: DEFAULT_ENVIRONMENT.to_owned(),
            allowed_cidrs: Vec::new(),
        }
    }
}

impl TryFrom<KeyPolicyRequest> for ValidatedKeyPolicy {
    type Error = ApiError;

    fn try_from(request: KeyPolicyRequest) -> Result<Self, Self::Error> {
        if !valid_environment(&request.environment) || request.allowed_cidrs.len() > 32 {
            return Err(ApiError::InvalidRequest);
        }
        let mut allowed_cidrs = request
            .allowed_cidrs
            .into_iter()
            .map(|value| {
                value
                    .parse::<IpNet>()
                    .map(|network| network.to_string())
                    .map_err(|_| ApiError::InvalidRequest)
            })
            .collect::<Result<Vec<_>, _>>()?;
        allowed_cidrs.sort();
        allowed_cidrs.dedup();
        Ok(Self {
            environment: request.environment,
            allowed_cidrs,
        })
    }
}

#[derive(Clone, Serialize)]
struct ProjectSetupView {
    owner_id: String,
    organization: OrganizationView,
    project: ProjectView,
    ingest_keys: Vec<IngestKeyView>,
}

#[derive(Serialize)]
struct UnrealConfiguration {
    #[serde(rename = "default_game_ini_path")]
    game_ini_path: &'static str,
    #[serde(rename = "default_game_ini")]
    game_ini: &'static str,
    #[serde(rename = "default_engine_ini_path")]
    engine_ini_path: &'static str,
    #[serde(rename = "default_engine_ini")]
    engine_ini: String,
}

#[derive(Serialize)]
struct SecretKeyView {
    id: String,
    value: String,
    display_suffix: String,
}

#[derive(Serialize)]
struct CreatedSetupResponse {
    setup: ProjectSetupView,
    ingest_key: SecretKeyView,
    data_router_url: String,
    configuration: UnrealConfiguration,
}

#[derive(Serialize)]
struct ExistingSetupResponse {
    setup: ProjectSetupView,
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: &'static str,
}

#[derive(Clone)]
struct GeneratedKey {
    value: String,
    digest: Vec<u8>,
    display_suffix: String,
}

impl GeneratedKey {
    fn new() -> Result<Self, ApiError> {
        let mut random = [0_u8; INGEST_KEY_BYTES];
        getrandom::fill(&mut random).map_err(|_| ApiError::Internal)?;
        let mut value = String::with_capacity(INGEST_KEY_PREFIX.len() + INGEST_KEY_BYTES * 2);
        value.push_str(INGEST_KEY_PREFIX);
        for byte in random {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        random.fill(0);
        let display_suffix = value[value.len() - DISPLAY_SUFFIX_BYTES..].to_owned();

        Ok(Self {
            digest: hash(&value).to_vec(),
            value,
            display_suffix,
        })
    }
}

async fn create_setup(
    State(state): State<ServerState>,
    headers: HeaderMap,
    payload: Result<Json<CreateSetupRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    state.bootstrap.authorize(&headers)?;
    let Json(request) = payload.map_err(|_| ApiError::InvalidRequest)?;
    let request = ValidatedSetup::try_from(request)?;
    let key = GeneratedKey::new()?;
    let policy = ValidatedKeyPolicy::default();
    let created = state
        .store
        .bootstrap(BOOTSTRAP_SUBJECT, &request, &key, &policy)
        .await?;
    let response = created_response(&state.ingest_base_url, created, key);

    Ok(no_store(StatusCode::CREATED, &response))
}

async fn get_setup(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath(project_id): AxumPath<String>,
) -> Result<Response, ApiError> {
    state.bootstrap.authorize(&headers)?;
    let setup = state
        .store
        .get_setup(BOOTSTRAP_SUBJECT, &project_id)
        .await?;

    Ok(no_store(StatusCode::OK, &ExistingSetupResponse { setup }))
}

async fn rotate_ingest_key(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath(project_id): AxumPath<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    state.bootstrap.authorize(&headers)?;
    let policy = if body.is_empty() {
        ValidatedKeyPolicy::default()
    } else {
        let request = serde_json::from_slice::<KeyPolicyRequest>(&body)
            .map_err(|_| ApiError::InvalidRequest)?;
        ValidatedKeyPolicy::try_from(request)?
    };
    let key = GeneratedKey::new()?;
    let created = state
        .store
        .rotate_key(BOOTSTRAP_SUBJECT, &project_id, &key, &policy)
        .await?;
    let response = created_response(&state.ingest_base_url, created, key);

    Ok(no_store(StatusCode::CREATED, &response))
}

async fn update_ingest_key_policy(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath((project_id, key_id)): AxumPath<(String, String)>,
    payload: Result<Json<KeyPolicyRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    state.bootstrap.authorize(&headers)?;
    let Json(request) = payload.map_err(|_| ApiError::InvalidRequest)?;
    let policy = ValidatedKeyPolicy::try_from(request)?;
    let setup = state
        .store
        .update_key_policy(BOOTSTRAP_SUBJECT, &project_id, &key_id, &policy)
        .await?;

    Ok(no_store(StatusCode::OK, &ExistingSetupResponse { setup }))
}

async fn revoke_ingest_key(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath((project_id, key_id)): AxumPath<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state.bootstrap.authorize(&headers)?;
    state
        .store
        .revoke_key(BOOTSTRAP_SUBJECT, &project_id, &key_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

fn created_response(
    ingest_base_url: &str,
    created: StoredSetup,
    key: GeneratedKey,
) -> CreatedSetupResponse {
    let data_router_url = format!("{ingest_base_url}/u/{}", key.value);
    let configuration = configuration(&created.setup.organization.name, &data_router_url);

    CreatedSetupResponse {
        setup: created.setup,
        ingest_key: SecretKeyView {
            id: created.key_id,
            value: key.value,
            display_suffix: key.display_suffix,
        },
        data_router_url,
        configuration,
    }
}

fn configuration(organization_name: &str, data_router_url: &str) -> UnrealConfiguration {
    UnrealConfiguration {
        game_ini_path: "Config/DefaultGame.ini",
        game_ini: "[/Script/UnrealEd.ProjectPackagingSettings]\nIncludeCrashReporter=True\n",
        engine_ini_path: "Config/DefaultEngine.ini",
        engine_ini: format!(
            "[CrashReportClient]\nCompanyName=\"{organization_name}\"\nDataRouterUrl=\"{data_router_url}\"\nbSendLogFile=true\n"
        ),
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

#[derive(Debug)]
enum ApiError {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Conflict,
    Internal,
}

impl IntoResponse for ApiError {
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
                "authorization is required",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "resource was not found"),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "setup_conflict",
                "project setup is already complete",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "request could not be completed",
            ),
        };

        no_store(status, &ErrorResponse { code, message })
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::AlreadyBootstrapped | StoreError::Conflict => Self::Conflict,
            StoreError::NotFound => Self::NotFound,
            StoreError::Internal => Self::Internal,
        }
    }
}

fn valid_email(value: &str) -> bool {
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();

    !local.is_empty()
        && !domain.is_empty()
        && parts.next().is_none()
        && value.len() <= MAX_EMAIL_BYTES
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value.trim() == value
        && !value.contains(['"', '\\'])
        && !value.chars().any(char::is_control)
}

fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SLUG_BYTES
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_environment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_ingest_key(value: &str) -> bool {
    value.len() == INGEST_KEY_PREFIX.len() + INGEST_KEY_BYTES * 2
        && value.starts_with(INGEST_KEY_PREFIX)
        && value[INGEST_KEY_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_ingest_base_url(value: &str) -> Result<String, StartupError> {
    let value = value.trim_end_matches('/');
    let authority = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"));
    if !authority.is_some_and(|authority| {
        !authority.is_empty()
            && !authority.contains(['/', '\\', '@'])
            && !authority.chars().any(char::is_whitespace)
    }) || value.contains(['?', '#', '\n', '\r'])
    {
        return Err(StartupError::InvalidConfiguration(
            "INGEST_BASE_URL must be an HTTP origin",
        ));
    }
    Ok(value.to_owned())
}

fn hash(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

#[derive(Clone)]
enum ProjectStore {
    Postgres(PgPool),
    #[cfg(test)]
    Memory(std::sync::Arc<std::sync::Mutex<MemoryStore>>),
}

#[derive(Debug)]
pub(crate) enum StoreError {
    AlreadyBootstrapped,
    Conflict,
    NotFound,
    Internal,
}

impl ProjectStore {
    async fn bootstrap(
        &self,
        subject: &str,
        request: &ValidatedSetup,
        key: &GeneratedKey,
        policy: &ValidatedKeyPolicy,
    ) -> Result<StoredSetup, StoreError> {
        match self {
            Self::Postgres(pool) => postgres_bootstrap(pool, subject, request, key, policy).await,
            #[cfg(test)]
            Self::Memory(store) => memory_bootstrap(store, subject, request, key, policy),
        }
    }

    async fn get_setup(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<ProjectSetupView, StoreError> {
        match self {
            Self::Postgres(pool) => postgres_get_setup(pool, subject, project_id).await,
            #[cfg(test)]
            Self::Memory(store) => memory_get_setup(store, subject, project_id),
        }
    }

    async fn rotate_key(
        &self,
        subject: &str,
        project_id: &str,
        key: &GeneratedKey,
        policy: &ValidatedKeyPolicy,
    ) -> Result<StoredSetup, StoreError> {
        match self {
            Self::Postgres(pool) => {
                postgres_rotate_key(pool, subject, project_id, key, policy).await
            }
            #[cfg(test)]
            Self::Memory(store) => memory_rotate_key(store, subject, project_id, key, policy),
        }
    }

    async fn update_key_policy(
        &self,
        subject: &str,
        project_id: &str,
        key_id: &str,
        policy: &ValidatedKeyPolicy,
    ) -> Result<ProjectSetupView, StoreError> {
        match self {
            Self::Postgres(pool) => {
                postgres_update_key_policy(pool, subject, project_id, key_id, policy).await
            }
            #[cfg(test)]
            Self::Memory(store) => {
                memory_update_key_policy(store, subject, project_id, key_id, policy)
            }
        }
    }

    async fn revoke_key(
        &self,
        subject: &str,
        project_id: &str,
        key_id: &str,
    ) -> Result<(), StoreError> {
        match self {
            Self::Postgres(pool) => postgres_revoke_key(pool, subject, project_id, key_id).await,
            #[cfg(test)]
            Self::Memory(store) => memory_revoke_key(store, subject, project_id, key_id),
        }
    }

    async fn resolve_key(&self, digest: &[u8]) -> Result<Option<KeyScope>, StoreError> {
        match self {
            Self::Postgres(pool) => postgres_resolve_key(pool, digest).await,
            #[cfg(test)]
            Self::Memory(store) => memory_resolve_key(store, digest),
        }
    }
}

#[derive(Clone)]
pub(crate) struct KeyScope {
    pub(crate) key_id: String,
    pub(crate) organization_id: String,
    pub(crate) project_id: String,
    pub(crate) environment: String,
    pub(crate) allowed_cidrs: Vec<IpNet>,
}

struct StoredSetup {
    setup: ProjectSetupView,
    key_id: String,
}

struct StoredKey {
    id: String,
    created_at: String,
}

async fn postgres_bootstrap(
    pool: &PgPool,
    subject: &str,
    request: &ValidatedSetup,
    key: &GeneratedKey,
    policy: &ValidatedKeyPolicy,
) -> Result<StoredSetup, StoreError> {
    let mut transaction = pool.begin().await.map_err(map_sqlx_error)?;
    let existing =
        sqlx::query_scalar::<_, String>("SELECT id::text FROM users WHERE bootstrap_subject = $1")
            .bind(subject)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_sqlx_error)?;
    if existing.is_some() {
        return Err(StoreError::AlreadyBootstrapped);
    }

    let owner_id = sqlx::query_scalar::<_, String>(
        "INSERT INTO users (bootstrap_subject, email) VALUES ($1, $2) RETURNING id::text",
    )
    .bind(subject)
    .bind(&request.owner_email)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_bootstrap_error)?;
    let organization_id = sqlx::query_scalar::<_, String>(
        "INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
    )
    .bind(&request.organization_name)
    .bind(&request.organization_slug)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_sqlx_error)?;
    sqlx::query(
        "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')",
    )
    .bind(&organization_id)
    .bind(&owner_id)
    .execute(&mut *transaction)
    .await
    .map_err(map_sqlx_error)?;
    let project_id = sqlx::query_scalar::<_, String>(
        "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, $2, $3) RETURNING id::text",
    )
    .bind(&organization_id)
    .bind(&request.project_name)
    .bind(&request.project_slug)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_sqlx_error)?;
    let stored_key =
        insert_key(&mut transaction, &organization_id, &project_id, key, policy).await?;
    transaction.commit().await.map_err(map_sqlx_error)?;

    Ok(StoredSetup {
        key_id: stored_key.id.clone(),
        setup: ProjectSetupView {
            owner_id,
            organization: OrganizationView {
                id: organization_id,
                name: request.organization_name.clone(),
                slug: request.organization_slug.clone(),
            },
            project: ProjectView {
                id: project_id,
                name: request.project_name.clone(),
                slug: request.project_slug.clone(),
            },
            ingest_keys: vec![IngestKeyView {
                id: stored_key.id,
                display_suffix: key.display_suffix.clone(),
                environment: policy.environment.clone(),
                allowed_cidrs: policy.allowed_cidrs.clone(),
                created_at: stored_key.created_at,
                revoked_at: None,
            }],
        },
    })
}

async fn insert_key(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
    project_id: &str,
    key: &GeneratedKey,
    policy: &ValidatedKeyPolicy,
) -> Result<StoredKey, StoreError> {
    let row = sqlx::query(
        "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix, environment, allowed_cidrs) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6) RETURNING id::text AS id, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(&key.digest)
    .bind(&key.display_suffix)
    .bind(&policy.environment)
    .bind(&policy.allowed_cidrs)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sqlx_error)?;

    Ok(StoredKey {
        id: row.get("id"),
        created_at: row.get("created_at"),
    })
}

async fn postgres_get_setup(
    pool: &PgPool,
    subject: &str,
    project_id: &str,
) -> Result<ProjectSetupView, StoreError> {
    let row = sqlx::query(
        "SELECT u.id::text AS owner_id, o.id::text AS organization_id, o.name AS organization_name, o.slug AS organization_slug, p.id::text AS project_id, p.name AS project_name, p.slug AS project_slug FROM users u JOIN organization_memberships m ON m.user_id = u.id AND m.role = 'owner' JOIN organizations o ON o.id = m.organization_id JOIN projects p ON p.organization_id = o.id WHERE u.bootstrap_subject = $1 AND p.id::text = $2",
    )
    .bind(subject)
    .bind(project_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sqlx_error)?
    .ok_or(StoreError::NotFound)?;
    let keys = postgres_keys(pool, subject, project_id).await?;

    Ok(ProjectSetupView {
        owner_id: row.get("owner_id"),
        organization: OrganizationView {
            id: row.get("organization_id"),
            name: row.get("organization_name"),
            slug: row.get("organization_slug"),
        },
        project: ProjectView {
            id: row.get("project_id"),
            name: row.get("project_name"),
            slug: row.get("project_slug"),
        },
        ingest_keys: keys,
    })
}

async fn postgres_keys(
    pool: &PgPool,
    subject: &str,
    project_id: &str,
) -> Result<Vec<IngestKeyView>, StoreError> {
    let rows = sqlx::query(
        "SELECT k.id::text AS id, k.display_suffix, k.environment, k.allowed_cidrs, to_char(k.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, CASE WHEN k.revoked_at IS NULL THEN NULL ELSE to_char(k.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS revoked_at FROM project_ingest_keys k JOIN projects p ON p.id = k.project_id AND p.organization_id = k.organization_id JOIN organization_memberships m ON m.organization_id = p.organization_id AND m.role = 'owner' JOIN users u ON u.id = m.user_id WHERE u.bootstrap_subject = $1 AND p.id::text = $2 ORDER BY k.created_at, k.id",
    )
    .bind(subject)
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(map_sqlx_error)?;

    Ok(rows
        .into_iter()
        .map(|row| IngestKeyView {
            id: row.get("id"),
            display_suffix: row.get("display_suffix"),
            environment: row.get("environment"),
            allowed_cidrs: row.get("allowed_cidrs"),
            created_at: row.get("created_at"),
            revoked_at: row.get("revoked_at"),
        })
        .collect())
}

async fn postgres_rotate_key(
    pool: &PgPool,
    subject: &str,
    project_id: &str,
    key: &GeneratedKey,
    policy: &ValidatedKeyPolicy,
) -> Result<StoredSetup, StoreError> {
    let scope = sqlx::query(
        "SELECT p.organization_id::text AS organization_id FROM projects p JOIN organization_memberships m ON m.organization_id = p.organization_id AND m.role = 'owner' JOIN users u ON u.id = m.user_id WHERE u.bootstrap_subject = $1 AND p.id::text = $2",
    )
    .bind(subject)
    .bind(project_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sqlx_error)?
    .ok_or(StoreError::NotFound)?;
    let organization_id: String = scope.get("organization_id");
    let mut transaction = pool.begin().await.map_err(map_sqlx_error)?;
    let stored_key =
        insert_key(&mut transaction, &organization_id, project_id, key, policy).await?;
    transaction.commit().await.map_err(map_sqlx_error)?;
    let setup = postgres_get_setup(pool, subject, project_id).await?;
    Ok(StoredSetup {
        setup,
        key_id: stored_key.id,
    })
}

async fn postgres_update_key_policy(
    pool: &PgPool,
    subject: &str,
    project_id: &str,
    key_id: &str,
    policy: &ValidatedKeyPolicy,
) -> Result<ProjectSetupView, StoreError> {
    let result = sqlx::query(
        "UPDATE project_ingest_keys k SET environment = $4, allowed_cidrs = $5 FROM projects p, organization_memberships m, users u WHERE k.project_id = p.id AND k.organization_id = p.organization_id AND m.organization_id = p.organization_id AND m.role = 'owner' AND u.id = m.user_id AND u.bootstrap_subject = $1 AND p.id::text = $2 AND k.id::text = $3",
    )
    .bind(subject)
    .bind(project_id)
    .bind(key_id)
    .bind(&policy.environment)
    .bind(&policy.allowed_cidrs)
    .execute(pool)
    .await
    .map_err(map_sqlx_error)?;
    if result.rows_affected() != 1 {
        return Err(StoreError::NotFound);
    }
    postgres_get_setup(pool, subject, project_id).await
}

async fn postgres_revoke_key(
    pool: &PgPool,
    subject: &str,
    project_id: &str,
    key_id: &str,
) -> Result<(), StoreError> {
    let result = sqlx::query(
        "UPDATE project_ingest_keys k SET revoked_at = COALESCE(k.revoked_at, now()) FROM projects p, organization_memberships m, users u WHERE k.project_id = p.id AND k.organization_id = p.organization_id AND m.organization_id = p.organization_id AND m.role = 'owner' AND u.id = m.user_id AND u.bootstrap_subject = $1 AND p.id::text = $2 AND k.id::text = $3",
    )
    .bind(subject)
    .bind(project_id)
    .bind(key_id)
    .execute(pool)
    .await
    .map_err(map_sqlx_error)?;

    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(StoreError::NotFound)
    }
}

async fn postgres_resolve_key(
    pool: &PgPool,
    digest: &[u8],
) -> Result<Option<KeyScope>, StoreError> {
    let row = sqlx::query(
        "SELECT id::text AS key_id, organization_id::text AS organization_id, project_id::text AS project_id, environment, allowed_cidrs FROM project_ingest_keys WHERE secret_hash = $1 AND revoked_at IS NULL",
    )
    .bind(digest)
    .fetch_optional(pool)
    .await
    .map_err(map_sqlx_error)?;

    row.map(|row| {
        let cidrs: Vec<String> = row.get("allowed_cidrs");
        let allowed_cidrs = cidrs
            .into_iter()
            .map(|value| value.parse::<IpNet>().map_err(|_| StoreError::Internal))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(KeyScope {
            key_id: row.get("key_id"),
            organization_id: row.get("organization_id"),
            project_id: row.get("project_id"),
            environment: row.get("environment"),
            allowed_cidrs,
        })
    })
    .transpose()
}

fn map_sqlx_error(error: sqlx::Error) -> StoreError {
    let unique_violation = error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation);
    drop(error);
    if unique_violation {
        StoreError::Conflict
    } else {
        StoreError::Internal
    }
}

fn map_bootstrap_error(error: sqlx::Error) -> StoreError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        == Some("users_bootstrap_subject_key")
    {
        StoreError::AlreadyBootstrapped
    } else {
        map_sqlx_error(error)
    }
}

#[cfg(test)]
#[derive(Default)]
struct MemoryStore {
    next_id: u64,
    setup: Option<MemorySetup>,
    outside_projects: Vec<String>,
}

#[cfg(test)]
struct MemorySetup {
    subject: String,
    view: ProjectSetupView,
    keys: Vec<MemoryKey>,
}

#[cfg(test)]
struct MemoryKey {
    id: String,
    digest: Vec<u8>,
    environment: String,
    allowed_cidrs: Vec<String>,
    revoked: bool,
}

#[cfg(test)]
fn memory_bootstrap(
    store: &std::sync::Mutex<MemoryStore>,
    subject: &str,
    request: &ValidatedSetup,
    key: &GeneratedKey,
    policy: &ValidatedKeyPolicy,
) -> Result<StoredSetup, StoreError> {
    let mut store = store.lock().map_err(|_| StoreError::Internal)?;
    if store.setup.is_some() {
        return Err(StoreError::AlreadyBootstrapped);
    }
    store.next_id += 1;
    let owner_id = format!("owner-{}", store.next_id);
    store.next_id += 1;
    let organization_id = format!("organization-{}", store.next_id);
    store.next_id += 1;
    let project_id = format!("project-{}", store.next_id);
    store.next_id += 1;
    let key_id = format!("key-{}", store.next_id);
    let view = ProjectSetupView {
        owner_id,
        organization: OrganizationView {
            id: organization_id,
            name: request.organization_name.clone(),
            slug: request.organization_slug.clone(),
        },
        project: ProjectView {
            id: project_id,
            name: request.project_name.clone(),
            slug: request.project_slug.clone(),
        },
        ingest_keys: vec![IngestKeyView {
            id: key_id.clone(),
            display_suffix: key.display_suffix.clone(),
            environment: policy.environment.clone(),
            allowed_cidrs: policy.allowed_cidrs.clone(),
            created_at: "2026-08-13T00:00:00Z".to_owned(),
            revoked_at: None,
        }],
    };
    store.setup = Some(MemorySetup {
        subject: subject.to_owned(),
        view: view.clone(),
        keys: vec![MemoryKey {
            id: key_id.clone(),
            digest: key.digest.clone(),
            environment: policy.environment.clone(),
            allowed_cidrs: policy.allowed_cidrs.clone(),
            revoked: false,
        }],
    });
    Ok(StoredSetup {
        setup: view,
        key_id,
    })
}

#[cfg(test)]
fn memory_get_setup(
    store: &std::sync::Mutex<MemoryStore>,
    subject: &str,
    project_id: &str,
) -> Result<ProjectSetupView, StoreError> {
    let store = store.lock().map_err(|_| StoreError::Internal)?;
    if store.outside_projects.iter().any(|id| id == project_id) {
        return Err(StoreError::NotFound);
    }
    let setup = store.setup.as_ref().ok_or(StoreError::NotFound)?;
    if setup.subject == subject && setup.view.project.id == project_id {
        Ok(setup.view.clone())
    } else {
        Err(StoreError::NotFound)
    }
}

#[cfg(test)]
fn memory_rotate_key(
    store: &std::sync::Mutex<MemoryStore>,
    subject: &str,
    project_id: &str,
    key: &GeneratedKey,
    policy: &ValidatedKeyPolicy,
) -> Result<StoredSetup, StoreError> {
    let mut store = store.lock().map_err(|_| StoreError::Internal)?;
    store.next_id += 1;
    let key_id = format!("key-{}", store.next_id);
    let setup = store.setup.as_mut().ok_or(StoreError::NotFound)?;
    if setup.subject != subject || setup.view.project.id != project_id {
        return Err(StoreError::NotFound);
    }
    setup.keys.push(MemoryKey {
        id: key_id.clone(),
        digest: key.digest.clone(),
        environment: policy.environment.clone(),
        allowed_cidrs: policy.allowed_cidrs.clone(),
        revoked: false,
    });
    setup.view.ingest_keys.push(IngestKeyView {
        id: key_id.clone(),
        display_suffix: key.display_suffix.clone(),
        environment: policy.environment.clone(),
        allowed_cidrs: policy.allowed_cidrs.clone(),
        created_at: "2026-08-13T00:00:00Z".to_owned(),
        revoked_at: None,
    });
    Ok(StoredSetup {
        setup: setup.view.clone(),
        key_id,
    })
}

#[cfg(test)]
fn memory_update_key_policy(
    store: &std::sync::Mutex<MemoryStore>,
    subject: &str,
    project_id: &str,
    key_id: &str,
    policy: &ValidatedKeyPolicy,
) -> Result<ProjectSetupView, StoreError> {
    let mut store = store.lock().map_err(|_| StoreError::Internal)?;
    let setup = store.setup.as_mut().ok_or(StoreError::NotFound)?;
    if setup.subject != subject || setup.view.project.id != project_id {
        return Err(StoreError::NotFound);
    }
    let key = setup
        .keys
        .iter_mut()
        .find(|key| key.id == key_id)
        .ok_or(StoreError::NotFound)?;
    key.environment.clone_from(&policy.environment);
    key.allowed_cidrs.clone_from(&policy.allowed_cidrs);
    let view = setup
        .view
        .ingest_keys
        .iter_mut()
        .find(|key| key.id == key_id)
        .ok_or(StoreError::NotFound)?;
    view.environment.clone_from(&policy.environment);
    view.allowed_cidrs.clone_from(&policy.allowed_cidrs);
    Ok(setup.view.clone())
}

#[cfg(test)]
fn memory_revoke_key(
    store: &std::sync::Mutex<MemoryStore>,
    subject: &str,
    project_id: &str,
    key_id: &str,
) -> Result<(), StoreError> {
    let mut store = store.lock().map_err(|_| StoreError::Internal)?;
    let setup = store.setup.as_mut().ok_or(StoreError::NotFound)?;
    if setup.subject != subject || setup.view.project.id != project_id {
        return Err(StoreError::NotFound);
    }
    let key = setup
        .keys
        .iter_mut()
        .find(|key| key.id == key_id)
        .ok_or(StoreError::NotFound)?;
    key.revoked = true;
    if let Some(view) = setup
        .view
        .ingest_keys
        .iter_mut()
        .find(|key| key.id == key_id)
    {
        view.revoked_at = Some("2026-08-13T00:00:00Z".to_owned());
    }
    Ok(())
}

#[cfg(test)]
fn memory_resolve_key(
    store: &std::sync::Mutex<MemoryStore>,
    digest: &[u8],
) -> Result<Option<KeyScope>, StoreError> {
    let store = store.lock().map_err(|_| StoreError::Internal)?;
    let Some(setup) = store.setup.as_ref() else {
        return Ok(None);
    };
    setup
        .keys
        .iter()
        .find(|key| !key.revoked && key.digest == digest)
        .map(|key| {
            let allowed_cidrs = key
                .allowed_cidrs
                .iter()
                .map(|value| value.parse::<IpNet>().map_err(|_| StoreError::Internal))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(KeyScope {
                key_id: key.id.clone(),
                organization_id: setup.view.organization.id.clone(),
                project_id: setup.view.project.id.clone(),
                environment: key.environment.clone(),
                allowed_cidrs,
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, request::Builder},
    };
    use serde_json::{Value, json};
    use sqlx::Row;
    use tower::ServiceExt;

    use super::{
        BootstrapAuthorization, DATABASE_TEST_LOCK, ServerState, StartupError, hash, migrate,
        router, valid_name, validate_ingest_base_url,
    };

    const SECRET: &str = "local-bootstrap-secret-with-32-bytes";

    fn authorized(request: Builder) -> Builder {
        request
            .header("authorization", format!("Bootstrap {SECRET}"))
            .header("content-type", "application/json")
    }

    async fn json_body(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap_or_else(|error| panic!("response body must be readable: {error}"));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("response must be JSON: {error}"))
    }

    async fn create(state: &ServerState) -> (StatusCode, Value) {
        let response = router("api", state.clone())
            .oneshot(
                authorized(Request::builder().method("POST").uri("/api/v1/setup"))
                    .body(Body::from(
                        json!({
                            "owner_email": "owner@example.com",
                            "organization_name": "Example Studio",
                            "organization_slug": "example-studio",
                            "project_name": "CacheLane Proof",
                            "project_slug": "cachelane-proof"
                        })
                        .to_string(),
                    ))
                    .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        let status = response.status();
        let body = json_body(response).await;
        (status, body)
    }

    #[test]
    fn bootstrap_requires_a_loopback_host_and_long_secret() {
        assert!(matches!(
            BootstrapAuthorization::new("0.0.0.0", true, Some(SECRET)),
            Err(StartupError::InvalidConfiguration(_))
        ));
        assert!(matches!(
            BootstrapAuthorization::new("127.0.0.1", true, Some("short")),
            Err(StartupError::InvalidConfiguration(_))
        ));
        assert!(BootstrapAuthorization::new("0.0.0.0", false, None).is_ok());
        assert!(validate_ingest_base_url("http://127.0.0.1:8081/").is_ok());
        assert!(validate_ingest_base_url("http://127.0.0.1:8081/path").is_err());
        assert!(validate_ingest_base_url("https://user@example.com").is_err());
        assert!(!valid_name("Example\\"));
    }

    #[tokio::test]
    async fn concurrent_bootstrap_creates_only_one_setup() {
        let state = ServerState::memory(SECRET);
        let (first, second) = tokio::join!(create(&state), create(&state));
        let mut statuses = [first.0.as_u16(), second.0.as_u16()];
        statuses.sort_unstable();

        assert_eq!(
            statuses,
            [StatusCode::CREATED.as_u16(), StatusCode::CONFLICT.as_u16()]
        );
    }

    #[tokio::test]
    async fn creates_setup_once_and_never_returns_the_key_again() {
        let state = ServerState::memory(SECRET);
        let (status, created) = create(&state).await;

        assert_eq!(status, StatusCode::CREATED);
        let value = created["ingest_key"]["value"]
            .as_str()
            .unwrap_or_else(|| panic!("created key must be present"));
        assert!(value.starts_with("clpk_"));
        assert!(
            created["data_router_url"]
                .as_str()
                .is_some_and(|url| url.ends_with(value))
        );
        assert_eq!(
            created["configuration"]["default_game_ini_path"],
            "Config/DefaultGame.ini"
        );
        assert_eq!(
            created["configuration"]["default_engine_ini_path"],
            "Config/DefaultEngine.ini"
        );
        assert!(
            created["configuration"]["default_engine_ini"]
                .as_str()
                .is_some_and(|configuration| {
                    configuration.contains(value) && configuration.contains("bSendLogFile=true")
                })
        );

        let (second_status, second) = create(&state).await;
        assert_eq!(second_status, StatusCode::CONFLICT);
        assert_eq!(second["code"], "setup_conflict");

        let project_id = created["setup"]["project"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("project id must exist"));
        let response = router("api", state)
            .oneshot(
                authorized(Request::builder().uri(format!("/api/v1/projects/{project_id}/setup")))
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        let refreshed = json_body(response).await;
        assert!(refreshed.get("ingest_key").is_none());
        assert!(!refreshed.to_string().contains(value));
    }

    #[tokio::test]
    async fn rotates_and_revokes_write_only_keys() {
        let state = ServerState::memory(SECRET);
        let (_, created) = create(&state).await;
        let project_id = created["setup"]["project"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("project id must exist"));
        let first_key = created["ingest_key"]["value"]
            .as_str()
            .unwrap_or_else(|| panic!("created key must exist"));
        let first_key_id = created["setup"]["ingest_keys"][0]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("key id must exist"));

        let rotated = router("api", state.clone())
            .oneshot(
                authorized(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/v1/projects/{project_id}/ingest-keys")),
                )
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        assert_eq!(rotated.status(), StatusCode::CREATED);
        let rotated = json_body(rotated).await;
        let second_key = rotated["ingest_key"]["value"]
            .as_str()
            .unwrap_or_else(|| panic!("rotated key must exist"));
        assert_ne!(first_key, second_key);
        assert_eq!(
            rotated["setup"]["ingest_keys"].as_array().map(Vec::len),
            Some(2)
        );

        for key in [first_key, second_key] {
            let response = router("ingest", state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/u/{key}"))
                        .body(Body::empty())
                        .unwrap_or_else(|error| panic!("request must build: {error}")),
                )
                .await
                .unwrap_or_else(|error| panic!("router must answer: {error}"));
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }

        let revoked = router("api", state.clone())
            .oneshot(
                authorized(Request::builder().method("DELETE").uri(format!(
                    "/api/v1/projects/{project_id}/ingest-keys/{first_key_id}"
                )))
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

        let revoked_again = router("api", state.clone())
            .oneshot(
                authorized(Request::builder().method("DELETE").uri(format!(
                    "/api/v1/projects/{project_id}/ingest-keys/{first_key_id}"
                )))
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        assert_eq!(revoked_again.status(), StatusCode::NO_CONTENT);

        let response = router("ingest", state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/u/{first_key}"))
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn updates_environment_and_allowlist_for_one_key() {
        let state = ServerState::memory(SECRET);
        let (_, created) = create(&state).await;
        let project_id = created["setup"]["project"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("project id must exist"));
        let key_id = created["setup"]["ingest_keys"][0]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("key id must exist"));
        let key = created["ingest_key"]["value"]
            .as_str()
            .unwrap_or_else(|| panic!("created key must exist"));
        let response = router("api", state.clone())
            .oneshot(
                authorized(Request::builder().method("PATCH").uri(format!(
                    "/api/v1/projects/{project_id}/ingest-keys/{key_id}/policy"
                )))
                .body(Body::from(
                    json!({
                        "environment": "playtest",
                        "allowed_cidrs": ["203.0.113.0/24", "203.0.113.0/24"]
                    })
                    .to_string(),
                ))
                .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["setup"]["ingest_keys"][0]["environment"], "playtest");
        assert_eq!(
            body["setup"]["ingest_keys"][0]["allowed_cidrs"],
            json!(["203.0.113.0/24"])
        );
        let scope = state
            .resolve_ingest_scope(key)
            .await
            .unwrap_or_else(|error| panic!("key lookup must succeed: {error:?}"))
            .unwrap_or_else(|| panic!("key must resolve"));
        assert_eq!(scope.environment, "playtest");
        assert!(
            scope.allowed_cidrs[0].contains(
                &"203.0.113.8"
                    .parse::<std::net::IpAddr>()
                    .unwrap_or_else(|error| panic!("test address must be valid: {error}"))
            )
        );
    }

    #[tokio::test]
    async fn ingest_keys_cannot_access_control_routes() {
        let state = ServerState::memory(SECRET);
        let (_, created) = create(&state).await;
        let project_id = created["setup"]["project"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("project id must exist"));
        let key = created["ingest_key"]["value"]
            .as_str()
            .unwrap_or_else(|| panic!("created key must exist"));
        let key_id = created["ingest_key"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("created key id must exist"));

        for (method, path) in [
            ("POST", "/api/v1/setup".to_owned()),
            ("GET", format!("/api/v1/projects/{project_id}/setup")),
            ("POST", format!("/api/v1/projects/{project_id}/ingest-keys")),
            (
                "DELETE",
                format!("/api/v1/projects/{project_id}/ingest-keys/{key_id}"),
            ),
        ] {
            let control = router("api", state.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("authorization", format!("Bootstrap {key}"))
                        .body(Body::empty())
                        .unwrap_or_else(|error| panic!("request must build: {error}")),
                )
                .await
                .unwrap_or_else(|error| panic!("router must answer: {error}"));
            assert_eq!(control.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn rejects_invalid_requests_and_unknown_resources_without_echoing_them() {
        let state = ServerState::memory(SECRET);
        let invalid = "private-do-not-echo";
        let response = router("api", state.clone())
            .oneshot(
                authorized(Request::builder().method("POST").uri("/api/v1/setup"))
                    .body(Body::from(format!("{{\"owner_email\":\"{invalid}\"}}")))
                    .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        let body = json_body(response).await.to_string();
        assert!(!body.contains(invalid));

        let unauthorized = router("api", state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/setup")
                    .header("authorization", format!("Bootstrap {invalid}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        let body = json_body(unauthorized).await.to_string();
        assert!(!body.contains(invalid));
    }

    #[tokio::test]
    async fn malformed_and_unknown_ingest_keys_are_indistinguishable() {
        let state = ServerState::memory(SECRET);
        let malformed = "clpk_private-do-not-echo";
        let unknown = format!("clpk_{}", "0".repeat(64));
        let mut responses = Vec::new();

        for key in [malformed, &unknown] {
            let response = router("ingest", state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/u/{key}"))
                        .body(Body::empty())
                        .unwrap_or_else(|error| panic!("request must build: {error}")),
                )
                .await
                .unwrap_or_else(|error| panic!("router must answer: {error}"));
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            responses.push(json_body(response).await);
        }

        assert_eq!(responses[0], responses[1]);
        assert!(!responses[0].to_string().contains("private-do-not-echo"));
    }

    #[tokio::test]
    async fn hides_projects_outside_the_bootstrap_organization() {
        let state = ServerState::memory(SECRET);
        let _ = create(&state).await;
        state.add_outside_project("outside-project");

        for (method, path) in [
            ("GET", "/api/v1/projects/outside-project/setup"),
            ("POST", "/api/v1/projects/outside-project/ingest-keys"),
            (
                "DELETE",
                "/api/v1/projects/outside-project/ingest-keys/key-1",
            ),
        ] {
            let response = router("api", state.clone())
                .oneshot(
                    authorized(Request::builder().method(method).uri(path))
                        .body(Body::empty())
                        .unwrap_or_else(|error| panic!("request must build: {error}")),
                )
                .await
                .unwrap_or_else(|error| panic!("router must answer: {error}"));
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    async fn assert_single_setup_rows(pool: &sqlx::PgPool) {
        let counts = sqlx::query(
            "SELECT (SELECT count(*) FROM users) AS users, (SELECT count(*) FROM organizations) AS organizations, (SELECT count(*) FROM projects) AS projects, (SELECT count(*) FROM project_ingest_keys) AS keys",
        )
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("setup counts must load: {error}"));
        for column in ["users", "organizations", "projects", "keys"] {
            assert_eq!(counts.get::<i64, _>(column), 1);
        }
    }

    async fn insert_outside_project(pool: &sqlx::PgPool) -> (String, String) {
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Outside Studio', 'outside-studio') RETURNING id::text",
        )
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("outside organization must insert: {error}"));
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Outside Project', 'outside-project') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("outside project must insert: {error}"));
        let key_id: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, '00000000') RETURNING id::text",
        )
        .bind(organization_id)
        .bind(&project_id)
        .bind(hash("outside-key"))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("outside key must insert: {error}"));
        (project_id, key_id)
    }

    async fn assert_outside_operations_hidden(state: &ServerState, project_id: &str, key_id: &str) {
        for (method, path) in [
            ("GET", format!("/api/v1/projects/{project_id}/setup")),
            ("POST", format!("/api/v1/projects/{project_id}/ingest-keys")),
            (
                "DELETE",
                format!("/api/v1/projects/{project_id}/ingest-keys/{key_id}"),
            ),
        ] {
            let response = router("api", state.clone())
                .oneshot(
                    authorized(Request::builder().method(method).uri(path))
                        .body(Body::empty())
                        .unwrap_or_else(|error| panic!("request must build: {error}")),
                )
                .await
                .unwrap_or_else(|error| panic!("router must answer: {error}"));
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    fn assert_isolated_database(database_url: &str) {
        let database_name = database_url
            .rsplit('/')
            .next()
            .and_then(|value| value.split('?').next())
            .unwrap_or_default();
        assert!(
            database_name == "cachelane_295"
                || database_name.starts_with("cachelane_295_")
                || database_name == "cachelane_296"
                || database_name.starts_with("cachelane_296_")
                || database_name == "cachelane_test"
        );
    }

    #[tokio::test]
    async fn postgres_persists_hashes_and_enforces_tenant_scope_when_configured() {
        let Ok(database_url) = std::env::var("CACHELANE_TEST_DATABASE_URL") else {
            return;
        };
        let _guard = DATABASE_TEST_LOCK.lock().await;
        assert_isolated_database(&database_url);

        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test migrations must run: {error}"));
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));

        let state = ServerState::postgres(
            &database_url,
            "127.0.0.1",
            true,
            Some(SECRET),
            "http://127.0.0.1:8081",
            "worker",
        )
        .await
        .unwrap_or_else(|error| panic!("test state must start: {error}"));
        let (first, second) = tokio::join!(create(&state), create(&state));
        let mut statuses = [first.0.as_u16(), second.0.as_u16()];
        statuses.sort_unstable();
        assert_eq!(
            statuses,
            [StatusCode::CREATED.as_u16(), StatusCode::CONFLICT.as_u16()]
        );
        let created = if first.0 == StatusCode::CREATED {
            first.1
        } else {
            second.1
        };
        assert_single_setup_rows(&pool).await;
        let key = created["ingest_key"]["value"]
            .as_str()
            .unwrap_or_else(|| panic!("created key must exist"))
            .to_owned();
        let key_id = created["ingest_key"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("created key id must exist"))
            .to_owned();
        let stored_hash: Vec<u8> =
            sqlx::query_scalar("SELECT secret_hash FROM project_ingest_keys WHERE id::text = $1")
                .bind(&key_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("stored key hash must load: {error}"));
        assert_eq!(stored_hash, hash(&key));
        assert_ne!(stored_hash, key.as_bytes());

        let restarted = ServerState::postgres(
            &database_url,
            "127.0.0.1",
            true,
            Some(SECRET),
            "http://127.0.0.1:8081",
            "worker",
        )
        .await
        .unwrap_or_else(|error| panic!("restarted test state must start: {error}"));
        let response = router("ingest", restarted)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/u/{key}"))
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let (outside_project, outside_key) = insert_outside_project(&pool).await;
        assert_outside_operations_hidden(&state, &outside_project, &outside_key).await;
    }
}
