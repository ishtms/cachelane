use std::{
    collections::BTreeSet,
    env, fmt, fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{Path as AxumPath, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use hmac::{Hmac, Mac as _};
use reqwest::{Client, Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::net::lookup_host;
use tracing::{info, warn};

use crate::{
    identifiers::valid_uuid,
    project_setup::{ServerState, StartupError},
};

const MAX_NAME_BYTES: usize = 80;
const MAX_ENVIRONMENT_BYTES: usize = 32;
const MAX_ENDPOINT_BYTES: usize = 2048;
const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
const DELIVERY_LEASE_SECONDS: i64 = 30;
const DELIVERY_POLL_MILLISECONDS: u64 = 250;
const ALERT_RULE_PAGE_SIZE: i64 = 1_000;
const ALERT_ISSUE_PAGE_SIZE: i64 = 1_000;
const ALERT_RECOVERY_PAGE_SIZE: i64 = 1_000;
const CONFIG_VERSION: i32 = 1;

#[derive(Clone)]
pub(crate) struct Alerts {
    enabled: bool,
    cipher: Option<SecretCipher>,
}

impl Alerts {
    pub(crate) fn for_role(role: &str) -> Result<Self, StartupError> {
        let enabled = enabled_from_environment();
        validate_public_base_url(
            &env::var("PUBLIC_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned()),
        )?;
        let needs_cipher = enabled && matches!(role, "api" | "worker");
        let cipher = if needs_cipher {
            Some(SecretCipher::from_environment()?)
        } else {
            None
        };
        Ok(Self { enabled, cipher })
    }

    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            cipher: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn test(key: [u8; 32]) -> Self {
        Self {
            enabled: true,
            cipher: Some(SecretCipher::new(key)),
        }
    }

    fn cipher(&self) -> Result<&SecretCipher, AlertError> {
        self.cipher.as_ref().ok_or(AlertError::Unavailable)
    }
}

pub(crate) fn enabled_from_environment() -> bool {
    env::var("FAULTLANE_ALERTS_ENABLED").is_ok_and(|value| value.eq_ignore_ascii_case("true"))
}

#[derive(Clone)]
struct SecretCipher {
    key: Arc<[u8; 32]>,
}

impl SecretCipher {
    fn from_environment() -> Result<Self, StartupError> {
        let encoded = match (
            nonempty_environment("FAULTLANE_INTEGRATION_KEY_FILE"),
            nonempty_environment("FAULTLANE_INTEGRATION_KEY"),
        ) {
            (Some(path), None) => read_secret_file(Path::new(&path))?,
            (None, Some(value)) => value,
            _ => return Err(StartupError::AlertsConfiguration),
        };
        let decoded = STANDARD
            .decode(encoded.trim())
            .map_err(|_| StartupError::AlertsConfiguration)?;
        let key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| StartupError::AlertsConfiguration)?;
        Ok(Self::new(key))
    }

    fn new(key: [u8; 32]) -> Self {
        Self { key: Arc::new(key) }
    }

    fn encrypt(
        &self,
        scope: &SecretScope<'_>,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), AlertError> {
        if plaintext.is_empty() || plaintext.len() > MAX_ENDPOINT_BYTES + 512 {
            return Err(AlertError::InvalidRequest);
        }
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| AlertError::Internal)?;
        let key: Key = (*self.key).into();
        let nonce: XNonce = nonce.into();
        let cipher = XChaCha20Poly1305::new(&key);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: scope.aad().as_bytes(),
                },
            )
            .map_err(|_| AlertError::Internal)?;
        Ok((ciphertext, nonce.to_vec()))
    }

    fn decrypt(
        &self,
        scope: &SecretScope<'_>,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, DeliveryError> {
        if nonce.len() != 24 || ciphertext.len() < 17 || ciphertext.len() > 8192 {
            return Err(DeliveryError::Permanent("integration_config_invalid"));
        }
        let key: Key = (*self.key).into();
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| DeliveryError::Permanent("integration_config_invalid"))?;
        let nonce: XNonce = nonce.into();
        let cipher = XChaCha20Poly1305::new(&key);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: scope.aad().as_bytes(),
                },
            )
            .map_err(|_| DeliveryError::Permanent("integration_decrypt_failed"))
    }
}

struct SecretScope<'a> {
    organization_id: &'a str,
    project_id: &'a str,
    integration_id: &'a str,
    kind: &'a str,
}

impl SecretScope<'_> {
    fn aad(&self) -> String {
        format!(
            "faultlane-integration-v{CONFIG_VERSION}:{}:{}:{}:{}",
            self.organization_id, self.project_id, self.integration_id, self.kind
        )
    }
}

fn read_secret_file(path: &Path) -> Result<String, StartupError> {
    let metadata = fs::metadata(path).map_err(|_| StartupError::AlertsConfiguration)?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(StartupError::AlertsConfiguration);
    }
    fs::read_to_string(path).map_err(|_| StartupError::AlertsConfiguration)
}

fn nonempty_environment(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn validate_public_base_url(value: &str) -> Result<String, StartupError> {
    let url = Url::parse(value).map_err(|_| StartupError::AlertsConfiguration)?;
    let valid_scheme = url.scheme() == "https"
        || (url.scheme() == "http"
            && url
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost")));
    if !valid_scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(StartupError::AlertsConfiguration);
    }
    Ok(value.trim_end_matches('/').to_owned())
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AlertError {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
    Internal,
}

impl IntoResponse for AlertError {
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
            Self::Conflict => (StatusCode::CONFLICT, "conflict", "resource already exists"),
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
        no_store(status, &json!({"code": code, "message": message}))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateIntegration {
    kind: String,
    name: String,
    recipient_user_id: Option<String>,
    url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateIntegration {
    name: Option<String>,
    enabled: Option<bool>,
    url: Option<String>,
    #[serde(default)]
    rotate_signing_secret: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateRule {
    integration_id: String,
    condition_kind: String,
    environment: String,
    threshold: Option<i32>,
    window_seconds: Option<i32>,
    quiet_start_minute: Option<i32>,
    quiet_end_minute: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateRule {
    enabled: Option<bool>,
    threshold: Option<i32>,
    window_seconds: Option<i32>,
    quiet_start_minute: Option<i32>,
    quiet_end_minute: Option<i32>,
    #[serde(default)]
    clear_quiet_hours: bool,
}

#[derive(Serialize)]
struct IntegrationView {
    id: String,
    kind: String,
    name: String,
    recipient_user_id: Option<String>,
    endpoint_host: Option<String>,
    enabled: bool,
    created_at: String,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_secret: Option<String>,
}

#[derive(Serialize)]
struct RuleView {
    id: String,
    integration_id: String,
    condition_kind: String,
    environment: String,
    threshold: Option<i32>,
    window_seconds: Option<i32>,
    quiet_start_minute: Option<i32>,
    quiet_end_minute: Option<i32>,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

pub(crate) async fn get_alerts(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath(project_id): AxumPath<String>,
) -> Result<Response, AlertError> {
    require_enabled(&state)?;
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ReadProject,
    )
    .await?;
    let pool = state.control_pool().ok_or(AlertError::Unavailable)?;
    let integration_rows = sqlx::query(
        "SELECT id::text AS id, kind, name, recipient_user_id::text AS recipient_user_id, endpoint_host, enabled, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at FROM alert_integrations WHERE organization_id = $1::uuid AND project_id = $2::uuid ORDER BY created_at, id",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_all(pool)
    .await
    .map_err(|_| AlertError::Unavailable)?;
    let rule_rows = sqlx::query(
        "SELECT id::text AS id, integration_id::text AS integration_id, condition_kind, environment, threshold, window_seconds, quiet_start_minute, quiet_end_minute, enabled, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at FROM alert_rules WHERE organization_id = $1::uuid AND project_id = $2::uuid ORDER BY created_at, id",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_all(pool)
    .await
    .map_err(|_| AlertError::Unavailable)?;
    let condition_rows = sqlx::query(
        "SELECT rule_id::text AS rule_id, scope_key, state, generation, payload, to_char(transitioned_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS transitioned_at FROM alert_condition_states WHERE organization_id = $1::uuid AND project_id = $2::uuid ORDER BY transitioned_at DESC LIMIT 100",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_all(pool)
    .await
    .map_err(|_| AlertError::Unavailable)?;
    let delivery_rows = sqlx::query(
        "SELECT id::text AS id, integration_id::text AS integration_id, rule_id::text AS rule_id, scope_key, generation, transition, state, attempt, failure_code, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, CASE WHEN delivered_at IS NULL THEN NULL ELSE to_char(delivered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') END AS delivered_at FROM alert_deliveries WHERE organization_id = $1::uuid AND project_id = $2::uuid ORDER BY created_at DESC, id DESC LIMIT 100",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_all(pool)
    .await
    .map_err(|_| AlertError::Unavailable)?;
    let integrations = integration_rows
        .iter()
        .map(|row| integration_view(row, None))
        .collect::<Vec<_>>();
    let rules = rule_rows.iter().map(rule_view).collect::<Vec<_>>();
    let conditions = condition_rows
        .iter()
        .map(|row| {
            json!({
                "rule_id": row.get::<String, _>("rule_id"),
                "scope_key": row.get::<String, _>("scope_key"),
                "state": row.get::<String, _>("state"),
                "generation": row.get::<i64, _>("generation"),
                "payload": row.get::<Value, _>("payload"),
                "transitioned_at": row.get::<String, _>("transitioned_at")
            })
        })
        .collect::<Vec<_>>();
    let deliveries = delivery_rows
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<String, _>("id"),
                "integration_id": row.get::<String, _>("integration_id"),
                "rule_id": row.get::<String, _>("rule_id"),
                "scope_key": row.get::<String, _>("scope_key"),
                "generation": row.get::<i64, _>("generation"),
                "transition": row.get::<String, _>("transition"),
                "state": row.get::<String, _>("state"),
                "attempt": row.get::<i32, _>("attempt"),
                "failure_code": row.get::<Option<String>, _>("failure_code"),
                "created_at": row.get::<String, _>("created_at"),
                "delivered_at": row.get::<Option<String>, _>("delivered_at")
            })
        })
        .collect::<Vec<_>>();
    Ok(no_store(
        StatusCode::OK,
        &json!({
            "enabled": true,
            "can_edit": actor.allows(crate::auth::Permission::ManageProject),
            "integrations": integrations,
            "rules": rules,
            "conditions": conditions,
            "deliveries": deliveries
        }),
    ))
}

pub(crate) async fn create_integration(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath(project_id): AxumPath<String>,
    body: Result<Json<CreateIntegration>, JsonRejection>,
) -> Result<Response, AlertError> {
    require_enabled(&state)?;
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ManageProject,
    )
    .await?;
    let Json(request) = body.map_err(|_| AlertError::InvalidRequest)?;
    let name = valid_name(&request.name)?;
    let kind = valid_kind(&request.kind)?;
    let pool = state.control_pool().ok_or(AlertError::Unavailable)?;
    let id = random_uuid().map_err(|_| AlertError::Internal)?;
    let (recipient_user_id, endpoint_host, encrypted, nonce, signing_secret) = if kind == "email" {
        let recipient = request
            .recipient_user_id
            .as_deref()
            .or(Some(actor.actor.user_id.as_str()))
            .filter(|value| valid_uuid(value))
            .ok_or(AlertError::InvalidRequest)?;
        if request.url.is_some() {
            return Err(AlertError::InvalidRequest);
        }
        ensure_member(pool, &actor.organization_id, recipient).await?;
        (Some(recipient.to_owned()), None, None, None, None)
    } else {
        if request.recipient_user_id.is_some() {
            return Err(AlertError::InvalidRequest);
        }
        let url = request.url.as_deref().ok_or(AlertError::InvalidRequest)?;
        let parsed = validate_customer_destination(kind, url)?;
        validate_public_resolution(&parsed).await?;
        let signing_secret = (kind == "webhook")
            .then(generate_signing_secret)
            .transpose()?;
        let config = SecretConfig {
            url: parsed.as_str().to_owned(),
            signing_secret: signing_secret.clone(),
        };
        let plaintext = serde_json::to_vec(&config).map_err(|_| AlertError::Internal)?;
        let scope = SecretScope {
            organization_id: &actor.organization_id,
            project_id: &actor.project_id,
            integration_id: &id,
            kind,
        };
        let (encrypted, nonce) = state.alerts().cipher()?.encrypt(&scope, &plaintext)?;
        (
            None,
            parsed.host_str().map(str::to_owned),
            Some(encrypted),
            Some(nonce),
            signing_secret,
        )
    };
    let mut transaction = pool.begin().await.map_err(|_| AlertError::Unavailable)?;
    let row = sqlx::query(
        "INSERT INTO alert_integrations (id, organization_id, project_id, kind, name, endpoint_host, recipient_user_id, encrypted_config, config_nonce, config_version, created_by_user_id) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7::uuid, $8, $9, $10, $11::uuid) RETURNING id::text AS id, kind, name, recipient_user_id::text AS recipient_user_id, endpoint_host, enabled, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at",
    )
    .bind(&id)
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .bind(kind)
    .bind(name)
    .bind(endpoint_host)
    .bind(recipient_user_id)
    .bind(encrypted)
    .bind(nonce)
    .bind((kind != "email").then_some(CONFIG_VERSION))
    .bind(&actor.actor.user_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(database_write_error)?;
    audit(
        &mut transaction,
        &actor.organization_id,
        &actor.actor.user_id,
        "alert_integration.created",
        "alert_integration",
        &id,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| AlertError::Unavailable)?;
    Ok(no_store(
        StatusCode::CREATED,
        &integration_view(&row, signing_secret),
    ))
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn update_integration(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath((project_id, integration_id)): AxumPath<(String, String)>,
    body: Result<Json<UpdateIntegration>, JsonRejection>,
) -> Result<Response, AlertError> {
    require_enabled(&state)?;
    if !valid_uuid(&integration_id) {
        return Err(AlertError::NotFound);
    }
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ManageProject,
    )
    .await?;
    let Json(request) = body.map_err(|_| AlertError::InvalidRequest)?;
    if request.name.is_none()
        && request.enabled.is_none()
        && request.url.is_none()
        && !request.rotate_signing_secret
    {
        return Err(AlertError::InvalidRequest);
    }
    let pool = state.control_pool().ok_or(AlertError::Unavailable)?;
    let current = sqlx::query(
        "SELECT kind, name, encrypted_config, config_nonce FROM alert_integrations WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid",
    )
    .bind(&integration_id)
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| AlertError::Unavailable)?
    .ok_or(AlertError::NotFound)?;
    let kind = current.get::<String, _>("kind");
    let name = request
        .name
        .as_deref()
        .map(valid_name)
        .transpose()?
        .unwrap_or_else(|| current.get("name"));
    if kind == "email" && (request.url.is_some() || request.rotate_signing_secret) {
        return Err(AlertError::InvalidRequest);
    }
    if kind != "webhook" && request.rotate_signing_secret {
        return Err(AlertError::InvalidRequest);
    }
    let mut endpoint_host = None;
    let mut encrypted = current.get::<Option<Vec<u8>>, _>("encrypted_config");
    let mut nonce = current.get::<Option<Vec<u8>>, _>("config_nonce");
    let mut returned_secret = None;
    if kind != "email" && (request.url.is_some() || request.rotate_signing_secret) {
        let scope = SecretScope {
            organization_id: &actor.organization_id,
            project_id: &actor.project_id,
            integration_id: &integration_id,
            kind: &kind,
        };
        let plaintext = state
            .alerts()
            .cipher()?
            .decrypt(
                &scope,
                encrypted.as_deref().ok_or(AlertError::Internal)?,
                nonce.as_deref().ok_or(AlertError::Internal)?,
            )
            .map_err(|_| AlertError::Unavailable)?;
        let mut config: SecretConfig =
            serde_json::from_slice(&plaintext).map_err(|_| AlertError::Unavailable)?;
        if let Some(url) = request.url.as_deref() {
            let parsed = validate_customer_destination(&kind, url)?;
            validate_public_resolution(&parsed).await?;
            endpoint_host = parsed.host_str().map(str::to_owned);
            config.url = parsed.as_str().to_owned();
        }
        if request.rotate_signing_secret {
            let secret = generate_signing_secret()?;
            config.signing_secret = Some(secret.clone());
            returned_secret = Some(secret);
        }
        let plaintext = serde_json::to_vec(&config).map_err(|_| AlertError::Internal)?;
        let result = state.alerts().cipher()?.encrypt(&scope, &plaintext)?;
        encrypted = Some(result.0);
        nonce = Some(result.1);
    }
    let mut transaction = pool.begin().await.map_err(|_| AlertError::Unavailable)?;
    let row = sqlx::query(
        "UPDATE alert_integrations SET name = $4, enabled = COALESCE($5, enabled), endpoint_host = COALESCE($6, endpoint_host), encrypted_config = $7, config_nonce = $8, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid RETURNING id::text AS id, kind, name, recipient_user_id::text AS recipient_user_id, endpoint_host, enabled, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at",
    )
    .bind(&integration_id)
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .bind(name)
    .bind(request.enabled)
    .bind(endpoint_host)
    .bind(encrypted)
    .bind(nonce)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_write_error)?
    .ok_or(AlertError::NotFound)?;
    audit(
        &mut transaction,
        &actor.organization_id,
        &actor.actor.user_id,
        "alert_integration.updated",
        "alert_integration",
        &integration_id,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| AlertError::Unavailable)?;
    Ok(no_store(
        StatusCode::OK,
        &integration_view(&row, returned_secret),
    ))
}

pub(crate) async fn create_rule(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath(project_id): AxumPath<String>,
    body: Result<Json<CreateRule>, JsonRejection>,
) -> Result<Response, AlertError> {
    require_enabled(&state)?;
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ManageProject,
    )
    .await?;
    let Json(request) = body.map_err(|_| AlertError::InvalidRequest)?;
    let condition = valid_condition(&request.condition_kind)?;
    let environment = valid_environment(&request.environment)?;
    validate_rule_fields(
        condition,
        request.threshold,
        request.window_seconds,
        request.quiet_start_minute,
        request.quiet_end_minute,
    )?;
    if !valid_uuid(&request.integration_id) {
        return Err(AlertError::InvalidRequest);
    }
    let pool = state.control_pool().ok_or(AlertError::Unavailable)?;
    let mut transaction = pool.begin().await.map_err(|_| AlertError::Unavailable)?;
    let row = sqlx::query(
        "INSERT INTO alert_rules (organization_id, project_id, integration_id, condition_kind, environment, threshold, window_seconds, quiet_start_minute, quiet_end_minute, created_by_user_id) SELECT $1::uuid, $2::uuid, i.id, $4, $5, $6, $7, $8, $9, $10::uuid FROM alert_integrations i WHERE i.id = $3::uuid AND i.organization_id = $1::uuid AND i.project_id = $2::uuid RETURNING id::text AS id, integration_id::text AS integration_id, condition_kind, environment, threshold, window_seconds, quiet_start_minute, quiet_end_minute, enabled, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at",
    )
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .bind(&request.integration_id)
    .bind(condition)
    .bind(environment)
    .bind(request.threshold)
    .bind(request.window_seconds)
    .bind(request.quiet_start_minute)
    .bind(request.quiet_end_minute)
    .bind(&actor.actor.user_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_write_error)?
    .ok_or(AlertError::NotFound)?;
    let id = row.get::<String, _>("id");
    audit(
        &mut transaction,
        &actor.organization_id,
        &actor.actor.user_id,
        "alert_rule.created",
        "alert_rule",
        &id,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| AlertError::Unavailable)?;
    Ok(no_store(StatusCode::CREATED, &rule_view(&row)))
}

pub(crate) async fn update_rule(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath((project_id, rule_id)): AxumPath<(String, String)>,
    body: Result<Json<UpdateRule>, JsonRejection>,
) -> Result<Response, AlertError> {
    require_enabled(&state)?;
    if !valid_uuid(&rule_id) {
        return Err(AlertError::NotFound);
    }
    let actor = authorize(
        &state,
        &headers,
        &project_id,
        crate::auth::Permission::ManageProject,
    )
    .await?;
    let Json(request) = body.map_err(|_| AlertError::InvalidRequest)?;
    if request.enabled.is_none()
        && request.threshold.is_none()
        && request.window_seconds.is_none()
        && request.quiet_start_minute.is_none()
        && request.quiet_end_minute.is_none()
        && !request.clear_quiet_hours
    {
        return Err(AlertError::InvalidRequest);
    }
    let pool = state.control_pool().ok_or(AlertError::Unavailable)?;
    let current = sqlx::query(
        "SELECT condition_kind, threshold, window_seconds, quiet_start_minute, quiet_end_minute FROM alert_rules WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid",
    )
    .bind(&rule_id)
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| AlertError::Unavailable)?
    .ok_or(AlertError::NotFound)?;
    let condition = current.get::<String, _>("condition_kind");
    let threshold = request
        .threshold
        .or_else(|| current.get::<Option<i32>, _>("threshold"));
    let window_seconds = request
        .window_seconds
        .or_else(|| current.get::<Option<i32>, _>("window_seconds"));
    let (quiet_start, quiet_end) = if request.clear_quiet_hours {
        (None, None)
    } else {
        (
            request
                .quiet_start_minute
                .or_else(|| current.get("quiet_start_minute")),
            request
                .quiet_end_minute
                .or_else(|| current.get("quiet_end_minute")),
        )
    };
    validate_rule_fields(
        &condition,
        threshold,
        window_seconds,
        quiet_start,
        quiet_end,
    )?;
    let mut transaction = pool.begin().await.map_err(|_| AlertError::Unavailable)?;
    let row = sqlx::query(
        "UPDATE alert_rules SET enabled = COALESCE($4, enabled), threshold = $5, window_seconds = $6, quiet_start_minute = $7, quiet_end_minute = $8, last_evaluated_at = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid RETURNING id::text AS id, integration_id::text AS integration_id, condition_kind, environment, threshold, window_seconds, quiet_start_minute, quiet_end_minute, enabled, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at",
    )
    .bind(&rule_id)
    .bind(&actor.organization_id)
    .bind(&actor.project_id)
    .bind(request.enabled)
    .bind(threshold)
    .bind(window_seconds)
    .bind(quiet_start)
    .bind(quiet_end)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_write_error)?
    .ok_or(AlertError::NotFound)?;
    audit(
        &mut transaction,
        &actor.organization_id,
        &actor.actor.user_id,
        "alert_rule.updated",
        "alert_rule",
        &rule_id,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| AlertError::Unavailable)?;
    Ok(no_store(StatusCode::OK, &rule_view(&row)))
}

fn integration_view(
    row: &sqlx::postgres::PgRow,
    signing_secret: Option<String>,
) -> IntegrationView {
    IntegrationView {
        id: row.get("id"),
        kind: row.get("kind"),
        name: row.get("name"),
        recipient_user_id: row.get("recipient_user_id"),
        endpoint_host: row.get("endpoint_host"),
        enabled: row.get("enabled"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        signing_secret,
    }
}

fn rule_view(row: &sqlx::postgres::PgRow) -> RuleView {
    RuleView {
        id: row.get("id"),
        integration_id: row.get("integration_id"),
        condition_kind: row.get("condition_kind"),
        environment: row.get("environment"),
        threshold: row.get("threshold"),
        window_seconds: row.get("window_seconds"),
        quiet_start_minute: row.get("quiet_start_minute"),
        quiet_end_minute: row.get("quiet_end_minute"),
        enabled: row.get("enabled"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn require_enabled(state: &ServerState) -> Result<(), AlertError> {
    if state.alerts().enabled {
        Ok(())
    } else {
        Err(AlertError::NotFound)
    }
}

async fn authorize(
    state: &ServerState,
    headers: &HeaderMap,
    project_id: &str,
    permission: crate::auth::Permission,
) -> Result<crate::auth::ProjectActor, AlertError> {
    crate::auth::authorize_project(state, headers, project_id, permission)
        .await
        .map_err(|error| match error {
            crate::auth::AuthorizationError::Unauthorized => AlertError::Unauthorized,
            crate::auth::AuthorizationError::Forbidden => AlertError::Forbidden,
            crate::auth::AuthorizationError::NotFound => AlertError::NotFound,
            crate::auth::AuthorizationError::Unavailable => AlertError::Unavailable,
        })
}

async fn ensure_member(
    pool: &PgPool,
    organization_id: &str,
    user_id: &str,
) -> Result<(), AlertError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE organization_id = $1::uuid AND user_id = $2::uuid)",
    )
    .bind(organization_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|_| AlertError::Unavailable)?;
    if exists {
        Ok(())
    } else {
        Err(AlertError::NotFound)
    }
}

async fn audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
    user_id: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
) -> Result<(), AlertError> {
    sqlx::query(
        "INSERT INTO audit_log (organization_id, actor_user_id, action, target_type, target_id, result) VALUES ($1::uuid, $2::uuid, $3, $4, $5, 'succeeded')",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AlertError::Unavailable)?;
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn database_write_error(error: sqlx::Error) -> AlertError {
    if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        AlertError::Conflict
    } else if error.as_database_error().is_some() {
        AlertError::InvalidRequest
    } else {
        AlertError::Unavailable
    }
}

fn valid_name(value: &str) -> Result<String, AlertError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_NAME_BYTES || value.chars().any(char::is_control) {
        Err(AlertError::InvalidRequest)
    } else {
        Ok(value.to_owned())
    }
}

fn valid_kind(value: &str) -> Result<&str, AlertError> {
    match value {
        "email" | "discord" | "slack" | "webhook" => Ok(value),
        _ => Err(AlertError::InvalidRequest),
    }
}

fn valid_condition(value: &str) -> Result<&str, AlertError> {
    match value {
        "first_seen" | "regression" | "volume" | "missing_symbols" | "processing_failure"
        | "ingest_silence" | "quota" => Ok(value),
        _ => Err(AlertError::InvalidRequest),
    }
}

fn valid_environment(value: &str) -> Result<&str, AlertError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_ENVIRONMENT_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'_' | b'-'))
        });
    if valid {
        Ok(value)
    } else {
        Err(AlertError::InvalidRequest)
    }
}

fn validate_rule_fields(
    condition: &str,
    threshold: Option<i32>,
    window_seconds: Option<i32>,
    quiet_start: Option<i32>,
    quiet_end: Option<i32>,
) -> Result<(), AlertError> {
    let condition_valid = match condition {
        "volume" => {
            threshold.is_some_and(|value| (1..=1_000_000).contains(&value))
                && window_seconds.is_some_and(|value| (60..=86_400).contains(&value))
        }
        "ingest_silence" => {
            threshold.is_none()
                && window_seconds.is_some_and(|value| (60..=604_800).contains(&value))
        }
        "quota" => matches!(threshold, Some(70 | 90 | 100 | 101)) && window_seconds.is_none(),
        "first_seen" | "regression" | "missing_symbols" | "processing_failure" => {
            threshold.is_none() && window_seconds.is_none()
        }
        _ => false,
    };
    let quiet_valid = match (quiet_start, quiet_end) {
        (None, None) => true,
        (Some(start), Some(end)) => {
            (0..=1439).contains(&start) && (0..=1439).contains(&end) && start != end
        }
        _ => false,
    };
    if condition_valid && quiet_valid {
        Ok(())
    } else {
        Err(AlertError::InvalidRequest)
    }
}

#[derive(Deserialize, Serialize)]
struct SecretConfig {
    url: String,
    signing_secret: Option<String>,
}

fn generate_signing_secret() -> Result<String, AlertError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AlertError::Internal)?;
    Ok(format!("flw_{}", STANDARD.encode(bytes)))
}

fn random_uuid() -> Result<String, getrandom::Error> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)?;
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

fn no_store(status: StatusCode, value: &impl Serialize) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn validate_customer_destination(kind: &str, value: &str) -> Result<Url, AlertError> {
    if value.len() > MAX_ENDPOINT_BYTES {
        return Err(AlertError::InvalidRequest);
    }
    let url = Url::parse(value).map_err(|_| AlertError::InvalidRequest)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
    {
        return Err(AlertError::InvalidRequest);
    }
    let host = url
        .host_str()
        .map(str::to_ascii_lowercase)
        .ok_or(AlertError::InvalidRequest)?;
    let segments = url
        .path_segments()
        .map(Iterator::collect::<Vec<_>>)
        .ok_or(AlertError::InvalidRequest)?;
    let provider_valid = match kind {
        "discord" => {
            matches!(host.as_str(), "discord.com" | "discordapp.com")
                && segments.len() == 4
                && segments[0] == "api"
                && segments[1] == "webhooks"
                && !segments[2].is_empty()
                && !segments[3].is_empty()
        }
        "slack" => {
            host == "hooks.slack.com"
                && segments.len() == 4
                && segments[0] == "services"
                && segments[1..].iter().all(|segment| !segment.is_empty())
        }
        "webhook" => !segments.is_empty(),
        _ => false,
    };
    if provider_valid {
        Ok(url)
    } else {
        Err(AlertError::InvalidRequest)
    }
}

async fn validate_public_resolution(url: &Url) -> Result<Vec<SocketAddr>, AlertError> {
    resolve_public_destination(url)
        .await
        .map_err(|_| AlertError::InvalidRequest)
}

enum ResolutionError {
    Unsafe,
    Unavailable,
}

async fn resolve_public_destination(url: &Url) -> Result<Vec<SocketAddr>, ResolutionError> {
    let host = url.host_str().ok_or(ResolutionError::Unsafe)?;
    if host
        .parse::<IpAddr>()
        .is_ok_and(|address| !public_ip(address))
    {
        return Err(ResolutionError::Unsafe);
    }
    let resolved = tokio::time::timeout(Duration::from_secs(5), lookup_host((host, 443)))
        .await
        .map_err(|_| ResolutionError::Unavailable)?
        .map_err(|_| ResolutionError::Unavailable)?;
    let addresses = resolved
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(ResolutionError::Unavailable);
    }
    if addresses.len() > 16 || addresses.iter().any(|address| !public_ip(address.ip())) {
        return Err(ResolutionError::Unsafe);
    }
    Ok(addresses)
}

fn public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => public_ipv4(address),
        IpAddr::V6(address) => public_ipv6(address),
    }
}

fn public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && matches!(b, 18 | 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return public_ipv4(mapped);
    }
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        && !(segments[0] == 0x2001 && segments[1] == 0x0002)
        && !(segments[0] == 0x0064 && segments[1] == 0xff9b)
        && segments[0] & 0xffc0 != 0xfec0
}

#[derive(Clone)]
struct RuleEvaluation {
    id: String,
    organization_id: String,
    project_id: String,
    project_name: String,
    integration_id: String,
    condition_kind: String,
    environment: String,
    threshold: Option<i32>,
    window_seconds: Option<i32>,
    quiet_start_minute: Option<i32>,
    quiet_end_minute: Option<i32>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

struct Observation {
    scope_key: String,
    payload: Value,
}

struct IssueObservation {
    sort_at: OffsetDateTime,
    issue_id: String,
    observation: Observation,
}

#[derive(Debug)]
pub(crate) enum AlertSchedulerError {
    Configuration,
    Database,
}

impl fmt::Display for AlertSchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "alert scheduler configuration is invalid",
            Self::Database => "alert scheduler database is unavailable",
        })
    }
}

impl std::error::Error for AlertSchedulerError {}

pub(crate) async fn run_scheduler() -> Result<(), AlertSchedulerError> {
    let database_url = env::var("DATABASE_URL").map_err(|_| AlertSchedulerError::Configuration)?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .map_err(|_| AlertSchedulerError::Database)?;
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if evaluate_rules_once(&pool).await.is_err() {
                    warn!("alert rule evaluation failed");
                }
            }
            shutdown = tokio::signal::ctrl_c() => {
                shutdown.map_err(|_| AlertSchedulerError::Configuration)?;
                return Ok(());
            }
        }
    }
}

pub(crate) async fn evaluate_rules_once(pool: &PgPool) -> Result<(), AlertSchedulerError> {
    let started = Instant::now();
    validate_public_base_url(
        &env::var("PUBLIC_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned()),
    )
    .map_err(|_| AlertSchedulerError::Configuration)?;
    let rows = sqlx::query(
        "SELECT r.id::text AS id, r.organization_id::text AS organization_id, r.project_id::text AS project_id, p.name AS project_name, r.integration_id::text AS integration_id, r.condition_kind, r.environment, r.threshold, r.window_seconds, r.quiet_start_minute, r.quiet_end_minute, r.created_at, r.updated_at FROM alert_rules r JOIN alert_integrations i ON i.id = r.integration_id AND i.organization_id = r.organization_id AND i.project_id = r.project_id JOIN projects p ON p.id = r.project_id AND p.organization_id = r.organization_id WHERE r.enabled AND i.enabled ORDER BY r.last_evaluated_at NULLS FIRST, r.id LIMIT $1",
    )
    .bind(ALERT_RULE_PAGE_SIZE)
    .fetch_all(pool)
    .await
    .map_err(|_| AlertSchedulerError::Database)?;
    let selected_rules = rows.len();
    for row in rows {
        let rule = RuleEvaluation {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            project_id: row.get("project_id"),
            project_name: row.get("project_name"),
            integration_id: row.get("integration_id"),
            condition_kind: row.get("condition_kind"),
            environment: row.get("environment"),
            threshold: row.get("threshold"),
            window_seconds: row.get("window_seconds"),
            quiet_start_minute: row.get("quiet_start_minute"),
            quiet_end_minute: row.get("quiet_end_minute"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };
        evaluate_rule(pool, &rule).await?;
        sqlx::query(
            "UPDATE alert_rules r SET last_evaluated_at = now() WHERE r.id = $1::uuid AND r.organization_id = $2::uuid AND r.project_id = $3::uuid AND r.updated_at = $4::timestamptz AND r.enabled AND EXISTS (SELECT 1 FROM alert_integrations i WHERE i.id = r.integration_id AND i.organization_id = r.organization_id AND i.project_id = r.project_id AND i.enabled)",
        )
        .bind(&rule.id)
        .bind(&rule.organization_id)
        .bind(&rule.project_id)
        .bind(rule.updated_at)
        .execute(pool)
        .await
        .map_err(|_| AlertSchedulerError::Database)?;
    }
    info!(
        evaluated_rules = selected_rules,
        duration_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
        "alert rule page evaluated"
    );
    Ok(())
}

async fn evaluate_rule(pool: &PgPool, rule: &RuleEvaluation) -> Result<(), AlertSchedulerError> {
    if rule.condition_kind == "first_seen" {
        evaluate_issue_rule_pages(pool, rule, false).await?;
        return Ok(());
    }
    if rule.condition_kind == "regression" {
        evaluate_issue_rule_pages(pool, rule, true).await?;
        return Ok(());
    }
    let observations = match rule.condition_kind.as_str() {
        "volume" => volume_observation(pool, rule).await?,
        "missing_symbols" => processing_observation(pool, rule, true).await?,
        "processing_failure" => processing_observation(pool, rule, false).await?,
        "ingest_silence" => silence_observation(pool, rule).await?,
        "quota" => quota_observation(pool, rule).await?,
        _ => return Err(AlertSchedulerError::Database),
    };
    let active_scopes = observations
        .iter()
        .map(|observation| observation.scope_key.clone())
        .collect::<BTreeSet<_>>();
    for observation in observations {
        transition_condition(
            pool,
            rule,
            &observation.scope_key,
            true,
            observation.payload,
        )
        .await?;
    }
    recover_absent_conditions(pool, rule, &active_scopes).await
}

async fn recover_absent_conditions(
    pool: &PgPool,
    rule: &RuleEvaluation,
    active_scopes: &BTreeSet<String>,
) -> Result<(), AlertSchedulerError> {
    let rows = sqlx::query(
        "SELECT scope_key, payload FROM alert_condition_states WHERE organization_id = $1::uuid AND project_id = $2::uuid AND rule_id = $3::uuid AND state = 'active'",
    )
    .bind(&rule.organization_id)
    .bind(&rule.project_id)
    .bind(&rule.id)
    .fetch_all(pool)
    .await
    .map_err(|_| AlertSchedulerError::Database)?;
    for row in rows {
        let scope_key = row.get::<String, _>("scope_key");
        if !active_scopes.contains(&scope_key) {
            transition_condition(
                pool,
                rule,
                &scope_key,
                false,
                row.get::<Value, _>("payload"),
            )
            .await?;
        }
    }
    Ok(())
}

async fn evaluate_issue_rule_pages(
    pool: &PgPool,
    rule: &RuleEvaluation,
    regression: bool,
) -> Result<bool, AlertSchedulerError> {
    evaluate_issue_rule_pages_bounded(pool, rule, regression, None).await
}

async fn evaluate_issue_rule_pages_bounded(
    pool: &PgPool,
    rule: &RuleEvaluation,
    regression: bool,
    maximum_pages: Option<usize>,
) -> Result<bool, AlertSchedulerError> {
    let mut cursor: Option<(OffsetDateTime, String)> = None;
    let mut pages = 0_usize;
    loop {
        let observations = issue_observations_page(pool, rule, regression, cursor.as_ref()).await?;
        if observations.is_empty() {
            recover_issue_conditions(pool, rule, regression).await?;
            info!(
                rule_id = rule.id,
                project_id = rule.project_id,
                pages,
                "alert issue rule evaluated"
            );
            return Ok(true);
        }
        let page_length = observations.len();
        let next_cursor = observations
            .last()
            .map(|observation| (observation.sort_at, observation.issue_id.clone()));
        for observation in observations {
            transition_condition(
                pool,
                rule,
                &observation.observation.scope_key,
                true,
                observation.observation.payload,
            )
            .await?;
        }
        pages = pages.saturating_add(1);
        if page_length
            < usize::try_from(ALERT_ISSUE_PAGE_SIZE).map_err(|_| AlertSchedulerError::Database)?
        {
            recover_issue_conditions(pool, rule, regression).await?;
            info!(
                rule_id = rule.id,
                project_id = rule.project_id,
                pages,
                "alert issue rule evaluated"
            );
            return Ok(true);
        }
        if maximum_pages.is_some_and(|maximum| pages >= maximum) {
            return Ok(false);
        }
        cursor = next_cursor;
    }
}

async fn issue_observations_page(
    pool: &PgPool,
    rule: &RuleEvaluation,
    regression: bool,
    cursor: Option<&(OffsetDateTime, String)>,
) -> Result<Vec<IssueObservation>, AlertSchedulerError> {
    let cursor_at = cursor.map(|(sort_at, _)| *sort_at);
    let cursor_id = cursor.map(|(_, issue_id)| issue_id.as_str());
    let rows = if regression {
        sqlx::query(
            "SELECT i.id::text AS issue_id, i.title, i.event_count, i.updated_at AS sort_at FROM issues i WHERE i.organization_id = $1::uuid AND i.project_id = $2::uuid AND i.status = 'open' AND i.regression_state = 'regressed' AND EXISTS (SELECT 1 FROM crash_events e WHERE e.organization_id = i.organization_id AND e.project_id = i.project_id AND e.issue_id = i.id AND e.environment = $3) AND ($4::timestamptz IS NULL OR (i.updated_at, i.id) > ($4::timestamptz, $5::uuid)) ORDER BY i.updated_at, i.id LIMIT $6",
        )
        .bind(&rule.organization_id)
        .bind(&rule.project_id)
        .bind(&rule.environment)
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(ALERT_ISSUE_PAGE_SIZE)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query(
            "SELECT i.id::text AS issue_id, i.title, i.event_count, i.first_seen_at AS sort_at FROM issues i WHERE i.organization_id = $1::uuid AND i.project_id = $2::uuid AND i.status = 'open' AND i.first_seen_at >= $4::timestamptz AND EXISTS (SELECT 1 FROM crash_events e WHERE e.organization_id = i.organization_id AND e.project_id = i.project_id AND e.issue_id = i.id AND e.environment = $3) AND ($5::timestamptz IS NULL OR (i.first_seen_at, i.id) > ($5::timestamptz, $6::uuid)) ORDER BY i.first_seen_at, i.id LIMIT $7",
        )
        .bind(&rule.organization_id)
        .bind(&rule.project_id)
        .bind(&rule.environment)
        .bind(rule.created_at)
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(ALERT_ISSUE_PAGE_SIZE)
        .fetch_all(pool)
        .await
    }
    .map_err(|_| AlertSchedulerError::Database)?;
    Ok(rows
        .iter()
        .map(|row| {
            let issue_id = row.get::<String, _>("issue_id");
            let title = row.get::<String, _>("title");
            IssueObservation {
                sort_at: row.get("sort_at"),
                issue_id: issue_id.clone(),
                observation: Observation {
                    scope_key: format!("issue:{issue_id}"),
                    payload: base_payload(
                        rule,
                        Some(&issue_id),
                        Some(&title),
                        row.get("event_count"),
                    ),
                },
            }
        })
        .collect())
}

async fn recover_issue_conditions(
    pool: &PgPool,
    rule: &RuleEvaluation,
    regression: bool,
) -> Result<(), AlertSchedulerError> {
    loop {
        let rows = if regression {
            sqlx::query(
                "SELECT s.scope_key, s.payload FROM alert_condition_states s WHERE s.organization_id = $1::uuid AND s.project_id = $2::uuid AND s.rule_id = $3::uuid AND s.state = 'active' AND NOT EXISTS (SELECT 1 FROM issues i WHERE i.id = (s.payload ->> 'issue_id')::uuid AND i.organization_id = s.organization_id AND i.project_id = s.project_id AND i.status = 'open' AND i.regression_state = 'regressed' AND EXISTS (SELECT 1 FROM crash_events e WHERE e.organization_id = i.organization_id AND e.project_id = i.project_id AND e.issue_id = i.id AND e.environment = $4)) ORDER BY s.scope_key LIMIT $5",
            )
            .bind(&rule.organization_id)
            .bind(&rule.project_id)
            .bind(&rule.id)
            .bind(&rule.environment)
            .bind(ALERT_RECOVERY_PAGE_SIZE)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query(
                "SELECT s.scope_key, s.payload FROM alert_condition_states s WHERE s.organization_id = $1::uuid AND s.project_id = $2::uuid AND s.rule_id = $3::uuid AND s.state = 'active' AND NOT EXISTS (SELECT 1 FROM issues i WHERE i.id = (s.payload ->> 'issue_id')::uuid AND i.organization_id = s.organization_id AND i.project_id = s.project_id AND i.status = 'open' AND i.first_seen_at >= $5::timestamptz AND EXISTS (SELECT 1 FROM crash_events e WHERE e.organization_id = i.organization_id AND e.project_id = i.project_id AND e.issue_id = i.id AND e.environment = $4)) ORDER BY s.scope_key LIMIT $6",
            )
            .bind(&rule.organization_id)
            .bind(&rule.project_id)
            .bind(&rule.id)
            .bind(&rule.environment)
            .bind(rule.created_at)
            .bind(ALERT_RECOVERY_PAGE_SIZE)
            .fetch_all(pool)
            .await
        }
        .map_err(|_| AlertSchedulerError::Database)?;
        if rows.is_empty() {
            return Ok(());
        }
        for row in rows {
            let scope_key = row.get::<String, _>("scope_key");
            transition_condition(
                pool,
                rule,
                &scope_key,
                false,
                row.get::<Value, _>("payload"),
            )
            .await?;
        }
    }
}

async fn volume_observation(
    pool: &PgPool,
    rule: &RuleEvaluation,
) -> Result<Vec<Observation>, AlertSchedulerError> {
    let window = rule.window_seconds.ok_or(AlertSchedulerError::Database)?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM crash_events WHERE organization_id = $1::uuid AND project_id = $2::uuid AND environment = $3 AND received_at >= now() - ($4 * interval '1 second')",
    )
    .bind(&rule.organization_id)
    .bind(&rule.project_id)
    .bind(&rule.environment)
    .bind(window)
    .fetch_one(pool)
    .await
    .map_err(|_| AlertSchedulerError::Database)?;
    let active = count >= i64::from(rule.threshold.ok_or(AlertSchedulerError::Database)?);
    Ok(active
        .then(|| Observation {
            scope_key: format!("project:{}", rule.environment),
            payload: base_payload(rule, None, None, count),
        })
        .into_iter()
        .collect())
}

async fn processing_observation(
    pool: &PgPool,
    rule: &RuleEvaluation,
    missing_symbols: bool,
) -> Result<Vec<Observation>, AlertSchedulerError> {
    let count: i64 = if missing_symbols {
        sqlx::query_scalar(
            "SELECT count(*) FROM crash_events WHERE organization_id = $1::uuid AND project_id = $2::uuid AND environment = $3 AND processing_state = 'awaiting_symbols'",
        )
        .bind(&rule.organization_id)
        .bind(&rule.project_id)
        .bind(&rule.environment)
        .fetch_one(pool)
        .await
    } else {
        sqlx::query_scalar(
            "SELECT count(*) FROM crash_events WHERE organization_id = $1::uuid AND project_id = $2::uuid AND environment = $3 AND processing_state IN ('failed', 'quarantined')",
        )
        .bind(&rule.organization_id)
        .bind(&rule.project_id)
        .bind(&rule.environment)
        .fetch_one(pool)
        .await
    }
    .map_err(|_| AlertSchedulerError::Database)?;
    Ok((count > 0)
        .then(|| Observation {
            scope_key: format!("project:{}", rule.environment),
            payload: base_payload(rule, None, None, count),
        })
        .into_iter()
        .collect())
}

async fn silence_observation(
    pool: &PgPool,
    rule: &RuleEvaluation,
) -> Result<Vec<Observation>, AlertSchedulerError> {
    let window = rule.window_seconds.ok_or(AlertSchedulerError::Database)?;
    let silent: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT max(e.received_at) FROM crash_events e WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.environment = $3), r.created_at) < now() - ($4 * interval '1 second') FROM alert_rules r WHERE r.id = $5::uuid AND r.organization_id = $1::uuid AND r.project_id = $2::uuid",
    )
    .bind(&rule.organization_id)
    .bind(&rule.project_id)
    .bind(&rule.environment)
    .bind(window)
    .bind(&rule.id)
    .fetch_one(pool)
    .await
    .map_err(|_| AlertSchedulerError::Database)?;
    Ok(silent
        .then(|| Observation {
            scope_key: format!("project:{}", rule.environment),
            payload: base_payload(rule, None, None, i64::from(window)),
        })
        .into_iter()
        .collect())
}

async fn quota_observation(
    pool: &PgPool,
    rule: &RuleEvaluation,
) -> Result<Vec<Observation>, AlertSchedulerError> {
    let row = sqlx::query(
        "SELECT COALESCE(c.accepted_events, 0) AS accepted_events, p.event_limit, p.courtesy_percent FROM project_usage_policies p LEFT JOIN usage_cycle_counters c ON c.organization_id = p.organization_id AND c.project_id = p.project_id AND c.cycle_start = date_trunc('month', now() AT TIME ZONE 'UTC')::date WHERE p.organization_id = $1::uuid AND p.project_id = $2::uuid",
    )
    .bind(&rule.organization_id)
    .bind(&rule.project_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| AlertSchedulerError::Database)?
    .ok_or(AlertSchedulerError::Database)?;
    let accepted = row.get::<i64, _>("accepted_events");
    let limit = row.get::<i64, _>("event_limit");
    let threshold = rule.threshold.ok_or(AlertSchedulerError::Database)?;
    let active = if threshold == 101 {
        let courtesy = row.get::<i32, _>("courtesy_percent");
        accepted > limit.saturating_add(limit.saturating_mul(i64::from(courtesy)) / 100)
    } else {
        i128::from(accepted).saturating_mul(100)
            >= i128::from(limit).saturating_mul(i128::from(threshold))
    };
    Ok(active
        .then(|| Observation {
            scope_key: format!("quota:{}", rule.environment),
            payload: base_payload(rule, None, None, accepted),
        })
        .into_iter()
        .collect())
}

fn base_payload(
    rule: &RuleEvaluation,
    issue_id: Option<&str>,
    issue_title: Option<&str>,
    count: i64,
) -> Value {
    let base = env::var("PUBLIC_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned())
        .trim_end_matches('/')
        .to_owned();
    let url = issue_id.map_or_else(
        || format!("{base}/projects/{}", rule.project_id),
        |issue_id| format!("{base}/projects/{}/issues/{issue_id}", rule.project_id),
    );
    json!({
        "condition": rule.condition_kind,
        "project_id": rule.project_id,
        "project_name": rule.project_name,
        "environment": rule.environment,
        "issue_id": issue_id,
        "issue_title": issue_title,
        "count": count,
        "url": url
    })
}

#[allow(clippy::too_many_lines)]
async fn transition_condition(
    pool: &PgPool,
    rule: &RuleEvaluation,
    scope_key: &str,
    active: bool,
    mut payload: Value,
) -> Result<(), AlertSchedulerError> {
    if scope_key.is_empty() || scope_key.len() > 200 {
        return Err(AlertSchedulerError::Database);
    }
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| AlertSchedulerError::Database)?;
    let previous = sqlx::query(
        "SELECT state, generation FROM alert_condition_states WHERE organization_id = $1::uuid AND project_id = $2::uuid AND rule_id = $3::uuid AND scope_key = $4 FOR UPDATE",
    )
    .bind(&rule.organization_id)
    .bind(&rule.project_id)
    .bind(&rule.id)
    .bind(scope_key)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| AlertSchedulerError::Database)?;
    let next_state = if active { "active" } else { "inactive" };
    if previous
        .as_ref()
        .is_some_and(|row| row.get::<String, _>("state") == next_state)
    {
        sqlx::query(
            "UPDATE alert_condition_states SET payload = $5, evaluated_at = now() WHERE organization_id = $1::uuid AND project_id = $2::uuid AND rule_id = $3::uuid AND scope_key = $4",
        )
        .bind(&rule.organization_id)
        .bind(&rule.project_id)
        .bind(&rule.id)
        .bind(scope_key)
        .bind(payload)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AlertSchedulerError::Database)?;
        return transaction
            .commit()
            .await
            .map_err(|_| AlertSchedulerError::Database);
    }
    if previous.is_none() && !active {
        return transaction
            .commit()
            .await
            .map_err(|_| AlertSchedulerError::Database);
    }
    let generation = previous.as_ref().map_or(1_i64, |row| {
        row.get::<i64, _>("generation").saturating_add(1)
    });
    let transition = if active { "triggered" } else { "recovered" };
    payload["transition"] = json!(transition);
    payload["occurred_at"] = json!(
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| AlertSchedulerError::Database)?
    );
    if serde_json::to_vec(&payload)
        .map_err(|_| AlertSchedulerError::Database)?
        .len()
        > MAX_PAYLOAD_BYTES
    {
        return Err(AlertSchedulerError::Database);
    }
    sqlx::query(
        "INSERT INTO alert_condition_states (organization_id, project_id, rule_id, scope_key, state, generation, payload) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7) ON CONFLICT (organization_id, project_id, rule_id, scope_key) DO UPDATE SET state = EXCLUDED.state, generation = EXCLUDED.generation, payload = EXCLUDED.payload, transitioned_at = now(), evaluated_at = now()",
    )
    .bind(&rule.organization_id)
    .bind(&rule.project_id)
    .bind(&rule.id)
    .bind(scope_key)
    .bind(next_state)
    .bind(generation)
    .bind(&payload)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AlertSchedulerError::Database)?;
    let suppressed_pair = if active {
        false
    } else {
        sqlx::query(
            "UPDATE alert_deliveries SET state = 'suppressed', failure_code = 'quiet_recovered', updated_at = now() WHERE organization_id = $1::uuid AND project_id = $2::uuid AND rule_id = $3::uuid AND scope_key = $4 AND generation = $5 AND transition = 'triggered' AND state = 'pending' AND available_at > now()",
        )
        .bind(&rule.organization_id)
        .bind(&rule.project_id)
        .bind(&rule.id)
        .bind(scope_key)
        .bind(generation.saturating_sub(1))
        .execute(&mut *transaction)
        .await
        .map_err(|_| AlertSchedulerError::Database)?
        .rows_affected()
            > 0
    };
    let delay = quiet_delay_seconds(
        OffsetDateTime::now_utc(),
        rule.quiet_start_minute,
        rule.quiet_end_minute,
    );
    let delivery_state = if suppressed_pair {
        "suppressed"
    } else {
        "pending"
    };
    let failure_code = suppressed_pair.then_some("quiet_recovered");
    sqlx::query(
        "INSERT INTO alert_deliveries (organization_id, project_id, integration_id, rule_id, scope_key, generation, transition, payload, state, available_at, failure_code) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, now() + ($10 * interval '1 second'), $11) ON CONFLICT DO NOTHING",
    )
    .bind(&rule.organization_id)
    .bind(&rule.project_id)
    .bind(&rule.integration_id)
    .bind(&rule.id)
    .bind(scope_key)
    .bind(generation)
    .bind(transition)
    .bind(payload)
    .bind(delivery_state)
    .bind(delay)
    .bind(failure_code)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AlertSchedulerError::Database)?;
    transaction
        .commit()
        .await
        .map_err(|_| AlertSchedulerError::Database)
}

fn quiet_delay_seconds(now: OffsetDateTime, start: Option<i32>, end: Option<i32>) -> i64 {
    let (Some(start), Some(end)) = (start, end) else {
        return 0;
    };
    let minute = i32::from(now.hour()) * 60 + i32::from(now.minute());
    let quiet = if start < end {
        minute >= start && minute < end
    } else {
        minute >= start || minute < end
    };
    if !quiet {
        return 0;
    }
    let minutes = if minute < end {
        end - minute
    } else {
        1440 - minute + end
    };
    i64::from(minutes) * 60 - i64::from(now.second())
}

#[derive(Debug)]
pub(crate) enum AlertWorkerError {
    Configuration,
    Database,
}

impl fmt::Display for AlertWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "alert worker configuration is invalid",
            Self::Database => "alert worker database is unavailable",
        })
    }
}

impl std::error::Error for AlertWorkerError {}

#[derive(Debug)]
enum DeliveryError {
    Retryable(&'static str),
    Permanent(&'static str),
    Unknown(&'static str),
}

struct ClaimedDelivery {
    id: String,
    organization_id: String,
    project_id: String,
    integration_id: String,
    attempt: i32,
    max_attempt: i32,
    lease_token: String,
    payload: Value,
}

struct DeliveryIntegration {
    kind: String,
    recipient_email: Option<String>,
    encrypted_config: Option<Vec<u8>>,
    config_nonce: Option<Vec<u8>>,
}

struct EmailDelivery {
    url: Url,
    token: String,
}

pub(crate) async fn run_worker() -> Result<(), AlertWorkerError> {
    let database_url = env::var("DATABASE_URL").map_err(|_| AlertWorkerError::Configuration)?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .map_err(|_| AlertWorkerError::Database)?;
    let cipher = SecretCipher::from_environment().map_err(|_| AlertWorkerError::Configuration)?;
    let email = email_delivery_from_environment()?;
    let worker_id = random_uuid().map_err(|_| AlertWorkerError::Configuration)?;
    info!(worker_id, "alert worker started");
    loop {
        tokio::select! {
            result = deliver_next(&pool, &cipher, email.as_ref(), &worker_id) => {
                match result {
                    Ok(true) => {}
                    Ok(false) => tokio::time::sleep(Duration::from_millis(DELIVERY_POLL_MILLISECONDS)).await,
                    Err(AlertWorkerError::Database) => {
                        warn!(worker_id, "alert delivery claim failed");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
            shutdown = tokio::signal::ctrl_c() => {
                shutdown.map_err(|_| AlertWorkerError::Configuration)?;
                return Ok(());
            }
        }
    }
}

fn email_delivery_from_environment() -> Result<Option<EmailDelivery>, AlertWorkerError> {
    match (
        nonempty_environment("FAULTLANE_EMAIL_DELIVERY_URL"),
        nonempty_environment("FAULTLANE_EMAIL_DELIVERY_TOKEN"),
    ) {
        (None, None) => Ok(None),
        (Some(url), Some(token)) => {
            let url = Url::parse(&url).map_err(|_| AlertWorkerError::Configuration)?;
            let local_http = url.scheme() == "http"
                && url
                    .host_str()
                    .and_then(|host| host.parse::<IpAddr>().ok())
                    .is_some_and(|address| address.is_loopback());
            if (url.scheme() != "https" && !local_http)
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(AlertWorkerError::Configuration);
            }
            Ok(Some(EmailDelivery { url, token }))
        }
        _ => Err(AlertWorkerError::Configuration),
    }
}

async fn deliver_next(
    pool: &PgPool,
    cipher: &SecretCipher,
    email: Option<&EmailDelivery>,
    worker_id: &str,
) -> Result<bool, AlertWorkerError> {
    let Some(delivery) = claim_delivery(pool, worker_id).await? else {
        return Ok(false);
    };
    let result = deliver_claim(pool, cipher, email, &delivery).await;
    finish_delivery(pool, &delivery, result).await?;
    Ok(true)
}

async fn claim_delivery(
    pool: &PgPool,
    worker_id: &str,
) -> Result<Option<ClaimedDelivery>, AlertWorkerError> {
    loop {
        let mut transaction = pool.begin().await.map_err(|_| AlertWorkerError::Database)?;
        let candidate = sqlx::query(
            "SELECT id::text AS id, organization_id::text AS organization_id, project_id::text AS project_id, state, attempt, max_attempt FROM alert_deliveries WHERE ((state IN ('pending', 'failed') AND available_at <= now() AND attempt < max_attempt) OR (state = 'leased' AND lease_expires_at <= now())) ORDER BY available_at, created_at, id FOR UPDATE SKIP LOCKED LIMIT 1",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AlertWorkerError::Database)?;
        let Some(candidate) = candidate else {
            transaction
                .commit()
                .await
                .map_err(|_| AlertWorkerError::Database)?;
            return Ok(None);
        };
        let id = candidate.get::<String, _>("id");
        let organization_id = candidate.get::<String, _>("organization_id");
        let project_id = candidate.get::<String, _>("project_id");
        let attempt = candidate.get::<i32, _>("attempt");
        let max_attempt = candidate.get::<i32, _>("max_attempt");
        if candidate.get::<String, _>("state") == "leased" && attempt >= max_attempt {
            let changed = sqlx::query(
                "UPDATE alert_deliveries SET state = 'dead', lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, failure_code = 'lease_expired_final', updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'leased' AND lease_expires_at <= now() AND attempt >= max_attempt",
            )
            .bind(&id)
            .bind(&organization_id)
            .bind(&project_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AlertWorkerError::Database)?
            .rows_affected();
            if changed != 1 {
                return Err(AlertWorkerError::Database);
            }
            transaction
                .commit()
                .await
                .map_err(|_| AlertWorkerError::Database)?;
            info!(
                delivery_id = id,
                project_id,
                attempt,
                failure_code = "lease_expired_final",
                "expired final alert delivery reconciled"
            );
            continue;
        }
        let lease_token = random_uuid().map_err(|_| AlertWorkerError::Configuration)?;
        let row = sqlx::query(
            "UPDATE alert_deliveries SET state = 'leased', attempt = attempt + 1, lease_owner = $4, lease_token = $5::uuid, lease_expires_at = now() + ($6 * interval '1 second'), failure_code = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND attempt < max_attempt AND ((state IN ('pending', 'failed') AND available_at <= now()) OR (state = 'leased' AND lease_expires_at <= now())) RETURNING id::text AS id, organization_id::text AS organization_id, project_id::text AS project_id, integration_id::text AS integration_id, attempt, max_attempt, lease_token::text AS lease_token, payload",
        )
        .bind(&id)
        .bind(&organization_id)
        .bind(&project_id)
        .bind(worker_id)
        .bind(lease_token)
        .bind(DELIVERY_LEASE_SECONDS)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AlertWorkerError::Database)?
        .ok_or(AlertWorkerError::Database)?;
        let delivery = ClaimedDelivery {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            project_id: row.get("project_id"),
            integration_id: row.get("integration_id"),
            attempt: row.get("attempt"),
            max_attempt: row.get("max_attempt"),
            lease_token: row.get("lease_token"),
            payload: row.get("payload"),
        };
        transaction
            .commit()
            .await
            .map_err(|_| AlertWorkerError::Database)?;
        return Ok(Some(delivery));
    }
}

async fn deliver_claim(
    pool: &PgPool,
    cipher: &SecretCipher,
    email: Option<&EmailDelivery>,
    delivery: &ClaimedDelivery,
) -> Result<(), DeliveryError> {
    let row = sqlx::query(
        "SELECT i.kind, i.enabled, i.encrypted_config, i.config_nonce, CASE WHEN m.user_id IS NOT NULL THEN u.email END AS recipient_email FROM alert_integrations i LEFT JOIN users u ON u.id = i.recipient_user_id LEFT JOIN organization_memberships m ON m.organization_id = i.organization_id AND m.user_id = u.id WHERE i.id = $1::uuid AND i.organization_id = $2::uuid AND i.project_id = $3::uuid",
    )
    .bind(&delivery.integration_id)
    .bind(&delivery.organization_id)
    .bind(&delivery.project_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| DeliveryError::Retryable("integration_lookup_failed"))?
    .ok_or(DeliveryError::Permanent("integration_not_found"))?;
    if !row.get::<bool, _>("enabled") {
        return Err(DeliveryError::Permanent("integration_disabled"));
    }
    let integration = DeliveryIntegration {
        kind: row.get("kind"),
        recipient_email: row.get("recipient_email"),
        encrypted_config: row.get("encrypted_config"),
        config_nonce: row.get("config_nonce"),
    };
    if integration.kind == "email" {
        deliver_email(email, &integration, &delivery.payload).await
    } else {
        deliver_webhook(cipher, delivery, &integration).await
    }
}

async fn deliver_email(
    email: Option<&EmailDelivery>,
    integration: &DeliveryIntegration,
    payload: &Value,
) -> Result<(), DeliveryError> {
    let email = email.ok_or(DeliveryError::Permanent("email_not_configured"))?;
    let recipient = integration
        .recipient_email
        .as_deref()
        .ok_or(DeliveryError::Permanent("recipient_not_found"))?;
    let body = json!({
        "to": recipient,
        "subject": alert_subject(payload),
        "text": alert_text(payload),
    });
    send_request(
        Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| DeliveryError::Permanent("delivery_client_invalid"))?,
        email.url.clone(),
        body,
        Some(("authorization", format!("Bearer {}", email.token))),
    )
    .await
}

async fn deliver_webhook(
    cipher: &SecretCipher,
    delivery: &ClaimedDelivery,
    integration: &DeliveryIntegration,
) -> Result<(), DeliveryError> {
    let scope = SecretScope {
        organization_id: &delivery.organization_id,
        project_id: &delivery.project_id,
        integration_id: &delivery.integration_id,
        kind: &integration.kind,
    };
    let plaintext = cipher.decrypt(
        &scope,
        integration
            .encrypted_config
            .as_deref()
            .ok_or(DeliveryError::Permanent("integration_config_invalid"))?,
        integration
            .config_nonce
            .as_deref()
            .ok_or(DeliveryError::Permanent("integration_config_invalid"))?,
    )?;
    let config: SecretConfig = serde_json::from_slice(&plaintext)
        .map_err(|_| DeliveryError::Permanent("integration_config_invalid"))?;
    let url = validate_customer_destination(&integration.kind, &config.url)
        .map_err(|_| DeliveryError::Permanent("destination_invalid"))?;
    let addresses = resolve_public_destination(&url)
        .await
        .map_err(|error| match error {
            ResolutionError::Unsafe => DeliveryError::Permanent("destination_invalid"),
            ResolutionError::Unavailable => {
                DeliveryError::Retryable("destination_resolution_failed")
            }
        })?;
    let host = url
        .host_str()
        .ok_or(DeliveryError::Permanent("destination_invalid"))?;
    let client = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(|_| DeliveryError::Permanent("delivery_client_invalid"))?;
    let (body, authentication) = destination_payload(
        &integration.kind,
        &delivery.id,
        &delivery.payload,
        config.signing_secret.as_deref(),
    )?;
    send_request(client, url, body, authentication).await
}

type DeliveryHeader = Option<(&'static str, String)>;

fn destination_payload(
    kind: &str,
    delivery_id: &str,
    payload: &Value,
    signing_secret: Option<&str>,
) -> Result<(Value, DeliveryHeader), DeliveryError> {
    match kind {
        "discord" => Ok((json!({"content": alert_text(payload)}), None)),
        "slack" => Ok((json!({"text": alert_text(payload)}), None)),
        "webhook" => {
            let body = json!({"version": 1, "delivery_id": delivery_id, "event": payload});
            let encoded = serde_json::to_vec(&body)
                .map_err(|_| DeliveryError::Permanent("payload_invalid"))?;
            let secret =
                signing_secret.ok_or(DeliveryError::Permanent("signing_secret_missing"))?;
            Ok((
                body,
                Some((
                    "x-faultlane-signature",
                    webhook_signature(secret, &encoded)?,
                )),
            ))
        }
        _ => Err(DeliveryError::Permanent("integration_kind_invalid")),
    }
}

fn webhook_signature(secret: &str, body: &[u8]) -> Result<String, DeliveryError> {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(secret.as_bytes())
        .map_err(|_| DeliveryError::Permanent("signing_secret_invalid"))?;
    mac.update(body);
    Ok(format!("v1={}", hex_bytes(&mac.finalize().into_bytes())))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

async fn send_request(
    client: Client,
    url: Url,
    body: Value,
    header: Option<(&'static str, String)>,
) -> Result<(), DeliveryError> {
    let mut request = client.post(url).json(&body);
    if let Some((name, value)) = header {
        request = request.header(name, value);
    }
    let response = request.send().await.map_err(|error| {
        if error.is_connect() {
            DeliveryError::Retryable("destination_connect_failed")
        } else {
            DeliveryError::Unknown("delivery_outcome_unknown")
        }
    })?;
    match response.status().as_u16() {
        200..=299 => Ok(()),
        408 | 425 | 429 | 500..=599 => Err(DeliveryError::Retryable("destination_retryable")),
        _ => Err(DeliveryError::Permanent("destination_rejected")),
    }
}

fn alert_subject(payload: &Value) -> String {
    format!(
        "FaultLane {} alert for {}",
        payload
            .get("condition")
            .and_then(Value::as_str)
            .unwrap_or("project"),
        payload
            .get("project_name")
            .and_then(Value::as_str)
            .unwrap_or("project")
    )
}

fn alert_text(payload: &Value) -> String {
    let transition = payload
        .get("transition")
        .and_then(Value::as_str)
        .unwrap_or("triggered");
    let condition = payload
        .get("condition")
        .and_then(Value::as_str)
        .unwrap_or("project");
    let project = payload
        .get("project_name")
        .and_then(Value::as_str)
        .unwrap_or("project");
    let environment = payload
        .get("environment")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let url = payload.get("url").and_then(Value::as_str).unwrap_or("");
    format!("{condition} {transition} for {project} in {environment}. {url}")
}

async fn finish_delivery(
    pool: &PgPool,
    delivery: &ClaimedDelivery,
    result: Result<(), DeliveryError>,
) -> Result<(), AlertWorkerError> {
    let (state, failure_code, retry_seconds, delivered) = match result {
        Ok(()) => ("delivered", None, 0_i64, true),
        Err(DeliveryError::Retryable(code)) if delivery.attempt < delivery.max_attempt => (
            "failed",
            Some(code),
            i64::from(delivery.attempt) * 15,
            false,
        ),
        Err(DeliveryError::Retryable(code) | DeliveryError::Permanent(code)) => {
            ("dead", Some(code), 0, false)
        }
        Err(DeliveryError::Unknown(code)) => ("unknown", Some(code), 0, false),
    };
    let changed = sqlx::query(
        "UPDATE alert_deliveries SET state = $4, available_at = now() + ($5 * interval '1 second'), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, failure_code = $6, delivered_at = CASE WHEN $7 THEN now() ELSE delivered_at END, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND lease_token = $8::uuid AND state = 'leased'",
    )
    .bind(&delivery.id)
    .bind(&delivery.organization_id)
    .bind(&delivery.project_id)
    .bind(state)
    .bind(retry_seconds)
    .bind(failure_code)
    .bind(delivered)
    .bind(&delivery.lease_token)
    .execute(pool)
    .await
    .map_err(|_| AlertWorkerError::Database)?
    .rows_affected();
    if changed != 1 {
        return Err(AlertWorkerError::Database);
    }
    info!(
        delivery_id = delivery.id,
        project_id = delivery.project_id,
        state,
        attempt = delivery.attempt,
        "alert delivery finished"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ClaimedDelivery, DeliveryError, EmailDelivery, RuleEvaluation, SecretCipher, SecretScope,
        alert_subject, alert_text, claim_delivery, deliver_claim, destination_payload,
        evaluate_issue_rule_pages_bounded, evaluate_rules_once, finish_delivery, public_ip,
        quiet_delay_seconds, random_uuid, send_request, validate_customer_destination,
        validate_rule_fields, webhook_signature,
    };
    use crate::project_setup::{DATABASE_TEST_LOCK, ServerState, migrate, router};
    use axum::{
        Json, Router,
        body::Body,
        extract::State,
        http::{HeaderMap, Request, StatusCode},
        routing::post,
    };
    use reqwest::{Client, Url, redirect::Policy};
    use serde_json::json;
    use sqlx::{PgPool, Row, postgres::PgPoolOptions};
    use std::{
        error::Error,
        net::IpAddr,
        sync::Arc,
        time::{Duration, Instant},
    };
    use time::OffsetDateTime;
    use tokio::sync::Mutex;
    use tower::ServiceExt as _;

    type ReceivedDeliveries = Arc<Mutex<Vec<(HeaderMap, serde_json::Value)>>>;

    #[test]
    fn integration_secrets_are_scoped_and_authenticated() {
        let cipher = SecretCipher::new([7_u8; 32]);
        let scope = SecretScope {
            organization_id: "11111111-1111-4111-8111-111111111111",
            project_id: "22222222-2222-4222-8222-222222222222",
            integration_id: "33333333-3333-4333-8333-333333333333",
            kind: "webhook",
        };
        let (encrypted, nonce) = cipher
            .encrypt(&scope, br#"{"url":"https://example.com/hook"}"#)
            .unwrap_or_else(|error| panic!("test encryption failed: {error:?}"));
        let decrypted = cipher
            .decrypt(&scope, &encrypted, &nonce)
            .unwrap_or_else(|error| panic!("test decryption failed: {error:?}"));
        assert_eq!(decrypted, br#"{"url":"https://example.com/hook"}"#);
        let (second_encrypted, second_nonce) = cipher
            .encrypt(&scope, br#"{"url":"https://example.com/hook"}"#)
            .unwrap_or_else(|error| panic!("second encryption failed: {error:?}"));
        assert_ne!(nonce, second_nonce);
        assert_ne!(encrypted, second_encrypted);
        assert!(
            SecretCipher::new([8_u8; 32])
                .decrypt(&scope, &encrypted, &nonce)
                .is_err()
        );

        let other_scope = SecretScope {
            project_id: "44444444-4444-4444-8444-444444444444",
            ..scope
        };
        assert!(matches!(
            cipher.decrypt(&other_scope, &encrypted, &nonce),
            Err(DeliveryError::Permanent("integration_decrypt_failed"))
        ));
        let mut tampered = encrypted;
        tampered[0] ^= 1;
        assert!(cipher.decrypt(&scope, &tampered, &nonce).is_err());
    }

    #[test]
    fn destinations_are_strict_and_private_networks_are_blocked() {
        assert!(
            validate_customer_destination("discord", "https://discord.com/api/webhooks/123/token")
                .is_ok()
        );
        assert!(
            validate_customer_destination("slack", "https://hooks.slack.com/services/T/B/token")
                .is_ok()
        );
        assert!(
            validate_customer_destination("webhook", "https://example.com/hooks/faultlane").is_ok()
        );
        assert!(validate_customer_destination("webhook", "http://example.com/hook").is_err());
        assert!(
            validate_customer_destination("discord", "https://example.com/api/webhooks/1/2")
                .is_err()
        );
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "fec0::1",
            "64:ff9b::a00:1",
        ] {
            let parsed: IpAddr = address
                .parse()
                .unwrap_or_else(|error| panic!("test address must parse: {error}"));
            assert!(!public_ip(parsed));
        }
        let public: IpAddr = "8.8.8.8"
            .parse()
            .unwrap_or_else(|error| panic!("test address must parse: {error}"));
        assert!(public_ip(public));
    }

    #[test]
    fn every_destination_has_a_bounded_payload() {
        let payload = json!({
            "condition": "first_seen",
            "transition": "triggered",
            "project_name": "Game",
            "environment": "production",
            "url": "https://faultlane.example/projects/1/issues/2"
        });
        assert!(alert_subject(&payload).contains("first_seen"));
        assert!(alert_text(&payload).contains("production"));

        let (discord, discord_header) = destination_payload("discord", "delivery", &payload, None)
            .unwrap_or_else(|error| panic!("discord payload failed: {error:?}"));
        assert!(discord["content"].as_str().is_some());
        assert!(discord_header.is_none());
        let (slack, slack_header) = destination_payload("slack", "delivery", &payload, None)
            .unwrap_or_else(|error| panic!("slack payload failed: {error:?}"));
        assert!(slack["text"].as_str().is_some());
        assert!(slack_header.is_none());
        let (webhook, webhook_header) =
            destination_payload("webhook", "delivery", &payload, Some("secret"))
                .unwrap_or_else(|error| panic!("webhook payload failed: {error:?}"));
        assert_eq!(webhook["version"], 1);
        assert!(webhook_header.is_some_and(|header| header.1.starts_with("v1=")));
        assert_eq!(
            webhook_signature("secret", b"body")
                .unwrap_or_else(|error| panic!("signature failed: {error:?}")),
            webhook_signature("secret", b"body")
                .unwrap_or_else(|error| panic!("signature failed: {error:?}"))
        );
    }

    #[test]
    fn all_conditions_and_quiet_hours_enforce_bounds() {
        for condition in [
            "first_seen",
            "regression",
            "missing_symbols",
            "processing_failure",
        ] {
            assert!(validate_rule_fields(condition, None, None, None, None).is_ok());
        }
        assert!(validate_rule_fields("volume", Some(10), Some(300), None, None).is_ok());
        assert!(validate_rule_fields("ingest_silence", None, Some(300), None, None).is_ok());
        for threshold in [70, 90, 100, 101] {
            assert!(validate_rule_fields("quota", Some(threshold), None, None, None).is_ok());
        }
        assert!(validate_rule_fields("quota", Some(80), None, None, None).is_err());
        assert!(validate_rule_fields("volume", Some(1), Some(59), None, None).is_err());

        let noon = OffsetDateTime::from_unix_timestamp(12 * 60 * 60)
            .unwrap_or_else(|error| panic!("test time failed: {error}"));
        assert_eq!(
            quiet_delay_seconds(noon, Some(11 * 60), Some(13 * 60)),
            3600
        );
        assert_eq!(quiet_delay_seconds(noon, Some(13 * 60), Some(11 * 60)), 0);
    }

    #[tokio::test]
    async fn adapters_send_to_mock_receivers_and_classify_outcomes() {
        let received = Arc::new(Mutex::new(Vec::<(HeaderMap, serde_json::Value)>::new()));
        let app = Router::new()
            .route("/ok", post(collect_delivery))
            .route(
                "/retry",
                post(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route("/reject", post(|| async { StatusCode::BAD_REQUEST }))
            .route(
                "/slow",
                post(|| async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    StatusCode::NO_CONTENT
                }),
            )
            .with_state(received.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("mock listener failed: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("mock address failed: {error}"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = || {
            Client::builder()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap_or_else(|error| panic!("mock client failed: {error}"))
        };
        let payload = json!({
            "condition": "first_seen",
            "transition": "triggered",
            "project_name": "Game",
            "environment": "production"
        });
        let email = json!({
            "to": "member@example.com",
            "subject": alert_subject(&payload),
            "text": alert_text(&payload)
        });
        send_request(client(), mock_url(address, "/ok"), email, None)
            .await
            .unwrap_or_else(|error| panic!("email mock failed: {error:?}"));
        for kind in ["discord", "slack", "webhook"] {
            let (body, header) = destination_payload(
                kind,
                "11111111-1111-4111-8111-111111111111",
                &payload,
                (kind == "webhook").then_some("secret"),
            )
            .unwrap_or_else(|error| panic!("{kind} payload failed: {error:?}"));
            send_request(client(), mock_url(address, "/ok"), body, header)
                .await
                .unwrap_or_else(|error| panic!("{kind} mock failed: {error:?}"));
        }
        let requests = received.lock().await;
        assert_eq!(requests.len(), 4);
        assert!(requests[0].1.get("to").is_some());
        assert!(requests[1].1.get("content").is_some());
        assert!(requests[2].1.get("text").is_some());
        assert!(requests[3].1.get("delivery_id").is_some());
        assert!(requests[3].0.get("x-faultlane-signature").is_some());
        drop(requests);

        assert!(matches!(
            send_request(client(), mock_url(address, "/retry"), json!({}), None).await,
            Err(DeliveryError::Retryable("destination_retryable"))
        ));
        assert!(matches!(
            send_request(client(), mock_url(address, "/reject"), json!({}), None).await,
            Err(DeliveryError::Permanent("destination_rejected"))
        ));
        let timeout_client = Client::builder()
            .timeout(Duration::from_millis(5))
            .build()
            .unwrap_or_else(|error| panic!("timeout client failed: {error}"));
        assert!(matches!(
            send_request(timeout_client, mock_url(address, "/slow"), json!({}), None).await,
            Err(DeliveryError::Unknown("delivery_outcome_unknown"))
        ));
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used, clippy::too_many_lines)]
    async fn alert_conditions_dedupe_recover_retry_and_stay_scoped() -> Result<(), Box<dyn Error>> {
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

        let (user_id, organization_id, project_id, key_id, release_id) =
            seed_scope(&pool, "primary").await?;
        let regression_event = seed_event(
            &pool,
            &organization_id,
            &project_id,
            &key_id,
            "processed",
            "production",
            "regression",
        )
        .await?;
        let regression_issue: String = sqlx::query_scalar(
            "INSERT INTO issues (id, organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint, title, status, regression_state, first_seen_at, last_seen_at, event_count, representative_event_id, resolved_in_release_id, resolved_at) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'stack', 1, repeat('a', 64), 'Regressed crash', 'open', 'regressed', now() - interval '1 day', now(), 1, $3::uuid, $4::uuid, now() - interval '1 hour') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&regression_event)
        .bind(&release_id)
        .fetch_one(&pool)
        .await?;
        sqlx::query("UPDATE crash_events SET issue_id = $2::uuid, grouping_state = 'grouped', fingerprint_algorithm = 'stack', fingerprint_version = 1, fingerprint = repeat('a', 64), variant_fingerprint = repeat('c', 64), grouping_quality = 100, grouped_at = now() WHERE id = $1::uuid")
            .bind(&regression_event)
            .bind(&regression_issue)
            .execute(&pool)
            .await?;

        let integration_id: String = sqlx::query_scalar(
            "INSERT INTO alert_integrations (organization_id, project_id, kind, name, recipient_user_id, created_by_user_id) VALUES ($1::uuid, $2::uuid, 'email', 'Owner email', $3::uuid, $3::uuid) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&user_id)
        .fetch_one(&pool)
        .await?;
        for (condition, environment, threshold, window) in [
            ("first_seen", "production", None, None),
            ("regression", "production", None, None),
            ("volume", "production", Some(1), Some(60)),
            ("missing_symbols", "production", None, None),
            ("processing_failure", "production", None, None),
            ("ingest_silence", "silent", None, Some(60)),
            ("quota", "production", Some(70), None),
        ] {
            add_rule(
                &pool,
                &organization_id,
                &project_id,
                &integration_id,
                &user_id,
                condition,
                environment,
                threshold,
                window,
            )
            .await?;
        }

        let first_event = seed_event(
            &pool,
            &organization_id,
            &project_id,
            &key_id,
            "processed",
            "production",
            "first",
        )
        .await?;
        let first_issue: String = sqlx::query_scalar(
            "INSERT INTO issues (id, organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint, title, regression_state, first_seen_at, last_seen_at, event_count, representative_event_id) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'stack', 1, repeat('b', 64), 'First crash', 'new', now(), now(), 1, $3::uuid) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&first_event)
        .fetch_one(&pool)
        .await?;
        sqlx::query("UPDATE crash_events SET issue_id = $2::uuid, grouping_state = 'grouped', fingerprint_algorithm = 'stack', fingerprint_version = 1, fingerprint = repeat('b', 64), variant_fingerprint = repeat('d', 64), grouping_quality = 100, grouped_at = now() WHERE id = $1::uuid")
            .bind(&first_event)
            .bind(&first_issue)
            .execute(&pool)
            .await?;
        seed_event(
            &pool,
            &organization_id,
            &project_id,
            &key_id,
            "awaiting_symbols",
            "production",
            "missing",
        )
        .await?;
        seed_event(
            &pool,
            &organization_id,
            &project_id,
            &key_id,
            "failed",
            "production",
            "failed",
        )
        .await?;
        sqlx::query(
            "INSERT INTO usage_cycle_counters (organization_id, project_id, cycle_start, accepted_events) VALUES ($1::uuid, $2::uuid, date_trunc('month', now() AT TIME ZONE 'UTC')::date, 7) ON CONFLICT (organization_id, project_id, cycle_start) DO UPDATE SET accepted_events = 7",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            "UPDATE project_usage_policies SET event_limit = 10 WHERE organization_id = $1::uuid AND project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .execute(&pool)
        .await?;

        let (other_user, other_organization, other_project, _, _) =
            seed_scope(&pool, "other").await?;
        let other_integration: String = sqlx::query_scalar(
            "INSERT INTO alert_integrations (organization_id, project_id, kind, name, recipient_user_id, created_by_user_id) VALUES ($1::uuid, $2::uuid, 'email', 'Other email', $3::uuid, $3::uuid) RETURNING id::text",
        )
        .bind(&other_organization)
        .bind(&other_project)
        .bind(&other_user)
        .fetch_one(&pool)
        .await?;
        add_rule(
            &pool,
            &other_organization,
            &other_project,
            &other_integration,
            &other_user,
            "volume",
            "production",
            Some(1),
            Some(60),
        )
        .await?;

        let (first_evaluation, replayed_evaluation) =
            tokio::join!(evaluate_rules_once(&pool), evaluate_rules_once(&pool));
        first_evaluation?;
        replayed_evaluation?;
        evaluate_rules_once(&pool).await?;
        assert_eq!(delivery_count(&pool, &project_id).await?, 7);
        assert_eq!(delivery_count(&pool, &other_project).await?, 0);

        sqlx::query("UPDATE crash_events SET issue_id = NULL, grouping_state = 'disabled', fingerprint_algorithm = NULL, fingerprint_version = NULL, fingerprint = NULL, variant_fingerprint = NULL, grouping_quality = NULL, grouped_at = NULL, processing_state = 'processed', state_reason = NULL, received_at = now() - interval '2 hours' WHERE organization_id = $1::uuid AND project_id = $2::uuid")
            .bind(&organization_id)
            .bind(&project_id)
            .execute(&pool)
            .await?;
        sqlx::query(
            "DELETE FROM issues WHERE organization_id = $1::uuid AND project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .execute(&pool)
        .await?;
        seed_event(
            &pool,
            &organization_id,
            &project_id,
            &key_id,
            "processed",
            "silent",
            "silence-recovered",
        )
        .await?;
        sqlx::query("UPDATE usage_cycle_counters SET accepted_events = 0 WHERE organization_id = $1::uuid AND project_id = $2::uuid")
            .bind(&organization_id)
            .bind(&project_id)
            .execute(&pool)
            .await?;
        let (first_recovery, replayed_recovery) =
            tokio::join!(evaluate_rules_once(&pool), evaluate_rules_once(&pool));
        first_recovery?;
        replayed_recovery?;
        evaluate_rules_once(&pool).await?;
        assert_eq!(delivery_count(&pool, &project_id).await?, 14);

        let claimed = claim_delivery(&pool, "test-worker")
            .await?
            .ok_or("delivery was not claimed")?;
        finish_delivery(
            &pool,
            &claimed,
            Err(DeliveryError::Retryable("destination_retryable")),
        )
        .await?;
        sqlx::query("UPDATE alert_deliveries SET available_at = CASE WHEN id = $1::uuid THEN now() ELSE now() + interval '1 hour' END WHERE state IN ('pending', 'failed')")
            .bind(&claimed.id)
            .execute(&pool)
            .await?;
        let retried = claim_delivery(&pool, "test-worker")
            .await?
            .ok_or("delivery was not retried")?;
        assert_eq!(retried.id, claimed.id);
        finish_delivery(&pool, &retried, Ok(())).await?;
        let state: String = sqlx::query_scalar(
            "SELECT state FROM alert_deliveries WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid",
        )
        .bind(&retried.id)
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(state, "delivered");
        assert_eq!(retried.attempt, 2);

        let server = ServerState::alert_test(
            pool.clone(),
            "alerts-api-secret-000000000000000",
            [9_u8; 32],
        );
        let listed = alert_request(&server, "GET", &project_id, None).await?;
        assert_eq!(listed.status(), axum::http::StatusCode::OK);
        let listed = response_json(listed).await?;
        assert_eq!(listed["enabled"], true);
        assert_eq!(listed["can_edit"], true);
        assert_eq!(listed["rules"].as_array().map(Vec::len), Some(7));
        assert!(listed.to_string().find("encrypted_config").is_none());
        let volume_rule: String = sqlx::query_scalar(
            "SELECT id::text FROM alert_rules WHERE organization_id = $1::uuid AND project_id = $2::uuid AND condition_kind = 'volume'",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        sqlx::query("UPDATE alert_rules SET last_evaluated_at = now() WHERE id = $1::uuid")
            .bind(&volume_rule)
            .execute(&pool)
            .await?;
        let updated_rule =
            alert_rule_update_request(&server, &project_id, &volume_rule, json!({"threshold": 2}))
                .await?;
        assert_eq!(updated_rule.status(), axum::http::StatusCode::OK);
        let evaluation_reset: Option<OffsetDateTime> =
            sqlx::query_scalar("SELECT last_evaluated_at FROM alert_rules WHERE id = $1::uuid")
                .bind(&volume_rule)
                .fetch_one(&pool)
                .await?;
        assert!(evaluation_reset.is_none());
        let created = alert_request(
            &server,
            "POST",
            &project_id,
            Some(json!({"kind": "email", "name": "Second owner email"})),
        )
        .await?;
        assert_eq!(created.status(), axum::http::StatusCode::CREATED);
        let created = response_json(created).await?;
        assert_eq!(created["recipient_user_id"], user_id);
        assert!(created.get("signing_secret").is_none());
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE organization_id = $1::uuid AND actor_user_id = $2::uuid AND action = 'alert_integration.created'",
        )
        .bind(&organization_id)
        .bind(&user_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(audit_count, 1);
        let departing_user: String = sqlx::query_scalar(
            "INSERT INTO users (bootstrap_subject, email) VALUES ('alerts-departing-member', 'departing@example.com') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await?;
        sqlx::query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'developer')")
            .bind(&organization_id)
            .bind(&departing_user)
            .execute(&pool)
            .await?;
        let departing_integration: String = sqlx::query_scalar(
            "INSERT INTO alert_integrations (organization_id, project_id, kind, name, recipient_user_id, created_by_user_id) VALUES ($1::uuid, $2::uuid, 'email', 'Departing member', $3::uuid, $4::uuid) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&departing_user)
        .bind(&user_id)
        .fetch_one(&pool)
        .await?;
        sqlx::query("DELETE FROM organization_memberships WHERE organization_id = $1::uuid AND user_id = $2::uuid")
            .bind(&organization_id)
            .bind(&departing_user)
            .execute(&pool)
            .await?;
        let removed_recipient = deliver_claim(
            &pool,
            &SecretCipher::new([9_u8; 32]),
            Some(&EmailDelivery {
                url: Url::parse("https://email.example.com")?,
                token: "test-token".to_owned(),
            }),
            &ClaimedDelivery {
                id: random_uuid()?,
                organization_id: organization_id.clone(),
                project_id: project_id.clone(),
                integration_id: departing_integration,
                attempt: 1,
                max_attempt: 3,
                lease_token: random_uuid()?,
                payload: json!({}),
            },
        )
        .await;
        assert!(matches!(
            removed_recipient,
            Err(DeliveryError::Permanent("recipient_not_found"))
        ));
        let outside = alert_request(&server, "GET", &other_project, None).await?;
        assert_eq!(outside.status(), axum::http::StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used, clippy::too_many_lines)]
    async fn expired_final_deliveries_finish_and_concurrent_reclaimers_do_not_duplicate()
    -> Result<(), Box<dyn Error>> {
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
        let (user_id, organization_id, project_id, _, _) =
            seed_scope(&pool, "delivery-reclaim").await?;
        let integration_id =
            seed_email_integration(&pool, &organization_id, &project_id, &user_id).await?;
        add_rule(
            &pool,
            &organization_id,
            &project_id,
            &integration_id,
            &user_id,
            "volume",
            "production",
            Some(1),
            Some(60),
        )
        .await?;
        let rule_id: String = sqlx::query_scalar(
            "SELECT id::text FROM alert_rules WHERE organization_id = $1::uuid AND project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        let final_id: String = sqlx::query_scalar(
            "INSERT INTO alert_deliveries (organization_id, project_id, integration_id, rule_id, scope_key, generation, transition, payload, attempt, max_attempt) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'project:final', 1, 'triggered', '{}'::jsonb, 2, 3) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&integration_id)
        .bind(&rule_id)
        .fetch_one(&pool)
        .await?;
        let final_claim = claim_delivery(&pool, "final-worker")
            .await?
            .ok_or("final attempt was not claimed")?;
        assert_eq!(final_claim.id, final_id);
        assert_eq!(final_claim.attempt, 3);
        sqlx::query(
            "UPDATE alert_deliveries SET lease_expires_at = now() - interval '1 second' WHERE id = $1::uuid",
        )
        .bind(&final_id)
        .execute(&pool)
        .await?;
        let (left, right) = tokio::join!(
            claim_delivery(&pool, "final-reclaimer-left"),
            claim_delivery(&pool, "final-reclaimer-right")
        );
        assert!(left?.is_none());
        assert!(right?.is_none());
        let final_state = sqlx::query(
            "SELECT state, attempt, failure_code, lease_owner, lease_token::text AS lease_token, lease_expires_at FROM alert_deliveries WHERE id = $1::uuid",
        )
        .bind(&final_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(final_state.get::<String, _>("state"), "dead");
        assert_eq!(final_state.get::<i32, _>("attempt"), 3);
        assert_eq!(
            final_state
                .get::<Option<String>, _>("failure_code")
                .as_deref(),
            Some("lease_expired_final")
        );
        assert!(
            final_state
                .get::<Option<String>, _>("lease_owner")
                .is_none()
        );
        assert!(
            final_state
                .get::<Option<String>, _>("lease_token")
                .is_none()
        );
        assert!(
            final_state
                .get::<Option<OffsetDateTime>, _>("lease_expires_at")
                .is_none()
        );

        let reclaim_id: String = sqlx::query_scalar(
            "INSERT INTO alert_deliveries (organization_id, project_id, integration_id, rule_id, scope_key, generation, transition, payload, state, attempt, max_attempt, lease_owner, lease_token, lease_expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'project:reclaim', 1, 'triggered', '{}'::jsonb, 'leased', 2, 3, 'stale-worker', gen_random_uuid(), now() - interval '1 second') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&integration_id)
        .bind(&rule_id)
        .fetch_one(&pool)
        .await?;
        let (left, right) = tokio::join!(
            claim_delivery(&pool, "reclaimer-left"),
            claim_delivery(&pool, "reclaimer-right")
        );
        let claims = [left?, right?].into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, reclaim_id);
        assert_eq!(claims[0].attempt, 3);
        finish_delivery(&pool, &claims[0], Ok(())).await?;
        let reclaimed_state: String =
            sqlx::query_scalar("SELECT state FROM alert_deliveries WHERE id = $1::uuid")
                .bind(&reclaim_id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(reclaimed_state, "delivered");
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    async fn scheduler_rotates_through_every_enabled_rule() -> Result<(), Box<dyn Error>> {
        let database_url = std::env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await?;
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await?;
        let (user_id, organization_id, project_id, _, _) = seed_scope(&pool, "rule-pages").await?;
        let integration_id =
            seed_email_integration(&pool, &organization_id, &project_id, &user_id).await?;
        let inserted: i64 = sqlx::query_scalar(
            "WITH inserted AS (INSERT INTO alert_rules (organization_id, project_id, integration_id, condition_kind, environment, threshold, window_seconds, enabled, created_by_user_id) SELECT $1::uuid, $2::uuid, $3::uuid, 'volume', 'e' || lpad(n::text, 4, '0'), 1, 60, n <= 1001, $4::uuid FROM generate_series(1, 1002) values(n) RETURNING 1) SELECT count(*)::bigint FROM inserted",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&integration_id)
        .bind(&user_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(inserted, 1_002);
        sqlx::query("ANALYZE alert_rules").execute(&pool).await?;

        let started = Instant::now();
        evaluate_rules_once(&pool).await?;
        let first_tick: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM alert_rules WHERE organization_id = $1::uuid AND project_id = $2::uuid AND enabled AND last_evaluated_at IS NOT NULL",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(first_tick, 1_000);
        evaluate_rules_once(&pool).await?;
        let state = sqlx::query(
            "SELECT count(*) FILTER (WHERE enabled AND last_evaluated_at IS NOT NULL)::bigint AS enabled_evaluated, count(*) FILTER (WHERE enabled AND last_evaluated_at IS NULL)::bigint AS enabled_waiting, count(*) FILTER (WHERE NOT enabled AND last_evaluated_at IS NOT NULL)::bigint AS disabled_evaluated FROM alert_rules WHERE organization_id = $1::uuid AND project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(state.get::<i64, _>("enabled_evaluated"), 1_001);
        assert_eq!(state.get::<i64, _>("enabled_waiting"), 0);
        assert_eq!(state.get::<i64, _>("disabled_evaluated"), 0);
        assert_eq!(delivery_count(&pool, &project_id).await?, 0);
        println!(
            "enabled_rules=1001 ticks=2 elapsed_ms={}",
            started.elapsed().as_millis()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used, clippy::too_many_lines)]
    async fn issue_evaluation_pages_every_match_before_recovery() -> Result<(), Box<dyn Error>> {
        let database_url = std::env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await?;
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await?;
        let (user_id, organization_id, project_id, key_id, release_id) =
            seed_scope(&pool, "issue-pages").await?;
        let integration_id =
            seed_email_integration(&pool, &organization_id, &project_id, &user_id).await?;
        add_rule(
            &pool,
            &organization_id,
            &project_id,
            &integration_id,
            &user_id,
            "regression",
            "production",
            None,
            None,
        )
        .await?;
        let rule_id: String = sqlx::query_scalar(
            "SELECT id::text FROM alert_rules WHERE organization_id = $1::uuid AND project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        let inserted_issues: i64 = sqlx::query_scalar(
            "WITH inserted AS (INSERT INTO issues (id, organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint, title, status, regression_state, first_seen_at, last_seen_at, event_count, resolved_in_release_id, resolved_at, updated_at) SELECT gen_random_uuid(), $1::uuid, $2::uuid, 'stack', 1, md5('issue:' || n::text) || md5('fingerprint:' || n::text), 'Paged issue ' || n::text, 'open', 'regressed', now() - interval '1 hour' + n * interval '1 millisecond', now(), 1, $3::uuid, now() - interval '2 hours', now() - interval '1 hour' + n * interval '1 millisecond' FROM generate_series(1, 1001) values(n) RETURNING 1) SELECT count(*)::bigint FROM inserted",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&release_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(inserted_issues, 1_001);
        let inserted_events: i64 = sqlx::query_scalar(
            "WITH targets AS MATERIALIZED (SELECT id AS issue_id, substring(title FROM 13)::integer AS n, fingerprint FROM issues WHERE organization_id = $1::uuid AND project_id = $2::uuid AND title LIKE 'Paged issue %'), objects AS (INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) SELECT gen_random_uuid(), $1::uuid, $2::uuid, 'alert-pages/' || n::text, decode(md5('object:' || n::text) || md5('checksum:' || n::text), 'hex'), 1, 'application/octet-stream' FROM targets RETURNING id, split_part(object_key, '/', 2)::integer AS n), inserted AS (INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, crash_guid, environment, processing_state, grouping_state, fingerprint_algorithm, fingerprint_version, fingerprint, variant_fingerprint, grouping_quality, grouped_at, issue_id, received_at, updated_at) SELECT gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, o.id, 'alert-page-' || t.n::text, 'production', 'processed', 'grouped', 'stack', 1, t.fingerprint, md5('variant:' || t.n::text) || md5('other:' || t.n::text), 100, now(), t.issue_id, now(), now() FROM targets t JOIN objects o ON o.n = t.n RETURNING issue_id) SELECT count(*)::bigint FROM inserted",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&key_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(inserted_events, 1_001);
        sqlx::query(
            "UPDATE issues i SET representative_event_id = e.id FROM crash_events e WHERE e.organization_id = i.organization_id AND e.project_id = i.project_id AND e.issue_id = i.id AND i.organization_id = $1::uuid AND i.project_id = $2::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .execute(&pool)
        .await?;
        let stale_issue = random_uuid()?;
        sqlx::query(
            "INSERT INTO alert_condition_states (organization_id, project_id, rule_id, scope_key, state, generation, payload) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'active', 1, $5)",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&rule_id)
        .bind(format!("issue:{stale_issue}"))
        .bind(json!({
            "condition": "regression",
            "project_id": project_id,
            "project_name": "issue-pages game",
            "environment": "production",
            "issue_id": stale_issue,
            "issue_title": "Stale issue",
            "count": 1,
            "url": "http://127.0.0.1:3000/projects/test/issues/stale",
            "transition": "triggered"
        }))
        .execute(&pool)
        .await?;

        let (_, other_organization, other_project, other_key, other_release) =
            seed_scope(&pool, "other-issue-pages").await?;
        let other_event = seed_event(
            &pool,
            &other_organization,
            &other_project,
            &other_key,
            "processed",
            "production",
            "other-regression",
        )
        .await?;
        let other_issue: String = sqlx::query_scalar(
            "INSERT INTO issues (id, organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint, title, status, regression_state, first_seen_at, last_seen_at, event_count, representative_event_id, resolved_in_release_id, resolved_at) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'stack', 1, repeat('f', 64), 'Other regression', 'open', 'regressed', now() - interval '1 hour', now(), 1, $3::uuid, $4::uuid, now() - interval '2 hours') RETURNING id::text",
        )
        .bind(&other_organization)
        .bind(&other_project)
        .bind(&other_event)
        .bind(&other_release)
        .fetch_one(&pool)
        .await?;
        sqlx::query(
            "UPDATE crash_events SET issue_id = $2::uuid, grouping_state = 'grouped', fingerprint_algorithm = 'stack', fingerprint_version = 1, fingerprint = repeat('f', 64), variant_fingerprint = repeat('e', 64), grouping_quality = 100, grouped_at = now() WHERE id = $1::uuid",
        )
        .bind(&other_event)
        .bind(&other_issue)
        .execute(&pool)
        .await?;
        sqlx::query("ANALYZE issues").execute(&pool).await?;

        let started = Instant::now();
        let rule_row = sqlx::query(
            "SELECT r.id::text AS id, r.organization_id::text AS organization_id, r.project_id::text AS project_id, p.name AS project_name, r.integration_id::text AS integration_id, r.condition_kind, r.environment, r.threshold, r.window_seconds, r.quiet_start_minute, r.quiet_end_minute, r.created_at, r.updated_at FROM alert_rules r JOIN projects p ON p.id = r.project_id AND p.organization_id = r.organization_id WHERE r.id = $1::uuid AND r.organization_id = $2::uuid AND r.project_id = $3::uuid",
        )
        .bind(&rule_id)
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        let rule = RuleEvaluation {
            id: rule_row.get("id"),
            organization_id: rule_row.get("organization_id"),
            project_id: rule_row.get("project_id"),
            project_name: rule_row.get("project_name"),
            integration_id: rule_row.get("integration_id"),
            condition_kind: rule_row.get("condition_kind"),
            environment: rule_row.get("environment"),
            threshold: rule_row.get("threshold"),
            window_seconds: rule_row.get("window_seconds"),
            quiet_start_minute: rule_row.get("quiet_start_minute"),
            quiet_end_minute: rule_row.get("quiet_end_minute"),
            created_at: rule_row.get("created_at"),
            updated_at: rule_row.get("updated_at"),
        };
        assert!(
            !evaluate_issue_rule_pages_bounded(&pool, &rule, true, Some(1)).await?,
            "one page must not be treated as a complete evaluation"
        );
        let interrupted_state = sqlx::query(
            "SELECT count(*) FILTER (WHERE state = 'active')::bigint AS active, count(*) FILTER (WHERE state = 'inactive')::bigint AS inactive FROM alert_condition_states WHERE organization_id = $1::uuid AND project_id = $2::uuid AND rule_id = $3::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&rule_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(interrupted_state.get::<i64, _>("active"), 1_001);
        assert_eq!(interrupted_state.get::<i64, _>("inactive"), 0);
        assert_eq!(delivery_count(&pool, &project_id).await?, 1_000);

        evaluate_rules_once(&pool).await?;
        let first_state = sqlx::query(
            "SELECT count(*) FILTER (WHERE state = 'active')::bigint AS active, count(*) FILTER (WHERE state = 'inactive')::bigint AS inactive FROM alert_condition_states WHERE organization_id = $1::uuid AND project_id = $2::uuid AND rule_id = $3::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&rule_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(first_state.get::<i64, _>("active"), 1_001);
        assert_eq!(first_state.get::<i64, _>("inactive"), 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM alert_condition_states WHERE organization_id = $1::uuid",
            )
            .bind(&other_organization)
            .fetch_one(&pool)
            .await?,
            0
        );
        assert_eq!(delivery_count(&pool, &project_id).await?, 1_002);

        let moved_issue: String = sqlx::query_scalar(
            "UPDATE issues SET updated_at = now() + interval '1 day' WHERE id = (SELECT id FROM issues WHERE organization_id = $1::uuid AND project_id = $2::uuid ORDER BY updated_at, id LIMIT 1) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await?;
        evaluate_rules_once(&pool).await?;
        let moved_state: String = sqlx::query_scalar(
            "SELECT state FROM alert_condition_states WHERE organization_id = $1::uuid AND project_id = $2::uuid AND rule_id = $3::uuid AND scope_key = $4",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&rule_id)
        .bind(format!("issue:{moved_issue}"))
        .fetch_one(&pool)
        .await?;
        assert_eq!(moved_state, "active");
        assert_eq!(delivery_count(&pool, &project_id).await?, 1_002);

        let resolved_issue: String = sqlx::query_scalar(
            "UPDATE issues SET status = 'resolved', regression_state = 'resolved', updated_at = now() + interval '2 days' WHERE id = (SELECT id FROM issues WHERE organization_id = $1::uuid AND project_id = $2::uuid AND id <> $3::uuid ORDER BY updated_at, id LIMIT 1) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&moved_issue)
        .fetch_one(&pool)
        .await?;
        evaluate_rules_once(&pool).await?;
        let final_state = sqlx::query(
            "SELECT count(*) FILTER (WHERE state = 'active')::bigint AS active, count(*) FILTER (WHERE state = 'inactive')::bigint AS inactive FROM alert_condition_states WHERE organization_id = $1::uuid AND project_id = $2::uuid AND rule_id = $3::uuid",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&rule_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(final_state.get::<i64, _>("active"), 1_000);
        assert_eq!(final_state.get::<i64, _>("inactive"), 2);
        let resolved_state: String = sqlx::query_scalar(
            "SELECT state FROM alert_condition_states WHERE organization_id = $1::uuid AND project_id = $2::uuid AND rule_id = $3::uuid AND scope_key = $4",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&rule_id)
        .bind(format!("issue:{resolved_issue}"))
        .fetch_one(&pool)
        .await?;
        assert_eq!(resolved_state, "inactive");
        assert_eq!(delivery_count(&pool, &project_id).await?, 1_003);
        println!(
            "matching_issues=1001 pages=2 false_recoveries=0 elapsed_ms={}",
            started.elapsed().as_millis()
        );
        Ok(())
    }

    async fn seed_scope(
        pool: &PgPool,
        prefix: &str,
    ) -> Result<(String, String, String, String, String), sqlx::Error> {
        let bootstrap_subject = if prefix == "primary" {
            "local-bootstrap".to_owned()
        } else {
            format!("alerts-{prefix}")
        };
        let user_id: String = sqlx::query_scalar(
            "INSERT INTO users (bootstrap_subject, email) VALUES ($1, $2) RETURNING id::text",
        )
        .bind(bootstrap_subject)
        .bind(format!("{prefix}@example.com"))
        .fetch_one(pool)
        .await?;
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
        )
        .bind(format!("{prefix} alerts org"))
        .bind(format!("{prefix}-alerts-org"))
        .fetch_one(pool)
        .await?;
        sqlx::query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')")
            .bind(&organization_id)
            .bind(&user_id)
            .execute(pool)
            .await?;
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, $2, $3) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(format!("{prefix} game"))
        .bind(format!("{prefix}-game"))
        .fetch_one(pool)
        .await?;
        let key_id: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, 'alertkey') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(vec![prefix.bytes().next().unwrap_or_default(); 32])
        .fetch_one(pool)
        .await?;
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration) VALUES ($1::uuid, $2::uuid, '1.0.0', 'windows', 'x86_64', 'Shipping') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(pool)
        .await?;
        Ok((user_id, organization_id, project_id, key_id, release_id))
    }

    async fn seed_email_integration(
        pool: &PgPool,
        organization_id: &str,
        project_id: &str,
        user_id: &str,
    ) -> Result<String, sqlx::Error> {
        sqlx::query_scalar(
            "INSERT INTO alert_integrations (organization_id, project_id, kind, name, recipient_user_id, created_by_user_id) VALUES ($1::uuid, $2::uuid, 'email', 'Scale owner email', $3::uuid, $3::uuid) RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_rule(
        pool: &PgPool,
        organization_id: &str,
        project_id: &str,
        integration_id: &str,
        user_id: &str,
        condition: &str,
        environment: &str,
        threshold: Option<i32>,
        window: Option<i32>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO alert_rules (organization_id, project_id, integration_id, condition_kind, environment, threshold, window_seconds, created_by_user_id, created_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8::uuid, CASE WHEN $4 = 'ingest_silence' THEN now() - interval '2 minutes' ELSE now() END)",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(integration_id)
        .bind(condition)
        .bind(environment)
        .bind(threshold)
        .bind(window)
        .bind(user_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn seed_event(
        pool: &PgPool,
        organization_id: &str,
        project_id: &str,
        key_id: &str,
        state: &str,
        environment: &str,
        suffix: &str,
    ) -> Result<String, sqlx::Error> {
        let object_id: String = sqlx::query_scalar(
            "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3, $4, 1, 'application/octet-stream') RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(format!("alerts/{project_id}/{suffix}"))
        .bind(vec![3_u8; 32])
        .fetch_one(pool)
        .await?;
        sqlx::query_scalar(
            "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, crash_guid, environment, processing_state, state_reason) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, CASE WHEN $7 IN ('failed', 'quarantined') THEN 'test_failure' ELSE NULL END) RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(key_id)
        .bind(object_id)
        .bind(format!("alerts-{project_id}-{suffix}"))
        .bind(environment)
        .bind(state)
        .fetch_one(pool)
        .await
    }

    async fn delivery_count(pool: &PgPool, project_id: &str) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT count(*) FROM alert_deliveries WHERE project_id = $1::uuid")
            .bind(project_id)
            .fetch_one(pool)
            .await
    }

    async fn alert_request(
        state: &ServerState,
        method: &str,
        project_id: &str,
        body: Option<serde_json::Value>,
    ) -> Result<axum::response::Response, Box<dyn Error>> {
        let mut request = Request::builder()
            .method(method)
            .uri(if method == "POST" {
                format!("/api/v1/projects/{project_id}/alert-integrations")
            } else {
                format!("/api/v1/projects/{project_id}/alerts")
            })
            .header(
                "authorization",
                "Bootstrap alerts-api-secret-000000000000000",
            );
        let body = if let Some(body) = body {
            request = request.header("content-type", "application/json");
            Body::from(body.to_string())
        } else {
            Body::empty()
        };
        Ok(router("api", state.clone())
            .oneshot(request.body(body)?)
            .await?)
    }

    async fn alert_rule_update_request(
        state: &ServerState,
        project_id: &str,
        rule_id: &str,
        body: serde_json::Value,
    ) -> Result<axum::response::Response, Box<dyn Error>> {
        let request = Request::builder()
            .method("PATCH")
            .uri(format!(
                "/api/v1/projects/{project_id}/alert-rules/{rule_id}"
            ))
            .header(
                "authorization",
                "Bootstrap alerts-api-secret-000000000000000",
            )
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        Ok(router("api", state.clone()).oneshot(request).await?)
    }

    async fn response_json(
        response: axum::response::Response,
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn collect_delivery(
        State(received): State<ReceivedDeliveries>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        received.lock().await.push((headers, body));
        StatusCode::NO_CONTENT
    }

    fn mock_url(address: std::net::SocketAddr, path: &str) -> Url {
        Url::parse(&format!("http://{address}{path}"))
            .unwrap_or_else(|error| panic!("mock URL failed: {error}"))
    }
}
