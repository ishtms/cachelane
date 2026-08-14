use std::{env, net::IpAddr, str::FromStr, time::Duration};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use url::Url;

use crate::project_setup::{ServerState, StartupError};

const LOGIN_TOKEN_BYTES: usize = 32;
const SESSION_PREFIX: &str = "fls_";
const GITHUB_STATE_PREFIX: &str = "flg_";
const EMAIL_TOKEN_PREFIX: &str = "fle_";
const INVITATION_TOKEN_PREFIX: &str = "fli_";
const MAX_EMAIL_BYTES: usize = 254;
const MAX_PROVIDER_SUBJECT_BYTES: usize = MAX_EMAIL_BYTES;
const MAX_GITHUB_CODE_BYTES: usize = 512;
const MAX_AUDIT_RESULTS: i64 = 100;
const MAX_EMAIL_ATTEMPTS: i64 = 5;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone)]
pub(crate) struct Auth {
    pool: Option<PgPool>,
    client: Client,
    web_base_url: String,
    github: Option<GithubConfig>,
    email: Option<EmailConfig>,
}

#[derive(Clone)]
struct GithubConfig {
    client_id: String,
    client_secret: String,
    authorize_url: String,
    token_url: String,
    user_url: String,
    emails_url: String,
}

#[derive(Clone)]
struct EmailConfig {
    delivery_url: String,
    delivery_token: String,
}

impl Auth {
    pub(crate) fn for_role(pool: PgPool, host: &str, role: &str) -> Result<Self, StartupError> {
        if role == "api" {
            Self::from_environment(pool, host)
        } else {
            Ok(Self {
                pool: Some(pool),
                client: Client::new(),
                web_base_url: String::new(),
                github: None,
                email: None,
            })
        }
    }

    pub(crate) fn from_environment(pool: PgPool, host: &str) -> Result<Self, StartupError> {
        let web_base_url = validate_web_base_url(
            &env::var("PUBLIC_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned()),
            host,
        )?;
        let github_client_id = nonempty_environment("FAULTLANE_GITHUB_CLIENT_ID");
        let github_client_secret = nonempty_environment("FAULTLANE_GITHUB_CLIENT_SECRET");
        let github = match (github_client_id, github_client_secret) {
            (Some(client_id), Some(client_secret))
                if !client_id.trim().is_empty() && !client_secret.trim().is_empty() =>
            {
                Some(GithubConfig {
                    client_id,
                    client_secret,
                    authorize_url: "https://github.com/login/oauth/authorize".to_owned(),
                    token_url: "https://github.com/login/oauth/access_token".to_owned(),
                    user_url: "https://api.github.com/user".to_owned(),
                    emails_url: "https://api.github.com/user/emails".to_owned(),
                })
            }
            (None, None) => None,
            _ => return Err(StartupError::AuthenticationConfiguration),
        };
        let email_url = nonempty_environment("FAULTLANE_EMAIL_DELIVERY_URL");
        let email_token = nonempty_environment("FAULTLANE_EMAIL_DELIVERY_TOKEN");
        let email = match (email_url, email_token) {
            (Some(delivery_url), Some(delivery_token)) if !delivery_token.trim().is_empty() => {
                validate_delivery_url(&delivery_url, host)?;
                Some(EmailConfig {
                    delivery_url,
                    delivery_token,
                })
            }
            (None, None) => None,
            _ => return Err(StartupError::AuthenticationConfiguration),
        };
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| StartupError::AuthenticationConfiguration)?;

        Ok(Self {
            pool: Some(pool),
            client,
            web_base_url,
            github,
            email,
        })
    }

    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            pool: None,
            client: Client::new(),
            web_base_url: "http://127.0.0.1:3000".to_owned(),
            github: None,
            email: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn test(pool: PgPool) -> Self {
        Self {
            pool: Some(pool),
            client: Client::new(),
            web_base_url: "http://127.0.0.1:3000".to_owned(),
            github: None,
            email: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_providers(pool: PgPool, provider_base_url: &str) -> Self {
        Self {
            pool: Some(pool),
            client: Client::new(),
            web_base_url: "http://127.0.0.1:3000".to_owned(),
            github: Some(GithubConfig {
                client_id: "test-client".to_owned(),
                client_secret: "test-secret".to_owned(),
                authorize_url: format!("{provider_base_url}/login/oauth/authorize"),
                token_url: format!("{provider_base_url}/login/oauth/access_token"),
                user_url: format!("{provider_base_url}/user"),
                emails_url: format!("{provider_base_url}/user/emails"),
            }),
            email: Some(EmailConfig {
                delivery_url: format!("{provider_base_url}/deliver"),
                delivery_token: "test-delivery-secret".to_owned(),
            }),
        }
    }

    fn pool(&self) -> Result<&PgPool, ApiError> {
        self.pool.as_ref().ok_or(ApiError::Unavailable)
    }

    async fn session_actor(&self, headers: &HeaderMap) -> Result<ControlActor, AuthorizationError> {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Session "))
            .filter(|value| valid_secret(value, SESSION_PREFIX))
            .ok_or(AuthorizationError::Unauthorized)?;
        let pool = self.pool.as_ref().ok_or(AuthorizationError::Unavailable)?;
        let row = sqlx::query(
            "UPDATE auth_sessions s SET last_seen_at = now() FROM users u WHERE s.user_id = u.id AND s.secret_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() RETURNING s.id::text AS session_id, u.id::text AS user_id",
        )
        .bind(hash(token))
        .fetch_optional(pool)
        .await
        .map_err(|_| AuthorizationError::Unavailable)?
        .ok_or(AuthorizationError::Unauthorized)?;

        Ok(ControlActor {
            user_id: row.get("user_id"),
            session_id: Some(row.get("session_id")),
        })
    }
}

pub(crate) fn router() -> Router<ServerState> {
    Router::new()
        .route("/api/v1/auth/providers", get(get_providers))
        .route("/api/v1/auth/github/start", post(start_github))
        .route("/api/v1/auth/github/callback", post(complete_github))
        .route("/api/v1/auth/email/start", post(start_email))
        .route("/api/v1/auth/email/verify", post(verify_email))
        .route("/api/v1/auth/session", get(get_session))
        .route("/api/v1/auth/sessions", get(list_sessions))
        .route("/api/v1/auth/sessions/{session_id}", delete(revoke_session))
        .route(
            "/api/v1/organizations/{organization_id}/members",
            get(list_members),
        )
        .route(
            "/api/v1/organizations/{organization_id}/members/{user_id}",
            patch(update_member).delete(remove_member),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations",
            post(create_invitation),
        )
        .route(
            "/api/v1/organizations/{organization_id}/invitations/{invitation_id}",
            delete(revoke_invitation),
        )
        .route("/api/v1/invitations/accept", post(accept_invitation))
        .route(
            "/api/v1/organizations/{organization_id}/audit",
            get(list_audit),
        )
        .layer(DefaultBodyLimit::max(8 * 1024))
}

#[derive(Clone, Debug)]
pub(crate) struct ControlActor {
    pub(crate) user_id: String,
    pub(crate) session_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Role {
    Owner,
    Admin,
    Developer,
    Viewer,
}

impl Role {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "developer" => Some(Self::Developer),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Developer => "developer",
            Self::Viewer => "viewer",
        }
    }

    const fn allows(self, permission: Permission) -> bool {
        match permission {
            Permission::ReadProject => true,
            Permission::ManageIssue | Permission::ReadRaw => !matches!(self, Self::Viewer),
            Permission::ManageProject | Permission::ManageMembers | Permission::ReadAudit => {
                matches!(self, Self::Owner | Self::Admin)
            }
            Permission::ManageDataRules => matches!(self, Self::Owner),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Permission {
    ReadProject,
    ManageIssue,
    ManageProject,
    ManageDataRules,
    ManageMembers,
    ReadRaw,
    ReadAudit,
}

#[derive(Clone, Debug)]
pub(crate) struct ProjectActor {
    pub(crate) actor: ControlActor,
    pub(crate) organization_id: String,
    pub(crate) project_id: String,
    role: Role,
}

impl ProjectActor {
    pub(crate) const fn allows(&self, permission: Permission) -> bool {
        self.role.allows(permission)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct OrganizationActor {
    pub(crate) actor: ControlActor,
    pub(crate) role: Role,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AuthorizationError {
    Unauthorized,
    Forbidden,
    NotFound,
    Unavailable,
}

pub(crate) async fn authenticate(
    state: &ServerState,
    headers: &HeaderMap,
) -> Result<ControlActor, AuthorizationError> {
    if state.authorize_bootstrap(headers) {
        if let Some(pool) = state.control_pool() {
            let row = sqlx::query(
                "SELECT id::text AS user_id FROM users WHERE bootstrap_subject = 'local-bootstrap'",
            )
            .fetch_optional(pool)
            .await
            .map_err(|_| AuthorizationError::Unavailable)?
            .ok_or(AuthorizationError::Unauthorized)?;
            return Ok(ControlActor {
                user_id: row.get("user_id"),
                session_id: None,
            });
        }
        return Ok(ControlActor {
            user_id: "local-bootstrap".to_owned(),
            session_id: None,
        });
    }
    state.auth().session_actor(headers).await
}

pub(crate) async fn authorize_project(
    state: &ServerState,
    headers: &HeaderMap,
    project_id: &str,
    permission: Permission,
) -> Result<ProjectActor, AuthorizationError> {
    let actor = authenticate(state, headers).await?;
    let Some(pool) = state.control_pool() else {
        return Ok(ProjectActor {
            actor,
            organization_id: String::new(),
            project_id: project_id.to_owned(),
            role: Role::Owner,
        });
    };
    let row = sqlx::query(
        "SELECT p.organization_id::text AS organization_id, m.role FROM projects p JOIN organization_memberships m ON m.organization_id = p.organization_id WHERE p.id::text = $1 AND m.user_id::text = $2",
    )
    .bind(project_id)
    .bind(&actor.user_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| AuthorizationError::Unavailable)?
    .ok_or(AuthorizationError::NotFound)?;
    let role = Role::parse(&row.get::<String, _>("role")).ok_or(AuthorizationError::Unavailable)?;
    if !role.allows(permission) {
        return Err(AuthorizationError::Forbidden);
    }

    Ok(ProjectActor {
        actor,
        organization_id: row.get("organization_id"),
        project_id: project_id.to_owned(),
        role,
    })
}

pub(crate) async fn authorize_organization(
    state: &ServerState,
    headers: &HeaderMap,
    organization_id: &str,
    permission: Permission,
) -> Result<OrganizationActor, AuthorizationError> {
    let actor = authenticate(state, headers).await?;
    let pool = state
        .control_pool()
        .ok_or(AuthorizationError::Unavailable)?;
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM organization_memberships WHERE organization_id::text = $1 AND user_id::text = $2",
    )
    .bind(organization_id)
    .bind(&actor.user_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| AuthorizationError::Unavailable)?
    .ok_or(AuthorizationError::NotFound)?;
    let role = Role::parse(&role).ok_or(AuthorizationError::Unavailable)?;
    if !role.allows(permission) {
        return Err(AuthorizationError::Forbidden);
    }
    Ok(OrganizationActor { actor, role })
}

#[derive(Serialize)]
struct GithubStartResponse {
    authorization_url: String,
}

#[derive(Serialize)]
struct ProviderResponse {
    github: bool,
    email: bool,
}

async fn get_providers(State(state): State<ServerState>) -> Response {
    no_store(
        StatusCode::OK,
        &ProviderResponse {
            github: state.auth().github.is_some(),
            email: state.auth().email.is_some(),
        },
    )
}

async fn start_github(State(state): State<ServerState>) -> Result<Response, ApiError> {
    let auth = state.auth();
    let github = auth.github.as_ref().ok_or(ApiError::NotFound)?;
    prune_login_attempts(auth.pool()?).await;
    let state_token = generated_secret(GITHUB_STATE_PREFIX)?;
    sqlx::query(
        "INSERT INTO auth_login_attempts (kind, secret_hash, expires_at) VALUES ('github', $1, now() + interval '10 minutes')",
    )
    .bind(hash(&state_token))
    .execute(auth.pool()?)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    let callback = format!("{}/auth/github/callback", auth.web_base_url);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &github.client_id)
        .append_pair("redirect_uri", &callback)
        .append_pair("scope", "read:user user:email")
        .append_pair("state", &state_token)
        .finish();
    Ok(no_store(
        StatusCode::OK,
        &GithubStartResponse {
            authorization_url: format!("{}?{query}", github.authorize_url),
        },
    ))
}

#[derive(Deserialize)]
struct GithubCallbackRequest {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

async fn complete_github(
    State(state): State<ServerState>,
    payload: Result<Json<GithubCallbackRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = payload.map_err(|_| ApiError::InvalidRequest)?;
    if !valid_secret(&request.state, GITHUB_STATE_PREFIX)
        || request.code.is_empty()
        || request.code.len() > MAX_GITHUB_CODE_BYTES
    {
        return Err(ApiError::InvalidRequest);
    }
    let auth = state.auth();
    let github = auth.github.as_ref().ok_or(ApiError::NotFound)?;
    consume_login(auth.pool()?, "github", &request.state).await?;
    let callback = format!("{}/auth/github/callback", auth.web_base_url);
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &github.client_id)
        .append_pair("client_secret", &github.client_secret)
        .append_pair("code", &request.code)
        .append_pair("redirect_uri", &callback)
        .finish();
    let token = auth
        .client
        .post(&github.token_url)
        .header(header::ACCEPT.as_str(), "application/json")
        .header(
            header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        )
        .header(header::USER_AGENT.as_str(), "FaultLane")
        .body(form)
        .send()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    if !token.status().is_success() {
        return Err(ApiError::Unauthorized);
    }
    let token = token
        .json::<GithubTokenResponse>()
        .await
        .map_err(|_| ApiError::Unavailable)?
        .access_token
        .filter(|value| !value.is_empty() && value.len() <= 2048)
        .ok_or(ApiError::Unauthorized)?;
    let user = github_get::<GithubUser>(auth, &github.user_url, &token).await?;
    let email = github_get::<Vec<GithubEmail>>(auth, &github.emails_url, &token)
        .await?
        .into_iter()
        .find(|email| email.primary && email.verified && valid_email(&email.email))
        .map(|email| normalize_email(&email.email))
        .transpose()?
        .ok_or(ApiError::Unauthorized)?;
    let session =
        create_identity_session(auth.pool()?, "github", &user.id.to_string(), &email).await?;
    audit_all_organizations(
        auth.pool()?,
        &session.user.id,
        "session.created",
        "session",
        &session.session.id,
        "succeeded",
    )
    .await;
    Ok(no_store(StatusCode::CREATED, &session))
}

async fn github_get<T: for<'de> Deserialize<'de>>(
    auth: &Auth,
    url: &str,
    token: &str,
) -> Result<T, ApiError> {
    let response = auth
        .client
        .get(url)
        .header(header::ACCEPT.as_str(), "application/vnd.github+json")
        .header(header::USER_AGENT.as_str(), "FaultLane")
        .header(header::AUTHORIZATION.as_str(), format!("Bearer {token}"))
        .send()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    if !response.status().is_success() {
        return Err(ApiError::Unauthorized);
    }
    response.json().await.map_err(|_| ApiError::Unavailable)
}

#[derive(Deserialize)]
struct EmailStartRequest {
    email: String,
}

#[derive(Serialize)]
struct EmailDeliveryRequest<'a> {
    to: &'a str,
    sign_in_url: &'a str,
}

async fn start_email(
    State(state): State<ServerState>,
    payload: Result<Json<EmailStartRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(request) = payload.map_err(|_| ApiError::InvalidRequest)?;
    let email = normalize_email(&request.email)?;
    let auth = state.auth();
    let delivery = auth.email.as_ref().ok_or(ApiError::NotFound)?;
    prune_login_attempts(auth.pool()?).await;
    let token = generated_secret(EMAIL_TOKEN_PREFIX)?;
    let mut transaction = auth
        .pool()?
        .begin()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(&email)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let recent_attempts = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM auth_login_attempts WHERE kind = 'email' AND email = $1 AND created_at > now() - interval '15 minutes'",
    )
    .bind(&email)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    if recent_attempts >= MAX_EMAIL_ATTEMPTS {
        return Ok(StatusCode::ACCEPTED);
    }
    let attempt_id = sqlx::query_scalar::<_, String>(
        "INSERT INTO auth_login_attempts (kind, secret_hash, email, expires_at) VALUES ('email', $1, $2, now() + interval '15 minutes') RETURNING id::text",
    )
    .bind(hash(&token))
    .bind(&email)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let sign_in_url = format!("{}/auth/email/verify?token={token}", auth.web_base_url);
    let response = auth
        .client
        .post(&delivery.delivery_url)
        .bearer_auth(&delivery.delivery_token)
        .json(&EmailDeliveryRequest {
            to: &email,
            sign_in_url: &sign_in_url,
        })
        .send()
        .await;
    if !response.is_ok_and(|response| response.status().is_success()) {
        let _ = sqlx::query("DELETE FROM auth_login_attempts WHERE id::text = $1")
            .bind(attempt_id)
            .execute(auth.pool()?)
            .await;
        return Err(ApiError::Unavailable);
    }
    Ok(StatusCode::ACCEPTED)
}

async fn prune_login_attempts(pool: &PgPool) {
    let _ = sqlx::query(
        "DELETE FROM auth_login_attempts WHERE expires_at <= now() OR consumed_at < now() - interval '15 minutes'",
    )
    .execute(pool)
    .await;
}

#[derive(Deserialize)]
struct SecretRequest {
    token: String,
}

async fn verify_email(
    State(state): State<ServerState>,
    payload: Result<Json<SecretRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = payload.map_err(|_| ApiError::InvalidRequest)?;
    if !valid_secret(&request.token, EMAIL_TOKEN_PREFIX) {
        return Err(ApiError::InvalidRequest);
    }
    let auth = state.auth();
    let email = consume_login(auth.pool()?, "email", &request.token)
        .await?
        .ok_or(ApiError::InvalidRequest)?;
    let session = create_identity_session(auth.pool()?, "email", &email, &email).await?;
    audit_all_organizations(
        auth.pool()?,
        &session.user.id,
        "session.created",
        "session",
        &session.session.id,
        "succeeded",
    )
    .await;
    Ok(no_store(StatusCode::CREATED, &session))
}

async fn consume_login(pool: &PgPool, kind: &str, token: &str) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, Option<String>>(
        "UPDATE auth_login_attempts SET consumed_at = now() WHERE kind = $1 AND secret_hash = $2 AND consumed_at IS NULL AND expires_at > now() RETURNING email",
    )
    .bind(kind)
    .bind(hash(token))
    .fetch_optional(pool)
    .await
    .map_err(|_| ApiError::Unavailable)?
    .ok_or(ApiError::Unauthorized)
}

#[derive(Serialize)]
struct SessionCreated {
    token: String,
    session: SessionView,
    user: UserView,
    memberships: Vec<MembershipView>,
}

#[derive(Serialize)]
struct SessionResponse {
    session: SessionView,
    user: UserView,
    memberships: Vec<MembershipView>,
}

#[derive(Serialize)]
struct SessionListResponse {
    sessions: Vec<SessionView>,
}

#[derive(Serialize)]
struct SessionView {
    id: String,
    created_at: String,
    last_seen_at: String,
    expires_at: String,
    current: bool,
}

#[derive(Serialize)]
struct UserView {
    id: String,
    email: String,
}

#[derive(Serialize)]
struct MembershipView {
    organization_id: String,
    organization_name: String,
    organization_slug: String,
    role: Role,
}

async fn create_identity_session(
    pool: &PgPool,
    provider: &str,
    subject: &str,
    email: &str,
) -> Result<SessionCreated, ApiError> {
    let token = generated_secret(SESSION_PREFIX)?;
    let mut transaction = pool.begin().await.map_err(|_| ApiError::Unavailable)?;
    let (user_id, session) =
        insert_identity_session(&mut transaction, provider, subject, email, &token).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let user = user_view(pool, &user_id).await?;
    let memberships = memberships(pool, &user_id).await?;
    Ok(SessionCreated {
        token,
        session,
        user,
        memberships,
    })
}

async fn insert_identity_session(
    transaction: &mut Transaction<'_, Postgres>,
    provider: &str,
    subject: &str,
    email: &str,
    token: &str,
) -> Result<(String, SessionView), ApiError> {
    if subject.is_empty() || subject.len() > MAX_PROVIDER_SUBJECT_BYTES {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(email)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let identity = sqlx::query_scalar::<_, String>(
        "SELECT user_id::text FROM user_identities WHERE provider = $1 AND subject = $2",
    )
    .bind(provider)
    .bind(subject)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    let user_id = if let Some(user_id) = identity {
        user_id
    } else {
        let user_id = if let Some(user_id) =
            sqlx::query_scalar::<_, String>("SELECT id::text FROM users WHERE lower(email) = $1")
                .bind(email)
                .fetch_optional(&mut **transaction)
                .await
                .map_err(|_| ApiError::Unavailable)?
        {
            user_id
        } else {
            let legacy_subject = format!("{provider}:{subject}");
            sqlx::query_scalar::<_, String>(
                "INSERT INTO users (bootstrap_subject, email) VALUES ($1, $2) RETURNING id::text",
            )
            .bind(legacy_subject)
            .bind(email)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| ApiError::Unavailable)?
        };
        sqlx::query(
            "INSERT INTO user_identities (provider, subject, user_id) VALUES ($1, $2, $3::uuid)",
        )
        .bind(provider)
        .bind(subject)
        .bind(&user_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        user_id
    };
    let row = sqlx::query(
        "INSERT INTO auth_sessions (user_id, secret_hash, expires_at) VALUES ($1::uuid, $2, now() + interval '30 days') RETURNING id::text AS id, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at",
    )
    .bind(&user_id)
    .bind(hash(token))
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;

    Ok((
        user_id,
        SessionView {
            id: row.get("id"),
            created_at: row.get("created_at"),
            last_seen_at: row.get("last_seen_at"),
            expires_at: row.get("expires_at"),
            current: true,
        },
    ))
}

async fn get_session(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let actor = authenticate(&state, &headers)
        .await
        .map_err(ApiError::from)?;
    let pool = state.auth().pool()?;
    let session_id = actor.session_id.as_ref().ok_or(ApiError::NotFound)?;
    let session = session_view(pool, &actor.user_id, session_id, session_id).await?;
    Ok(no_store(
        StatusCode::OK,
        &SessionResponse {
            session,
            user: user_view(pool, &actor.user_id).await?,
            memberships: memberships(pool, &actor.user_id).await?,
        },
    ))
}

async fn list_sessions(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let actor = authenticate(&state, &headers)
        .await
        .map_err(ApiError::from)?;
    let current = actor.session_id.as_ref().ok_or(ApiError::NotFound)?;
    let rows = sqlx::query(
        "SELECT id::text AS id, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at FROM auth_sessions WHERE user_id::text = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC, id DESC LIMIT 100",
    )
    .bind(&actor.user_id)
    .fetch_all(state.auth().pool()?)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    let sessions = rows
        .into_iter()
        .map(|row| {
            let id: String = row.get("id");
            SessionView {
                current: id == *current,
                id,
                created_at: row.get("created_at"),
                last_seen_at: row.get("last_seen_at"),
                expires_at: row.get("expires_at"),
            }
        })
        .collect();
    Ok(no_store(StatusCode::OK, &SessionListResponse { sessions }))
}

async fn revoke_session(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let actor = authenticate(&state, &headers)
        .await
        .map_err(ApiError::from)?;
    let result = sqlx::query(
        "UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, now()) WHERE id::text = $1 AND user_id::text = $2 AND revoked_at IS NULL",
    )
    .bind(&session_id)
    .bind(&actor.user_id)
    .execute(state.auth().pool()?)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    if result.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    audit_all_organizations(
        state.auth().pool()?,
        &actor.user_id,
        "session.revoked",
        "session",
        &session_id,
        "succeeded",
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn session_view(
    pool: &PgPool,
    user_id: &str,
    session_id: &str,
    current_id: &str,
) -> Result<SessionView, ApiError> {
    let row = sqlx::query(
        "SELECT id::text AS id, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_seen_at, to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at FROM auth_sessions WHERE id::text = $1 AND user_id::text = $2 AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ApiError::Unavailable)?
    .ok_or(ApiError::NotFound)?;
    let id: String = row.get("id");
    Ok(SessionView {
        current: id == current_id,
        id,
        created_at: row.get("created_at"),
        last_seen_at: row.get("last_seen_at"),
        expires_at: row.get("expires_at"),
    })
}

async fn user_view(pool: &PgPool, user_id: &str) -> Result<UserView, ApiError> {
    let row =
        sqlx::query("SELECT id::text AS id, lower(email) AS email FROM users WHERE id::text = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| ApiError::Unavailable)?
            .ok_or(ApiError::NotFound)?;
    Ok(UserView {
        id: row.get("id"),
        email: row.get("email"),
    })
}

async fn memberships(pool: &PgPool, user_id: &str) -> Result<Vec<MembershipView>, ApiError> {
    let rows = sqlx::query(
        "SELECT o.id::text AS organization_id, o.name AS organization_name, o.slug AS organization_slug, m.role FROM organization_memberships m JOIN organizations o ON o.id = m.organization_id WHERE m.user_id::text = $1 ORDER BY o.name, o.id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    rows.into_iter()
        .map(|row| {
            let role = Role::parse(&row.get::<String, _>("role")).ok_or(ApiError::Unavailable)?;
            Ok(MembershipView {
                organization_id: row.get("organization_id"),
                organization_name: row.get("organization_name"),
                organization_slug: row.get("organization_slug"),
                role,
            })
        })
        .collect()
}

#[derive(Serialize)]
struct MemberListResponse {
    members: Vec<MemberView>,
    invitations: Vec<InvitationView>,
}

#[derive(Serialize)]
struct MemberView {
    user_id: String,
    email: String,
    role: Role,
    joined_at: String,
}

#[derive(Serialize)]
struct InvitationView {
    id: String,
    email: String,
    role: Role,
    expires_at: String,
    created_at: String,
}

async fn list_members(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
) -> Result<Response, ApiError> {
    let caller =
        authorize_organization(&state, &headers, &organization_id, Permission::ReadProject)
            .await
            .map_err(ApiError::from)?;
    let pool = state.auth().pool()?;
    let rows = sqlx::query(
        "SELECT u.id::text AS user_id, lower(u.email) AS email, m.role, to_char(m.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS joined_at FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id::text = $1 ORDER BY lower(u.email), u.id",
    )
    .bind(&organization_id)
    .fetch_all(pool)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    let members = rows
        .into_iter()
        .map(|row| {
            Ok(MemberView {
                user_id: row.get("user_id"),
                email: row.get("email"),
                role: Role::parse(&row.get::<String, _>("role")).ok_or(ApiError::Unavailable)?,
                joined_at: row.get("joined_at"),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let invitations = if caller.role.allows(Permission::ManageMembers) {
        let rows = sqlx::query(
            "SELECT id::text AS id, lower(email) AS email, role, to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at FROM organization_invitations WHERE organization_id::text = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at, id",
        )
        .bind(&organization_id)
        .fetch_all(pool)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        rows.into_iter()
            .map(|row| {
                Ok(InvitationView {
                    id: row.get("id"),
                    email: row.get("email"),
                    role: Role::parse(&row.get::<String, _>("role"))
                        .ok_or(ApiError::Unavailable)?,
                    expires_at: row.get("expires_at"),
                    created_at: row.get("created_at"),
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?
    } else {
        Vec::new()
    };
    Ok(no_store(
        StatusCode::OK,
        &MemberListResponse {
            members,
            invitations,
        },
    ))
}

#[derive(Deserialize)]
struct InvitationRequest {
    email: String,
    role: Role,
}

async fn create_invitation(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    payload: Result<Json<InvitationRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let caller = authorize_organization(
        &state,
        &headers,
        &organization_id,
        Permission::ManageMembers,
    )
    .await
    .map_err(ApiError::from)?;
    let Json(request) = payload.map_err(|_| ApiError::InvalidRequest)?;
    if caller.role == Role::Admin && matches!(request.role, Role::Owner | Role::Admin) {
        return Err(ApiError::Forbidden);
    }
    let email = normalize_email(&request.email)?;
    let delivery = state.auth().email.as_ref().ok_or(ApiError::NotFound)?;
    let token = generated_secret(INVITATION_TOKEN_PREFIX)?;
    let row = sqlx::query(
        "INSERT INTO organization_invitations (organization_id, email, role, secret_hash, invited_by_user_id, expires_at) SELECT $1::uuid, $2, $3, $4, $5::uuid, now() + interval '7 days' WHERE NOT EXISTS (SELECT 1 FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id::text = $1 AND lower(u.email) = $2) RETURNING id::text AS id, to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at",
    )
    .bind(&organization_id)
    .bind(&email)
    .bind(request.role.as_str())
    .bind(hash(&token))
    .bind(&caller.actor.user_id)
    .fetch_optional(state.auth().pool()?)
    .await
    .map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
        {
            ApiError::Conflict
        } else {
            ApiError::Unavailable
        }
    })?
    .ok_or(ApiError::Conflict)?;
    let invitation = InvitationView {
        id: row.get("id"),
        email: email.clone(),
        role: request.role,
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
    };
    let invitation_url = format!(
        "{}/invitations/accept?token={token}",
        state.auth().web_base_url
    );
    let delivered = state
        .auth()
        .client
        .post(&delivery.delivery_url)
        .bearer_auth(&delivery.delivery_token)
        .json(&EmailDeliveryRequest {
            to: &email,
            sign_in_url: &invitation_url,
        })
        .send()
        .await
        .is_ok_and(|response| response.status().is_success());
    if !delivered {
        let _ = sqlx::query(
            "UPDATE organization_invitations SET revoked_at = now() WHERE id::text = $1",
        )
        .bind(&invitation.id)
        .execute(state.auth().pool()?)
        .await;
        audit(
            state.auth().pool()?,
            &organization_id,
            Some(&caller.actor.user_id),
            "invitation.created",
            "invitation",
            &invitation.id,
            "failed",
        )
        .await;
        return Err(ApiError::Unavailable);
    }
    audit(
        state.auth().pool()?,
        &organization_id,
        Some(&caller.actor.user_id),
        "invitation.created",
        "invitation",
        &invitation.id,
        "succeeded",
    )
    .await;
    Ok(no_store(StatusCode::CREATED, &invitation))
}

async fn revoke_invitation(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((organization_id, invitation_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let caller = authorize_organization(
        &state,
        &headers,
        &organization_id,
        Permission::ManageMembers,
    )
    .await
    .map_err(ApiError::from)?;
    let result = sqlx::query(
        "UPDATE organization_invitations SET revoked_at = COALESCE(revoked_at, now()) WHERE organization_id::text = $1 AND id::text = $2 AND accepted_at IS NULL",
    )
    .bind(&organization_id)
    .bind(&invitation_id)
    .execute(state.auth().pool()?)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    if result.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    audit(
        state.auth().pool()?,
        &organization_id,
        Some(&caller.actor.user_id),
        "invitation.revoked",
        "invitation",
        &invitation_id,
        "succeeded",
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn accept_invitation(
    State(state): State<ServerState>,
    payload: Result<Json<SecretRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = payload.map_err(|_| ApiError::InvalidRequest)?;
    if !valid_secret(&request.token, INVITATION_TOKEN_PREFIX) {
        return Err(ApiError::InvalidRequest);
    }
    let pool = state.auth().pool()?;
    let session_token = generated_secret(SESSION_PREFIX)?;
    let mut transaction = pool.begin().await.map_err(|_| ApiError::Unavailable)?;
    let row = sqlx::query(
        "SELECT id::text AS id, organization_id::text AS organization_id, lower(email) AS email, role FROM organization_invitations WHERE secret_hash = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now() FOR UPDATE",
    )
    .bind(hash(&request.token))
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?
    .ok_or(ApiError::NotFound)?;
    let email: String = row.get("email");
    let invitation_id: String = row.get("id");
    let organization_id: String = row.get("organization_id");
    let role: String = row.get("role");
    let (user_id, session) =
        insert_identity_session(&mut transaction, "email", &email, &email, &session_token).await?;
    sqlx::query(
        "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, $3) ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role",
    )
    .bind(&organization_id)
    .bind(&user_id)
    .bind(&role)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    sqlx::query("UPDATE organization_invitations SET accepted_at = now() WHERE id::text = $1")
        .bind(&invitation_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    sqlx::query(
        "INSERT INTO audit_log (organization_id, actor_user_id, action, target_type, target_id, result) VALUES ($1::uuid, $2::uuid, 'invitation.accepted', 'invitation', $3, 'succeeded')",
    )
    .bind(&organization_id)
    .bind(&user_id)
    .bind(&invitation_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let response = SessionCreated {
        token: session_token,
        session,
        user: user_view(pool, &user_id).await?,
        memberships: memberships(pool, &user_id).await?,
    };
    Ok(no_store(StatusCode::OK, &response))
}

#[derive(Deserialize)]
struct UpdateMemberRequest {
    role: Role,
}

async fn update_member(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((organization_id, user_id)): Path<(String, String)>,
    payload: Result<Json<UpdateMemberRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let caller = authorize_organization(
        &state,
        &headers,
        &organization_id,
        Permission::ManageMembers,
    )
    .await
    .map_err(ApiError::from)?;
    let Json(request) = payload.map_err(|_| ApiError::InvalidRequest)?;
    let mut transaction = state
        .auth()
        .pool()?
        .begin()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    lock_organization(&mut transaction, &organization_id).await?;
    let caller_role =
        member_role(&mut transaction, &organization_id, &caller.actor.user_id).await?;
    if !caller_role.allows(Permission::ManageMembers) {
        return Err(ApiError::Forbidden);
    }
    let target = member_role(&mut transaction, &organization_id, &user_id).await?;
    if caller_role == Role::Admin
        && (matches!(target, Role::Owner | Role::Admin)
            || matches!(request.role, Role::Owner | Role::Admin))
    {
        return Err(ApiError::Forbidden);
    }
    if target == Role::Owner && request.role != Role::Owner {
        require_another_owner(&mut transaction, &organization_id, &user_id).await?;
    }
    let result = sqlx::query(
        "UPDATE organization_memberships SET role = $3 WHERE organization_id::text = $1 AND user_id::text = $2",
    )
    .bind(&organization_id)
    .bind(&user_id)
    .bind(request.role.as_str())
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    if result.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    insert_audit(
        &mut transaction,
        &organization_id,
        Some(&caller.actor.user_id),
        "membership.role_changed",
        "user",
        &user_id,
        "succeeded",
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let member = member_view(state.auth().pool()?, &organization_id, &user_id).await?;
    Ok(no_store(StatusCode::OK, &member))
}

async fn remove_member(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((organization_id, user_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let caller = authorize_organization(
        &state,
        &headers,
        &organization_id,
        Permission::ManageMembers,
    )
    .await
    .map_err(ApiError::from)?;
    let mut transaction = state
        .auth()
        .pool()?
        .begin()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    lock_organization(&mut transaction, &organization_id).await?;
    let caller_role =
        member_role(&mut transaction, &organization_id, &caller.actor.user_id).await?;
    if !caller_role.allows(Permission::ManageMembers) {
        return Err(ApiError::Forbidden);
    }
    let target = member_role(&mut transaction, &organization_id, &user_id).await?;
    if caller_role == Role::Admin && matches!(target, Role::Owner | Role::Admin) {
        return Err(ApiError::Forbidden);
    }
    if target == Role::Owner {
        require_another_owner(&mut transaction, &organization_id, &user_id).await?;
    }
    let result = sqlx::query(
        "DELETE FROM organization_memberships WHERE organization_id::text = $1 AND user_id::text = $2",
    )
    .bind(&organization_id)
    .bind(&user_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    if result.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    insert_audit(
        &mut transaction,
        &organization_id,
        Some(&caller.actor.user_id),
        "membership.removed",
        "user",
        &user_id,
        "succeeded",
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn lock_organization(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(organization_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(())
}

async fn member_role(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    user_id: &str,
) -> Result<Role, ApiError> {
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM organization_memberships WHERE organization_id::text = $1 AND user_id::text = $2",
    )
    .bind(organization_id)
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?
    .ok_or(ApiError::NotFound)?;
    Role::parse(&role).ok_or(ApiError::Unavailable)
}

async fn require_another_owner(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    user_id: &str,
) -> Result<(), ApiError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM organization_memberships WHERE organization_id::text = $1 AND user_id::text <> $2 AND role = 'owner'",
    )
    .bind(organization_id)
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    if count == 0 {
        Err(ApiError::Conflict)
    } else {
        Ok(())
    }
}

async fn member_view(
    pool: &PgPool,
    organization_id: &str,
    user_id: &str,
) -> Result<MemberView, ApiError> {
    let row = sqlx::query(
        "SELECT u.id::text AS user_id, lower(u.email) AS email, m.role, to_char(m.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS joined_at FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id::text = $1 AND u.id::text = $2",
    )
    .bind(organization_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ApiError::Unavailable)?
    .ok_or(ApiError::NotFound)?;
    Ok(MemberView {
        user_id: row.get("user_id"),
        email: row.get("email"),
        role: Role::parse(&row.get::<String, _>("role")).ok_or(ApiError::Unavailable)?,
        joined_at: row.get("joined_at"),
    })
}

#[derive(Serialize)]
struct AuditListResponse {
    items: Vec<AuditView>,
}

#[derive(Serialize)]
struct AuditView {
    id: String,
    actor_user_id: Option<String>,
    action: String,
    target_type: String,
    target_id: String,
    result: String,
    occurred_at: String,
}

async fn list_audit(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
) -> Result<Response, ApiError> {
    authorize_organization(&state, &headers, &organization_id, Permission::ReadAudit)
        .await
        .map_err(ApiError::from)?;
    let rows = sqlx::query(
        "SELECT id::text AS id, actor_user_id::text AS actor_user_id, action, target_type, target_id, result, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS occurred_at FROM audit_log WHERE organization_id::text = $1 ORDER BY occurred_at DESC, id DESC LIMIT $2",
    )
    .bind(&organization_id)
    .bind(MAX_AUDIT_RESULTS)
    .fetch_all(state.auth().pool()?)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    let items = rows
        .into_iter()
        .map(|row| AuditView {
            id: row.get("id"),
            actor_user_id: row.get("actor_user_id"),
            action: row.get("action"),
            target_type: row.get("target_type"),
            target_id: row.get("target_id"),
            result: row.get("result"),
            occurred_at: row.get("occurred_at"),
        })
        .collect();
    Ok(no_store(StatusCode::OK, &AuditListResponse { items }))
}

pub(crate) async fn audit(
    pool: &PgPool,
    organization_id: &str,
    actor_user_id: Option<&str>,
    action: &str,
    target_type: &str,
    target_id: &str,
    result: &str,
) {
    let _ = sqlx::query(
        "INSERT INTO audit_log (organization_id, actor_user_id, action, target_type, target_id, result) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)",
    )
    .bind(organization_id)
    .bind(actor_user_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(result)
    .execute(pool)
    .await;
}

async fn insert_audit(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    actor_user_id: Option<&str>,
    action: &str,
    target_type: &str,
    target_id: &str,
    result: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit_log (organization_id, actor_user_id, action, target_type, target_id, result) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)",
    )
    .bind(organization_id)
    .bind(actor_user_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(result)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::Unavailable)?;
    Ok(())
}

async fn audit_all_organizations(
    pool: &PgPool,
    user_id: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    result: &str,
) {
    let _ = sqlx::query(
        "INSERT INTO audit_log (organization_id, actor_user_id, action, target_type, target_id, result) SELECT organization_id, user_id, $2, $3, $4, $5 FROM organization_memberships WHERE user_id::text = $1",
    )
    .bind(user_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(result)
    .execute(pool)
    .await;
}

fn generated_secret(prefix: &str) -> Result<String, ApiError> {
    let mut random = [0_u8; LOGIN_TOKEN_BYTES];
    getrandom::fill(&mut random).map_err(|_| ApiError::Internal)?;
    let mut value = String::with_capacity(prefix.len() + LOGIN_TOKEN_BYTES * 2);
    value.push_str(prefix);
    for byte in random {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    random.fill(0);
    Ok(value)
}

fn valid_secret(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + LOGIN_TOKEN_BYTES * 2
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn hash(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

fn normalize_email(value: &str) -> Result<String, ApiError> {
    let value = value.trim().to_ascii_lowercase();
    if valid_email(&value) {
        Ok(value)
    } else {
        Err(ApiError::InvalidRequest)
    }
}

fn valid_email(value: &str) -> bool {
    value.len() <= MAX_EMAIL_BYTES
        && !value.chars().any(char::is_whitespace)
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
        })
}

fn nonempty_environment(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn validate_web_base_url(value: &str, host: &str) -> Result<String, StartupError> {
    let url = Url::parse(value).map_err(|_| StartupError::AuthenticationConfiguration)?;
    let api_loopback = IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    let web_loopback = url
        .host_str()
        .and_then(|host| IpAddr::from_str(host).ok())
        .is_some_and(|address| address.is_loopback());
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "https" && !(api_loopback && web_loopback))
    {
        return Err(StartupError::AuthenticationConfiguration);
    }
    Ok(value.trim_end_matches('/').to_owned())
}

fn validate_delivery_url(value: &str, host: &str) -> Result<(), StartupError> {
    let url = Url::parse(value).map_err(|_| StartupError::AuthenticationConfiguration)?;
    let api_loopback = IpAddr::from_str(host).is_ok_and(|address| address.is_loopback());
    let delivery_loopback = url
        .host_str()
        .and_then(|host| IpAddr::from_str(host).ok())
        .is_some_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(api_loopback && delivery_loopback && url.scheme() == "http") {
        return Err(StartupError::AuthenticationConfiguration);
    }
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return Err(StartupError::AuthenticationConfiguration);
    }
    Ok(())
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
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
    Internal,
}

impl From<AuthorizationError> for ApiError {
    fn from(error: AuthorizationError) -> Self {
        match error {
            AuthorizationError::Unauthorized => Self::Unauthorized,
            AuthorizationError::Forbidden => Self::Forbidden,
            AuthorizationError::NotFound => Self::NotFound,
            AuthorizationError::Unavailable => Self::Unavailable,
        }
    }
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
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "operation is not allowed",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "resource was not found"),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "conflict",
                "request conflicts with current state",
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
        let mut response = (status, Json(ErrorBody { code, message })).into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        response
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        extract::State,
        http::{HeaderMap, Request, StatusCode},
        routing::{get, post},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use url::Url;

    use super::{
        EMAIL_TOKEN_PREFIX, Permission, Role, SESSION_PREFIX, authorize_project, generated_secret,
        normalize_email, valid_secret, validate_web_base_url,
    };
    use crate::project_setup::{DATABASE_TEST_LOCK, ServerState, migrate, router};

    const BOOTSTRAP_SECRET: &str = "hosted-auth-test-secret-with-32-bytes";

    #[derive(Clone, Default)]
    struct ProviderState {
        deliveries: Arc<Mutex<Vec<String>>>,
    }

    async fn deliver(
        State(state): State<ProviderState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> StatusCode {
        if headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            != Some("Bearer test-delivery-secret")
        {
            return StatusCode::UNAUTHORIZED;
        }
        let Some(url) = body.get("sign_in_url").and_then(Value::as_str) else {
            return StatusCode::BAD_REQUEST;
        };
        state
            .deliveries
            .lock()
            .unwrap_or_else(|error| panic!("delivery capture must lock: {error}"))
            .push(url.to_owned());
        StatusCode::ACCEPTED
    }

    async fn provider() -> (String, ProviderState) {
        let state = ProviderState::default();
        let app = Router::new()
            .route("/deliver", post(deliver))
            .route(
                "/login/oauth/access_token",
                post(|| async { Json(json!({"access_token": "github-test-token"})) }),
            )
            .route(
                "/user",
                get(|| async { Json(json!({"id": 42, "email": null})) }),
            )
            .route(
                "/user/emails",
                get(|| async {
                    Json(json!([{
                        "email": "owner@example.com",
                        "primary": true,
                        "verified": true
                    }]))
                }),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("provider listener must bind: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("provider address must exist: {error}"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{address}"), state)
    }

    async fn api_request(
        state: &ServerState,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        body: Option<Value>,
    ) -> axum::response::Response {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(authorization) = authorization {
            request = request.header("authorization", authorization);
        }
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

    async fn response_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap_or_else(|error| panic!("response body must load: {error}"));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("response must be JSON: {error}"))
    }

    fn delivered_token(provider: &ProviderState) -> String {
        let url = provider
            .deliveries
            .lock()
            .unwrap_or_else(|error| panic!("delivery capture must lock: {error}"))
            .last()
            .cloned()
            .unwrap_or_else(|| panic!("a delivery must be captured"));
        Url::parse(&url)
            .unwrap_or_else(|error| panic!("delivered URL must parse: {error}"))
            .query_pairs()
            .find_map(|(name, value)| (name == "token").then(|| value.into_owned()))
            .unwrap_or_else(|| panic!("delivered URL must contain a token"))
    }

    async fn email_session(state: &ServerState, provider: &ProviderState, email: &str) -> Value {
        let started = api_request(
            state,
            "POST",
            "/api/v1/auth/email/start",
            None,
            Some(json!({"email": email})),
        )
        .await;
        assert_eq!(started.status(), StatusCode::ACCEPTED);
        let token = delivered_token(provider);
        let verified = api_request(
            state,
            "POST",
            "/api/v1/auth/email/verify",
            None,
            Some(json!({"token": token})),
        )
        .await;
        assert_eq!(verified.status(), StatusCode::CREATED);
        response_json(verified).await
    }

    #[test]
    fn generated_secrets_are_fixed_and_typed() {
        let session = generated_secret(SESSION_PREFIX)
            .unwrap_or_else(|error| panic!("session secret must generate: {error:?}"));
        let email = generated_secret(EMAIL_TOKEN_PREFIX)
            .unwrap_or_else(|error| panic!("email secret must generate: {error:?}"));
        assert!(valid_secret(&session, SESSION_PREFIX));
        assert!(valid_secret(&email, EMAIL_TOKEN_PREFIX));
        assert_ne!(session, email);
    }

    #[test]
    fn emails_and_roles_are_bounded() {
        assert_eq!(
            normalize_email(" Owner@Example.COM ").ok().as_deref(),
            Some("owner@example.com")
        );
        assert!(normalize_email("not-an-email").is_err());
        assert_eq!(Role::parse("developer"), Some(Role::Developer));
        assert_eq!(Role::parse("unknown"), None);
    }

    #[test]
    fn roles_enforce_the_product_permission_matrix() {
        for role in [Role::Owner, Role::Admin, Role::Developer, Role::Viewer] {
            assert!(role.allows(Permission::ReadProject));
        }
        assert!(Role::Owner.allows(Permission::ManageProject));
        assert!(Role::Admin.allows(Permission::ManageProject));
        assert!(!Role::Developer.allows(Permission::ManageProject));
        assert!(!Role::Viewer.allows(Permission::ManageProject));
        assert!(Role::Developer.allows(Permission::ManageIssue));
        assert!(Role::Developer.allows(Permission::ReadRaw));
        assert!(!Role::Viewer.allows(Permission::ManageIssue));
        assert!(!Role::Viewer.allows(Permission::ReadRaw));
        assert!(Role::Owner.allows(Permission::ManageDataRules));
        assert!(!Role::Admin.allows(Permission::ManageDataRules));
        assert!(!Role::Developer.allows(Permission::ManageMembers));
        assert!(!Role::Viewer.allows(Permission::ReadAudit));
    }

    #[test]
    fn hosted_web_urls_require_https_outside_loopback() {
        assert!(validate_web_base_url("http://127.0.0.1:3000", "127.0.0.1").is_ok());
        assert!(validate_web_base_url("https://faultlane.example", "0.0.0.0").is_ok());
        assert!(validate_web_base_url("http://faultlane.example", "0.0.0.0").is_err());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn hosted_sign_in_roles_invitations_sessions_and_audit_work_when_configured() {
        let Ok(database_url) = std::env::var("FAULTLANE_TEST_DATABASE_URL") else {
            return;
        };
        let _guard = DATABASE_TEST_LOCK.lock().await;
        let database_name = database_url
            .rsplit('/')
            .next()
            .and_then(|value| value.split('?').next())
            .unwrap_or_default();
        assert!(database_name == "faultlane_test" || database_name.starts_with("faultlane_"));
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test migrations must run: {error}"));
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations, auth_login_attempts CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let (provider_url, provider_state) = provider().await;
        let state = ServerState::hosted_auth_test(pool.clone(), BOOTSTRAP_SECRET, &provider_url);

        let setup = api_request(
            &state,
            "POST",
            "/api/v1/setup",
            Some(&format!("Bootstrap {BOOTSTRAP_SECRET}")),
            Some(json!({
                "owner_email": "owner@example.com",
                "organization_name": "Example Studio",
                "organization_slug": "example-studio",
                "project_name": "Windows Game",
                "project_slug": "windows-game"
            })),
        )
        .await;
        assert_eq!(setup.status(), StatusCode::CREATED);
        let setup = response_json(setup).await;
        let organization_id = setup["setup"]["organization"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("organization id must exist"))
            .to_owned();
        let project_id = setup["setup"]["project"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("project id must exist"))
            .to_owned();

        let owner = email_session(&state, &provider_state, "owner@example.com").await;
        let owner_token = owner["token"]
            .as_str()
            .unwrap_or_else(|| panic!("owner token must exist"))
            .to_owned();
        let owner_user_id = owner["user"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("owner id must exist"))
            .to_owned();
        assert_eq!(owner["memberships"][0]["role"], "owner");
        let last_owner = api_request(
            &state,
            "DELETE",
            &format!("/api/v1/organizations/{organization_id}/members/{owner_user_id}"),
            Some(&format!("Session {owner_token}")),
            None,
        )
        .await;
        assert_eq!(last_owner.status(), StatusCode::CONFLICT);

        for _ in 0..4 {
            let started = api_request(
                &state,
                "POST",
                "/api/v1/auth/email/start",
                None,
                Some(json!({"email": "owner@example.com"})),
            )
            .await;
            assert_eq!(started.status(), StatusCode::ACCEPTED);
        }
        let deliveries = provider_state
            .deliveries
            .lock()
            .unwrap_or_else(|error| panic!("delivery capture must lock: {error}"))
            .len();
        let throttled = api_request(
            &state,
            "POST",
            "/api/v1/auth/email/start",
            None,
            Some(json!({"email": "owner@example.com"})),
        )
        .await;
        assert_eq!(throttled.status(), StatusCode::ACCEPTED);
        assert_eq!(
            provider_state
                .deliveries
                .lock()
                .unwrap_or_else(|error| panic!("delivery capture must lock: {error}"))
                .len(),
            deliveries
        );

        let github_start =
            api_request(&state, "POST", "/api/v1/auth/github/start", None, None).await;
        assert_eq!(github_start.status(), StatusCode::OK);
        let github_start = response_json(github_start).await;
        let state_token = Url::parse(
            github_start["authorization_url"]
                .as_str()
                .unwrap_or_else(|| panic!("GitHub URL must exist")),
        )
        .unwrap_or_else(|error| panic!("GitHub URL must parse: {error}"))
        .query_pairs()
        .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
        .unwrap_or_else(|| panic!("GitHub state must exist"));
        let github = api_request(
            &state,
            "POST",
            "/api/v1/auth/github/callback",
            None,
            Some(json!({"code": "test-code", "state": state_token})),
        )
        .await;
        assert_eq!(github.status(), StatusCode::CREATED);
        let github = response_json(github).await;
        assert_eq!(github["user"]["id"], owner_user_id);
        let github_token = github["token"]
            .as_str()
            .unwrap_or_else(|| panic!("GitHub token must exist"))
            .to_owned();
        let github_session_id = github["session"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("GitHub session id must exist"))
            .to_owned();

        let invitation = api_request(
            &state,
            "POST",
            &format!("/api/v1/organizations/{organization_id}/invitations"),
            Some(&format!("Session {owner_token}")),
            Some(json!({"email": "viewer@example.com", "role": "viewer"})),
        )
        .await;
        assert_eq!(invitation.status(), StatusCode::CREATED);
        let invitation_token = delivered_token(&provider_state);
        let viewer = email_session(&state, &provider_state, "viewer@example.com").await;
        let viewer_token = viewer["token"]
            .as_str()
            .unwrap_or_else(|| panic!("viewer token must exist"))
            .to_owned();
        let viewer_user_id = viewer["user"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("viewer id must exist"))
            .to_owned();
        let accepted = api_request(
            &state,
            "POST",
            "/api/v1/invitations/accept",
            Some(&format!("Session {viewer_token}")),
            Some(json!({"token": invitation_token})),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);

        let pending = api_request(
            &state,
            "POST",
            &format!("/api/v1/organizations/{organization_id}/invitations"),
            Some(&format!("Session {owner_token}")),
            Some(json!({"email": "pending@example.com", "role": "developer"})),
        )
        .await;
        assert_eq!(pending.status(), StatusCode::CREATED);
        let viewer_members = api_request(
            &state,
            "GET",
            &format!("/api/v1/organizations/{organization_id}/members"),
            Some(&format!("Session {viewer_token}")),
            None,
        )
        .await;
        assert_eq!(viewer_members.status(), StatusCode::OK);
        assert_eq!(
            response_json(viewer_members).await["invitations"],
            json!([])
        );
        let owner_members = api_request(
            &state,
            "GET",
            &format!("/api/v1/organizations/{organization_id}/members"),
            Some(&format!("Session {owner_token}")),
            None,
        )
        .await;
        assert_eq!(owner_members.status(), StatusCode::OK);
        assert_eq!(
            response_json(owner_members).await["invitations"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );

        let admin_invitation = api_request(
            &state,
            "POST",
            &format!("/api/v1/organizations/{organization_id}/invitations"),
            Some(&format!("Session {owner_token}")),
            Some(json!({"email": "admin@example.com", "role": "admin"})),
        )
        .await;
        assert_eq!(admin_invitation.status(), StatusCode::CREATED);
        let admin_invitation_token = delivered_token(&provider_state);
        let admin = api_request(
            &state,
            "POST",
            "/api/v1/invitations/accept",
            None,
            Some(json!({"token": admin_invitation_token})),
        )
        .await;
        assert_eq!(admin.status(), StatusCode::OK);
        let admin = response_json(admin).await;
        assert_eq!(admin["memberships"][0]["role"], "admin");
        let admin_token = admin["token"]
            .as_str()
            .unwrap_or_else(|| panic!("admin token must exist"));
        let admin_read = api_request(
            &state,
            "GET",
            &format!("/api/v1/projects/{project_id}/setup"),
            Some(&format!("Session {admin_token}")),
            None,
        )
        .await;
        assert_eq!(admin_read.status(), StatusCode::OK);
        let admin_cannot_change_owner = api_request(
            &state,
            "PATCH",
            &format!("/api/v1/organizations/{organization_id}/members/{owner_user_id}"),
            Some(&format!("Session {admin_token}")),
            Some(json!({"role": "viewer"})),
        )
        .await;
        assert_eq!(admin_cannot_change_owner.status(), StatusCode::FORBIDDEN);
        let admin_can_invite_developer = api_request(
            &state,
            "POST",
            &format!("/api/v1/organizations/{organization_id}/invitations"),
            Some(&format!("Session {admin_token}")),
            Some(json!({"email": "developer@example.com", "role": "developer"})),
        )
        .await;
        assert_eq!(admin_can_invite_developer.status(), StatusCode::CREATED);

        let visible = api_request(
            &state,
            "GET",
            &format!("/api/v1/projects/{project_id}/setup"),
            Some(&format!("Session {viewer_token}")),
            None,
        )
        .await;
        assert_eq!(visible.status(), StatusCode::OK);
        let denied = api_request(
            &state,
            "POST",
            &format!("/api/v1/projects/{project_id}/ingest-keys"),
            Some(&format!("Session {viewer_token}")),
            None,
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let role_changed = api_request(
            &state,
            "PATCH",
            &format!("/api/v1/organizations/{organization_id}/members/{viewer_user_id}"),
            Some(&format!("Session {owner_token}")),
            Some(json!({"role": "developer"})),
        )
        .await;
        assert_eq!(role_changed.status(), StatusCode::OK);
        let developer_headers = HeaderMap::from_iter([(
            "authorization"
                .parse()
                .unwrap_or_else(|error| panic!("header name must parse: {error}")),
            format!("Session {viewer_token}")
                .parse()
                .unwrap_or_else(|error| panic!("header value must parse: {error}")),
        )]);
        assert!(
            authorize_project(
                &state,
                &developer_headers,
                &project_id,
                Permission::ManageIssue
            )
            .await
            .is_ok()
        );
        assert!(
            authorize_project(
                &state,
                &developer_headers,
                &project_id,
                Permission::ManageProject
            )
            .await
            .is_err()
        );

        let outside_organization: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Outside', 'outside') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("outside organization must insert: {error}"));
        let outside_project: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Outside', 'outside') RETURNING id::text",
        )
        .bind(outside_organization)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("outside project must insert: {error}"));
        let hidden = api_request(
            &state,
            "GET",
            &format!("/api/v1/projects/{outside_project}/setup"),
            Some(&format!("Session {viewer_token}")),
            None,
        )
        .await;
        assert_eq!(hidden.status(), StatusCode::NOT_FOUND);

        let audit = api_request(
            &state,
            "GET",
            &format!("/api/v1/organizations/{organization_id}/audit"),
            Some(&format!("Session {owner_token}")),
            None,
        )
        .await;
        assert_eq!(audit.status(), StatusCode::OK);
        let audit = response_json(audit).await;
        let actions = audit["items"]
            .as_array()
            .unwrap_or_else(|| panic!("audit items must exist"))
            .iter()
            .filter_map(|item| item["action"].as_str())
            .collect::<Vec<_>>();
        assert!(actions.contains(&"invitation.created"));
        assert!(actions.contains(&"invitation.accepted"));
        assert!(actions.contains(&"membership.role_changed"));

        let revoked = api_request(
            &state,
            "DELETE",
            &format!("/api/v1/auth/sessions/{github_session_id}"),
            Some(&format!("Session {owner_token}")),
            None,
        )
        .await;
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        let rejected = api_request(
            &state,
            "GET",
            "/api/v1/auth/session",
            Some(&format!("Session {github_token}")),
            None,
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

        let removed = api_request(
            &state,
            "DELETE",
            &format!("/api/v1/organizations/{organization_id}/members/{viewer_user_id}"),
            Some(&format!("Session {owner_token}")),
            None,
        )
        .await;
        assert_eq!(removed.status(), StatusCode::NO_CONTENT);
        let no_longer_visible = api_request(
            &state,
            "GET",
            &format!("/api/v1/projects/{project_id}/setup"),
            Some(&format!("Session {viewer_token}")),
            None,
        )
        .await;
        assert_eq!(no_longer_visible.status(), StatusCode::NOT_FOUND);

        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE organization_id::text = $1 AND actor_user_id::text = $2",
        )
        .bind(&organization_id)
        .bind(&owner_user_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("audit count must load: {error}"));
        assert!(audit_count >= 3);
    }
}
