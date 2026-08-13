use std::{
    collections::BTreeMap,
    env, fmt,
    net::IpAddr,
    path::{Path as FilePath, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(test)]
use std::{collections::HashMap, sync::Mutex};

use aws_sdk_s3::{
    config::{Credentials, Region, RequestChecksumCalculation},
    presigning::PresigningConfig,
    types::{CompletedMultipartUpload, CompletedPart},
};
use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use cachelane_symbols::{
    Architecture, ArtifactScanLimits, ArtifactType, scan_artifacts_with_limits,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{fs, io::AsyncWriteExt};
use url::Url;

use crate::project_setup::{ServerState, StartupError};

const TOKEN_PREFIX: &str = "clsu_";
const TOKEN_BYTES: usize = 32;
const DISPLAY_SUFFIX_BYTES: usize = 8;
const MAX_ARTIFACTS: usize = 512;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const PART_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PARTS: u64 = 10_000;
const PRESIGN_SECONDS: u64 = 10 * 60;
const STORAGE_SECONDS: u64 = 30;
const VERIFY_SECONDS: u64 = 15 * 60;
const MAX_TEXT_BYTES: usize = 256;

#[derive(Clone)]
pub(crate) struct SymbolUploads {
    pool: Option<PgPool>,
    objects: ArtifactObjects,
    spool_directory: Arc<PathBuf>,
    enabled: bool,
}

impl SymbolUploads {
    pub(crate) fn postgres(
        pool: PgPool,
        role: &'static str,
        host: &str,
    ) -> Result<Self, StartupError> {
        if role != "api"
            || !env::var("CACHELANE_SYMBOL_UPLOAD_ENABLED")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true"))
        {
            return Ok(Self::disabled());
        }
        if !valid_upload_host(host) {
            return Err(StartupError::SymbolUploadConfiguration);
        }

        let endpoint = required_env("OBJECT_STORE_ENDPOINT")?;
        let endpoint_url =
            Url::parse(&endpoint).map_err(|_| StartupError::SymbolUploadConfiguration)?;
        if endpoint_url.host_str().is_none()
            || !endpoint_url.username().is_empty()
            || endpoint_url.password().is_some()
            || endpoint_url.path() != "/"
            || endpoint_url.query().is_some()
            || endpoint_url.fragment().is_some()
            || (endpoint_url.scheme() != "https"
                && !(endpoint_url.scheme() == "http"
                    && endpoint_url
                        .host_str()
                        .and_then(|value| value.parse::<IpAddr>().ok())
                        .is_some_and(|address| address.is_loopback())))
        {
            return Err(StartupError::SymbolUploadConfiguration);
        }
        let bucket = required_env("OBJECT_STORE_BUCKET")?;
        let access_key =
            required_env("OBJECT_STORE_ACCESS_KEY").or_else(|_| required_env("MINIO_ROOT_USER"))?;
        let secret_key = required_env("OBJECT_STORE_SECRET_KEY")
            .or_else(|_| required_env("MINIO_ROOT_PASSWORD"))?;
        let region = env::var("OBJECT_STORE_REGION")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "auto".to_owned());
        let config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(Region::new(region))
            .credentials_provider(Credentials::new(
                access_key,
                secret_key,
                None,
                None,
                "cachelane-object-store",
            ))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .build();
        let spool_directory = env::var("CACHELANE_ARTIFACT_SPOOL_DIR").map_or_else(
            |_| env::temp_dir().join("cachelane-artifacts"),
            PathBuf::from,
        );
        validate_spool_directory(&spool_directory)?;

        Ok(Self {
            pool: Some(pool),
            objects: ArtifactObjects::S3 {
                client: aws_sdk_s3::Client::from_conf(config),
                bucket: Arc::from(bucket),
            },
            spool_directory: Arc::new(spool_directory),
            enabled: true,
        })
    }

    pub(crate) fn disabled() -> Self {
        Self {
            pool: None,
            objects: ArtifactObjects::Disabled,
            spool_directory: Arc::new(env::temp_dir().join("cachelane-artifacts-disabled")),
            enabled: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn test(pool: PgPool, spool_directory: PathBuf) -> Self {
        validate_spool_directory(&spool_directory)
            .unwrap_or_else(|error| panic!("test spool directory must be valid: {error}"));
        Self {
            pool: Some(pool),
            objects: ArtifactObjects::Memory(Arc::new(Mutex::new(MemoryObjects::default()))),
            spool_directory: Arc::new(spool_directory),
            enabled: true,
        }
    }

    #[cfg(test)]
    async fn test_put_part(
        &self,
        upload_id: &str,
        part_number: i32,
        bytes: Vec<u8>,
    ) -> Result<String, UploadError> {
        let row = sqlx::query(
            "SELECT object_key, provider_upload_id FROM artifact_upload_sessions WHERE id::text = $1",
        )
        .bind(upload_id)
        .fetch_one(self.pool()?)
        .await
        .map_err(|_| UploadError::Unavailable)?;
        let provider_upload_id: String = row.get("provider_upload_id");
        let object_key: String = row.get("object_key");
        let ArtifactObjects::Memory(objects) = &self.objects else {
            return Err(UploadError::Internal);
        };
        let mut objects = objects.lock().map_err(|_| UploadError::Internal)?;
        let upload = objects
            .uploads
            .get_mut(&provider_upload_id)
            .filter(|upload| upload.key == object_key)
            .ok_or(UploadError::NotFound)?;
        let etag = format!("\"{}\"", lower_hex(&md5::Md5::digest(&bytes)));
        upload.parts.insert(part_number, bytes);
        Ok(etag)
    }

    fn pool(&self) -> Result<&PgPool, UploadError> {
        if !self.enabled {
            return Err(UploadError::Unavailable);
        }
        self.pool.as_ref().ok_or(UploadError::Unavailable)
    }
}

#[derive(Clone)]
enum ArtifactObjects {
    S3 {
        client: aws_sdk_s3::Client,
        bucket: Arc<str>,
    },
    #[cfg(test)]
    Memory(Arc<Mutex<MemoryObjects>>),
    Disabled,
}

#[cfg(test)]
#[derive(Default)]
struct MemoryObjects {
    next_id: u64,
    uploads: HashMap<String, MemoryMultipart>,
    objects: HashMap<String, Vec<u8>>,
}

#[cfg(test)]
struct MemoryMultipart {
    key: String,
    parts: BTreeMap<i32, Vec<u8>>,
}

#[derive(Debug)]
enum ObjectError {
    Unavailable,
    Missing,
    Invalid,
}

#[derive(Clone)]
struct ProviderPart {
    number: i32,
    etag: String,
    byte_size: i64,
}

struct SignedPart {
    url: String,
    headers: BTreeMap<String, String>,
}

impl ArtifactObjects {
    async fn create_multipart(&self, key: &str) -> Result<String, ObjectError> {
        #[cfg(test)]
        if let Self::Memory(objects) = self {
            let mut objects = objects.lock().map_err(|_| ObjectError::Unavailable)?;
            objects.next_id = objects.next_id.saturating_add(1);
            let upload_id = format!("memory-upload-{}", objects.next_id);
            objects.uploads.insert(
                upload_id.clone(),
                MemoryMultipart {
                    key: key.to_owned(),
                    parts: BTreeMap::new(),
                },
            );
            return Ok(upload_id);
        }
        let Self::S3 { client, bucket } = self else {
            return Err(ObjectError::Unavailable);
        };
        let request = client
            .create_multipart_upload()
            .bucket(bucket.as_ref())
            .key(key)
            .content_type("application/octet-stream")
            .send();
        let output = tokio::time::timeout(Duration::from_secs(STORAGE_SECONDS), request)
            .await
            .map_err(|_| ObjectError::Unavailable)?
            .map_err(|_| ObjectError::Unavailable)?;
        output
            .upload_id()
            .map(ToOwned::to_owned)
            .ok_or(ObjectError::Unavailable)
    }

    async fn sign_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        byte_size: i64,
        content_md5: &str,
    ) -> Result<SignedPart, ObjectError> {
        #[cfg(test)]
        if matches!(self, Self::Memory(_)) {
            return Ok(SignedPart {
                url: format!("http://127.0.0.1/upload/{upload_id}/{part_number}"),
                headers: BTreeMap::from([
                    ("content-length".to_owned(), byte_size.to_string()),
                    ("content-md5".to_owned(), content_md5.to_owned()),
                ]),
            });
        }
        let Self::S3 { client, bucket } = self else {
            return Err(ObjectError::Unavailable);
        };
        let config = PresigningConfig::expires_in(Duration::from_secs(PRESIGN_SECONDS))
            .map_err(|_| ObjectError::Unavailable)?;
        let request = client
            .upload_part()
            .bucket(bucket.as_ref())
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .content_length(byte_size)
            .content_md5(content_md5)
            .presigned(config)
            .await
            .map_err(|_| ObjectError::Unavailable)?;
        let headers = request
            .headers()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
            .collect();
        Ok(SignedPart {
            url: request.uri().to_owned(),
            headers,
        })
    }

    async fn provider_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
    ) -> Result<Option<ProviderPart>, ObjectError> {
        #[cfg(test)]
        if let Self::Memory(objects) = self {
            let objects = objects.lock().map_err(|_| ObjectError::Unavailable)?;
            let part = objects
                .uploads
                .get(upload_id)
                .filter(|upload| upload.key == key)
                .and_then(|upload| upload.parts.get(&part_number));
            return Ok(part.map(|bytes| ProviderPart {
                number: part_number,
                etag: format!("\"{}\"", lower_hex(&md5::Md5::digest(bytes))),
                byte_size: i64::try_from(bytes.len()).unwrap_or(i64::MAX),
            }));
        }
        let Self::S3 { client, bucket } = self else {
            return Err(ObjectError::Unavailable);
        };
        let request = client
            .list_parts()
            .bucket(bucket.as_ref())
            .key(key)
            .upload_id(upload_id)
            .part_number_marker(part_number.saturating_sub(1).to_string())
            .max_parts(1)
            .send();
        let output = tokio::time::timeout(Duration::from_secs(STORAGE_SECONDS), request)
            .await
            .map_err(|_| ObjectError::Unavailable)?
            .map_err(|_| ObjectError::Unavailable)?;
        Ok(output.parts().iter().find_map(|part| {
            (part.part_number() == Some(part_number)).then(|| ProviderPart {
                number: part_number,
                etag: part.e_tag().unwrap_or_default().to_owned(),
                byte_size: part.size().unwrap_or_default(),
            })
        }))
    }

    async fn object_exists(&self, key: &str) -> Result<bool, ObjectError> {
        #[cfg(test)]
        if let Self::Memory(objects) = self {
            return objects
                .lock()
                .map(|objects| objects.objects.contains_key(key))
                .map_err(|_| ObjectError::Unavailable);
        }
        let Self::S3 { client, bucket } = self else {
            return Err(ObjectError::Unavailable);
        };
        let request = client.head_object().bucket(bucket.as_ref()).key(key).send();
        match tokio::time::timeout(Duration::from_secs(STORAGE_SECONDS), request).await {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(error))
                if error.as_service_error().is_some_and(
                    aws_sdk_s3::operation::head_object::HeadObjectError::is_not_found,
                ) =>
            {
                Ok(false)
            }
            _ => Err(ObjectError::Unavailable),
        }
    }

    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[ProviderPart],
    ) -> Result<(), ObjectError> {
        #[cfg(test)]
        if let Self::Memory(objects) = self {
            let mut objects = objects.lock().map_err(|_| ObjectError::Unavailable)?;
            let upload = objects
                .uploads
                .remove(upload_id)
                .filter(|upload| upload.key == key)
                .ok_or(ObjectError::Missing)?;
            let mut bytes = Vec::new();
            for part in parts {
                let value = upload.parts.get(&part.number).ok_or(ObjectError::Missing)?;
                if !same_etag(
                    &part.etag,
                    &format!("\"{}\"", lower_hex(&md5::Md5::digest(value))),
                ) {
                    return Err(ObjectError::Unavailable);
                }
                bytes.extend_from_slice(value);
            }
            objects.objects.insert(key.to_owned(), bytes);
            return Ok(());
        }
        let Self::S3 { client, bucket } = self else {
            return Err(ObjectError::Unavailable);
        };
        let completed = parts
            .iter()
            .map(|part| {
                CompletedPart::builder()
                    .part_number(part.number)
                    .e_tag(&part.etag)
                    .build()
            })
            .collect();
        let upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed))
            .build();
        let request = client
            .complete_multipart_upload()
            .bucket(bucket.as_ref())
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(upload)
            .send();
        tokio::time::timeout(Duration::from_secs(STORAGE_SECONDS), request)
            .await
            .map_err(|_| ObjectError::Unavailable)?
            .map_err(|_| ObjectError::Unavailable)?;
        Ok(())
    }

    async fn abort_multipart(&self, key: &str, upload_id: &str) {
        #[cfg(test)]
        if let Self::Memory(objects) = self {
            if let Ok(mut objects) = objects.lock()
                && objects
                    .uploads
                    .get(upload_id)
                    .is_some_and(|upload| upload.key == key)
            {
                objects.uploads.remove(upload_id);
            }
            return;
        }
        let Self::S3 { client, bucket } = self else {
            return;
        };
        let request = client
            .abort_multipart_upload()
            .bucket(bucket.as_ref())
            .key(key)
            .upload_id(upload_id)
            .send();
        let _ = tokio::time::timeout(Duration::from_secs(STORAGE_SECONDS), request).await;
    }

    async fn download_to(
        &self,
        key: &str,
        path: &FilePath,
        maximum_bytes: u64,
    ) -> Result<(u64, [u8; 32]), ObjectError> {
        #[cfg(test)]
        if let Self::Memory(objects) = self {
            let bytes = objects
                .lock()
                .map_err(|_| ObjectError::Unavailable)?
                .objects
                .get(key)
                .cloned()
                .ok_or(ObjectError::Missing)?;
            if u64::try_from(bytes.len()).map_err(|_| ObjectError::Invalid)? > maximum_bytes {
                return Err(ObjectError::Invalid);
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .await
                .map_err(|_| ObjectError::Unavailable)?;
            file.write_all(&bytes)
                .await
                .map_err(|_| ObjectError::Unavailable)?;
            file.sync_all()
                .await
                .map_err(|_| ObjectError::Unavailable)?;
            return Ok((
                u64::try_from(bytes.len()).map_err(|_| ObjectError::Unavailable)?,
                Sha256::digest(&bytes).into(),
            ));
        }
        let Self::S3 { client, bucket } = self else {
            return Err(ObjectError::Unavailable);
        };
        let request = client.get_object().bucket(bucket.as_ref()).key(key).send();
        let output = tokio::time::timeout(Duration::from_secs(STORAGE_SECONDS), request)
            .await
            .map_err(|_| ObjectError::Unavailable)?
            .map_err(|error| {
                if error
                    .as_service_error()
                    .is_some_and(aws_sdk_s3::operation::get_object::GetObjectError::is_no_such_key)
                {
                    ObjectError::Missing
                } else {
                    ObjectError::Unavailable
                }
            })?;
        let mut body = output.body;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await
            .map_err(|_| ObjectError::Unavailable)?;
        let download = async {
            let mut digest = Sha256::new();
            let mut size = 0_u64;
            while let Some(chunk) = body
                .try_next()
                .await
                .map_err(|_| ObjectError::Unavailable)?
            {
                size = size
                    .checked_add(chunk.len() as u64)
                    .ok_or(ObjectError::Invalid)?;
                if size > maximum_bytes {
                    return Err(ObjectError::Invalid);
                }
                digest.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .map_err(|_| ObjectError::Unavailable)?;
            }
            file.sync_all()
                .await
                .map_err(|_| ObjectError::Unavailable)?;
            Ok((size, digest.finalize().into()))
        };
        tokio::time::timeout(Duration::from_secs(VERIFY_SECONDS), download)
            .await
            .map_err(|_| ObjectError::Unavailable)?
    }

    async fn delete_object(&self, key: &str) {
        #[cfg(test)]
        if let Self::Memory(objects) = self {
            if let Ok(mut objects) = objects.lock() {
                objects.objects.remove(key);
            }
            return;
        }
        let Self::S3 { client, bucket } = self else {
            return;
        };
        let request = client
            .delete_object()
            .bucket(bucket.as_ref())
            .key(key)
            .send();
        let _ = tokio::time::timeout(Duration::from_secs(STORAGE_SECONDS), request).await;
    }
}

#[cfg(test)]
fn lower_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Debug)]
pub(crate) enum UploadError {
    Invalid,
    Unauthorized,
    NotFound,
    Conflict,
    Mismatch,
    Unavailable,
    Internal,
}

impl IntoResponse for UploadError {
    fn into_response(self) -> Response {
        let (status, code, message, retryable) = match self {
            Self::Invalid => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request is invalid",
                false,
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "artifact upload authorization is required",
                false,
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "resource was not found",
                false,
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "upload_conflict",
                "upload state changed",
                true,
            ),
            Self::Mismatch => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "artifact_mismatch",
                "uploaded artifact does not match its declared identity",
                false,
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "upload_unavailable",
                "artifact upload is temporarily unavailable",
                true,
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "request could not be completed",
                false,
            ),
        };
        no_store((
            status,
            Json(ErrorBody {
                code,
                message,
                retryable,
            }),
        ))
    }
}

#[derive(Serialize)]
struct CreatedToken {
    id: String,
    project_id: String,
    token: String,
    display_suffix: String,
    created_at: String,
}

pub(crate) async fn create_upload_token(
    State(state): State<ServerState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, UploadError> {
    if !state.authorize_control(&headers) {
        return Err(UploadError::Unauthorized);
    }
    let uploads = state.symbol_uploads();
    let secret = GeneratedSecret::new()?;
    let row = sqlx::query(
        "INSERT INTO artifact_upload_tokens (organization_id, project_id, created_by_user_id, secret_hash, display_suffix) SELECT p.organization_id, p.id, u.id, $2, $3 FROM projects p JOIN organization_memberships m ON m.organization_id = p.organization_id AND m.role = 'owner' JOIN users u ON u.id = m.user_id AND u.bootstrap_subject = 'local-bootstrap' WHERE p.id::text = $1 RETURNING id::text AS id, project_id::text AS project_id, created_at::text AS created_at",
    )
    .bind(&project_id)
    .bind(secret.digest.to_vec())
    .bind(&secret.suffix)
    .fetch_optional(uploads.pool()?)
    .await
    .map_err(|_| UploadError::Unavailable)?
    .ok_or(UploadError::NotFound)?;
    let response = Json(CreatedToken {
        id: row.get("id"),
        project_id: row.get("project_id"),
        token: secret.value,
        display_suffix: secret.suffix,
        created_at: row.get("created_at"),
    });
    Ok(no_store((StatusCode::CREATED, response)))
}

pub(crate) async fn revoke_upload_token(
    State(state): State<ServerState>,
    Path((project_id, token_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, UploadError> {
    if !state.authorize_control(&headers) {
        return Err(UploadError::Unauthorized);
    }
    let result = sqlx::query(
        "UPDATE artifact_upload_tokens t SET revoked_at = COALESCE(t.revoked_at, now()) FROM projects p JOIN organization_memberships m ON m.organization_id = p.organization_id AND m.role = 'owner' JOIN users u ON u.id = m.user_id AND u.bootstrap_subject = 'local-bootstrap' WHERE t.id::text = $2 AND t.project_id = p.id AND t.organization_id = p.organization_id AND p.id::text = $1",
    )
    .bind(project_id)
    .bind(token_id)
    .execute(state.symbol_uploads().pool()?)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    if result.rows_affected() == 0 {
        return Err(UploadError::NotFound);
    }
    Ok(no_store(StatusCode::NO_CONTENT))
}

#[derive(Clone)]
struct TokenScope {
    token_id: String,
    organization_id: String,
    project_id: String,
    project_slug: String,
    user_id: String,
}

async fn authorize_upload(
    uploads: &SymbolUploads,
    headers: &HeaderMap,
) -> Result<TokenScope, UploadError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| valid_token(value))
        .ok_or(UploadError::Unauthorized)?;
    let row = sqlx::query(
        "SELECT t.id::text AS token_id, t.organization_id::text AS organization_id, t.project_id::text AS project_id, p.slug AS project_slug, t.created_by_user_id::text AS user_id FROM artifact_upload_tokens t JOIN projects p ON p.id = t.project_id AND p.organization_id = t.organization_id WHERE t.secret_hash = $1 AND t.revoked_at IS NULL",
    )
    .bind(Sha256::digest(token.as_bytes()).to_vec())
    .fetch_optional(uploads.pool()?)
    .await
    .map_err(|_| UploadError::Unavailable)?
    .ok_or(UploadError::Unauthorized)?;
    Ok(TokenScope {
        token_id: row.get("token_id"),
        organization_id: row.get("organization_id"),
        project_id: row.get("project_id"),
        project_slug: row.get("project_slug"),
        user_id: row.get("user_id"),
    })
}

struct GeneratedSecret {
    value: String,
    digest: [u8; 32],
    suffix: String,
}

impl GeneratedSecret {
    fn new() -> Result<Self, UploadError> {
        let mut random = [0_u8; TOKEN_BYTES];
        getrandom::fill(&mut random).map_err(|_| UploadError::Internal)?;
        let mut value = String::with_capacity(TOKEN_PREFIX.len() + TOKEN_BYTES * 2);
        value.push_str(TOKEN_PREFIX);
        for byte in random {
            use fmt::Write as _;
            write!(&mut value, "{byte:02x}").map_err(|_| UploadError::Internal)?;
        }
        let suffix = value[value.len() - DISPLAY_SUFFIX_BYTES..].to_owned();
        Ok(Self {
            digest: Sha256::digest(value.as_bytes()).into(),
            value,
            suffix,
        })
    }
}

fn valid_token(value: &str) -> bool {
    value.len() == TOKEN_PREFIX.len() + TOKEN_BYTES * 2
        && value.starts_with(TOKEN_PREFIX)
        && value[TOKEN_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn required_env(name: &str) -> Result<String, StartupError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(StartupError::SymbolUploadConfiguration)
}

fn valid_upload_host(host: &str) -> bool {
    host.parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn validate_spool_directory(path: &FilePath) -> Result<(), StartupError> {
    std::fs::create_dir_all(path).map_err(|_| StartupError::SymbolUploadConfiguration)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| StartupError::SymbolUploadConfiguration)?;
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| StartupError::SymbolUploadConfiguration)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(StartupError::SymbolUploadConfiguration);
    }
    Ok(())
}

pub(crate) async fn negotiate_uploads(
    State(state): State<ServerState>,
    Path(project_slug): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<NegotiateRequest>, JsonRejection>,
) -> Result<Response, UploadError> {
    let uploads = state.symbol_uploads();
    let scope = authorize_upload(uploads, &headers).await?;
    if scope.project_slug != project_slug {
        return Err(UploadError::NotFound);
    }
    let Json(payload) = payload.map_err(|_| UploadError::Invalid)?;
    let request = ValidatedNegotiation::try_from(payload)?;
    negotiate(uploads, &scope, request)
        .await
        .map(|value| no_store(Json(value)))
}

pub(crate) async fn sign_part(
    State(state): State<ServerState>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<SignPartRequest>, JsonRejection>,
) -> Result<Response, UploadError> {
    let uploads = state.symbol_uploads();
    let scope = authorize_upload(uploads, &headers).await?;
    let Json(payload) = payload.map_err(|_| UploadError::Invalid)?;
    sign_upload_part(uploads, &scope, &upload_id, payload)
        .await
        .map(|value| no_store(Json(value)))
}

pub(crate) async fn record_part(
    State(state): State<ServerState>,
    Path((upload_id, part_number)): Path<(String, i32)>,
    headers: HeaderMap,
    payload: Result<Json<RecordPartRequest>, JsonRejection>,
) -> Result<Response, UploadError> {
    let uploads = state.symbol_uploads();
    let scope = authorize_upload(uploads, &headers).await?;
    let Json(payload) = payload.map_err(|_| UploadError::Invalid)?;
    record_upload_part(uploads, &scope, &upload_id, part_number, payload).await?;
    Ok(no_store(StatusCode::NO_CONTENT))
}

pub(crate) async fn complete_upload(
    State(state): State<ServerState>,
    Path(upload_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, UploadError> {
    let uploads = state.symbol_uploads();
    let scope = authorize_upload(uploads, &headers).await?;
    complete(uploads, &scope, &upload_id)
        .await
        .map(|value| no_store(Json(value)))
}

pub(crate) async fn get_coverage(
    State(state): State<ServerState>,
    Path(release_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, UploadError> {
    let uploads = state.symbol_uploads();
    let scope = authorize_upload(uploads, &headers).await?;
    coverage_response(uploads.pool()?, &scope, &release_id)
        .await
        .map(|value| no_store(Json(value)))
}

#[derive(Deserialize)]
pub(crate) struct NegotiateRequest {
    release: ReleaseRequest,
    artifacts: Vec<ArtifactRequest>,
    cli_version: String,
    ci_job: Option<String>,
}

#[derive(Deserialize)]
struct ReleaseRequest {
    version: String,
    platform: String,
    architecture: String,
    configuration: String,
    revision: Option<String>,
    channel: Option<String>,
    build_timestamp: Option<String>,
}

#[derive(Deserialize)]
struct ArtifactRequest {
    path: String,
    module: String,
    artifact_type: String,
    architecture: String,
    byte_size: u64,
    sha256: String,
    debug_id: String,
    code_id: Option<String>,
}

struct ValidatedNegotiation {
    release: ReleaseRequest,
    artifacts: Vec<ValidatedArtifact>,
    cli_version: String,
    ci_job: Option<String>,
}

struct ValidatedArtifact {
    path: String,
    module: String,
    artifact_type: String,
    architecture: String,
    byte_size: u64,
    checksum: [u8; 32],
    sha256: String,
    debug_id: String,
    code_id: Option<String>,
}

impl TryFrom<NegotiateRequest> for ValidatedNegotiation {
    type Error = UploadError;

    fn try_from(request: NegotiateRequest) -> Result<Self, Self::Error> {
        if request.artifacts.is_empty()
            || request.artifacts.len() > MAX_ARTIFACTS
            || !valid_text(&request.release.version, 128)
            || request.release.platform != "windows"
            || !valid_architecture(&request.release.architecture)
            || !valid_text(&request.release.configuration, 32)
            || !valid_optional_text(request.release.revision.as_deref(), MAX_TEXT_BYTES)
            || !valid_optional_text(request.release.channel.as_deref(), 64)
            || !valid_build_timestamp(request.release.build_timestamp.as_deref())
            || !valid_text(&request.cli_version, 64)
            || !valid_optional_text(request.ci_job.as_deref(), MAX_TEXT_BYTES)
        {
            return Err(UploadError::Invalid);
        }
        let mut paths = std::collections::HashSet::new();
        let mut total = 0_u64;
        let mut artifacts = Vec::with_capacity(request.artifacts.len());
        for artifact in request.artifacts {
            let checksum = decode_sha256(&artifact.sha256).ok_or(UploadError::Invalid)?;
            if !valid_source_path(&artifact.path)
                || !paths.insert(artifact.path.clone())
                || !valid_text(&artifact.module, MAX_TEXT_BYTES)
                || !valid_artifact_module(&artifact.path, &artifact.module)
                || !matches!(
                    artifact.artifact_type.as_str(),
                    "pe_executable" | "pe_dynamic_library" | "pdb"
                )
                || !valid_architecture(&artifact.architecture)
                || artifact.architecture != request.release.architecture
                || artifact.byte_size == 0
                || artifact.byte_size > MAX_ARTIFACT_BYTES
                || !valid_identity(&artifact.debug_id)
                || !valid_optional_identity(artifact.code_id.as_deref())
                || artifact.artifact_type != "pdb" && artifact.code_id.is_none()
                || artifact.artifact_type == "pdb" && artifact.code_id.is_some()
            {
                return Err(UploadError::Invalid);
            }
            total = total
                .checked_add(artifact.byte_size)
                .filter(|value| *value <= MAX_TOTAL_BYTES)
                .ok_or(UploadError::Invalid)?;
            artifacts.push(ValidatedArtifact {
                path: artifact.path,
                module: artifact.module,
                artifact_type: artifact.artifact_type,
                architecture: artifact.architecture,
                byte_size: artifact.byte_size,
                checksum,
                sha256: artifact.sha256,
                debug_id: artifact.debug_id,
                code_id: artifact.code_id,
            });
        }
        artifacts.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(Self {
            release: request.release,
            artifacts,
            cli_version: request.cli_version,
            ci_job: request.ci_job,
        })
    }
}

#[derive(Serialize)]
pub(crate) struct NegotiateResponse {
    release: ReleaseView,
    artifacts: Vec<NegotiatedArtifact>,
    coverage: Coverage,
}

#[derive(Serialize)]
struct ReleaseView {
    id: String,
    version: String,
    platform: String,
    architecture: String,
    configuration: String,
    revision: Option<String>,
    channel: Option<String>,
    build_timestamp: Option<String>,
}

#[derive(Serialize)]
struct NegotiatedArtifact {
    path: String,
    sha256: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload: Option<UploadView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    correction: Option<&'static str>,
}

#[derive(Serialize)]
struct UploadView {
    id: String,
    part_size: u64,
    part_count: u32,
    completed_parts: Vec<CompletedPartView>,
}

#[derive(Serialize)]
struct CompletedPartView {
    part_number: i32,
    byte_size: i32,
    content_md5: String,
}

#[derive(Clone, Serialize)]
struct Coverage {
    total: u64,
    available: u64,
    missing: u64,
    mismatch: u64,
    ready: bool,
}

#[derive(Serialize)]
pub(crate) struct CoverageResponse {
    release: ReleaseView,
    coverage: Coverage,
}

#[derive(Serialize)]
pub(crate) struct CompleteResponse {
    release_id: String,
    artifact_status: &'static str,
    coverage: Coverage,
}

#[derive(Deserialize)]
pub(crate) struct SignPartRequest {
    part_number: i32,
    byte_size: i64,
    content_md5: String,
}

#[derive(Serialize)]
pub(crate) struct SignPartResponse {
    method: &'static str,
    url: String,
    headers: BTreeMap<String, String>,
    expires_in_seconds: u64,
}

#[derive(Deserialize)]
pub(crate) struct RecordPartRequest {
    etag: String,
    byte_size: i64,
    content_md5: String,
}

#[derive(Clone)]
struct Session {
    id: String,
    release_id: String,
    manifest_artifact_id: String,
    upload_token_id: String,
    uploaded_by_user_id: String,
    object_key: String,
    provider_upload_id: String,
    checksum: Vec<u8>,
    byte_size: i64,
    part_size: i32,
    part_count: i32,
    artifact_type: String,
    module_name: String,
    architecture: String,
    debug_id: String,
    code_id: Option<String>,
    ci_job: Option<String>,
    cli_version: String,
    state: String,
    expired: bool,
}

async fn negotiate(
    uploads: &SymbolUploads,
    scope: &TokenScope,
    request: ValidatedNegotiation,
) -> Result<NegotiateResponse, UploadError> {
    let pool = uploads.pool()?;
    let release = upsert_release(pool, scope, &request.release).await?;
    let mut negotiated = Vec::with_capacity(request.artifacts.len());
    for artifact in &request.artifacts {
        let manifest_id = upsert_manifest_artifact(
            uploads,
            scope,
            &release.id,
            artifact,
            &request.cli_version,
            request.ci_job.as_deref(),
        )
        .await?;
        if let Some(debug_image_id) = find_matching_debug_image(pool, scope, artifact).await? {
            mark_manifest_available(pool, scope, &manifest_id, &debug_image_id).await?;
            negotiated.push(NegotiatedArtifact {
                path: artifact.path.clone(),
                sha256: artifact.sha256.clone(),
                status: "already_present",
                upload: None,
                correction: None,
            });
            continue;
        }
        if organization_has_checksum(pool, scope, artifact).await? {
            mark_manifest_mismatch(pool, scope, &manifest_id).await?;
            negotiated.push(NegotiatedArtifact {
                path: artifact.path.clone(),
                sha256: artifact.sha256.clone(),
                status: "identity_mismatch",
                upload: None,
                correction: Some("rescan the artifact and upload its embedded identity"),
            });
            continue;
        }
        mark_manifest_missing(pool, scope, &manifest_id).await?;
        let session = get_or_create_session(
            uploads,
            scope,
            &release.id,
            &manifest_id,
            artifact,
            &request.cli_version,
            request.ci_job.as_deref(),
        )
        .await?;
        let completed_parts = load_completed_parts(pool, scope, &session.id).await?;
        negotiated.push(NegotiatedArtifact {
            path: artifact.path.clone(),
            sha256: artifact.sha256.clone(),
            status: "upload_required",
            upload: Some(UploadView {
                id: session.id,
                part_size: u64::try_from(session.part_size).map_err(|_| UploadError::Internal)?,
                part_count: u32::try_from(session.part_count).map_err(|_| UploadError::Internal)?,
                completed_parts,
            }),
            correction: None,
        });
    }
    let coverage = load_coverage(pool, scope, &release.id).await?;
    Ok(NegotiateResponse {
        release,
        artifacts: negotiated,
        coverage,
    })
}

async fn upsert_release(
    pool: &PgPool,
    scope: &TokenScope,
    release: &ReleaseRequest,
) -> Result<ReleaseView, UploadError> {
    let row = sqlx::query(
        "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, revision, channel, build_timestamp) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9::timestamptz) ON CONFLICT (project_id, version, platform, architecture, configuration) DO UPDATE SET revision = COALESCE(EXCLUDED.revision, releases.revision), channel = COALESCE(EXCLUDED.channel, releases.channel), build_timestamp = COALESCE(EXCLUDED.build_timestamp, releases.build_timestamp), updated_at = now() WHERE releases.organization_id = EXCLUDED.organization_id RETURNING id::text AS id, version, platform, architecture, configuration, revision, channel, build_timestamp",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&release.version)
    .bind(&release.platform)
    .bind(&release.architecture)
    .bind(&release.configuration)
    .bind(&release.revision)
    .bind(&release.channel)
    .bind(&release.build_timestamp)
    .fetch_one(pool)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    Ok(release_view(&row))
}

async fn upsert_manifest_artifact(
    uploads: &SymbolUploads,
    scope: &TokenScope,
    release_id: &str,
    artifact: &ValidatedArtifact,
    cli_version: &str,
    ci_job: Option<&str>,
) -> Result<String, UploadError> {
    if let Some(id) = try_upsert_manifest_artifact(
        uploads.pool()?,
        scope,
        release_id,
        artifact,
        cli_version,
        ci_job,
    )
    .await?
    {
        return Ok(id);
    }
    retire_replaced_active_session(uploads, scope, release_id, artifact).await?;
    try_upsert_manifest_artifact(
        uploads.pool()?,
        scope,
        release_id,
        artifact,
        cli_version,
        ci_job,
    )
    .await?
    .ok_or(UploadError::Conflict)
}

async fn try_upsert_manifest_artifact(
    pool: &PgPool,
    scope: &TokenScope,
    release_id: &str,
    artifact: &ValidatedArtifact,
    cli_version: &str,
    ci_job: Option<&str>,
) -> Result<Option<String>, UploadError> {
    sqlx::query_scalar(
        "INSERT INTO release_manifest_artifacts (release_id, organization_id, project_id, uploaded_by_user_id, upload_token_id, checksum, byte_size, artifact_type, module_name, architecture, debug_id, code_id, ci_job, source_path, cli_version) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) ON CONFLICT (release_id, source_path) DO UPDATE SET uploaded_by_user_id = EXCLUDED.uploaded_by_user_id, upload_token_id = EXCLUDED.upload_token_id, checksum = EXCLUDED.checksum, byte_size = EXCLUDED.byte_size, artifact_type = EXCLUDED.artifact_type, module_name = EXCLUDED.module_name, architecture = EXCLUDED.architecture, debug_id = EXCLUDED.debug_id, code_id = EXCLUDED.code_id, ci_job = EXCLUDED.ci_job, cli_version = EXCLUDED.cli_version, debug_image_id = NULL, state = 'missing', uploaded_at = NULL, updated_at = now() WHERE release_manifest_artifacts.organization_id = EXCLUDED.organization_id AND release_manifest_artifacts.project_id = EXCLUDED.project_id AND (NOT EXISTS (SELECT 1 FROM artifact_upload_sessions s WHERE s.manifest_artifact_id = release_manifest_artifacts.id AND s.organization_id = release_manifest_artifacts.organization_id AND s.project_id = release_manifest_artifacts.project_id AND s.state IN ('active', 'completing')) OR (release_manifest_artifacts.checksum = EXCLUDED.checksum AND release_manifest_artifacts.byte_size = EXCLUDED.byte_size AND release_manifest_artifacts.artifact_type = EXCLUDED.artifact_type AND release_manifest_artifacts.module_name = EXCLUDED.module_name AND release_manifest_artifacts.architecture = EXCLUDED.architecture AND release_manifest_artifacts.debug_id = EXCLUDED.debug_id AND release_manifest_artifacts.code_id IS NOT DISTINCT FROM EXCLUDED.code_id)) RETURNING id::text",
    )
    .bind(release_id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&scope.user_id)
    .bind(&scope.token_id)
    .bind(artifact.checksum.to_vec())
    .bind(i64::try_from(artifact.byte_size).map_err(|_| UploadError::Invalid)?)
    .bind(&artifact.artifact_type)
    .bind(&artifact.module)
    .bind(&artifact.architecture)
    .bind(&artifact.debug_id)
    .bind(&artifact.code_id)
    .bind(ci_job)
    .bind(&artifact.path)
    .bind(cli_version)
    .fetch_optional(pool)
    .await
    .map_err(|_| UploadError::Unavailable)
}

async fn retire_replaced_active_session(
    uploads: &SymbolUploads,
    scope: &TokenScope,
    release_id: &str,
    artifact: &ValidatedArtifact,
) -> Result<(), UploadError> {
    let row = sqlx::query(
        "UPDATE artifact_upload_sessions SET state = 'aborted', updated_at = now() WHERE id = (SELECT s.id FROM artifact_upload_sessions s JOIN release_manifest_artifacts m ON m.id = s.manifest_artifact_id AND m.organization_id = s.organization_id AND m.project_id = s.project_id WHERE m.release_id = $1::uuid AND m.organization_id = $2::uuid AND m.project_id = $3::uuid AND m.source_path = $4 AND s.state = 'active' AND (s.checksum <> $5 OR s.byte_size <> $6 OR s.artifact_type <> $7 OR s.module_name <> $8 OR s.architecture <> $9 OR s.debug_id <> $10 OR s.code_id IS DISTINCT FROM $11) ORDER BY s.created_at DESC LIMIT 1) RETURNING object_key, provider_upload_id",
    )
    .bind(release_id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&artifact.path)
    .bind(artifact.checksum.to_vec())
    .bind(i64::try_from(artifact.byte_size).map_err(|_| UploadError::Invalid)?)
    .bind(&artifact.artifact_type)
    .bind(&artifact.module)
    .bind(&artifact.architecture)
    .bind(&artifact.debug_id)
    .bind(&artifact.code_id)
    .fetch_optional(uploads.pool()?)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    if let Some(row) = row {
        let object_key: String = row.get("object_key");
        let provider_upload_id: String = row.get("provider_upload_id");
        uploads
            .objects
            .abort_multipart(&object_key, &provider_upload_id)
            .await;
    }
    Ok(())
}

async fn find_matching_debug_image(
    pool: &PgPool,
    scope: &TokenScope,
    artifact: &ValidatedArtifact,
) -> Result<Option<String>, UploadError> {
    sqlx::query_scalar(
        "SELECT d.id::text FROM artifact_objects o JOIN artifact_debug_images d ON d.object_id = o.id AND d.organization_id = o.organization_id WHERE o.organization_id = $1::uuid AND o.checksum = $2 AND o.byte_size = $3 AND o.lifecycle_state = 'stored' AND d.processing_status = 'available' AND d.artifact_type = $4 AND d.architecture = $5 AND d.debug_id = $6 AND d.code_id IS NOT DISTINCT FROM $7 LIMIT 1",
    )
    .bind(&scope.organization_id)
    .bind(artifact.checksum.to_vec())
    .bind(i64::try_from(artifact.byte_size).map_err(|_| UploadError::Invalid)?)
    .bind(&artifact.artifact_type)
    .bind(&artifact.architecture)
    .bind(&artifact.debug_id)
    .bind(&artifact.code_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| UploadError::Unavailable)
}

async fn organization_has_checksum(
    pool: &PgPool,
    scope: &TokenScope,
    artifact: &ValidatedArtifact,
) -> Result<bool, UploadError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM artifact_objects WHERE organization_id = $1::uuid AND checksum = $2)",
    )
    .bind(&scope.organization_id)
    .bind(artifact.checksum.to_vec())
    .fetch_one(pool)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    Ok(exists)
}

async fn mark_manifest_available(
    pool: &PgPool,
    scope: &TokenScope,
    manifest_id: &str,
    debug_image_id: &str,
) -> Result<(), UploadError> {
    update_manifest_state(pool, scope, manifest_id, "available", Some(debug_image_id)).await
}

async fn mark_manifest_missing(
    pool: &PgPool,
    scope: &TokenScope,
    manifest_id: &str,
) -> Result<(), UploadError> {
    update_manifest_state(pool, scope, manifest_id, "missing", None).await
}

async fn mark_manifest_mismatch(
    pool: &PgPool,
    scope: &TokenScope,
    manifest_id: &str,
) -> Result<(), UploadError> {
    update_manifest_state(pool, scope, manifest_id, "mismatch", None).await
}

async fn update_manifest_state(
    pool: &PgPool,
    scope: &TokenScope,
    manifest_id: &str,
    state: &str,
    debug_image_id: Option<&str>,
) -> Result<(), UploadError> {
    let result = sqlx::query(
        "UPDATE release_manifest_artifacts SET state = $4, debug_image_id = $5::uuid, uploaded_at = CASE WHEN $4 = 'available' THEN now() ELSE NULL END, updated_at = now() WHERE id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(manifest_id)
    .bind(state)
    .bind(debug_image_id)
    .execute(pool)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    if result.rows_affected() != 1 {
        return Err(UploadError::NotFound);
    }
    Ok(())
}

async fn get_or_create_session(
    uploads: &SymbolUploads,
    scope: &TokenScope,
    release_id: &str,
    manifest_id: &str,
    artifact: &ValidatedArtifact,
    cli_version: &str,
    ci_job: Option<&str>,
) -> Result<Session, UploadError> {
    let pool = uploads.pool()?;
    retire_stale_session(uploads, scope, manifest_id, artifact).await?;
    if let Some(session) = load_active_session(pool, scope, manifest_id).await? {
        return Ok(session);
    }
    let id = random_uuid()?;
    let object_key = format!("org/{}/artifacts/uploads/{id}", scope.organization_id);
    let provider_upload_id = uploads
        .objects
        .create_multipart(&object_key)
        .await
        .map_err(|_| UploadError::Unavailable)?;
    let part_count = artifact.byte_size.div_ceil(PART_BYTES);
    if part_count == 0 || part_count > MAX_PARTS {
        uploads
            .objects
            .abort_multipart(&object_key, &provider_upload_id)
            .await;
        return Err(UploadError::Invalid);
    }
    let inserted = sqlx::query(
        "INSERT INTO artifact_upload_sessions (id, organization_id, project_id, release_id, manifest_artifact_id, upload_token_id, uploaded_by_user_id, object_key, provider_upload_id, checksum, byte_size, part_size, part_count, artifact_type, module_name, architecture, debug_id, code_id, source_path, ci_job, cli_version, expires_at) SELECT $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid, $7::uuid, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, now() + interval '24 hours' FROM release_manifest_artifacts m WHERE m.id = $5::uuid AND m.release_id = $4::uuid AND m.organization_id = $2::uuid AND m.project_id = $3::uuid AND m.checksum = $10 AND m.byte_size = $11 AND m.artifact_type = $14 AND m.module_name = $15 AND m.architecture = $16 AND m.debug_id = $17 AND m.code_id IS NOT DISTINCT FROM $18 AND m.source_path = $19",
    )
    .bind(&id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(release_id)
    .bind(manifest_id)
    .bind(&scope.token_id)
    .bind(&scope.user_id)
    .bind(&object_key)
    .bind(&provider_upload_id)
    .bind(artifact.checksum.to_vec())
    .bind(i64::try_from(artifact.byte_size).map_err(|_| UploadError::Invalid)?)
    .bind(i32::try_from(PART_BYTES).map_err(|_| UploadError::Internal)?)
    .bind(i32::try_from(part_count).map_err(|_| UploadError::Invalid)?)
    .bind(&artifact.artifact_type)
    .bind(&artifact.module)
    .bind(&artifact.architecture)
    .bind(&artifact.debug_id)
    .bind(&artifact.code_id)
    .bind(&artifact.path)
    .bind(ci_job)
    .bind(cli_version)
    .execute(pool)
    .await;
    match inserted {
        Ok(result) if result.rows_affected() == 1 => load_session(pool, scope, &id).await,
        Ok(_) => {
            uploads
                .objects
                .abort_multipart(&object_key, &provider_upload_id)
                .await;
            Err(UploadError::Conflict)
        }
        Err(error)
            if error
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_unique_violation) =>
        {
            uploads
                .objects
                .abort_multipart(&object_key, &provider_upload_id)
                .await;
            load_active_session(pool, scope, manifest_id)
                .await?
                .ok_or(UploadError::Conflict)
        }
        Err(_) => {
            uploads
                .objects
                .abort_multipart(&object_key, &provider_upload_id)
                .await;
            Err(UploadError::Unavailable)
        }
    }
}

async fn retire_stale_session(
    uploads: &SymbolUploads,
    scope: &TokenScope,
    manifest_id: &str,
    artifact: &ValidatedArtifact,
) -> Result<(), UploadError> {
    let row = sqlx::query(
        "UPDATE artifact_upload_sessions SET state = 'aborted', updated_at = now() WHERE id = (SELECT id FROM artifact_upload_sessions WHERE organization_id = $1::uuid AND project_id = $2::uuid AND manifest_artifact_id = $3::uuid AND state = 'active' AND (expires_at <= now() OR checksum <> $4 OR byte_size <> $5 OR artifact_type <> $6 OR module_name <> $7 OR architecture <> $8 OR debug_id <> $9 OR code_id IS DISTINCT FROM $10) ORDER BY created_at DESC LIMIT 1) RETURNING object_key, provider_upload_id",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(manifest_id)
    .bind(artifact.checksum.to_vec())
    .bind(i64::try_from(artifact.byte_size).map_err(|_| UploadError::Invalid)?)
    .bind(&artifact.artifact_type)
    .bind(&artifact.module)
    .bind(&artifact.architecture)
    .bind(&artifact.debug_id)
    .bind(&artifact.code_id)
    .fetch_optional(uploads.pool()?)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    if let Some(row) = row {
        let object_key: String = row.get("object_key");
        let provider_upload_id: String = row.get("provider_upload_id");
        uploads
            .objects
            .abort_multipart(&object_key, &provider_upload_id)
            .await;
    }
    let completing: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM artifact_upload_sessions WHERE organization_id = $1::uuid AND project_id = $2::uuid AND manifest_artifact_id = $3::uuid AND state = 'completing' AND (checksum <> $4 OR byte_size <> $5 OR artifact_type <> $6 OR module_name <> $7 OR architecture <> $8 OR debug_id <> $9 OR code_id IS DISTINCT FROM $10))",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(manifest_id)
    .bind(artifact.checksum.to_vec())
    .bind(i64::try_from(artifact.byte_size).map_err(|_| UploadError::Invalid)?)
    .bind(&artifact.artifact_type)
    .bind(&artifact.module)
    .bind(&artifact.architecture)
    .bind(&artifact.debug_id)
    .bind(&artifact.code_id)
    .fetch_one(uploads.pool()?)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    if completing {
        return Err(UploadError::Conflict);
    }
    Ok(())
}

async fn load_active_session(
    pool: &PgPool,
    scope: &TokenScope,
    manifest_id: &str,
) -> Result<Option<Session>, UploadError> {
    let row = sqlx::query(
        "SELECT id::text AS id, release_id::text AS release_id, manifest_artifact_id::text AS manifest_artifact_id, upload_token_id::text AS upload_token_id, uploaded_by_user_id::text AS uploaded_by_user_id, object_key, provider_upload_id, checksum, byte_size, part_size, part_count, artifact_type, module_name, architecture, debug_id, code_id, ci_job, cli_version, state, expires_at <= now() AS expired FROM artifact_upload_sessions WHERE organization_id = $1::uuid AND project_id = $2::uuid AND manifest_artifact_id = $3::uuid AND (state = 'completing' OR (state = 'active' AND expires_at > now())) ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(manifest_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    Ok(row.map(|row| session_from_row(&row)))
}

async fn load_session(
    pool: &PgPool,
    scope: &TokenScope,
    upload_id: &str,
) -> Result<Session, UploadError> {
    let row = sqlx::query(
        "SELECT id::text AS id, release_id::text AS release_id, manifest_artifact_id::text AS manifest_artifact_id, upload_token_id::text AS upload_token_id, uploaded_by_user_id::text AS uploaded_by_user_id, object_key, provider_upload_id, checksum, byte_size, part_size, part_count, artifact_type, module_name, architecture, debug_id, code_id, ci_job, cli_version, state, expires_at <= now() AS expired FROM artifact_upload_sessions WHERE id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(upload_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| UploadError::Unavailable)?
    .ok_or(UploadError::NotFound)?;
    Ok(session_from_row(&row))
}

fn session_from_row(row: &sqlx::postgres::PgRow) -> Session {
    Session {
        id: row.get("id"),
        release_id: row.get("release_id"),
        manifest_artifact_id: row.get("manifest_artifact_id"),
        upload_token_id: row.get("upload_token_id"),
        uploaded_by_user_id: row.get("uploaded_by_user_id"),
        object_key: row.get("object_key"),
        provider_upload_id: row.get("provider_upload_id"),
        checksum: row.get("checksum"),
        byte_size: row.get("byte_size"),
        part_size: row.get("part_size"),
        part_count: row.get("part_count"),
        artifact_type: row.get("artifact_type"),
        module_name: row.get("module_name"),
        architecture: row.get("architecture"),
        debug_id: row.get("debug_id"),
        code_id: row.get("code_id"),
        ci_job: row.get("ci_job"),
        cli_version: row.get("cli_version"),
        state: row.get("state"),
        expired: row.get("expired"),
    }
}

async fn load_completed_parts(
    pool: &PgPool,
    scope: &TokenScope,
    upload_id: &str,
) -> Result<Vec<CompletedPartView>, UploadError> {
    let rows = sqlx::query(
        "SELECT p.part_number, p.byte_size, p.content_md5 FROM artifact_upload_parts p JOIN artifact_upload_sessions s ON s.id = p.upload_id AND s.organization_id = p.organization_id AND s.project_id = p.project_id WHERE p.upload_id::text = $3 AND p.organization_id = $1::uuid AND p.project_id = $2::uuid ORDER BY p.part_number",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(upload_id)
    .fetch_all(pool)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    Ok(rows
        .into_iter()
        .map(|row| CompletedPartView {
            part_number: row.get("part_number"),
            byte_size: row.get("byte_size"),
            content_md5: row.get("content_md5"),
        })
        .collect())
}

async fn sign_upload_part(
    uploads: &SymbolUploads,
    scope: &TokenScope,
    upload_id: &str,
    request: SignPartRequest,
) -> Result<SignPartResponse, UploadError> {
    let session = load_session(uploads.pool()?, scope, upload_id).await?;
    if session.state != "active" || session.expired {
        return Err(UploadError::Conflict);
    }
    if request.part_number < 1
        || request.part_number > session.part_count
        || request.byte_size != expected_part_size(&session, request.part_number)?
        || !valid_content_md5(&request.content_md5)
    {
        return Err(UploadError::Invalid);
    }
    let signed = uploads
        .objects
        .sign_part(
            &session.object_key,
            &session.provider_upload_id,
            request.part_number,
            request.byte_size,
            &request.content_md5,
        )
        .await
        .map_err(|_| UploadError::Unavailable)?;
    Ok(SignPartResponse {
        method: "PUT",
        url: signed.url,
        headers: signed.headers,
        expires_in_seconds: PRESIGN_SECONDS,
    })
}

async fn record_upload_part(
    uploads: &SymbolUploads,
    scope: &TokenScope,
    upload_id: &str,
    part_number: i32,
    request: RecordPartRequest,
) -> Result<(), UploadError> {
    let session = load_session(uploads.pool()?, scope, upload_id).await?;
    if session.state != "active" || session.expired {
        return Err(UploadError::Conflict);
    }
    if part_number < 1
        || part_number > session.part_count
        || request.byte_size != expected_part_size(&session, part_number)?
        || !valid_content_md5(&request.content_md5)
        || !valid_etag(&request.etag)
    {
        return Err(UploadError::Invalid);
    }
    let provider = uploads
        .objects
        .provider_part(
            &session.object_key,
            &session.provider_upload_id,
            part_number,
        )
        .await
        .map_err(|_| UploadError::Unavailable)?
        .ok_or(UploadError::Conflict)?;
    if provider.byte_size != request.byte_size
        || !same_etag(&provider.etag, &request.etag)
        || !etag_matches_md5(&provider.etag, &request.content_md5)
    {
        return Err(UploadError::Conflict);
    }
    sqlx::query(
        "INSERT INTO artifact_upload_parts (upload_id, organization_id, project_id, part_number, etag, content_md5, byte_size) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7) ON CONFLICT (upload_id, part_number) DO UPDATE SET etag = EXCLUDED.etag, content_md5 = EXCLUDED.content_md5, byte_size = EXCLUDED.byte_size, completed_at = now()",
    )
    .bind(upload_id)
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(part_number)
    .bind(provider.etag)
    .bind(request.content_md5)
    .bind(i32::try_from(request.byte_size).map_err(|_| UploadError::Invalid)?)
    .execute(uploads.pool()?)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    Ok(())
}

async fn complete(
    uploads: &SymbolUploads,
    scope: &TokenScope,
    upload_id: &str,
) -> Result<CompleteResponse, UploadError> {
    let mut session = load_session(uploads.pool()?, scope, upload_id).await?;
    if session.state == "completed" {
        cleanup_duplicate_object(uploads, scope, &session).await?;
        return complete_response(uploads.pool()?, scope, &session.release_id).await;
    }
    if session.state == "failed" {
        uploads.objects.delete_object(&session.object_key).await;
        return Err(UploadError::Mismatch);
    }
    if !matches!(session.state.as_str(), "active" | "completing") {
        return Err(UploadError::Conflict);
    }
    if session.state == "active" && session.expired {
        return Err(UploadError::Conflict);
    }
    let parts = load_provider_parts(uploads.pool()?, scope, &session).await?;
    if session.state == "active" {
        let result = sqlx::query(
            "UPDATE artifact_upload_sessions SET state = 'completing', updated_at = now() WHERE id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid AND state = 'active'",
        )
        .bind(&scope.organization_id)
        .bind(&scope.project_id)
        .bind(upload_id)
        .execute(uploads.pool()?)
        .await
        .map_err(|_| UploadError::Unavailable)?;
        if result.rows_affected() != 1 {
            return Err(UploadError::Conflict);
        }
        "completing".clone_into(&mut session.state);
    }
    let exists = uploads
        .objects
        .object_exists(&session.object_key)
        .await
        .map_err(|_| UploadError::Unavailable)?;
    if !exists {
        uploads
            .objects
            .complete_multipart(&session.object_key, &session.provider_upload_id, &parts)
            .await
            .map_err(|_| UploadError::Unavailable)?;
    }
    let verified = verify_object(uploads, &session).await;
    let record = match verified {
        Ok(record) => record,
        Err(VerifyError::Mismatch) => {
            fail_session(uploads.pool()?, scope, &session, "artifact_mismatch").await?;
            uploads.objects.delete_object(&session.object_key).await;
            return Err(UploadError::Mismatch);
        }
        Err(VerifyError::Unavailable) => return Err(UploadError::Unavailable),
    };
    publish_artifact(uploads, scope, &session, record).await?;
    complete_response(uploads.pool()?, scope, &session.release_id).await
}

async fn cleanup_duplicate_object(
    uploads: &SymbolUploads,
    scope: &TokenScope,
    session: &Session,
) -> Result<(), UploadError> {
    let canonical_key: Option<String> = sqlx::query_scalar(
        "SELECT o.object_key FROM release_manifest_artifacts m JOIN artifact_debug_images d ON d.id = m.debug_image_id AND d.organization_id = m.organization_id JOIN artifact_objects o ON o.id = d.object_id AND o.organization_id = d.organization_id WHERE m.id::text = $3 AND m.organization_id = $1::uuid AND m.project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&session.manifest_artifact_id)
    .fetch_optional(uploads.pool()?)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    if canonical_key.is_some_and(|key| key != session.object_key) {
        uploads.objects.delete_object(&session.object_key).await;
    }
    Ok(())
}

async fn load_provider_parts(
    pool: &PgPool,
    scope: &TokenScope,
    session: &Session,
) -> Result<Vec<ProviderPart>, UploadError> {
    let rows = sqlx::query(
        "SELECT part_number, etag, byte_size FROM artifact_upload_parts WHERE upload_id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid ORDER BY part_number",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&session.id)
    .fetch_all(pool)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    if rows.len() != usize::try_from(session.part_count).map_err(|_| UploadError::Internal)? {
        return Err(UploadError::Conflict);
    }
    let mut parts = Vec::with_capacity(rows.len());
    for (index, row) in rows.into_iter().enumerate() {
        let number: i32 = row.get("part_number");
        let byte_size = i64::from(row.get::<i32, _>("byte_size"));
        if number != i32::try_from(index + 1).map_err(|_| UploadError::Internal)?
            || byte_size != expected_part_size(session, number)?
        {
            return Err(UploadError::Conflict);
        }
        parts.push(ProviderPart {
            number,
            etag: row.get("etag"),
            byte_size,
        });
    }
    Ok(parts)
}

enum VerifyError {
    Mismatch,
    Unavailable,
}

struct VerifiedRecord {
    artifact_type: String,
    architecture: String,
    debug_id: String,
    code_id: Option<String>,
}

async fn verify_object(
    uploads: &SymbolUploads,
    session: &Session,
) -> Result<VerifiedRecord, VerifyError> {
    let extension = match session.artifact_type.as_str() {
        "pdb" => "pdb",
        "pe_dynamic_library" => "dll",
        "pe_executable" => "exe",
        _ => return Err(VerifyError::Mismatch),
    };
    let spool_id = random_uuid().map_err(|_| VerifyError::Unavailable)?;
    let path = uploads
        .spool_directory
        .join(format!("cachelane-{spool_id}.{extension}"));
    let downloaded = uploads
        .objects
        .download_to(
            &session.object_key,
            &path,
            u64::try_from(session.byte_size).map_err(|_| VerifyError::Mismatch)?,
        )
        .await;
    let (size, digest) = match downloaded {
        Ok(value) => value,
        Err(ObjectError::Invalid) => {
            let _ = fs::remove_file(&path).await;
            return Err(VerifyError::Mismatch);
        }
        Err(ObjectError::Unavailable | ObjectError::Missing) => {
            let _ = fs::remove_file(&path).await;
            return Err(VerifyError::Unavailable);
        }
    };
    if size != u64::try_from(session.byte_size).map_err(|_| VerifyError::Mismatch)?
        || digest.as_slice() != session.checksum.as_slice()
    {
        let _ = fs::remove_file(&path).await;
        return Err(VerifyError::Mismatch);
    }
    let scan_path = path.clone();
    let scan_size = size;
    let scan = tokio::task::spawn_blocking(move || {
        scan_artifacts_with_limits(
            &scan_path,
            ArtifactScanLimits {
                entries: 1,
                depth: 0,
                files: 1,
                file_bytes: scan_size,
                total_bytes: scan_size,
            },
        )
    })
    .await
    .map_err(|_| VerifyError::Unavailable)?
    .map_err(|_| VerifyError::Mismatch);
    let _ = fs::remove_file(&path).await;
    let scan = scan?;
    let Some(record) = scan.artifacts.into_iter().next() else {
        return Err(VerifyError::Mismatch);
    };
    if record.error.is_some() {
        return Err(VerifyError::Mismatch);
    }
    let artifact_type = artifact_type_name(record.artifact_type);
    let architecture = record.architecture.map(architecture_name);
    if artifact_type != session.artifact_type
        || architecture.as_deref() != Some(session.architecture.as_str())
        || record.debug_id.as_deref() != Some(session.debug_id.as_str())
        || record.code_id != session.code_id
    {
        return Err(VerifyError::Mismatch);
    }
    Ok(VerifiedRecord {
        artifact_type,
        architecture: architecture.unwrap_or_default(),
        debug_id: record.debug_id.unwrap_or_default(),
        code_id: record.code_id,
    })
}

async fn publish_artifact(
    uploads: &SymbolUploads,
    scope: &TokenScope,
    session: &Session,
    record: VerifiedRecord,
) -> Result<(), UploadError> {
    let mut transaction = uploads
        .pool()?
        .begin()
        .await
        .map_err(|_| UploadError::Unavailable)?;
    let object = sqlx::query(
        "INSERT INTO artifact_objects (organization_id, object_key, checksum, byte_size) VALUES ($1::uuid, $2, $3, $4) ON CONFLICT (organization_id, checksum) DO UPDATE SET checksum = EXCLUDED.checksum RETURNING id::text AS id, object_key",
    )
    .bind(&scope.organization_id)
    .bind(&session.object_key)
    .bind(&session.checksum)
    .bind(session.byte_size)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    let object_id: String = object.get("id");
    let canonical_key: String = object.get("object_key");
    let inserted_debug_image: Option<String> = sqlx::query_scalar(
        "INSERT INTO artifact_debug_images (organization_id, object_id, artifact_type, module_name, architecture, debug_id, code_id) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING RETURNING id::text",
    )
    .bind(&scope.organization_id)
    .bind(&object_id)
    .bind(&record.artifact_type)
    .bind(&session.module_name)
    .bind(&record.architecture)
    .bind(&record.debug_id)
    .bind(&record.code_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    let debug_image_id = if let Some(id) = inserted_debug_image {
        id
    } else {
        sqlx::query_scalar(
            "SELECT id::text FROM artifact_debug_images WHERE organization_id = $1::uuid AND object_id = $2::uuid AND artifact_type = $3 AND debug_id = $4 AND code_id IS NOT DISTINCT FROM $5",
        )
        .bind(&scope.organization_id)
        .bind(&object_id)
        .bind(&record.artifact_type)
        .bind(&record.debug_id)
        .bind(&record.code_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| UploadError::Unavailable)?
    };
    let manifest = sqlx::query(
        "UPDATE release_manifest_artifacts SET debug_image_id = $4::uuid, uploaded_by_user_id = $5::uuid, upload_token_id = $6::uuid, ci_job = $7, cli_version = $8, state = 'available', uploaded_at = now(), updated_at = now() WHERE id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid AND checksum = $9 AND byte_size = $10 AND artifact_type = $11 AND module_name = $12 AND architecture = $13 AND debug_id = $14 AND code_id IS NOT DISTINCT FROM $15",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&session.manifest_artifact_id)
    .bind(debug_image_id)
    .bind(&session.uploaded_by_user_id)
    .bind(&session.upload_token_id)
    .bind(&session.ci_job)
    .bind(&session.cli_version)
    .bind(&session.checksum)
    .bind(session.byte_size)
    .bind(&session.artifact_type)
    .bind(&session.module_name)
    .bind(&session.architecture)
    .bind(&session.debug_id)
    .bind(&session.code_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    if manifest.rows_affected() != 1 {
        transaction
            .rollback()
            .await
            .map_err(|_| UploadError::Unavailable)?;
        abort_replaced_completion(uploads.pool()?, scope, session).await?;
        uploads.objects.delete_object(&session.object_key).await;
        return Err(UploadError::Conflict);
    }
    sqlx::query(
        "UPDATE artifact_upload_sessions SET state = 'completed', updated_at = now() WHERE id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&session.id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| UploadError::Unavailable)?;
    if canonical_key != session.object_key {
        uploads.objects.delete_object(&session.object_key).await;
    }
    Ok(())
}

async fn abort_replaced_completion(
    pool: &PgPool,
    scope: &TokenScope,
    session: &Session,
) -> Result<(), UploadError> {
    sqlx::query(
        "UPDATE artifact_upload_sessions SET state = 'aborted', updated_at = now() WHERE id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid AND state = 'completing'",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&session.id)
    .execute(pool)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    Ok(())
}

async fn fail_session(
    pool: &PgPool,
    scope: &TokenScope,
    session: &Session,
    failure_code: &str,
) -> Result<(), UploadError> {
    let mut transaction = pool.begin().await.map_err(|_| UploadError::Unavailable)?;
    sqlx::query(
        "UPDATE artifact_upload_sessions SET state = 'failed', failure_code = $4, updated_at = now() WHERE id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&session.id)
    .bind(failure_code)
    .execute(&mut *transaction)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    sqlx::query(
        "UPDATE release_manifest_artifacts SET state = 'mismatch', debug_image_id = NULL, updated_at = now() WHERE id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(&session.manifest_artifact_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| UploadError::Unavailable)
}

async fn complete_response(
    pool: &PgPool,
    scope: &TokenScope,
    release_id: &str,
) -> Result<CompleteResponse, UploadError> {
    Ok(CompleteResponse {
        release_id: release_id.to_owned(),
        artifact_status: "available",
        coverage: load_coverage(pool, scope, release_id).await?,
    })
}

async fn coverage_response(
    pool: &PgPool,
    scope: &TokenScope,
    release_id: &str,
) -> Result<CoverageResponse, UploadError> {
    let row = sqlx::query(
        "SELECT id::text AS id, version, platform, architecture, configuration, revision, channel, build_timestamp FROM releases WHERE id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(release_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| UploadError::Unavailable)?
    .ok_or(UploadError::NotFound)?;
    Ok(CoverageResponse {
        release: release_view(&row),
        coverage: load_coverage(pool, scope, release_id).await?,
    })
}

async fn load_coverage(
    pool: &PgPool,
    scope: &TokenScope,
    release_id: &str,
) -> Result<Coverage, UploadError> {
    let row = sqlx::query(
        "SELECT count(*)::bigint AS total, count(*) FILTER (WHERE state = 'available')::bigint AS available, count(*) FILTER (WHERE state = 'missing')::bigint AS missing, count(*) FILTER (WHERE state = 'mismatch')::bigint AS mismatch FROM release_manifest_artifacts WHERE release_id::text = $3 AND organization_id = $1::uuid AND project_id = $2::uuid",
    )
    .bind(&scope.organization_id)
    .bind(&scope.project_id)
    .bind(release_id)
    .fetch_one(pool)
    .await
    .map_err(|_| UploadError::Unavailable)?;
    let total = u64::try_from(row.get::<i64, _>("total")).map_err(|_| UploadError::Internal)?;
    let available =
        u64::try_from(row.get::<i64, _>("available")).map_err(|_| UploadError::Internal)?;
    let missing = u64::try_from(row.get::<i64, _>("missing")).map_err(|_| UploadError::Internal)?;
    let mismatch =
        u64::try_from(row.get::<i64, _>("mismatch")).map_err(|_| UploadError::Internal)?;
    Ok(Coverage {
        total,
        available,
        missing,
        mismatch,
        ready: total > 0 && available == total,
    })
}

fn release_view(row: &sqlx::postgres::PgRow) -> ReleaseView {
    ReleaseView {
        id: row.get("id"),
        version: row.get("version"),
        platform: row.get("platform"),
        architecture: row.get("architecture"),
        configuration: row.get("configuration"),
        revision: row.get("revision"),
        channel: row.get("channel"),
        build_timestamp: row
            .get::<Option<OffsetDateTime>, _>("build_timestamp")
            .and_then(|value| value.format(&Rfc3339).ok()),
    }
}

fn expected_part_size(session: &Session, part_number: i32) -> Result<i64, UploadError> {
    if part_number < 1 || part_number > session.part_count {
        return Err(UploadError::Invalid);
    }
    if part_number < session.part_count {
        return Ok(i64::from(session.part_size));
    }
    let preceding = i64::from(session.part_size)
        .checked_mul(i64::from(session.part_count - 1))
        .ok_or(UploadError::Internal)?;
    session
        .byte_size
        .checked_sub(preceding)
        .filter(|value| *value > 0)
        .ok_or(UploadError::Internal)
}

fn valid_content_md5(value: &str) -> bool {
    value.len() == 24
        && BASE64
            .decode(value)
            .is_ok_and(|decoded| decoded.len() == 16)
}

fn valid_etag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn same_etag(left: &str, right: &str) -> bool {
    left.trim_matches('"').eq(right.trim_matches('"'))
}

fn etag_matches_md5(etag: &str, content_md5: &str) -> bool {
    BASE64
        .decode(content_md5)
        .ok()
        .is_some_and(|digest| lower_hex_bytes(&digest) == etag.trim_matches('"'))
}

fn lower_hex_bytes(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_optional_text(value: Option<&str>, max: usize) -> bool {
    value.is_none_or(|value| valid_text(value, max))
}

fn valid_identity(value: &str) -> bool {
    valid_text(value, 128)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_optional_identity(value: Option<&str>) -> bool {
    value.is_none_or(valid_identity)
}

fn valid_build_timestamp(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.len() <= 64 && OffsetDateTime::parse(value, &Rfc3339).is_ok())
}

fn valid_architecture(value: &str) -> bool {
    matches!(value, "x86" | "x86_64" | "arm64")
}

fn valid_source_path(value: &str) -> bool {
    valid_text(value, 512)
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}

fn valid_artifact_module(path: &str, module: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|file_name| file_name.eq_ignore_ascii_case(module))
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn random_uuid() -> Result<String, UploadError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| UploadError::Internal)?;
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

fn artifact_type_name(value: ArtifactType) -> String {
    match value {
        ArtifactType::PeExecutable => "pe_executable",
        ArtifactType::PeDynamicLibrary => "pe_dynamic_library",
        ArtifactType::Pdb => "pdb",
    }
    .to_owned()
}

fn architecture_name(value: Architecture) -> String {
    match value {
        Architecture::X86 => "x86",
        Architecture::X86_64 => "x86_64",
        Architecture::Arm64 => "arm64",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use std::{env, path::Path as FilePath};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, request::Builder},
    };
    use base64::Engine as _;
    use cachelane_symbols::scan_artifacts;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use sqlx::Row;
    use tower::ServiceExt;

    use super::{
        BASE64, GeneratedSecret, SymbolUploads, architecture_name, artifact_type_name, lower_hex,
        valid_artifact_module, valid_build_timestamp, valid_upload_host,
    };
    use crate::project_setup::{DATABASE_TEST_LOCK, ServerState, migrate, router};

    const BOOTSTRAP_SECRET: &str = "local-bootstrap-secret-with-32-bytes";

    #[test]
    fn upload_feature_requires_a_literal_loopback_host() {
        assert!(valid_upload_host("127.0.0.1"));
        assert!(valid_upload_host("::1"));
        assert!(!valid_upload_host("localhost"));
        assert!(!valid_upload_host("0.0.0.0"));
        assert!(!valid_upload_host("203.0.113.10"));
    }

    #[test]
    fn build_timestamp_requires_rfc3339() {
        assert!(valid_build_timestamp(None));
        assert!(valid_build_timestamp(Some("2026-08-14T00:00:00Z")));
        assert!(!valid_build_timestamp(Some("August 14")));
    }

    #[test]
    fn module_name_must_match_the_relative_file_name() {
        assert!(valid_artifact_module(
            "symbols/Game-Win64-Shipping.pdb",
            "game-win64-shipping.PDB"
        ));
        assert!(!valid_artifact_module(
            "symbols/Game-Win64-Shipping.pdb",
            "Other.pdb"
        ));
    }

    fn bootstrap(request: Builder) -> Builder {
        request
            .header("authorization", format!("Bootstrap {BOOTSTRAP_SECRET}"))
            .header("content-type", "application/json")
    }

    fn bearer(request: Builder, token: &str) -> Builder {
        request
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
    }

    async fn json_body(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap_or_else(|error| panic!("response body must be readable: {error}"));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("response must be JSON: {error}"))
    }

    async fn request_json(
        state: &ServerState,
        request: axum::http::Request<Body>,
    ) -> (StatusCode, Value) {
        let response = router("api", state.clone())
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        let status = response.status();
        (status, json_body(response).await)
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn uploads_only_missing_artifacts_and_keeps_tenants_isolated() {
        let Ok(database_url) = env::var("CACHELANE_TEST_DATABASE_URL") else {
            return;
        };
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let spool = env::temp_dir().join(format!(
            "cachelane-symbol-upload-test-{}",
            std::process::id()
        ));
        let uploads = SymbolUploads::test(pool.clone(), spool.clone());
        let state = ServerState::symbol_upload_test(pool.clone(), uploads, BOOTSTRAP_SECRET);

        let (status, setup) = request_json(
            &state,
            bootstrap(Request::builder().method("POST").uri("/api/v1/setup"))
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
        .await;
        assert_eq!(status, StatusCode::CREATED, "{setup}");
        let project_id = setup["setup"]["project"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("project ID must exist"));

        let (status, created_token) = request_json(
            &state,
            bootstrap(Request::builder().method("POST").uri(format!(
                "/api/v1/projects/{project_id}/artifact-upload-tokens"
            )))
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created_token}");
        let token = created_token["token"]
            .as_str()
            .unwrap_or_else(|| panic!("upload token must exist"));
        let token_id = created_token["id"]
            .as_str()
            .unwrap_or_else(|| panic!("upload token ID must exist"));

        let fixture = FilePath::new(env!("CARGO_MANIFEST_DIR"))
            .join("../cli/tests/fixtures/windows-symbolication/cachelane-symbolication.pdb");
        let bytes = std::fs::read(&fixture)
            .unwrap_or_else(|error| panic!("fixture must be readable: {error}"));
        let scan =
            scan_artifacts(&fixture).unwrap_or_else(|error| panic!("fixture must scan: {error}"));
        let artifact = scan
            .artifacts
            .first()
            .unwrap_or_else(|| panic!("fixture artifact must exist"));
        let sha256 = lower_hex(&Sha256::digest(&bytes));
        let request = json!({
            "release": {
                "version": "1.0.0",
                "platform": "windows",
                "architecture": architecture_name(artifact.architecture.unwrap_or_else(|| panic!("architecture must exist"))),
                "configuration": "shipping",
                "revision": "abc123",
                "channel": "playtest",
                "build_timestamp": "2026-08-14T00:00:00Z"
            },
            "artifacts": [{
                "path": "symbols/cachelane-symbolication.pdb",
                "module": artifact.module,
                "artifact_type": artifact_type_name(artifact.artifact_type),
                "architecture": architecture_name(artifact.architecture.unwrap_or_else(|| panic!("architecture must exist"))),
                "byte_size": bytes.len(),
                "sha256": sha256,
                "debug_id": artifact.debug_id,
                "code_id": artifact.code_id
            }],
            "cli_version": "0.1.0",
            "ci_job": "build-42"
        });

        let (status, negotiated) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/cachelane-proof/artifact-uploads"),
                token,
            )
            .body(Body::from(request.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{negotiated}");
        assert_eq!(negotiated["artifacts"][0]["status"], "upload_required");
        assert_eq!(negotiated["coverage"]["missing"], 1);
        assert_eq!(negotiated["release"]["channel"], "playtest");
        assert_eq!(
            negotiated["release"]["build_timestamp"],
            "2026-08-14T00:00:00Z"
        );
        let upload_id = negotiated["artifacts"][0]["upload"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("upload ID must exist"));
        let release_id = negotiated["release"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("release ID must exist"));

        let concurrent_left = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/cachelane-proof/artifact-uploads"),
                token,
            )
            .body(Body::from(request.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        );
        let concurrent_right = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/cachelane-proof/artifact-uploads"),
                token,
            )
            .body(Body::from(request.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        );
        let ((left_status, left), (right_status, right)) =
            tokio::join!(concurrent_left, concurrent_right);
        assert_eq!(left_status, StatusCode::OK, "{left}");
        assert_eq!(right_status, StatusCode::OK, "{right}");
        assert_eq!(left["artifacts"][0]["upload"]["id"], upload_id);
        assert_eq!(right["artifacts"][0]["upload"]["id"], upload_id);
        let content_md5 = BASE64.encode(md5::Md5::digest(&bytes));

        let (status, signed) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/artifact-uploads/{upload_id}/parts")),
                token,
            )
            .body(Body::from(
                json!({
                    "part_number": 1,
                    "byte_size": bytes.len(),
                    "content_md5": content_md5
                })
                .to_string(),
            ))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{signed}");
        assert_eq!(signed["headers"]["content-md5"], content_md5);
        assert_eq!(signed["headers"]["content-length"], bytes.len().to_string());
        let etag = state
            .symbol_uploads()
            .test_put_part(upload_id, 1, bytes.clone())
            .await
            .unwrap_or_else(|error| panic!("part must upload: {error:?}"));

        let record_response = router("api", state.clone())
            .oneshot(
                bearer(
                    Request::builder()
                        .method("PATCH")
                        .uri(format!("/api/v1/artifact-uploads/{upload_id}/parts/1")),
                    token,
                )
                .body(Body::from(
                    json!({
                        "etag": etag,
                        "byte_size": bytes.len(),
                        "content_md5": content_md5
                    })
                    .to_string(),
                ))
                .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        assert_eq!(record_response.status(), StatusCode::NO_CONTENT);

        let (status, resumed) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/cachelane-proof/artifact-uploads"),
                token,
            )
            .body(Body::from(request.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resumed}");
        assert_eq!(resumed["artifacts"][0]["status"], "upload_required");
        assert_eq!(resumed["artifacts"][0]["upload"]["id"], upload_id);
        assert_eq!(
            resumed["artifacts"][0]["upload"]["completed_parts"][0]["part_number"],
            1
        );
        assert_eq!(
            resumed["artifacts"][0]["upload"]["completed_parts"][0]["content_md5"],
            content_md5
        );

        sqlx::query("UPDATE artifact_upload_sessions SET state = 'completing' WHERE id::text = $1")
            .bind(upload_id)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("upload must enter completing state: {error}"));
        let mut replaced = request.clone();
        replaced["artifacts"][0]["sha256"] = json!("0".repeat(64));
        let (status, conflict) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/cachelane-proof/artifact-uploads"),
                token,
            )
            .body(Body::from(replaced.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
        let manifest_checksum: Vec<u8> = sqlx::query_scalar(
            "SELECT checksum FROM release_manifest_artifacts WHERE release_id::text = $1 AND source_path = 'symbols/cachelane-symbolication.pdb'",
        )
        .bind(release_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("manifest identity must persist: {error}"));
        assert_eq!(manifest_checksum, Sha256::digest(&bytes).to_vec());

        let (status, completed) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/artifact-uploads/{upload_id}/complete")),
                token,
            )
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{completed}");
        assert_eq!(completed["coverage"]["available"], 1);
        assert_eq!(completed["coverage"]["ready"], true);

        let (status, repeated_complete) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/artifact-uploads/{upload_id}/complete")),
                token,
            )
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{repeated_complete}");
        assert_eq!(repeated_complete["coverage"], completed["coverage"]);

        let (status, repeated) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/cachelane-proof/artifact-uploads"),
                token,
            )
            .body(Body::from(request.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{repeated}");
        assert_eq!(repeated["artifacts"][0]["status"], "already_present");
        assert_eq!(repeated["coverage"], completed["coverage"]);
        assert_eq!(repeated["release"]["id"], release_id);

        let mut next_release = request.clone();
        next_release["release"]["version"] = json!("1.0.1");
        let (status, deduplicated) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/cachelane-proof/artifact-uploads"),
                token,
            )
            .body(Body::from(next_release.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{deduplicated}");
        assert_eq!(deduplicated["artifacts"][0]["status"], "already_present");
        assert_ne!(deduplicated["release"]["id"], release_id);
        assert_eq!(deduplicated["coverage"]["available"], 1);

        let provenance = sqlx::query(
            "SELECT source_path, cli_version, ci_job, state, uploaded_at IS NOT NULL AS has_uploaded_at FROM release_manifest_artifacts WHERE release_id::text = $1",
        )
        .bind(release_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("provenance must persist: {error}"));
        assert_eq!(
            provenance.get::<String, _>("source_path"),
            "symbols/cachelane-symbolication.pdb"
        );
        assert_eq!(provenance.get::<String, _>("cli_version"), "0.1.0");
        assert_eq!(
            provenance.get::<Option<String>, _>("ci_job").as_deref(),
            Some("build-42")
        );
        assert_eq!(provenance.get::<String, _>("state"), "available");
        assert!(provenance.get::<bool, _>("has_uploaded_at"));
        let stored_digest: Vec<u8> = sqlx::query_scalar(
            "SELECT secret_hash FROM artifact_upload_tokens WHERE id::text = $1",
        )
        .bind(token_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("token digest must persist: {error}"));
        assert_eq!(stored_digest, Sha256::digest(token.as_bytes()).to_vec());
        assert_ne!(stored_digest, token.as_bytes());

        let invalid_bytes = b"not a portable program database".to_vec();
        let invalid_byte_size = invalid_bytes.len();
        let invalid_sha256 = lower_hex(&Sha256::digest(&invalid_bytes));
        let invalid_md5 = BASE64.encode(md5::Md5::digest(&invalid_bytes));
        let mut mismatch_request = request.clone();
        mismatch_request["release"]["version"] = json!("2.0.0");
        mismatch_request["artifacts"][0]["path"] = json!("symbols/mismatch.pdb");
        mismatch_request["artifacts"][0]["module"] = json!("mismatch.pdb");
        mismatch_request["artifacts"][0]["byte_size"] = json!(invalid_byte_size);
        mismatch_request["artifacts"][0]["sha256"] = json!(invalid_sha256);
        let (status, mismatch_negotiated) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/cachelane-proof/artifact-uploads"),
                token,
            )
            .body(Body::from(mismatch_request.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{mismatch_negotiated}");
        assert_eq!(
            mismatch_negotiated["artifacts"][0]["status"],
            "upload_required"
        );
        let mismatch_upload_id = mismatch_negotiated["artifacts"][0]["upload"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("mismatch upload ID must exist"));
        let mismatch_release_id = mismatch_negotiated["release"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("mismatch release ID must exist"));
        let (status, signed) = request_json(
            &state,
            bearer(
                Request::builder().method("POST").uri(format!(
                    "/api/v1/artifact-uploads/{mismatch_upload_id}/parts"
                )),
                token,
            )
            .body(Body::from(
                json!({
                    "part_number": 1,
                    "byte_size": invalid_byte_size,
                    "content_md5": invalid_md5
                })
                .to_string(),
            ))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{signed}");
        let invalid_etag = state
            .symbol_uploads()
            .test_put_part(mismatch_upload_id, 1, invalid_bytes)
            .await
            .unwrap_or_else(|error| panic!("mismatch part must upload: {error:?}"));
        let mismatch_record = router("api", state.clone())
            .oneshot(
                bearer(
                    Request::builder().method("PATCH").uri(format!(
                        "/api/v1/artifact-uploads/{mismatch_upload_id}/parts/1"
                    )),
                    token,
                )
                .body(Body::from(
                    json!({
                        "etag": invalid_etag,
                        "byte_size": invalid_byte_size,
                        "content_md5": invalid_md5
                    })
                    .to_string(),
                ))
                .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        assert_eq!(mismatch_record.status(), StatusCode::NO_CONTENT);
        let (status, mismatch) = request_json(
            &state,
            bearer(
                Request::builder().method("POST").uri(format!(
                    "/api/v1/artifact-uploads/{mismatch_upload_id}/complete"
                )),
                token,
            )
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{mismatch}");
        assert_eq!(mismatch["code"], "artifact_mismatch");
        assert_eq!(mismatch["retryable"], false);
        let (status, mismatch_coverage) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/releases/{mismatch_release_id}/coverage")),
                token,
            )
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{mismatch_coverage}");
        assert_eq!(mismatch_coverage["coverage"]["mismatch"], 1);
        assert_eq!(mismatch_coverage["coverage"]["ready"], false);

        let user_id: String = sqlx::query_scalar(
            "SELECT id::text FROM users WHERE bootstrap_subject = 'local-bootstrap'",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("bootstrap user must exist: {error}"));
        let outside_org: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Outside', 'outside') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("outside organization must insert: {error}"));
        sqlx::query(
            "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')",
        )
        .bind(&outside_org)
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("outside membership must insert: {error}"));
        let outside_project: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Outside', 'outside-project') RETURNING id::text",
        )
        .bind(&outside_org)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("outside project must insert: {error}"));
        let outside_secret = GeneratedSecret::new()
            .unwrap_or_else(|error| panic!("outside token must generate: {error:?}"));
        sqlx::query(
            "INSERT INTO artifact_upload_tokens (organization_id, project_id, created_by_user_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)",
        )
        .bind(&outside_org)
        .bind(&outside_project)
        .bind(&user_id)
        .bind(outside_secret.digest.to_vec())
        .bind(&outside_secret.suffix)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("outside token must insert: {error}"));
        let (status, outside) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/outside-project/artifact-uploads"),
                &outside_secret.value,
            )
            .body(Body::from(request.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{outside}");
        assert_eq!(outside["artifacts"][0]["status"], "upload_required");
        let (status, hidden) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/outside-project/artifact-uploads"),
                token,
            )
            .body(Body::from(request.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{hidden}");
        assert_eq!(hidden["code"], "not_found");

        let revoke = router("api", state.clone())
            .oneshot(
                bootstrap(Request::builder().method("DELETE").uri(format!(
                    "/api/v1/projects/{project_id}/artifact-upload-tokens/{token_id}"
                )))
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request must build: {error}")),
            )
            .await
            .unwrap_or_else(|error| panic!("router must answer: {error}"));
        assert_eq!(revoke.status(), StatusCode::NO_CONTENT);
        let (status, denied) = request_json(
            &state,
            bearer(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects/cachelane-proof/artifact-uploads"),
                token,
            )
            .body(Body::from(request.to_string()))
            .unwrap_or_else(|error| panic!("request must build: {error}")),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{denied}");

        pool.close().await;
        let _ = std::fs::remove_dir_all(spool);
    }
}
