use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use faultlane_symbols::{
    Architecture, ArtifactScanLimits, ArtifactType, MatchState, scan_artifacts_with_limits,
};
use md5::Md5;
use reqwest::{
    Method, StatusCode, Url,
    blocking::{Client, Response},
    header::{HeaderName, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

const MAX_ARTIFACTS: usize = 512;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_API_BODY_BYTES: u64 = 1024 * 1024;
const MAX_PART_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PARTS: u32 = 10_000;

pub(crate) struct UploadOptions {
    pub(crate) path: PathBuf,
    pub(crate) project: String,
    pub(crate) release: String,
    pub(crate) api_url: String,
    pub(crate) token: String,
    pub(crate) architecture: Option<String>,
    pub(crate) configuration: Option<String>,
    pub(crate) revision: Option<String>,
    pub(crate) channel: Option<String>,
    pub(crate) build_timestamp: Option<String>,
    pub(crate) ci_job: Option<String>,
}

pub(crate) enum UploadError {
    Validation(String),
    Unauthorized,
    Retryable,
    Internal,
}

impl UploadError {
    pub(crate) const fn exit_code(&self) -> u8 {
        match self {
            Self::Validation(_) => 2,
            Self::Unauthorized => 3,
            Self::Retryable => 4,
            Self::Internal => 5,
        }
    }
}

impl fmt::Display for UploadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(message) => formatter.write_str(message),
            Self::Unauthorized => formatter.write_str("artifact upload authorization failed"),
            Self::Retryable => formatter.write_str("artifact upload failed and can be retried"),
            Self::Internal => formatter.write_str("artifact upload could not be completed"),
        }
    }
}

pub(crate) fn upload(options: &UploadOptions) -> Result<(), UploadError> {
    validate_option(&options.project, 63, "project slug is invalid")?;
    validate_option(&options.release, 128, "release version is invalid")?;
    validate_optional(options.revision.as_deref(), 256, "revision is invalid")?;
    validate_optional(options.channel.as_deref(), 64, "release channel is invalid")?;
    validate_optional(
        options.build_timestamp.as_deref(),
        64,
        "build timestamp is invalid",
    )?;
    validate_optional(options.ci_job.as_deref(), 256, "CI job is invalid")?;
    let configuration = options.configuration.as_deref().unwrap_or("unknown");
    validate_option(configuration, 32, "release configuration is invalid")?;

    let (artifacts, architecture) = collect_artifacts(options)?;

    let api = ApiClient::new(&options.api_url, &options.token)?;
    let request = NegotiateRequest {
        release: ReleaseRequest {
            version: &options.release,
            platform: "windows",
            architecture: &architecture,
            configuration,
            revision: options.revision.as_deref(),
            channel: options.channel.as_deref(),
            build_timestamp: options.build_timestamp.as_deref(),
        },
        artifacts: artifacts.iter().map(ArtifactRequest::from).collect(),
        cli_version: env!("CARGO_PKG_VERSION"),
        ci_job: options.ci_job.as_deref(),
    };
    let endpoint = format!(
        "/api/v1/projects/{}/artifact-uploads",
        percent_encode_segment(&options.project)
    );
    let negotiation: NegotiateResponse = api.json(Method::POST, &endpoint, Some(&request))?;
    let local_by_path = artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<HashMap<_, _>>();
    let mut uploaded = 0_u64;
    let mut already_present = 0_u64;
    let mut bytes_transferred = 0_u64;
    let mut coverage = negotiation.coverage.clone();
    let release = negotiation.release.clone();

    for negotiated in negotiation.artifacts {
        match negotiated.status.as_str() {
            "already_present" => already_present += 1,
            "identity_mismatch" => {
                return Err(UploadError::Validation(format!(
                    "artifact identity mismatch: {}; rescan and upload the embedded identity",
                    negotiated.path
                )));
            }
            "upload_required" => {
                let artifact = local_by_path
                    .get(negotiated.path.as_str())
                    .ok_or(UploadError::Internal)?;
                let upload = negotiated.upload.ok_or(UploadError::Internal)?;
                bytes_transferred = bytes_transferred
                    .checked_add(upload_artifact(&api, artifact, &upload)?)
                    .ok_or(UploadError::Internal)?;
                let complete_path = format!(
                    "/api/v1/artifact-uploads/{}/complete",
                    percent_encode_segment(&upload.id)
                );
                let completed: CompleteResponse =
                    api.json::<(), _>(Method::POST, &complete_path, None)?;
                if completed.release_id != release.id || completed.artifact_status != "available" {
                    return Err(UploadError::Internal);
                }
                coverage = completed.coverage;
                uploaded += 1;
            }
            _ => return Err(UploadError::Internal),
        }
    }
    let coverage_path = format!(
        "/api/v1/releases/{}/coverage",
        percent_encode_segment(&release.id)
    );
    let final_coverage: CoverageResponse = api.json::<(), _>(Method::GET, &coverage_path, None)?;
    if final_coverage.release.id != release.id || final_coverage.coverage != coverage {
        return Err(UploadError::Internal);
    }
    let result = UploadResult {
        schema_version: 1,
        release,
        artifacts_scanned: u64::try_from(artifacts.len()).map_err(|_| UploadError::Internal)?,
        uploaded,
        already_present,
        bytes_transferred,
        coverage: final_coverage.coverage,
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &result).map_err(|_| UploadError::Internal)?;
    writeln!(output).map_err(|_| UploadError::Internal)
}

fn collect_artifacts(options: &UploadOptions) -> Result<(Vec<LocalArtifact>, String), UploadError> {
    let scan = scan_artifacts_with_limits(
        &options.path,
        ArtifactScanLimits {
            entries: 4096,
            depth: 64,
            files: MAX_ARTIFACTS,
            file_bytes: MAX_ARTIFACT_BYTES,
            total_bytes: MAX_TOTAL_BYTES,
        },
    )
    .map_err(|error| UploadError::Validation(error.to_string()))?;
    if scan.artifacts.is_empty() {
        return Err(UploadError::Validation(
            "no supported Windows artifacts were found".to_owned(),
        ));
    }
    let root_is_file = fs::symlink_metadata(&options.path)
        .map_err(|_| UploadError::Validation("failed to inspect artifact path".to_owned()))?
        .is_file();
    let mut artifacts = Vec::with_capacity(scan.artifacts.len());
    let mut inferred_architecture = None;
    for record in scan.artifacts {
        if record.error.is_some() || record.match_state == MatchState::Invalid {
            return Err(UploadError::Validation(format!(
                "invalid artifact: {}",
                record.path
            )));
        }
        if record.match_state == MatchState::Mismatched {
            return Err(UploadError::Validation(format!(
                "artifact identity mismatch: {}",
                record.path
            )));
        }
        let architecture = record.architecture.map(architecture_name).ok_or_else(|| {
            UploadError::Validation(format!("unknown architecture: {}", record.path))
        })?;
        if inferred_architecture
            .as_deref()
            .is_some_and(|value| value != architecture)
        {
            return Err(UploadError::Validation(
                "artifacts contain more than one architecture".to_owned(),
            ));
        }
        inferred_architecture = Some(architecture.to_owned());
        let file_path = if root_is_file {
            options.path.clone()
        } else {
            options.path.join(path_from_scan(&record.path)?)
        };
        let expected_size = record.size.ok_or_else(|| {
            UploadError::Validation(format!("unknown file size: {}", record.path))
        })?;
        let sha256 = hash_file(&file_path, expected_size)?;
        artifacts.push(LocalArtifact {
            file_path,
            path: record.path,
            module: record.module,
            artifact_type: artifact_type_name(record.artifact_type).to_owned(),
            architecture: architecture.to_owned(),
            byte_size: expected_size,
            sha256,
            debug_id: record.debug_id.ok_or_else(|| {
                UploadError::Validation("artifact has no debug identity".to_owned())
            })?,
            code_id: record.code_id,
        });
    }
    let architecture = options
        .architecture
        .as_deref()
        .unwrap_or_else(|| inferred_architecture.as_deref().unwrap_or("unknown"));
    if !matches!(architecture, "x86" | "x86_64" | "arm64")
        || inferred_architecture.as_deref() != Some(architecture)
    {
        return Err(UploadError::Validation(
            "release architecture does not match the scanned artifacts".to_owned(),
        ));
    }

    Ok((artifacts, architecture.to_owned()))
}

fn upload_artifact(
    api: &ApiClient,
    artifact: &LocalArtifact,
    upload: &UploadView,
) -> Result<u64, UploadError> {
    if upload.part_size == 0
        || upload.part_size > MAX_PART_BYTES
        || upload.part_count == 0
        || upload.part_count > MAX_PARTS
        || u64::from(upload.part_count) != artifact.byte_size.div_ceil(upload.part_size)
    {
        return Err(UploadError::Internal);
    }
    let mut completed = HashSet::new();
    for part in &upload.completed_parts {
        let offset = u64::try_from(part.part_number - 1)
            .ok()
            .and_then(|value| value.checked_mul(upload.part_size));
        let expected_size = offset.map(|value| (artifact.byte_size - value).min(upload.part_size));
        if part.part_number < 1
            || u32::try_from(part.part_number)
                .ok()
                .is_none_or(|value| value > upload.part_count)
            || part.byte_size <= 0
            || u64::try_from(part.byte_size).ok() != expected_size
            || BASE64
                .decode(&part.content_md5)
                .ok()
                .is_none_or(|value| value.len() != 16)
            || !completed.insert(part.part_number)
        {
            return Err(UploadError::Internal);
        }
    }
    let mut file = File::open(&artifact.file_path).map_err(|_| {
        UploadError::Validation(format!("failed to read artifact: {}", artifact.path))
    })?;
    let mut transferred = 0_u64;
    for part_number in 1..=upload.part_count {
        let part_number_i32 = i32::try_from(part_number).map_err(|_| UploadError::Internal)?;
        if completed.contains(&part_number_i32) {
            continue;
        }
        let offset = u64::from(part_number - 1)
            .checked_mul(upload.part_size)
            .ok_or(UploadError::Internal)?;
        let byte_size = (artifact.byte_size - offset).min(upload.part_size);
        let capacity = usize::try_from(byte_size).map_err(|_| UploadError::Internal)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| UploadError::Internal)?;
        bytes.resize(capacity, 0);
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.read_exact(&mut bytes))
            .map_err(|_| {
                UploadError::Validation(format!("failed to read artifact: {}", artifact.path))
            })?;
        let content_md5 = BASE64.encode(Md5::digest(&bytes));
        let sign_path = format!(
            "/api/v1/artifact-uploads/{}/parts",
            percent_encode_segment(&upload.id)
        );
        let signed: SignPartResponse = api.json(
            Method::POST,
            &sign_path,
            Some(&SignPartRequest {
                part_number: part_number_i32,
                byte_size: i64::try_from(byte_size).map_err(|_| UploadError::Internal)?,
                content_md5: &content_md5,
            }),
        )?;
        if signed.method != "PUT" || signed.expires_in_seconds == 0 {
            return Err(UploadError::Internal);
        }
        let etag = api.upload_part(&signed, bytes)?;
        let record_path = format!(
            "/api/v1/artifact-uploads/{}/parts/{part_number}",
            percent_encode_segment(&upload.id)
        );
        api.empty(
            Method::PATCH,
            &record_path,
            Some(&RecordPartRequest {
                etag: &etag,
                byte_size: i64::try_from(byte_size).map_err(|_| UploadError::Internal)?,
                content_md5: &content_md5,
            }),
        )?;
        transferred = transferred
            .checked_add(byte_size)
            .ok_or(UploadError::Internal)?;
    }
    Ok(transferred)
}

struct ApiClient {
    base_url: Url,
    token: String,
    client: Client,
}

impl ApiClient {
    fn new(base_url: &str, token: &str) -> Result<Self, UploadError> {
        let base_url = valid_service_url(base_url)?;
        if base_url.path() != "/" || base_url.query().is_some() {
            return Err(UploadError::Validation(
                "API URL must not contain a path or query".to_owned(),
            ));
        }
        if token.is_empty() || token.len() > 256 || token.chars().any(char::is_whitespace) {
            return Err(UploadError::Validation(
                "upload token is invalid".to_owned(),
            ));
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_mins(2))
            .redirect(Policy::none())
            .build()
            .map_err(|_| UploadError::Internal)?;
        Ok(Self {
            base_url,
            token: token.to_owned(),
            client,
        })
    }

    fn json<B: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<R, UploadError> {
        let response = self.send_api(method, path, body)?;
        let bytes = bounded_body(response)?;
        serde_json::from_slice(&bytes).map_err(|_| UploadError::Internal)
    }

    fn empty<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<(), UploadError> {
        let response = self.send_api(method, path, body)?;
        let _ = bounded_body(response)?;
        Ok(())
    }

    fn send_api<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<Response, UploadError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| UploadError::Internal)?;
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(&self.token)
            .header("accept", "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().map_err(|_| UploadError::Retryable)?;
        if response.status().is_success() {
            return Ok(response);
        }
        map_api_error(response)
    }

    fn upload_part(
        &self,
        signed: &SignPartResponse,
        bytes: Vec<u8>,
    ) -> Result<String, UploadError> {
        let url = valid_service_url(&signed.url)?;
        if url.path() == "/" {
            return Err(UploadError::Internal);
        }
        let expected_host = url.host_str().ok_or(UploadError::Internal)?.to_owned();
        let expected_port = url.port_or_known_default();
        let mut request = self.client.put(url);
        for (name, value) in &signed.headers {
            let normalized = name.to_ascii_lowercase();
            if matches!(normalized.as_str(), "authorization" | "cookie" | "host") {
                return Err(UploadError::Internal);
            }
            let name =
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| UploadError::Internal)?;
            let value = HeaderValue::from_str(value).map_err(|_| UploadError::Internal)?;
            request = request.header(name, value);
        }
        let response = request
            .body(bytes)
            .send()
            .map_err(|_| UploadError::Retryable)?;
        if response.url().host_str() != Some(expected_host.as_str())
            || response.url().port_or_known_default() != expected_port
        {
            return Err(UploadError::Internal);
        }
        if !response.status().is_success() {
            return Err(UploadError::Retryable);
        }
        response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .map(ToOwned::to_owned)
            .ok_or(UploadError::Retryable)
    }
}

fn bounded_body(response: Response) -> Result<Vec<u8>, UploadError> {
    let mut reader = response.take(MAX_API_BODY_BYTES + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| UploadError::Retryable)?;
    if bytes.len() as u64 > MAX_API_BODY_BYTES {
        return Err(UploadError::Internal);
    }
    Ok(bytes)
}

fn map_api_error(response: Response) -> Result<Response, UploadError> {
    let status = response.status();
    let body = bounded_body(response).ok();
    let error = body
        .as_deref()
        .and_then(|body| serde_json::from_slice::<ApiErrorBody>(body).ok());
    if status == StatusCode::UNAUTHORIZED {
        return Err(UploadError::Unauthorized);
    }
    if status.is_server_error() || error.as_ref().is_some_and(|error| error.retryable) {
        return Err(UploadError::Retryable);
    }
    if matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::NOT_FOUND
            | StatusCode::CONFLICT
            | StatusCode::UNPROCESSABLE_ENTITY
    ) {
        let message = if status == StatusCode::UNPROCESSABLE_ENTITY {
            "uploaded artifact does not match its declared identity"
        } else {
            "artifact upload request was rejected"
        };
        return Err(UploadError::Validation(message.to_owned()));
    }
    Err(UploadError::Internal)
}

fn valid_service_url(value: &str) -> Result<Url, UploadError> {
    let url =
        Url::parse(value).map_err(|_| UploadError::Validation("URL is invalid".to_owned()))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "https"
            && !(url.scheme() == "http"
                && url
                    .host_str()
                    .and_then(|host| host.parse::<IpAddr>().ok())
                    .is_some_and(|address| address.is_loopback())))
    {
        return Err(UploadError::Validation(
            "URL must use HTTPS or literal loopback HTTP".to_owned(),
        ));
    }
    Ok(url)
}

fn hash_file(path: &Path, expected_size: u64) -> Result<String, UploadError> {
    let file = File::open(path)
        .map_err(|_| UploadError::Validation("failed to read artifact".to_owned()))?;
    let mut reader = file.take(expected_size.saturating_add(1));
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| UploadError::Validation("failed to read artifact".to_owned()))?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or(UploadError::Internal)?;
        digest.update(&buffer[..count]);
    }
    if size != expected_size {
        return Err(UploadError::Validation(
            "artifact changed while it was scanned".to_owned(),
        ));
    }
    Ok(hex_lower(&digest.finalize()))
}

fn path_from_scan(value: &str) -> Result<PathBuf, UploadError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(UploadError::Internal);
    }
    Ok(value.split('/').collect())
}

fn validate_option(value: &str, max: usize, message: &'static str) -> Result<(), UploadError> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(UploadError::Validation(message.to_owned()));
    }
    Ok(())
}

fn validate_optional(
    value: Option<&str>,
    max: usize,
    message: &'static str,
) -> Result<(), UploadError> {
    if let Some(value) = value {
        validate_option(value, max, message)?;
    }
    Ok(())
}

fn percent_encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use fmt::Write as _;
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

const fn artifact_type_name(value: ArtifactType) -> &'static str {
    match value {
        ArtifactType::PeExecutable => "pe_executable",
        ArtifactType::PeDynamicLibrary => "pe_dynamic_library",
        ArtifactType::Pdb => "pdb",
    }
}

const fn architecture_name(value: Architecture) -> &'static str {
    match value {
        Architecture::X86 => "x86",
        Architecture::X86_64 => "x86_64",
        Architecture::Arm64 => "arm64",
    }
}

struct LocalArtifact {
    file_path: PathBuf,
    path: String,
    module: String,
    artifact_type: String,
    architecture: String,
    byte_size: u64,
    sha256: String,
    debug_id: String,
    code_id: Option<String>,
}

#[derive(Serialize)]
struct NegotiateRequest<'a> {
    release: ReleaseRequest<'a>,
    artifacts: Vec<ArtifactRequest<'a>>,
    cli_version: &'static str,
    ci_job: Option<&'a str>,
}

#[derive(Serialize)]
struct ReleaseRequest<'a> {
    version: &'a str,
    platform: &'static str,
    architecture: &'a str,
    configuration: &'a str,
    revision: Option<&'a str>,
    channel: Option<&'a str>,
    build_timestamp: Option<&'a str>,
}

#[derive(Serialize)]
struct ArtifactRequest<'a> {
    path: &'a str,
    module: &'a str,
    artifact_type: &'a str,
    architecture: &'a str,
    byte_size: u64,
    sha256: &'a str,
    debug_id: &'a str,
    code_id: Option<&'a str>,
}

impl<'a> From<&'a LocalArtifact> for ArtifactRequest<'a> {
    fn from(artifact: &'a LocalArtifact) -> Self {
        Self {
            path: &artifact.path,
            module: &artifact.module,
            artifact_type: &artifact.artifact_type,
            architecture: &artifact.architecture,
            byte_size: artifact.byte_size,
            sha256: &artifact.sha256,
            debug_id: &artifact.debug_id,
            code_id: artifact.code_id.as_deref(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
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

#[derive(Deserialize)]
struct NegotiateResponse {
    release: ReleaseView,
    artifacts: Vec<NegotiatedArtifact>,
    coverage: Coverage,
}

#[derive(Deserialize)]
struct NegotiatedArtifact {
    path: String,
    status: String,
    upload: Option<UploadView>,
}

#[derive(Deserialize)]
struct UploadView {
    id: String,
    part_size: u64,
    part_count: u32,
    completed_parts: Vec<CompletedPartView>,
}

#[derive(Deserialize)]
struct CompletedPartView {
    part_number: i32,
    byte_size: i32,
    content_md5: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct Coverage {
    total: u64,
    available: u64,
    missing: u64,
    mismatch: u64,
    ready: bool,
}

#[derive(Deserialize)]
struct CoverageResponse {
    release: ReleaseView,
    coverage: Coverage,
}

#[derive(Serialize)]
struct SignPartRequest<'a> {
    part_number: i32,
    byte_size: i64,
    content_md5: &'a str,
}

#[derive(Deserialize)]
struct SignPartResponse {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
struct RecordPartRequest<'a> {
    etag: &'a str,
    byte_size: i64,
    content_md5: &'a str,
}

#[derive(Deserialize)]
struct CompleteResponse {
    release_id: String,
    artifact_status: String,
    coverage: Coverage,
}

#[derive(Deserialize)]
struct ApiErrorBody {
    retryable: bool,
}

#[derive(Serialize)]
struct UploadResult {
    schema_version: u32,
    release: ReleaseView,
    artifacts_scanned: u64,
    uploaded: u64,
    already_present: u64,
    bytes_transferred: u64,
    coverage: Coverage,
}
