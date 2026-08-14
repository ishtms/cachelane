use std::{
    env, fmt, fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use faultlane_symbols::{SYMCACHE_FORMAT_VERSION, SYMCACHE_PROCESSOR_VERSION};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use tokio::sync::watch;
use tracing::{info, warn};
use url::Url;

use crate::{
    processor_runner::{
        OwnedContainer, ProcessorOperation, ProcessorOutput, ProcessorRunner, RunnerError,
    },
    symbol_upload::{ArtifactObjects, ObjectError},
};

const LEASE_SECONDS: i64 = 300;
const HEARTBEAT_SECONDS: u64 = 30;
const POLL_MILLISECONDS: u64 = 250;
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SELECTED_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_RAW_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024;
const SCRATCH_MARKER: &[u8] = b"faultlane-worker-scratch-v1\n";

pub(crate) async fn run() -> Result<(), WorkerStartupError> {
    let database_url = required_env("DATABASE_URL")?;
    let processor_scope = processor_scope(&database_url)?;
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .map_err(|_| WorkerStartupError::Database)?;
    let objects = ArtifactObjects::from_environment().map_err(|_| WorkerStartupError::Objects)?;
    let runner = ProcessorRunner::from_environment(&processor_scope)
        .await
        .map_err(|_| WorkerStartupError::Processor)?;
    let scratch = worker_scratch()?;
    let worker_id = random_uuid().map_err(|_| WorkerStartupError::Random)?;
    let worker = Worker {
        pool,
        objects,
        runner,
        scratch: Arc::new(scratch),
        instance_id: Arc::from(worker_id),
    };
    worker.reconcile_containers().await?;
    worker.run_loop().await
}

#[derive(Debug)]
pub(crate) enum WorkerStartupError {
    Configuration,
    Database,
    Objects,
    Processor,
    Scratch,
    Random,
}

impl fmt::Display for WorkerStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "worker configuration is invalid",
            Self::Database => "worker database is unavailable",
            Self::Objects => "worker object storage is unavailable",
            Self::Processor => "worker processor image is unavailable",
            Self::Scratch => "worker scratch directory is invalid",
            Self::Random => "worker could not generate an identity",
        })
    }
}

impl std::error::Error for WorkerStartupError {}

#[derive(Clone)]
struct Worker {
    pool: PgPool,
    objects: ArtifactObjects,
    runner: ProcessorRunner,
    scratch: Arc<PathBuf>,
    instance_id: Arc<str>,
}

impl Worker {
    async fn run_loop(&self) -> Result<(), WorkerStartupError> {
        info!(worker_id = self.instance_id.as_ref(), "worker started");
        let mut reconciliation = tokio::time::interval(Duration::from_secs(30));
        reconciliation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        reconciliation.tick().await;
        loop {
            tokio::select! {
                result = self.claim() => {
                    match result {
                        Ok(Some(job)) => {
                            let running = job.clone();
                            tokio::select! {
                                () = self.run_job(running) => {}
                                shutdown = tokio::signal::ctrl_c() => {
                                    shutdown.map_err(|_| WorkerStartupError::Configuration)?;
                                    self.runner.cancel(&container_name(&job.id, &job.lease_token)).await;
                                    let _ = self.cancel_job(&job).await;
                                    info!("worker stopped");
                                    return Ok(());
                                }
                            }
                        }
                        Ok(None) => tokio::time::sleep(Duration::from_millis(POLL_MILLISECONDS)).await,
                        Err(()) => {
                            warn!("worker claim failed");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
                shutdown = tokio::signal::ctrl_c() => {
                    shutdown.map_err(|_| WorkerStartupError::Configuration)?;
                    info!("worker stopped");
                    return Ok(());
                }
                _ = reconciliation.tick() => {
                    if self.reconcile_containers().await.is_err() {
                        warn!("worker container reconciliation failed");
                    }
                }
            }
        }
    }

    async fn reconcile_containers(&self) -> Result<(), WorkerStartupError> {
        let containers = self
            .runner
            .owned_containers()
            .await
            .map_err(|_| WorkerStartupError::Processor)?;
        for container in containers {
            let attempt = owned_attempt(&container);
            let active = if let Some((job_id, lease_token)) = attempt {
                self.lease_is_active(job_id, lease_token).await?
            } else {
                false
            };
            if active {
                continue;
            }
            self.runner
                .cancel_owned(&container.name)
                .await
                .map_err(|_| WorkerStartupError::Processor)?;
            if let Some((job_id, lease_token)) = attempt {
                remove_attempt_directory(&self.scratch, job_id, lease_token)?;
            }
        }
        self.reconcile_attempt_directories().await
    }

    async fn reconcile_attempt_directories(&self) -> Result<(), WorkerStartupError> {
        let entries =
            fs::read_dir(self.scratch.as_ref()).map_err(|_| WorkerStartupError::Scratch)?;
        for entry in entries {
            let entry = entry.map_err(|_| WorkerStartupError::Scratch)?;
            let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            let Some((job_id, lease_token)) = attempt_identity(&name) else {
                continue;
            };
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(WorkerStartupError::Scratch),
            };
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(WorkerStartupError::Scratch);
            }
            if !self.lease_is_active(job_id, lease_token).await? {
                remove_attempt_directory(&self.scratch, job_id, lease_token)?;
            }
        }
        Ok(())
    }

    async fn lease_is_active(
        &self,
        job_id: &str,
        lease_token: &str,
    ) -> Result<bool, WorkerStartupError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM jobs WHERE id::text = $1 AND state = 'leased' AND lease_token::text = $2 AND lease_expires_at > now())",
        )
        .bind(job_id)
        .bind(lease_token)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| WorkerStartupError::Database)
    }

    async fn claim(&self) -> Result<Option<Job>, ()> {
        claim_job(&self.pool, self.instance_id.as_ref()).await
    }

    async fn run_job(&self, job: Job) {
        let (stop, heartbeat) = self.start_heartbeat(&job);
        let resource_retry =
            job.resource_failures == 1 && job.attempt == job.max_attempt.saturating_add(1);
        let result = if job.attempt > job.max_attempt && !resource_retry {
            Err(JobError::Transient("retry_exhausted"))
        } else {
            match job.kind.as_str() {
                "index_artifact" => self.index_artifact(&job).await,
                "generate_symcache" => self.generate_symcache(&job).await,
                "process_crash" => self.process_crash(&job).await,
                _ => Err(JobError::Deterministic("unknown_job_type")),
            }
        };
        let _ = stop.send(true);
        let _ = heartbeat.await;
        self.finish_result(&job, result).await;
    }

    async fn finish_result(&self, job: &Job, result: Result<(), JobError>) {
        match result {
            Ok(()) | Err(JobError::LostLease) => {}
            Err(JobError::Dependency) => {
                let _ = self.wait_for_dependency(job).await;
            }
            Err(JobError::Deterministic(code)) => {
                let _ = self.quarantine(job, code).await;
            }
            Err(JobError::Resource(code)) => {
                if job.resource_failures == 0 {
                    let _ = self.retry(job, code, true).await;
                } else {
                    let _ = self.quarantine_resource(job, code).await;
                }
            }
            Err(JobError::Transient(code)) => {
                if job.attempt < job.max_attempt {
                    let _ = self.retry(job, code, false).await;
                } else {
                    let _ = self.fail(job, code).await;
                }
            }
        }
    }

    fn start_heartbeat(&self, job: &Job) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let (stop, mut stopped) = watch::channel(false);
        let pool = self.pool.clone();
        let job = job.clone();
        let worker_id = self.instance_id.clone();
        let heartbeat = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECONDS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    changed = stopped.changed() => {
                        if changed.is_err() || *stopped.borrow() {
                            return;
                        }
                    }
                    _ = interval.tick() => {
                        let updated = sqlx::query("UPDATE jobs SET heartbeat_at = now(), lease_expires_at = now() + ($6 * interval '1 second'), updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'leased' AND lease_owner = $4 AND lease_token::text = $5")
                            .bind(&job.id)
                            .bind(&job.organization_id)
                            .bind(&job.project_id)
                            .bind(worker_id.as_ref())
                            .bind(&job.lease_token)
                            .bind(LEASE_SECONDS)
                            .execute(&pool)
                            .await;
                        if !updated.is_ok_and(|result| result.rows_affected() == 1) {
                            return;
                        }
                    }
                }
            }
        });
        (stop, heartbeat)
    }

    async fn index_artifact(&self, job: &Job) -> Result<(), JobError> {
        let upload_id = job
            .artifact_upload_id
            .as_deref()
            .ok_or(JobError::Deterministic("missing_artifact_upload"))?;
        let row = sqlx::query(
            "SELECT s.id::text AS id, s.release_id::text AS release_id, s.manifest_artifact_id::text AS manifest_artifact_id, s.upload_token_id::text AS upload_token_id, s.uploaded_by_user_id::text AS uploaded_by_user_id, s.object_key, s.checksum, s.byte_size, s.artifact_type, s.module_name, s.architecture, s.debug_id, s.code_id, s.ci_job, s.cli_version FROM artifact_upload_sessions s WHERE s.id::text = $1 AND s.organization_id::text = $2 AND s.project_id::text = $3 AND s.state = 'processing'",
        )
        .bind(upload_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?
        .ok_or(JobError::Deterministic("artifact_session_missing"))?;
        let artifact = ArtifactSession::from_row(&row);
        let attempt = AttemptDirectory::new(&self.scratch, &job.id, &job.lease_token)?;
        let extension = match artifact.artifact_type.as_str() {
            "pdb" => "pdb",
            "pe_executable" => "exe",
            "pe_dynamic_library" => "dll",
            _ => return Err(JobError::Deterministic("artifact_type_invalid")),
        };
        let path = attempt.input().join(format!("artifact.{extension}"));
        let expected_size = u64::try_from(artifact.byte_size)
            .map_err(|_| JobError::Deterministic("artifact_size_invalid"))?;
        if expected_size > MAX_ARTIFACT_BYTES {
            return Err(JobError::Deterministic("artifact_size_invalid"));
        }
        let (size, checksum) = self
            .objects
            .download_to(&artifact.object_key, &path, expected_size)
            .await
            .map_err(map_artifact_object_error)?;
        if size != expected_size || checksum.as_slice() != artifact.checksum.as_slice() {
            return self
                .publish_artifact_failure(job, &artifact, "artifact_mismatch", false)
                .await;
        }
        let operation = match artifact.artifact_type.as_str() {
            "pdb" => ProcessorOperation::IndexPdb,
            "pe_executable" => ProcessorOperation::IndexExe,
            "pe_dynamic_library" => ProcessorOperation::IndexDll,
            _ => return Err(JobError::Deterministic("artifact_type_invalid")),
        };
        let output = self.run_processor(job, operation, &attempt, None).await;
        let output = match output {
            Ok(output) => output,
            Err(JobError::Deterministic(_)) => {
                return self
                    .publish_artifact_failure(job, &artifact, "artifact_malformed", true)
                    .await;
            }
            Err(error) => return Err(error),
        };
        let scan: IndexOutput = strict_json(&output.stdout)?;
        let [record] = scan.artifacts.as_slice() else {
            return self
                .publish_artifact_failure(job, &artifact, "artifact_malformed", true)
                .await;
        };
        if scan.schema_version != 1
            || record.path != format!("artifact.{extension}")
            || !record.module.eq_ignore_ascii_case(&record.path)
            || record.artifact_type != artifact.artifact_type
            || record.architecture.as_deref() != Some(artifact.architecture.as_str())
            || record.debug_id.as_deref() != Some(artifact.debug_id.as_str())
            || record.code_id != artifact.code_id
            || record.size != Some(expected_size)
            || !matches!(record.match_state.as_str(), "matched" | "missing_companion")
            || !record.matches.is_empty()
            || record.error.is_some()
        {
            return self
                .publish_artifact_failure(job, &artifact, "artifact_mismatch", false)
                .await;
        }
        self.publish_artifact(job, &artifact, record).await
    }

    async fn generate_symcache(&self, job: &Job) -> Result<(), JobError> {
        let cache_id = job
            .derived_cache_id
            .as_deref()
            .ok_or(JobError::Deterministic("missing_cache"))?;
        let row = sqlx::query(
            "SELECT c.id::text AS id, c.object_key AS cache_key, c.processor_version, c.format_version, o.object_key AS source_key, o.checksum AS source_checksum, o.byte_size AS source_size, d.debug_id, d.architecture FROM derived_symbol_caches c JOIN artifact_objects o ON o.id = c.source_object_id AND o.organization_id = c.organization_id JOIN artifact_debug_images d ON d.object_id = o.id AND d.organization_id = o.organization_id AND d.artifact_type = 'pdb' WHERE c.id::text = $1 AND c.organization_id::text = $2 AND c.project_id::text = $3 AND c.state IN ('pending', 'processing') LIMIT 1",
        )
        .bind(cache_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?
        .ok_or(JobError::Deterministic("cache_source_missing"))?;
        let attempt = AttemptDirectory::new(&self.scratch, &job.id, &job.lease_token)?;
        let source = attempt.input().join("artifact.pdb");
        let source_size: i64 = row.get("source_size");
        let expected_size = u64::try_from(source_size)
            .map_err(|_| JobError::Deterministic("cache_source_invalid"))?;
        let source_checksum: Vec<u8> = row.get("source_checksum");
        let (size, checksum) = self
            .objects
            .download_to(row.get("source_key"), &source, expected_size)
            .await
            .map_err(map_cache_object_error)?;
        if size != expected_size || checksum.as_slice() != source_checksum.as_slice() {
            return Err(JobError::Deterministic("cache_source_mismatch"));
        }
        self.mark_cache_processing(job).await?;
        let cache_path = attempt.path().join("artifact.symcache");
        let output = self
            .run_processor(
                job,
                ProcessorOperation::GenerateSymcache,
                &attempt,
                Some(&cache_path),
            )
            .await?;
        let metadata: CacheOutput = strict_json(&output.stdout)?;
        let expected_debug_id: String = row.get("debug_id");
        let expected_architecture: String = row.get("architecture");
        let expected_processor: String = row.get("processor_version");
        let expected_format: i32 = row.get("format_version");
        if metadata.schema_version != 1
            || metadata.processor_version != expected_processor
            || metadata.processor_version != SYMCACHE_PROCESSOR_VERSION
            || metadata.format_version != expected_format
            || metadata.format_version
                != i32::try_from(SYMCACHE_FORMAT_VERSION)
                    .map_err(|_| JobError::Deterministic("cache_format_invalid"))?
            || metadata.debug_id != expected_debug_id
            || metadata.architecture != expected_architecture
        {
            return Err(JobError::Deterministic("cache_output_invalid"));
        }
        let (cache_size, cache_checksum) = hash_file(&cache_path, MAX_CACHE_BYTES).await?;
        if cache_size != metadata.byte_size {
            return Err(JobError::Deterministic("cache_output_invalid"));
        }
        let cache_key: String = row.get("cache_key");
        self.publish_cache(
            job,
            cache_id,
            &cache_key,
            &cache_path,
            &cache_checksum,
            cache_size,
        )
        .await
    }

    async fn process_crash(&self, job: &Job) -> Result<(), JobError> {
        let event_id = job
            .event_id
            .as_deref()
            .ok_or(JobError::Deterministic("missing_event"))?;
        let row = sqlx::query(
            "SELECT e.crash_guid, o.object_key, o.checksum, o.byte_size FROM crash_events e JOIN crash_event_objects o ON o.id = e.raw_object_id AND o.organization_id = e.organization_id AND o.project_id = e.project_id WHERE e.id::text = $1 AND e.organization_id::text = $2 AND e.project_id::text = $3",
        )
        .bind(event_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?
        .ok_or(JobError::Deterministic("event_missing"))?;
        let crash_guid: String = row.get("crash_guid");
        let attempt = AttemptDirectory::new(&self.scratch, &job.id, &job.lease_token)?;
        let raw = attempt.input().join("raw.bundle");
        let byte_size: i64 = row.get("byte_size");
        let expected_size =
            u64::try_from(byte_size).map_err(|_| JobError::Deterministic("raw_size_invalid"))?;
        if expected_size > MAX_RAW_BYTES {
            return Err(JobError::Deterministic("raw_size_invalid"));
        }
        let expected_checksum: Vec<u8> = row.get("checksum");
        let object_key: String = row.get("object_key");
        let (size, checksum) = self
            .objects
            .download_to(&object_key, &raw, expected_size)
            .await
            .map_err(map_crash_object_error)?;
        if size != expected_size || checksum.as_slice() != expected_checksum.as_slice() {
            return Err(JobError::Deterministic("raw_object_mismatch"));
        }
        fs::create_dir(attempt.input().join("symbols"))
            .map_err(|_| JobError::Transient("scratch_unavailable"))?;
        fs::write(attempt.input().join("symcaches.json"), br#"{"entries":[]}"#)
            .map_err(|_| JobError::Transient("scratch_unavailable"))?;
        let inspection = self
            .run_processor(job, ProcessorOperation::ProcessCrash, &attempt, None)
            .await?;
        let inspected: Value = strict_json(&inspection.stdout)?;
        validate_processing_result(&inspected, Some(&crash_guid))?;
        let selection = self.materialize_symbols(job, &attempt, &inspected).await?;
        let (result, state, reason) = match selection {
            SymbolSelection::Dependency => return Err(JobError::Dependency),
            SymbolSelection::Missing => (inspected, "awaiting_symbols", "matching_symbols_missing"),
            SymbolSelection::Ready(entries) => {
                fs::write(
                    attempt.input().join("symcaches.json"),
                    serde_json::to_vec(&json!({ "entries": entries }))
                        .map_err(|_| JobError::Deterministic("cache_manifest_invalid"))?,
                )
                .map_err(|_| JobError::Transient("scratch_unavailable"))?;
                let output = self
                    .run_processor(job, ProcessorOperation::ProcessCrash, &attempt, None)
                    .await?;
                let result: Value = strict_json(&output.stdout)?;
                validate_processing_result(&result, Some(&crash_guid))?;
                if has_resolved_frame(&result) {
                    (result, "processed", "processing_complete")
                } else {
                    (result, "awaiting_symbols", "matching_symbols_missing")
                }
            }
        };
        self.publish_crash_result(job, event_id, result, state, reason)
            .await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keeps tenant-scoped symbol selection in one auditable flow"
    )]
    async fn materialize_symbols(
        &self,
        job: &Job,
        attempt: &AttemptDirectory,
        result: &Value,
    ) -> Result<SymbolSelection, JobError> {
        let context = result
            .get("crash_context")
            .and_then(Value::as_object)
            .ok_or(JobError::Deterministic("processor_output_invalid"))?;
        let Some(version) = context.get("build_version").and_then(Value::as_str) else {
            return Ok(SymbolSelection::Missing);
        };
        let Some(platform) = context
            .get("platform")
            .and_then(|value| value.get("normalized"))
            .and_then(Value::as_str)
        else {
            return Ok(SymbolSelection::Missing);
        };
        let Some(architecture) = context.get("architecture").and_then(Value::as_str) else {
            return Ok(SymbolSelection::Missing);
        };
        let Some(configuration) = context.get("build_configuration").and_then(Value::as_str) else {
            return Ok(SymbolSelection::Missing);
        };
        let releases = sqlx::query_scalar::<_, String>(
            "SELECT id::text FROM releases WHERE organization_id::text = $1 AND project_id::text = $2 AND version = $3 AND platform = $4 AND architecture = $5 AND lower(configuration) = lower($6) ORDER BY id LIMIT 2",
        )
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(version)
        .bind(platform)
        .bind(architecture)
        .bind(configuration)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        let [release_id] = releases.as_slice() else {
            return Ok(SymbolSelection::Missing);
        };
        let modules = processing_modules(result)?;
        let rows = sqlx::query(
            "SELECT m.artifact_type, m.module_name, m.architecture, m.debug_id, m.code_id, o.id::text AS object_id, o.object_key, o.checksum, o.byte_size FROM release_manifest_artifacts m JOIN artifact_debug_images d ON d.id = m.debug_image_id AND d.organization_id = m.organization_id AND d.processing_status = 'available' JOIN artifact_objects o ON o.id = d.object_id AND o.organization_id = d.organization_id AND o.lifecycle_state = 'stored' WHERE m.release_id::text = $1 AND m.organization_id::text = $2 AND m.project_id::text = $3 AND m.state = 'available'",
        )
        .bind(release_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        let mut selected = Vec::new();
        for row in rows {
            let artifact = SelectedArtifact::from_row(&row);
            if modules
                .iter()
                .any(|module| artifact.matches_module(module, architecture))
                && selected
                    .iter()
                    .all(|selected: &SelectedArtifact| selected.object_id != artifact.object_id)
            {
                selected.push(artifact);
            }
        }
        if selected.is_empty() || !selected_artifact_size_valid(&selected) {
            return Ok(SymbolSelection::Missing);
        }
        let symbols = attempt.input().join("symbols");
        for artifact in selected
            .iter()
            .filter(|artifact| artifact.artifact_type != "pdb")
        {
            let extension = if artifact.artifact_type == "pe_executable" {
                "exe"
            } else {
                "dll"
            };
            let path = symbols.join(format!("{}.{}", lower_hex(&artifact.checksum), extension));
            let expected_size = u64::try_from(artifact.byte_size)
                .map_err(|_| JobError::Deterministic("artifact_size_invalid"))?;
            let (size, checksum) = self
                .objects
                .download_to(&artifact.object_key, &path, expected_size)
                .await
                .map_err(map_artifact_object_error)?;
            if size != expected_size || checksum.as_slice() != artifact.checksum.as_slice() {
                return Err(JobError::Deterministic("artifact_object_mismatch"));
            }
        }
        let mut entries = Vec::new();
        for artifact in selected
            .iter()
            .filter(|artifact| artifact.artifact_type == "pdb")
        {
            let cache = self.ensure_cache(job, artifact).await?;
            match cache {
                CacheState::Pending => return Ok(SymbolSelection::Dependency),
                CacheState::Unavailable => {}
                CacheState::Available {
                    key,
                    checksum,
                    size,
                } => {
                    let file = format!("{}.symcache", lower_hex(&checksum));
                    let path = symbols.join(&file);
                    let (actual_size, actual_checksum) = self
                        .objects
                        .download_to(&key, &path, size)
                        .await
                        .map_err(map_cache_object_error)?;
                    if actual_size != size || actual_checksum != checksum {
                        return Err(JobError::Deterministic("cache_object_mismatch"));
                    }
                    entries.push(CacheManifestEntry {
                        debug_id: artifact.debug_id.clone(),
                        file,
                    });
                }
            }
        }
        if entries.is_empty() {
            Ok(SymbolSelection::Missing)
        } else {
            Ok(SymbolSelection::Ready(entries))
        }
    }

    async fn ensure_cache(
        &self,
        job: &Job,
        artifact: &SelectedArtifact,
    ) -> Result<CacheState, JobError> {
        let id = random_uuid().map_err(|_| JobError::Transient("random_unavailable"))?;
        let key = format!(
            "org/{}/derived/{}/{}/{}/symcache",
            job.organization_id,
            lower_hex(&artifact.checksum),
            SYMCACHE_PROCESSOR_VERSION,
            SYMCACHE_FORMAT_VERSION
        );
        let row = sqlx::query(
            "INSERT INTO derived_symbol_caches (id, organization_id, project_id, source_object_id, processor_version, format_version, cache_kind, object_key) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, 'symcache', $7) ON CONFLICT (organization_id, source_object_id, processor_version, format_version, cache_kind) DO UPDATE SET updated_at = derived_symbol_caches.updated_at RETURNING id::text AS id, project_id::text AS project_id, state, object_key, checksum, byte_size",
        )
        .bind(&id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(&artifact.object_id)
        .bind(SYMCACHE_PROCESSOR_VERSION)
        .bind(i32::try_from(SYMCACHE_FORMAT_VERSION).map_err(|_| JobError::Deterministic("cache_format_invalid"))?)
        .bind(&key)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        let state: String = row.get("state");
        if state == "available" {
            let checksum: Vec<u8> = row.get("checksum");
            let size: i64 = row.get("byte_size");
            return Ok(CacheState::Available {
                key: row.get("object_key"),
                checksum: checksum
                    .try_into()
                    .map_err(|_| JobError::Deterministic("cache_checksum_invalid"))?,
                size: u64::try_from(size)
                    .map_err(|_| JobError::Deterministic("cache_size_invalid"))?,
            });
        }
        if matches!(state.as_str(), "failed" | "quarantined") {
            return Ok(CacheState::Unavailable);
        }
        let cache_id: String = row.get("id");
        let cache_project_id: String = row.get("project_id");
        let cache_job_id = random_uuid().map_err(|_| JobError::Transient("random_unavailable"))?;
        sqlx::query(
            "INSERT INTO jobs (id, organization_id, project_id, event_id, derived_cache_id, job_type, payload, priority, idempotency_key) VALUES ($1::uuid, $2::uuid, $3::uuid, NULL, $4::uuid, 'generate_symcache', $5, 50, $6) ON CONFLICT (idempotency_key) DO NOTHING",
        )
        .bind(cache_job_id)
        .bind(&job.organization_id)
        .bind(cache_project_id)
        .bind(&cache_id)
        .bind(json!({ "derived_cache_id": cache_id }))
        .bind(format!("generate_symcache:{cache_id}"))
        .execute(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        Ok(CacheState::Pending)
    }

    async fn run_processor(
        &self,
        job: &Job,
        operation: ProcessorOperation,
        attempt: &AttemptDirectory,
        copied_output: Option<&Path>,
    ) -> Result<ProcessorOutput, JobError> {
        let name = container_name(&job.id, &job.lease_token);
        self.runner
            .run(
                operation,
                attempt.input(),
                &name,
                &job.id,
                &job.lease_token,
                copied_output,
            )
            .await
            .map_err(|error| match error {
                RunnerError::Unavailable | RunnerError::InvalidImage => {
                    JobError::Transient("processor_unavailable")
                }
                RunnerError::ResourceLimit => JobError::Resource("processor_resource_limit"),
                RunnerError::Rejected | RunnerError::InvalidOutput => {
                    JobError::Deterministic("processor_rejected")
                }
            })
    }

    async fn publish_artifact(
        &self,
        job: &Job,
        artifact: &ArtifactSession,
        record: &IndexRecord,
    ) -> Result<(), JobError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        lock_lease(&mut transaction, job, self.instance_id.as_ref()).await?;
        let object = sqlx::query(
            "INSERT INTO artifact_objects (organization_id, object_key, checksum, byte_size) VALUES ($1::uuid, $2, $3, $4) ON CONFLICT (organization_id, checksum) DO UPDATE SET checksum = EXCLUDED.checksum RETURNING id::text AS id, object_key",
        )
        .bind(&job.organization_id)
        .bind(&artifact.object_key)
        .bind(&artifact.checksum)
        .bind(artifact.byte_size)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        let object_id: String = object.get("id");
        let canonical_key: String = object.get("object_key");
        let debug_image_id: String = sqlx::query_scalar(
            "INSERT INTO artifact_debug_images (organization_id, object_id, artifact_type, module_name, architecture, debug_id, code_id) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7) ON CONFLICT (organization_id, object_id, artifact_type, debug_id, COALESCE(code_id, '')) DO UPDATE SET processing_status = 'available' RETURNING id::text",
        )
        .bind(&job.organization_id)
        .bind(&object_id)
        .bind(&record.artifact_type)
        .bind(&artifact.module_name)
        .bind(record.architecture.as_deref().unwrap_or_default())
        .bind(record.debug_id.as_deref().unwrap_or_default())
        .bind(&record.code_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        let manifest = sqlx::query(
            "UPDATE release_manifest_artifacts SET debug_image_id = $4::uuid, state = 'available', failure_code = NULL, uploaded_at = now(), updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'processing' AND checksum = $5 AND byte_size = $6 AND artifact_type = $7 AND module_name = $8 AND architecture = $9 AND debug_id = $10 AND code_id IS NOT DISTINCT FROM $11",
        )
        .bind(&artifact.manifest_artifact_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(debug_image_id)
        .bind(&artifact.checksum)
        .bind(artifact.byte_size)
        .bind(&artifact.artifact_type)
        .bind(&artifact.module_name)
        .bind(&artifact.architecture)
        .bind(&artifact.debug_id)
        .bind(&artifact.code_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if manifest.rows_affected() != 1 {
            return Err(JobError::LostLease);
        }
        let session = sqlx::query(
            "UPDATE artifact_upload_sessions SET state = 'completed', failure_code = NULL, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'processing' AND checksum = $4 AND byte_size = $5 AND artifact_type = $6 AND module_name = $7 AND architecture = $8 AND debug_id = $9 AND code_id IS NOT DISTINCT FROM $10",
        )
        .bind(&artifact.id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(&artifact.checksum)
        .bind(artifact.byte_size)
        .bind(&artifact.artifact_type)
        .bind(&artifact.module_name)
        .bind(&artifact.architecture)
        .bind(&artifact.debug_id)
        .bind(&artifact.code_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if session.rows_affected() != 1 {
            return Err(JobError::LostLease);
        }
        complete_job(&mut transaction, job, self.instance_id.as_ref(), None).await?;
        transaction
            .commit()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        if canonical_key != artifact.object_key {
            self.objects.delete_object(&artifact.object_key).await;
        }
        Ok(())
    }

    async fn publish_artifact_failure(
        &self,
        job: &Job,
        artifact: &ArtifactSession,
        code: &'static str,
        quarantine: bool,
    ) -> Result<(), JobError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        lock_lease(&mut transaction, job, self.instance_id.as_ref()).await?;
        let session = sqlx::query(
            "UPDATE artifact_upload_sessions SET state = 'failed', failure_code = $4, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'processing' AND checksum = $5 AND byte_size = $6 AND artifact_type = $7 AND module_name = $8 AND architecture = $9 AND debug_id = $10 AND code_id IS NOT DISTINCT FROM $11",
        )
        .bind(&artifact.id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(code)
        .bind(&artifact.checksum)
        .bind(artifact.byte_size)
        .bind(&artifact.artifact_type)
        .bind(&artifact.module_name)
        .bind(&artifact.architecture)
        .bind(&artifact.debug_id)
        .bind(&artifact.code_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if session.rows_affected() != 1 {
            return Err(JobError::LostLease);
        }
        let manifest = sqlx::query(
            "UPDATE release_manifest_artifacts SET state = $4, failure_code = CASE WHEN $4 = 'quarantined' THEN $5 ELSE NULL END, debug_image_id = NULL, uploaded_at = NULL, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'processing' AND checksum = $6 AND byte_size = $7 AND artifact_type = $8 AND module_name = $9 AND architecture = $10 AND debug_id = $11 AND code_id IS NOT DISTINCT FROM $12",
        )
        .bind(&artifact.manifest_artifact_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(if quarantine { "quarantined" } else { "mismatch" })
        .bind(code)
        .bind(&artifact.checksum)
        .bind(artifact.byte_size)
        .bind(&artifact.artifact_type)
        .bind(&artifact.module_name)
        .bind(&artifact.architecture)
        .bind(&artifact.debug_id)
        .bind(&artifact.code_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if manifest.rows_affected() != 1 {
            return Err(JobError::LostLease);
        }
        complete_job(&mut transaction, job, self.instance_id.as_ref(), Some(code)).await?;
        transaction
            .commit()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        self.objects.delete_object(&artifact.object_key).await;
        Ok(())
    }

    async fn mark_cache_processing(&self, job: &Job) -> Result<(), JobError> {
        let updated = sqlx::query(
            "UPDATE derived_symbol_caches c SET state = 'processing', updated_at = now() FROM jobs j WHERE c.id = j.derived_cache_id AND c.organization_id = j.organization_id AND c.project_id = j.project_id AND j.id::text = $1 AND j.organization_id::text = $2 AND j.project_id::text = $3 AND j.state = 'leased' AND j.lease_owner = $4 AND j.lease_token::text = $5 AND j.lease_expires_at > now()",
        )
        .bind(&job.id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(self.instance_id.as_ref())
        .bind(&job.lease_token)
        .execute(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if updated.rows_affected() == 1 {
            Ok(())
        } else {
            Err(JobError::LostLease)
        }
    }

    async fn publish_cache(
        &self,
        job: &Job,
        cache_id: &str,
        cache_key: &str,
        cache_path: &Path,
        checksum: &[u8; 32],
        size: u64,
    ) -> Result<(), JobError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        lock_lease(&mut transaction, job, self.instance_id.as_ref()).await?;
        self.objects
            .put_from_path(cache_key, cache_path)
            .await
            .map_err(map_cache_object_error)?;
        let updated = sqlx::query(
            "UPDATE derived_symbol_caches SET state = 'available', checksum = $4, byte_size = $5, failure_code = NULL, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'processing' AND object_key = $6",
        )
        .bind(cache_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(checksum.as_slice())
        .bind(i64::try_from(size).map_err(|_| JobError::Deterministic("cache_size_invalid"))?)
        .bind(cache_key)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if updated.rows_affected() != 1 {
            return Err(JobError::LostLease);
        }
        complete_job(&mut transaction, job, self.instance_id.as_ref(), None).await?;
        transaction
            .commit()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))
    }

    async fn publish_crash_result(
        &self,
        job: &Job,
        event_id: &str,
        result: Value,
        state: &str,
        reason: &str,
    ) -> Result<(), JobError> {
        let bytes = serde_json::to_vec(&result)
            .map_err(|_| JobError::Deterministic("processor_output_invalid"))?;
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        let result_id = random_uuid().map_err(|_| JobError::Transient("random_unavailable"))?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        lock_lease(&mut transaction, job, self.instance_id.as_ref()).await?;
        let stored_id: String = sqlx::query_scalar(
            "INSERT INTO crash_processing_results (id, organization_id, project_id, event_id, schema_version, processing_version, result, checksum) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 1, $5, $6) ON CONFLICT (event_id, processing_version, checksum) DO UPDATE SET checksum = EXCLUDED.checksum RETURNING id::text",
        )
        .bind(result_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(event_id)
        .bind(result)
        .bind(checksum.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        let updated = sqlx::query(
            "UPDATE crash_events SET current_result_id = $4::uuid, processing_state = $5, state_reason = CASE WHEN $5 = 'processed' THEN NULL ELSE $6 END, retryable = false, retry_at = NULL, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3",
        )
        .bind(event_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(stored_id)
        .bind(state)
        .bind(reason)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if updated.rows_affected() != 1 {
            return Err(JobError::LostLease);
        }
        complete_job(&mut transaction, job, self.instance_id.as_ref(), None).await?;
        transaction
            .commit()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))
    }

    async fn wait_for_dependency(&self, job: &Job) -> Result<(), JobError> {
        self.release_job(job, "dependency_pending", 1, false, true)
            .await
    }

    async fn cancel_job(&self, job: &Job) -> Result<(), JobError> {
        self.release_job(job, "processing_cancelled", 0, false, true)
            .await
    }

    async fn retry(&self, job: &Job, code: &'static str, resource: bool) -> Result<(), JobError> {
        let exponent = u32::try_from(job.attempt.saturating_sub(1))
            .unwrap_or(10)
            .min(6);
        let seconds = i64::from(1_u32 << exponent).min(60);
        self.release_job(job, code, seconds, resource, false).await
    }

    async fn release_job(
        &self,
        job: &Job,
        code: &'static str,
        seconds: i64,
        resource: bool,
        dependency: bool,
    ) -> Result<(), JobError> {
        let updated = sqlx::query(
            "UPDATE jobs SET state = 'pending', available_at = now() + ($6 * interval '1 second'), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL, failure_code = $7, resource_failures = resource_failures + CASE WHEN $8 THEN 1 ELSE 0 END, attempt = attempt - CASE WHEN $9 THEN 1 ELSE 0 END, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'leased' AND lease_owner = $4 AND lease_token::text = $5",
        )
        .bind(&job.id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(self.instance_id.as_ref())
        .bind(&job.lease_token)
        .bind(seconds)
        .bind(code)
        .bind(resource)
        .bind(dependency)
        .execute(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if updated.rows_affected() == 1 {
            Ok(())
        } else {
            Err(JobError::LostLease)
        }
    }

    async fn quarantine(&self, job: &Job, code: &'static str) -> Result<(), JobError> {
        self.finish_failure(job, code, true, false).await
    }

    async fn quarantine_resource(&self, job: &Job, code: &'static str) -> Result<(), JobError> {
        self.finish_failure(job, code, true, true).await
    }

    async fn fail(&self, job: &Job, code: &'static str) -> Result<(), JobError> {
        self.finish_failure(job, code, false, false).await
    }

    async fn finish_failure(
        &self,
        job: &Job,
        code: &'static str,
        quarantine: bool,
        resource_failure: bool,
    ) -> Result<(), JobError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        lock_lease(&mut transaction, job, self.instance_id.as_ref()).await?;
        match job.kind.as_str() {
            "process_crash" => {
                let updated = sqlx::query(
                    "UPDATE crash_events SET processing_state = $4, state_reason = $5, retryable = false, retry_at = NULL, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3",
                )
                .bind(job.event_id.as_deref().unwrap_or_default())
                .bind(&job.organization_id)
                .bind(&job.project_id)
                .bind(if quarantine { "quarantined" } else { "failed" })
                .bind(code)
                .execute(&mut *transaction)
                .await
                .map_err(|_| JobError::Transient("database_unavailable"))?;
                if updated.rows_affected() != 1 {
                    return Err(JobError::LostLease);
                }
            }
            "index_artifact" => {
                let session = sqlx::query(
                    "UPDATE artifact_upload_sessions SET state = 'failed', failure_code = $4, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'processing'",
                )
                .bind(job.artifact_upload_id.as_deref().unwrap_or_default())
                .bind(&job.organization_id)
                .bind(&job.project_id)
                .bind(code)
                .execute(&mut *transaction)
                .await
                .map_err(|_| JobError::Transient("database_unavailable"))?;
                if session.rows_affected() != 1 {
                    return Err(JobError::LostLease);
                }
                let manifest = sqlx::query(
                    "UPDATE release_manifest_artifacts m SET state = 'quarantined', failure_code = $4, debug_image_id = NULL, updated_at = now() FROM artifact_upload_sessions s WHERE s.id::text = $1 AND s.organization_id::text = $2 AND s.project_id::text = $3 AND m.id = s.manifest_artifact_id AND m.organization_id = s.organization_id AND m.project_id = s.project_id AND m.state = 'processing'",
                )
                .bind(job.artifact_upload_id.as_deref().unwrap_or_default())
                .bind(&job.organization_id)
                .bind(&job.project_id)
                .bind(code)
                .execute(&mut *transaction)
                .await
                .map_err(|_| JobError::Transient("database_unavailable"))?;
                if manifest.rows_affected() != 1 {
                    return Err(JobError::LostLease);
                }
            }
            "generate_symcache" => {
                let updated = sqlx::query(
                    "UPDATE derived_symbol_caches SET state = $4, failure_code = $5, checksum = NULL, byte_size = NULL, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state IN ('pending', 'processing')",
                )
                .bind(job.derived_cache_id.as_deref().unwrap_or_default())
                .bind(&job.organization_id)
                .bind(&job.project_id)
                .bind(if quarantine { "quarantined" } else { "failed" })
                .bind(code)
                .execute(&mut *transaction)
                .await
                .map_err(|_| JobError::Transient("database_unavailable"))?;
                if updated.rows_affected() != 1 {
                    return Err(JobError::LostLease);
                }
            }
            _ => return Err(JobError::Deterministic("unknown_job_type")),
        }
        let terminal = if quarantine { "failed" } else { "dead" };
        terminal_job(
            &mut transaction,
            job,
            self.instance_id.as_ref(),
            terminal,
            code,
            resource_failure,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))
    }
}

async fn claim_job(pool: &PgPool, worker_id: &str) -> Result<Option<Job>, ()> {
    let lease_token = random_uuid().map_err(|_| ())?;
    let row = sqlx::query(
        "WITH candidate AS (SELECT j.id FROM jobs j JOIN projects p ON p.id = j.project_id AND p.organization_id = j.organization_id WHERE ((j.state = 'pending' AND j.available_at <= now() AND (j.attempt < j.max_attempt OR (j.attempt = j.max_attempt AND j.resource_failures = 1))) OR (j.state = 'leased' AND j.lease_expires_at <= now())) AND NOT EXISTS (SELECT 1 FROM jobs active WHERE active.project_id = j.project_id AND active.id <> j.id AND active.state = 'leased' AND active.lease_expires_at > now()) ORDER BY j.priority, j.available_at, j.created_at FOR UPDATE OF p, j SKIP LOCKED LIMIT 1) UPDATE jobs j SET state = 'leased', attempt = j.attempt + 1, lease_owner = $1, lease_token = $2::uuid, lease_expires_at = now() + ($3 * interval '1 second'), heartbeat_at = now(), updated_at = now() FROM candidate WHERE j.id = candidate.id RETURNING j.id::text AS id, j.organization_id::text AS organization_id, j.project_id::text AS project_id, j.event_id::text AS event_id, j.artifact_upload_id::text AS artifact_upload_id, j.derived_cache_id::text AS derived_cache_id, j.job_type, j.attempt, j.max_attempt, j.resource_failures, j.lease_token::text AS lease_token",
    )
    .bind(worker_id)
    .bind(&lease_token)
    .bind(LEASE_SECONDS)
    .fetch_optional(pool)
    .await
    .map_err(|_| ())?;
    Ok(row.map(|row| Job {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        project_id: row.get("project_id"),
        event_id: row.get("event_id"),
        artifact_upload_id: row.get("artifact_upload_id"),
        derived_cache_id: row.get("derived_cache_id"),
        kind: row.get("job_type"),
        attempt: row.get("attempt"),
        max_attempt: row.get("max_attempt"),
        resource_failures: row.get("resource_failures"),
        lease_token: row.get("lease_token"),
    }))
}

#[derive(Clone)]
struct Job {
    id: String,
    organization_id: String,
    project_id: String,
    event_id: Option<String>,
    artifact_upload_id: Option<String>,
    derived_cache_id: Option<String>,
    kind: String,
    attempt: i32,
    max_attempt: i32,
    resource_failures: i32,
    lease_token: String,
}

enum JobError {
    LostLease,
    Dependency,
    Deterministic(&'static str),
    Resource(&'static str),
    Transient(&'static str),
}

struct AttemptDirectory {
    path: PathBuf,
    input: PathBuf,
}

impl AttemptDirectory {
    fn new(root: &Path, job_id: &str, lease_token: &str) -> Result<Self, JobError> {
        let path = root.join(format!("attempt-{job_id}-{lease_token}"));
        fs::create_dir(&path).map_err(|_| JobError::Transient("scratch_unavailable"))?;
        let input = path.join("input");
        let attempt = Self { path, input };
        set_private_permissions(&attempt.path)
            .map_err(|_| JobError::Transient("scratch_unavailable"))?;
        fs::create_dir(&attempt.input).map_err(|_| JobError::Transient("scratch_unavailable"))?;
        set_private_permissions(&attempt.input)
            .map_err(|_| JobError::Transient("scratch_unavailable"))?;
        Ok(attempt)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn input(&self) -> &Path {
        &self.input
    }
}

impl Drop for AttemptDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct ArtifactSession {
    id: String,
    manifest_artifact_id: String,
    object_key: String,
    checksum: Vec<u8>,
    byte_size: i64,
    artifact_type: String,
    module_name: String,
    architecture: String,
    debug_id: String,
    code_id: Option<String>,
}

impl ArtifactSession {
    fn from_row(row: &sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            manifest_artifact_id: row.get("manifest_artifact_id"),
            object_key: row.get("object_key"),
            checksum: row.get("checksum"),
            byte_size: row.get("byte_size"),
            artifact_type: row.get("artifact_type"),
            module_name: row.get("module_name"),
            architecture: row.get("architecture"),
            debug_id: row.get("debug_id"),
            code_id: row.get("code_id"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexOutput {
    schema_version: u32,
    artifacts: Vec<IndexRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexRecord {
    path: String,
    module: String,
    artifact_type: String,
    architecture: Option<String>,
    size: Option<u64>,
    debug_id: Option<String>,
    code_id: Option<String>,
    match_state: String,
    matches: Vec<String>,
    error: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheOutput {
    schema_version: u32,
    processor_version: String,
    format_version: i32,
    debug_id: String,
    architecture: String,
    byte_size: u64,
}

#[derive(serde::Serialize)]
struct CacheManifestEntry {
    debug_id: String,
    file: String,
}

enum SymbolSelection {
    Dependency,
    Missing,
    Ready(Vec<CacheManifestEntry>),
}

struct ModuleIdentity {
    module: String,
    debug_id: Option<String>,
    code_id: Option<String>,
}

struct SelectedArtifact {
    object_id: String,
    object_key: String,
    checksum: Vec<u8>,
    byte_size: i64,
    artifact_type: String,
    module_name: String,
    architecture: String,
    debug_id: String,
    code_id: Option<String>,
}

impl SelectedArtifact {
    fn from_row(row: &sqlx::postgres::PgRow) -> Self {
        Self {
            object_id: row.get("object_id"),
            object_key: row.get("object_key"),
            checksum: row.get("checksum"),
            byte_size: row.get("byte_size"),
            artifact_type: row.get("artifact_type"),
            module_name: row.get("module_name"),
            architecture: row.get("architecture"),
            debug_id: row.get("debug_id"),
            code_id: row.get("code_id"),
        }
    }

    fn matches_module(&self, module: &ModuleIdentity, architecture: &str) -> bool {
        self.architecture.eq_ignore_ascii_case(architecture)
            && if self.artifact_type == "pdb" {
                module.debug_id.as_deref() == Some(self.debug_id.as_str())
            } else {
                self.module_name.eq_ignore_ascii_case(&module.module)
                    && module.debug_id.as_deref() == Some(self.debug_id.as_str())
                    && self.code_id == module.code_id
            }
    }
}

fn selected_artifact_size_valid(artifacts: &[SelectedArtifact]) -> bool {
    artifacts
        .iter()
        .try_fold(0_u64, |total, artifact| {
            let size = u64::try_from(artifact.byte_size).ok()?;
            if size > MAX_ARTIFACT_BYTES {
                return None;
            }
            total.checked_add(size)
        })
        .is_some_and(|total| total <= MAX_SELECTED_ARTIFACT_BYTES)
}

enum CacheState {
    Pending,
    Unavailable,
    Available {
        key: String,
        checksum: [u8; 32],
        size: u64,
    },
}

async fn lock_lease(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    worker_id: &str,
) -> Result<(), JobError> {
    let found: Option<String> = sqlx::query_scalar(
        "UPDATE jobs SET heartbeat_at = now(), lease_expires_at = now() + ($6 * interval '1 second'), updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'leased' AND lease_owner = $4 AND lease_token::text = $5 AND lease_expires_at > now() RETURNING id::text",
    )
    .bind(&job.id)
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(worker_id)
    .bind(&job.lease_token)
    .bind(LEASE_SECONDS)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    found.map_or(Err(JobError::LostLease), |_| Ok(()))
}

async fn complete_job(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    worker_id: &str,
    failure_code: Option<&str>,
) -> Result<(), JobError> {
    let updated = sqlx::query(
        "UPDATE jobs SET state = 'completed', failure_code = $6, completed_at = now(), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'leased' AND lease_owner = $4 AND lease_token::text = $5",
    )
    .bind(&job.id)
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(worker_id)
    .bind(&job.lease_token)
    .bind(failure_code)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(JobError::LostLease)
    }
}

async fn terminal_job(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    worker_id: &str,
    state: &str,
    code: &str,
    resource_failure: bool,
) -> Result<(), JobError> {
    let updated = sqlx::query(
        "UPDATE jobs SET state = $6, failure_code = $7, resource_failures = resource_failures + CASE WHEN $8 THEN 1 ELSE 0 END, completed_at = now(), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL, updated_at = now() WHERE id::text = $1 AND organization_id::text = $2 AND project_id::text = $3 AND state = 'leased' AND lease_owner = $4 AND lease_token::text = $5",
    )
    .bind(&job.id)
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(worker_id)
    .bind(&job.lease_token)
    .bind(state)
    .bind(code)
    .bind(resource_failure)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(JobError::LostLease)
    }
}

fn processing_modules(result: &Value) -> Result<Vec<ModuleIdentity>, JobError> {
    result
        .pointer("/current/symbolication/modules")
        .and_then(Value::as_array)
        .ok_or(JobError::Deterministic("processor_output_invalid"))?
        .iter()
        .map(|module| {
            Ok(ModuleIdentity {
                module: module
                    .get("module")
                    .and_then(Value::as_str)
                    .ok_or(JobError::Deterministic("processor_output_invalid"))?
                    .to_owned(),
                debug_id: module
                    .get("debug_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                code_id: module
                    .get("code_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            })
        })
        .collect()
}

fn validate_processing_result(result: &Value, expected_guid: Option<&str>) -> Result<(), JobError> {
    faultlane_processing::validate_processing_result(result, expected_guid).map_err(|error| {
        match error {
            faultlane_processing::ProcessingResultError::PreviousIdentityMismatch => {
                JobError::Deterministic("crash_identity_mismatch")
            }
            _ => JobError::Deterministic("processor_output_invalid"),
        }
    })?;
    processing_modules(result).map(|_| ())
}

fn has_resolved_frame(result: &Value) -> bool {
    result
        .pointer("/current/symbolication/threads")
        .and_then(Value::as_array)
        .is_some_and(|threads| {
            threads.iter().any(|thread| {
                thread
                    .get("frames")
                    .and_then(Value::as_array)
                    .is_some_and(|frames| {
                        frames.iter().any(|frame| {
                            frame.get("symbol_status").and_then(Value::as_str) == Some("resolved")
                        })
                    })
            })
        })
}

fn strict_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, JobError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)
        .map_err(|_| JobError::Deterministic("processor_output_invalid"))?;
    deserializer
        .end()
        .map_err(|_| JobError::Deterministic("processor_output_invalid"))?;
    Ok(value)
}

async fn hash_file(path: &Path, maximum: u64) -> Result<(u64, [u8; 32]), JobError> {
    use tokio::io::AsyncReadExt as _;

    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| JobError::Deterministic("cache_output_invalid"))?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(JobError::Resource("cache_output_limit"));
    }
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| JobError::Deterministic("cache_output_invalid"))?;
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|_| JobError::Deterministic("cache_output_invalid"))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).map_err(|_| JobError::Resource("cache_output_limit"))?)
            .filter(|size| *size <= maximum)
            .ok_or(JobError::Resource("cache_output_limit"))?;
        digest.update(&buffer[..read]);
    }
    Ok((size, digest.finalize().into()))
}

fn map_artifact_object_error(error: ObjectError) -> JobError {
    match error {
        ObjectError::Unavailable => JobError::Transient("object_store_unavailable"),
        ObjectError::Missing => JobError::Transient("artifact_object_missing"),
        ObjectError::Invalid => JobError::Deterministic("artifact_object_invalid"),
    }
}

fn map_cache_object_error(error: ObjectError) -> JobError {
    match error {
        ObjectError::Unavailable => JobError::Transient("object_store_unavailable"),
        ObjectError::Missing => JobError::Transient("cache_object_missing"),
        ObjectError::Invalid => JobError::Deterministic("cache_object_invalid"),
    }
}

fn map_crash_object_error(error: ObjectError) -> JobError {
    match error {
        ObjectError::Unavailable => JobError::Transient("object_store_unavailable"),
        ObjectError::Missing => JobError::Transient("raw_object_missing"),
        ObjectError::Invalid => JobError::Deterministic("raw_object_invalid"),
    }
}

fn worker_scratch() -> Result<PathBuf, WorkerStartupError> {
    let path = env::var("FAULTLANE_WORKER_SCRATCH_DIR")
        .map_or_else(|_| env::temp_dir().join("faultlane-worker"), PathBuf::from);
    prepare_worker_scratch(&path)?;
    Ok(path)
}

fn prepare_worker_scratch(path: &Path) -> Result<(), WorkerStartupError> {
    let marker = path.join(".faultlane-worker-scratch");
    let existed = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(WorkerStartupError::Scratch);
            }
            if fs::read(&marker).map_err(|_| WorkerStartupError::Scratch)? != SCRATCH_MARKER {
                return Err(WorkerStartupError::Scratch);
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| WorkerStartupError::Scratch)?;
            false
        }
        Err(_) => return Err(WorkerStartupError::Scratch),
    };
    let metadata = fs::symlink_metadata(path).map_err(|_| WorkerStartupError::Scratch)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(WorkerStartupError::Scratch);
    }
    set_private_permissions(path).map_err(|_| WorkerStartupError::Scratch)?;
    if !existed {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options
            .open(marker)
            .map_err(|_| WorkerStartupError::Scratch)?;
        file.write_all(SCRATCH_MARKER)
            .and_then(|()| file.sync_all())
            .map_err(|_| WorkerStartupError::Scratch)?;
    }
    Ok(())
}

fn processor_scope(database_url: &str) -> Result<String, WorkerStartupError> {
    let mut database = Url::parse(database_url).map_err(|_| WorkerStartupError::Configuration)?;
    if !matches!(database.scheme(), "postgres" | "postgresql") {
        return Err(WorkerStartupError::Configuration);
    }
    database
        .set_username("")
        .map_err(|()| WorkerStartupError::Configuration)?;
    database
        .set_password(None)
        .map_err(|()| WorkerStartupError::Configuration)?;
    database.set_fragment(None);
    Ok(lower_hex(&Sha256::digest(database.as_str().as_bytes())))
}

fn owned_attempt(container: &OwnedContainer) -> Option<(&str, &str)> {
    let job_id = container.job_id.as_deref()?;
    let lease_token = container.lease_token.as_deref()?;
    if valid_internal_uuid(job_id)
        && valid_internal_uuid(lease_token)
        && container.name == container_name(job_id, lease_token)
    {
        Some((job_id, lease_token))
    } else {
        None
    }
}

fn attempt_identity(value: &str) -> Option<(&str, &str)> {
    let value = value.strip_prefix("attempt-")?;
    let job_id = value.get(..36)?;
    if value.as_bytes().get(36) != Some(&b'-') {
        return None;
    }
    let lease_token = value.get(37..)?;
    if valid_internal_uuid(job_id) && valid_internal_uuid(lease_token) {
        Some((job_id, lease_token))
    } else {
        None
    }
}

fn remove_attempt_directory(
    root: &Path,
    job_id: &str,
    lease_token: &str,
) -> Result<(), WorkerStartupError> {
    let path = root.join(format!("attempt-{job_id}-{lease_token}"));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(WorkerStartupError::Scratch),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(WorkerStartupError::Scratch);
    }
    fs::remove_dir_all(path).map_err(|_| WorkerStartupError::Scratch)
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn set_private_permissions(path: &Path) -> Result<(), std::io::Error> {
    let identity = std::process::Command::new(windows_system_tool("whoami.exe")?)
        .args(["/user", "/fo", "csv", "/nh"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()?;
    if !identity.status.success() {
        return Err(std::io::Error::other("could not resolve worker identity"));
    }
    let identity = String::from_utf8_lossy(&identity.stdout);
    let start = identity
        .find("S-1-")
        .ok_or_else(|| std::io::Error::other("worker identity has no SID"))?;
    let sid: String = identity[start..]
        .chars()
        .take_while(|character| character.is_ascii_digit() || matches!(*character, 'S' | '-'))
        .collect();
    if sid.len() < 7 {
        return Err(std::io::Error::other("worker identity SID is invalid"));
    }
    let user = format!("*{sid}:(OI)(CI)F");
    let system = "*S-1-5-18:(OI)(CI)F";
    let icacls = windows_system_tool("icacls.exe")?;
    let reset = std::process::Command::new(&icacls)
        .arg(path)
        .arg("/reset")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !reset.success() {
        return Err(std::io::Error::other("could not reset worker scratch"));
    }
    let status = std::process::Command::new(&icacls)
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &user, system])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other("could not restrict worker scratch"));
    }
    verify_private_windows_acl(path, &sid, &icacls)
}

#[cfg(windows)]
fn verify_private_windows_acl(path: &Path, sid: &str, icacls: &Path) -> Result<(), std::io::Error> {
    let dump = env::temp_dir().join(format!(
        "faultlane-acl-{}.txt",
        random_uuid().map_err(std::io::Error::other)?
    ));
    let status = std::process::Command::new(icacls)
        .arg(path)
        .arg("/save")
        .arg(&dump)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let result = status.and_then(|status| {
        if !status.success() {
            return Err(std::io::Error::other("could not inspect worker scratch"));
        }
        let bytes = fs::read(&dump)?;
        let descriptor = decode_windows_acl(&bytes)?;
        if windows_acl_is_private(&descriptor, sid) {
            Ok(())
        } else {
            Err(std::io::Error::other("worker scratch ACL is not private"))
        }
    });
    let _ = fs::remove_file(dump);
    result
}

#[cfg(windows)]
fn decode_windows_acl(bytes: &[u8]) -> Result<String, std::io::Error> {
    let bytes = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
    let mut chunks = bytes.chunks_exact(2);
    let units: Vec<u16> = chunks
        .by_ref()
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    if !chunks.remainder().is_empty() {
        return Err(std::io::Error::other("worker scratch ACL is invalid"));
    }
    String::from_utf16(&units).map_err(std::io::Error::other)
}

#[cfg(windows)]
fn windows_acl_is_private(descriptor: &str, sid: &str) -> bool {
    let Some((dacl, first_ace)) = descriptor
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("D:"))
        .find_map(|line| {
            let first_ace = line.find('(')?;
            line[2..first_ace]
                .contains('P')
                .then_some((line, first_ace))
        })
    else {
        return false;
    };
    let mut actual: Vec<&str> = dacl[first_ace..]
        .split('(')
        .skip(1)
        .filter_map(|ace| ace.strip_suffix(')'))
        .collect();
    if actual.iter().any(|ace| ace.contains(['(', ')'])) {
        return false;
    }
    let user = match sid {
        "S-1-5-18" => "SY",
        "S-1-5-19" => "LS",
        "S-1-5-20" => "NS",
        value => value,
    };
    let system = "A;OICI;FA;;;SY";
    let user = format!("A;OICI;FA;;;{user}");
    let mut expected = vec![system, user.as_str()];
    actual.sort_unstable();
    actual.dedup();
    expected.sort_unstable();
    expected.dedup();
    actual == expected
}

#[cfg(windows)]
fn windows_system_tool(name: &str) -> Result<PathBuf, std::io::Error> {
    let root = env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| std::io::Error::other("Windows system root is invalid"))?;
    let path = root.join("System32").join(name);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::other("Windows system tool is invalid"));
    }
    Ok(path)
}

fn container_name(job_id: &str, lease_token: &str) -> String {
    format!(
        "faultlane-{}-{}",
        job_id.replace('-', ""),
        lease_token.replace('-', "")
    )
}

fn valid_internal_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn required_env(name: &str) -> Result<String, WorkerStartupError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(WorkerStartupError::Configuration)
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

fn lower_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        sync::{Arc, Mutex},
    };

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use sqlx::{PgPool, Row, postgres::PgPoolOptions};

    use super::{
        JobError, ModuleIdentity, SelectedArtifact, Worker, attempt_identity, claim_job,
        container_name, has_resolved_frame, lock_lease, owned_attempt, prepare_worker_scratch,
        processor_scope, random_uuid, selected_artifact_size_valid, set_private_permissions,
        strict_json, valid_internal_uuid,
    };
    use crate::project_setup::{DATABASE_TEST_LOCK, migrate};
    use crate::{
        processor_runner::{OwnedContainer, ProcessorRunner},
        symbol_upload::{ArtifactObjects, MemoryObjects},
    };

    #[test]
    fn container_names_use_only_internal_identifiers() {
        let name = container_name(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        );
        assert_eq!(
            name,
            "faultlane-aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa-bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn processor_scope_is_stable_across_credential_rotation() {
        let first =
            processor_scope("postgres://first:secret@db.example:5432/faultlane?sslmode=require")
                .unwrap_or_else(|error| panic!("first scope must resolve: {error}"));
        let second =
            processor_scope("postgres://second:changed@db.example:5432/faultlane?sslmode=require")
                .unwrap_or_else(|error| panic!("second scope must resolve: {error}"));
        let other = processor_scope("postgres://second:changed@db.example:5432/other")
            .unwrap_or_else(|error| panic!("other scope must resolve: {error}"));
        assert_eq!(first, second);
        assert_ne!(first, other);
        assert_eq!(first.len(), 64);
    }

    #[cfg(windows)]
    #[test]
    fn windows_acl_parser_ignores_drive_paths() {
        let sid = "S-1-5-21-1000";
        let descriptor =
            format!("D:\\a\\faultlane\\scratch\r\nD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})\r\n");
        assert!(super::windows_acl_is_private(&descriptor, sid));
    }

    #[cfg(windows)]
    #[test]
    fn windows_scratch_acl_uses_system_tools() {
        let path = env::temp_dir().join(format!(
            "faultlane-private-scratch-test-{}",
            std::process::id()
        ));
        std::fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("scratch test directory must be created: {error}"));
        let broad = std::process::Command::new(
            super::windows_system_tool("icacls.exe")
                .unwrap_or_else(|error| panic!("icacls must exist: {error}")),
        )
        .arg(&path)
        .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap_or_else(|error| panic!("broad scratch ACL must be applied: {error}"));
        assert!(broad.success());
        set_private_permissions(&path)
            .unwrap_or_else(|error| panic!("scratch ACL must be applied: {error}"));
        std::fs::remove_dir(&path)
            .unwrap_or_else(|error| panic!("scratch test directory must be removed: {error}"));
    }

    #[test]
    fn owned_attempt_requires_matching_internal_labels() {
        let job_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let lease_token = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let valid = OwnedContainer {
            name: container_name(job_id, lease_token),
            job_id: Some(job_id.to_owned()),
            lease_token: Some(lease_token.to_owned()),
        };
        assert_eq!(owned_attempt(&valid), Some((job_id, lease_token)));

        let malformed = OwnedContainer {
            name: valid.name.clone(),
            job_id: Some("../../outside".to_owned()),
            lease_token: valid.lease_token.clone(),
        };
        assert_eq!(owned_attempt(&malformed), None);
        assert!(valid_internal_uuid(job_id));
        assert!(!valid_internal_uuid("../../outside"));
    }

    #[test]
    fn attempt_directories_require_exact_internal_identifiers() {
        let name =
            "attempt-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        assert_eq!(
            attempt_identity(name),
            Some((
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            ))
        );
        assert!(attempt_identity("attempt-untrusted").is_none());
        assert!(
            attempt_identity("attempt-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa-../escape").is_none()
        );
    }

    #[test]
    fn worker_scratch_reuses_only_owned_directories() {
        let owned = env::temp_dir().join(format!(
            "faultlane-owned-scratch-test-{}",
            random_uuid().unwrap_or_else(|error| panic!("test UUID must generate: {error}"))
        ));
        prepare_worker_scratch(&owned)
            .unwrap_or_else(|error| panic!("new scratch must be prepared: {error}"));
        prepare_worker_scratch(&owned)
            .unwrap_or_else(|error| panic!("owned scratch must be reusable: {error}"));
        assert_eq!(
            std::fs::read(owned.join(".faultlane-worker-scratch"))
                .unwrap_or_else(|error| panic!("scratch marker must be readable: {error}")),
            super::SCRATCH_MARKER
        );
        std::fs::remove_dir_all(&owned)
            .unwrap_or_else(|error| panic!("owned scratch must be removed: {error}"));

        let unowned = env::temp_dir().join(format!(
            "faultlane-unowned-scratch-test-{}",
            random_uuid().unwrap_or_else(|error| panic!("test UUID must generate: {error}"))
        ));
        std::fs::create_dir(&unowned)
            .unwrap_or_else(|error| panic!("unowned directory must be created: {error}"));
        let sentinel = unowned.join("keep.txt");
        std::fs::write(&sentinel, b"keep")
            .unwrap_or_else(|error| panic!("sentinel must be written: {error}"));
        assert!(prepare_worker_scratch(&unowned).is_err());
        assert_eq!(
            std::fs::read(&sentinel)
                .unwrap_or_else(|error| panic!("sentinel must remain readable: {error}")),
            b"keep"
        );
        std::fs::remove_dir_all(&unowned)
            .unwrap_or_else(|error| panic!("unowned directory must be removed: {error}"));
    }

    #[tokio::test]
    async fn reconciliation_removes_stale_scratch_without_touching_unknown_entries() {
        let Ok(database_url) = env::var("FAULTLANE_TEST_DATABASE_URL") else {
            return;
        };
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must migrate: {error}"));
        let pool = PgPoolOptions::new()
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        let root = env::temp_dir().join(format!(
            "faultlane-reconciliation-test-{}",
            random_uuid().unwrap_or_else(|error| panic!("test UUID must generate: {error}"))
        ));
        std::fs::create_dir(&root)
            .unwrap_or_else(|error| panic!("scratch root must be created: {error}"));
        set_private_permissions(&root)
            .unwrap_or_else(|error| panic!("scratch root must be private: {error}"));
        let job_id =
            random_uuid().unwrap_or_else(|error| panic!("job UUID must generate: {error}"));
        let lease_token =
            random_uuid().unwrap_or_else(|error| panic!("lease UUID must generate: {error}"));
        let stale = root.join(format!("attempt-{job_id}-{lease_token}"));
        let unknown = root.join("leave-unknown-entry");
        std::fs::create_dir(&stale)
            .unwrap_or_else(|error| panic!("stale attempt must be created: {error}"));
        std::fs::create_dir(&unknown)
            .unwrap_or_else(|error| panic!("unknown entry must be created: {error}"));
        let worker = Worker {
            pool,
            objects: ArtifactObjects::Memory(Arc::new(Mutex::new(MemoryObjects::default()))),
            runner: ProcessorRunner::test(),
            scratch: Arc::new(root.clone()),
            instance_id: Arc::from("reconciliation-test"),
        };
        worker
            .reconcile_attempt_directories()
            .await
            .unwrap_or_else(|error| panic!("scratch reconciliation must succeed: {error}"));
        assert!(!stale.exists());
        assert!(unknown.exists());
        std::fs::remove_dir_all(&root)
            .unwrap_or_else(|error| panic!("scratch root must be removed: {error}"));
    }

    #[test]
    fn artifact_selection_requires_the_release_architecture() {
        let module = ModuleIdentity {
            module: "game.exe".to_owned(),
            debug_id: Some("DEBUG".to_owned()),
            code_id: Some("CODE".to_owned()),
        };
        let artifact = SelectedArtifact {
            object_id: String::new(),
            object_key: String::new(),
            checksum: Vec::new(),
            byte_size: 0,
            artifact_type: "pe_executable".to_owned(),
            module_name: "game.exe".to_owned(),
            architecture: "x86_64".to_owned(),
            debug_id: "DEBUG".to_owned(),
            code_id: Some("CODE".to_owned()),
        };
        assert!(artifact.matches_module(&module, "x86_64"));
        assert!(!artifact.matches_module(&module, "arm64"));
        assert!(!artifact.matches_module(
            &ModuleIdentity {
                module: "game.exe".to_owned(),
                debug_id: None,
                code_id: Some("CODE".to_owned()),
            },
            "x86_64"
        ));

        let oversized = SelectedArtifact {
            byte_size: i64::try_from(super::MAX_ARTIFACT_BYTES + 1)
                .unwrap_or_else(|error| panic!("test size must fit: {error}")),
            ..artifact
        };
        assert!(!selected_artifact_size_valid(&[oversized]));
    }

    #[test]
    fn strict_output_rejects_trailing_data() {
        let result = strict_json::<Value>(br"{}{}");
        assert!(result.is_err());
    }

    #[test]
    fn resolved_frames_control_the_processed_state() {
        let result = json!({
            "current": {"symbolication": {"threads": [{"frames": [
                {"symbol_status": "unresolved"},
                {"symbol_status": "resolved"}
            ]}]}}
        });
        assert!(has_resolved_frame(&result));
    }

    async fn insert_event_job(
        pool: &PgPool,
        organization_id: &str,
        project_id: &str,
        suffix: &str,
    ) -> String {
        let ingest_key_id: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, $4) RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(Sha256::digest(format!("key-{suffix}")).to_vec())
        .bind(suffix)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("ingest key must insert: {error}"));
        let object_id: String = sqlx::query_scalar(
            "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3, $4, 1, 'application/octet-stream') RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(format!("test/{suffix}"))
        .bind(vec![0_u8; 32])
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("event object must insert: {error}"));
        let event_id: String = sqlx::query_scalar(
            "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, environment) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'production') RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(ingest_key_id)
        .bind(object_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("event must insert: {error}"));
        sqlx::query_scalar(
            "INSERT INTO jobs (id, organization_id, project_id, event_id, job_type, payload, idempotency_key) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, 'process_crash', '{}'::jsonb, $4) RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(event_id)
        .bind(format!("worker-test-{suffix}"))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("job must insert: {error}"))
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn claims_are_fair_and_stale_leases_cannot_publish_when_configured() {
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
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Worker test', 'worker-test') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("organization must insert: {error}"));
        let projects = sqlx::query(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'First', 'first'), ($1::uuid, 'Second', 'second') RETURNING id::text AS id, slug",
        )
        .bind(&organization_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("projects must insert: {error}"));
        let first_project: String = projects
            .iter()
            .find(|row| row.get::<String, _>("slug") == "first")
            .map_or_else(|| panic!("first project must exist"), |row| row.get("id"));
        let second_project: String = projects
            .iter()
            .find(|row| row.get::<String, _>("slug") == "second")
            .map_or_else(|| panic!("second project must exist"), |row| row.get("id"));
        let _ = insert_event_job(&pool, &organization_id, &first_project, "first-a").await;
        let _ = insert_event_job(&pool, &organization_id, &first_project, "first-b").await;
        let _ = insert_event_job(&pool, &organization_id, &second_project, "second-a").await;

        let (left, right) = tokio::join!(
            claim_job(&pool, "worker-left"),
            claim_job(&pool, "worker-right")
        );
        let left = left
            .unwrap_or_else(|()| panic!("left claim must succeed"))
            .unwrap_or_else(|| panic!("left claim must find work"));
        let right = right
            .unwrap_or_else(|()| panic!("right claim must succeed"))
            .unwrap_or_else(|| panic!("right claim must find work"));
        assert_ne!(left.project_id, right.project_id);

        let (stale, stale_owner) = if left.project_id == first_project {
            (left, "worker-left")
        } else {
            (right, "worker-right")
        };
        sqlx::query(
            "UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id::text = $1",
        )
        .bind(&stale.id)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("lease must expire: {error}"));
        sqlx::query(
            "UPDATE jobs SET available_at = now() + interval '1 hour' WHERE project_id::text = $1 AND state = 'pending'",
        )
        .bind(&stale.project_id)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("other work must defer: {error}"));
        let reclaimed = claim_job(&pool, "worker-new")
            .await
            .unwrap_or_else(|()| panic!("reclaim must succeed"))
            .unwrap_or_else(|| panic!("expired lease must be reclaimed"));
        assert_eq!(reclaimed.id, stale.id);
        assert_ne!(reclaimed.lease_token, stale.lease_token);

        let mut stale_transaction = pool
            .begin()
            .await
            .unwrap_or_else(|error| panic!("transaction must begin: {error}"));
        assert!(matches!(
            lock_lease(&mut stale_transaction, &stale, stale_owner).await,
            Err(JobError::LostLease)
        ));
        stale_transaction
            .rollback()
            .await
            .unwrap_or_else(|error| panic!("transaction must roll back: {error}"));
        let mut current_transaction = pool
            .begin()
            .await
            .unwrap_or_else(|error| panic!("transaction must begin: {error}"));
        lock_lease(&mut current_transaction, &reclaimed, "worker-new")
            .await
            .unwrap_or_else(|_| panic!("current lease must publish"));
        current_transaction
            .rollback()
            .await
            .unwrap_or_else(|error| panic!("transaction must roll back: {error}"));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn resource_failures_retry_once_quarantine_and_do_not_block_when_configured() {
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
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Resource test', 'resource-test') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("organization must insert: {error}"));
        let projects = sqlx::query(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Unsafe', 'unsafe'), ($1::uuid, 'Unrelated', 'unrelated') RETURNING id::text AS id, slug",
        )
        .bind(&organization_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("projects must insert: {error}"));
        let unsafe_project: String = projects
            .iter()
            .find(|row| row.get::<String, _>("slug") == "unsafe")
            .map_or_else(|| panic!("unsafe project must exist"), |row| row.get("id"));
        let unrelated_project: String = projects
            .iter()
            .find(|row| row.get::<String, _>("slug") == "unrelated")
            .map_or_else(
                || panic!("unrelated project must exist"),
                |row| row.get("id"),
            );
        let resource_job_id =
            insert_event_job(&pool, &organization_id, &unsafe_project, "resource").await;
        sqlx::query("UPDATE jobs SET max_attempt = 1 WHERE id::text = $1")
            .bind(&resource_job_id)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("resource retry budget must be constrained: {error}"));
        let worker = Worker {
            pool: pool.clone(),
            objects: ArtifactObjects::Memory(Arc::new(Mutex::new(MemoryObjects::default()))),
            runner: ProcessorRunner::test(),
            scratch: Arc::new(env::temp_dir()),
            instance_id: Arc::from("worker-resource"),
        };
        let first = claim_job(&pool, "worker-resource")
            .await
            .unwrap_or_else(|()| panic!("first claim must succeed"))
            .unwrap_or_else(|| panic!("resource job must be claimed"));
        assert_eq!(first.id, resource_job_id);
        worker
            .finish_result(&first, Err(JobError::Resource("processor_resource_limit")))
            .await;
        let retry = sqlx::query(
            "SELECT state, attempt, resource_failures, failure_code FROM jobs WHERE id::text = $1",
        )
        .bind(&resource_job_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("retry state must load: {error}"));
        assert_eq!(retry.get::<String, _>("state"), "pending");
        assert_eq!(retry.get::<i32, _>("attempt"), 1);
        assert_eq!(retry.get::<i32, _>("resource_failures"), 1);
        assert_eq!(
            retry.get::<Option<String>, _>("failure_code").as_deref(),
            Some("processor_resource_limit")
        );
        sqlx::query("UPDATE jobs SET available_at = now() WHERE id::text = $1")
            .bind(&resource_job_id)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("resource retry must become available: {error}"));
        let waiting = claim_job(&pool, "worker-resource")
            .await
            .unwrap_or_else(|()| panic!("second claim must succeed"))
            .unwrap_or_else(|| panic!("resource retry must be claimed"));
        assert_eq!(waiting.id, resource_job_id);
        assert_eq!(waiting.resource_failures, 1);
        worker
            .finish_result(&waiting, Err(JobError::Dependency))
            .await;
        let dependency = sqlx::query(
            "SELECT state, attempt, resource_failures, failure_code FROM jobs WHERE id::text = $1",
        )
        .bind(&resource_job_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("dependency state must load: {error}"));
        assert_eq!(dependency.get::<String, _>("state"), "pending");
        assert_eq!(dependency.get::<i32, _>("attempt"), 1);
        assert_eq!(dependency.get::<i32, _>("resource_failures"), 1);
        assert_eq!(
            dependency
                .get::<Option<String>, _>("failure_code")
                .as_deref(),
            Some("dependency_pending")
        );
        sqlx::query("UPDATE jobs SET available_at = now() WHERE id::text = $1")
            .bind(&resource_job_id)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("dependency retry must become available: {error}"));
        let second = claim_job(&pool, "worker-resource")
            .await
            .unwrap_or_else(|()| panic!("post-dependency claim must succeed"))
            .unwrap_or_else(|| panic!("resource retry must survive dependency wait"));
        assert_eq!(second.id, resource_job_id);
        assert_eq!(second.resource_failures, 1);
        worker
            .finish_result(&second, Err(JobError::Resource("processor_resource_limit")))
            .await;
        let terminal = sqlx::query(
            "SELECT j.state, j.attempt, j.resource_failures, e.processing_state FROM jobs j JOIN crash_events e ON e.id = j.event_id AND e.organization_id = j.organization_id AND e.project_id = j.project_id WHERE j.id::text = $1",
        )
        .bind(&resource_job_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("terminal state must load: {error}"));
        assert_eq!(terminal.get::<String, _>("state"), "failed");
        assert_eq!(terminal.get::<i32, _>("attempt"), 2);
        assert_eq!(terminal.get::<i32, _>("resource_failures"), 2);
        assert_eq!(terminal.get::<String, _>("processing_state"), "quarantined");

        let cancelled_job =
            insert_event_job(&pool, &organization_id, &unsafe_project, "cancel").await;
        let cancelled = claim_job(&pool, "worker-resource")
            .await
            .unwrap_or_else(|()| panic!("cancel claim must succeed"))
            .unwrap_or_else(|| panic!("cancelled job must be claimed"));
        worker
            .cancel_job(&cancelled)
            .await
            .unwrap_or_else(|_| panic!("cancellation must release the lease"));
        let attempt: i32 = sqlx::query_scalar("SELECT attempt FROM jobs WHERE id::text = $1")
            .bind(&cancelled_job)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|error| panic!("cancelled attempt must load: {error}"));
        assert_eq!(attempt, 0);
        sqlx::query("UPDATE jobs SET available_at = now() + interval '1 hour' WHERE id::text = $1")
            .bind(&cancelled_job)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("cancelled job must defer: {error}"));

        let unrelated_job =
            insert_event_job(&pool, &organization_id, &unrelated_project, "unrelated").await;
        let claimed = claim_job(&pool, "worker-unrelated")
            .await
            .unwrap_or_else(|()| panic!("unrelated claim must succeed"))
            .unwrap_or_else(|| panic!("unrelated work must be available"));
        assert_eq!(claimed.id, unrelated_job);
        assert_eq!(claimed.project_id, unrelated_project);
        let unrelated_worker = Worker {
            instance_id: Arc::from("worker-unrelated"),
            ..worker.clone()
        };
        unrelated_worker
            .cancel_job(&claimed)
            .await
            .unwrap_or_else(|_| panic!("unrelated lease must release"));
        sqlx::query("UPDATE jobs SET available_at = now() + interval '1 hour' WHERE id::text = $1")
            .bind(&unrelated_job)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("unrelated job must defer: {error}"));

        let transient_job =
            insert_event_job(&pool, &organization_id, &unrelated_project, "transient").await;
        let transient_worker = Worker {
            instance_id: Arc::from("worker-transient"),
            ..worker
        };
        for attempt in 1..=5 {
            let claimed = claim_job(&pool, "worker-transient")
                .await
                .unwrap_or_else(|()| panic!("transient claim must succeed"))
                .unwrap_or_else(|| panic!("transient job must be claimed"));
            assert_eq!(claimed.id, transient_job);
            assert_eq!(claimed.attempt, attempt);
            transient_worker
                .finish_result(
                    &claimed,
                    Err(JobError::Transient("object_store_unavailable")),
                )
                .await;
            let state: String = sqlx::query_scalar("SELECT state FROM jobs WHERE id::text = $1")
                .bind(&transient_job)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("transient state must load: {error}"));
            if attempt < 5 {
                assert_eq!(state, "pending");
                sqlx::query("UPDATE jobs SET available_at = now() WHERE id::text = $1")
                    .bind(&transient_job)
                    .execute(&pool)
                    .await
                    .unwrap_or_else(|error| panic!("transient retry must become ready: {error}"));
            } else {
                assert_eq!(state, "dead");
            }
        }
        let failed_state: String =
            sqlx::query_scalar("SELECT processing_state FROM crash_events WHERE id = (SELECT event_id FROM jobs WHERE id::text = $1)")
                .bind(&transient_job)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("failed event must load: {error}"));
        assert_eq!(failed_state, "failed");
    }
}
