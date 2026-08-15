use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt, fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use faultlane_symbols::{SYMCACHE_FORMAT_VERSION, SYMCACHE_PROCESSOR_VERSION};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use tokio::{sync::watch, task::JoinSet};
use tracing::{info, warn};
use url::Url;

use crate::{
    processor_runner::{
        OwnedContainer, ProcessorOperation, ProcessorOutput, ProcessorRunner, RunnerError,
    },
    symbol_upload::{ArtifactObjects, ObjectError},
};

const LEASE_SECONDS: i64 = 300;
const REPROCESSING_REQUEST_LEASE_SECONDS: i64 = 60;
const HEARTBEAT_SECONDS: u64 = 30;
const POLL_MILLISECONDS: u64 = 250;
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SELECTED_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_RAW_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PREVIOUS_RESULT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SEARCH_COMMENT_CHARS: usize = 8_192;
const MAX_STORED_RELEASE_CANDIDATES: i64 = 101;
const MAX_SYMBOL_WAITERS: usize = 4_096;
const AUTOMATIC_REPROCESSING_BATCH: usize = 100;
const JOBS_BETWEEN_REPROCESSING_REQUESTS: u32 = 20;
const MAX_WORKER_CONCURRENCY: u32 = 8;
const MAX_PROJECT_CONCURRENCY: u32 = 8;
const SCRATCH_MARKER: &[u8] = b"faultlane-worker-scratch-v1\n";

pub(crate) async fn run() -> Result<(), WorkerStartupError> {
    let database_url = required_env("DATABASE_URL")?;
    let processor_scope = processor_scope(&database_url)?;
    let settings = WorkerSettings::from_environment()?;
    let pool = PgPoolOptions::new()
        .max_connections(settings.pool_connections())
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
        grouping_enabled: env::var("FAULTLANE_GROUPING_ENABLED")
            .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
        reprocessing_enabled: env::var("FAULTLANE_REPROCESSING_ENABLED")
            .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
    };
    worker.reconcile_containers().await?;
    worker.run_loop(settings).await
}

#[derive(Clone, Copy)]
struct WorkerSettings {
    worker_concurrency: usize,
    project_concurrency: i64,
}

impl WorkerSettings {
    fn from_environment() -> Result<Self, WorkerStartupError> {
        Self::parse(
            env::var("FAULTLANE_WORKER_CONCURRENCY").ok().as_deref(),
            env::var("FAULTLANE_PROJECT_CONCURRENCY").ok().as_deref(),
        )
    }

    fn parse(
        worker_concurrency: Option<&str>,
        project_concurrency: Option<&str>,
    ) -> Result<Self, WorkerStartupError> {
        let worker_concurrency = parse_concurrency(worker_concurrency, MAX_WORKER_CONCURRENCY)?;
        let project_concurrency = parse_concurrency(project_concurrency, MAX_PROJECT_CONCURRENCY)?;
        Ok(Self {
            worker_concurrency: usize::try_from(worker_concurrency)
                .map_err(|_| WorkerStartupError::Configuration)?,
            project_concurrency: i64::from(project_concurrency),
        })
    }

    fn pool_connections(self) -> u32 {
        u32::try_from(self.worker_concurrency)
            .unwrap_or(MAX_WORKER_CONCURRENCY)
            .saturating_mul(2)
            .saturating_add(4)
    }
}

fn parse_concurrency(value: Option<&str>, maximum: u32) -> Result<u32, WorkerStartupError> {
    let value = value
        .unwrap_or("1")
        .parse::<u32>()
        .map_err(|_| WorkerStartupError::Configuration)?;
    if !(1..=maximum).contains(&value) {
        return Err(WorkerStartupError::Configuration);
    }
    Ok(value)
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

#[derive(serde::Serialize)]
pub(crate) struct RepairIssueReport {
    events: i64,
    variants: i64,
    releases: i64,
}

#[derive(Debug)]
pub(crate) enum RepairIssueError {
    InvalidIdentifier,
    NotFound,
    Database,
}

impl fmt::Display for RepairIssueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "repair issue identifiers are invalid",
            Self::NotFound => "repair issue target was not found",
            Self::Database => "repair issue database operation failed",
        })
    }
}

impl std::error::Error for RepairIssueError {}

pub(crate) async fn repair_issue(
    database_url: &str,
    organization_id: &str,
    project_id: &str,
    issue_id: &str,
) -> Result<RepairIssueReport, RepairIssueError> {
    if !crate::identifiers::valid_uuid(organization_id)
        || !crate::identifiers::valid_uuid(project_id)
        || !crate::identifiers::valid_uuid(issue_id)
    {
        return Err(RepairIssueError::InvalidIdentifier);
    }
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .map_err(|_| RepairIssueError::Database)?;
    let mut transaction = pool.begin().await.map_err(|_| RepairIssueError::Database)?;
    let found: Option<bool> = sqlx::query_scalar(
        "SELECT true FROM issues WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid FOR UPDATE",
    )
    .bind(issue_id)
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| RepairIssueError::Database)?;
    if found.is_none() {
        return Err(RepairIssueError::NotFound);
    }
    refresh_issue_memberships(&mut transaction, organization_id, project_id, issue_id)
        .await
        .map_err(|error| map_repair_error(&error))?;
    update_issue_transitions(
        &mut transaction,
        organization_id,
        project_id,
        issue_id,
        true,
    )
    .await
    .map_err(|error| map_repair_error(&error))?;
    let row = sqlx::query(
        "SELECT i.event_count, (SELECT count(*) FROM issue_variants v WHERE v.organization_id = i.organization_id AND v.project_id = i.project_id AND v.issue_id = i.id) AS variant_count, (SELECT count(*) FROM issue_releases r WHERE r.organization_id = i.organization_id AND r.project_id = i.project_id AND r.issue_id = i.id) AS release_count FROM issues i WHERE i.id = $1::uuid AND i.organization_id = $2::uuid AND i.project_id = $3::uuid",
    )
    .bind(issue_id)
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| RepairIssueError::Database)?;
    let report = RepairIssueReport {
        events: row.get("event_count"),
        variants: row.get("variant_count"),
        releases: row.get("release_count"),
    };
    transaction
        .commit()
        .await
        .map_err(|_| RepairIssueError::Database)?;
    Ok(report)
}

fn map_repair_error(error: &JobError) -> RepairIssueError {
    match error {
        JobError::Deterministic("issue_missing") => RepairIssueError::NotFound,
        _ => RepairIssueError::Database,
    }
}

#[derive(Clone)]
struct Worker {
    pool: PgPool,
    objects: ArtifactObjects,
    runner: ProcessorRunner,
    scratch: Arc<PathBuf>,
    instance_id: Arc<str>,
    grouping_enabled: bool,
    reprocessing_enabled: bool,
}

impl Worker {
    #[allow(clippy::too_many_lines)]
    async fn run_loop(&self, settings: WorkerSettings) -> Result<(), WorkerStartupError> {
        info!(
            worker_id = self.instance_id.as_ref(),
            worker_concurrency = settings.worker_concurrency,
            project_concurrency = settings.project_concurrency,
            database_connections = settings.pool_connections(),
            "worker started"
        );
        let mut reconciliation = tokio::time::interval(Duration::from_secs(30));
        reconciliation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        reconciliation.tick().await;
        let mut jobs_since_reprocessing = 0_u32;
        let mut running = JoinSet::<(Job, i64)>::new();
        let mut active = BTreeMap::<String, Job>::new();
        let mut wait = Duration::ZERO;
        loop {
            if running.len() < settings.worker_concurrency && wait.is_zero() {
                if self.reprocessing_enabled
                    && jobs_since_reprocessing >= JOBS_BETWEEN_REPROCESSING_REQUESTS
                {
                    if self.schedule_reprocessing_request().await.is_err() {
                        warn!("reprocessing request scheduling failed");
                    }
                    jobs_since_reprocessing = 0;
                }
                let claim_started = Instant::now();
                match self.claim(settings.project_concurrency).await {
                    Ok(Some(job)) => {
                        jobs_since_reprocessing = jobs_since_reprocessing.saturating_add(1);
                        info!(
                            worker_id = self.instance_id.as_ref(),
                            job_id = job.id,
                            project_id = job.project_id,
                            active_jobs = running.len().saturating_add(1),
                            project_active_jobs = job.project_active_jobs,
                            queue_age_seconds = job.queue_age_seconds,
                            claim_duration_ms = i64::try_from(claim_started.elapsed().as_millis())
                                .unwrap_or(i64::MAX),
                            "worker job claimed"
                        );
                        active.insert(job.id.clone(), job.clone());
                        let worker = self.clone();
                        running.spawn(async move {
                            let started = Instant::now();
                            let completed = job.clone();
                            worker.run_job(job).await;
                            (
                                completed,
                                i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
                            )
                        });
                        continue;
                    }
                    Ok(None) => {
                        let scheduled = self.reprocessing_enabled
                            && self
                                .schedule_reprocessing_request()
                                .await
                                .unwrap_or_else(|()| {
                                    warn!("reprocessing request scheduling failed");
                                    false
                                });
                        jobs_since_reprocessing = 0;
                        if scheduled {
                            continue;
                        }
                        wait = Duration::from_millis(POLL_MILLISECONDS);
                    }
                    Err(()) => {
                        warn!("worker claim failed");
                        wait = Duration::from_secs(1);
                    }
                }
            }
            tokio::select! {
                completed = running.join_next(), if !running.is_empty() => {
                    match completed {
                        Some(Ok((job, duration_ms))) => {
                            active.remove(&job.id);
                            info!(
                                worker_id = self.instance_id.as_ref(),
                                job_id = job.id,
                                active_jobs = running.len(),
                                duration_ms,
                                "worker job finished"
                            );
                            wait = Duration::ZERO;
                        }
                        Some(Err(_)) => {
                            warn!("worker job task failed");
                            self.stop_running_jobs(&mut running, &active).await;
                            return Err(WorkerStartupError::Processor);
                        }
                        None => {}
                    }
                }
                shutdown = tokio::signal::ctrl_c() => {
                    shutdown.map_err(|_| WorkerStartupError::Configuration)?;
                    self.stop_running_jobs(&mut running, &active).await;
                    info!("worker stopped");
                    return Ok(());
                }
                _ = reconciliation.tick() => {
                    if self.reconcile_containers().await.is_err() {
                        warn!("worker container reconciliation failed");
                    }
                }
                () = tokio::time::sleep(wait), if !wait.is_zero() => {
                    wait = Duration::ZERO;
                }
            }
        }
    }

    async fn stop_running_jobs(
        &self,
        running: &mut JoinSet<(Job, i64)>,
        active: &BTreeMap<String, Job>,
    ) {
        running.abort_all();
        while running.join_next().await.is_some() {}
        let mut cancellations = JoinSet::new();
        for job in active.values().cloned() {
            let worker = self.clone();
            cancellations.spawn(async move {
                worker
                    .runner
                    .cancel(&container_name(&job.id, &job.lease_token))
                    .await;
                let _ = worker.cancel_job(&job).await;
            });
        }
        while cancellations.join_next().await.is_some() {}
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
            "SELECT EXISTS (SELECT 1 FROM jobs WHERE id = $1::uuid AND state = 'leased' AND lease_token = $2::uuid AND lease_expires_at > now())",
        )
        .bind(job_id)
        .bind(lease_token)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| WorkerStartupError::Database)
    }

    async fn claim(&self, project_concurrency: i64) -> Result<Option<Job>, ()> {
        claim_job_with_project_limit(&self.pool, self.instance_id.as_ref(), project_concurrency)
            .await
    }

    async fn schedule_reprocessing_request(&self) -> Result<bool, ()> {
        let reconciled = reconcile_reprocessing_event_jobs(&self.pool).await?;
        let Some(request) =
            claim_reprocessing_request(&self.pool, self.instance_id.as_ref()).await?
        else {
            return Ok(reconciled);
        };
        if request.exhausted {
            finish_reprocessing_schedule_failure(
                &self.pool,
                &request,
                self.instance_id.as_ref(),
                "reprocessing_schedule_failed",
            )
            .await
            .map_err(|_| ())?;
            return Ok(true);
        }
        if self.expand_reprocessing_request(&request).await.is_err() {
            finish_reprocessing_schedule_failure(
                &self.pool,
                &request,
                self.instance_id.as_ref(),
                "reprocessing_schedule_failed",
            )
            .await
            .map_err(|_| ())?;
        }
        Ok(true)
    }

    async fn expand_reprocessing_request(&self, request: &ReprocessingRequest) -> Result<(), ()> {
        let mut transaction = self.pool.begin().await.map_err(|_| ())?;
        lock_reprocessing_request(&mut transaction, request, self.instance_id.as_ref())
            .await
            .map_err(|_| ())?;
        let mut candidates = if request.source == "automatic" {
            automatic_reprocessing_candidates(&mut transaction, request)
                .await
                .map_err(|_| ())?
        } else {
            manual_reprocessing_candidates(&mut transaction, request)
                .await
                .map_err(|_| ())?
        };
        let limit = if request.source == "automatic" {
            AUTOMATIC_REPROCESSING_BATCH
        } else {
            usize::try_from(request.request_limit.ok_or(())?).map_err(|_| ())?
        };
        let truncated = candidates.len() > limit;
        candidates.truncate(limit);
        let event_ids = candidates
            .iter()
            .map(|candidate| candidate.event_id.clone())
            .collect::<Vec<_>>();
        schedule_reprocessing_events(&mut transaction, request, &event_ids)
            .await
            .map_err(|_| ())?;
        let cursor = candidates
            .last()
            .map(|candidate| candidate.event_id.as_str());
        if request.source == "automatic" && truncated {
            release_reprocessing_request_page(
                &mut transaction,
                request,
                self.instance_id.as_ref(),
                cursor,
            )
            .await
            .map_err(|_| ())?;
        } else {
            complete_reprocessing_selection(
                &mut transaction,
                request,
                self.instance_id.as_ref(),
                truncated,
                truncated.then_some(cursor).flatten(),
            )
            .await
            .map_err(|_| ())?;
        }
        refresh_reprocessing_request(&mut transaction, &request.id)
            .await
            .map_err(|_| ())?;
        transaction.commit().await.map_err(|_| ())
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
                "delete_raw" => self.delete_raw(&job).await,
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
                        let updated = sqlx::query("UPDATE jobs SET heartbeat_at = now(), lease_expires_at = now() + ($6 * interval '1 second'), updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'leased' AND lease_owner = $4 AND lease_token = $5::uuid")
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
            "SELECT s.id::text AS id, s.release_id::text AS release_id, s.manifest_artifact_id::text AS manifest_artifact_id, s.upload_token_id::text AS upload_token_id, s.uploaded_by_user_id::text AS uploaded_by_user_id, s.object_key, s.checksum, s.byte_size, s.artifact_type, s.module_name, s.architecture, s.debug_id, s.code_id, s.ci_job, s.cli_version FROM artifact_upload_sessions s WHERE s.id = $1::uuid AND s.organization_id = $2::uuid AND s.project_id = $3::uuid AND s.state = 'processing'",
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
            "SELECT c.id::text AS id, c.object_key AS cache_key, c.processor_version, c.format_version, o.object_key AS source_key, o.checksum AS source_checksum, o.byte_size AS source_size, d.debug_id, d.architecture FROM derived_symbol_caches c JOIN artifact_objects o ON o.id = c.source_object_id AND o.organization_id = c.organization_id JOIN artifact_debug_images d ON d.object_id = o.id AND d.organization_id = o.organization_id AND d.artifact_type = 'pdb' WHERE c.id = $1::uuid AND c.organization_id = $2::uuid AND c.project_id = $3::uuid AND c.state IN ('pending', 'processing') LIMIT 1",
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
            "SELECT e.crash_guid, o.object_key, o.checksum, o.byte_size, r.result AS previous_result FROM crash_events e JOIN crash_event_objects o ON o.id = e.raw_object_id AND o.organization_id = e.organization_id AND o.project_id = e.project_id LEFT JOIN crash_processing_results r ON r.id = e.current_result_id AND r.organization_id = e.organization_id AND r.project_id = e.project_id AND r.event_id = e.id WHERE e.id = $1::uuid AND e.organization_id = $2::uuid AND e.project_id = $3::uuid",
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
        if let Some(previous) = row.get::<Option<Value>, _>("previous_result") {
            let bytes = serde_json::to_vec(&previous)
                .map_err(|_| JobError::Deterministic("previous_result_invalid"))?;
            if bytes.len() > MAX_PREVIOUS_RESULT_BYTES {
                return Err(JobError::Deterministic("previous_result_too_large"));
            }
            fs::write(attempt.input().join("previous.json"), bytes)
                .map_err(|_| JobError::Transient("scratch_unavailable"))?;
        }
        let inspection = self
            .run_processor(job, ProcessorOperation::ProcessCrash, &attempt, None)
            .await?;
        let inspected: Value = strict_json(&inspection.stdout)?;
        validate_processing_result(&inspected, Some(&crash_guid))?;
        let release = self.resolve_release(job, &inspected).await?;
        let selection = self
            .materialize_symbols(job, &attempt, &inspected, &release)
            .await?;
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
        if release.lookup != release_lookup(&result)? {
            return Err(JobError::Deterministic("processor_output_invalid"));
        }
        self.publish_crash_result(job, event_id, result, state, reason, &release)
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn delete_raw(&self, job: &Job) -> Result<(), JobError> {
        let event_id = job
            .event_id
            .as_deref()
            .ok_or(JobError::Deterministic("missing_event"))?;
        let raw = sqlx::query(
            "SELECT o.id::text AS object_id, o.object_key, o.byte_size, o.lifecycle_state, e.raw_retention_class FROM crash_events e JOIN crash_event_objects o ON o.id = e.raw_object_id AND o.organization_id = e.organization_id AND o.project_id = e.project_id WHERE e.id = $1::uuid AND e.organization_id = $2::uuid AND e.project_id = $3::uuid",
        )
        .bind(event_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?
        .ok_or(JobError::Deterministic("raw_object_missing"))?;
        if raw.get::<String, _>("lifecycle_state") == "deleting"
            && raw.get::<String, _>("raw_retention_class") != "expired"
            && !crate::usage::enforcement_enabled()
        {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| JobError::Transient("database_unavailable"))?;
            lock_lease(&mut transaction, job, self.instance_id.as_ref()).await?;
            let restored = sqlx::query(
                "UPDATE crash_event_objects o SET lifecycle_state = 'stored' FROM crash_events e WHERE o.id = $1::uuid AND o.organization_id = $2::uuid AND o.project_id = $3::uuid AND o.lifecycle_state = 'deleting' AND e.raw_object_id = o.id AND e.organization_id = o.organization_id AND e.project_id = o.project_id AND e.raw_retention_class = 'deleting'",
            )
            .bind(raw.get::<String, _>("object_id"))
            .bind(&job.organization_id)
            .bind(&job.project_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
            if restored.rows_affected() == 1 {
                sqlx::query(
                    "UPDATE crash_events SET raw_retention_class = 'standard' WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND raw_retention_class = 'deleting'",
                )
                .bind(event_id)
                .bind(&job.organization_id)
                .bind(&job.project_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| JobError::Transient("database_unavailable"))?;
                complete_job(&mut transaction, job, self.instance_id.as_ref(), None).await?;
                return transaction
                    .commit()
                    .await
                    .map_err(|_| JobError::Transient("database_unavailable"));
            }
            transaction
                .rollback()
                .await
                .map_err(|_| JobError::Transient("database_unavailable"))?;
        }
        if raw.get::<String, _>("lifecycle_state") == "deleting" {
            match self
                .objects
                .delete_object_checked(&raw.get::<String, _>("object_key"))
                .await
            {
                Ok(()) | Err(ObjectError::Missing) => {}
                Err(ObjectError::Unavailable | ObjectError::Invalid) => {
                    return Err(JobError::Transient("object_store_unavailable"));
                }
            }
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        lock_lease(&mut transaction, job, self.instance_id.as_ref()).await?;
        let current = sqlx::query(
            "SELECT o.id::text AS object_id, o.byte_size, o.lifecycle_state FROM crash_events e JOIN crash_event_objects o ON o.id = e.raw_object_id AND o.organization_id = e.organization_id AND o.project_id = e.project_id WHERE e.id = $1::uuid AND e.organization_id = $2::uuid AND e.project_id = $3::uuid FOR UPDATE OF e, o",
        )
        .bind(event_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?
        .ok_or(JobError::Deterministic("raw_object_missing"))?;
        if current.get::<String, _>("lifecycle_state") == "deleting" {
            crate::usage::record_raw_deleted(
                &mut transaction,
                &job.organization_id,
                &job.project_id,
                event_id,
                &current.get::<String, _>("object_id"),
                current.get("byte_size"),
            )
            .await
            .map_err(map_usage_error)?;
        }
        complete_job(&mut transaction, job, self.instance_id.as_ref(), None).await?;
        transaction
            .commit()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))
    }

    async fn resolve_release(
        &self,
        job: &Job,
        result: &Value,
    ) -> Result<ReleaseResolution, JobError> {
        let Some(lookup) = release_lookup(result)? else {
            return Ok(ReleaseResolution {
                lookup: None,
                candidates: Vec::new(),
            });
        };
        let candidates = sqlx::query_scalar::<_, String>(
            "SELECT id::text FROM releases WHERE organization_id = $1::uuid AND project_id = $2::uuid AND version = $3 AND platform = $4 AND architecture = $5 AND lower(configuration) = lower($6) ORDER BY id LIMIT $7",
        )
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(&lookup.version)
        .bind(&lookup.platform)
        .bind(&lookup.architecture)
        .bind(&lookup.configuration)
        .bind(MAX_STORED_RELEASE_CANDIDATES)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        Ok(ReleaseResolution {
            lookup: Some(lookup),
            candidates,
        })
    }

    async fn materialize_symbols(
        &self,
        job: &Job,
        attempt: &AttemptDirectory,
        result: &Value,
        release: &ReleaseResolution,
    ) -> Result<SymbolSelection, JobError> {
        let Some(release_id) = release.matched_id() else {
            return Ok(SymbolSelection::Missing);
        };
        let architecture = release
            .lookup
            .as_ref()
            .map(|lookup| lookup.architecture.as_str())
            .ok_or(JobError::Deterministic("processor_output_invalid"))?;
        let modules = processing_modules(result)?;
        let rows = sqlx::query(
            "SELECT m.artifact_type, m.module_name, m.architecture, m.debug_id, m.code_id, o.id::text AS object_id, o.object_key, o.checksum, o.byte_size FROM release_manifest_artifacts m JOIN artifact_debug_images d ON d.id = m.debug_image_id AND d.organization_id = m.organization_id AND d.processing_status = 'available' JOIN artifact_objects o ON o.id = d.object_id AND o.organization_id = d.organization_id AND o.lifecycle_state = 'stored' WHERE m.release_id = $1::uuid AND m.organization_id = $2::uuid AND m.project_id = $3::uuid AND m.state = 'available'",
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
            "UPDATE release_manifest_artifacts SET debug_image_id = $4::uuid, state = 'available', failure_code = NULL, uploaded_at = now(), updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'processing' AND checksum = $5 AND byte_size = $6 AND artifact_type = $7 AND module_name = $8 AND architecture = $9 AND debug_id = $10 AND code_id IS NOT DISTINCT FROM $11",
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
            "UPDATE artifact_upload_sessions SET state = 'completed', failure_code = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'processing' AND checksum = $4 AND byte_size = $5 AND artifact_type = $6 AND module_name = $7 AND architecture = $8 AND debug_id = $9 AND code_id IS NOT DISTINCT FROM $10",
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
        crate::usage::record_symbol_stored(
            &mut transaction,
            &job.organization_id,
            &job.project_id,
            &object_id,
            artifact.byte_size,
        )
        .await
        .map_err(map_usage_error)?;
        crate::reprocessing::enqueue_artifact_request(
            &mut transaction,
            &job.organization_id,
            &job.project_id,
            &artifact.manifest_artifact_id,
        )
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
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
            "UPDATE artifact_upload_sessions SET state = 'failed', failure_code = $4, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'processing' AND checksum = $5 AND byte_size = $6 AND artifact_type = $7 AND module_name = $8 AND architecture = $9 AND debug_id = $10 AND code_id IS NOT DISTINCT FROM $11",
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
            "UPDATE release_manifest_artifacts SET state = $4, failure_code = CASE WHEN $4 = 'quarantined' THEN $5 ELSE NULL END, debug_image_id = NULL, uploaded_at = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'processing' AND checksum = $6 AND byte_size = $7 AND artifact_type = $8 AND module_name = $9 AND architecture = $10 AND debug_id = $11 AND code_id IS NOT DISTINCT FROM $12",
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
            "UPDATE derived_symbol_caches c SET state = 'processing', updated_at = now() FROM jobs j WHERE c.id = j.derived_cache_id AND c.organization_id = j.organization_id AND c.project_id = j.project_id AND j.id = $1::uuid AND j.organization_id = $2::uuid AND j.project_id = $3::uuid AND j.state = 'leased' AND j.lease_owner = $4 AND j.lease_token = $5::uuid AND j.lease_expires_at > now()",
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
            "UPDATE derived_symbol_caches SET state = 'available', checksum = $4, byte_size = $5, failure_code = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'processing' AND object_key = $6",
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

    #[allow(clippy::too_many_lines)]
    async fn publish_crash_result(
        &self,
        job: &Job,
        event_id: &str,
        mut result: Value,
        state: &str,
        reason: &str,
        release: &ReleaseResolution,
    ) -> Result<(), JobError> {
        let (schema_version, processing_version) = processing_versions(&result)?;
        let waiters = if state == "awaiting_symbols" {
            symbol_waiters(&result, release)?
        } else {
            Vec::new()
        };
        let result_id = random_uuid().map_err(|_| JobError::Transient("random_unavailable"))?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        let rules = crate::data_rules::lock_for_publication(
            &mut transaction,
            &job.organization_id,
            &job.project_id,
        )
        .await
        .map_err(|error| match error {
            crate::data_rules::DataRulesError::Unavailable => {
                JobError::Transient("database_unavailable")
            }
            crate::data_rules::DataRulesError::NotFound => JobError::LostLease,
            _ => JobError::Deterministic("data_rules_invalid"),
        })?;
        lock_lease(&mut transaction, job, self.instance_id.as_ref()).await?;
        let existing = lock_event(&mut transaction, job, event_id).await?;
        let existing_grouped = existing.state == "grouped";
        let context_facets = crate::data_rules::redact_and_index(&mut result, &rules);
        let grouping = grouping_publication(self.grouping_enabled, &result)?;
        let search_text = event_search_text(&result, &context_facets);
        let user_comment = projected_text(&result, "/crash_context/user_comment").map(|value| {
            value
                .chars()
                .take(MAX_SEARCH_COMMENT_CHARS)
                .collect::<String>()
        });
        let crash_type = projected_text(&result, "/crash_context/crash_type");
        let platform = projected_text(&result, "/crash_context/platform/normalized");
        let architecture = projected_text(&result, "/crash_context/architecture");
        let engine_version = projected_text(&result, "/crash_context/engine_version");
        let symbolication_state = projected_symbolication_state(state, &result);
        let bytes = serde_json::to_vec(&result)
            .map_err(|_| JobError::Deterministic("processor_output_invalid"))?;
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        let stored_id: String = sqlx::query_scalar(
            "INSERT INTO crash_processing_results (id, organization_id, project_id, event_id, schema_version, processing_version, data_rules_version, result, checksum) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8, $9) ON CONFLICT (event_id, processing_version, data_rules_version, checksum) DO UPDATE SET checksum = EXCLUDED.checksum RETURNING id::text",
        )
        .bind(result_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(event_id)
        .bind(schema_version)
        .bind(processing_version)
        .bind(rules.version)
        .bind(&result)
        .bind(checksum.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        sqlx::query(
            "INSERT INTO crash_event_search (organization_id, project_id, event_id, result_id, data_rules_version, search_text, user_comment, crash_type, platform, architecture, engine_version, symbolication_state) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT (organization_id, project_id, event_id) DO UPDATE SET result_id = EXCLUDED.result_id, data_rules_version = EXCLUDED.data_rules_version, search_text = EXCLUDED.search_text, user_comment = EXCLUDED.user_comment, crash_type = EXCLUDED.crash_type, platform = EXCLUDED.platform, architecture = EXCLUDED.architecture, engine_version = EXCLUDED.engine_version, symbolication_state = EXCLUDED.symbolication_state, updated_at = now()",
        )
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(event_id)
        .bind(&stored_id)
        .bind(rules.version)
        .bind(search_text)
        .bind(user_comment)
        .bind(crash_type)
        .bind(platform)
        .bind(architecture)
        .bind(engine_version)
        .bind(symbolication_state)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        sqlx::query(
            "DELETE FROM crash_event_context_facets WHERE organization_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid",
        )
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(event_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if !context_facets.is_empty() {
            let facet_keys = context_facets
                .iter()
                .map(|facet| facet.key.as_str())
                .collect::<Vec<_>>();
            let facet_values = context_facets
                .iter()
                .map(|facet| facet.value.as_str())
                .collect::<Vec<_>>();
            let facet_truncation = context_facets
                .iter()
                .map(|facet| facet.value_truncated)
                .collect::<Vec<_>>();
            sqlx::query(
                "INSERT INTO crash_event_context_facets (organization_id, project_id, event_id, result_id, data_rules_version, key, value, value_truncated) SELECT $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, facets.key, facets.value, facets.value_truncated FROM unnest($6::text[], $7::text[], $8::boolean[]) AS facets(key, value, value_truncated)",
            )
            .bind(&job.organization_id)
            .bind(&job.project_id)
            .bind(event_id)
            .bind(&stored_id)
            .bind(rules.version)
            .bind(facet_keys)
            .bind(facet_values)
            .bind(facet_truncation)
            .execute(&mut *transaction)
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        }
        record_release_mapping(&mut transaction, job, event_id, release).await?;
        replace_symbol_waiters(
            &mut transaction,
            job,
            event_id,
            &stored_id,
            release,
            &waiters,
        )
        .await?;
        crate::reprocessing::enqueue_waiter_catchup_requests(
            &mut transaction,
            &job.organization_id,
            &job.project_id,
            event_id,
            &stored_id,
        )
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        let assignment =
            apply_grouping(&mut transaction, job, event_id, existing, &grouping).await?;
        if let Some(assignment) = assignment.as_ref() {
            let rollup_changed = apply_release_delta(
                &mut transaction,
                job,
                event_id,
                assignment,
                release.matched_id(),
            )
            .await?;
            if rollup_changed {
                update_issue_transitions(
                    &mut transaction,
                    &job.organization_id,
                    &job.project_id,
                    &assignment.issue_id,
                    self.grouping_enabled,
                )
                .await?;
            }
        }
        let issue_id = assignment
            .as_ref()
            .map(|assignment| assignment.issue_id.as_str());
        let updated = sqlx::query(
            "UPDATE crash_events SET current_result_id = $4::uuid, processing_state = $5, state_reason = CASE WHEN $5 = 'processed' THEN NULL ELSE $6 END, retryable = false, retry_at = NULL, completed_reprocessing_generation = GREATEST(completed_reprocessing_generation, $7), updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid RETURNING requested_reprocessing_generation",
        )
        .bind(event_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(&stored_id)
        .bind(state)
        .bind(reason)
        .bind(job.target_generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?
        .ok_or(JobError::LostLease)?;
        let requested_generation: i64 = updated.get("requested_reprocessing_generation");
        crate::usage::schedule_raw_retention(
            &mut transaction,
            &job.organization_id,
            &job.project_id,
            event_id,
        )
        .await
        .map_err(map_usage_error)?;
        complete_reprocessing_request_events(&mut transaction, job, event_id, &stored_id).await?;
        if requested_generation > job.target_generation {
            requeue_job_for_new_generation(&mut transaction, job, self.instance_id.as_ref())
                .await?;
        } else {
            complete_job(&mut transaction, job, self.instance_id.as_ref(), None).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        info!(
            event_id,
            project_id = job.project_id,
            issue_id = issue_id.unwrap_or(""),
            processing_state = state,
            grouping_state = if existing_grouped {
                "grouped"
            } else {
                grouping.state()
            },
            release_mapping_state = release.state(),
            fingerprint_algorithm = faultlane_grouping::FINGERPRINT_ALGORITHM,
            fingerprint_version = faultlane_grouping::FINGERPRINT_VERSION,
            "crash grouping published"
        );
        Ok(())
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
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        let updated = sqlx::query(
            "UPDATE jobs SET state = 'pending', available_at = now() + ($6 * interval '1 second'), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL, failure_code = $7, resource_failures = resource_failures + CASE WHEN $8 THEN 1 ELSE 0 END, attempt = attempt - CASE WHEN $9 THEN 1 ELSE 0 END, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'leased' AND lease_owner = $4 AND lease_token = $5::uuid",
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
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if updated.rows_affected() != 1 {
            return Err(JobError::LostLease);
        }
        if job.target_generation > 0
            && let Some(event_id) = job.event_id.as_deref()
        {
            let request_ids = sqlx::query_scalar::<_, String>(
                "UPDATE crash_reprocessing_request_events SET state = 'queued' WHERE organization_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid AND generation <= $4 AND state = 'running' RETURNING request_id::text",
            )
            .bind(&job.organization_id)
            .bind(&job.project_id)
            .bind(event_id)
            .bind(job.target_generation)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
            for request_id in BTreeSet::from_iter(request_ids) {
                refresh_reprocessing_request(&mut transaction, &request_id).await?;
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))
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

    #[allow(clippy::too_many_lines)]
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
        let mut requeue_newer_generation = false;
        match job.kind.as_str() {
            "process_crash" => {
                let updated = sqlx::query(
                    "UPDATE crash_events SET processing_state = CASE WHEN $6 > 0 AND current_result_id IS NOT NULL THEN processing_state ELSE $4 END, state_reason = CASE WHEN $6 > 0 AND current_result_id IS NOT NULL THEN state_reason ELSE $5 END, retryable = CASE WHEN $6 > 0 AND current_result_id IS NOT NULL THEN retryable ELSE false END, retry_at = CASE WHEN $6 > 0 AND current_result_id IS NOT NULL THEN retry_at ELSE NULL END, completed_reprocessing_generation = GREATEST(completed_reprocessing_generation, $6), updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid RETURNING requested_reprocessing_generation",
                )
                .bind(job.event_id.as_deref().unwrap_or_default())
                .bind(&job.organization_id)
                .bind(&job.project_id)
                .bind(if quarantine { "quarantined" } else { "failed" })
                .bind(code)
                .bind(job.target_generation)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| JobError::Transient("database_unavailable"))?
                .ok_or(JobError::LostLease)?;
                let requested_generation: i64 = updated.get("requested_reprocessing_generation");
                if job.target_generation > 0 {
                    let request_ids = sqlx::query_scalar::<_, String>(
                        "UPDATE crash_reprocessing_request_events SET state = 'failed', result_id = NULL, failure_code = $5, completed_at = now() WHERE organization_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid AND generation <= $4 AND state IN ('queued', 'running') RETURNING request_id::text",
                    )
                    .bind(&job.organization_id)
                    .bind(&job.project_id)
                    .bind(job.event_id.as_deref().unwrap_or_default())
                    .bind(job.target_generation)
                    .bind(code)
                    .fetch_all(&mut *transaction)
                    .await
                    .map_err(|_| JobError::Transient("database_unavailable"))?;
                    for request_id in BTreeSet::from_iter(request_ids) {
                        refresh_reprocessing_request(&mut transaction, &request_id).await?;
                    }
                }
                requeue_newer_generation = requested_generation > job.target_generation;
            }
            "index_artifact" => {
                let session = sqlx::query(
                    "UPDATE artifact_upload_sessions SET state = 'failed', failure_code = $4, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'processing'",
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
                    "UPDATE release_manifest_artifacts m SET state = 'quarantined', failure_code = $4, debug_image_id = NULL, updated_at = now() FROM artifact_upload_sessions s WHERE s.id = $1::uuid AND s.organization_id = $2::uuid AND s.project_id = $3::uuid AND m.id = s.manifest_artifact_id AND m.organization_id = s.organization_id AND m.project_id = s.project_id AND m.state = 'processing'",
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
                    "UPDATE derived_symbol_caches SET state = $4, failure_code = $5, checksum = NULL, byte_size = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state IN ('pending', 'processing')",
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
            "delete_raw" => {}
            _ => return Err(JobError::Deterministic("unknown_job_type")),
        }
        if requeue_newer_generation {
            requeue_job_for_new_generation(&mut transaction, job, self.instance_id.as_ref())
                .await?;
        } else {
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
        }
        transaction
            .commit()
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))
    }
}

#[derive(Clone)]
struct ReprocessingRequest {
    id: String,
    organization_id: String,
    project_id: String,
    source: String,
    scope_kind: String,
    scope_value: Option<String>,
    request_limit: Option<i32>,
    input_cursor_event_id: Option<String>,
    selection_before: time::OffsetDateTime,
    selection_cursor_event_id: Option<String>,
    attempt: i32,
    max_attempt: i32,
    lease_token: String,
    exhausted: bool,
}

struct ReprocessingCandidate {
    event_id: String,
}

async fn reconcile_reprocessing_event_jobs(pool: &PgPool) -> Result<bool, ()> {
    let mut transaction = pool.begin().await.map_err(|_| ())?;
    let rows = sqlx::query(
        "WITH candidates AS MATERIALIZED (SELECT x.id, x.request_id, x.event_id FROM crash_reprocessing_request_events x JOIN crash_reprocessing_requests r ON r.id = x.request_id AND r.organization_id = x.organization_id AND r.project_id = x.project_id JOIN crash_events e ON e.id = x.event_id AND e.organization_id = x.organization_id AND e.project_id = x.project_id JOIN jobs j ON j.event_id = e.id AND j.organization_id = e.organization_id AND j.project_id = e.project_id AND j.job_type = 'process_crash' WHERE x.state IN ('queued', 'running') AND r.state IN ('running', 'partial', 'failed') AND e.completed_reprocessing_generation < x.generation AND j.state IN ('completed', 'failed', 'dead') ORDER BY x.created_at FOR UPDATE OF x, e, j SKIP LOCKED LIMIT 100), reset_events AS (UPDATE crash_reprocessing_request_events x SET state = 'queued' FROM candidates c WHERE x.id = c.id RETURNING x.request_id, x.event_id), reset_jobs AS (UPDATE jobs j SET state = 'pending', priority = 200, attempt = 0, resource_failures = 0, available_at = now(), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL, failure_code = NULL, completed_at = NULL, updated_at = now() FROM (SELECT DISTINCT event_id FROM reset_events) e WHERE j.event_id = e.event_id AND j.job_type = 'process_crash' AND j.state IN ('completed', 'failed', 'dead') RETURNING j.event_id) SELECT DISTINCT request_id::text AS request_id, (SELECT count(*) FROM reset_jobs) AS reset_count FROM reset_events",
    )
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ())?;
    let request_ids = rows
        .iter()
        .map(|row| row.get::<String, _>("request_id"))
        .collect::<BTreeSet<_>>();
    for request_id in request_ids {
        refresh_reprocessing_request(&mut transaction, &request_id)
            .await
            .map_err(|_| ())?;
    }
    let reconciled = rows
        .first()
        .is_some_and(|row| row.get::<i64, _>("reset_count") > 0);
    transaction.commit().await.map_err(|_| ())?;
    Ok(reconciled)
}

async fn claim_reprocessing_request(
    pool: &PgPool,
    worker_id: &str,
) -> Result<Option<ReprocessingRequest>, ()> {
    let lease_token = random_uuid().map_err(|_| ())?;
    let row = sqlx::query(
        "WITH candidate AS (SELECT r.id, r.state = 'scheduling' AND r.attempt >= r.max_attempt AS exhausted FROM crash_reprocessing_requests r JOIN projects p ON p.id = r.project_id AND p.organization_id = r.organization_id WHERE (r.state = 'pending' AND r.available_at <= now() AND r.attempt < r.max_attempt) OR (r.state = 'scheduling' AND r.lease_expires_at <= now()) ORDER BY CASE WHEN r.source = 'automatic' THEN 0 ELSE 1 END, r.available_at, r.created_at FOR UPDATE OF p, r SKIP LOCKED LIMIT 1) UPDATE crash_reprocessing_requests r SET state = 'scheduling', attempt = r.attempt + CASE WHEN candidate.exhausted THEN 0 ELSE 1 END, lease_owner = $1, lease_token = $2::uuid, lease_expires_at = now() + ($3 * interval '1 second'), updated_at = now(), completed_at = NULL FROM candidate WHERE r.id = candidate.id RETURNING r.id::text AS id, r.organization_id::text AS organization_id, r.project_id::text AS project_id, r.source, r.scope_kind, r.scope_value, r.request_limit, r.input_cursor_event_id::text AS input_cursor_event_id, r.selection_before, r.selection_cursor_event_id::text AS selection_cursor_event_id, r.attempt, r.max_attempt, r.lease_token::text AS lease_token, candidate.exhausted",
    )
    .bind(worker_id)
    .bind(&lease_token)
    .bind(REPROCESSING_REQUEST_LEASE_SECONDS)
    .fetch_optional(pool)
    .await
    .map_err(|_| ())?;
    Ok(row.map(|row| ReprocessingRequest {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        project_id: row.get("project_id"),
        source: row.get("source"),
        scope_kind: row.get("scope_kind"),
        scope_value: row.get("scope_value"),
        request_limit: row.get("request_limit"),
        input_cursor_event_id: row.get("input_cursor_event_id"),
        selection_before: row.get("selection_before"),
        selection_cursor_event_id: row.get("selection_cursor_event_id"),
        attempt: row.get("attempt"),
        max_attempt: row.get("max_attempt"),
        lease_token: row.get("lease_token"),
        exhausted: row.get("exhausted"),
    }))
}

async fn lock_reprocessing_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &ReprocessingRequest,
    worker_id: &str,
) -> Result<(), JobError> {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT id::text FROM crash_reprocessing_requests WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'scheduling' AND lease_owner = $4 AND lease_token = $5::uuid AND lease_expires_at > now() FOR UPDATE",
    )
    .bind(&request.id)
    .bind(&request.organization_id)
    .bind(&request.project_id)
    .bind(worker_id)
    .bind(&request.lease_token)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    found.map_or(Err(JobError::LostLease), |_| Ok(()))
}

async fn automatic_reprocessing_candidates(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &ReprocessingRequest,
) -> Result<Vec<ReprocessingCandidate>, JobError> {
    let batch = i64::try_from(AUTOMATIC_REPROCESSING_BATCH + 1).unwrap_or(i64::MAX);
    let rows = match request.scope_kind.as_str() {
        "artifact" => sqlx::query(
            "SELECT e.id::text AS event_id FROM release_manifest_artifacts m JOIN crash_symbol_waiters w ON w.organization_id = m.organization_id AND w.project_id = m.project_id AND w.release_id = m.release_id JOIN crash_events e ON e.id = w.event_id AND e.organization_id = w.organization_id AND e.project_id = w.project_id AND e.current_result_id = w.result_id WHERE m.id = $1::uuid AND m.organization_id = $2::uuid AND m.project_id = $3::uuid AND m.state = 'available' AND e.processing_state = 'awaiting_symbols' AND w.created_at <= $4 AND ($5::uuid IS NULL OR e.id > $5::uuid) AND ((m.artifact_type = 'pdb' AND w.required_artifact = 'pdb' AND w.architecture = m.architecture AND w.debug_id = m.debug_id AND w.code_id = '') OR (m.artifact_type IN ('pe_executable', 'pe_dynamic_library') AND w.required_artifact = 'pe' AND w.module_name = lower(m.module_name) AND w.architecture = m.architecture AND w.debug_id = m.debug_id AND w.code_id = m.code_id)) GROUP BY e.id ORDER BY e.id LIMIT $6",
        )
        .bind(request.scope_value.as_deref().unwrap_or_default())
        .bind(&request.organization_id)
        .bind(&request.project_id)
        .bind(request.selection_before)
        .bind(&request.selection_cursor_event_id)
        .bind(batch)
        .fetch_all(&mut **transaction)
        .await,
        "data_rules_version" => {
            let version = request
                .scope_value
                .as_deref()
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value > 0)
                .ok_or(JobError::Deterministic("reprocessing_request_invalid"))?;
            sqlx::query(
                "SELECT e.id::text AS event_id FROM crash_events e JOIN crash_processing_results r ON r.id = e.current_result_id AND r.organization_id = e.organization_id AND r.project_id = e.project_id AND r.event_id = e.id WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.received_at <= $3 AND r.data_rules_version < $4 AND ($5::uuid IS NULL OR (e.received_at, e.id) > (SELECT c.received_at, c.id FROM crash_events c WHERE c.id = $5::uuid AND c.organization_id = e.organization_id AND c.project_id = e.project_id)) ORDER BY e.received_at, e.id LIMIT $6",
            )
            .bind(&request.organization_id)
            .bind(&request.project_id)
            .bind(request.selection_before)
            .bind(version)
            .bind(&request.selection_cursor_event_id)
            .bind(batch)
            .fetch_all(&mut **transaction)
            .await
        }
        _ => return Err(JobError::Deterministic("reprocessing_request_invalid")),
    }
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    Ok(rows
        .iter()
        .map(|row| ReprocessingCandidate {
            event_id: row.get("event_id"),
        })
        .collect())
}

async fn manual_reprocessing_candidates(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &ReprocessingRequest,
) -> Result<Vec<ReprocessingCandidate>, JobError> {
    let limit = request
        .request_limit
        .ok_or(JobError::Deterministic("reprocessing_request_invalid"))?;
    let rows = sqlx::query(
        "SELECT e.id::text AS event_id FROM crash_events e LEFT JOIN crash_processing_results r ON r.id = e.current_result_id AND r.organization_id = e.organization_id AND r.project_id = e.project_id AND r.event_id = e.id WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.received_at <= $3 AND ($4::uuid IS NULL OR (e.received_at, e.id) > (SELECT c.received_at, c.id FROM crash_events c WHERE c.id = $4::uuid AND c.organization_id = e.organization_id AND c.project_id = e.project_id)) AND (($5 = 'event' AND e.id = $6::uuid) OR ($5 = 'issue' AND e.issue_id = $6::uuid) OR ($5 = 'release' AND e.release_id = $6::uuid) OR ($5 = 'project') OR ($5 = 'parser_version' AND r.result #>> '{current,parser_version}' = $6) OR ($5 = 'symbolicator_version' AND r.result #>> '{current,symbolication,symbolicator_version}' = $6) OR ($5 = 'fingerprint_version' AND e.fingerprint_version = $6::integer)) ORDER BY e.received_at, e.id LIMIT $7",
    )
    .bind(&request.organization_id)
    .bind(&request.project_id)
    .bind(request.selection_before)
    .bind(&request.input_cursor_event_id)
    .bind(&request.scope_kind)
    .bind(request.scope_value.as_deref())
    .bind(i64::from(limit) + 1)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    Ok(rows
        .iter()
        .map(|row| ReprocessingCandidate {
            event_id: row.get("event_id"),
        })
        .collect())
}

async fn schedule_reprocessing_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &ReprocessingRequest,
    event_ids: &[String],
) -> Result<(), JobError> {
    let locked_jobs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT j.id FROM jobs j JOIN unnest($3::text[]) selected(event_id) ON selected.event_id::uuid = j.event_id WHERE j.organization_id = $1::uuid AND j.project_id = $2::uuid AND j.job_type = 'process_crash' ORDER BY j.id FOR UPDATE OF j) locked",
    )
    .bind(&request.organization_id)
    .bind(&request.project_id)
    .bind(event_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if locked_jobs
        != i64::try_from(event_ids.len())
            .map_err(|_| JobError::Deterministic("reprocessing_request_invalid"))?
    {
        return Err(JobError::Deterministic("event_job_missing"));
    }
    let row = sqlx::query(
        "WITH selected AS (SELECT unnest($4::text[])::uuid AS event_id), eligible AS MATERIALIZED (SELECT e.id, e.current_result_id, CASE WHEN j.state = 'leased' THEN CASE WHEN e.requested_reprocessing_generation <= COALESCE((SELECT max(x.generation) FROM crash_reprocessing_request_events x WHERE x.organization_id = e.organization_id AND x.project_id = e.project_id AND x.event_id = e.id AND x.state = 'running'), 0) THEN e.requested_reprocessing_generation + 1 ELSE e.requested_reprocessing_generation END WHEN e.requested_reprocessing_generation > e.completed_reprocessing_generation THEN e.requested_reprocessing_generation ELSE e.requested_reprocessing_generation + 1 END AS generation FROM crash_events e JOIN selected s ON s.event_id = e.id JOIN jobs j ON j.event_id = e.id AND j.organization_id = e.organization_id AND j.project_id = e.project_id AND j.job_type = 'process_crash' WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND NOT EXISTS (SELECT 1 FROM crash_reprocessing_request_events x WHERE x.request_id = $3::uuid AND x.event_id = e.id) FOR UPDATE OF e), advanced AS (UPDATE crash_events e SET requested_reprocessing_generation = c.generation, updated_at = now() FROM eligible c WHERE e.id = c.id AND e.organization_id = $1::uuid AND e.project_id = $2::uuid RETURNING e.id, e.current_result_id, e.requested_reprocessing_generation), inserted AS (INSERT INTO crash_reprocessing_request_events (organization_id, project_id, request_id, event_id, generation, previous_result_id) SELECT $1::uuid, $2::uuid, $3::uuid, a.id, a.requested_reprocessing_generation, a.current_result_id FROM advanced a ON CONFLICT (request_id, event_id) DO NOTHING RETURNING event_id), reactivated AS (UPDATE jobs j SET state = CASE WHEN j.state = 'leased' THEN j.state ELSE 'pending' END, priority = CASE WHEN j.state IN ('completed', 'failed', 'dead') THEN 200 ELSE j.priority END, attempt = CASE WHEN j.state = 'leased' THEN j.attempt ELSE 0 END, resource_failures = CASE WHEN j.state = 'leased' THEN j.resource_failures ELSE 0 END, available_at = CASE WHEN j.state = 'leased' THEN j.available_at ELSE now() END, lease_owner = CASE WHEN j.state = 'leased' THEN j.lease_owner ELSE NULL END, lease_token = CASE WHEN j.state = 'leased' THEN j.lease_token ELSE NULL END, lease_expires_at = CASE WHEN j.state = 'leased' THEN j.lease_expires_at ELSE NULL END, heartbeat_at = CASE WHEN j.state = 'leased' THEN j.heartbeat_at ELSE NULL END, failure_code = CASE WHEN j.state = 'leased' THEN j.failure_code ELSE NULL END, completed_at = CASE WHEN j.state = 'leased' THEN j.completed_at ELSE NULL END, updated_at = now() FROM inserted i WHERE j.event_id = i.event_id AND j.organization_id = $1::uuid AND j.project_id = $2::uuid AND j.job_type = 'process_crash' RETURNING j.event_id) SELECT (SELECT count(*) FROM inserted) AS inserted_count, (SELECT count(*) FROM reactivated) AS reactivated_count",
    )
    .bind(&request.organization_id)
    .bind(&request.project_id)
    .bind(&request.id)
    .bind(event_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    let inserted: i64 = row.get("inserted_count");
    let reactivated: i64 = row.get("reactivated_count");
    if inserted == reactivated {
        Ok(())
    } else {
        Err(JobError::Deterministic("event_job_missing"))
    }
}

async fn release_reprocessing_request_page(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &ReprocessingRequest,
    worker_id: &str,
    cursor: Option<&str>,
) -> Result<(), JobError> {
    let updated = sqlx::query(
        "UPDATE crash_reprocessing_requests SET state = 'pending', selection_cursor_event_id = $6::uuid, attempt = 0, available_at = now(), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, failure_code = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'scheduling' AND lease_owner = $4 AND lease_token = $5::uuid",
    )
    .bind(&request.id)
    .bind(&request.organization_id)
    .bind(&request.project_id)
    .bind(worker_id)
    .bind(&request.lease_token)
    .bind(cursor)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(JobError::LostLease)
    }
}

async fn complete_reprocessing_selection(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &ReprocessingRequest,
    worker_id: &str,
    truncated: bool,
    next_cursor: Option<&str>,
) -> Result<(), JobError> {
    let updated = sqlx::query(
        "UPDATE crash_reprocessing_requests SET state = 'running', selection_complete = true, selection_truncated = $6, next_cursor_event_id = $7::uuid, lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, failure_code = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'scheduling' AND lease_owner = $4 AND lease_token = $5::uuid",
    )
    .bind(&request.id)
    .bind(&request.organization_id)
    .bind(&request.project_id)
    .bind(worker_id)
    .bind(&request.lease_token)
    .bind(truncated)
    .bind(next_cursor)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(JobError::LostLease)
    }
}

async fn refresh_reprocessing_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: &str,
) -> Result<(), JobError> {
    let updated = sqlx::query(
        "WITH counts AS (SELECT count(*) AS selected_count, count(*) FILTER (WHERE state = 'queued') AS queued_count, count(*) FILTER (WHERE state = 'running') AS running_count, count(*) FILTER (WHERE state = 'completed') AS completed_count, count(*) FILTER (WHERE state = 'failed') AS failed_count FROM crash_reprocessing_request_events WHERE request_id = $1::uuid), desired AS (SELECT r.id, c.*, CASE WHEN NOT r.selection_complete THEN r.state WHEN r.failure_code IS NOT NULL AND c.completed_count > 0 THEN 'partial' WHEN r.failure_code IS NOT NULL THEN 'failed' WHEN c.selected_count = 0 THEN 'completed' WHEN c.queued_count + c.running_count > 0 THEN 'running' WHEN c.completed_count > 0 AND c.failed_count > 0 THEN 'partial' WHEN c.failed_count > 0 THEN 'failed' ELSE 'completed' END AS next_state FROM crash_reprocessing_requests r CROSS JOIN counts c WHERE r.id = $1::uuid) UPDATE crash_reprocessing_requests r SET state = d.next_state, selected_count = d.selected_count, queued_count = d.queued_count, running_count = d.running_count, completed_count = d.completed_count, failed_count = d.failed_count, completed_at = CASE WHEN d.next_state IN ('completed', 'partial', 'failed') THEN COALESCE(r.completed_at, now()) ELSE NULL END, updated_at = now() FROM desired d WHERE r.id = d.id",
    )
    .bind(request_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(JobError::Deterministic("reprocessing_request_missing"))
    }
}

async fn finish_reprocessing_schedule_failure(
    pool: &PgPool,
    request: &ReprocessingRequest,
    worker_id: &str,
    code: &'static str,
) -> Result<(), JobError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
    lock_reprocessing_request(&mut transaction, request, worker_id).await?;
    if request.attempt < request.max_attempt {
        let exponent = u32::try_from(request.attempt.saturating_sub(1))
            .unwrap_or(6)
            .min(6);
        let seconds = i64::from(1_u32 << exponent).min(60);
        sqlx::query(
            "UPDATE crash_reprocessing_requests SET state = 'pending', available_at = now() + ($6 * interval '1 second'), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, failure_code = $7, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND lease_owner = $4 AND lease_token = $5::uuid",
        )
        .bind(&request.id)
        .bind(&request.organization_id)
        .bind(&request.project_id)
        .bind(worker_id)
        .bind(&request.lease_token)
        .bind(seconds)
        .bind(code)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
    } else {
        sqlx::query(
            "UPDATE crash_reprocessing_requests SET state = 'failed', selection_complete = true, lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, failure_code = $6, completed_at = now(), updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND lease_owner = $4 AND lease_token = $5::uuid",
        )
        .bind(&request.id)
        .bind(&request.organization_id)
        .bind(&request.project_id)
        .bind(worker_id)
        .bind(&request.lease_token)
        .bind(code)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        refresh_reprocessing_request(&mut transaction, &request.id).await?;
    }
    transaction
        .commit()
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))
}

#[cfg(test)]
async fn claim_job(pool: &PgPool, worker_id: &str) -> Result<Option<Job>, ()> {
    claim_job_with_project_limit(pool, worker_id, 1).await
}

async fn claim_job_with_project_limit(
    pool: &PgPool,
    worker_id: &str,
    project_concurrency: i64,
) -> Result<Option<Job>, ()> {
    let lease_token = random_uuid().map_err(|_| ())?;
    let mut transaction = pool.begin().await.map_err(|_| ())?;
    let row = sqlx::query(
        "WITH candidate_project AS MATERIALIZED (SELECT p.id, p.organization_id, active.job_count AS prior_project_active_jobs FROM jobs seed JOIN projects p ON p.id = seed.project_id AND p.organization_id = seed.organization_id CROSS JOIN LATERAL (SELECT count(*)::bigint AS job_count FROM jobs active WHERE active.organization_id = seed.organization_id AND active.project_id = seed.project_id AND active.state = 'leased' AND active.lease_expires_at > now()) active WHERE ((seed.state = 'pending' AND seed.available_at <= now() AND (seed.attempt < seed.max_attempt OR (seed.attempt = seed.max_attempt AND seed.resource_failures = 1))) OR (seed.state = 'leased' AND seed.lease_expires_at <= now())) AND active.job_count < $4 ORDER BY seed.priority, seed.available_at, seed.created_at, seed.id FOR UPDATE OF p SKIP LOCKED LIMIT 1), candidate AS MATERIALIZED (SELECT j.id, project.prior_project_active_jobs FROM jobs j JOIN candidate_project project ON project.id = j.project_id AND project.organization_id = j.organization_id WHERE ((j.state = 'pending' AND j.available_at <= now() AND (j.attempt < j.max_attempt OR (j.attempt = j.max_attempt AND j.resource_failures = 1))) OR (j.state = 'leased' AND j.lease_expires_at <= now())) ORDER BY j.priority, j.available_at, j.created_at, j.id FOR UPDATE OF j SKIP LOCKED LIMIT 1) UPDATE jobs j SET state = 'leased', attempt = j.attempt + 1, lease_owner = $1, lease_token = $2::uuid, lease_expires_at = now() + ($3 * interval '1 second'), heartbeat_at = now(), updated_at = now() FROM candidate WHERE j.id = candidate.id RETURNING j.id::text AS id, j.organization_id::text AS organization_id, j.project_id::text AS project_id, j.event_id::text AS event_id, j.artifact_upload_id::text AS artifact_upload_id, j.derived_cache_id::text AS derived_cache_id, j.job_type, j.attempt, j.max_attempt, j.resource_failures, j.lease_token::text AS lease_token, COALESCE((SELECT e.requested_reprocessing_generation FROM crash_events e WHERE e.id = j.event_id AND e.organization_id = j.organization_id AND e.project_id = j.project_id), 0) AS target_generation, candidate.prior_project_active_jobs + 1 AS project_active_jobs, GREATEST(0, EXTRACT(EPOCH FROM now() - j.created_at)::bigint) AS queue_age_seconds",
    )
    .bind(worker_id)
    .bind(&lease_token)
    .bind(LEASE_SECONDS)
    .bind(project_concurrency)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ())?;
    let job = row.map(|row| Job {
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
        target_generation: row.get("target_generation"),
        project_active_jobs: row.get("project_active_jobs"),
        queue_age_seconds: row.get("queue_age_seconds"),
    });
    if let Some(job) = job.as_ref() {
        mark_reprocessing_events_running(&mut transaction, job)
            .await
            .map_err(|_| ())?;
    }
    transaction.commit().await.map_err(|_| ())?;
    Ok(job)
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
    target_generation: i64,
    project_active_jobs: i64,
    queue_age_seconds: i64,
}

async fn mark_reprocessing_events_running(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
) -> Result<(), JobError> {
    if job.target_generation == 0 {
        return Ok(());
    }
    let Some(event_id) = job.event_id.as_deref() else {
        return Ok(());
    };
    let request_ids = sqlx::query_scalar::<_, String>(
        "UPDATE crash_reprocessing_request_events SET state = 'running', started_at = COALESCE(started_at, now()) WHERE organization_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid AND generation <= $4 AND state = 'queued' RETURNING request_id::text",
    )
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(event_id)
    .bind(job.target_generation)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    for request_id in BTreeSet::from_iter(request_ids) {
        refresh_reprocessing_request(transaction, &request_id).await?;
    }
    Ok(())
}

#[derive(Debug)]
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

enum GroupingPublication {
    Disabled,
    Insufficient,
    Grouped(faultlane_grouping::Fingerprint),
}

impl GroupingPublication {
    fn state(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Insufficient => "insufficient",
            Self::Grouped(_) => "grouped",
        }
    }
}

struct ExistingGrouping {
    state: String,
    issue_id: Option<String>,
    release_id: Option<String>,
    received_at: time::OffsetDateTime,
}

struct GroupingAssignment {
    issue_id: String,
    first_assignment: bool,
    previous_release_id: Option<String>,
    received_at: time::OffsetDateTime,
}

struct ReleaseEvidence {
    id: String,
    build_timestamp: Option<time::OffsetDateTime>,
}

struct ReleaseChronology {
    first: Option<String>,
    last: Option<String>,
    last_timestamp: Option<time::OffsetDateTime>,
    release_count: usize,
    valid: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReleaseLookup {
    version: String,
    platform: String,
    architecture: String,
    configuration: String,
}

#[derive(Clone, Debug)]
struct ReleaseResolution {
    lookup: Option<ReleaseLookup>,
    candidates: Vec<String>,
}

impl ReleaseResolution {
    fn state(&self) -> &'static str {
        match self.candidates.len() {
            0 => "missing",
            1 => "matched",
            _ => "ambiguous",
        }
    }

    fn matched_id(&self) -> Option<&str> {
        let [release_id] = self.candidates.as_slice() else {
            return None;
        };
        Some(release_id)
    }
}

struct ModuleIdentity {
    module: String,
    debug_id: Option<String>,
    code_id: Option<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SymbolWaiter {
    required_artifact: &'static str,
    module_name: String,
    architecture: String,
    debug_id: String,
    code_id: String,
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

fn processing_versions(result: &Value) -> Result<(i32, i32), JobError> {
    let schema = result
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(JobError::Deterministic("processor_output_invalid"))?;
    let processing = result
        .pointer("/current/processing_version")
        .and_then(Value::as_u64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(JobError::Deterministic("processor_output_invalid"))?;
    Ok((schema, processing))
}

fn event_search_text(result: &Value, context_facets: &[crate::data_rules::ContextFacet]) -> String {
    const MAX_SEARCH_DOCUMENT_CHARS: usize = 65_536;

    fn append(document: &mut String, remaining: &mut usize, value: Option<&str>) {
        let Some(value) = value.filter(|value| !value.is_empty()) else {
            return;
        };
        if *remaining == 0 {
            return;
        }
        if !document.is_empty() {
            document.push('\u{1f}');
            *remaining -= 1;
        }
        for character in value.chars().take(*remaining) {
            document.push(character);
            *remaining -= 1;
        }
    }

    let mut document = String::new();
    let mut remaining = MAX_SEARCH_DOCUMENT_CHARS;
    append(
        &mut document,
        &mut remaining,
        result
            .pointer("/crash_context/error_message")
            .and_then(Value::as_str),
    );
    append(
        &mut document,
        &mut remaining,
        result
            .pointer("/crash_context/user_comment")
            .and_then(Value::as_str),
    );
    if let Some(modules) = result
        .pointer("/current/symbolication/modules")
        .and_then(Value::as_array)
    {
        for module in modules {
            append(
                &mut document,
                &mut remaining,
                module.get("module").and_then(Value::as_str),
            );
        }
    }
    if let Some(threads) = result
        .pointer("/current/symbolication/threads")
        .and_then(Value::as_array)
    {
        for thread in threads {
            if let Some(frames) = thread.get("frames").and_then(Value::as_array) {
                for frame in frames {
                    append(
                        &mut document,
                        &mut remaining,
                        frame.get("function").and_then(Value::as_str),
                    );
                    if let Some(inlines) = frame.get("inlines").and_then(Value::as_array) {
                        for inline in inlines {
                            append(
                                &mut document,
                                &mut remaining,
                                inline.get("function").and_then(Value::as_str),
                            );
                        }
                    }
                }
            }
        }
    }
    for facet in context_facets {
        append(&mut document, &mut remaining, Some(&facet.value));
    }
    document
}

fn projected_text<'a>(result: &'a Value, pointer: &str) -> Option<&'a str> {
    result
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn projected_symbolication_state(state: &str, result: &Value) -> &'static str {
    if matches!(state, "failed" | "quarantined") {
        return "failed";
    }
    let resolved = result
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
        });
    let missing = result
        .pointer("/current/symbolication/modules")
        .and_then(Value::as_array)
        .is_some_and(|modules| {
            modules.iter().any(|module| {
                matches!(
                    module.get("status").and_then(Value::as_str),
                    Some("missing_pe" | "missing_pdb" | "mismatched" | "missing_identity")
                )
            })
        });
    match (resolved, missing, state) {
        (true, true, _) => "partial",
        (true, false, _) => "readable",
        (_, true, _) | (_, _, "awaiting_symbols") => "missing",
        _ => "processing",
    }
}

fn grouping_publication(enabled: bool, result: &Value) -> Result<GroupingPublication, JobError> {
    if !enabled {
        return Ok(GroupingPublication::Disabled);
    }
    match faultlane_grouping::fingerprint(result)
        .map_err(|_| JobError::Deterministic("processor_output_invalid"))?
    {
        faultlane_grouping::GroupingOutcome::Grouped(fingerprint) => {
            Ok(GroupingPublication::Grouped(fingerprint))
        }
        faultlane_grouping::GroupingOutcome::Insufficient => Ok(GroupingPublication::Insufficient),
    }
}

async fn lock_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    event_id: &str,
) -> Result<ExistingGrouping, JobError> {
    let row = sqlx::query(
        "SELECT grouping_state, issue_id::text AS issue_id, release_id::text AS release_id, received_at FROM crash_events WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid FOR UPDATE",
    )
    .bind(event_id)
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?
    .ok_or(JobError::LostLease)?;
    Ok(ExistingGrouping {
        state: row.get("grouping_state"),
        issue_id: row.get("issue_id"),
        release_id: row.get("release_id"),
        received_at: row.get("received_at"),
    })
}

async fn record_release_mapping(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    event_id: &str,
    release: &ReleaseResolution,
) -> Result<(), JobError> {
    sqlx::query(
        "DELETE FROM crash_event_release_candidates WHERE organization_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid",
    )
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(event_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if !release.candidates.is_empty() {
        sqlx::query(
            "INSERT INTO crash_event_release_candidates (organization_id, project_id, event_id, release_id) SELECT $1::uuid, $2::uuid, $3::uuid, candidates.release_id::uuid FROM unnest($4::text[]) AS candidates(release_id) ON CONFLICT DO NOTHING",
        )
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(event_id)
        .bind(&release.candidates)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
    }
    let updated = sqlx::query(
        "UPDATE crash_events SET release_id = $4::uuid, release_mapping_state = $5, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid",
    )
    .bind(event_id)
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(release.matched_id())
    .bind(release.state())
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(JobError::LostLease)
    }
}

async fn apply_grouping(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    event_id: &str,
    existing: ExistingGrouping,
    grouping: &GroupingPublication,
) -> Result<Option<GroupingAssignment>, JobError> {
    if existing.state == "grouped" {
        let issue_id = existing
            .issue_id
            .ok_or(JobError::Deterministic("grouping_state_invalid"))?;
        return Ok(Some(GroupingAssignment {
            issue_id,
            first_assignment: false,
            previous_release_id: existing.release_id,
            received_at: existing.received_at,
        }));
    }
    let GroupingPublication::Grouped(fingerprint) = grouping else {
        let state = match grouping {
            GroupingPublication::Disabled => "disabled",
            GroupingPublication::Insufficient => "insufficient",
            GroupingPublication::Grouped(_) => {
                return Err(JobError::Deterministic("grouping_state_invalid"));
            }
        };
        let updated = sqlx::query(
            "UPDATE crash_events SET grouping_state = $4, fingerprint_algorithm = $5, fingerprint_version = $6, issue_id = NULL, fingerprint = NULL, variant_fingerprint = NULL, grouping_quality = NULL, grouped_at = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND grouping_state <> 'grouped'",
        )
        .bind(event_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(state)
        .bind(faultlane_grouping::FINGERPRINT_ALGORITHM)
        .bind(i32::try_from(faultlane_grouping::FINGERPRINT_VERSION).unwrap_or(i32::MAX))
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        return if updated.rows_affected() == 1 {
            Ok(None)
        } else {
            Err(JobError::LostLease)
        };
    };
    assign_issue(
        transaction,
        job,
        event_id,
        fingerprint,
        existing.received_at,
    )
    .await
}

async fn assign_issue(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    event_id: &str,
    fingerprint: &faultlane_grouping::Fingerprint,
    received_at: time::OffsetDateTime,
) -> Result<Option<GroupingAssignment>, JobError> {
    let issue_id = random_uuid().map_err(|_| JobError::Transient("random_unavailable"))?;
    let inserted_issue: Option<String> = sqlx::query_scalar(
        "INSERT INTO issues (id, organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint, title, first_seen_at, last_seen_at, event_count, representative_event_id) SELECT $1::uuid, e.organization_id, e.project_id, $5, $6, $7, $8, e.received_at, e.received_at, 1, e.id FROM crash_events e WHERE e.id = $2::uuid AND e.organization_id = $3::uuid AND e.project_id = $4::uuid ON CONFLICT (organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint) DO NOTHING RETURNING id::text",
    )
    .bind(issue_id)
    .bind(event_id)
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(faultlane_grouping::FINGERPRINT_ALGORITHM)
    .bind(i32::try_from(faultlane_grouping::FINGERPRINT_VERSION).unwrap_or(i32::MAX))
    .bind(&fingerprint.issue_fingerprint)
    .bind(&fingerprint.title)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    let new_issue = inserted_issue.is_some();
    let stored_issue = if let Some(issue_id) = inserted_issue {
        issue_id
    } else {
        sqlx::query_scalar(
            "SELECT id::text FROM issues WHERE organization_id = $1::uuid AND project_id = $2::uuid AND fingerprint_algorithm = $3 AND fingerprint_version = $4 AND fingerprint = $5 FOR UPDATE",
        )
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(faultlane_grouping::FINGERPRINT_ALGORITHM)
        .bind(i32::try_from(faultlane_grouping::FINGERPRINT_VERSION).unwrap_or(i32::MAX))
        .bind(&fingerprint.issue_fingerprint)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?
        .ok_or(JobError::Deterministic("issue_missing"))?
    };
    let updated = sqlx::query(
        "UPDATE crash_events SET issue_id = $4::uuid, grouping_state = 'grouped', fingerprint_algorithm = $5, fingerprint_version = $6, fingerprint = $7, variant_fingerprint = $8, grouping_quality = $9, grouped_at = now(), updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND grouping_state <> 'grouped'",
    )
    .bind(event_id)
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(&stored_issue)
    .bind(faultlane_grouping::FINGERPRINT_ALGORITHM)
    .bind(i32::try_from(faultlane_grouping::FINGERPRINT_VERSION).unwrap_or(i32::MAX))
    .bind(&fingerprint.issue_fingerprint)
    .bind(&fingerprint.variant_fingerprint)
    .bind(fingerprint.grouping_quality)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if updated.rows_affected() == 1 {
        if !new_issue {
            let issue_updated = sqlx::query(
                "UPDATE issues i SET first_seen_at = LEAST(i.first_seen_at, event.received_at), last_seen_at = GREATEST(i.last_seen_at, event.received_at), event_count = i.event_count + 1, representative_event_id = CASE WHEN i.representative_event_id IS NULL OR COALESCE((SELECT event.grouping_quality > representative.grouping_quality OR (event.grouping_quality = representative.grouping_quality AND (event.received_at < representative.received_at OR (event.received_at = representative.received_at AND event.id < representative.id))) FROM crash_events representative WHERE representative.id = i.representative_event_id AND representative.organization_id = i.organization_id AND representative.project_id = i.project_id), true) THEN event.id ELSE i.representative_event_id END, updated_at = now() FROM crash_events event WHERE i.id = $1::uuid AND i.organization_id = $2::uuid AND i.project_id = $3::uuid AND event.id = $4::uuid AND event.organization_id = i.organization_id AND event.project_id = i.project_id",
            )
            .bind(&stored_issue)
            .bind(&job.organization_id)
            .bind(&job.project_id)
            .bind(event_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
            if issue_updated.rows_affected() != 1 {
                return Err(JobError::Deterministic("issue_missing"));
            }
        }
        let variant = sqlx::query(
            "INSERT INTO issue_variants (organization_id, project_id, issue_id, variant_fingerprint, first_seen_at, last_seen_at, event_count, representative_event_id) SELECT e.organization_id, e.project_id, e.issue_id, e.variant_fingerprint, e.received_at, e.received_at, 1, e.id FROM crash_events e WHERE e.id = $1::uuid AND e.organization_id = $2::uuid AND e.project_id = $3::uuid ON CONFLICT (organization_id, project_id, issue_id, variant_fingerprint) DO UPDATE SET first_seen_at = LEAST(issue_variants.first_seen_at, EXCLUDED.first_seen_at), last_seen_at = GREATEST(issue_variants.last_seen_at, EXCLUDED.last_seen_at), event_count = issue_variants.event_count + 1, representative_event_id = (SELECT member.id FROM crash_events member WHERE member.organization_id = EXCLUDED.organization_id AND member.project_id = EXCLUDED.project_id AND member.id IN (issue_variants.representative_event_id, EXCLUDED.representative_event_id) ORDER BY member.grouping_quality DESC, member.received_at, member.id LIMIT 1)",
        )
        .bind(event_id)
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
        if variant.rows_affected() != 1 {
            return Err(JobError::Deterministic("issue_rollup_invalid"));
        }
        Ok(Some(GroupingAssignment {
            issue_id: stored_issue,
            first_assignment: true,
            previous_release_id: None,
            received_at,
        }))
    } else {
        Err(JobError::LostLease)
    }
}

async fn apply_release_delta(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    event_id: &str,
    assignment: &GroupingAssignment,
    release_id: Option<&str>,
) -> Result<bool, JobError> {
    if !assignment.first_assignment && assignment.previous_release_id.as_deref() == release_id {
        return Ok(false);
    }
    if !assignment.first_assignment
        && let Some(previous_release_id) = assignment.previous_release_id.as_deref()
    {
        remove_release_membership(
            transaction,
            job,
            event_id,
            &assignment.issue_id,
            previous_release_id,
            assignment.received_at,
        )
        .await?;
    }
    if let Some(release_id) = release_id {
        add_release_membership(transaction, job, event_id, &assignment.issue_id, release_id)
            .await?;
    }
    Ok(true)
}

async fn add_release_membership(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    event_id: &str,
    issue_id: &str,
    release_id: &str,
) -> Result<(), JobError> {
    let release = sqlx::query(
        "INSERT INTO issue_releases (organization_id, project_id, issue_id, release_id, first_seen_at, last_seen_at, event_count, representative_event_id) SELECT e.organization_id, e.project_id, e.issue_id, e.release_id, e.received_at, e.received_at, 1, e.id FROM crash_events e WHERE e.id = $1::uuid AND e.organization_id = $2::uuid AND e.project_id = $3::uuid AND e.issue_id = $4::uuid AND e.release_id = $5::uuid AND e.release_mapping_state = 'matched' ON CONFLICT (organization_id, project_id, issue_id, release_id) DO UPDATE SET first_seen_at = LEAST(issue_releases.first_seen_at, EXCLUDED.first_seen_at), last_seen_at = GREATEST(issue_releases.last_seen_at, EXCLUDED.last_seen_at), event_count = issue_releases.event_count + 1, representative_event_id = (SELECT member.id FROM crash_events member WHERE member.organization_id = EXCLUDED.organization_id AND member.project_id = EXCLUDED.project_id AND member.id IN (issue_releases.representative_event_id, EXCLUDED.representative_event_id) ORDER BY member.grouping_quality DESC, member.received_at, member.id LIMIT 1)",
    )
    .bind(event_id)
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(issue_id)
    .bind(release_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if release.rows_affected() == 1 {
        Ok(())
    } else {
        Err(JobError::Deterministic("issue_rollup_invalid"))
    }
}

async fn remove_release_membership(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    event_id: &str,
    issue_id: &str,
    release_id: &str,
    received_at: time::OffsetDateTime,
) -> Result<(), JobError> {
    let deleted: Option<bool> = sqlx::query_scalar(
        "DELETE FROM issue_releases WHERE organization_id = $1::uuid AND project_id = $2::uuid AND issue_id = $3::uuid AND release_id = $4::uuid AND event_count = 1 RETURNING true",
    )
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(issue_id)
    .bind(release_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if deleted.is_some() {
        return Ok(());
    }
    let row = sqlx::query(
        "UPDATE issue_releases SET event_count = event_count - 1 WHERE organization_id = $1::uuid AND project_id = $2::uuid AND issue_id = $3::uuid AND release_id = $4::uuid AND event_count > 1 RETURNING first_seen_at, last_seen_at, representative_event_id::text AS representative_event_id",
    )
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(issue_id)
    .bind(release_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?
    .ok_or(JobError::Deterministic("issue_rollup_invalid"))?;
    let representative_event_id: String = row.get("representative_event_id");
    let first_seen_at: time::OffsetDateTime = row.get("first_seen_at");
    let last_seen_at: time::OffsetDateTime = row.get("last_seen_at");
    if representative_event_id != event_id
        && first_seen_at != received_at
        && last_seen_at != received_at
    {
        return Ok(());
    }
    let replacement_event_id = if representative_event_id == event_id {
        sqlx::query_scalar(
            "SELECT id::text FROM crash_events WHERE organization_id = $1::uuid AND project_id = $2::uuid AND issue_id = $3::uuid AND release_id = $4::uuid AND grouping_state = 'grouped' AND release_mapping_state = 'matched' ORDER BY grouping_quality DESC, received_at, id LIMIT 1",
        )
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(issue_id)
        .bind(release_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?
        .ok_or(JobError::Deterministic("issue_rollup_invalid"))?
    } else {
        representative_event_id
    };
    let (replacement_first_seen_at, replacement_last_seen_at) = if first_seen_at == received_at
        || last_seen_at == received_at
    {
        let bounds = sqlx::query(
                "SELECT min(received_at) AS first_seen_at, max(received_at) AS last_seen_at FROM crash_events WHERE organization_id = $1::uuid AND project_id = $2::uuid AND issue_id = $3::uuid AND release_id = $4::uuid AND grouping_state = 'grouped' AND release_mapping_state = 'matched'",
            )
            .bind(&job.organization_id)
            .bind(&job.project_id)
            .bind(issue_id)
            .bind(release_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| JobError::Transient("database_unavailable"))?;
        let first: Option<time::OffsetDateTime> = bounds.get("first_seen_at");
        let last: Option<time::OffsetDateTime> = bounds.get("last_seen_at");
        first
            .zip(last)
            .ok_or(JobError::Deterministic("issue_rollup_invalid"))?
    } else {
        (first_seen_at, last_seen_at)
    };
    let updated = sqlx::query(
        "UPDATE issue_releases SET first_seen_at = $5, last_seen_at = $6, representative_event_id = $7::uuid WHERE organization_id = $1::uuid AND project_id = $2::uuid AND issue_id = $3::uuid AND release_id = $4::uuid",
    )
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(issue_id)
    .bind(release_id)
    .bind(replacement_first_seen_at)
    .bind(replacement_last_seen_at)
    .bind(replacement_event_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(JobError::Deterministic("issue_rollup_invalid"))
    }
}

async fn update_issue_transitions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
    project_id: &str,
    issue_id: &str,
    transitions_enabled: bool,
) -> Result<(), JobError> {
    let issue = sqlx::query(
        "SELECT status, regression_state, resolved_in_release_id::text AS resolved_in_release_id FROM issues WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid FOR UPDATE",
    )
    .bind(issue_id)
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?
    .ok_or(JobError::Deterministic("issue_missing"))?;
    let chronology =
        load_release_chronology(transaction, organization_id, project_id, issue_id).await?;
    let status: String = issue.get("status");
    let regression_state: String = issue.get("regression_state");
    if !transitions_enabled {
        return update_issue_chronology(
            transaction,
            organization_id,
            project_id,
            issue_id,
            &chronology,
            &status,
            &regression_state,
        )
        .await;
    }
    let resolution_id: Option<String> = issue.get("resolved_in_release_id");
    let resolution_timestamp = if let Some(release_id) = resolution_id.as_deref() {
        sqlx::query_scalar::<_, Option<time::OffsetDateTime>>(
            "SELECT build_timestamp FROM releases WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid",
        )
        .bind(release_id)
        .bind(organization_id)
        .bind(project_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?
        .flatten()
    } else {
        None
    };
    let later = chronology.valid
        && resolution_timestamp
            .zip(chronology.last_timestamp)
            .is_some_and(|(resolved, latest)| latest > resolved);
    let (next_status, regression_state) = if status == "resolved" {
        if later {
            ("open", "regressed")
        } else {
            ("resolved", "resolved")
        }
    } else if resolution_id.is_some() {
        if later {
            ("open", "regressed")
        } else {
            ("open", "unknown")
        }
    } else if !chronology.valid {
        ("open", "unknown")
    } else if chronology.release_count == 1 {
        ("open", "new")
    } else {
        ("open", "ongoing")
    };
    update_issue_chronology(
        transaction,
        organization_id,
        project_id,
        issue_id,
        &chronology,
        next_status,
        regression_state,
    )
    .await
}

async fn refresh_issue_memberships(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
    project_id: &str,
    issue_id: &str,
) -> Result<(), JobError> {
    sqlx::query(
        "DELETE FROM issue_variants WHERE organization_id = $1::uuid AND project_id = $2::uuid AND issue_id = $3::uuid",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(issue_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    sqlx::query(
        "INSERT INTO issue_variants (organization_id, project_id, issue_id, variant_fingerprint, first_seen_at, last_seen_at, event_count, representative_event_id) SELECT e.organization_id, e.project_id, e.issue_id, e.variant_fingerprint, min(e.received_at), max(e.received_at), count(*), (array_agg(e.id ORDER BY e.grouping_quality DESC, e.received_at, e.id))[1] FROM crash_events e WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.issue_id = $3::uuid GROUP BY e.organization_id, e.project_id, e.issue_id, e.variant_fingerprint",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(issue_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    sqlx::query(
        "DELETE FROM issue_releases WHERE organization_id = $1::uuid AND project_id = $2::uuid AND issue_id = $3::uuid",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(issue_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    sqlx::query(
        "INSERT INTO issue_releases (organization_id, project_id, issue_id, release_id, first_seen_at, last_seen_at, event_count, representative_event_id) SELECT e.organization_id, e.project_id, e.issue_id, e.release_id, min(e.received_at), max(e.received_at), count(*), (array_agg(e.id ORDER BY e.grouping_quality DESC, e.received_at, e.id))[1] FROM crash_events e WHERE e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.issue_id = $3::uuid AND e.release_mapping_state = 'matched' GROUP BY e.organization_id, e.project_id, e.issue_id, e.release_id",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(issue_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    let updated = sqlx::query(
        "WITH aggregate AS (SELECT min(e.received_at) AS first_seen_at, max(e.received_at) AS last_seen_at, count(*) AS event_count, (array_agg(e.id ORDER BY e.grouping_quality DESC, e.received_at, e.id))[1] AS representative_event_id FROM crash_events e WHERE e.organization_id = $2::uuid AND e.project_id = $3::uuid AND e.issue_id = $1::uuid) UPDATE issues i SET first_seen_at = aggregate.first_seen_at, last_seen_at = aggregate.last_seen_at, event_count = aggregate.event_count, representative_event_id = aggregate.representative_event_id, updated_at = now() FROM aggregate WHERE i.id = $1::uuid AND i.organization_id = $2::uuid AND i.project_id = $3::uuid AND aggregate.event_count > 0",
    )
    .bind(issue_id)
    .bind(organization_id)
    .bind(project_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(JobError::Deterministic("issue_missing"))
    }
}

async fn load_release_chronology(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
    project_id: &str,
    issue_id: &str,
) -> Result<ReleaseChronology, JobError> {
    let rows = sqlx::query(
        "SELECT r.id::text AS id, r.build_timestamp FROM issue_releases ir JOIN releases r ON r.id = ir.release_id AND r.organization_id = ir.organization_id AND r.project_id = ir.project_id WHERE ir.organization_id = $1::uuid AND ir.project_id = $2::uuid AND ir.issue_id = $3::uuid ORDER BY r.build_timestamp NULLS LAST, r.id",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(issue_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    Ok(release_chronology(
        &rows
            .iter()
            .map(|row| ReleaseEvidence {
                id: row.get("id"),
                build_timestamp: row.get("build_timestamp"),
            })
            .collect::<Vec<_>>(),
    ))
}

fn release_chronology(evidence: &[ReleaseEvidence]) -> ReleaseChronology {
    let mut ordered = evidence
        .iter()
        .filter_map(|release| {
            release
                .build_timestamp
                .map(|timestamp| (timestamp, release.id.clone()))
        })
        .collect::<Vec<_>>();
    ordered.sort();
    let valid = !ordered.is_empty()
        && ordered.len() == evidence.len()
        && !ordered.windows(2).any(|pair| pair[0].0 == pair[1].0);
    if !valid {
        return ReleaseChronology {
            first: None,
            last: None,
            last_timestamp: None,
            release_count: evidence.len(),
            valid: false,
        };
    }
    ReleaseChronology {
        first: ordered.first().map(|(_, id)| id.clone()),
        last: ordered.last().map(|(_, id)| id.clone()),
        last_timestamp: ordered.last().map(|(timestamp, _)| *timestamp),
        release_count: ordered.len(),
        valid: true,
    }
}

async fn update_issue_chronology(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
    project_id: &str,
    issue_id: &str,
    chronology: &ReleaseChronology,
    status: &str,
    regression_state: &str,
) -> Result<(), JobError> {
    let updated = sqlx::query(
        "UPDATE issues SET first_release_id = $4::uuid, last_release_id = $5::uuid, status = $6, regression_state = $7, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid",
    )
    .bind(issue_id)
    .bind(organization_id)
    .bind(project_id)
    .bind(chronology.first.as_deref())
    .bind(chronology.last.as_deref())
    .bind(status)
    .bind(regression_state)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(JobError::Deterministic("issue_missing"))
    }
}

async fn lock_lease(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    worker_id: &str,
) -> Result<(), JobError> {
    let found: Option<String> = sqlx::query_scalar(
        "UPDATE jobs SET heartbeat_at = now(), lease_expires_at = now() + ($6 * interval '1 second'), updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'leased' AND lease_owner = $4 AND lease_token = $5::uuid AND lease_expires_at > now() RETURNING id::text",
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
        "UPDATE jobs SET state = 'completed', failure_code = $6, completed_at = now(), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'leased' AND lease_owner = $4 AND lease_token = $5::uuid",
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

async fn complete_reprocessing_request_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    event_id: &str,
    result_id: &str,
) -> Result<(), JobError> {
    if job.target_generation == 0 {
        return Ok(());
    }
    let request_ids = sqlx::query_scalar::<_, String>(
        "UPDATE crash_reprocessing_request_events SET state = 'completed', result_id = $5::uuid, failure_code = NULL, completed_at = now() WHERE organization_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid AND generation <= $4 AND state IN ('queued', 'running') RETURNING request_id::text",
    )
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(event_id)
    .bind(job.target_generation)
    .bind(result_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    for request_id in BTreeSet::from_iter(request_ids) {
        refresh_reprocessing_request(transaction, &request_id).await?;
    }
    Ok(())
}

async fn requeue_job_for_new_generation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    worker_id: &str,
) -> Result<(), JobError> {
    let updated = sqlx::query(
        "UPDATE jobs SET state = 'pending', priority = 200, attempt = 0, resource_failures = 0, available_at = now(), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL, failure_code = NULL, completed_at = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'leased' AND lease_owner = $4 AND lease_token = $5::uuid",
    )
    .bind(&job.id)
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(worker_id)
    .bind(&job.lease_token)
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
        "UPDATE jobs SET state = $6, failure_code = $7, resource_failures = resource_failures + CASE WHEN $8 THEN 1 ELSE 0 END, completed_at = now(), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL, updated_at = now() WHERE id = $1::uuid AND organization_id = $2::uuid AND project_id = $3::uuid AND state = 'leased' AND lease_owner = $4 AND lease_token = $5::uuid",
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

fn symbol_waiters(
    result: &Value,
    release: &ReleaseResolution,
) -> Result<Vec<SymbolWaiter>, JobError> {
    if release.matched_id().is_none() {
        return Ok(Vec::new());
    }
    let symbolication = result
        .pointer("/current/symbolication")
        .and_then(Value::as_object)
        .ok_or(JobError::Deterministic("processor_output_invalid"))?;
    let architecture = symbolication
        .get("architecture")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 32)
        .ok_or(JobError::Deterministic("processor_output_invalid"))?;
    let modules = symbolication
        .get("modules")
        .and_then(Value::as_array)
        .ok_or(JobError::Deterministic("processor_output_invalid"))?;
    let mut waiters = BTreeSet::new();
    for module in modules {
        let Some(module_name) = module
            .get("module")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 256)
        else {
            continue;
        };
        let Some(debug_id) = module
            .get("debug_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 128)
        else {
            continue;
        };
        let code_id = module
            .get("code_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 128);
        let status = module
            .get("status")
            .and_then(Value::as_str)
            .ok_or(JobError::Deterministic("processor_output_invalid"))?;
        if matches!(status, "missing_pdb" | "mismatched") {
            waiters.insert(SymbolWaiter {
                required_artifact: "pdb",
                module_name: module_name.to_ascii_lowercase(),
                architecture: architecture.to_ascii_lowercase(),
                debug_id: debug_id.to_ascii_uppercase(),
                code_id: String::new(),
            });
        }
        if matches!(status, "missing_pe" | "mismatched")
            && let Some(code_id) = code_id
        {
            waiters.insert(SymbolWaiter {
                required_artifact: "pe",
                module_name: module_name.to_ascii_lowercase(),
                architecture: architecture.to_ascii_lowercase(),
                debug_id: debug_id.to_ascii_uppercase(),
                code_id: code_id.to_ascii_uppercase(),
            });
        }
        if waiters.len() > MAX_SYMBOL_WAITERS {
            return Err(JobError::Deterministic("processor_output_invalid"));
        }
    }
    Ok(waiters.into_iter().collect())
}

async fn replace_symbol_waiters(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job: &Job,
    event_id: &str,
    result_id: &str,
    release: &ReleaseResolution,
    waiters: &[SymbolWaiter],
) -> Result<(), JobError> {
    sqlx::query(
        "DELETE FROM crash_symbol_waiters WHERE organization_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid",
    )
    .bind(&job.organization_id)
    .bind(&job.project_id)
    .bind(event_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::Transient("database_unavailable"))?;
    let Some(release_id) = release.matched_id() else {
        return Ok(());
    };
    if !waiters.is_empty() {
        let required_artifacts = waiters
            .iter()
            .map(|waiter| waiter.required_artifact)
            .collect::<Vec<_>>();
        let module_names = waiters
            .iter()
            .map(|waiter| waiter.module_name.as_str())
            .collect::<Vec<_>>();
        let architectures = waiters
            .iter()
            .map(|waiter| waiter.architecture.as_str())
            .collect::<Vec<_>>();
        let debug_ids = waiters
            .iter()
            .map(|waiter| waiter.debug_id.as_str())
            .collect::<Vec<_>>();
        let code_ids = waiters
            .iter()
            .map(|waiter| waiter.code_id.as_str())
            .collect::<Vec<_>>();
        sqlx::query(
            "INSERT INTO crash_symbol_waiters (organization_id, project_id, event_id, result_id, release_id, required_artifact, module_name, architecture, debug_id, code_id) SELECT $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, waiters.required_artifact, waiters.module_name, waiters.architecture, waiters.debug_id, waiters.code_id FROM unnest($6::text[], $7::text[], $8::text[], $9::text[], $10::text[]) AS waiters(required_artifact, module_name, architecture, debug_id, code_id) ON CONFLICT DO NOTHING",
        )
        .bind(&job.organization_id)
        .bind(&job.project_id)
        .bind(event_id)
        .bind(result_id)
        .bind(release_id)
        .bind(required_artifacts)
        .bind(module_names)
        .bind(architectures)
        .bind(debug_ids)
        .bind(code_ids)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::Transient("database_unavailable"))?;
    }
    Ok(())
}

fn release_lookup(result: &Value) -> Result<Option<ReleaseLookup>, JobError> {
    let context = result
        .get("crash_context")
        .and_then(Value::as_object)
        .ok_or(JobError::Deterministic("processor_output_invalid"))?;
    let Some(version) = context
        .get("build_version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    let Some(platform) = context
        .get("platform")
        .and_then(|value| value.get("normalized"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    let Some(architecture) = context
        .get("architecture")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    let Some(configuration) = context
        .get("build_configuration")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    Ok(Some(ReleaseLookup {
        version: version.to_owned(),
        platform: platform.to_owned(),
        architecture: architecture.to_owned(),
        configuration: configuration.to_owned(),
    }))
}

fn validate_processing_result(result: &Value, expected_guid: Option<&str>) -> Result<(), JobError> {
    faultlane_processing::validate_current_processing_result(result, expected_guid).map_err(
        |error| match error {
            faultlane_processing::ProcessingResultError::PreviousIdentityMismatch => {
                JobError::Deterministic("crash_identity_mismatch")
            }
            _ => JobError::Deterministic("processor_output_invalid"),
        },
    )?;
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

fn map_usage_error(error: crate::usage::UsageError) -> JobError {
    match error {
        crate::usage::UsageError::NotFound => JobError::Deterministic("usage_state_missing"),
        crate::usage::UsageError::InvalidRequest
        | crate::usage::UsageError::Unauthorized
        | crate::usage::UsageError::Forbidden => JobError::Deterministic("usage_policy_invalid"),
        crate::usage::UsageError::Unavailable | crate::usage::UsageError::Internal => {
            JobError::Transient("database_unavailable")
        }
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
        let current = format!("*{sid}");
        let current_sid_found = std::process::Command::new(icacls)
            .arg(path)
            .args(["/findsid", &current])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?
            .success();
        if windows_acl_is_private(&descriptor, sid, current_sid_found) {
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
fn windows_acl_is_private(descriptor: &str, sid: &str, current_sid_present: bool) -> bool {
    if !current_sid_present {
        return false;
    }
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
    let mut trustees: Vec<&str> = dacl[first_ace..]
        .split('(')
        .skip(1)
        .filter_map(|ace| ace.strip_suffix(')'))
        .filter_map(|ace| ace.strip_prefix("A;OICI;FA;;;"))
        .collect();
    let ace_count = dacl[first_ace..].matches('(').count();
    if trustees.len() != ace_count || trustees.iter().any(|trustee| trustee.contains(['(', ')'])) {
        return false;
    }
    trustees.sort_unstable();
    trustees.dedup();
    let system_count = trustees
        .iter()
        .filter(|trustee| matches!(**trustee, "SY" | "S-1-5-18"))
        .count();
    system_count == 1 && trustees.len() == usize::from(sid != "S-1-5-18") + 1
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
        collections::BTreeMap,
        env,
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicI64, Ordering},
        },
        time::{Duration, Instant},
    };

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use sqlx::{PgPool, Row, postgres::PgPoolOptions};
    use tokio::task::JoinSet;

    use super::{
        Job, JobError, ModuleIdentity, ReleaseEvidence, ReleaseLookup, ReleaseResolution,
        SelectedArtifact, Worker, WorkerSettings, attempt_identity, claim_job,
        claim_job_with_project_limit, complete_job, container_name, event_search_text,
        has_resolved_frame, lock_lease, owned_attempt, prepare_worker_scratch, processor_scope,
        projected_symbolication_state, projected_text, random_uuid, release_chronology,
        release_lookup, selected_artifact_size_valid, set_private_permissions, strict_json,
        valid_internal_uuid,
    };
    use crate::project_setup::{DATABASE_TEST_LOCK, migrate};
    use crate::{
        processor_runner::{OwnedContainer, ProcessorRunner},
        symbol_upload::{ArtifactObjects, MemoryObjects},
    };

    fn test_temp_directory() -> PathBuf {
        #[cfg(windows)]
        {
            let Some(path) = env::var_os("USERPROFILE") else {
                panic!("Windows test profile must exist");
            };
            PathBuf::from(path)
        }
        #[cfg(not(windows))]
        env::temp_dir()
    }

    #[test]
    fn worker_concurrency_is_bounded_and_sizes_the_database_pool() {
        let defaults = WorkerSettings::parse(None, None)
            .unwrap_or_else(|error| panic!("default settings must parse: {error}"));
        assert_eq!(defaults.worker_concurrency, 1);
        assert_eq!(defaults.project_concurrency, 1);
        assert_eq!(defaults.pool_connections(), 6);

        let maximum = WorkerSettings::parse(Some("8"), Some("8"))
            .unwrap_or_else(|error| panic!("maximum settings must parse: {error}"));
        assert_eq!(maximum.worker_concurrency, 8);
        assert_eq!(maximum.project_concurrency, 8);
        assert_eq!(maximum.pool_connections(), 20);

        for invalid in ["0", "9", "invalid"] {
            assert!(WorkerSettings::parse(Some(invalid), None).is_err());
            assert!(WorkerSettings::parse(None, Some(invalid)).is_err());
        }
    }

    #[test]
    fn event_search_projects_only_approved_current_fields() {
        let result = json!({
            "crash_context": {
                "error_message": "access violation",
                "user_comment": "player report",
                "unknown_fields": {"Secret": "do-not-index"}
            },
            "log": {"tail": {"text": "do-not-index"}},
            "current": {"symbolication": {
                "modules": [{"module": "Game.exe"}],
                "threads": [{"frames": [{
                    "function": "Arena::Tick()",
                    "inlines": [{"function": "Arena::Inner()"}]
                }]}]
            }}
        });

        assert_eq!(
            event_search_text(&result, &[]),
            "access violation\u{1f}player report\u{1f}Game.exe\u{1f}Arena::Tick()\u{1f}Arena::Inner()"
        );
        assert_eq!(
            projected_text(&result, "/crash_context/error_message"),
            Some("access violation")
        );
        assert_eq!(projected_text(&result, "/crash_context/unknown"), None);
        assert_eq!(
            projected_symbolication_state("processed", &result),
            "processing"
        );

        let oversized = json!({
            "crash_context": {"error_message": "雪".repeat(70_000)}
        });
        let projected = event_search_text(&oversized, &[]);
        assert_eq!(projected.chars().count(), 65_536);
        assert!(projected.chars().all(|character| character == '雪'));
    }

    #[test]
    fn event_search_projects_symbolication_state() {
        let partial = json!({
            "current": {"symbolication": {
                "modules": [{"status": "missing_pdb"}],
                "threads": [{"frames": [{"symbol_status": "resolved"}]}]
            }}
        });
        let readable = json!({
            "current": {"symbolication": {
                "modules": [{"status": "matched"}],
                "threads": [{"frames": [{"symbol_status": "resolved"}]}]
            }}
        });
        assert_eq!(
            projected_symbolication_state("processed", &partial),
            "partial"
        );
        assert_eq!(
            projected_symbolication_state("processed", &readable),
            "readable"
        );
        assert_eq!(
            projected_symbolication_state("awaiting_symbols", &json!({})),
            "missing"
        );
        assert_eq!(
            projected_symbolication_state("quarantined", &readable),
            "failed"
        );
    }

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
        assert!(super::windows_acl_is_private(&descriptor, sid, true));
        assert!(super::windows_acl_is_private(
            "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;LA)\r\n",
            sid,
            true
        ));
        assert!(!super::windows_acl_is_private(
            "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;LA)\r\n",
            sid,
            false
        ));
        assert!(!super::windows_acl_is_private(
            "D:NO_ACCESS_CONTROL\r\n",
            sid,
            true
        ));
        assert!(!super::windows_acl_is_private(
            "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;LA)(A;OICI;FA;;;BA)\r\n",
            sid,
            true
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_scratch_acl_uses_system_tools() {
        let path = test_temp_directory().join(format!(
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
        let owned = test_temp_directory().join(format!(
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

        let unowned = test_temp_directory().join(format!(
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
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    async fn reconciliation_removes_stale_scratch_without_touching_unknown_entries() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
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
            grouping_enabled: false,
            reprocessing_enabled: false,
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
    fn symbol_waiters_require_exact_bounded_identities_and_one_release() {
        let mut result = processing_result("UECC-Windows-Waiters", "1.0.0", "CrashFixture()");
        result["current"]["symbolication"]["modules"][0]["status"] = json!("mismatched");
        result["current"]["symbolication"]["modules"][0]["module"] = json!("GAME.EXE");
        result["current"]["symbolication"]["modules"][0]["debug_id"] = json!("debug-a");
        result["current"]["symbolication"]["modules"][0]["code_id"] = json!("code-a");
        let matched = release_resolution(
            "1.0.0",
            vec!["11111111-1111-4111-8111-111111111111".to_owned()],
        );
        let waiters = super::symbol_waiters(&result, &matched)
            .unwrap_or_else(|error| panic!("waiters must parse: {error:?}"));
        assert_eq!(waiters.len(), 2);
        assert_eq!(waiters[0].architecture, "x86_64");
        assert_eq!(waiters[0].debug_id, "DEBUG-A");
        assert_eq!(waiters[0].module_name, "game.exe");
        assert!(
            waiters
                .iter()
                .any(|waiter| { waiter.required_artifact == "pe" && waiter.code_id == "CODE-A" })
        );
        assert!(
            waiters
                .iter()
                .any(|waiter| { waiter.required_artifact == "pdb" && waiter.code_id.is_empty() })
        );

        let ambiguous = release_resolution(
            "1.0.0",
            vec![
                "11111111-1111-4111-8111-111111111111".to_owned(),
                "22222222-2222-4222-8222-222222222222".to_owned(),
            ],
        );
        assert!(
            super::symbol_waiters(&result, &ambiguous)
                .unwrap_or_else(|error| panic!("ambiguous result must parse: {error:?}"))
                .is_empty()
        );
        result["current"]["symbolication"]["modules"][0]["status"] = json!("missing_pe");
        result["current"]["symbolication"]["modules"][0]["code_id"] = Value::Null;
        assert!(
            super::symbol_waiters(&result, &matched)
                .unwrap_or_else(|error| panic!("incomplete identity must parse: {error:?}"))
                .is_empty()
        );
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

    #[test]
    fn release_lookup_requires_the_complete_structured_identity() {
        let mut result = json!({"crash_context": {
            "build_version": "1.0.0",
            "platform": {"normalized": "windows"},
            "architecture": "x86_64",
            "build_configuration": "Shipping"
        }});
        let lookup = release_lookup(&result)
            .unwrap_or_else(|_| panic!("release lookup must parse"))
            .unwrap_or_else(|| panic!("complete release lookup must exist"));
        assert_eq!(lookup.version, "1.0.0");
        assert_eq!(lookup.platform, "windows");

        result["crash_context"]["build_configuration"] = Value::Null;
        assert!(
            release_lookup(&result)
                .unwrap_or_else(|_| panic!("missing release lookup must parse"))
                .is_none()
        );
    }

    #[test]
    fn release_chronology_rejects_missing_and_tied_timestamps() {
        let first = time::OffsetDateTime::from_unix_timestamp(100)
            .unwrap_or_else(|error| panic!("first timestamp must parse: {error}"));
        let second = time::OffsetDateTime::from_unix_timestamp(200)
            .unwrap_or_else(|error| panic!("second timestamp must parse: {error}"));
        let ordered = release_chronology(&[
            ReleaseEvidence {
                id: "first".to_owned(),
                build_timestamp: Some(first),
            },
            ReleaseEvidence {
                id: "second".to_owned(),
                build_timestamp: Some(second),
            },
        ]);
        assert!(ordered.valid);
        assert_eq!(ordered.first.as_deref(), Some("first"));
        assert_eq!(ordered.last.as_deref(), Some("second"));

        let tied = release_chronology(&[
            ReleaseEvidence {
                id: "first".to_owned(),
                build_timestamp: Some(first),
            },
            ReleaseEvidence {
                id: "second".to_owned(),
                build_timestamp: Some(first),
            },
        ]);
        assert!(!tied.valid);
        let missing = release_chronology(&[ReleaseEvidence {
            id: "first".to_owned(),
            build_timestamp: None,
        }]);
        assert!(!missing.valid);
    }

    async fn explain_plan(pool: &PgPool, query: &'static str) -> String {
        sqlx::query(query)
            .fetch_all(pool)
            .await
            .unwrap_or_else(|error| panic!("query plan must load: {error}"))
            .iter()
            .map(|row| row.get::<String, _>("QUERY PLAN"))
            .collect::<Vec<_>>()
            .join("\n")
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

    async fn lease_exact_job(pool: &PgPool, job_id: &str, owner: &str) -> Job {
        let lease_token =
            random_uuid().unwrap_or_else(|error| panic!("lease token must generate: {error}"));
        let row = sqlx::query(
            "UPDATE jobs SET state = 'leased', attempt = attempt + 1, lease_owner = $2, lease_token = $3::uuid, lease_expires_at = now() + interval '5 minutes', heartbeat_at = now(), failure_code = NULL, completed_at = NULL, updated_at = now() WHERE id = $1::uuid RETURNING id::text AS id, organization_id::text AS organization_id, project_id::text AS project_id, event_id::text AS event_id, artifact_upload_id::text AS artifact_upload_id, derived_cache_id::text AS derived_cache_id, job_type, attempt, max_attempt, resource_failures, lease_token::text AS lease_token, COALESCE((SELECT requested_reprocessing_generation FROM crash_events WHERE id = jobs.event_id), 0) AS target_generation, 1::bigint AS project_active_jobs, 0::bigint AS queue_age_seconds",
        )
        .bind(job_id)
        .bind(owner)
        .bind(&lease_token)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("job must lease: {error}"));
        Job {
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
            target_generation: row.get("target_generation"),
            project_active_jobs: row.get("project_active_jobs"),
            queue_age_seconds: row.get("queue_age_seconds"),
        }
    }

    fn publication_worker(pool: PgPool, owner: &str, grouping_enabled: bool) -> Worker {
        Worker {
            pool,
            objects: ArtifactObjects::Memory(Arc::new(Mutex::new(MemoryObjects::default()))),
            runner: ProcessorRunner::test(),
            scratch: Arc::new(env::temp_dir()),
            instance_id: Arc::from(owner.to_owned()),
            grouping_enabled,
            reprocessing_enabled: true,
        }
    }

    struct TestScope {
        user: String,
        organization: String,
        project: String,
    }

    async fn insert_test_scope(pool: &PgPool, subject: &str, slug: &str) -> TestScope {
        let user_id: String = sqlx::query_scalar(
            "INSERT INTO users (bootstrap_subject, email) VALUES ($1, $2) RETURNING id::text",
        )
        .bind(subject)
        .bind(format!("{slug}@example.com"))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("test user must insert: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
        )
        .bind(slug)
        .bind(slug)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("test organization must insert: {error}"));
        sqlx::query(
            "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')",
        )
        .bind(&organization_id)
        .bind(&user_id)
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("test membership must insert: {error}"));
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, $2, $2) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(slug)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("test project must insert: {error}"));
        TestScope {
            user: user_id,
            organization: organization_id,
            project: project_id,
        }
    }

    async fn insert_manual_reprocessing_request(
        pool: &PgPool,
        organization_id: &str,
        project_id: &str,
        user_id: &str,
        scope_kind: &str,
        scope_value: Option<&str>,
        nonce: &str,
    ) -> String {
        let digest = Sha256::digest(format!("manual-request-{nonce}")).to_vec();
        sqlx::query_scalar(
            "INSERT INTO crash_reprocessing_requests (organization_id, project_id, source, scope_kind, scope_value, scope_fingerprint, idempotency_digest, requested_by_user_id, request_limit) VALUES ($1::uuid, $2::uuid, 'manual', $3, $4, $5, $5, $6::uuid, 1) RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(scope_kind)
        .bind(scope_value)
        .bind(digest)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("manual request must insert: {error}"))
    }

    async fn insert_manual_reprocessing_page(
        pool: &PgPool,
        scope: &TestScope,
        scope_kind: &str,
        scope_value: Option<&str>,
        nonce: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> String {
        let digest = Sha256::digest(format!("manual-page-{nonce}")).to_vec();
        sqlx::query_scalar(
            "INSERT INTO crash_reprocessing_requests (organization_id, project_id, source, scope_kind, scope_value, scope_fingerprint, idempotency_digest, requested_by_user_id, request_limit, input_cursor_event_id) VALUES ($1::uuid, $2::uuid, 'manual', $3, $4, $5, $5, $6::uuid, $7, $8::uuid) RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(scope_kind)
        .bind(scope_value)
        .bind(digest)
        .bind(&scope.user)
        .bind(limit)
        .bind(cursor)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("manual page must insert: {error}"))
    }

    fn processing_result(crash_guid: &str, version: &str, function: &str) -> Value {
        json!({
            "schema_version": 1,
            "crash_guid": crash_guid,
            "crash_context": {
                "parser_version": 1,
                "crash_guid": crash_guid,
                "crash_type": "crash",
                "error_message": null,
                "build_version": version,
                "engine_version": "5.8.1",
                "platform": {"original": "Win64", "normalized": "windows"},
                "architecture": "x86_64",
                "build_configuration": "Shipping",
                "modules": [],
                "threads": [],
                "system_metadata": [],
                "user_comment": null,
                "game_data": [],
                "unknown_fields": {}
            },
            "classification": {
                "crash_type": "crash",
                "confidence": "high",
                "evidence": [],
                "signals": []
            },
            "current": {
                "processing_version": 2,
                "parser_version": 1,
                "symbolication": {
                    "schema_version": 2,
                    "symbolicator_version": "0.1.0",
                    "minidump_version": "0.27.0",
                    "minidump_processor_version": "0.27.0",
                    "minidump_unwind_version": "0.27.0",
                    "platform": "windows",
                    "architecture": "x86_64",
                    "faulting_thread_id": 7,
                    "exception_reason": "EXCEPTION_ACCESS_VIOLATION_READ",
                    "assertion": null,
                    "modules": [{
                        "module": "Game.exe",
                        "base_address": "0x0000000140000000",
                        "size": 4096,
                        "code_id": "CODE-A",
                        "debug_id": "DEBUG-A",
                        "status": "matched",
                        "pe": "game.exe",
                        "pdb": "game.pdb"
                    }],
                    "threads": [{
                        "thread_id": 7,
                        "faulting": true,
                        "name": "GameThread",
                        "unwind_status": "ok",
                        "frames_truncated": false,
                        "frames": [{
                            "instruction": "0x0000000140001000",
                            "module": "Game.exe",
                            "module_relative": "0x1000",
                            "trust": "context",
                            "symbol_status": "resolved",
                            "function": function,
                            "source_file": "Game/Source/Arena.cpp",
                            "source_line": 42,
                            "inlines": []
                        }]
                    }]
                }
            },
            "history": []
        })
    }

    fn release_resolution(version: &str, candidates: Vec<String>) -> ReleaseResolution {
        ReleaseResolution {
            lookup: Some(ReleaseLookup {
                version: version.to_owned(),
                platform: "windows".to_owned(),
                architecture: "x86_64".to_owned(),
                configuration: "Shipping".to_owned(),
            }),
            candidates,
        }
    }

    async fn publish_new_event(
        worker: &Worker,
        organization_id: &str,
        project_id: &str,
        suffix: &str,
        result: Value,
        release: &ReleaseResolution,
        received_at: &str,
    ) -> (String, String) {
        let job_id = insert_event_job(&worker.pool, organization_id, project_id, suffix).await;
        let job = lease_exact_job(&worker.pool, &job_id, worker.instance_id.as_ref()).await;
        let event_id = job
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("crash job must have an event"));
        sqlx::query("UPDATE crash_events SET received_at = $2::timestamptz WHERE id = $1::uuid")
            .bind(&event_id)
            .bind(received_at)
            .execute(&worker.pool)
            .await
            .unwrap_or_else(|error| panic!("event timestamp must update: {error}"));
        worker
            .publish_crash_result(
                &job,
                &event_id,
                result,
                "processed",
                "processing_complete",
                release,
            )
            .await
            .unwrap_or_else(|error| panic!("event publication must succeed: {error:?}"));
        (job_id, event_id)
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn rule_changes_redact_current_results_and_reindex_only_approved_context() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let scope = insert_test_scope(&pool, "data-rules", "data-rules").await;
        let worker = publication_worker(pool.clone(), "data-rules-worker", false);
        let release = release_resolution("1.0.0", Vec::new());
        let mut original = processing_result("UECC-Windows-Data-Rules", "1.0.0", "Rules::Crash()");
        original["crash_context"]["error_message"] = json!("failed with test-secret in Arena");
        original["crash_context"]["user_comment"] = json!("test-secret");
        original["crash_context"]["system_metadata"] =
            json!([{"name": "Account", "value": "test-secret"}]);
        original["crash_context"]["game_data"] = json!([
            {"name": "MapName", "value": "Arena-test-secret"},
            {"name": "Private", "value": "test-secret"}
        ]);
        original["log"] = json!({
            "name": "Project.log",
            "tail": {
                "text": "token test-secret",
                "truncated": false,
                "invalid_utf8": false
            }
        });
        let (job_id, event_id) = publish_new_event(
            &worker,
            &scope.organization,
            &scope.project,
            "data-rules-event",
            original.clone(),
            &release,
            "2020-08-15T00:00:00Z",
        )
        .await;
        let initial: (i64, String, i64) = sqlx::query_as(
            "SELECT r.data_rules_version, s.search_text, (SELECT count(*) FROM crash_event_context_facets f WHERE f.event_id = e.id) FROM crash_events e JOIN crash_processing_results r ON r.id = e.current_result_id JOIN crash_event_search s ON s.event_id = e.id AND s.result_id = e.current_result_id WHERE e.id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("initial projection must load: {error}"));
        assert_eq!(initial.0, 0);
        assert!(initial.1.contains("test-secret"));
        assert_eq!(initial.2, 0);

        sqlx::query(
            "INSERT INTO project_data_rules (organization_id, project_id, version, redaction_patterns, indexed_game_data_keys, updated_by_user_id) VALUES ($1::uuid, $2::uuid, 1, ARRAY['test-secret'], ARRAY['MapName'], $3::uuid)",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&scope.user)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("data rules must insert: {error}"));
        sqlx::query(
            "INSERT INTO crash_reprocessing_requests (organization_id, project_id, source, scope_kind, scope_value, scope_fingerprint, idempotency_digest) VALUES ($1::uuid, $2::uuid, 'automatic', 'data_rules_version', '1', $3, $3)",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(vec![7_u8; 32])
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("rule reprocessing request must insert: {error}"));
        assert!(
            worker
                .schedule_reprocessing_request()
                .await
                .unwrap_or_else(|()| panic!("rule reprocessing must schedule"))
        );
        let job = lease_exact_job(&pool, &job_id, worker.instance_id.as_ref()).await;
        worker
            .publish_crash_result(
                &job,
                &event_id,
                original.clone(),
                "processed",
                "processing_complete",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("redacted result must publish: {error:?}"));

        let current = sqlx::query(
            "SELECT r.result, r.data_rules_version, s.search_text, o.checksum, q.state AS request_state FROM crash_events e JOIN crash_processing_results r ON r.id = e.current_result_id JOIN crash_event_search s ON s.event_id = e.id AND s.result_id = e.current_result_id JOIN crash_event_objects o ON o.id = e.raw_object_id JOIN crash_reprocessing_request_events x ON x.event_id = e.id JOIN crash_reprocessing_requests q ON q.id = x.request_id WHERE e.id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("redacted projection must load: {error}"));
        let result: Value = current.get("result");
        let encoded = result.to_string();
        assert!(!encoded.contains("test-secret"));
        assert_eq!(current.get::<i64, _>("data_rules_version"), 1);
        assert!(
            !current
                .get::<String, _>("search_text")
                .contains("test-secret")
        );
        assert_eq!(current.get::<Vec<u8>, _>("checksum"), vec![0_u8; 32]);
        assert_eq!(current.get::<String, _>("request_state"), "completed");
        let facets = sqlx::query(
            "SELECT key, value, value_truncated FROM crash_event_context_facets WHERE organization_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid ORDER BY key, value",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&event_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("context facets must load: {error}"));
        assert_eq!(facets.len(), 1);
        assert_eq!(facets[0].get::<String, _>("key"), "MapName");
        assert_eq!(facets[0].get::<String, _>("value"), "Arena-[REDACTED]");
        assert!(!facets[0].get::<bool, _>("value_truncated"));

        let duplicate = lease_exact_job(&pool, &job_id, worker.instance_id.as_ref()).await;
        worker
            .publish_crash_result(
                &duplicate,
                &event_id,
                original,
                "processed",
                "processing_complete",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("duplicate reprocessing must publish: {error:?}"));
        let rule_version_results: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_processing_results WHERE event_id = $1::uuid AND data_rules_version = 1",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("result count must load: {error}"));
        assert_eq!(rule_version_results, 1);
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn publication_groups_repeats_maps_releases_and_flags_regressions_when_configured() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Grouping test', 'grouping-test') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("organization must insert: {error}"));
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Game', 'game') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("project must insert: {error}"));
        let releases = sqlx::query(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '1.0.0', 'windows', 'x86_64', 'Shipping', '2026-01-01T00:00:00Z'), ($1::uuid, $2::uuid, '2.0.0', 'windows', 'x86_64', 'Shipping', '2026-02-01T00:00:00Z') RETURNING id::text AS id, version",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("ordered releases must insert: {error}"));
        let first_release: String = releases
            .iter()
            .find(|row| row.get::<String, _>("version") == "1.0.0")
            .map_or_else(|| panic!("first release must exist"), |row| row.get("id"));
        let second_release: String = releases
            .iter()
            .find(|row| row.get::<String, _>("version") == "2.0.0")
            .map_or_else(|| panic!("second release must exist"), |row| row.get("id"));
        let worker = publication_worker(pool.clone(), "grouping-worker", true);
        let first_mapping = release_resolution("1.0.0", vec![first_release.clone()]);
        let (first_job, first_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "group-first",
            processing_result("UECC-Windows-Group-1", "1.0.0", "Arena::Tick()"),
            &first_mapping,
            "2026-01-02T00:00:00Z",
        )
        .await;
        let issue_id: String =
            sqlx::query_scalar("SELECT issue_id::text FROM crash_events WHERE id = $1::uuid")
                .bind(&first_event)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("first issue must load: {error}"));

        let retry = lease_exact_job(&pool, &first_job, worker.instance_id.as_ref()).await;
        worker
            .publish_crash_result(
                &retry,
                &first_event,
                processing_result("UECC-Windows-Group-1", "1.0.0", "Arena::Tick()"),
                "processed",
                "processing_complete",
                &first_mapping,
            )
            .await
            .unwrap_or_else(|error| panic!("retry must remain idempotent: {error:?}"));

        let (_, second_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "group-second",
            processing_result("UECC-Windows-Group-2", "1.0.0", "Arena::Tick()"),
            &first_mapping,
            "2026-01-03T00:00:00Z",
        )
        .await;
        let (_, distinct_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "group-distinct",
            processing_result("UECC-Windows-Distinct", "1.0.0", "Arena::Load()"),
            &first_mapping,
            "2026-01-04T00:00:00Z",
        )
        .await;
        let distinct_issue: String =
            sqlx::query_scalar("SELECT issue_id::text FROM crash_events WHERE id = $1::uuid")
                .bind(&distinct_event)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("distinct issue must load: {error}"));
        assert_ne!(issue_id, distinct_issue);

        sqlx::query(
            "UPDATE issues SET status = 'resolved', regression_state = 'resolved', resolved_in_release_id = $2::uuid, resolved_at = now() WHERE id = $1::uuid",
        )
        .bind(&issue_id)
        .bind(&first_release)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("issue must resolve: {error}"));
        let second_mapping = release_resolution("2.0.0", vec![second_release.clone()]);
        let (_, later_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "group-later",
            processing_result("UECC-Windows-Group-3", "2.0.0", "Arena::Tick()"),
            &second_mapping,
            "2026-02-02T00:00:00Z",
        )
        .await;

        let issue = sqlx::query(
            "SELECT status, regression_state, event_count, representative_event_id::text AS representative_event_id, first_release_id::text AS first_release_id, last_release_id::text AS last_release_id FROM issues WHERE id = $1::uuid",
        )
        .bind(&issue_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("grouped issue must load: {error}"));
        assert_eq!(issue.get::<String, _>("status"), "open");
        assert_eq!(issue.get::<String, _>("regression_state"), "regressed");
        assert_eq!(issue.get::<i64, _>("event_count"), 3);
        assert_eq!(
            issue.get::<String, _>("representative_event_id"),
            first_event
        );
        assert_eq!(issue.get::<String, _>("first_release_id"), first_release);
        assert_eq!(issue.get::<String, _>("last_release_id"), second_release);
        let repeated_ids = sqlx::query_scalar::<_, String>(
            "SELECT issue_id::text FROM crash_events WHERE id = ANY(ARRAY(SELECT value::uuid FROM unnest($1::text[]) AS values(value)))",
        )
        .bind(vec![second_event, later_event])
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("repeat assignments must load: {error}"));
        assert!(repeated_ids.iter().all(|id| id == &issue_id));
        let variants: i64 =
            sqlx::query_scalar("SELECT count(*) FROM issue_variants WHERE issue_id = $1::uuid")
                .bind(&issue_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("variant count must load: {error}"));
        assert_eq!(variants, 1);
        let release_counts = sqlx::query(
            "SELECT release_id::text AS release_id, event_count FROM issue_releases WHERE issue_id = $1::uuid ORDER BY release_id",
        )
        .bind(&issue_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("release counts must load: {error}"));
        assert_eq!(release_counts.len(), 2);
        assert_eq!(
            release_counts
                .iter()
                .map(|row| row.get::<i64, _>("event_count"))
                .sum::<i64>(),
            3
        );
        let first_results: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_processing_results WHERE event_id = $1::uuid",
        )
        .bind(&first_event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("processing result count must load: {error}"));
        assert_eq!(first_results, 1);
        let search = sqlx::query(
            "SELECT search.search_text, search.result_id = event.current_result_id AS current FROM crash_event_search search JOIN crash_events event ON event.id = search.event_id AND event.organization_id = search.organization_id AND event.project_id = search.project_id WHERE event.id = $1::uuid",
        )
        .bind(&first_event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("event search projection must load: {error}"));
        assert!(search.get::<bool, _>("current"));
        assert!(
            search
                .get::<String, _>("search_text")
                .contains("Arena::Tick()")
        );

        let ambiguous = sqlx::query_scalar::<_, String>(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '9.0.0', 'windows', 'x86_64', 'Shipping', '2026-09-01T00:00:00Z'), ($1::uuid, $2::uuid, '9.0.0', 'windows', 'x86_64', 'shipping', '2026-09-02T00:00:00Z') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("ambiguous releases must insert: {error}"));
        let (_, ambiguous_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "group-ambiguous",
            processing_result("UECC-Windows-Ambiguous", "9.0.0", "Ambiguous::Root()"),
            &release_resolution("9.0.0", ambiguous.clone()),
            "2026-09-03T00:00:00Z",
        )
        .await;
        let (_, missing_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "group-missing",
            processing_result("UECC-Windows-Missing", "404.0.0", "Missing::Root()"),
            &release_resolution("404.0.0", Vec::new()),
            "2026-09-04T00:00:00Z",
        )
        .await;
        let mappings = sqlx::query(
            "SELECT id::text AS event_id, release_mapping_state, release_id::text AS release_id, (SELECT count(*) FROM crash_event_release_candidates c WHERE c.event_id = e.id) AS candidates FROM crash_events e WHERE id = ANY(ARRAY(SELECT value::uuid FROM unnest($1::text[]) AS values(value)))",
        )
        .bind(vec![ambiguous_event, missing_event])
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("release mappings must load: {error}"));
        let ambiguous_row = mappings
            .iter()
            .find(|row| row.get::<String, _>("release_mapping_state") == "ambiguous")
            .unwrap_or_else(|| panic!("ambiguous mapping must exist"));
        assert_eq!(ambiguous_row.get::<i64, _>("candidates"), 2);
        assert!(
            ambiguous_row
                .get::<Option<String>, _>("release_id")
                .is_none()
        );
        let missing_row = mappings
            .iter()
            .find(|row| row.get::<String, _>("release_mapping_state") == "missing")
            .unwrap_or_else(|| panic!("missing mapping must exist"));
        assert_eq!(missing_row.get::<i64, _>("candidates"), 0);
        assert!(missing_row.get::<Option<String>, _>("release_id").is_none());
        let without_identity: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_events WHERE current_result_id IS NOT NULL AND (fingerprint_algorithm IS NULL OR fingerprint_version IS NULL)",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("fingerprint identity count must load: {error}"));
        assert_eq!(without_identity, 0);
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn publication_converges_concurrently_and_honors_leases_and_the_kill_switch() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Concurrency test', 'concurrency-test') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("organization must insert: {error}"));
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Game', 'game') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("project must insert: {error}"));
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '1.0.0', 'windows', 'x86_64', 'Shipping', '2026-01-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("release must insert: {error}"));
        let worker = publication_worker(pool.clone(), "concurrent-worker", true);
        let first_job_id =
            insert_event_job(&pool, &organization_id, &project_id, "concurrent-first").await;
        let second_job_id =
            insert_event_job(&pool, &organization_id, &project_id, "concurrent-second").await;
        let first_job = lease_exact_job(&pool, &first_job_id, worker.instance_id.as_ref()).await;
        let second_job = lease_exact_job(&pool, &second_job_id, worker.instance_id.as_ref()).await;
        let first_event = first_job
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("first event must exist"));
        let second_event = second_job
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("second event must exist"));
        let release = release_resolution("1.0.0", vec![release_id.clone()]);
        let (first, second) = tokio::join!(
            worker.publish_crash_result(
                &first_job,
                &first_event,
                processing_result("UECC-Concurrent-1", "1.0.0", "Race::Root()"),
                "processed",
                "processing_complete",
                &release,
            ),
            worker.publish_crash_result(
                &second_job,
                &second_event,
                processing_result("UECC-Concurrent-2", "1.0.0", "Race::Root()"),
                "processed",
                "processing_complete",
                &release,
            )
        );
        assert!(first.is_ok(), "first concurrent publication: {first:?}");
        assert!(second.is_ok(), "second concurrent publication: {second:?}");
        let issue = sqlx::query(
            "SELECT id::text AS issue_id, count(*) OVER () AS issues, event_count FROM issues WHERE project_id = $1::uuid",
        )
        .bind(&project_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("concurrent issue must load: {error}"));
        assert_eq!(issue.get::<i64, _>("issues"), 1);
        assert_eq!(issue.get::<i64, _>("event_count"), 2);
        let concurrent_issue_id: String = issue.get("issue_id");

        for mask in 0..102_u16 {
            let configuration = "shipping"
                .chars()
                .enumerate()
                .map(|(index, character)| {
                    if mask & (1 << index) == 0 {
                        character
                    } else {
                        character.to_ascii_uppercase()
                    }
                })
                .collect::<String>();
            sqlx::query(
                "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, 'bounded', 'windows', 'x86_64', $3, '2026-01-02T00:00:00Z')",
            )
            .bind(&organization_id)
            .bind(&project_id)
            .bind(configuration)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("bounded release must insert: {error}"));
        }
        let bounded = worker
            .resolve_release(
                &first_job,
                &processing_result("UECC-Bounded", "bounded", "Bounded::Root()"),
            )
            .await
            .unwrap_or_else(|error| panic!("bounded release lookup must succeed: {error:?}"));
        assert_eq!(
            bounded.candidates.len(),
            usize::try_from(super::MAX_STORED_RELEASE_CANDIDATES)
                .unwrap_or_else(|error| panic!("candidate limit must fit usize: {error}"))
        );
        assert_eq!(bounded.state(), "ambiguous");

        let stale_job_id =
            insert_event_job(&pool, &organization_id, &project_id, "stale-publication").await;
        let stale_job = lease_exact_job(&pool, &stale_job_id, worker.instance_id.as_ref()).await;
        let stale_event = stale_job
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("stale event must exist"));
        sqlx::query(
            "UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id = $1::uuid",
        )
        .bind(&stale_job.id)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("lease must expire: {error}"));
        let stale = worker
            .publish_crash_result(
                &stale_job,
                &stale_event,
                processing_result("UECC-Stale", "1.0.0", "Stale::Root()"),
                "processed",
                "processing_complete",
                &release,
            )
            .await;
        assert!(matches!(stale, Err(JobError::LostLease)));
        let stale_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_processing_results WHERE event_id = $1::uuid",
        )
        .bind(&stale_event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("stale result count must load: {error}"));
        assert_eq!(stale_rows, 0);
        let stale_candidates: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_event_release_candidates WHERE event_id = $1::uuid",
        )
        .bind(&stale_event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("stale candidate count must load: {error}"));
        assert_eq!(stale_candidates, 0);

        let disabled = publication_worker(pool.clone(), "disabled-worker", false);
        let second_release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '2.0.0', 'windows', 'x86_64', 'Shipping', '2026-02-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("second release must insert: {error}"));
        let disabled_reprocessing =
            lease_exact_job(&pool, &first_job_id, disabled.instance_id.as_ref()).await;
        disabled
            .publish_crash_result(
                &disabled_reprocessing,
                &first_event,
                processing_result("UECC-Concurrent-1", "2.0.0", "Race::Root()"),
                "processed",
                "processing_complete",
                &release_resolution("2.0.0", vec![second_release_id.clone()]),
            )
            .await
            .unwrap_or_else(|error| {
                panic!("disabled reprocessing must retain exact rollups: {error:?}")
            });
        let retained = sqlx::query(
            "SELECT i.event_count, (SELECT count(*) FROM issue_releases ir WHERE ir.issue_id = i.id) AS releases FROM issues i WHERE i.id = $1::uuid",
        )
        .bind(&concurrent_issue_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("retained issue rollups must load: {error}"));
        assert_eq!(retained.get::<i64, _>("event_count"), 2);
        assert_eq!(retained.get::<i64, _>("releases"), 2);
        let release_rollups = sqlx::query(
            "SELECT release_id::text AS release_id, first_seen_at, last_seen_at, event_count, representative_event_id::text AS representative_event_id FROM issue_releases WHERE organization_id = $1::uuid AND project_id = $2::uuid AND issue_id = $3::uuid ORDER BY release_id",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&concurrent_issue_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("release rollups must load: {error}"));
        let old_release = release_rollups
            .iter()
            .find(|row| row.get::<String, _>("release_id") == release_id)
            .unwrap_or_else(|| panic!("old release rollup must exist"));
        assert_eq!(old_release.get::<i64, _>("event_count"), 1);
        assert_eq!(
            old_release.get::<String, _>("representative_event_id"),
            second_event
        );
        assert_eq!(
            old_release.get::<time::OffsetDateTime, _>("first_seen_at"),
            old_release.get::<time::OffsetDateTime, _>("last_seen_at")
        );
        let new_release = release_rollups
            .iter()
            .find(|row| row.get::<String, _>("release_id") == second_release_id)
            .unwrap_or_else(|| panic!("new release rollup must exist"));
        assert_eq!(new_release.get::<i64, _>("event_count"), 1);
        assert_eq!(
            new_release.get::<String, _>("representative_event_id"),
            first_event
        );

        let disabled_job_id =
            insert_event_job(&pool, &organization_id, &project_id, "disabled-grouping").await;
        let disabled_job =
            lease_exact_job(&pool, &disabled_job_id, disabled.instance_id.as_ref()).await;
        let disabled_event = disabled_job
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("disabled event must exist"));
        disabled
            .publish_crash_result(
                &disabled_job,
                &disabled_event,
                processing_result("UECC-Disabled", "1.0.0", "Disabled::Root()"),
                "processed",
                "processing_complete",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("disabled grouping must still process: {error:?}"));
        let disabled_state = sqlx::query(
            "SELECT grouping_state, fingerprint_algorithm, fingerprint_version, issue_id::text AS issue_id, current_result_id::text AS current_result_id FROM crash_events WHERE id = $1::uuid",
        )
        .bind(&disabled_event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("disabled state must load: {error}"));
        assert_eq!(
            disabled_state.get::<String, _>("grouping_state"),
            "disabled"
        );
        assert_eq!(
            disabled_state.get::<String, _>("fingerprint_algorithm"),
            "stack"
        );
        assert_eq!(disabled_state.get::<i32, _>("fingerprint_version"), 1);
        assert!(
            disabled_state
                .get::<Option<String>, _>("issue_id")
                .is_none()
        );
        assert!(
            disabled_state
                .get::<Option<String>, _>("current_result_id")
                .is_some()
        );

        let insufficient_job_id = insert_event_job(
            &pool,
            &organization_id,
            &project_id,
            "insufficient-grouping",
        )
        .await;
        let insufficient_job =
            lease_exact_job(&pool, &insufficient_job_id, worker.instance_id.as_ref()).await;
        let insufficient_event = insufficient_job
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("insufficient event must exist"));
        let mut insufficient = processing_result("UECC-Insufficient", "1.0.0", "Unused::Root()");
        insufficient["current"]["symbolication"]["threads"][0]["frames"] = json!([]);
        worker
            .publish_crash_result(
                &insufficient_job,
                &insufficient_event,
                insufficient,
                "awaiting_symbols",
                "matching_symbols_missing",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("insufficient event must process: {error:?}"));
        let insufficient_state: String =
            sqlx::query_scalar("SELECT grouping_state FROM crash_events WHERE id = $1::uuid")
                .bind(&insufficient_event)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("insufficient state must load: {error}"));
        assert_eq!(insufficient_state, "insufficient");
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn maximum_publication_collections_are_exact_and_idempotent_when_configured() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Collection test', 'collection-test') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("organization must insert: {error}"));
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Game', 'game') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("project must insert: {error}"));
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '1.0.0', 'windows', 'x86_64', 'Shipping', '2026-01-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("release must insert: {error}"));
        let facet_keys = (0..32)
            .map(|index| format!("Facet{index:02}"))
            .collect::<Vec<_>>();
        sqlx::query(
            "INSERT INTO project_data_rules (organization_id, project_id, version, indexed_game_data_keys) VALUES ($1::uuid, $2::uuid, 1, $3)",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&facet_keys)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("data rules must insert: {error}"));
        let worker = publication_worker(pool.clone(), "collection-worker", false);
        let job_id =
            insert_event_job(&pool, &organization_id, &project_id, "max-collections").await;
        let job = lease_exact_job(&pool, &job_id, worker.instance_id.as_ref()).await;
        let event_id = job
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("event must exist"));
        let mut result = processing_result("UECC-Max-Collections", "1.0.0", "Maximum::Root()");
        result["crash_context"]["game_data"] = Value::Array(
            facet_keys
                .iter()
                .map(|key| json!({"name": key, "value": format!("value-{key}")}))
                .collect(),
        );
        result["current"]["symbolication"]["modules"] = Value::Array(
            (0..super::MAX_SYMBOL_WAITERS)
                .map(|index| {
                    json!({
                        "module": format!("Module{index:04}.dll"),
                        "code_id": format!("CODE-{index:04}"),
                        "debug_id": format!("DEBUG-{index:04}"),
                        "status": "missing_pdb",
                        "pe": null,
                        "pdb": null
                    })
                })
                .collect(),
        );
        let release = release_resolution("1.0.0", vec![release_id]);
        let started = std::time::Instant::now();
        worker
            .publish_crash_result(
                &job,
                &event_id,
                result.clone(),
                "awaiting_symbols",
                "matching_symbols_missing",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("maximum publication must succeed: {error:?}"));
        assert!(started.elapsed() < std::time::Duration::from_mins(1));
        let counts = sqlx::query(
            "SELECT (SELECT count(*) FROM crash_event_context_facets WHERE event_id = $1::uuid) AS facets, (SELECT count(*) FROM crash_symbol_waiters WHERE event_id = $1::uuid) AS waiters",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("collection counts must load: {error}"));
        assert_eq!(counts.get::<i64, _>("facets"), 32);
        assert_eq!(
            counts.get::<i64, _>("waiters"),
            i64::try_from(super::MAX_SYMBOL_WAITERS)
                .unwrap_or_else(|error| panic!("waiter limit must fit: {error}"))
        );
        let retry = lease_exact_job(&pool, &job_id, worker.instance_id.as_ref()).await;
        worker
            .publish_crash_result(
                &retry,
                &event_id,
                result,
                "awaiting_symbols",
                "matching_symbols_missing",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("maximum retry must succeed: {error:?}"));
        let retry_counts = sqlx::query(
            "SELECT (SELECT count(*) FROM crash_event_context_facets WHERE event_id = $1::uuid) AS facets, (SELECT count(*) FROM crash_symbol_waiters WHERE event_id = $1::uuid) AS waiters",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("retry collection counts must load: {error}"));
        assert_eq!(retry_counts.get::<i64, _>("facets"), 32);
        assert_eq!(
            retry_counts.get::<i64, _>("waiters"),
            i64::try_from(super::MAX_SYMBOL_WAITERS)
                .unwrap_or_else(|error| panic!("waiter limit must fit: {error}"))
        );

        let candidates = sqlx::query_scalar::<_, String>(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration) SELECT $1::uuid, $2::uuid, 'ambiguous', 'windows', 'x86_64', 'candidate-' || value::text FROM generate_series(1, 101) AS values(value) RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("candidate releases must insert: {error}"));
        let candidate_job_id =
            insert_event_job(&pool, &organization_id, &project_id, "max-candidates").await;
        let candidate_job =
            lease_exact_job(&pool, &candidate_job_id, worker.instance_id.as_ref()).await;
        let candidate_event = candidate_job
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("candidate event must exist"));
        let candidate_release = release_resolution("ambiguous", candidates);
        worker
            .publish_crash_result(
                &candidate_job,
                &candidate_event,
                processing_result("UECC-Max-Candidates", "ambiguous", "Candidate::Root()"),
                "processed",
                "processing_complete",
                &candidate_release,
            )
            .await
            .unwrap_or_else(|error| panic!("candidate publication must succeed: {error:?}"));
        let candidate_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_event_release_candidates WHERE event_id = $1::uuid",
        )
        .bind(&candidate_event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("candidate count must load: {error}"));
        assert_eq!(candidate_count, 101);
        let candidate_retry =
            lease_exact_job(&pool, &candidate_job_id, worker.instance_id.as_ref()).await;
        worker
            .publish_crash_result(
                &candidate_retry,
                &candidate_event,
                processing_result("UECC-Max-Candidates", "ambiguous", "Candidate::Root()"),
                "processed",
                "processing_complete",
                &candidate_release,
            )
            .await
            .unwrap_or_else(|error| panic!("candidate retry must succeed: {error:?}"));
        let retry_candidate_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_event_release_candidates WHERE event_id = $1::uuid",
        )
        .bind(&candidate_event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("retry candidate count must load: {error}"));
        assert_eq!(retry_candidate_count, 101);
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn hot_issue_publication_stays_bounded_at_one_hundred_thousand_events() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Scale test', 'scale-test') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("organization must insert: {error}"));
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Game', 'game') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("project must insert: {error}"));
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '1.0.0', 'windows', 'x86_64', 'Shipping', '2026-01-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("release must insert: {error}"));
        let worker = publication_worker(pool.clone(), "scale-worker", true);
        let release = release_resolution("1.0.0", vec![release_id.clone()]);
        let (first_job_id, first_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "scale-first",
            processing_result("UECC-Scale-1", "1.0.0", "Scale::Root()"),
            &release,
            "2026-01-01T00:00:00Z",
        )
        .await;
        let first = sqlx::query(
            "SELECT issue_id::text AS issue_id, ingest_key_id::text AS ingest_key_id, fingerprint, variant_fingerprint, grouping_quality FROM crash_events WHERE id = $1::uuid",
        )
        .bind(&first_event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("first event must load: {error}"));
        let issue_id: String = first.get("issue_id");
        let ingest_key_id: String = first.get("ingest_key_id");
        let fingerprint: String = first.get("fingerprint");
        let variant_fingerprint: String = first.get("variant_fingerprint");
        let grouping_quality: i32 = first.get("grouping_quality");
        let seeded: i64 = sqlx::query_scalar::<_, i32>(
            "WITH generated AS MATERIALIZED (SELECT gen_random_uuid() AS object_id, gen_random_uuid() AS event_id, value FROM generate_series(1, 99999) AS values(value)), objects AS (INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) SELECT object_id, $1::uuid, $2::uuid, 'scale/' || object_id::text, $9, 1, 'application/octet-stream' FROM generated RETURNING id) INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, environment, processing_state, received_at, release_id, release_mapping_state, grouping_state, fingerprint_algorithm, fingerprint_version, fingerprint, variant_fingerprint, grouping_quality, grouped_at, issue_id) SELECT generated.event_id, $1::uuid, $2::uuid, $3::uuid, generated.object_id, 'production', 'processed', '2026-01-02T00:00:00Z'::timestamptz + generated.value * interval '1 second', $4::uuid, 'matched', 'grouped', 'stack', 1, $6, $7, $8, now(), $5::uuid FROM generated JOIN objects ON objects.id = generated.object_id RETURNING 1",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&ingest_key_id)
        .bind(&release_id)
        .bind(&issue_id)
        .bind(&fingerprint)
        .bind(&variant_fingerprint)
        .bind(grouping_quality)
        .bind(vec![0_u8; 32])
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("scale events must insert: {error}"))
        .len()
        .try_into()
        .unwrap_or_else(|error| panic!("seed count must fit: {error}"));
        assert_eq!(seeded, 99_999);
        let repaired = super::repair_issue(&database_url, &organization_id, &project_id, &issue_id)
            .await
            .unwrap_or_else(|error| panic!("scale issue repair must succeed: {error}"));
        assert_eq!(repaired.events, 100_000);

        let next_job_id =
            insert_event_job(&pool, &organization_id, &project_id, "scale-next").await;
        let next_job = lease_exact_job(&pool, &next_job_id, worker.instance_id.as_ref()).await;
        let next_event = next_job
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("next event must exist"));
        sqlx::query(
            "UPDATE crash_events SET received_at = '2026-02-15T00:00:00Z' WHERE id = $1::uuid",
        )
        .bind(&next_event)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("next event timestamp must update: {error}"));
        let started = std::time::Instant::now();
        worker
            .publish_crash_result(
                &next_job,
                &next_event,
                processing_result("UECC-Scale-Next", "1.0.0", "Scale::Root()"),
                "processed",
                "processing_complete",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("next scale event must publish: {error:?}"));
        let next_elapsed = started.elapsed();
        assert!(next_elapsed < std::time::Duration::from_secs(5));
        let next_count: i64 =
            sqlx::query_scalar("SELECT event_count FROM issues WHERE id = $1::uuid")
                .bind(&issue_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("next issue count must load: {error}"));
        assert_eq!(next_count, 100_001);

        let retry = lease_exact_job(&pool, &next_job_id, worker.instance_id.as_ref()).await;
        let retry_started = std::time::Instant::now();
        worker
            .publish_crash_result(
                &retry,
                &next_event,
                processing_result("UECC-Scale-Next", "1.0.0", "Scale::Root()"),
                "processed",
                "processing_complete",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("scale retry must publish: {error:?}"));
        let retry_elapsed = retry_started.elapsed();
        assert!(retry_elapsed < std::time::Duration::from_secs(5));
        let retry_count: i64 =
            sqlx::query_scalar("SELECT event_count FROM issues WHERE id = $1::uuid")
                .bind(&issue_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("retry issue count must load: {error}"));
        assert_eq!(retry_count, 100_001);

        let concurrent_first_job_id = insert_event_job(
            &pool,
            &organization_id,
            &project_id,
            "scale-concurrent-first",
        )
        .await;
        let concurrent_second_job_id = insert_event_job(
            &pool,
            &organization_id,
            &project_id,
            "scale-concurrent-second",
        )
        .await;
        let concurrent_first =
            lease_exact_job(&pool, &concurrent_first_job_id, worker.instance_id.as_ref()).await;
        let concurrent_second = lease_exact_job(
            &pool,
            &concurrent_second_job_id,
            worker.instance_id.as_ref(),
        )
        .await;
        let concurrent_first_event = concurrent_first
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("first concurrent event must exist"));
        let concurrent_second_event = concurrent_second
            .event_id
            .clone()
            .unwrap_or_else(|| panic!("second concurrent event must exist"));
        let (first_result, second_result) = tokio::join!(
            worker.publish_crash_result(
                &concurrent_first,
                &concurrent_first_event,
                processing_result("UECC-Scale-Concurrent-1", "1.0.0", "Scale::Root()"),
                "processed",
                "processing_complete",
                &release,
            ),
            worker.publish_crash_result(
                &concurrent_second,
                &concurrent_second_event,
                processing_result("UECC-Scale-Concurrent-2", "1.0.0", "Scale::Root()"),
                "processed",
                "processing_complete",
                &release,
            )
        );
        assert!(
            first_result.is_ok(),
            "first concurrent publication: {first_result:?}"
        );
        assert!(
            second_result.is_ok(),
            "second concurrent publication: {second_result:?}"
        );
        let concurrent_count: i64 =
            sqlx::query_scalar("SELECT event_count FROM issues WHERE id = $1::uuid")
                .bind(&issue_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("concurrent issue count must load: {error}"));
        assert_eq!(concurrent_count, 100_003);
        let concurrent_first_retry =
            lease_exact_job(&pool, &concurrent_first_job_id, worker.instance_id.as_ref()).await;
        let concurrent_second_retry = lease_exact_job(
            &pool,
            &concurrent_second_job_id,
            worker.instance_id.as_ref(),
        )
        .await;
        let (first_retry_result, second_retry_result) = tokio::join!(
            worker.publish_crash_result(
                &concurrent_first_retry,
                &concurrent_first_event,
                processing_result("UECC-Scale-Concurrent-1", "1.0.0", "Scale::Root()"),
                "processed",
                "processing_complete",
                &release,
            ),
            worker.publish_crash_result(
                &concurrent_second_retry,
                &concurrent_second_event,
                processing_result("UECC-Scale-Concurrent-2", "1.0.0", "Scale::Root()"),
                "processed",
                "processing_complete",
                &release,
            )
        );
        assert!(
            first_retry_result.is_ok(),
            "first concurrent retry: {first_retry_result:?}"
        );
        assert!(
            second_retry_result.is_ok(),
            "second concurrent retry: {second_retry_result:?}"
        );
        let concurrent_retry_count: i64 =
            sqlx::query_scalar("SELECT event_count FROM issues WHERE id = $1::uuid")
                .bind(&issue_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("concurrent retry count must load: {error}"));
        assert_eq!(concurrent_retry_count, 100_003);

        let plan = sqlx::query_scalar::<_, String>(
            "EXPLAIN (ANALYZE, BUFFERS) SELECT id FROM crash_events WHERE organization_id = $1::uuid AND project_id = $2::uuid AND issue_id = $3::uuid AND release_id = $4::uuid AND grouping_state = 'grouped' AND release_mapping_state = 'matched' ORDER BY grouping_quality DESC, received_at, id LIMIT 1",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&issue_id)
        .bind(&release_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("replacement plan must load: {error}"))
        .join("\n");
        assert!(plan.contains("crash_events_issue_release_representative"));
        assert!(!plan.contains("Seq Scan"));

        let first_retry = lease_exact_job(&pool, &first_job_id, worker.instance_id.as_ref()).await;
        worker
            .publish_crash_result(
                &first_retry,
                &first_event,
                processing_result("UECC-Scale-1", "1.0.0", "Scale::Root()"),
                "processed",
                "processing_complete",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("old event retry must publish: {error:?}"));
        let final_count: i64 =
            sqlx::query_scalar("SELECT event_count FROM issues WHERE id = $1::uuid")
                .bind(&issue_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("final issue count must load: {error}"));
        assert_eq!(final_count, 100_003);
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn issue_repair_rebuilds_only_the_scoped_issue_when_configured() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Repair test', 'repair-test') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("organization must insert: {error}"));
        let other_organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Other tenant', 'other-tenant') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("other organization must insert: {error}"));
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Game', 'game') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("project must insert: {error}"));
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '1.0.0', 'windows', 'x86_64', 'Shipping', '2026-01-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("release must insert: {error}"));
        let worker = publication_worker(pool.clone(), "repair-worker", true);
        let release = release_resolution("1.0.0", vec![release_id]);
        let (_, first_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "repair-first",
            processing_result("UECC-Repair-1", "1.0.0", "Repair::Root()"),
            &release,
            "2026-01-02T00:00:00Z",
        )
        .await;
        let (_, second_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "repair-second",
            processing_result("UECC-Repair-2", "1.0.0", "Repair::Root()"),
            &release,
            "2026-01-03T00:00:00Z",
        )
        .await;
        let (_, unrelated_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "repair-unrelated",
            processing_result("UECC-Repair-Other", "1.0.0", "Other::Root()"),
            &release,
            "2026-01-04T00:00:00Z",
        )
        .await;
        let issue_id: String =
            sqlx::query_scalar("SELECT issue_id::text FROM crash_events WHERE id = $1::uuid")
                .bind(&first_event)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("repair issue must load: {error}"));
        let unrelated_issue_id: String =
            sqlx::query_scalar("SELECT issue_id::text FROM crash_events WHERE id = $1::uuid")
                .bind(&unrelated_event)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("unrelated issue must load: {error}"));
        sqlx::query("UPDATE issues SET event_count = 99, representative_event_id = $2::uuid WHERE id = $1::uuid")
            .bind(&issue_id)
            .bind(&second_event)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("issue drift must insert: {error}"));
        sqlx::query("UPDATE issue_variants SET event_count = 99, representative_event_id = $2::uuid WHERE issue_id = $1::uuid")
            .bind(&issue_id)
            .bind(&second_event)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("variant drift must insert: {error}"));
        sqlx::query("UPDATE issue_releases SET event_count = 99, representative_event_id = $2::uuid WHERE issue_id = $1::uuid")
            .bind(&issue_id)
            .bind(&second_event)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("release drift must insert: {error}"));
        let report = super::repair_issue(&database_url, &organization_id, &project_id, &issue_id)
            .await
            .unwrap_or_else(|error| panic!("repair must succeed: {error}"));
        assert_eq!(report.events, 2);
        assert_eq!(report.variants, 1);
        assert_eq!(report.releases, 1);
        let repaired = sqlx::query(
            "SELECT i.event_count, i.representative_event_id::text AS representative_event_id, v.event_count AS variant_count, r.event_count AS release_count FROM issues i JOIN issue_variants v ON v.issue_id = i.id JOIN issue_releases r ON r.issue_id = i.id WHERE i.id = $1::uuid",
        )
        .bind(&issue_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("repaired rows must load: {error}"));
        assert_eq!(repaired.get::<i64, _>("event_count"), 2);
        assert_eq!(repaired.get::<i64, _>("variant_count"), 2);
        assert_eq!(repaired.get::<i64, _>("release_count"), 2);
        assert_eq!(
            repaired.get::<String, _>("representative_event_id"),
            first_event
        );
        let unrelated_count: i64 =
            sqlx::query_scalar("SELECT event_count FROM issues WHERE id = $1::uuid")
                .bind(&unrelated_issue_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("unrelated issue must load: {error}"));
        assert_eq!(unrelated_count, 1);
        assert!(matches!(
            super::repair_issue(
                &database_url,
                &other_organization_id,
                &project_id,
                &issue_id
            )
            .await,
            Err(super::RepairIssueError::NotFound)
        ));
        assert!(matches!(
            super::repair_issue(&database_url, "invalid", &project_id, &issue_id).await,
            Err(super::RepairIssueError::InvalidIdentifier)
        ));
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn publication_does_not_guess_regressions_from_late_or_tied_releases() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Ordering test', 'ordering-test') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("organization must insert: {error}"));
        let project_id: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Game', 'game') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("project must insert: {error}"));
        let releases = sqlx::query(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '1.0.0', 'windows', 'x86_64', 'Shipping', '2026-01-01T00:00:00Z'), ($1::uuid, $2::uuid, '2.0.0', 'windows', 'x86_64', 'Shipping', '2026-02-01T00:00:00Z'), ($1::uuid, $2::uuid, '2.0.1', 'windows', 'x86_64', 'Shipping', '2026-02-01T00:00:00Z') RETURNING id::text AS id, version",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("ordering releases must insert: {error}"));
        let release_id = |version: &str| {
            releases
                .iter()
                .find(|row| row.get::<String, _>("version") == version)
                .map_or_else(
                    || panic!("release {version} must exist"),
                    |row| row.get("id"),
                )
        };
        let older: String = release_id("1.0.0");
        let resolved: String = release_id("2.0.0");
        let tied: String = release_id("2.0.1");
        let worker = publication_worker(pool.clone(), "ordering-worker", true);

        let (_, late_root_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "ordering-late-root",
            processing_result("UECC-Ordering-Late-1", "2.0.0", "Late::Root()"),
            &release_resolution("2.0.0", vec![resolved.clone()]),
            "2026-02-02T00:00:00Z",
        )
        .await;
        let late_issue: String =
            sqlx::query_scalar("SELECT issue_id::text FROM crash_events WHERE id = $1::uuid")
                .bind(&late_root_event)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("late issue must load: {error}"));
        sqlx::query(
            "UPDATE issues SET status = 'resolved', regression_state = 'resolved', resolved_in_release_id = $2::uuid, resolved_at = now() WHERE id = $1::uuid",
        )
        .bind(&late_issue)
        .bind(&resolved)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("late issue must resolve: {error}"));
        let _ = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "ordering-late-older",
            processing_result("UECC-Ordering-Late-2", "1.0.0", "Late::Root()"),
            &release_resolution("1.0.0", vec![older.clone()]),
            "2026-03-01T00:00:00Z",
        )
        .await;
        let late_state = sqlx::query(
            "SELECT status, regression_state, first_release_id::text AS first_release_id, last_release_id::text AS last_release_id FROM issues WHERE id = $1::uuid",
        )
        .bind(&late_issue)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("late state must load: {error}"));
        assert_eq!(late_state.get::<String, _>("status"), "resolved");
        assert_eq!(late_state.get::<String, _>("regression_state"), "resolved");
        assert_eq!(late_state.get::<String, _>("first_release_id"), older);
        assert_eq!(late_state.get::<String, _>("last_release_id"), resolved);

        let (_, tied_root_event) = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "ordering-tied-root",
            processing_result("UECC-Ordering-Tied-1", "2.0.0", "Tie::Root()"),
            &release_resolution("2.0.0", vec![resolved.clone()]),
            "2026-02-03T00:00:00Z",
        )
        .await;
        let tied_issue: String =
            sqlx::query_scalar("SELECT issue_id::text FROM crash_events WHERE id = $1::uuid")
                .bind(&tied_root_event)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("tied issue must load: {error}"));
        sqlx::query(
            "UPDATE issues SET status = 'resolved', regression_state = 'resolved', resolved_in_release_id = $2::uuid, resolved_at = now() WHERE id = $1::uuid",
        )
        .bind(&tied_issue)
        .bind(&resolved)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("tied issue must resolve: {error}"));
        let _ = publish_new_event(
            &worker,
            &organization_id,
            &project_id,
            "ordering-tied-repeat",
            processing_result("UECC-Ordering-Tied-2", "2.0.1", "Tie::Root()"),
            &release_resolution("2.0.1", vec![tied]),
            "2026-02-04T00:00:00Z",
        )
        .await;
        let tied_state = sqlx::query(
            "SELECT status, regression_state, first_release_id::text AS first_release_id, last_release_id::text AS last_release_id FROM issues WHERE id = $1::uuid",
        )
        .bind(&tied_issue)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("tied state must load: {error}"));
        assert_eq!(tied_state.get::<String, _>("status"), "resolved");
        assert_eq!(tied_state.get::<String, _>("regression_state"), "resolved");
        assert!(
            tied_state
                .get::<Option<String>, _>("first_release_id")
                .is_none()
        );
        assert!(
            tied_state
                .get::<Option<String>, _>("last_release_id")
                .is_none()
        );
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn claims_are_fair_and_stale_leases_cannot_publish_when_configured() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
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

        let mut claim_round = 0_u8;
        let (left, right) = loop {
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
            claim_round = claim_round.saturating_add(1);
            if claim_round == 32 {
                break (left, right);
            }
            sqlx::query(
                "UPDATE jobs SET state = 'pending', attempt = 0, lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE state = 'leased'",
            )
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("claims must reset: {error}"));
        };

        let (stale, stale_owner) = if left.project_id == first_project {
            (left, "worker-left")
        } else {
            (right, "worker-right")
        };
        sqlx::query(
            "UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id = $1::uuid",
        )
        .bind(&stale.id)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("lease must expire: {error}"));
        sqlx::query(
            "UPDATE jobs SET available_at = now() + interval '1 hour' WHERE project_id = $1::uuid AND state = 'pending'",
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
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    async fn shutdown_releases_all_active_leases_and_pool_pressure_recovers() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let scope = insert_test_scope(&pool, "shutdown-worker", "shutdown-worker").await;
        let _ =
            insert_event_job(&pool, &scope.organization, &scope.project, "shutdown-first").await;
        let _ = insert_event_job(
            &pool,
            &scope.organization,
            &scope.project,
            "shutdown-second",
        )
        .await;

        let first = claim_job_with_project_limit(&pool, "shutdown-worker", 2)
            .await
            .unwrap_or_else(|()| panic!("first shutdown claim must succeed"))
            .unwrap_or_else(|| panic!("first shutdown claim must find work"));
        let second = claim_job_with_project_limit(&pool, "shutdown-worker", 2)
            .await
            .unwrap_or_else(|()| panic!("second shutdown claim must succeed"))
            .unwrap_or_else(|| panic!("second shutdown claim must find work"));
        assert_eq!(first.project_active_jobs, 1);
        assert_eq!(second.project_active_jobs, 2);

        let worker = publication_worker(pool.clone(), "shutdown-worker", false);
        let mut running = JoinSet::new();
        let mut active = BTreeMap::new();
        for job in [first, second] {
            active.insert(job.id.clone(), job.clone());
            running.spawn(async move {
                tokio::time::sleep(Duration::from_mins(1)).await;
                (job, 60_000)
            });
        }
        worker.stop_running_jobs(&mut running, &active).await;
        assert!(running.is_empty());
        let released = sqlx::query(
            "SELECT count(*)::bigint AS jobs, min(attempt) AS minimum_attempt, max(attempt) AS maximum_attempt, bool_and(state = 'pending' AND failure_code = 'processing_cancelled' AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) AS safely_released FROM jobs WHERE organization_id = $1::uuid AND project_id = $2::uuid",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("released jobs must load: {error}"));
        assert_eq!(released.get::<i64, _>("jobs"), 2);
        assert_eq!(released.get::<i32, _>("minimum_attempt"), 0);
        assert_eq!(released.get::<i32, _>("maximum_attempt"), 0);
        assert!(released.get::<bool, _>("safely_released"));

        let constrained = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(500))
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("constrained pool must connect: {error}"));
        let held = constrained
            .acquire()
            .await
            .unwrap_or_else(|error| panic!("only pool connection must acquire: {error}"));
        let pressure_started = Instant::now();
        assert!(
            claim_job_with_project_limit(&constrained, "pool-worker", 2)
                .await
                .is_err()
        );
        assert!(pressure_started.elapsed() < Duration::from_secs(2));
        drop(held);
        let recovered = claim_job_with_project_limit(&constrained, "pool-worker", 2)
            .await
            .unwrap_or_else(|()| panic!("claim must recover after pool pressure"))
            .unwrap_or_else(|| panic!("recovered claim must find work"));
        publication_worker(pool.clone(), "pool-worker", false)
            .cancel_job(&recovered)
            .await
            .unwrap_or_else(|error| panic!("recovered claim must release: {error:?}"));
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn concurrent_workers_drain_a_hot_project_without_starving_another() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must rerun: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(24)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let scope = insert_test_scope(&pool, "queue-scale", "queue-scale").await;
        let cold_project: String = sqlx::query_scalar(
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Queue scale cold', 'queue-scale-cold') RETURNING id::text",
        )
        .bind(&scope.organization)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("cold project must insert: {error}"));
        let hot_ingest_key: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, 'hot00000') RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(vec![21_u8; 32])
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("hot ingest key must insert: {error}"));
        let cold_ingest_key: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, 'cold0000') RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&cold_project)
        .bind(vec![22_u8; 32])
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("cold ingest key must insert: {error}"));

        for (project_id, ingest_key_id, job_count, prefix) in [
            (&scope.project, &hot_ingest_key, 10_000_i64, "hot"),
            (&cold_project, &cold_ingest_key, 100_i64, "cold"),
        ] {
            let inserted: i64 = sqlx::query_scalar(
                "WITH generated AS MATERIALIZED (SELECT gen_random_uuid() AS object_id, gen_random_uuid() AS event_id, n FROM generate_series(1, $4) values(n)), objects AS (INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) SELECT object_id, $1::uuid, $2::uuid, $5 || '/' || n::text, decode(md5($2 || ':' || n::text) || md5(n::text || ':' || $2), 'hex'), 1, 'application/octet-stream' FROM generated RETURNING id), events AS (INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, environment) SELECT generated.event_id, $1::uuid, $2::uuid, $3::uuid, generated.object_id, 'production' FROM generated JOIN objects ON objects.id = generated.object_id RETURNING id), inserted_jobs AS (INSERT INTO jobs (id, organization_id, project_id, event_id, job_type, payload, idempotency_key) SELECT gen_random_uuid(), $1::uuid, $2::uuid, id, 'process_crash', '{}'::jsonb, 'queue-scale:' || id::text FROM events RETURNING 1) SELECT count(*)::bigint FROM inserted_jobs",
            )
            .bind(&scope.organization)
            .bind(project_id)
            .bind(ingest_key_id)
            .bind(job_count)
            .bind(prefix)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|error| panic!("queue scale jobs must insert: {error}"));
            assert_eq!(inserted, job_count);
        }
        sqlx::query("ANALYZE jobs")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("queue statistics must refresh: {error}"));

        let pending_plan = explain_plan(
            &pool,
            "EXPLAIN (FORMAT TEXT) SELECT id FROM jobs WHERE state = 'pending' AND available_at <= now() AND attempt < max_attempt ORDER BY priority, available_at, created_at, id LIMIT 1",
        )
        .await;
        assert!(
            pending_plan.contains("jobs_pending_priority_order"),
            "{pending_plan}"
        );
        let active_plan_rows = sqlx::query(
            "EXPLAIN (FORMAT TEXT) SELECT count(*) FROM jobs WHERE organization_id = $1::uuid AND project_id = $2::uuid AND state = 'leased' AND lease_expires_at > now()",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("active lease plan must load: {error}"));
        let active_plan = active_plan_rows
            .iter()
            .map(|row| row.get::<String, _>("QUERY PLAN"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            active_plan.contains("jobs_active_project_leases"),
            "{active_plan}"
        );
        let expired_plan = explain_plan(
            &pool,
            "EXPLAIN (FORMAT TEXT) SELECT id FROM jobs WHERE state = 'leased' AND lease_expires_at <= now() ORDER BY lease_expires_at, project_id LIMIT 1",
        )
        .await;
        assert!(
            expired_plan.contains("jobs_expired_leases")
                || expired_plan.contains("jobs_active_project_leases"),
            "{expired_plan}"
        );

        let started = Instant::now();
        let mut initial = Vec::new();
        for slot in 0..6 {
            let worker_id = format!("queue-scale-worker-{}", slot / 2);
            let job = claim_job_with_project_limit(&pool, &worker_id, 4)
                .await
                .unwrap_or_else(|()| panic!("initial scale claim must succeed"))
                .unwrap_or_else(|| panic!("initial scale claim must find work"));
            if slot < 4 {
                assert_eq!(job.project_id, scope.project);
                assert_eq!(job.project_active_jobs, i64::from(slot + 1));
            } else {
                assert_eq!(job.project_id, cold_project);
            }
            assert!(job.project_active_jobs <= 4);
            initial.push((worker_id, job));
        }
        let cold_first_millis = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        assert!(cold_first_millis < 2_000, "{cold_first_millis}");

        let active_hot = Arc::new(AtomicI64::new(4));
        let active_cold = Arc::new(AtomicI64::new(2));
        let max_hot = Arc::new(AtomicI64::new(4));
        let max_cold = Arc::new(AtomicI64::new(2));
        let mut tasks = Vec::new();
        for (worker_id, first_job) in initial {
            let task_pool = pool.clone();
            let hot_project = scope.project.clone();
            let active_hot = active_hot.clone();
            let active_cold = active_cold.clone();
            let max_hot = max_hot.clone();
            let max_cold = max_cold.clone();
            tasks.push(tokio::spawn(async move {
                let mut next = Some(first_job);
                let mut completed = 0_i64;
                let mut empty_polls = 0_u32;
                loop {
                    let job = if let Some(job) = next.take() {
                        job
                    } else {
                        match claim_job_with_project_limit(&task_pool, &worker_id, 4).await {
                            Ok(Some(job)) => {
                                empty_polls = 0;
                                let active = if job.project_id == hot_project {
                                    active_hot.fetch_add(1, Ordering::SeqCst) + 1
                                } else {
                                    active_cold.fetch_add(1, Ordering::SeqCst) + 1
                                };
                                if job.project_id == hot_project {
                                    max_hot.fetch_max(active, Ordering::SeqCst);
                                } else {
                                    max_cold.fetch_max(active, Ordering::SeqCst);
                                }
                                if job.project_active_jobs > 4 {
                                    return Err("project concurrency exceeded its bound");
                                }
                                job
                            }
                            Ok(None) if empty_polls < 50 => {
                                empty_polls += 1;
                                tokio::time::sleep(Duration::from_millis(1)).await;
                                continue;
                            }
                            Ok(None) => return Ok(completed),
                            Err(()) => return Err("queue scale claim failed"),
                        }
                    };
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    let mut transaction = task_pool
                        .begin()
                        .await
                        .map_err(|_| "queue scale completion must begin")?;
                    lock_lease(&mut transaction, &job, &worker_id)
                        .await
                        .map_err(|_| "queue scale lease must remain current")?;
                    complete_job(&mut transaction, &job, &worker_id, None)
                        .await
                        .map_err(|_| "queue scale completion must publish once")?;
                    transaction
                        .commit()
                        .await
                        .map_err(|_| "queue scale completion must commit")?;
                    if job.project_id == hot_project {
                        active_hot.fetch_sub(1, Ordering::SeqCst);
                    } else {
                        active_cold.fetch_sub(1, Ordering::SeqCst);
                    }
                    completed = completed.saturating_add(1);
                }
            }));
        }
        let mut completed = 0_i64;
        for task in tasks {
            completed = completed.saturating_add(
                task.await
                    .unwrap_or_else(|error| panic!("queue scale task must join: {error}"))
                    .unwrap_or_else(|error| panic!("queue scale task must drain: {error}")),
            );
        }
        let elapsed = started.elapsed();
        assert_eq!(completed, 10_100);
        assert_eq!(max_hot.load(Ordering::SeqCst), 4);
        assert!(max_cold.load(Ordering::SeqCst) <= 4);
        assert_eq!(active_hot.load(Ordering::SeqCst), 0);
        assert_eq!(active_cold.load(Ordering::SeqCst), 0);
        let final_state = sqlx::query(
            "SELECT count(*) FILTER (WHERE state = 'completed')::bigint AS completed, count(*) FILTER (WHERE state = 'pending')::bigint AS pending, count(*) FILTER (WHERE state = 'leased')::bigint AS leased, min(attempt) AS minimum_attempt, max(attempt) AS maximum_attempt FROM jobs",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("queue scale state must load: {error}"));
        assert_eq!(final_state.get::<i64, _>("completed"), 10_100);
        assert_eq!(final_state.get::<i64, _>("pending"), 0);
        assert_eq!(final_state.get::<i64, _>("leased"), 0);
        assert_eq!(final_state.get::<i32, _>("minimum_attempt"), 1);
        assert_eq!(final_state.get::<i32, _>("maximum_attempt"), 1);
        let elapsed_millis = i64::try_from(elapsed.as_millis())
            .unwrap_or(i64::MAX)
            .max(1);
        let throughput_per_second = completed.saturating_mul(1_000) / elapsed_millis;
        assert!(throughput_per_second > 6, "{throughput_per_second}");
        println!(
            "jobs={completed} workers=3 slots=6 project_concurrency=4 cold_first_ms={cold_first_millis} hot_completed_before_cold=0 elapsed_ms={elapsed_millis} throughput_per_second={throughput_per_second} database_connections_per_worker=8 processor_cpu_capacity=6 processor_memory_mib_capacity=12288 processor_scratch_mib_capacity=384"
        );
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn resource_failures_retry_once_quarantine_and_do_not_block_when_configured() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
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
        sqlx::query("UPDATE jobs SET max_attempt = 1 WHERE id = $1::uuid")
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
            grouping_enabled: false,
            reprocessing_enabled: true,
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
            "SELECT state, attempt, resource_failures, failure_code FROM jobs WHERE id = $1::uuid",
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
        sqlx::query("UPDATE jobs SET available_at = now() WHERE id = $1::uuid")
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
            "SELECT state, attempt, resource_failures, failure_code FROM jobs WHERE id = $1::uuid",
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
        sqlx::query("UPDATE jobs SET available_at = now() WHERE id = $1::uuid")
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
            "SELECT j.state, j.attempt, j.resource_failures, e.processing_state FROM jobs j JOIN crash_events e ON e.id = j.event_id AND e.organization_id = j.organization_id AND e.project_id = j.project_id WHERE j.id = $1::uuid",
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
        let attempt: i32 = sqlx::query_scalar("SELECT attempt FROM jobs WHERE id = $1::uuid")
            .bind(&cancelled_job)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|error| panic!("cancelled attempt must load: {error}"));
        assert_eq!(attempt, 0);
        sqlx::query("UPDATE jobs SET available_at = now() + interval '1 hour' WHERE id = $1::uuid")
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
        sqlx::query("UPDATE jobs SET available_at = now() + interval '1 hour' WHERE id = $1::uuid")
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
            let state: String = sqlx::query_scalar("SELECT state FROM jobs WHERE id = $1::uuid")
                .bind(&transient_job)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("transient state must load: {error}"));
            if attempt < 5 {
                assert_eq!(state, "pending");
                sqlx::query("UPDATE jobs SET available_at = now() WHERE id = $1::uuid")
                    .bind(&transient_job)
                    .execute(&pool)
                    .await
                    .unwrap_or_else(|error| panic!("transient retry must become ready: {error}"));
            } else {
                assert_eq!(state, "dead");
            }
        }
        let failed_state: String =
            sqlx::query_scalar("SELECT processing_state FROM crash_events WHERE id = (SELECT event_id FROM jobs WHERE id = $1::uuid)")
                .bind(&transient_job)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("failed event must load: {error}"));
        assert_eq!(failed_state, "failed");
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn exact_symbol_waiters_reprocess_one_event_without_losing_history_when_configured() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let user_id: String = sqlx::query_scalar(
            "INSERT INTO users (bootstrap_subject, email) VALUES ('local-bootstrap', 'reprocessing@example.com') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("user must insert: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Reprocessing test', 'reprocessing-test') RETURNING id::text",
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
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Game', 'game') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("project must insert: {error}"));
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '1.0.0', 'windows', 'x86_64', 'Shipping', '2026-01-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("release must insert: {error}"));
        let token_id: String = sqlx::query_scalar(
            "INSERT INTO artifact_upload_tokens (organization_id, project_id, created_by_user_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'waiter') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&user_id)
        .bind(Sha256::digest(b"reprocessing-token").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("upload token must insert: {error}"));
        let job_id = insert_event_job(&pool, &organization_id, &project_id, "reprocessing").await;
        let event_id: String =
            sqlx::query_scalar("SELECT event_id::text FROM jobs WHERE id = $1::uuid")
                .bind(&job_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("event ID must load: {error}"));
        let raw_object_id: String =
            sqlx::query_scalar("SELECT raw_object_id::text FROM crash_events WHERE id = $1::uuid")
                .bind(&event_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("raw object ID must load: {error}"));
        let worker = publication_worker(pool.clone(), "reprocessing-worker", false);
        let release = release_resolution("1.0.0", vec![release_id.clone()]);
        let mut partial =
            processing_result("UECC-Windows-Reprocessing-1", "1.0.0", "0x0000000140001000");
        partial["current"]["symbolication"]["modules"][0]["status"] = json!("missing_pdb");
        partial["current"]["symbolication"]["modules"][0]["pdb"] = Value::Null;
        partial["current"]["symbolication"]["threads"][0]["frames"][0]["symbol_status"] =
            json!("missing_pdb");
        partial["current"]["symbolication"]["threads"][0]["frames"][0]["function"] = Value::Null;
        partial["current"]["symbolication"]["threads"][0]["frames"][0]["source_file"] = Value::Null;
        partial["current"]["symbolication"]["threads"][0]["frames"][0]["source_line"] = Value::Null;
        let initial = lease_exact_job(&pool, &job_id, worker.instance_id.as_ref()).await;
        worker
            .publish_crash_result(
                &initial,
                &event_id,
                partial.clone(),
                "awaiting_symbols",
                "matching_symbols_missing",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("partial result must publish: {error:?}"));
        let waiter_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_symbol_waiters WHERE event_id = $1::uuid AND release_id = $2::uuid AND required_artifact = 'pdb' AND debug_id = 'DEBUG-A'",
        )
        .bind(&event_id)
        .bind(&release_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("waiter count must load: {error}"));
        assert_eq!(waiter_count, 1);

        let manifest_id: String = sqlx::query_scalar(
            "INSERT INTO release_manifest_artifacts (release_id, organization_id, project_id, uploaded_by_user_id, upload_token_id, checksum, byte_size, artifact_type, module_name, architecture, debug_id, source_path, cli_version, state, uploaded_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, 10, 'pdb', 'Game.pdb', 'x86_64', 'DEBUG-A', 'Game.pdb', '0.1.0', 'available', now()) RETURNING id::text",
        )
        .bind(&release_id)
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&user_id)
        .bind(&token_id)
        .bind(Sha256::digest(b"matching-pdb").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("manifest must insert: {error}"));
        let mut transaction = pool
            .begin()
            .await
            .unwrap_or_else(|error| panic!("request transaction must begin: {error}"));
        crate::reprocessing::enqueue_artifact_request(
            &mut transaction,
            &organization_id,
            &project_id,
            &manifest_id,
        )
        .await
        .unwrap_or_else(|error| panic!("automatic request must enqueue: {error}"));
        crate::reprocessing::enqueue_artifact_request(
            &mut transaction,
            &organization_id,
            &project_id,
            &manifest_id,
        )
        .await
        .unwrap_or_else(|error| panic!("duplicate request must be idempotent: {error}"));
        transaction
            .commit()
            .await
            .unwrap_or_else(|error| panic!("request transaction must commit: {error}"));
        assert!(
            worker
                .schedule_reprocessing_request()
                .await
                .unwrap_or_else(|()| panic!("request must schedule"))
        );
        let scheduled = sqlx::query(
            "SELECT e.requested_reprocessing_generation, e.completed_reprocessing_generation, j.state AS job_state, j.priority, r.state AS request_state, r.selected_count, r.queued_count FROM crash_events e JOIN jobs j ON j.event_id = e.id AND j.job_type = 'process_crash' JOIN crash_reprocessing_request_events x ON x.event_id = e.id JOIN crash_reprocessing_requests r ON r.id = x.request_id WHERE e.id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("scheduled state must load: {error}"));
        assert_eq!(
            scheduled.get::<i64, _>("requested_reprocessing_generation"),
            1
        );
        assert_eq!(
            scheduled.get::<i64, _>("completed_reprocessing_generation"),
            0
        );
        assert_eq!(scheduled.get::<String, _>("job_state"), "pending");
        assert_eq!(scheduled.get::<i16, _>("priority"), 200);
        assert_eq!(scheduled.get::<String, _>("request_state"), "running");
        assert_eq!(scheduled.get::<i64, _>("selected_count"), 1);
        assert_eq!(scheduled.get::<i64, _>("queued_count"), 1);

        let reprocessing_job = claim_job(&pool, worker.instance_id.as_ref())
            .await
            .unwrap_or_else(|()| panic!("event job claim must succeed"))
            .unwrap_or_else(|| panic!("event job must be claimable"));
        assert_eq!(reprocessing_job.target_generation, 1);
        let running_count: i64 =
            sqlx::query_scalar("SELECT running_count FROM crash_reprocessing_requests LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("running progress must load: {error}"));
        assert_eq!(running_count, 1);
        let mut resolved =
            processing_result("UECC-Windows-Reprocessing-1", "1.0.0", "CrashFixture()");
        resolved["history"] = json!([partial["current"].clone()]);
        worker
            .publish_crash_result(
                &reprocessing_job,
                &event_id,
                resolved,
                "processed",
                "processing_complete",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("resolved result must publish: {error:?}"));
        let completed = sqlx::query(
            "SELECT e.processing_state, e.raw_object_id::text AS raw_object_id, e.requested_reprocessing_generation, e.completed_reprocessing_generation, jsonb_array_length(r.result->'history') AS history_count, j.state AS job_state, q.state AS request_state, q.completed_count, q.failed_count FROM crash_events e JOIN crash_processing_results r ON r.id = e.current_result_id JOIN jobs j ON j.event_id = e.id AND j.job_type = 'process_crash' JOIN crash_reprocessing_request_events x ON x.event_id = e.id JOIN crash_reprocessing_requests q ON q.id = x.request_id WHERE e.id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("completed state must load: {error}"));
        assert_eq!(completed.get::<String, _>("processing_state"), "processed");
        assert_eq!(completed.get::<String, _>("raw_object_id"), raw_object_id);
        assert_eq!(
            completed.get::<i64, _>("requested_reprocessing_generation"),
            1
        );
        assert_eq!(
            completed.get::<i64, _>("completed_reprocessing_generation"),
            1
        );
        assert_eq!(completed.get::<i32, _>("history_count"), 1);
        assert_eq!(completed.get::<String, _>("job_state"), "completed");
        assert_eq!(completed.get::<String, _>("request_state"), "completed");
        assert_eq!(completed.get::<i64, _>("completed_count"), 1);
        assert_eq!(completed.get::<i64, _>("failed_count"), 0);
        let retained_results: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_processing_results WHERE event_id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("result history must load: {error}"));
        assert_eq!(retained_results, 2);
        let remaining_waiters: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_symbol_waiters WHERE event_id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("remaining waiters must load: {error}"));
        assert_eq!(remaining_waiters, 0);

        let mismatch_manifest: String = sqlx::query_scalar(
            "INSERT INTO release_manifest_artifacts (release_id, organization_id, project_id, uploaded_by_user_id, upload_token_id, checksum, byte_size, artifact_type, module_name, architecture, debug_id, source_path, cli_version, state, uploaded_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, 11, 'pdb', 'Other.pdb', 'x86_64', 'DEBUG-B', 'Other.pdb', '0.1.0', 'available', now()) RETURNING id::text",
        )
        .bind(&release_id)
        .bind(&organization_id)
        .bind(&project_id)
        .bind(&user_id)
        .bind(&token_id)
        .bind(Sha256::digest(b"mismatch-pdb").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("mismatch manifest must insert: {error}"));
        let mut transaction = pool
            .begin()
            .await
            .unwrap_or_else(|error| panic!("mismatch transaction must begin: {error}"));
        crate::reprocessing::enqueue_artifact_request(
            &mut transaction,
            &organization_id,
            &project_id,
            &mismatch_manifest,
        )
        .await
        .unwrap_or_else(|error| panic!("mismatch request must enqueue: {error}"));
        transaction
            .commit()
            .await
            .unwrap_or_else(|error| panic!("mismatch transaction must commit: {error}"));
        assert!(
            worker
                .schedule_reprocessing_request()
                .await
                .unwrap_or_else(|()| panic!("mismatch request must schedule"))
        );
        let generation: i64 = sqlx::query_scalar(
            "SELECT requested_reprocessing_generation FROM crash_events WHERE id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("generation must load: {error}"));
        assert_eq!(generation, 1);
        let request_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM crash_reprocessing_requests")
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("request count must load: {error}"));
        assert_eq!(request_count, 2);
        let zero_match_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crash_reprocessing_requests WHERE state = 'completed' AND selected_count = 0",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("zero match count must load: {error}"));
        assert_eq!(zero_match_count, 1);

        let catchup_job_id =
            insert_event_job(&pool, &organization_id, &project_id, "reprocessing-catchup").await;
        let catchup_event_id: String =
            sqlx::query_scalar("SELECT event_id::text FROM jobs WHERE id = $1::uuid")
                .bind(&catchup_job_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("catch-up event ID must load: {error}"));
        let catchup_job =
            lease_exact_job(&pool, &catchup_job_id, worker.instance_id.as_ref()).await;
        let mut late_partial = processing_result(
            "UECC-Windows-Reprocessing-Catchup",
            "1.0.0",
            "0x0000000140001000",
        );
        late_partial["current"]["symbolication"]["modules"][0]["status"] = json!("missing_pdb");
        late_partial["current"]["symbolication"]["modules"][0]["pdb"] = Value::Null;
        late_partial["current"]["symbolication"]["threads"][0]["frames"][0]["symbol_status"] =
            json!("missing_pdb");
        late_partial["current"]["symbolication"]["threads"][0]["frames"][0]["function"] =
            Value::Null;
        late_partial["current"]["symbolication"]["threads"][0]["frames"][0]["source_file"] =
            Value::Null;
        late_partial["current"]["symbolication"]["threads"][0]["frames"][0]["source_line"] =
            Value::Null;
        worker
            .publish_crash_result(
                &catchup_job,
                &catchup_event_id,
                late_partial,
                "awaiting_symbols",
                "matching_symbols_missing",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("late partial result must publish: {error:?}"));
        assert!(
            worker
                .schedule_reprocessing_request()
                .await
                .unwrap_or_else(|()| panic!("catch-up request must schedule"))
        );
        let catchup = sqlx::query(
            "SELECT e.requested_reprocessing_generation, r.state, r.selected_count FROM crash_events e JOIN crash_reprocessing_request_events x ON x.event_id = e.id JOIN crash_reprocessing_requests r ON r.id = x.request_id WHERE e.id = $1::uuid AND r.scope_value = $2",
        )
        .bind(&catchup_event_id)
        .bind(&manifest_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("catch-up state must load: {error}"));
        assert_eq!(
            catchup.get::<i64, _>("requested_reprocessing_generation"),
            1
        );
        assert_eq!(catchup.get::<String, _>("state"), "running");
        assert_eq!(catchup.get::<i64, _>("selected_count"), 1);
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn concurrent_reprocessing_coalesces_and_failure_keeps_the_current_result_when_configured()
     {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let user_id: String = sqlx::query_scalar(
            "INSERT INTO users (bootstrap_subject, email) VALUES ('local-bootstrap', 'coalescing@example.com') RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("user must insert: {error}"));
        let organization_id: String = sqlx::query_scalar(
            "INSERT INTO organizations (name, slug) VALUES ('Coalescing test', 'coalescing-test') RETURNING id::text",
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
            "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Game', 'game') RETURNING id::text",
        )
        .bind(&organization_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("project must insert: {error}"));
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '2.0.0', 'windows', 'x86_64', 'Shipping', '2026-02-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&organization_id)
        .bind(&project_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("release must insert: {error}"));
        let job_id = insert_event_job(&pool, &organization_id, &project_id, "coalescing").await;
        let event_id: String =
            sqlx::query_scalar("SELECT event_id::text FROM jobs WHERE id = $1::uuid")
                .bind(&job_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|error| panic!("event ID must load: {error}"));
        let worker = publication_worker(pool.clone(), "coalescing-worker", false);
        let release = release_resolution("2.0.0", vec![release_id]);
        let initial_job = lease_exact_job(&pool, &job_id, worker.instance_id.as_ref()).await;
        worker
            .publish_crash_result(
                &initial_job,
                &event_id,
                processing_result("UECC-Windows-Coalescing-1", "2.0.0", "Initial()"),
                "processed",
                "processing_complete",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("initial result must publish: {error:?}"));
        let initial = sqlx::query(
            "SELECT current_result_id::text AS result_id, raw_object_id::text AS raw_object_id FROM crash_events WHERE id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("initial event state must load: {error}"));
        let initial_result: String = initial.get("result_id");
        let raw_object_id: String = initial.get("raw_object_id");

        let first_request = insert_manual_reprocessing_request(
            &pool,
            &organization_id,
            &project_id,
            &user_id,
            "event",
            Some(&event_id),
            "first",
        )
        .await;
        assert!(
            worker
                .schedule_reprocessing_request()
                .await
                .unwrap_or_else(|()| panic!("first request must schedule"))
        );
        let first_job = claim_job(&pool, worker.instance_id.as_ref())
            .await
            .unwrap_or_else(|()| panic!("first generation must claim"))
            .unwrap_or_else(|| panic!("first generation must exist"));
        assert_eq!(first_job.target_generation, 1);

        let second_request = insert_manual_reprocessing_request(
            &pool,
            &organization_id,
            &project_id,
            &user_id,
            "event",
            Some(&event_id),
            "second",
        )
        .await;
        let third_request = insert_manual_reprocessing_request(
            &pool,
            &organization_id,
            &project_id,
            &user_id,
            "event",
            Some(&event_id),
            "third",
        )
        .await;
        for _ in 0..2 {
            assert!(
                worker
                    .schedule_reprocessing_request()
                    .await
                    .unwrap_or_else(|()| panic!("concurrent request must schedule"))
            );
        }
        let generations = sqlx::query(
            "SELECT request_id::text AS request_id, generation FROM crash_reprocessing_request_events WHERE event_id = $1::uuid ORDER BY generation, request_id",
        )
        .bind(&event_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("request generations must load: {error}"));
        assert_eq!(generations.len(), 3);
        assert_eq!(generations[0].get::<i64, _>("generation"), 1);
        assert_eq!(generations[1].get::<i64, _>("generation"), 2);
        assert_eq!(generations[2].get::<i64, _>("generation"), 2);

        worker
            .publish_crash_result(
                &first_job,
                &event_id,
                processing_result("UECC-Windows-Coalescing-1", "2.0.0", "Updated()"),
                "processed",
                "processing_complete",
                &release,
            )
            .await
            .unwrap_or_else(|error| panic!("first generation must publish: {error:?}"));
        let after_first = sqlx::query(
            "SELECT e.current_result_id::text AS result_id, e.requested_reprocessing_generation, e.completed_reprocessing_generation, j.state AS job_state FROM crash_events e JOIN jobs j ON j.event_id = e.id AND j.job_type = 'process_crash' WHERE e.id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("first generation state must load: {error}"));
        let updated_result: String = after_first.get("result_id");
        assert_ne!(updated_result, initial_result);
        assert_eq!(
            after_first.get::<i64, _>("requested_reprocessing_generation"),
            2
        );
        assert_eq!(
            after_first.get::<i64, _>("completed_reprocessing_generation"),
            1
        );
        assert_eq!(after_first.get::<String, _>("job_state"), "pending");
        let stale = worker
            .publish_crash_result(
                &first_job,
                &event_id,
                processing_result("UECC-Windows-Coalescing-1", "2.0.0", "Stale()"),
                "processed",
                "processing_complete",
                &release,
            )
            .await;
        assert!(matches!(stale, Err(JobError::LostLease)));

        let second_job = claim_job(&pool, worker.instance_id.as_ref())
            .await
            .unwrap_or_else(|()| panic!("second generation must claim"))
            .unwrap_or_else(|| panic!("second generation must exist"));
        assert_eq!(second_job.target_generation, 2);
        worker
            .finish_result(
                &second_job,
                Err(JobError::Deterministic("processor_output_invalid")),
            )
            .await;
        let failed = sqlx::query(
            "SELECT e.current_result_id::text AS result_id, e.raw_object_id::text AS raw_object_id, e.processing_state, e.state_reason, e.completed_reprocessing_generation, j.state AS job_state, j.failure_code, (SELECT count(*) FROM crash_processing_results r WHERE r.event_id = e.id) AS result_count FROM crash_events e JOIN jobs j ON j.event_id = e.id AND j.job_type = 'process_crash' WHERE e.id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("failed generation state must load: {error}"));
        assert_eq!(failed.get::<String, _>("result_id"), updated_result);
        assert_eq!(failed.get::<String, _>("raw_object_id"), raw_object_id);
        assert_eq!(failed.get::<String, _>("processing_state"), "processed");
        assert_eq!(failed.get::<Option<String>, _>("state_reason"), None);
        assert_eq!(failed.get::<i64, _>("completed_reprocessing_generation"), 2);
        assert_eq!(failed.get::<String, _>("job_state"), "failed");
        assert_eq!(
            failed.get::<Option<String>, _>("failure_code").as_deref(),
            Some("processor_output_invalid")
        );
        assert_eq!(failed.get::<i64, _>("result_count"), 2);
        let states = sqlx::query(
            "SELECT id::text AS request_id, state, completed_count, failed_count FROM crash_reprocessing_requests WHERE id = ANY(ARRAY(SELECT value::uuid FROM unnest($1::text[]) AS values(value))) ORDER BY id",
        )
        .bind(vec![&first_request, &second_request, &third_request])
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|error| panic!("request states must load: {error}"));
        assert_eq!(states.len(), 3);
        for state in states {
            let request_id: String = state.get("request_id");
            if request_id == first_request {
                assert_eq!(state.get::<String, _>("state"), "completed");
                assert_eq!(state.get::<i64, _>("completed_count"), 1);
            } else {
                assert_eq!(state.get::<String, _>("state"), "failed");
                assert_eq!(state.get::<i64, _>("failed_count"), 1);
            }
        }

        let recovered_request = insert_manual_reprocessing_request(
            &pool,
            &organization_id,
            &project_id,
            &user_id,
            "event",
            Some(&event_id),
            "recovered",
        )
        .await;
        let expired = super::claim_reprocessing_request(&pool, "expired-scheduler")
            .await
            .unwrap_or_else(|()| panic!("request lease must be claimed"))
            .unwrap_or_else(|| panic!("request lease must exist"));
        assert_eq!(expired.id, recovered_request);
        sqlx::query(
            "UPDATE crash_reprocessing_requests SET lease_expires_at = now() - interval '1 second' WHERE id = $1::uuid",
        )
        .bind(&recovered_request)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("request lease must expire: {error}"));
        let current = super::claim_reprocessing_request(&pool, "current-scheduler")
            .await
            .unwrap_or_else(|()| panic!("expired request must be reclaimed"))
            .unwrap_or_else(|| panic!("reclaimed request must exist"));
        assert_ne!(expired.lease_token, current.lease_token);
        let current_worker = publication_worker(pool.clone(), "current-scheduler", false);
        assert!(
            current_worker
                .expand_reprocessing_request(&expired)
                .await
                .is_err()
        );
        current_worker
            .expand_reprocessing_request(&current)
            .await
            .unwrap_or_else(|()| panic!("current request lease must schedule"));
        let recovered_generation: i64 = sqlx::query_scalar(
            "SELECT requested_reprocessing_generation FROM crash_events WHERE id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("recovered generation must load: {error}"));
        assert_eq!(recovered_generation, 3);
        sqlx::query(
            "UPDATE jobs SET state = 'completed', completed_at = now(), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = $1::uuid",
        )
        .bind(&job_id)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("old worker completion must be simulated: {error}"));
        assert!(
            super::reconcile_reprocessing_event_jobs(&pool)
                .await
                .unwrap_or_else(|()| panic!("request event reconciliation must succeed"))
        );
        let reconciled = sqlx::query(
            "SELECT j.state AS job_state, x.state AS event_state, r.state AS request_state FROM jobs j JOIN crash_reprocessing_request_events x ON x.event_id = j.event_id JOIN crash_reprocessing_requests r ON r.id = x.request_id WHERE j.id = $1::uuid AND r.id = $2::uuid",
        )
        .bind(&job_id)
        .bind(&recovered_request)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("reconciled state must load: {error}"));
        assert_eq!(reconciled.get::<String, _>("job_state"), "pending");
        assert_eq!(reconciled.get::<String, _>("event_state"), "queued");
        assert_eq!(reconciled.get::<String, _>("request_state"), "running");

        let exhausted_request = insert_manual_reprocessing_request(
            &pool,
            &organization_id,
            &project_id,
            &user_id,
            "event",
            Some(&event_id),
            "exhausted",
        )
        .await;
        sqlx::query(
            "UPDATE crash_reprocessing_requests SET state = 'scheduling', attempt = max_attempt, lease_owner = 'abandoned-scheduler', lease_token = gen_random_uuid(), lease_expires_at = now() - interval '1 second' WHERE id = $1::uuid",
        )
        .bind(&exhausted_request)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("exhausted request must expire: {error}"));
        let terminal_worker = publication_worker(pool.clone(), "terminal-scheduler", false);
        assert!(
            terminal_worker
                .schedule_reprocessing_request()
                .await
                .unwrap_or_else(|()| panic!("exhausted request must terminalize"))
        );
        let exhausted = sqlx::query(
            "SELECT state, selection_complete, attempt, max_attempt, lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL AS lease_released, failure_code, completed_at IS NOT NULL AS completed, (SELECT count(*) FROM crash_reprocessing_request_events x WHERE x.request_id = r.id) AS event_count FROM crash_reprocessing_requests r WHERE id = $1::uuid",
        )
        .bind(&exhausted_request)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("exhausted request state must load: {error}"));
        assert_eq!(exhausted.get::<String, _>("state"), "failed");
        assert!(exhausted.get::<bool, _>("selection_complete"));
        assert_eq!(
            exhausted.get::<i32, _>("attempt"),
            exhausted.get::<i32, _>("max_attempt")
        );
        assert!(exhausted.get::<bool, _>("lease_released"));
        assert_eq!(
            exhausted
                .get::<Option<String>, _>("failure_code")
                .as_deref(),
            Some("reprocessing_schedule_failed")
        );
        assert!(exhausted.get::<bool, _>("completed"));
        assert_eq!(exhausted.get::<i64, _>("event_count"), 0);
        let generation_after_exhaustion: i64 = sqlx::query_scalar(
            "SELECT requested_reprocessing_generation FROM crash_events WHERE id = $1::uuid",
        )
        .bind(&event_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("event generation must load: {error}"));
        assert_eq!(generation_after_exhaustion, recovered_generation);
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn manual_reprocessing_selectors_use_a_stable_tenant_scoped_cursor_when_configured() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let scope = insert_test_scope(&pool, "local-bootstrap", "selector-main").await;
        let outside = insert_test_scope(&pool, "outside-bootstrap", "selector-outside").await;
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '3.0.0', 'windows', 'x86_64', 'Shipping', '2026-03-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("release must insert: {error}"));
        let outside_release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '3.0.0', 'windows', 'x86_64', 'Shipping', '2026-03-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&outside.organization)
        .bind(&outside.project)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("outside release must insert: {error}"));
        let worker = publication_worker(pool.clone(), "selector-worker", true);
        let release = release_resolution("3.0.0", vec![release_id.clone()]);
        let (_, first_event) = publish_new_event(
            &worker,
            &scope.organization,
            &scope.project,
            "selector-first",
            processing_result("UECC-Windows-Selector-1", "3.0.0", "SelectorFirst()"),
            &release,
            "2026-03-02T00:00:00Z",
        )
        .await;
        let (_, second_event) = publish_new_event(
            &worker,
            &scope.organization,
            &scope.project,
            "selector-second",
            processing_result("UECC-Windows-Selector-2", "3.0.0", "SelectorSecond()"),
            &release,
            "2026-03-03T00:00:00Z",
        )
        .await;
        let outside_release = release_resolution("3.0.0", vec![outside_release_id.clone()]);
        let (_, outside_event) = publish_new_event(
            &worker,
            &outside.organization,
            &outside.project,
            "selector-outside",
            processing_result("UECC-Windows-Selector-Outside", "3.0.0", "SelectorFirst()"),
            &outside_release,
            "2026-03-02T00:00:00Z",
        )
        .await;
        let identity = sqlx::query(
            "SELECT issue_id::text AS issue_id, fingerprint_version FROM crash_events WHERE id = $1::uuid",
        )
        .bind(&first_event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("selector identity must load: {error}"));
        let issue_id: String = identity.get("issue_id");
        let fingerprint_version: i32 = identity.get("fingerprint_version");
        let specs = vec![
            ("event", Some(first_event.clone()), "selector-event"),
            ("issue", Some(issue_id), "selector-issue"),
            ("release", Some(release_id), "selector-release"),
            ("project", None, "selector-project"),
            ("parser_version", Some("1".to_owned()), "selector-parser"),
            (
                "symbolicator_version",
                Some("0.1.0".to_owned()),
                "selector-symbolicator",
            ),
            (
                "fingerprint_version",
                Some(fingerprint_version.to_string()),
                "selector-fingerprint",
            ),
        ];
        let mut request_ids = Vec::new();
        let mut project_request = None;
        for (scope_kind, scope_value, nonce) in specs {
            let request_id = insert_manual_reprocessing_page(
                &pool,
                &scope,
                scope_kind,
                scope_value.as_deref(),
                nonce,
                1,
                None,
            )
            .await;
            if scope_kind == "project" {
                project_request = Some(request_id.clone());
            }
            request_ids.push(request_id);
        }
        for _ in 0..request_ids.len() {
            assert!(
                worker
                    .schedule_reprocessing_request()
                    .await
                    .unwrap_or_else(|()| panic!("selector request must schedule"))
            );
        }
        let selected = sqlx::query(
            "SELECT count(*) AS selected_count, count(DISTINCT event_id) AS event_count, min(event_id::text) AS event_id, min(generation) AS min_generation, max(generation) AS max_generation FROM crash_reprocessing_request_events WHERE request_id = ANY(ARRAY(SELECT value::uuid FROM unnest($1::text[]) AS values(value)))",
        )
        .bind(&request_ids)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("selector results must load: {error}"));
        assert_eq!(
            selected.get::<i64, _>("selected_count"),
            i64::try_from(request_ids.len())
                .unwrap_or_else(|error| panic!("selector count must fit: {error}"))
        );
        assert_eq!(selected.get::<i64, _>("event_count"), 1);
        assert_eq!(selected.get::<String, _>("event_id"), first_event);
        assert_eq!(selected.get::<i64, _>("min_generation"), 1);
        assert_eq!(selected.get::<i64, _>("max_generation"), 1);
        let project_request =
            project_request.unwrap_or_else(|| panic!("project request must exist"));
        let project_page = sqlx::query(
            "SELECT selection_truncated, next_cursor_event_id::text AS next_cursor FROM crash_reprocessing_requests WHERE id = $1::uuid",
        )
        .bind(&project_request)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("project page must load: {error}"));
        assert!(project_page.get::<bool, _>("selection_truncated"));
        let next_cursor: String = project_page.get("next_cursor");
        assert_eq!(next_cursor, first_event);

        let next_request = insert_manual_reprocessing_page(
            &pool,
            &scope,
            "project",
            None,
            "selector-project-next",
            1,
            Some(&next_cursor),
        )
        .await;
        assert!(
            worker
                .schedule_reprocessing_request()
                .await
                .unwrap_or_else(|()| panic!("next page must schedule"))
        );
        let next = sqlx::query(
            "SELECT x.event_id::text AS event_id, x.generation, r.selection_truncated, r.next_cursor_event_id::text AS next_cursor FROM crash_reprocessing_request_events x JOIN crash_reprocessing_requests r ON r.id = x.request_id WHERE x.request_id = $1::uuid",
        )
        .bind(&next_request)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("next page result must load: {error}"));
        assert_eq!(next.get::<String, _>("event_id"), second_event);
        assert_eq!(next.get::<i64, _>("generation"), 1);
        assert!(!next.get::<bool, _>("selection_truncated"));
        assert_eq!(next.get::<Option<String>, _>("next_cursor"), None);
        let outside_generation: i64 = sqlx::query_scalar(
            "SELECT requested_reprocessing_generation FROM crash_events WHERE id = $1::uuid",
        )
        .bind(&outside_event)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("outside generation must load: {error}"));
        assert_eq!(outside_generation, 0);
    }

    #[tokio::test]
    #[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_lines)]
    async fn automatic_reprocessing_pages_past_the_request_attempt_limit_when_configured() {
        let database_url = env::var("FAULTLANE_TEST_DATABASE_URL")
            .expect("FAULTLANE_TEST_DATABASE_URL is required");
        let _guard = DATABASE_TEST_LOCK.lock().await;
        migrate(&database_url)
            .await
            .unwrap_or_else(|error| panic!("migrations must run: {error}"));
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        sqlx::query("TRUNCATE users, organizations CASCADE")
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("test database must reset: {error}"));
        let scope = insert_test_scope(&pool, "local-bootstrap", "automatic-backlog").await;
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '4.0.0', 'windows', 'x86_64', 'Shipping', '2026-04-01T00:00:00Z') RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("release must insert: {error}"));
        let ingest_key_id: String = sqlx::query_scalar(
            "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, 'backlog') RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(Sha256::digest(b"automatic-backlog-ingest").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("ingest key must insert: {error}"));
        let inserted = sqlx::query(
            "WITH objects AS (INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) SELECT gen_random_uuid(), $1::uuid, $2::uuid, 'backlog/' || n::text, decode(lpad(to_hex(n), 64, '0'), 'hex'), 1, 'application/octet-stream' FROM generate_series(1, 501) n RETURNING id, split_part(object_key, '/', 2)::integer AS n), events AS (INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, environment, processing_state, state_reason, release_id, release_mapping_state, grouping_state) SELECT gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, o.id, 'production', 'awaiting_symbols', 'matching_symbols_missing', $4::uuid, 'matched', 'disabled' FROM objects o RETURNING id, raw_object_id), indexed AS MATERIALIZED (SELECT e.id AS event_id, o.n FROM events e JOIN objects o ON o.id = e.raw_object_id), results AS (INSERT INTO crash_processing_results (id, organization_id, project_id, event_id, schema_version, processing_version, result, checksum) SELECT gen_random_uuid(), $1::uuid, $2::uuid, i.event_id, 1, 2, jsonb_build_object('fixture', i.n), decode(lpad(to_hex(i.n + 10000), 64, '0'), 'hex') FROM indexed i RETURNING event_id) SELECT (SELECT count(*) FROM events) AS events, (SELECT count(*) FROM results) AS results",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&ingest_key_id)
        .bind(&release_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("backlog fixtures must insert: {error}"));
        assert_eq!(inserted.get::<i64, _>("events"), 501);
        assert_eq!(inserted.get::<i64, _>("results"), 501);
        let prepared = sqlx::query(
            "WITH updated AS (UPDATE crash_events e SET current_result_id = r.id FROM crash_processing_results r WHERE e.id = r.event_id AND e.organization_id = $1::uuid AND e.project_id = $2::uuid AND e.current_result_id IS NULL RETURNING e.id AS event_id, e.current_result_id), inserted_jobs AS (INSERT INTO jobs (id, organization_id, project_id, event_id, job_type, payload, state, priority, attempt, idempotency_key, completed_at) SELECT gen_random_uuid(), $1::uuid, $2::uuid, u.event_id, 'process_crash', '{}'::jsonb, 'completed', 100, 1, 'automatic-backlog-' || u.event_id::text, now() FROM updated u RETURNING event_id), inserted_waiters AS (INSERT INTO crash_symbol_waiters (organization_id, project_id, event_id, result_id, release_id, required_artifact, module_name, architecture, debug_id, code_id) SELECT $1::uuid, $2::uuid, u.event_id, u.current_result_id, $3::uuid, 'pdb', 'game.exe', 'x86_64', 'DEBUG-A', '' FROM updated u RETURNING event_id) SELECT (SELECT count(*) FROM inserted_jobs) AS jobs, (SELECT count(*) FROM inserted_waiters) AS waiters",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&release_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("backlog state must prepare: {error}"));
        assert_eq!(prepared.get::<i64, _>("jobs"), 501);
        assert_eq!(prepared.get::<i64, _>("waiters"), 501);
        let token_id: String = sqlx::query_scalar(
            "INSERT INTO artifact_upload_tokens (organization_id, project_id, created_by_user_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'backlog') RETURNING id::text",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&scope.user)
        .bind(Sha256::digest(b"automatic-backlog-upload").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("upload token must insert: {error}"));
        let manifest_id: String = sqlx::query_scalar(
            "INSERT INTO release_manifest_artifacts (release_id, organization_id, project_id, uploaded_by_user_id, upload_token_id, checksum, byte_size, artifact_type, module_name, architecture, debug_id, source_path, cli_version, state, uploaded_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, 10, 'pdb', 'Game.pdb', 'x86_64', 'DEBUG-A', 'Game.pdb', '0.1.0', 'available', now()) RETURNING id::text",
        )
        .bind(&release_id)
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&scope.user)
        .bind(&token_id)
        .bind(Sha256::digest(b"automatic-backlog-pdb").to_vec())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("manifest must insert: {error}"));
        let mut transaction = pool
            .begin()
            .await
            .unwrap_or_else(|error| panic!("request transaction must begin: {error}"));
        for _ in 0..2 {
            crate::reprocessing::enqueue_artifact_request(
                &mut transaction,
                &scope.organization,
                &scope.project,
                &manifest_id,
            )
            .await
            .unwrap_or_else(|error| panic!("automatic request must enqueue: {error}"));
        }
        transaction
            .commit()
            .await
            .unwrap_or_else(|error| panic!("request transaction must commit: {error}"));
        let worker = publication_worker(pool.clone(), "automatic-backlog-worker", false);
        for page in 1_i64..=6 {
            assert!(
                worker
                    .schedule_reprocessing_request()
                    .await
                    .unwrap_or_else(|()| panic!("automatic page must schedule"))
            );
            let progress = sqlx::query(
                "SELECT state, selection_complete, selected_count, attempt FROM crash_reprocessing_requests WHERE scope_value = $1",
            )
            .bind(&manifest_id)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|error| panic!("automatic progress must load: {error}"));
            assert_eq!(
                progress.get::<i64, _>("selected_count"),
                (page * 100).min(501)
            );
            assert_eq!(progress.get::<i32, _>("attempt"), i32::from(page == 6));
            if page < 6 {
                assert_eq!(progress.get::<String, _>("state"), "pending");
                assert!(!progress.get::<bool, _>("selection_complete"));
            } else {
                assert_eq!(progress.get::<String, _>("state"), "running");
                assert!(progress.get::<bool, _>("selection_complete"));
            }
        }
        assert!(
            !worker
                .schedule_reprocessing_request()
                .await
                .unwrap_or_else(|()| panic!("empty scheduler pass must succeed"))
        );
        let aggregate = sqlx::query(
            "SELECT count(*) AS events, min(requested_reprocessing_generation) AS minimum_generation, max(requested_reprocessing_generation) AS maximum_generation, count(*) FILTER (WHERE j.state = 'pending' AND j.priority = 200) AS pending_jobs, (SELECT count(*) FROM crash_reprocessing_requests) AS requests, (SELECT count(*) FROM crash_reprocessing_request_events) AS request_events FROM crash_events e JOIN jobs j ON j.event_id = e.id AND j.job_type = 'process_crash' WHERE e.project_id = $1::uuid",
        )
        .bind(&scope.project)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|error| panic!("automatic aggregate must load: {error}"));
        assert_eq!(aggregate.get::<i64, _>("events"), 501);
        assert_eq!(aggregate.get::<i64, _>("minimum_generation"), 1);
        assert_eq!(aggregate.get::<i64, _>("maximum_generation"), 1);
        assert_eq!(aggregate.get::<i64, _>("pending_jobs"), 501);
        assert_eq!(aggregate.get::<i64, _>("requests"), 1);
        assert_eq!(aggregate.get::<i64, _>("request_events"), 501);
    }
}
