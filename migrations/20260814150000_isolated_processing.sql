ALTER TABLE jobs
    DROP CONSTRAINT jobs_job_type_check,
    ALTER COLUMN event_id DROP NOT NULL,
    ADD COLUMN artifact_upload_id UUID,
    ADD COLUMN derived_cache_id UUID,
    ADD COLUMN lease_token UUID,
    ADD COLUMN max_attempt INTEGER NOT NULL DEFAULT 5 CHECK (max_attempt BETWEEN 1 AND 20),
    ADD COLUMN resource_failures INTEGER NOT NULL DEFAULT 0 CHECK (resource_failures BETWEEN 0 AND 2),
    ADD COLUMN heartbeat_at TIMESTAMPTZ,
    ADD COLUMN failure_code TEXT,
    ADD COLUMN completed_at TIMESTAMPTZ,
    ADD CONSTRAINT jobs_job_type_check
        CHECK (job_type IN ('process_crash', 'index_artifact', 'generate_symcache'));

UPDATE jobs
SET lease_token = gen_random_uuid(),
    heartbeat_at = updated_at
WHERE state = 'leased';

UPDATE jobs
SET completed_at = updated_at
WHERE state IN ('completed', 'failed', 'dead');

ALTER TABLE jobs
    ADD CONSTRAINT jobs_failure_code_check
        CHECK (failure_code IS NULL OR failure_code ~ '^[a-z0-9][a-z0-9_]{0,63}$'),
    ADD CONSTRAINT jobs_completion_check
        CHECK ((state IN ('completed', 'failed', 'dead') AND completed_at IS NOT NULL)
            OR (state IN ('pending', 'leased') AND completed_at IS NULL)),
    ADD CONSTRAINT jobs_lease_token_check
        CHECK ((state = 'leased' AND lease_token IS NOT NULL AND heartbeat_at IS NOT NULL)
            OR state <> 'leased');

CREATE TABLE crash_processing_results (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    event_id UUID NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    processing_version INTEGER NOT NULL CHECK (processing_version > 0),
    result JSONB NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id, project_id, event_id),
    UNIQUE (event_id, processing_version, checksum),
    FOREIGN KEY (event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id)
);

ALTER TABLE crash_events
    ADD COLUMN current_result_id UUID,
    ADD CONSTRAINT crash_events_current_result_fk
        FOREIGN KEY (current_result_id, organization_id, project_id, id)
        REFERENCES crash_processing_results(id, organization_id, project_id, event_id);

CREATE INDEX crash_processing_results_event_created
    ON crash_processing_results (organization_id, project_id, event_id, created_at DESC);

CREATE TABLE derived_symbol_caches (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    source_object_id UUID NOT NULL,
    processor_version TEXT NOT NULL,
    format_version INTEGER NOT NULL CHECK (format_version > 0),
    cache_kind TEXT NOT NULL CHECK (cache_kind = 'symcache'),
    object_key TEXT NOT NULL UNIQUE,
    checksum BYTEA CHECK (checksum IS NULL OR octet_length(checksum) = 32),
    byte_size BIGINT CHECK (byte_size IS NULL OR byte_size > 0),
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'processing', 'available', 'failed', 'quarantined')),
    failure_code TEXT CHECK (failure_code IS NULL OR failure_code ~ '^[a-z0-9][a-z0-9_]{0,63}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id, project_id),
    UNIQUE (organization_id, source_object_id, processor_version, format_version, cache_kind),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (source_object_id, organization_id)
        REFERENCES artifact_objects(id, organization_id),
    CHECK ((state IN ('failed', 'quarantined') AND failure_code IS NOT NULL)
        OR (state NOT IN ('failed', 'quarantined') AND failure_code IS NULL)),
    CHECK ((state = 'available' AND checksum IS NOT NULL AND byte_size IS NOT NULL)
        OR (state <> 'available' AND checksum IS NULL AND byte_size IS NULL))
);

ALTER TABLE jobs
    ADD CONSTRAINT jobs_artifact_upload_fk
        FOREIGN KEY (artifact_upload_id, organization_id, project_id)
        REFERENCES artifact_upload_sessions(id, organization_id, project_id),
    ADD CONSTRAINT jobs_derived_cache_fk
        FOREIGN KEY (derived_cache_id, organization_id, project_id)
        REFERENCES derived_symbol_caches(id, organization_id, project_id),
    ADD CONSTRAINT jobs_target_check CHECK (
        (job_type = 'process_crash' AND event_id IS NOT NULL
            AND artifact_upload_id IS NULL AND derived_cache_id IS NULL)
        OR (job_type = 'index_artifact' AND event_id IS NULL
            AND artifact_upload_id IS NOT NULL AND derived_cache_id IS NULL)
        OR (job_type = 'generate_symcache' AND event_id IS NULL
            AND artifact_upload_id IS NULL AND derived_cache_id IS NOT NULL)
    );

CREATE UNIQUE INDEX jobs_artifact_upload_unique
    ON jobs (artifact_upload_id, job_type)
    WHERE artifact_upload_id IS NOT NULL;

CREATE UNIQUE INDEX jobs_derived_cache_unique
    ON jobs (derived_cache_id, job_type)
    WHERE derived_cache_id IS NOT NULL;

DROP INDEX jobs_claim_order;

CREATE INDEX jobs_claim_order
    ON jobs (available_at, priority, created_at, project_id)
    WHERE state = 'pending';

CREATE INDEX jobs_expired_leases
    ON jobs (lease_expires_at, project_id)
    WHERE state = 'leased';

ALTER TABLE release_manifest_artifacts
    DROP CONSTRAINT release_manifest_artifacts_state_check,
    ADD COLUMN failure_code TEXT,
    ADD CONSTRAINT release_manifest_artifacts_state_check
        CHECK (state IN ('missing', 'processing', 'available', 'mismatch', 'quarantined')),
    ADD CONSTRAINT release_manifest_artifacts_failure_check
        CHECK ((state = 'quarantined' AND failure_code IS NOT NULL)
            OR (state <> 'quarantined' AND failure_code IS NULL));

ALTER TABLE artifact_debug_images
    DROP CONSTRAINT artifact_debug_images_processing_status_check,
    ADD CONSTRAINT artifact_debug_images_processing_status_check
        CHECK (processing_status IN ('processing', 'available', 'quarantined'));

DROP INDEX artifact_upload_sessions_active_artifact;

ALTER TABLE artifact_upload_sessions
    DROP CONSTRAINT artifact_upload_sessions_state_check,
    DROP CONSTRAINT artifact_upload_sessions_check,
    ADD CONSTRAINT artifact_upload_sessions_state_check
        CHECK (state IN ('active', 'completing', 'processing', 'completed', 'failed', 'aborted')),
    ADD CONSTRAINT artifact_upload_sessions_failure_check
        CHECK ((state = 'failed' AND failure_code IS NOT NULL)
            OR (state <> 'failed' AND failure_code IS NULL));

CREATE UNIQUE INDEX artifact_upload_sessions_active_artifact
    ON artifact_upload_sessions (organization_id, project_id, manifest_artifact_id)
    WHERE state IN ('active', 'completing', 'processing');

CREATE INDEX release_manifest_artifacts_processing
    ON release_manifest_artifacts (organization_id, project_id, state, updated_at)
    WHERE state IN ('processing', 'quarantined');

CREATE INDEX derived_symbol_caches_identity
    ON derived_symbol_caches (
        organization_id,
        source_object_id,
        processor_version,
        format_version,
        cache_kind,
        state
    );
