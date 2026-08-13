ALTER TABLE project_ingest_keys
    ADD COLUMN environment TEXT NOT NULL DEFAULT 'production',
    ADD COLUMN allowed_cidrs TEXT[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT project_ingest_keys_environment_check
        CHECK (environment ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
    ADD CONSTRAINT project_ingest_keys_scope_unique
        UNIQUE (id, organization_id, project_id);

CREATE TABLE crash_event_objects (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    object_key TEXT NOT NULL UNIQUE,
    checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    byte_size BIGINT NOT NULL CHECK (byte_size > 0),
    media_type TEXT NOT NULL CHECK (media_type = 'application/octet-stream'),
    lifecycle_state TEXT NOT NULL DEFAULT 'stored'
        CHECK (lifecycle_state IN ('stored', 'orphaned')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id, project_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE TABLE crash_events (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    ingest_key_id UUID NOT NULL,
    raw_object_id UUID NOT NULL,
    crash_guid TEXT,
    environment TEXT NOT NULL,
    processing_state TEXT NOT NULL DEFAULT 'stored'
        CHECK (processing_state IN (
            'received',
            'stored',
            'parsed',
            'awaiting_symbols',
            'symbolicating',
            'processed',
            'failed',
            'quarantined'
        )),
    state_reason TEXT,
    retryable BOOLEAN NOT NULL DEFAULT false,
    retry_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id, project_id),
    UNIQUE (raw_object_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (ingest_key_id, organization_id, project_id)
        REFERENCES project_ingest_keys(id, organization_id, project_id),
    FOREIGN KEY (raw_object_id, organization_id, project_id)
        REFERENCES crash_event_objects(id, organization_id, project_id),
    CHECK ((processing_state IN ('failed', 'quarantined')
            AND state_reason IS NOT NULL)
        OR processing_state NOT IN ('failed', 'quarantined')),
    CHECK (state_reason IS NULL
        OR state_reason ~ '^[a-z0-9][a-z0-9_]{0,63}$'),
    CHECK ((retryable AND retry_at IS NOT NULL)
        OR (NOT retryable AND retry_at IS NULL))
);

CREATE UNIQUE INDEX crash_events_project_guid_unique
    ON crash_events (project_id, crash_guid)
    WHERE crash_guid IS NOT NULL;

CREATE INDEX crash_events_project_received
    ON crash_events (project_id, received_at DESC, id);

CREATE TABLE jobs (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    event_id UUID NOT NULL,
    job_type TEXT NOT NULL CHECK (job_type = 'process_crash'),
    payload JSONB NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'leased', 'completed', 'failed', 'dead')),
    priority SMALLINT NOT NULL DEFAULT 100,
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (event_id, job_type),
    FOREIGN KEY (event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    CHECK ((state = 'leased' AND lease_owner IS NOT NULL
            AND lease_expires_at IS NOT NULL)
        OR state <> 'leased')
);

CREATE INDEX jobs_claim_order
    ON jobs (state, available_at, priority, created_at)
    WHERE state = 'pending';

CREATE TABLE ingest_rate_limits (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('project', 'ip')),
    subject_hash BYTEA NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    requests INTEGER NOT NULL CHECK (requests > 0),
    PRIMARY KEY (
        organization_id,
        project_id,
        scope,
        subject_hash,
        bucket_start
    ),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE INDEX ingest_rate_limits_expiry
    ON ingest_rate_limits (expires_at);

CREATE TABLE ingest_orphan_objects (
    object_key TEXT PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);
