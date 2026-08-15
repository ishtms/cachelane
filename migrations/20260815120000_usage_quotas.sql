CREATE TABLE project_usage_policies (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    event_limit BIGINT NOT NULL DEFAULT 10000 CHECK (event_limit > 0),
    artifact_storage_limit_bytes BIGINT NOT NULL DEFAULT 25000000000
        CHECK (artifact_storage_limit_bytes > 0),
    project_limit INTEGER NOT NULL DEFAULT 1 CHECK (project_limit > 0),
    normalized_retention_limit_days INTEGER NOT NULL DEFAULT 30
        CHECK (normalized_retention_limit_days BETWEEN 1 AND 3650),
    raw_retention_limit_days INTEGER NOT NULL DEFAULT 7
        CHECK (raw_retention_limit_days BETWEEN 1 AND 3650),
    normalized_retention_days INTEGER NOT NULL DEFAULT 30
        CHECK (normalized_retention_days BETWEEN 1 AND 3650),
    raw_retention_days INTEGER NOT NULL DEFAULT 7
        CHECK (raw_retention_days BETWEEN 1 AND 3650),
    courtesy_percent INTEGER NOT NULL DEFAULT 20
        CHECK (courtesy_percent BETWEEN 0 AND 100),
    spend_cap_cents BIGINT CHECK (spend_cap_cents BETWEEN 1500 AND 10000000),
    retain_all_raw BOOLEAN NOT NULL DEFAULT false,
    updated_by_user_id UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, project_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (updated_by_user_id)
        REFERENCES users(id) ON DELETE SET NULL,
    CHECK (normalized_retention_days <= normalized_retention_limit_days),
    CHECK (raw_retention_days <= raw_retention_limit_days)
);

INSERT INTO project_usage_policies (organization_id, project_id)
SELECT organization_id, id
FROM projects;

CREATE TABLE project_usage_policy_versions (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    event_limit BIGINT NOT NULL CHECK (event_limit > 0),
    artifact_storage_limit_bytes BIGINT NOT NULL CHECK (artifact_storage_limit_bytes > 0),
    project_limit INTEGER NOT NULL CHECK (project_limit > 0),
    normalized_retention_limit_days INTEGER NOT NULL
        CHECK (normalized_retention_limit_days BETWEEN 1 AND 3650),
    raw_retention_limit_days INTEGER NOT NULL
        CHECK (raw_retention_limit_days BETWEEN 1 AND 3650),
    normalized_retention_days INTEGER NOT NULL
        CHECK (normalized_retention_days BETWEEN 1 AND 3650),
    raw_retention_days INTEGER NOT NULL
        CHECK (raw_retention_days BETWEEN 1 AND 3650),
    courtesy_percent INTEGER NOT NULL CHECK (courtesy_percent BETWEEN 0 AND 100),
    spend_cap_cents BIGINT CHECK (spend_cap_cents BETWEEN 1500 AND 10000000),
    retain_all_raw BOOLEAN NOT NULL,
    updated_by_user_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, project_id, version),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (updated_by_user_id)
        REFERENCES users(id) ON DELETE SET NULL,
    CHECK (normalized_retention_days <= normalized_retention_limit_days),
    CHECK (raw_retention_days <= raw_retention_limit_days)
);

INSERT INTO project_usage_policy_versions (
    organization_id,
    project_id,
    version,
    event_limit,
    artifact_storage_limit_bytes,
    project_limit,
    normalized_retention_limit_days,
    raw_retention_limit_days,
    normalized_retention_days,
    raw_retention_days,
    courtesy_percent,
    spend_cap_cents,
    retain_all_raw,
    updated_by_user_id,
    created_at
)
SELECT
    organization_id,
    project_id,
    version,
    event_limit,
    artifact_storage_limit_bytes,
    project_limit,
    normalized_retention_limit_days,
    raw_retention_limit_days,
    normalized_retention_days,
    raw_retention_days,
    courtesy_percent,
    spend_cap_cents,
    retain_all_raw,
    updated_by_user_id,
    updated_at
FROM project_usage_policies;

CREATE FUNCTION initialize_project_usage_policy()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO project_usage_policies (organization_id, project_id)
    VALUES (NEW.organization_id, NEW.id);

    INSERT INTO project_usage_policy_versions (
        organization_id,
        project_id,
        version,
        event_limit,
        artifact_storage_limit_bytes,
        project_limit,
        normalized_retention_limit_days,
        raw_retention_limit_days,
        normalized_retention_days,
        raw_retention_days,
        courtesy_percent,
        spend_cap_cents,
        retain_all_raw,
        updated_by_user_id,
        created_at
    )
    SELECT
        organization_id,
        project_id,
        version,
        event_limit,
        artifact_storage_limit_bytes,
        project_limit,
        normalized_retention_limit_days,
        raw_retention_limit_days,
        normalized_retention_days,
        raw_retention_days,
        courtesy_percent,
        spend_cap_cents,
        retain_all_raw,
        updated_by_user_id,
        updated_at
    FROM project_usage_policies
    WHERE organization_id = NEW.organization_id
      AND project_id = NEW.id;

    RETURN NEW;
END;
$$;

CREATE TRIGGER projects_initialize_usage_policy
AFTER INSERT ON projects
FOR EACH ROW
EXECUTE FUNCTION initialize_project_usage_policy();

CREATE TABLE usage_cycle_counters (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    cycle_start DATE NOT NULL,
    accepted_events BIGINT NOT NULL DEFAULT 0 CHECK (accepted_events >= 0),
    accepted_raw_bytes BIGINT NOT NULL DEFAULT 0 CHECK (accepted_raw_bytes >= 0),
    accepted_symbol_bytes BIGINT NOT NULL DEFAULT 0 CHECK (accepted_symbol_bytes >= 0),
    deleted_raw_bytes BIGINT NOT NULL DEFAULT 0 CHECK (deleted_raw_bytes >= 0),
    sampled_raw_events BIGINT NOT NULL DEFAULT 0 CHECK (sampled_raw_events >= 0),
    estimated_represented_events BIGINT NOT NULL DEFAULT 0
        CHECK (estimated_represented_events >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, project_id, cycle_start),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE TABLE usage_ledger (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    cycle_start DATE NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN (
        'accepted_event',
        'raw_stored',
        'raw_deleted',
        'symbol_stored'
    )),
    source_id UUID NOT NULL,
    quantity BIGINT NOT NULL CHECK (quantity > 0),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, project_id, kind, source_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE INDEX usage_ledger_cycle
    ON usage_ledger (organization_id, project_id, cycle_start, kind);

INSERT INTO usage_ledger (
    organization_id,
    project_id,
    cycle_start,
    kind,
    source_id,
    quantity,
    occurred_at
)
SELECT
    organization_id,
    project_id,
    date_trunc('month', received_at AT TIME ZONE 'UTC')::date,
    'accepted_event',
    id,
    1,
    received_at
FROM crash_events;

INSERT INTO usage_ledger (
    organization_id,
    project_id,
    cycle_start,
    kind,
    source_id,
    quantity,
    occurred_at
)
SELECT
    o.organization_id,
    o.project_id,
    date_trunc('month', e.received_at AT TIME ZONE 'UTC')::date,
    'raw_stored',
    o.id,
    o.byte_size,
    e.received_at
FROM crash_event_objects o
JOIN crash_events e
    ON e.raw_object_id = o.id
   AND e.organization_id = o.organization_id
   AND e.project_id = o.project_id;

INSERT INTO usage_ledger (
    organization_id,
    project_id,
    cycle_start,
    kind,
    source_id,
    quantity,
    occurred_at
)
SELECT
    m.organization_id,
    m.project_id,
    date_trunc('month', min(m.uploaded_at) AT TIME ZONE 'UTC')::date,
    'symbol_stored',
    ao.id,
    ao.byte_size,
    min(m.uploaded_at)
FROM release_manifest_artifacts m
JOIN artifact_debug_images d
    ON d.id = m.debug_image_id
   AND d.organization_id = m.organization_id
JOIN artifact_objects ao
    ON ao.id = d.object_id
   AND ao.organization_id = d.organization_id
WHERE m.state = 'available'
  AND m.uploaded_at IS NOT NULL
GROUP BY m.organization_id, m.project_id, ao.id, ao.byte_size;

INSERT INTO usage_cycle_counters (
    organization_id,
    project_id,
    cycle_start,
    accepted_events,
    accepted_raw_bytes
)
SELECT
    e.organization_id,
    e.project_id,
    date_trunc('month', e.received_at AT TIME ZONE 'UTC')::date,
    count(*),
    sum(o.byte_size)
FROM crash_events e
JOIN crash_event_objects o
    ON o.id = e.raw_object_id
   AND o.organization_id = e.organization_id
   AND o.project_id = e.project_id
GROUP BY e.organization_id, e.project_id,
    date_trunc('month', e.received_at AT TIME ZONE 'UTC')::date;

INSERT INTO usage_cycle_counters (
    organization_id,
    project_id,
    cycle_start,
    accepted_symbol_bytes
)
SELECT
    organization_id,
    project_id,
    cycle_start,
    sum(quantity)
FROM usage_ledger
WHERE kind = 'symbol_stored'
GROUP BY organization_id, project_id, cycle_start
ON CONFLICT (organization_id, project_id, cycle_start) DO UPDATE
SET accepted_symbol_bytes = EXCLUDED.accepted_symbol_bytes,
    updated_at = now();

ALTER TABLE crash_events
    ADD COLUMN usage_cycle_start DATE,
    ADD COLUMN usage_policy_version BIGINT,
    ADD COLUMN usage_outcome TEXT,
    ADD COLUMN usage_counted BOOLEAN,
    ADD COLUMN usage_estimated BOOLEAN,
    ADD COLUMN usage_accepted_events BIGINT,
    ADD COLUMN raw_retention_class TEXT,
    ADD COLUMN raw_sampling_rate INTEGER;

WITH ranked AS (
    SELECT
        id,
        row_number() OVER (
            PARTITION BY organization_id, project_id,
                date_trunc('month', received_at AT TIME ZONE 'UTC')::date
            ORDER BY received_at, id
        ) AS accepted_events
    FROM crash_events
)
UPDATE crash_events e
SET usage_cycle_start = date_trunc('month', e.received_at AT TIME ZONE 'UTC')::date,
    usage_policy_version = 1,
    usage_outcome = 'standard',
    usage_counted = true,
    usage_estimated = false,
    usage_accepted_events = ranked.accepted_events,
    raw_retention_class = 'standard',
    raw_sampling_rate = 1
FROM ranked
WHERE ranked.id = e.id;

ALTER TABLE crash_events
    ALTER COLUMN usage_cycle_start SET NOT NULL,
    ALTER COLUMN usage_cycle_start SET DEFAULT
        date_trunc('month', now() AT TIME ZONE 'UTC')::date,
    ALTER COLUMN usage_policy_version SET NOT NULL,
    ALTER COLUMN usage_policy_version SET DEFAULT 1,
    ALTER COLUMN usage_outcome SET NOT NULL,
    ALTER COLUMN usage_outcome SET DEFAULT 'standard',
    ALTER COLUMN usage_counted SET NOT NULL,
    ALTER COLUMN usage_counted SET DEFAULT false,
    ALTER COLUMN usage_estimated SET NOT NULL,
    ALTER COLUMN usage_estimated SET DEFAULT false,
    ALTER COLUMN usage_accepted_events SET NOT NULL,
    ALTER COLUMN usage_accepted_events SET DEFAULT 0,
    ALTER COLUMN raw_retention_class SET NOT NULL,
    ALTER COLUMN raw_retention_class SET DEFAULT 'pending',
    ALTER COLUMN raw_sampling_rate SET NOT NULL,
    ALTER COLUMN raw_sampling_rate SET DEFAULT 1,
    ADD CONSTRAINT crash_events_usage_policy_version_check
        CHECK (usage_policy_version > 0),
    ADD CONSTRAINT crash_events_usage_outcome_check
        CHECK (usage_outcome IN ('standard', 'courtesy', 'overage', 'sampling')),
    ADD CONSTRAINT crash_events_raw_retention_class_check
        CHECK (raw_retention_class IN (
            'pending',
            'standard',
            'novel',
            'representative',
            'recent',
            'variant',
            'reservoir',
            'deleting',
            'discarded',
            'expired'
        )),
    ADD CONSTRAINT crash_events_raw_sampling_rate_check
        CHECK (raw_sampling_rate BETWEEN 1 AND 10000),
    ADD CONSTRAINT crash_events_usage_estimate_check
        CHECK ((usage_estimated AND usage_outcome = 'sampling')
            OR NOT usage_estimated),
    ADD CONSTRAINT crash_events_usage_accepted_events_check
        CHECK (usage_accepted_events >= 0),
    ADD CONSTRAINT crash_events_usage_policy_version_fkey
        FOREIGN KEY (organization_id, project_id, usage_policy_version)
        REFERENCES project_usage_policy_versions (
            organization_id,
            project_id,
            version
        );

ALTER TABLE crash_event_objects
    DROP CONSTRAINT crash_event_objects_lifecycle_state_check,
    ADD COLUMN deleted_at TIMESTAMPTZ,
    ADD CONSTRAINT crash_event_objects_lifecycle_state_check
        CHECK (lifecycle_state IN ('stored', 'orphaned', 'deleting', 'discarded')),
    ADD CONSTRAINT crash_event_objects_deleted_check
        CHECK ((lifecycle_state = 'discarded' AND deleted_at IS NOT NULL)
            OR (lifecycle_state <> 'discarded' AND deleted_at IS NULL));

ALTER TABLE jobs
    DROP CONSTRAINT jobs_job_type_check,
    DROP CONSTRAINT jobs_target_check,
    ADD CONSTRAINT jobs_job_type_check
        CHECK (job_type IN (
            'process_crash',
            'index_artifact',
            'generate_symcache',
            'delete_raw'
        )),
    ADD CONSTRAINT jobs_target_check CHECK (
        (job_type IN ('process_crash', 'delete_raw')
            AND event_id IS NOT NULL
            AND artifact_upload_id IS NULL
            AND derived_cache_id IS NULL)
        OR (job_type = 'index_artifact'
            AND event_id IS NULL
            AND artifact_upload_id IS NOT NULL
            AND derived_cache_id IS NULL)
        OR (job_type = 'generate_symcache'
            AND event_id IS NULL
            AND artifact_upload_id IS NULL
            AND derived_cache_id IS NOT NULL)
    );

CREATE INDEX crash_event_objects_retention
    ON crash_event_objects (organization_id, project_id, created_at, id)
    WHERE lifecycle_state = 'stored';
