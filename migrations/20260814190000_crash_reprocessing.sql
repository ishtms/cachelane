ALTER TABLE crash_events
    ADD COLUMN requested_reprocessing_generation BIGINT NOT NULL DEFAULT 0
        CHECK (requested_reprocessing_generation >= 0),
    ADD COLUMN completed_reprocessing_generation BIGINT NOT NULL DEFAULT 0
        CHECK (completed_reprocessing_generation >= 0),
    ADD CONSTRAINT crash_events_reprocessing_generation_check
        CHECK (completed_reprocessing_generation <= requested_reprocessing_generation);

CREATE TABLE crash_symbol_waiters (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    event_id UUID NOT NULL,
    result_id UUID NOT NULL,
    release_id UUID NOT NULL,
    required_artifact TEXT NOT NULL CHECK (required_artifact IN ('pe', 'pdb')),
    module_name TEXT NOT NULL CHECK (char_length(module_name) BETWEEN 1 AND 256),
    architecture TEXT NOT NULL CHECK (char_length(architecture) BETWEEN 1 AND 32),
    debug_id TEXT NOT NULL CHECK (char_length(debug_id) BETWEEN 1 AND 128),
    code_id TEXT NOT NULL DEFAULT '' CHECK (char_length(code_id) <= 128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (
        organization_id,
        project_id,
        event_id,
        required_artifact,
        module_name,
        architecture,
        debug_id,
        code_id
    ),
    FOREIGN KEY (event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    FOREIGN KEY (result_id, organization_id, project_id, event_id)
        REFERENCES crash_processing_results(id, organization_id, project_id, event_id),
    FOREIGN KEY (release_id, organization_id, project_id)
        REFERENCES releases(id, organization_id, project_id),
    CHECK ((required_artifact = 'pe' AND code_id <> '') OR required_artifact = 'pdb')
);

CREATE INDEX crash_symbol_waiters_artifact_lookup
    ON crash_symbol_waiters (
        organization_id,
        project_id,
        release_id,
        required_artifact,
        architecture,
        debug_id,
        code_id,
        lower(module_name),
        event_id
    );

CREATE TABLE crash_reprocessing_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('automatic', 'manual')),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN (
        'artifact',
        'event',
        'issue',
        'release',
        'project',
        'parser_version',
        'symbolicator_version',
        'fingerprint_version'
    )),
    scope_value TEXT,
    scope_fingerprint BYTEA NOT NULL CHECK (octet_length(scope_fingerprint) = 32),
    idempotency_digest BYTEA NOT NULL CHECK (octet_length(idempotency_digest) = 32),
    requested_by_user_id UUID,
    request_limit INTEGER CHECK (request_limit BETWEEN 1 AND 1000),
    input_cursor_event_id UUID,
    selection_before TIMESTAMPTZ NOT NULL DEFAULT now(),
    selection_cursor_event_id UUID,
    next_cursor_event_id UUID,
    selection_complete BOOLEAN NOT NULL DEFAULT false,
    selection_truncated BOOLEAN NOT NULL DEFAULT false,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN (
        'pending',
        'scheduling',
        'running',
        'completed',
        'partial',
        'failed'
    )),
    selected_count BIGINT NOT NULL DEFAULT 0 CHECK (selected_count >= 0),
    queued_count BIGINT NOT NULL DEFAULT 0 CHECK (queued_count >= 0),
    running_count BIGINT NOT NULL DEFAULT 0 CHECK (running_count >= 0),
    completed_count BIGINT NOT NULL DEFAULT 0 CHECK (completed_count >= 0),
    failed_count BIGINT NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    max_attempt INTEGER NOT NULL DEFAULT 5 CHECK (max_attempt BETWEEN 1 AND 20),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner TEXT,
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    failure_code TEXT CHECK (failure_code IS NULL OR failure_code ~ '^[a-z0-9][a-z0-9_]{0,63}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    UNIQUE (id, organization_id, project_id),
    UNIQUE (organization_id, project_id, source, idempotency_digest),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (organization_id, requested_by_user_id)
        REFERENCES organization_memberships(organization_id, user_id),
    FOREIGN KEY (input_cursor_event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    FOREIGN KEY (selection_cursor_event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    FOREIGN KEY (next_cursor_event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    CHECK (
        (source = 'automatic'
            AND scope_kind = 'artifact'
            AND scope_value IS NOT NULL
            AND requested_by_user_id IS NULL
            AND request_limit IS NULL
            AND input_cursor_event_id IS NULL)
        OR (source = 'manual'
            AND scope_kind <> 'artifact'
            AND requested_by_user_id IS NOT NULL
            AND request_limit IS NOT NULL)
    ),
    CHECK ((scope_kind = 'project' AND scope_value IS NULL)
        OR (scope_kind <> 'project' AND scope_value IS NOT NULL)),
    CHECK ((state = 'scheduling'
            AND lease_owner IS NOT NULL
            AND lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL)
        OR (state <> 'scheduling'
            AND lease_owner IS NULL
            AND lease_token IS NULL
            AND lease_expires_at IS NULL)),
    CHECK ((state IN ('completed', 'partial', 'failed') AND completed_at IS NOT NULL)
        OR (state IN ('pending', 'scheduling', 'running') AND completed_at IS NULL)),
    CHECK (queued_count + running_count + completed_count + failed_count = selected_count)
);

CREATE TABLE crash_reprocessing_request_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    request_id UUID NOT NULL,
    event_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    previous_result_id UUID,
    result_id UUID,
    state TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'completed', 'failed')),
    failure_code TEXT CHECK (failure_code IS NULL OR failure_code ~ '^[a-z0-9][a-z0-9_]{0,63}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    UNIQUE (id, organization_id, project_id),
    UNIQUE (request_id, event_id),
    FOREIGN KEY (request_id, organization_id, project_id)
        REFERENCES crash_reprocessing_requests(id, organization_id, project_id),
    FOREIGN KEY (event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    FOREIGN KEY (previous_result_id, organization_id, project_id, event_id)
        REFERENCES crash_processing_results(id, organization_id, project_id, event_id),
    FOREIGN KEY (result_id, organization_id, project_id, event_id)
        REFERENCES crash_processing_results(id, organization_id, project_id, event_id),
    CHECK ((state = 'completed' AND result_id IS NOT NULL
            AND failure_code IS NULL AND completed_at IS NOT NULL)
        OR (state = 'failed' AND result_id IS NULL
            AND failure_code IS NOT NULL AND completed_at IS NOT NULL)
        OR (state IN ('queued', 'running') AND result_id IS NULL
            AND failure_code IS NULL AND completed_at IS NULL)),
    CHECK ((state = 'running' AND started_at IS NOT NULL)
        OR state <> 'running')
);

CREATE INDEX crash_reprocessing_requests_claim
    ON crash_reprocessing_requests (available_at, created_at, project_id)
    WHERE state = 'pending';

CREATE INDEX crash_reprocessing_requests_expired_lease
    ON crash_reprocessing_requests (lease_expires_at, project_id)
    WHERE state = 'scheduling';

CREATE INDEX crash_reprocessing_requests_active_manual
    ON crash_reprocessing_requests (organization_id, project_id, created_at)
    WHERE source = 'manual' AND state IN ('pending', 'scheduling', 'running');

CREATE INDEX crash_reprocessing_request_events_progress
    ON crash_reprocessing_request_events (request_id, state, event_id);

CREATE INDEX crash_reprocessing_request_events_event_generation
    ON crash_reprocessing_request_events (
        organization_id,
        project_id,
        event_id,
        generation,
        state
    );

CREATE INDEX crash_events_project_received_forward
    ON crash_events (organization_id, project_id, received_at, id);
