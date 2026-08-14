CREATE TABLE project_data_rules (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
    redaction_patterns TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[]
        CHECK (cardinality(redaction_patterns) <= 32),
    indexed_game_data_keys TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[]
        CHECK (cardinality(indexed_game_data_keys) <= 32),
    updated_by_user_id UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, project_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (updated_by_user_id)
        REFERENCES users(id) ON DELETE SET NULL
);

ALTER TABLE crash_processing_results
    ADD COLUMN data_rules_version BIGINT NOT NULL DEFAULT 0
        CHECK (data_rules_version >= 0),
    DROP CONSTRAINT crash_processing_results_event_id_processing_version_checks_key,
    ADD CONSTRAINT crash_processing_results_event_processing_rules_checksum_key
        UNIQUE (event_id, processing_version, data_rules_version, checksum);

ALTER TABLE crash_event_search
    ADD COLUMN data_rules_version BIGINT NOT NULL DEFAULT 0
        CHECK (data_rules_version >= 0);

CREATE TABLE crash_event_context_facets (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    event_id UUID NOT NULL,
    result_id UUID NOT NULL,
    data_rules_version BIGINT NOT NULL CHECK (data_rules_version >= 0),
    key TEXT NOT NULL CHECK (char_length(key) BETWEEN 1 AND 128),
    value TEXT NOT NULL CHECK (char_length(value) BETWEEN 1 AND 512),
    value_truncated BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (organization_id, project_id, event_id, key, value),
    FOREIGN KEY (event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    FOREIGN KEY (result_id, organization_id, project_id, event_id)
        REFERENCES crash_processing_results(id, organization_id, project_id, event_id)
);

CREATE INDEX crash_event_context_facets_lookup
    ON crash_event_context_facets (
        organization_id,
        project_id,
        key,
        value,
        event_id
    );

ALTER TABLE crash_reprocessing_requests
    DROP CONSTRAINT crash_reprocessing_requests_scope_kind_check,
    DROP CONSTRAINT crash_reprocessing_requests_check,
    ADD CONSTRAINT crash_reprocessing_requests_scope_kind_check CHECK (
        scope_kind IN (
            'artifact',
            'event',
            'issue',
            'release',
            'project',
            'parser_version',
            'symbolicator_version',
            'fingerprint_version',
            'data_rules_version'
        )
    ),
    ADD CONSTRAINT crash_reprocessing_requests_source_scope_check CHECK (
        (source = 'automatic'
            AND scope_kind IN ('artifact', 'data_rules_version')
            AND scope_value IS NOT NULL
            AND requested_by_user_id IS NULL
            AND request_limit IS NULL
            AND input_cursor_event_id IS NULL)
        OR (source = 'manual'
            AND scope_kind NOT IN ('artifact', 'data_rules_version')
            AND requested_by_user_id IS NOT NULL
            AND request_limit IS NOT NULL)
    );
