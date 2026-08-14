ALTER TABLE crash_events
    ADD COLUMN release_id UUID,
    ADD COLUMN release_mapping_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (release_mapping_state IN ('pending', 'matched', 'missing', 'ambiguous')),
    ADD COLUMN grouping_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (grouping_state IN ('pending', 'disabled', 'insufficient', 'grouped')),
    ADD COLUMN fingerprint_algorithm TEXT,
    ADD COLUMN fingerprint_version INTEGER,
    ADD COLUMN fingerprint TEXT,
    ADD COLUMN variant_fingerprint TEXT,
    ADD COLUMN grouping_quality INTEGER,
    ADD COLUMN grouped_at TIMESTAMPTZ,
    ADD CONSTRAINT crash_events_release_fk
        FOREIGN KEY (release_id, organization_id, project_id)
        REFERENCES releases(id, organization_id, project_id),
    ADD CONSTRAINT crash_events_fingerprint_identity_check CHECK (
        (fingerprint_algorithm IS NULL AND fingerprint_version IS NULL)
        OR (fingerprint_algorithm ~ '^[a-z][a-z0-9_]{0,31}$'
            AND fingerprint_version > 0)
    ),
    ADD CONSTRAINT crash_events_fingerprint_check CHECK (
        fingerprint IS NULL OR fingerprint ~ '^[a-f0-9]{64}$'
    ),
    ADD CONSTRAINT crash_events_variant_fingerprint_check CHECK (
        variant_fingerprint IS NULL OR variant_fingerprint ~ '^[a-f0-9]{64}$'
    ),
    ADD CONSTRAINT crash_events_grouping_assignment_check CHECK (
        (grouping_state = 'grouped'
            AND fingerprint_algorithm IS NOT NULL
            AND fingerprint_version IS NOT NULL
            AND fingerprint IS NOT NULL
            AND variant_fingerprint IS NOT NULL
            AND grouping_quality IS NOT NULL
            AND grouping_quality >= 0
            AND grouped_at IS NOT NULL)
        OR (grouping_state <> 'grouped'
            AND fingerprint IS NULL
            AND variant_fingerprint IS NULL
            AND grouping_quality IS NULL
            AND grouped_at IS NULL)
    ),
    ADD CONSTRAINT crash_events_release_mapping_check CHECK (
        (release_mapping_state = 'matched' AND release_id IS NOT NULL)
        OR (release_mapping_state <> 'matched' AND release_id IS NULL)
    );

CREATE TABLE crash_event_release_candidates (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    event_id UUID NOT NULL,
    release_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, project_id, event_id, release_id),
    FOREIGN KEY (event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    FOREIGN KEY (release_id, organization_id, project_id)
        REFERENCES releases(id, organization_id, project_id)
);

CREATE TABLE issues (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    fingerprint_algorithm TEXT NOT NULL
        CHECK (fingerprint_algorithm ~ '^[a-z][a-z0-9_]{0,31}$'),
    fingerprint_version INTEGER NOT NULL CHECK (fingerprint_version > 0),
    fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
    title TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    regression_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK (regression_state IN ('new', 'ongoing', 'resolved', 'regressed', 'unknown')),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    event_count BIGINT NOT NULL CHECK (event_count > 0),
    representative_event_id UUID,
    first_release_id UUID,
    last_release_id UUID,
    resolved_in_release_id UUID,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id, project_id),
    UNIQUE (
        organization_id,
        project_id,
        fingerprint_algorithm,
        fingerprint_version,
        fingerprint
    ),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (representative_event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    FOREIGN KEY (first_release_id, organization_id, project_id)
        REFERENCES releases(id, organization_id, project_id),
    FOREIGN KEY (last_release_id, organization_id, project_id)
        REFERENCES releases(id, organization_id, project_id),
    FOREIGN KEY (resolved_in_release_id, organization_id, project_id)
        REFERENCES releases(id, organization_id, project_id),
    CHECK (first_seen_at <= last_seen_at),
    CHECK ((status = 'resolved'
            AND resolved_in_release_id IS NOT NULL
            AND resolved_at IS NOT NULL)
        OR status = 'open'),
    CHECK ((regression_state = 'resolved' AND status = 'resolved')
        OR regression_state <> 'resolved'),
    CHECK ((regression_state = 'regressed'
            AND status = 'open'
            AND resolved_in_release_id IS NOT NULL
            AND resolved_at IS NOT NULL)
        OR regression_state <> 'regressed'),
    CHECK ((resolved_in_release_id IS NULL AND resolved_at IS NULL)
        OR (resolved_in_release_id IS NOT NULL AND resolved_at IS NOT NULL))
);

CREATE TABLE issue_variants (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    issue_id UUID NOT NULL,
    variant_fingerprint TEXT NOT NULL
        CHECK (variant_fingerprint ~ '^[a-f0-9]{64}$'),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    event_count BIGINT NOT NULL CHECK (event_count > 0),
    representative_event_id UUID NOT NULL,
    PRIMARY KEY (
        organization_id,
        project_id,
        issue_id,
        variant_fingerprint
    ),
    FOREIGN KEY (issue_id, organization_id, project_id)
        REFERENCES issues(id, organization_id, project_id),
    FOREIGN KEY (representative_event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    CHECK (first_seen_at <= last_seen_at)
);

CREATE TABLE issue_releases (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    issue_id UUID NOT NULL,
    release_id UUID NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    event_count BIGINT NOT NULL CHECK (event_count > 0),
    representative_event_id UUID NOT NULL,
    PRIMARY KEY (organization_id, project_id, issue_id, release_id),
    FOREIGN KEY (issue_id, organization_id, project_id)
        REFERENCES issues(id, organization_id, project_id),
    FOREIGN KEY (release_id, organization_id, project_id)
        REFERENCES releases(id, organization_id, project_id),
    FOREIGN KEY (representative_event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    CHECK (first_seen_at <= last_seen_at)
);

ALTER TABLE crash_events
    ADD COLUMN issue_id UUID,
    ADD CONSTRAINT crash_events_issue_fk
        FOREIGN KEY (issue_id, organization_id, project_id)
        REFERENCES issues(id, organization_id, project_id),
    ADD CONSTRAINT crash_events_issue_assignment_check CHECK (
        (grouping_state = 'grouped' AND issue_id IS NOT NULL)
        OR (grouping_state <> 'grouped' AND issue_id IS NULL)
    );

CREATE INDEX crash_event_release_candidates_event
    ON crash_event_release_candidates (organization_id, project_id, event_id, release_id);

CREATE INDEX crash_events_issue_received
    ON crash_events (organization_id, project_id, issue_id, received_at, id)
    WHERE issue_id IS NOT NULL;

CREATE INDEX issues_project_last_seen
    ON issues (organization_id, project_id, last_seen_at DESC, id DESC);

CREATE INDEX issues_project_state
    ON issues (organization_id, project_id, status, regression_state, last_seen_at DESC, id DESC);

CREATE INDEX issue_variants_issue_count
    ON issue_variants (
        organization_id,
        project_id,
        issue_id,
        event_count DESC,
        variant_fingerprint
    );

CREATE INDEX issue_releases_issue
    ON issue_releases (organization_id, project_id, issue_id, release_id);
