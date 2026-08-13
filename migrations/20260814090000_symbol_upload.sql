CREATE TABLE artifact_upload_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    created_by_user_id UUID NOT NULL REFERENCES users(id),
    secret_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(secret_hash) = 32),
    display_suffix TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (id, organization_id, project_id),
    FOREIGN KEY (organization_id, created_by_user_id)
        REFERENCES organization_memberships(organization_id, user_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE INDEX artifact_upload_tokens_active_hash
    ON artifact_upload_tokens (secret_hash)
    WHERE revoked_at IS NULL;

CREATE TABLE releases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    architecture TEXT NOT NULL,
    configuration TEXT NOT NULL,
    revision TEXT,
    channel TEXT,
    build_timestamp TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id, project_id),
    UNIQUE (project_id, version, platform, architecture, configuration),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE TABLE artifact_objects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    object_key TEXT NOT NULL UNIQUE,
    checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    byte_size BIGINT NOT NULL CHECK (byte_size > 0),
    lifecycle_state TEXT NOT NULL DEFAULT 'stored'
        CHECK (lifecycle_state IN ('stored', 'orphaned')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id),
    UNIQUE (organization_id, checksum)
);

CREATE TABLE artifact_debug_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    object_id UUID NOT NULL,
    artifact_type TEXT NOT NULL
        CHECK (artifact_type IN ('pe_executable', 'pe_dynamic_library', 'pdb')),
    module_name TEXT NOT NULL,
    architecture TEXT NOT NULL
        CHECK (architecture IN ('x86', 'x86_64', 'arm64')),
    debug_id TEXT NOT NULL,
    code_id TEXT,
    processing_status TEXT NOT NULL DEFAULT 'available'
        CHECK (processing_status IN ('available', 'quarantined')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id),
    FOREIGN KEY (object_id, organization_id)
        REFERENCES artifact_objects(id, organization_id)
);

CREATE UNIQUE INDEX artifact_debug_images_identity_unique
    ON artifact_debug_images (
        organization_id,
        object_id,
        artifact_type,
        debug_id,
        COALESCE(code_id, '')
    );

CREATE TABLE release_manifest_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    release_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    debug_image_id UUID,
    uploaded_by_user_id UUID NOT NULL REFERENCES users(id),
    upload_token_id UUID NOT NULL,
    checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    byte_size BIGINT NOT NULL CHECK (byte_size > 0),
    artifact_type TEXT NOT NULL
        CHECK (artifact_type IN ('pe_executable', 'pe_dynamic_library', 'pdb')),
    module_name TEXT NOT NULL,
    architecture TEXT NOT NULL
        CHECK (architecture IN ('x86', 'x86_64', 'arm64')),
    debug_id TEXT NOT NULL,
    code_id TEXT,
    ci_job TEXT,
    source_path TEXT NOT NULL,
    cli_version TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'missing'
        CHECK (state IN ('missing', 'available', 'mismatch')),
    uploaded_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id, project_id),
    UNIQUE (release_id, source_path),
    FOREIGN KEY (release_id, organization_id, project_id)
        REFERENCES releases(id, organization_id, project_id),
    FOREIGN KEY (debug_image_id, organization_id)
        REFERENCES artifact_debug_images(id, organization_id),
    FOREIGN KEY (organization_id, uploaded_by_user_id)
        REFERENCES organization_memberships(organization_id, user_id),
    FOREIGN KEY (upload_token_id, organization_id, project_id)
        REFERENCES artifact_upload_tokens(id, organization_id, project_id)
);

CREATE TABLE artifact_upload_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    release_id UUID NOT NULL,
    manifest_artifact_id UUID NOT NULL,
    upload_token_id UUID NOT NULL,
    uploaded_by_user_id UUID NOT NULL REFERENCES users(id),
    object_key TEXT NOT NULL UNIQUE,
    provider_upload_id TEXT NOT NULL,
    checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    byte_size BIGINT NOT NULL CHECK (byte_size > 0),
    part_size INTEGER NOT NULL CHECK (part_size >= 5242880),
    part_count INTEGER NOT NULL CHECK (part_count BETWEEN 1 AND 10000),
    artifact_type TEXT NOT NULL
        CHECK (artifact_type IN ('pe_executable', 'pe_dynamic_library', 'pdb')),
    module_name TEXT NOT NULL,
    architecture TEXT NOT NULL
        CHECK (architecture IN ('x86', 'x86_64', 'arm64')),
    debug_id TEXT NOT NULL,
    code_id TEXT,
    source_path TEXT NOT NULL,
    ci_job TEXT,
    cli_version TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'completing', 'completed', 'failed', 'aborted')),
    failure_code TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id, project_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (release_id, organization_id, project_id)
        REFERENCES releases(id, organization_id, project_id),
    FOREIGN KEY (manifest_artifact_id, organization_id, project_id)
        REFERENCES release_manifest_artifacts(id, organization_id, project_id),
    FOREIGN KEY (organization_id, uploaded_by_user_id)
        REFERENCES organization_memberships(organization_id, user_id),
    FOREIGN KEY (upload_token_id, organization_id, project_id)
        REFERENCES artifact_upload_tokens(id, organization_id, project_id),
    CHECK ((state = 'failed' AND failure_code IS NOT NULL)
        OR (state <> 'failed' AND failure_code IS NULL))
);

CREATE UNIQUE INDEX artifact_upload_sessions_active_artifact
    ON artifact_upload_sessions (
        organization_id,
        project_id,
        manifest_artifact_id
    )
    WHERE state IN ('active', 'completing');

CREATE INDEX artifact_upload_sessions_expiry
    ON artifact_upload_sessions (expires_at)
    WHERE state = 'active';

CREATE TABLE artifact_upload_parts (
    upload_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    part_number INTEGER NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
    etag TEXT NOT NULL,
    content_md5 TEXT NOT NULL,
    byte_size INTEGER NOT NULL CHECK (byte_size > 0),
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (upload_id, part_number),
    FOREIGN KEY (upload_id, organization_id, project_id)
        REFERENCES artifact_upload_sessions(id, organization_id, project_id)
        ON DELETE CASCADE
);
