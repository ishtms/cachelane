CREATE TABLE alert_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('email', 'discord', 'slack', 'webhook')),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    endpoint_host TEXT CHECK (
        endpoint_host IS NULL OR char_length(endpoint_host) BETWEEN 1 AND 253
    ),
    recipient_user_id UUID REFERENCES users(id),
    encrypted_config BYTEA,
    config_nonce BYTEA,
    config_version INTEGER,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by_user_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id, project_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    CHECK (
        (kind = 'email'
            AND recipient_user_id IS NOT NULL
            AND endpoint_host IS NULL
            AND encrypted_config IS NULL
            AND config_nonce IS NULL
            AND config_version IS NULL)
        OR (kind <> 'email'
            AND recipient_user_id IS NULL
            AND endpoint_host IS NOT NULL
            AND octet_length(encrypted_config) BETWEEN 17 AND 8192
            AND octet_length(config_nonce) = 24
            AND config_version = 1)
    )
);

CREATE INDEX alert_integrations_project
    ON alert_integrations (organization_id, project_id, created_at, id);

CREATE TABLE alert_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    integration_id UUID NOT NULL,
    condition_kind TEXT NOT NULL CHECK (condition_kind IN (
        'first_seen',
        'regression',
        'volume',
        'missing_symbols',
        'processing_failure',
        'ingest_silence',
        'quota'
    )),
    environment TEXT NOT NULL CHECK (
        char_length(environment) BETWEEN 1 AND 32
        AND environment ~ '^[a-z0-9][a-z0-9_-]*$'
    ),
    threshold INTEGER,
    window_seconds INTEGER,
    quiet_start_minute INTEGER,
    quiet_end_minute INTEGER,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by_user_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id, project_id),
    UNIQUE (
        organization_id,
        project_id,
        integration_id,
        condition_kind,
        environment
    ),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id),
    FOREIGN KEY (integration_id, organization_id, project_id)
        REFERENCES alert_integrations(id, organization_id, project_id),
    CHECK (
        (condition_kind = 'volume'
            AND threshold BETWEEN 1 AND 1000000
            AND window_seconds BETWEEN 60 AND 86400)
        OR (condition_kind = 'ingest_silence'
            AND threshold IS NULL
            AND window_seconds BETWEEN 60 AND 604800)
        OR (condition_kind = 'quota'
            AND threshold IN (70, 90, 100, 101)
            AND window_seconds IS NULL)
        OR (condition_kind IN (
                'first_seen',
                'regression',
                'missing_symbols',
                'processing_failure'
            )
            AND threshold IS NULL
            AND window_seconds IS NULL)
    ),
    CHECK (
        (quiet_start_minute IS NULL AND quiet_end_minute IS NULL)
        OR (quiet_start_minute BETWEEN 0 AND 1439
            AND quiet_end_minute BETWEEN 0 AND 1439
            AND quiet_start_minute <> quiet_end_minute)
    )
);

CREATE INDEX alert_rules_project_enabled
    ON alert_rules (organization_id, project_id, enabled, condition_kind);

CREATE TABLE alert_condition_states (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    rule_id UUID NOT NULL,
    scope_key TEXT NOT NULL CHECK (char_length(scope_key) BETWEEN 1 AND 200),
    state TEXT NOT NULL CHECK (state IN ('inactive', 'active')),
    generation BIGINT NOT NULL CHECK (generation > 0),
    payload JSONB NOT NULL CHECK (
        jsonb_typeof(payload) = 'object'
        AND octet_length(payload::text) <= 16384
    ),
    transitioned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, project_id, rule_id, scope_key),
    FOREIGN KEY (rule_id, organization_id, project_id)
        REFERENCES alert_rules(id, organization_id, project_id)
);

CREATE TABLE alert_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    integration_id UUID NOT NULL,
    rule_id UUID NOT NULL,
    scope_key TEXT NOT NULL CHECK (char_length(scope_key) BETWEEN 1 AND 200),
    generation BIGINT NOT NULL CHECK (generation > 0),
    transition TEXT NOT NULL CHECK (transition IN ('triggered', 'recovered')),
    payload JSONB NOT NULL CHECK (
        jsonb_typeof(payload) = 'object'
        AND octet_length(payload::text) <= 16384
    ),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN (
        'pending',
        'leased',
        'delivered',
        'failed',
        'dead',
        'suppressed',
        'unknown'
    )),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 5),
    max_attempt INTEGER NOT NULL DEFAULT 3 CHECK (max_attempt BETWEEN 1 AND 5),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner TEXT,
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    failure_code TEXT CHECK (
        failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'
    ),
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (
        organization_id,
        project_id,
        rule_id,
        scope_key,
        generation,
        transition
    ),
    FOREIGN KEY (integration_id, organization_id, project_id)
        REFERENCES alert_integrations(id, organization_id, project_id),
    FOREIGN KEY (rule_id, organization_id, project_id)
        REFERENCES alert_rules(id, organization_id, project_id),
    CHECK (
        (state = 'leased'
            AND lease_owner IS NOT NULL
            AND lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL)
        OR (state <> 'leased'
            AND lease_owner IS NULL
            AND lease_token IS NULL
            AND lease_expires_at IS NULL)
    ),
    CHECK ((state = 'delivered' AND delivered_at IS NOT NULL) OR state <> 'delivered')
);

CREATE INDEX alert_deliveries_claim
    ON alert_deliveries (available_at, created_at, id)
    WHERE state IN ('pending', 'failed', 'leased');

CREATE INDEX alert_deliveries_project_recent
    ON alert_deliveries (organization_id, project_id, created_at DESC, id DESC);
