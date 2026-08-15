CREATE TABLE project_daily_rollups (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    day DATE NOT NULL,
    dimension TEXT NOT NULL CHECK (dimension IN (
        'event_total',
        'release',
        'platform_architecture',
        'crash_type',
        'symbolication_state',
        'processing_state',
        'issue_total',
        'issue_new',
        'issue_regressed'
    )),
    key TEXT NOT NULL CHECK (char_length(key) BETWEEN 1 AND 512),
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 512),
    count BIGINT NOT NULL CHECK (count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, project_id, day, dimension, key),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

CREATE INDEX project_daily_rollups_dimension_days
    ON project_daily_rollups (organization_id, project_id, dimension, day)
    INCLUDE (key, label, count);

CREATE FUNCTION apply_project_daily_rollup_delta(
    rollup_organization_id UUID,
    rollup_project_id UUID,
    rollup_day DATE,
    rollup_dimension TEXT,
    rollup_key TEXT,
    rollup_label TEXT,
    rollup_delta BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF rollup_delta > 0 THEN
        INSERT INTO project_daily_rollups (
            organization_id,
            project_id,
            day,
            dimension,
            key,
            label,
            count
        )
        VALUES (
            rollup_organization_id,
            rollup_project_id,
            rollup_day,
            rollup_dimension,
            left(rollup_key, 512),
            left(rollup_label, 512),
            rollup_delta
        )
        ON CONFLICT (organization_id, project_id, day, dimension, key)
        DO UPDATE SET
            label = EXCLUDED.label,
            count = project_daily_rollups.count + EXCLUDED.count,
            updated_at = now();
    ELSIF rollup_delta < 0 THEN
        UPDATE project_daily_rollups
        SET count = count + rollup_delta,
            updated_at = now()
        WHERE organization_id = rollup_organization_id
          AND project_id = rollup_project_id
          AND day = rollup_day
          AND dimension = rollup_dimension
          AND key = left(rollup_key, 512)
          AND count + rollup_delta >= 0;

        DELETE FROM project_daily_rollups
        WHERE organization_id = rollup_organization_id
          AND project_id = rollup_project_id
          AND day = rollup_day
          AND dimension = rollup_dimension
          AND key = left(rollup_key, 512)
          AND count = 0;
    END IF;
END;
$$;

CREATE FUNCTION insert_crash_event_rollups()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM apply_project_daily_rollup_delta(
        rollup.organization_id,
        rollup.project_id,
        rollup.day,
        rollup.dimension,
        rollup.key,
        rollup.label,
        rollup.delta
    )
    FROM (
        SELECT
            event.organization_id,
            event.project_id,
            (event.received_at AT TIME ZONE 'UTC')::date AS day,
            dimensions.dimension,
            dimensions.key,
            dimensions.label,
            count(*)::bigint AS delta
        FROM inserted_events event
        LEFT JOIN crash_event_search search
          ON search.organization_id = event.organization_id
         AND search.project_id = event.project_id
         AND search.event_id = event.id
         AND search.result_id = event.current_result_id
        LEFT JOIN releases release
          ON release.organization_id = event.organization_id
         AND release.project_id = event.project_id
         AND release.id = event.release_id
        CROSS JOIN LATERAL (
            VALUES
                ('event_total'::text, 'all'::text, 'Events'::text),
                ('release', COALESCE(release.id::text, 'unmapped'), COALESCE(release.version, 'Unmapped')),
                ('platform_architecture', COALESCE(search.platform, 'unknown') || '/' || COALESCE(search.architecture, 'unknown'), initcap(COALESCE(search.platform, 'unknown')) || ' / ' || COALESCE(search.architecture, 'unknown')),
                ('crash_type', COALESCE(search.crash_type, 'unknown'), initcap(COALESCE(search.crash_type, 'unknown'))),
                ('symbolication_state', CASE WHEN event.processing_state IN ('failed', 'quarantined') THEN 'failed' WHEN search.symbolication_state IS NOT NULL THEN search.symbolication_state WHEN event.processing_state = 'awaiting_symbols' THEN 'missing' ELSE 'processing' END, initcap(CASE WHEN event.processing_state IN ('failed', 'quarantined') THEN 'failed' WHEN search.symbolication_state IS NOT NULL THEN search.symbolication_state WHEN event.processing_state = 'awaiting_symbols' THEN 'missing' ELSE 'processing' END)),
                ('processing_state', event.processing_state, initcap(replace(event.processing_state, '_', ' ')))
        ) AS dimensions(dimension, key, label)
        GROUP BY
            event.organization_id,
            event.project_id,
            (event.received_at AT TIME ZONE 'UTC')::date,
            dimensions.dimension,
            dimensions.key,
            dimensions.label
    ) rollup;
    RETURN NULL;
END;
$$;

CREATE TRIGGER crash_events_insert_daily_rollups
AFTER INSERT ON crash_events
REFERENCING NEW TABLE AS inserted_events
FOR EACH STATEMENT
EXECUTE FUNCTION insert_crash_event_rollups();

CREATE FUNCTION update_crash_event_rollups()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    old_day DATE;
    new_day DATE;
    old_release_key TEXT;
    old_release_label TEXT;
    new_release_key TEXT;
    new_release_label TEXT;
    old_platform TEXT;
    old_architecture TEXT;
    old_crash_type TEXT;
    old_search_symbolication TEXT;
    new_platform TEXT;
    new_architecture TEXT;
    new_crash_type TEXT;
    new_search_symbolication TEXT;
    old_symbolication TEXT;
    new_symbolication TEXT;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        old_day := (OLD.received_at AT TIME ZONE 'UTC')::date;
        old_release_key := COALESCE(OLD.release_id::text, 'unmapped');
        SELECT COALESCE(version, 'Unmapped')
        INTO old_release_label
        FROM releases
        WHERE id = OLD.release_id
          AND organization_id = OLD.organization_id
          AND project_id = OLD.project_id;
        old_release_label := COALESCE(old_release_label, 'Unmapped');
        SELECT platform, architecture, crash_type, symbolication_state
        INTO old_platform, old_architecture, old_crash_type, old_search_symbolication
        FROM crash_event_search
        WHERE organization_id = OLD.organization_id
          AND project_id = OLD.project_id
          AND event_id = OLD.id
          AND result_id = OLD.current_result_id;
        old_symbolication := CASE
            WHEN OLD.processing_state IN ('failed', 'quarantined') THEN 'failed'
            WHEN old_search_symbolication IS NOT NULL THEN old_search_symbolication
            WHEN OLD.processing_state = 'awaiting_symbols' THEN 'missing'
            ELSE 'processing'
        END;
    END IF;

    IF TG_OP <> 'DELETE' THEN
        new_day := (NEW.received_at AT TIME ZONE 'UTC')::date;
        new_release_key := COALESCE(NEW.release_id::text, 'unmapped');
        SELECT COALESCE(version, 'Unmapped')
        INTO new_release_label
        FROM releases
        WHERE id = NEW.release_id
          AND organization_id = NEW.organization_id
          AND project_id = NEW.project_id;
        new_release_label := COALESCE(new_release_label, 'Unmapped');
        SELECT platform, architecture, crash_type, symbolication_state
        INTO new_platform, new_architecture, new_crash_type, new_search_symbolication
        FROM crash_event_search
        WHERE organization_id = NEW.organization_id
          AND project_id = NEW.project_id
          AND event_id = NEW.id
          AND result_id = NEW.current_result_id;
        new_symbolication := CASE
            WHEN NEW.processing_state IN ('failed', 'quarantined') THEN 'failed'
            WHEN new_search_symbolication IS NOT NULL THEN new_search_symbolication
            WHEN NEW.processing_state = 'awaiting_symbols' THEN 'missing'
            ELSE 'processing'
        END;
    END IF;

    IF TG_OP = 'INSERT' THEN
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'event_total', 'all', 'Events', 1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'release', new_release_key, new_release_label, 1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'platform_architecture', COALESCE(new_platform, 'unknown') || '/' || COALESCE(new_architecture, 'unknown'), initcap(COALESCE(new_platform, 'unknown')) || ' / ' || COALESCE(new_architecture, 'unknown'), 1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'crash_type', COALESCE(new_crash_type, 'unknown'), initcap(COALESCE(new_crash_type, 'unknown')), 1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'symbolication_state', new_symbolication, initcap(new_symbolication), 1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'processing_state', NEW.processing_state, initcap(replace(NEW.processing_state, '_', ' ')), 1);
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'event_total', 'all', 'Events', -1);
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'release', old_release_key, old_release_label, -1);
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'platform_architecture', COALESCE(old_platform, 'unknown') || '/' || COALESCE(old_architecture, 'unknown'), initcap(COALESCE(old_platform, 'unknown')) || ' / ' || COALESCE(old_architecture, 'unknown'), -1);
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'crash_type', COALESCE(old_crash_type, 'unknown'), initcap(COALESCE(old_crash_type, 'unknown')), -1);
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'symbolication_state', old_symbolication, initcap(old_symbolication), -1);
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'processing_state', OLD.processing_state, initcap(replace(OLD.processing_state, '_', ' ')), -1);
        RETURN OLD;
    END IF;

    IF old_day IS DISTINCT FROM new_day THEN
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'event_total', 'all', 'Events', -1);
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'release', old_release_key, old_release_label, -1);
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'platform_architecture', COALESCE(old_platform, 'unknown') || '/' || COALESCE(old_architecture, 'unknown'), initcap(COALESCE(old_platform, 'unknown')) || ' / ' || COALESCE(old_architecture, 'unknown'), -1);
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'crash_type', COALESCE(old_crash_type, 'unknown'), initcap(COALESCE(old_crash_type, 'unknown')), -1);
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'symbolication_state', old_symbolication, initcap(old_symbolication), -1);
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'processing_state', OLD.processing_state, initcap(replace(OLD.processing_state, '_', ' ')), -1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'event_total', 'all', 'Events', 1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'release', new_release_key, new_release_label, 1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'platform_architecture', COALESCE(new_platform, 'unknown') || '/' || COALESCE(new_architecture, 'unknown'), initcap(COALESCE(new_platform, 'unknown')) || ' / ' || COALESCE(new_architecture, 'unknown'), 1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'crash_type', COALESCE(new_crash_type, 'unknown'), initcap(COALESCE(new_crash_type, 'unknown')), 1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'symbolication_state', new_symbolication, initcap(new_symbolication), 1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'processing_state', NEW.processing_state, initcap(replace(NEW.processing_state, '_', ' ')), 1);
        RETURN NEW;
    END IF;

    IF old_release_key IS DISTINCT FROM new_release_key THEN
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'release', old_release_key, old_release_label, -1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'release', new_release_key, new_release_label, 1);
    END IF;

    IF OLD.processing_state IS DISTINCT FROM NEW.processing_state THEN
        PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'processing_state', OLD.processing_state, initcap(replace(OLD.processing_state, '_', ' ')), -1);
        PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'processing_state', NEW.processing_state, initcap(replace(NEW.processing_state, '_', ' ')), 1);
    END IF;

    IF OLD.processing_state IS DISTINCT FROM NEW.processing_state THEN
        old_symbolication := CASE
            WHEN OLD.processing_state IN ('failed', 'quarantined') THEN 'failed'
            WHEN COALESCE(new_search_symbolication, old_search_symbolication) IS NOT NULL THEN COALESCE(new_search_symbolication, old_search_symbolication)
            WHEN OLD.processing_state = 'awaiting_symbols' THEN 'missing'
            ELSE 'processing'
        END;
        new_symbolication := CASE
            WHEN NEW.processing_state IN ('failed', 'quarantined') THEN 'failed'
            WHEN COALESCE(new_search_symbolication, old_search_symbolication) IS NOT NULL THEN COALESCE(new_search_symbolication, old_search_symbolication)
            WHEN NEW.processing_state = 'awaiting_symbols' THEN 'missing'
            ELSE 'processing'
        END;
        IF old_symbolication IS DISTINCT FROM new_symbolication THEN
            PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_day, 'symbolication_state', old_symbolication, initcap(old_symbolication), -1);
            PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_day, 'symbolication_state', new_symbolication, initcap(new_symbolication), 1);
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER crash_events_update_daily_rollups
AFTER UPDATE OF received_at, release_id, processing_state, current_result_id OR DELETE
ON crash_events
FOR EACH ROW
EXECUTE FUNCTION update_crash_event_rollups();

ALTER TABLE issues
    ADD COLUMN search_vector TSVECTOR;

ALTER TABLE crash_event_search
    ADD COLUMN search_vector TSVECTOR;

CREATE INDEX issues_search_vector_gin
    ON issues USING GIN (search_vector);

CREATE INDEX crash_event_search_vector_gin
    ON crash_event_search USING GIN (search_vector);

CREATE INDEX issues_search_vector_backfill
    ON issues (organization_id, project_id, id)
    WHERE search_vector IS NULL;

CREATE INDEX crash_event_search_vector_backfill
    ON crash_event_search (organization_id, project_id, event_id)
    WHERE search_vector IS NULL;

CREATE INDEX issues_project_open_count
    ON issues (organization_id, project_id, status, event_count DESC, last_seen_at DESC, id DESC);

CREATE FUNCTION update_issue_search_vector()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.search_vector := to_tsvector('simple', NEW.title);
    RETURN NEW;
END;
$$;

CREATE TRIGGER issues_update_search_vector
BEFORE INSERT OR UPDATE OF title
ON issues
FOR EACH ROW
EXECUTE FUNCTION update_issue_search_vector();

CREATE FUNCTION update_crash_event_search_vector()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.search_vector := to_tsvector('simple', NEW.search_text);
    RETURN NEW;
END;
$$;

CREATE TRIGGER crash_event_search_update_search_vector
BEFORE INSERT OR UPDATE OF search_text
ON crash_event_search
FOR EACH ROW
EXECUTE FUNCTION update_crash_event_search_vector();

CREATE FUNCTION update_crash_search_rollups()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    event_day DATE;
    event_state TEXT;
    current_result UUID;
    old_platform TEXT;
    old_architecture TEXT;
    old_crash_type TEXT;
    old_symbolication TEXT;
    new_platform TEXT;
    new_architecture TEXT;
    new_crash_type TEXT;
    new_symbolication TEXT;
BEGIN
    SELECT
        (received_at AT TIME ZONE 'UTC')::date,
        processing_state,
        current_result_id
    INTO event_day, event_state, current_result
    FROM crash_events
    WHERE organization_id = COALESCE(NEW.organization_id, OLD.organization_id)
      AND project_id = COALESCE(NEW.project_id, OLD.project_id)
      AND id = COALESCE(NEW.event_id, OLD.event_id);

    IF NOT FOUND THEN
        RETURN COALESCE(NEW, OLD);
    END IF;

    IF TG_OP = 'INSERT' AND current_result IS NOT NULL AND current_result <> NEW.result_id THEN
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE'
        AND current_result IS NOT NULL
        AND current_result <> OLD.result_id
        AND current_result <> NEW.result_id THEN
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' AND current_result IS NOT NULL AND current_result <> OLD.result_id THEN
        RETURN OLD;
    END IF;

    old_platform := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.platform END;
    old_architecture := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.architecture END;
    old_crash_type := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.crash_type END;
    old_symbolication := CASE
        WHEN event_state IN ('failed', 'quarantined') THEN 'failed'
        WHEN TG_OP <> 'INSERT' AND OLD.symbolication_state IS NOT NULL THEN OLD.symbolication_state
        WHEN event_state = 'awaiting_symbols' THEN 'missing'
        ELSE 'processing'
    END;
    new_platform := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE NEW.platform END;
    new_architecture := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE NEW.architecture END;
    new_crash_type := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE NEW.crash_type END;
    new_symbolication := CASE
        WHEN event_state IN ('failed', 'quarantined') THEN 'failed'
        WHEN TG_OP <> 'DELETE' AND NEW.symbolication_state IS NOT NULL THEN NEW.symbolication_state
        WHEN event_state = 'awaiting_symbols' THEN 'missing'
        ELSE 'processing'
    END;

    IF COALESCE(old_platform, 'unknown') IS DISTINCT FROM COALESCE(new_platform, 'unknown')
        OR COALESCE(old_architecture, 'unknown') IS DISTINCT FROM COALESCE(new_architecture, 'unknown') THEN
        PERFORM apply_project_daily_rollup_delta(COALESCE(NEW.organization_id, OLD.organization_id), COALESCE(NEW.project_id, OLD.project_id), event_day, 'platform_architecture', COALESCE(old_platform, 'unknown') || '/' || COALESCE(old_architecture, 'unknown'), initcap(COALESCE(old_platform, 'unknown')) || ' / ' || COALESCE(old_architecture, 'unknown'), -1);
        PERFORM apply_project_daily_rollup_delta(COALESCE(NEW.organization_id, OLD.organization_id), COALESCE(NEW.project_id, OLD.project_id), event_day, 'platform_architecture', COALESCE(new_platform, 'unknown') || '/' || COALESCE(new_architecture, 'unknown'), initcap(COALESCE(new_platform, 'unknown')) || ' / ' || COALESCE(new_architecture, 'unknown'), 1);
    END IF;

    IF COALESCE(old_crash_type, 'unknown') IS DISTINCT FROM COALESCE(new_crash_type, 'unknown') THEN
        PERFORM apply_project_daily_rollup_delta(COALESCE(NEW.organization_id, OLD.organization_id), COALESCE(NEW.project_id, OLD.project_id), event_day, 'crash_type', COALESCE(old_crash_type, 'unknown'), initcap(COALESCE(old_crash_type, 'unknown')), -1);
        PERFORM apply_project_daily_rollup_delta(COALESCE(NEW.organization_id, OLD.organization_id), COALESCE(NEW.project_id, OLD.project_id), event_day, 'crash_type', COALESCE(new_crash_type, 'unknown'), initcap(COALESCE(new_crash_type, 'unknown')), 1);
    END IF;

    IF old_symbolication IS DISTINCT FROM new_symbolication THEN
        PERFORM apply_project_daily_rollup_delta(COALESCE(NEW.organization_id, OLD.organization_id), COALESCE(NEW.project_id, OLD.project_id), event_day, 'symbolication_state', old_symbolication, initcap(old_symbolication), -1);
        PERFORM apply_project_daily_rollup_delta(COALESCE(NEW.organization_id, OLD.organization_id), COALESCE(NEW.project_id, OLD.project_id), event_day, 'symbolication_state', new_symbolication, initcap(new_symbolication), 1);
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER crash_event_search_update_daily_rollups
AFTER INSERT OR UPDATE OF result_id, crash_type, platform, architecture, symbolication_state OR DELETE
ON crash_event_search
FOR EACH ROW
EXECUTE FUNCTION update_crash_search_rollups();

CREATE FUNCTION update_issue_rollups()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    old_first_day DATE;
    old_regressed_day DATE;
    new_first_day DATE;
    new_regressed_day DATE;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        old_first_day := (OLD.first_seen_at AT TIME ZONE 'UTC')::date;
        IF OLD.regression_state = 'regressed' THEN
            old_regressed_day := (OLD.last_seen_at AT TIME ZONE 'UTC')::date;
        END IF;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_first_day := (NEW.first_seen_at AT TIME ZONE 'UTC')::date;
        IF NEW.regression_state = 'regressed' THEN
            new_regressed_day := (NEW.last_seen_at AT TIME ZONE 'UTC')::date;
        END IF;
    END IF;

    IF TG_OP = 'INSERT' OR old_first_day IS DISTINCT FROM new_first_day THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_first_day, 'issue_total', 'all', 'Issues', -1);
            PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_first_day, 'issue_new', 'all', 'New issues', -1);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_first_day, 'issue_total', 'all', 'Issues', 1);
            PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_first_day, 'issue_new', 'all', 'New issues', 1);
        END IF;
    END IF;

    IF old_regressed_day IS DISTINCT FROM new_regressed_day THEN
        IF old_regressed_day IS NOT NULL THEN
            PERFORM apply_project_daily_rollup_delta(OLD.organization_id, OLD.project_id, old_regressed_day, 'issue_regressed', 'all', 'Regressed issues', -1);
        END IF;
        IF new_regressed_day IS NOT NULL THEN
            PERFORM apply_project_daily_rollup_delta(NEW.organization_id, NEW.project_id, new_regressed_day, 'issue_regressed', 'all', 'Regressed issues', 1);
        END IF;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER issues_update_daily_rollups
AFTER INSERT OR UPDATE OF first_seen_at, last_seen_at, regression_state OR DELETE
ON issues
FOR EACH ROW
EXECUTE FUNCTION update_issue_rollups();
