CREATE TABLE project_storage_counters (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    retained_raw_bytes BIGINT NOT NULL DEFAULT 0
        CHECK (retained_raw_bytes >= 0),
    retained_symbol_bytes BIGINT NOT NULL DEFAULT 0
        CHECK (retained_symbol_bytes >= 0),
    reconciled_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, project_id),
    FOREIGN KEY (project_id, organization_id)
        REFERENCES projects(id, organization_id)
);

INSERT INTO project_storage_counters (organization_id, project_id)
SELECT organization_id, id
FROM projects;

CREATE FUNCTION initialize_project_storage_counter()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO project_storage_counters (
        organization_id,
        project_id,
        reconciled_at
    )
    VALUES (NEW.organization_id, NEW.id, now());

    RETURN NEW;
END;
$$;

CREATE TRIGGER projects_initialize_storage_counter
AFTER INSERT ON projects
FOR EACH ROW
EXECUTE FUNCTION initialize_project_storage_counter();

ALTER TABLE crash_event_objects
    ADD COLUMN raw_delete_after TIMESTAMPTZ;

CREATE INDEX crash_event_objects_raw_due
    ON crash_event_objects (raw_delete_after, id)
    INCLUDE (organization_id, project_id)
    WHERE lifecycle_state = 'stored'
      AND raw_delete_after IS NOT NULL;
