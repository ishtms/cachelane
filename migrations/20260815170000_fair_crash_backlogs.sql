CREATE INDEX jobs_pending_priority_order
    ON jobs (priority, available_at, created_at, id)
    INCLUDE (
        organization_id,
        project_id,
        attempt,
        max_attempt,
        resource_failures
    )
    WHERE state = 'pending';

CREATE INDEX jobs_active_project_leases
    ON jobs (organization_id, project_id, lease_expires_at)
    WHERE state = 'leased';
