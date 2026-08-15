CREATE INDEX crash_events_issue_release_representative
    ON crash_events (
        organization_id,
        project_id,
        issue_id,
        release_id,
        grouping_quality DESC,
        received_at,
        id
    )
    WHERE grouping_state = 'grouped'
        AND release_mapping_state = 'matched';
