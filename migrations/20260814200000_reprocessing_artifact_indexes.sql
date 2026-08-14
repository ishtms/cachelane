CREATE INDEX release_manifest_artifacts_available_pdb_identity
    ON release_manifest_artifacts (
        organization_id,
        project_id,
        release_id,
        architecture,
        debug_id,
        id
    )
    WHERE state = 'available' AND artifact_type = 'pdb';

CREATE INDEX release_manifest_artifacts_available_pe_identity
    ON release_manifest_artifacts (
        organization_id,
        project_id,
        release_id,
        lower(module_name),
        architecture,
        debug_id,
        code_id,
        id
    )
    WHERE state = 'available'
        AND artifact_type IN ('pe_executable', 'pe_dynamic_library');
