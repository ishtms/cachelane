CREATE INDEX crash_events_project_state_received
    ON crash_events (
        organization_id,
        project_id,
        processing_state,
        received_at DESC,
        id DESC
    );

CREATE INDEX crash_events_project_release_received
    ON crash_events (
        organization_id,
        project_id,
        release_id,
        received_at DESC,
        id DESC
    )
    WHERE release_id IS NOT NULL;

CREATE INDEX crash_events_project_current_result
    ON crash_events (organization_id, project_id, current_result_id)
    WHERE current_result_id IS NOT NULL;

CREATE INDEX issue_releases_project_release
    ON issue_releases (organization_id, project_id, release_id, issue_id);

CREATE INDEX jobs_project_active_health
    ON jobs (organization_id, project_id, state, available_at, created_at)
    WHERE state IN ('pending', 'leased', 'failed', 'dead');

CREATE TABLE crash_event_search (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    event_id UUID NOT NULL,
    result_id UUID NOT NULL,
    search_text TEXT NOT NULL CHECK (char_length(search_text) <= 65536),
    user_comment TEXT CHECK (char_length(user_comment) <= 8192),
    crash_type TEXT,
    platform TEXT,
    architecture TEXT,
    engine_version TEXT,
    symbolication_state TEXT NOT NULL CHECK (
        symbolication_state IN ('readable', 'partial', 'missing', 'failed', 'processing')
    ),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, project_id, event_id),
    FOREIGN KEY (event_id, organization_id, project_id)
        REFERENCES crash_events(id, organization_id, project_id),
    FOREIGN KEY (result_id, organization_id, project_id, event_id)
        REFERENCES crash_processing_results(id, organization_id, project_id, event_id)
);

INSERT INTO crash_event_search (
    organization_id,
    project_id,
    event_id,
    result_id,
    search_text,
    user_comment,
    crash_type,
    platform,
    architecture,
    engine_version,
    symbolication_state
)
SELECT
    event.organization_id,
    event.project_id,
    event.id,
    result.id,
    left(concat_ws(
        chr(31),
        result.result #>> '{crash_context,error_message}',
        result.result #>> '{crash_context,user_comment}',
        (
            SELECT string_agg(module ->> 'module', chr(31) ORDER BY module_index)
            FROM jsonb_array_elements(CASE
                WHEN jsonb_typeof(result.result #> '{current,symbolication,modules}') = 'array'
                    THEN result.result #> '{current,symbolication,modules}'
                ELSE '[]'::jsonb
            END) WITH ORDINALITY AS modules(module, module_index)
            WHERE module ->> 'module' IS NOT NULL
        ),
        (
            SELECT string_agg(
                frame ->> 'function',
                chr(31) ORDER BY thread_index, frame_index
            )
            FROM jsonb_array_elements(CASE
                WHEN jsonb_typeof(result.result #> '{current,symbolication,threads}') = 'array'
                    THEN result.result #> '{current,symbolication,threads}'
                ELSE '[]'::jsonb
            END) WITH ORDINALITY AS threads(thread, thread_index)
            CROSS JOIN LATERAL jsonb_array_elements(CASE
                WHEN jsonb_typeof(thread -> 'frames') = 'array'
                    THEN thread -> 'frames'
                ELSE '[]'::jsonb
            END) WITH ORDINALITY AS frames(frame, frame_index)
            WHERE frame ->> 'function' IS NOT NULL
        ),
        (
            SELECT string_agg(
                inline ->> 'function',
                chr(31) ORDER BY thread_index, frame_index, inline_index
            )
            FROM jsonb_array_elements(CASE
                WHEN jsonb_typeof(result.result #> '{current,symbolication,threads}') = 'array'
                    THEN result.result #> '{current,symbolication,threads}'
                ELSE '[]'::jsonb
            END) WITH ORDINALITY AS threads(thread, thread_index)
            CROSS JOIN LATERAL jsonb_array_elements(CASE
                WHEN jsonb_typeof(thread -> 'frames') = 'array'
                    THEN thread -> 'frames'
                ELSE '[]'::jsonb
            END) WITH ORDINALITY AS frames(frame, frame_index)
            CROSS JOIN LATERAL jsonb_array_elements(CASE
                WHEN jsonb_typeof(frame -> 'inlines') = 'array'
                    THEN frame -> 'inlines'
                ELSE '[]'::jsonb
            END) WITH ORDINALITY AS inlines(inline, inline_index)
            WHERE inline ->> 'function' IS NOT NULL
        )
    ), 65536),
    left(result.result #>> '{crash_context,user_comment}', 8192),
    result.result #>> '{crash_context,crash_type}',
    result.result #>> '{crash_context,platform,normalized}',
    result.result #>> '{crash_context,architecture}',
    result.result #>> '{crash_context,engine_version}',
    CASE
        WHEN event.processing_state IN ('failed', 'quarantined') THEN 'failed'
        WHEN jsonb_path_exists(
            result.result,
            '$.current.symbolication.threads[*].frames[*] ? (@.symbol_status == "resolved")'
        ) AND jsonb_path_exists(
            result.result,
            '$.current.symbolication.modules[*] ? (@.status == "missing_pe" || @.status == "missing_pdb" || @.status == "mismatched" || @.status == "missing_identity")'
        ) THEN 'partial'
        WHEN jsonb_path_exists(
            result.result,
            '$.current.symbolication.threads[*].frames[*] ? (@.symbol_status == "resolved")'
        ) THEN 'readable'
        WHEN event.processing_state = 'awaiting_symbols' OR jsonb_path_exists(
            result.result,
            '$.current.symbolication.modules[*] ? (@.status == "missing_pe" || @.status == "missing_pdb" || @.status == "mismatched" || @.status == "missing_identity")'
        ) THEN 'missing'
        ELSE 'processing'
    END
FROM crash_events event
JOIN crash_processing_results result
    ON result.id = event.current_result_id
    AND result.organization_id = event.organization_id
    AND result.project_id = event.project_id
    AND result.event_id = event.id;
