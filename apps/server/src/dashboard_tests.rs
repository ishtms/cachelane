use std::{env, error::Error, sync::Arc, time::Duration};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::Engine as _;
use object_store::{
    ClientOptions, ObjectStoreExt, PutPayload, RetryConfig, aws::AmazonS3Builder, memory::InMemory,
    path::Path as ObjectPath,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use time::OffsetDateTime;
use tower::ServiceExt;

use super::{
    CursorPayload, DashboardError, classification_view, decode_cursor, encode_cursor, frame_view,
    powershell_literal, property_views, remediation_command, symbolication_success_percent,
    thread_views, truncate_text,
};
use crate::project_setup::{DATABASE_TEST_LOCK, ServerState, migrate, router};

const SECRET: &str = "dashboard-secret-with-at-least-32-bytes";

#[test]
#[allow(clippy::too_many_lines)]
fn cursors_text_bounds_and_commands_are_safe() -> Result<(), Box<dyn Error>> {
    let cursor = CursorPayload {
        version: 1,
        kind: "issue_events:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
        project_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
        filter_hash: "c".repeat(64),
        sort_at: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?,
        id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_owned(),
    };
    let encoded = encode_cursor(&cursor).map_err(|_| "cursor must encode")?;
    assert!(
        decode_cursor(
            &encoded,
            "issue_events:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            &"c".repeat(64),
        )
        .is_ok()
    );
    assert!(matches!(
        decode_cursor(
            &encoded,
            "issue_events:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            &"c".repeat(64),
        ),
        Err(DashboardError::InvalidRequest)
    ));
    assert!(matches!(
        decode_cursor("not+base64", "kind", "project", "filter"),
        Err(DashboardError::InvalidRequest)
    ));

    let (bounded, truncated) = truncate_text("ab🙂cd", 5);
    assert_eq!(bounded, "ab");
    assert!(truncated);
    assert_eq!(
        powershell_literal("a'b;$env:PATH\n雪"),
        "'a''b;$env:PATH\n雪'"
    );
    assert_eq!(
        remediation_command("project's", "1.0;$env:X", Some("x86_64"), Some("Shipping")),
        "faultlane symbols upload '<build-directory>' --project 'project''s' --release '1.0;$env:X' --architecture 'x86_64' --configuration 'Shipping'"
    );
    assert_eq!(symbolication_success_percent(0, 0, 0), None);
    assert_eq!(symbolication_success_percent(1, 0, 0), Some(100.0));
    assert_eq!(symbolication_success_percent(1, 1, 1), Some(66.67));

    let classification = json!({
        "crash_type": "c".repeat(129),
        "confidence": "high",
        "evidence": (0..33).map(|_| "e".repeat(129)).collect::<Vec<_>>(),
        "signals": [{
            "kind": "k".repeat(129),
            "confidence": "high",
            "evidence": (0..33).map(|_| "signal").collect::<Vec<_>>()
        }]
    });
    let classification = classification_view(Some(&classification)).ok_or("classification")?;
    assert!(classification.truncated);
    assert!(classification.signals[0].truncated);
    assert_eq!(classification.evidence.len(), 32);

    let properties = json!([{"name": "n".repeat(300), "value": "v".repeat(5000)}]);
    let (properties, properties_truncated) =
        property_views(Some(&properties)).map_err(|_| "properties")?;
    assert!(!properties_truncated);
    assert!(properties[0].name_truncated);
    assert!(properties[0].value_truncated);

    let frame = json!({
        "instruction": "0x1",
        "module": "m".repeat(5000),
        "module_relative": "0x1",
        "trust": "context",
        "symbol_status": "resolved",
        "function": "f".repeat(5000),
        "source_file": null,
        "source_line": null,
        "inlines": [{"function": "i".repeat(5000), "source_file": null, "source_line": null}]
    });
    let frame = frame_view(&frame).map_err(|_| "frame")?;
    assert!(frame.truncated);
    assert!(frame.inlines[0].truncated);

    let threads = json!([{
        "thread_id": 1,
        "faulting": true,
        "name": "t".repeat(5000),
        "unwind_status": "u".repeat(129),
        "frames_truncated": false,
        "frames": [{
            "instruction": "0x1",
            "module": null,
            "module_relative": null,
            "trust": "context",
            "symbol_status": "unresolved",
            "function": null,
            "source_file": null,
            "source_line": null,
            "inlines": []
        }]
    }]);
    let (threads, threads_truncated) = thread_views(Some(&threads)).map_err(|_| "threads")?;
    assert!(!threads_truncated);
    assert!(threads[0].name_truncated);
    assert!(threads[0].unwind_status_truncated);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn dashboard_routes_are_bounded_scoped_and_stream_exact_artifacts()
-> Result<(), Box<dyn Error>> {
    let Ok(database_url) = env::var("FAULTLANE_TEST_DATABASE_URL") else {
        return Ok(());
    };
    let _guard = DATABASE_TEST_LOCK.lock().await;
    assert_isolated_database(&database_url);
    migrate(&database_url).await?;
    migrate(&database_url).await?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await?;
    sqlx::query("TRUNCATE users, organizations CASCADE")
        .execute(&pool)
        .await?;

    let objects = Arc::new(InMemory::new());
    let owned = insert_scope(&pool, "local-bootstrap", "owned").await?;
    let outside = insert_scope(&pool, "outside-user", "outside").await?;
    let empty_project: String = sqlx::query_scalar(
        "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, 'Empty project', 'empty-project') RETURNING id::text",
    )
    .bind(&owned.organization)
    .fetch_one(&pool)
    .await?;
    let issue = insert_issue(&pool, objects.as_ref(), &owned, "owned", 'a').await?;
    let outside_issue = insert_issue(&pool, objects.as_ref(), &outside, "outside", 'b').await?;
    let app = router(
        "api",
        ServerState::dashboard_test(pool.clone(), objects.clone(), SECRET),
    );

    let overview_response = app
        .clone()
        .oneshot(
            authorized(
                Request::builder().uri(format!("/api/v1/projects/{}/overview", owned.project)),
            )
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(overview_response.status(), StatusCode::OK);
    assert_no_store(&overview_response);
    let overview = json_body(overview_response).await?;
    assert_eq!(overview["window"]["days"], 30);
    assert_eq!(
        overview["events_over_time"].as_array().map(Vec::len),
        Some(30)
    );
    assert_eq!(overview["totals"]["events"], 2);
    assert_eq!(overview["totals"]["issues"], 1);
    assert_eq!(overview["top_issues"][0]["issue_id"], issue.issue_id);
    assert_eq!(overview["symbolication"]["readable"], 1);
    assert_eq!(overview["symbolication"]["partial"], 1);
    assert_eq!(overview["symbolication"]["denominator"], 2);
    assert_eq!(overview["missing_symbol_count"], 2);
    assert_eq!(overview["processing"]["pending_jobs"], 1);
    assert_eq!(overview["observed_usage"]["authoritative"], false);
    assert_eq!(
        overview["observed_usage"]["retained_raw_bytes"],
        i64::try_from(issue.raw_bytes.len() + issue.older_raw_bytes.len())?
    );
    assert_eq!(overview["observed_usage"]["organization_projects"], 2);

    let empty_overview = app
        .clone()
        .oneshot(
            authorized(
                Request::builder().uri(format!("/api/v1/projects/{empty_project}/overview")),
            )
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(empty_overview.status(), StatusCode::OK);
    let empty_overview = json_body(empty_overview).await?;
    assert_eq!(empty_overview["totals"]["events"], 0);
    assert_eq!(empty_overview["totals"]["issues"], 0);
    assert_eq!(
        empty_overview["symbolication"]["success_percent"],
        Value::Null
    );
    assert_eq!(
        empty_overview["events_over_time"].as_array().map(Vec::len),
        Some(30)
    );

    let distribution_issue =
        insert_distribution_issue(&pool, &owned.organization, &empty_project).await?;
    let distribution_overview = app
        .clone()
        .oneshot(
            authorized(
                Request::builder().uri(format!("/api/v1/projects/{empty_project}/overview")),
            )
            .body(Body::empty())?,
        )
        .await?;
    let distribution_overview = json_body(distribution_overview).await?;
    assert_eq!(
        distribution_overview["releases"].as_array().map(Vec::len),
        Some(20)
    );
    assert_eq!(distribution_overview["releases_truncated"], true);
    assert_eq!(distribution_overview["releases_other_count"], 1);
    let distribution_events = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(format!(
                "/api/v1/projects/{empty_project}/issues/{distribution_issue}/events"
            )))
            .body(Body::empty())?,
        )
        .await?;
    let distribution_events = json_body(distribution_events).await?;
    assert_eq!(
        distribution_events["facets"]["releases"]
            .as_array()
            .map(Vec::len),
        Some(20)
    );
    assert_eq!(distribution_events["facets"]["releases_truncated"], true);
    assert_eq!(distribution_events["facets"]["releases_other_count"], 1);

    let first_page_response = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(format!(
                "/api/v1/projects/{}/issues/{}/events?limit=1",
                owned.project, issue.issue_id
            )))
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(first_page_response.status(), StatusCode::OK);
    let first_page = json_body(first_page_response).await?;
    assert_eq!(first_page["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(first_page["items"][0]["event_id"], issue.event_id);
    assert_eq!(first_page["items"][0]["symbolication_state"], "partial");
    assert_eq!(first_page["facets"]["releases"][0]["count"], 2);
    let cursor = first_page["next_cursor"]
        .as_str()
        .ok_or("first event page must include a cursor")?;
    let second_page = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(format!(
                "/api/v1/projects/{}/issues/{}/events?limit=1&cursor={cursor}",
                owned.project, issue.issue_id
            )))
            .body(Body::empty())?,
        )
        .await?;
    let second_page = json_body(second_page).await?;
    assert_eq!(second_page["items"][0]["event_id"], issue.older_event_id);
    assert!(second_page["next_cursor"].is_null());

    let detail_response = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(event_path(&owned, &issue))).body(Body::empty())?,
        )
        .await?;
    assert_eq!(detail_response.status(), StatusCode::OK);
    assert_no_store(&detail_response);
    let detail = json_body(detail_response).await?;
    assert_eq!(detail["event"]["event_id"], issue.event_id);
    assert_eq!(detail["classification"]["crash_type"], "crash");
    assert_eq!(detail["classification"]["truncated"], false);
    assert_eq!(detail["threads"][0]["faulting"], true);
    assert_eq!(
        detail["threads"][0]["frames"][0]["function"],
        "Arena::Tick()"
    );
    let missing_symbols = detail["missing_symbols"]
        .as_array()
        .ok_or("missing symbol list")?;
    assert_eq!(missing_symbols.len(), 2);
    assert!(missing_symbols.iter().any(|symbol| {
        symbol["debug_id"] == "DEBUG-MISSING" && symbol["required_artifact"] == "pdb"
    }));
    assert!(missing_symbols.iter().any(|symbol| {
        symbol["debug_id"] == "DEBUG-MANIFEST" && symbol["required_artifact"] == "pdb"
    }));
    assert!(
        missing_symbols
            .iter()
            .all(|symbol| symbol["truncated"] == false)
    );
    assert_eq!(detail["event"]["metadata_truncated"], false);
    assert!(
        detail["remediation_command"]
            .as_str()
            .is_some_and(|value| value.contains("faultlane symbols upload"))
    );
    assert_eq!(
        detail["processing_history"]["results"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        detail["processing_history"]["requests"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(detail["raw_available"], true);
    let serialized = serde_json::to_string(&detail)?;
    for forbidden in [
        "object_key",
        "unknown_fields",
        "command_line",
        "registers",
        "raw-result-secret",
    ] {
        assert!(!serialized.contains(forbidden));
    }

    let log_response = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(format!("{}/log", event_path(&owned, &issue))))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(log_response.status(), StatusCode::OK);
    assert_download_headers(&log_response, "text/plain; charset=utf-8");
    let log = to_bytes(log_response.into_body(), 1024 * 1024).await?;
    assert_eq!(log.as_ref(), hostile_log().as_bytes());

    let raw_response = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(format!("{}/raw", event_path(&owned, &issue))))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(raw_response.status(), StatusCode::OK);
    assert_download_headers(&raw_response, "application/octet-stream");
    assert_eq!(
        raw_response
            .headers()
            .get("digest")
            .and_then(|value| value.to_str().ok()),
        Some(
            format!(
                "sha-256={}",
                base64::engine::general_purpose::STANDARD.encode(Sha256::digest(issue.raw_bytes))
            )
            .as_str()
        )
    );
    let raw = to_bytes(raw_response.into_body(), 1024 * 1024).await?;
    assert_eq!(raw.as_ref(), issue.raw_bytes);

    objects
        .delete(&ObjectPath::from(issue.object_key.clone()))
        .await?;
    let missing_object = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(format!("{}/raw", event_path(&owned, &issue))))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(missing_object.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(missing_object).await?["code"],
        "artifact_unavailable"
    );
    objects
        .put(
            &ObjectPath::from(issue.object_key.clone()),
            PutPayload::from(issue.raw_bytes.to_vec()),
        )
        .await?;

    let without_raw = router(
        "api",
        ServerState::dashboard_without_raw_test(pool.clone(), objects.clone(), SECRET),
    );
    let disabled_detail = without_raw
        .clone()
        .oneshot(
            authorized(Request::builder().uri(event_path(&owned, &issue))).body(Body::empty())?,
        )
        .await?;
    assert_eq!(json_body(disabled_detail).await?["raw_available"], false);
    let disabled_raw = without_raw
        .oneshot(
            authorized(Request::builder().uri(format!("{}/raw", event_path(&owned, &issue))))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(disabled_raw.status(), StatusCode::NOT_FOUND);
    assert_no_store(&disabled_raw);

    let disabled = router(
        "api",
        ServerState::dashboard_disabled_test(pool.clone(), SECRET),
    );
    let disabled_overview = disabled
        .clone()
        .oneshot(
            authorized(
                Request::builder().uri(format!("/api/v1/projects/{}/overview", owned.project)),
            )
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(disabled_overview.status(), StatusCode::NOT_FOUND);
    assert_no_store(&disabled_overview);
    let basic_issues = disabled
        .clone()
        .oneshot(
            authorized(
                Request::builder().uri(format!("/api/v1/projects/{}/issues", owned.project)),
            )
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(basic_issues.status(), StatusCode::OK);
    let disabled_search = disabled
        .oneshot(
            authorized(Request::builder().uri(format!(
                "/api/v1/projects/{}/issues?query=Arena",
                owned.project
            )))
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(disabled_search.status(), StatusCode::NOT_FOUND);

    let invalid_cursor = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(format!(
                "/api/v1/projects/{}/issues/{}/events?cursor={cursor}x",
                owned.project, issue.issue_id
            )))
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(invalid_cursor.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&invalid_cursor);

    for response in [
        app.clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/projects/{}/overview", owned.project))
                    .body(Body::empty())?,
            )
            .await?,
        app.clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/projects/{}/overview", owned.project))
                    .header(header::AUTHORIZATION, "Bearer clpk_not-a-control-secret")
                    .body(Body::empty())?,
            )
            .await?,
        app.clone()
            .oneshot(
                authorized(Request::builder().uri(format!(
                    "/api/v1/projects/{}/issues/{}/events",
                    owned.project, outside_issue.issue_id
                )))
                .body(Body::empty())?,
            )
            .await?,
        app.clone()
            .oneshot(
                authorized(Request::builder().uri(format!(
                    "/api/v1/projects/{}/issues/{}/events/{}/raw",
                    owned.project, issue.issue_id, outside_issue.event_id
                )))
                .body(Body::empty())?,
            )
            .await?,
    ] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_no_store(&response);
    }

    sqlx::query(
        "UPDATE crash_processing_results SET result = '{\"unexpected\":true}'::jsonb WHERE id::text = $1",
    )
    .bind(&issue.older_result_id)
    .execute(&pool)
    .await?;
    let corrupt = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(format!(
                "/api/v1/projects/{}/issues/{}/events/{}",
                owned.project, issue.issue_id, issue.older_event_id
            )))
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(corrupt.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(corrupt).await?["code"], "result_unavailable");
    let mismatched_result = processing_result("UECC-Windows-wrong-identity", false);
    sqlx::query("UPDATE crash_processing_results SET result = $2 WHERE id::text = $1")
        .bind(&issue.older_result_id)
        .bind(mismatched_result)
        .execute(&pool)
        .await?;
    let mismatched_identity = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(format!(
                "/api/v1/projects/{}/issues/{}/events/{}",
                owned.project, issue.issue_id, issue.older_event_id
            )))
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(mismatched_identity.status(), StatusCode::CONFLICT);

    sqlx::query("UPDATE crash_event_objects SET byte_size = byte_size + 1 WHERE id::text = $1")
        .bind(&issue.object_id)
        .execute(&pool)
        .await?;
    let mismatched_object = app
        .clone()
        .oneshot(
            authorized(Request::builder().uri(format!("{}/raw", event_path(&owned, &issue))))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(mismatched_object.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(mismatched_object).await?["code"],
        "artifact_unavailable"
    );

    let unavailable_store = AmazonS3Builder::new()
        .with_bucket_name("unavailable")
        .with_region("us-east-1")
        .with_endpoint("http://127.0.0.1:1")
        .with_access_key_id("test")
        .with_secret_access_key("test")
        .with_allow_http(true)
        .with_virtual_hosted_style_request(false)
        .with_retry(RetryConfig {
            max_retries: 0,
            retry_timeout: Duration::from_millis(100),
            ..RetryConfig::default()
        })
        .with_client_options(
            ClientOptions::new()
                .with_allow_http(true)
                .with_connect_timeout(Duration::from_millis(100))
                .with_timeout(Duration::from_millis(250)),
        )
        .build()?;
    let unavailable = router(
        "api",
        ServerState::dashboard_test(pool.clone(), Arc::new(unavailable_store), SECRET),
    );
    let storage_outage = unavailable
        .oneshot(
            authorized(Request::builder().uri(format!("{}/raw", event_path(&owned, &issue))))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(storage_outage.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(storage_outage).await?["code"],
        "artifact_unavailable"
    );
    Ok(())
}

struct Scope {
    user: String,
    organization: String,
    project: String,
    ingest_key: String,
    release: String,
}

struct SeededIssue {
    issue_id: String,
    event_id: String,
    older_event_id: String,
    older_result_id: String,
    object_id: String,
    object_key: String,
    raw_bytes: &'static [u8],
    older_raw_bytes: &'static [u8],
}

struct SeededEvent {
    event_id: String,
    result_id: String,
    object_id: String,
    object_key: String,
    raw_bytes: &'static [u8],
}

async fn insert_scope(
    pool: &PgPool,
    bootstrap_subject: &str,
    suffix: &str,
) -> Result<Scope, sqlx::Error> {
    let user: String = sqlx::query_scalar(
        "INSERT INTO users (bootstrap_subject, email) VALUES ($1, $2) RETURNING id::text",
    )
    .bind(bootstrap_subject)
    .bind(format!("{suffix}@example.com"))
    .fetch_one(pool)
    .await?;
    let organization: String = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
    )
    .bind(format!("{suffix} organization"))
    .bind(format!("{suffix}-organization"))
    .fetch_one(pool)
    .await?;
    sqlx::query(
        "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')",
    )
    .bind(&organization)
    .bind(&user)
    .execute(pool)
    .await?;
    let project_slug = format!("{suffix}-project");
    let project: String = sqlx::query_scalar(
        "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, $2, $3) RETURNING id::text",
    )
    .bind(&organization)
    .bind(format!("{suffix} project"))
    .bind(&project_slug)
    .fetch_one(pool)
    .await?;
    let ingest_key: String = sqlx::query_scalar(
        "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, $4) RETURNING id::text",
    )
    .bind(&organization)
    .bind(&project)
    .bind(Sha256::digest(format!("{suffix}-key")).to_vec())
    .bind(suffix)
    .fetch_one(pool)
    .await?;
    let release: String = sqlx::query_scalar(
        "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration, build_timestamp) VALUES ($1::uuid, $2::uuid, '1.0.0', 'windows', 'x86_64', 'Shipping', now() - interval '1 day') RETURNING id::text",
    )
    .bind(&organization)
    .bind(&project)
    .fetch_one(pool)
    .await?;
    Ok(Scope {
        user,
        organization,
        project,
        ingest_key,
        release,
    })
}

async fn insert_distribution_issue(
    pool: &PgPool,
    organization_id: &str,
    project_id: &str,
) -> Result<String, Box<dyn Error>> {
    let ingest_key: String = sqlx::query_scalar(
        "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, 'dist') RETURNING id::text",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(Sha256::digest(b"distribution-key").to_vec())
    .fetch_one(pool)
    .await?;
    let mut event_ids = Vec::with_capacity(21);
    let mut release_ids = Vec::with_capacity(21);
    for index in 0_i64..21 {
        let release_id: String = sqlx::query_scalar(
            "INSERT INTO releases (organization_id, project_id, version, platform, architecture, configuration) VALUES ($1::uuid, $2::uuid, $3, 'windows', 'x86_64', 'Shipping') RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(format!("distribution-{index}"))
        .fetch_one(pool)
        .await?;
        let object_id: String = sqlx::query_scalar(
            "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3, $4, 1, 'application/octet-stream') RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(format!("dashboard/distributions-{index}.uecrash"))
        .bind(Sha256::digest(format!("distribution-{index}")).to_vec())
        .fetch_one(pool)
        .await?;
        let event_id: String = sqlx::query_scalar(
            "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, crash_guid, environment, processing_state, release_id, release_mapping_state, grouping_state, received_at) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, 'production', 'received', $6::uuid, 'matched', 'disabled', now() - ($7::text || ' minutes')::interval) RETURNING id::text",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(&ingest_key)
        .bind(&object_id)
        .bind(format!("UECC-Distribution-{index}"))
        .bind(&release_id)
        .bind(index)
        .fetch_one(pool)
        .await?;
        release_ids.push(release_id);
        event_ids.push(event_id);
    }
    let fingerprint = "d".repeat(64);
    let issue_id: String = sqlx::query_scalar(
        "INSERT INTO issues (id, organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint, title, regression_state, first_seen_at, last_seen_at, event_count, representative_event_id, first_release_id, last_release_id) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'stack', 1, $3, 'Distribution issue', 'new', now() - interval '20 minutes', now(), 21, $4::uuid, $5::uuid, $6::uuid) RETURNING id::text",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(&fingerprint)
    .bind(&event_ids[0])
    .bind(&release_ids[0])
    .bind(&release_ids[20])
    .fetch_one(pool)
    .await?;
    sqlx::query(
        "UPDATE crash_events SET issue_id = $1::uuid, grouping_state = 'grouped', fingerprint_algorithm = 'stack', fingerprint_version = 1, fingerprint = $2, variant_fingerprint = $2, grouping_quality = 100, grouped_at = received_at WHERE project_id::text = $3 AND crash_guid LIKE 'UECC-Distribution-%'",
    )
    .bind(&issue_id)
    .bind(&fingerprint)
    .bind(project_id)
    .execute(pool)
    .await?;
    Ok(issue_id)
}

#[allow(clippy::too_many_lines)]
async fn insert_issue(
    pool: &PgPool,
    objects: &InMemory,
    scope: &Scope,
    suffix: &str,
    fingerprint_character: char,
) -> Result<SeededIssue, Box<dyn Error>> {
    let older = insert_event(
        pool,
        objects,
        scope,
        &format!("{suffix}-older"),
        "2 hours",
        false,
    )
    .await?;
    let latest = insert_event(
        pool,
        objects,
        scope,
        &format!("{suffix}-latest"),
        "1 hour",
        true,
    )
    .await?;
    let fingerprint = fingerprint_character.to_string().repeat(64);
    let variant = if fingerprint_character == 'f' {
        "e".repeat(64)
    } else {
        "f".repeat(64)
    };
    let issue_id: String = sqlx::query_scalar(
        "INSERT INTO issues (id, organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint, title, regression_state, first_seen_at, last_seen_at, event_count, representative_event_id, first_release_id, last_release_id) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'stack', 1, $3, $4, 'new', now() - interval '2 hours', now() - interval '1 hour', 2, $5::uuid, $6::uuid, $6::uuid) RETURNING id::text",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&fingerprint)
    .bind(format!("<script>{suffix}</script> root"))
    .bind(&latest.event_id)
    .bind(&scope.release)
    .fetch_one(pool)
    .await?;
    for event in [&older, &latest] {
        sqlx::query(
            "UPDATE crash_events SET issue_id = $2::uuid, grouping_state = 'grouped', fingerprint_algorithm = 'stack', fingerprint_version = 1, fingerprint = $3, variant_fingerprint = $4, grouping_quality = 100, grouped_at = received_at WHERE id::text = $1",
        )
        .bind(&event.event_id)
        .bind(&issue_id)
        .bind(&fingerprint)
        .bind(&variant)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO crash_event_release_candidates (organization_id, project_id, event_id, release_id) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)",
        )
        .bind(&scope.organization)
        .bind(&scope.project)
        .bind(&event.event_id)
        .bind(&scope.release)
        .execute(pool)
        .await?;
    }
    sqlx::query(
        "INSERT INTO issue_variants (organization_id, project_id, issue_id, variant_fingerprint, first_seen_at, last_seen_at, event_count, representative_event_id) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, now() - interval '2 hours', now() - interval '1 hour', 2, $5::uuid)",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&issue_id)
    .bind(&variant)
    .bind(&latest.event_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO issue_releases (organization_id, project_id, issue_id, release_id, first_seen_at, last_seen_at, event_count, representative_event_id) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, now() - interval '2 hours', now() - interval '1 hour', 2, $5::uuid)",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&issue_id)
    .bind(&scope.release)
    .bind(&latest.event_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO crash_symbol_waiters (organization_id, project_id, event_id, result_id, release_id, required_artifact, module_name, architecture, debug_id, code_id) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 'pdb', 'Missing.dll', 'x86_64', 'DEBUG-MISSING', '')",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&latest.event_id)
    .bind(&latest.result_id)
    .bind(&scope.release)
    .execute(pool)
    .await?;
    let artifact_token: String = sqlx::query_scalar(
        "INSERT INTO artifact_upload_tokens (organization_id, project_id, created_by_user_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'dash') RETURNING id::text",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&scope.user)
    .bind(Sha256::digest(format!("{suffix}-artifact-token")).to_vec())
    .fetch_one(pool)
    .await?;
    sqlx::query(
        "INSERT INTO release_manifest_artifacts (release_id, organization_id, project_id, uploaded_by_user_id, upload_token_id, checksum, byte_size, artifact_type, module_name, architecture, debug_id, source_path, cli_version) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, 10, 'pdb', 'Missing.dll', 'x86_64', 'DEBUG-MISSING', 'Missing.pdb', '0.1.0'), ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $7, 11, 'pdb', 'ManifestOnly.pdb', 'x86_64', 'DEBUG-MANIFEST', 'ManifestOnly.pdb', '0.1.0')",
    )
    .bind(&scope.release)
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&scope.user)
    .bind(&artifact_token)
    .bind(Sha256::digest(format!("{suffix}-missing-artifact")).to_vec())
    .bind(Sha256::digest(format!("{suffix}-manifest-artifact")).to_vec())
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO jobs (id, organization_id, project_id, event_id, job_type, payload, state, idempotency_key) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, 'process_crash', '{}'::jsonb, 'pending', $4)",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&older.event_id)
    .bind(format!("{suffix}-dashboard-job"))
    .execute(pool)
    .await?;
    let request_id: String = sqlx::query_scalar(
        "INSERT INTO crash_reprocessing_requests (organization_id, project_id, source, scope_kind, scope_value, scope_fingerprint, idempotency_digest, requested_by_user_id, request_limit, selection_complete, state, selected_count, completed_count, completed_at) VALUES ($1::uuid, $2::uuid, 'manual', 'event', $3, $4, $5, $6::uuid, 1, true, 'completed', 1, 1, now()) RETURNING id::text",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&latest.event_id)
    .bind(Sha256::digest(format!("{suffix}-scope")).to_vec())
    .bind(Sha256::digest(format!("{suffix}-request")).to_vec())
    .bind(&scope.user)
    .fetch_one(pool)
    .await?;
    sqlx::query(
        "INSERT INTO crash_reprocessing_request_events (organization_id, project_id, request_id, event_id, generation, result_id, state, completed_at) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, $5::uuid, 'completed', now())",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(request_id)
    .bind(&latest.event_id)
    .bind(&latest.result_id)
    .execute(pool)
    .await?;
    Ok(SeededIssue {
        issue_id,
        event_id: latest.event_id,
        older_event_id: older.event_id,
        older_result_id: older.result_id,
        object_id: latest.object_id,
        object_key: latest.object_key,
        raw_bytes: latest.raw_bytes,
        older_raw_bytes: older.raw_bytes,
    })
}

async fn insert_event(
    pool: &PgPool,
    objects: &InMemory,
    scope: &Scope,
    suffix: &str,
    age: &str,
    partial: bool,
) -> Result<SeededEvent, Box<dyn Error>> {
    let raw_bytes: &'static [u8] = if partial {
        b"CR1\0private-minidump-and-context"
    } else {
        b"CR1\0older-private-crash"
    };
    let object_key = format!("dashboard/{suffix}.uecrash");
    objects
        .put(
            &ObjectPath::from(object_key.clone()),
            PutPayload::from(raw_bytes.to_vec()),
        )
        .await?;
    let checksum = Sha256::digest(raw_bytes).to_vec();
    let object_id: String = sqlx::query_scalar(
        "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3, $4, $5, 'application/octet-stream') RETURNING id::text",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&object_key)
    .bind(&checksum)
    .bind(i64::try_from(raw_bytes.len())?)
    .fetch_one(pool)
    .await?;
    let event_id: String = sqlx::query_scalar(
        "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, crash_guid, environment, processing_state, state_reason, received_at, release_id, release_mapping_state, grouping_state) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, 'production', $6, $7, now() - $8::interval, $9::uuid, 'matched', 'disabled') RETURNING id::text",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&scope.ingest_key)
    .bind(&object_id)
    .bind(format!("UECC-Windows-{suffix}"))
    .bind(if partial { "awaiting_symbols" } else { "processed" })
    .bind(partial.then_some("matching_symbols_missing"))
    .bind(age)
    .bind(&scope.release)
    .fetch_one(pool)
    .await?;
    let result = processing_result(&format!("UECC-Windows-{suffix}"), partial);
    faultlane_processing::validate_current_processing_result(
        &result,
        Some(&format!("UECC-Windows-{suffix}")),
    )?;
    let result_checksum = Sha256::digest(serde_json::to_vec(&result)?).to_vec();
    let result_id: String = sqlx::query_scalar(
        "INSERT INTO crash_processing_results (id, organization_id, project_id, event_id, schema_version, processing_version, result, checksum) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, 1, 2, $4, $5) RETURNING id::text",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&event_id)
    .bind(&result)
    .bind(result_checksum)
    .fetch_one(pool)
    .await?;
    sqlx::query(
        "INSERT INTO crash_event_search (organization_id, project_id, event_id, result_id, search_text, user_comment, crash_type, platform, architecture, engine_version, symbolication_state) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, 'crash', 'windows', 'x86_64', '5.8.1', $7)",
    )
    .bind(&scope.organization)
    .bind(&scope.project)
    .bind(&event_id)
    .bind(&result_id)
    .bind(format!("{suffix} access violation\u{1f}Arena::Tick()"))
    .bind(
        result
            .pointer("/crash_context/user_comment")
            .and_then(Value::as_str),
    )
    .bind(if partial { "partial" } else { "readable" })
    .execute(pool)
    .await?;
    sqlx::query("UPDATE crash_events SET current_result_id = $2::uuid WHERE id::text = $1")
        .bind(&event_id)
        .bind(&result_id)
        .execute(pool)
        .await?;
    Ok(SeededEvent {
        event_id,
        result_id,
        object_id,
        object_key,
        raw_bytes,
    })
}

#[allow(clippy::too_many_lines)]
fn processing_result(crash_guid: &str, partial: bool) -> Value {
    let mut modules = vec![json!({
        "module": "Game.exe",
        "base_address": "0x0000000140000000",
        "size": 4096,
        "code_id": "CODE-A",
        "debug_id": "DEBUG-A",
        "status": "matched",
        "pe": "game.exe",
        "pdb": "game.pdb"
    })];
    if partial {
        modules.push(json!({
            "module": "Missing.dll",
            "base_address": "0x0000000180000000",
            "size": 2048,
            "code_id": "CODE-MISSING",
            "debug_id": "DEBUG-MISSING",
            "status": "missing_pdb",
            "pe": "missing.dll",
            "pdb": null
        }));
    }
    let crash_context = json!({
        "parser_version": 1,
        "crash_guid": crash_guid,
        "crash_type": "crash",
        "error_message": "<img src=x onerror=alert(1)>; $env:SECRET",
        "build_version": "1.0.0",
        "engine_version": "5.8.1",
        "platform": {"original": "Win64", "normalized": "windows"},
        "architecture": "x86_64",
        "build_configuration": "Shipping",
        "modules": [],
        "threads": [{
            "call_stack": "raw-result-secret",
            "crash_marker": null,
            "registers": "raw-result-secret",
            "thread_id": "7",
            "thread_name": "GameThread"
        }],
        "system_metadata": [{"name": "Locale", "value": "雪\u{202e}<script>"}],
        "user_comment": "</textarea><script>globalThis.pwned=true</script>",
        "game_data": [{"name": "Map", "value": "C:\\\\Game\\\\Maps\\\\Arena;$(calc)"}],
        "unknown_fields": {"RuntimeProperties": {"Secret": ["raw-result-secret"]}}
    });
    let symbolication = json!({
        "schema_version": 2,
        "symbolicator_version": "0.1.0",
        "minidump_version": "0.27.0",
        "minidump_processor_version": "0.27.0",
        "minidump_unwind_version": "0.27.0",
        "platform": "windows",
        "architecture": "x86_64",
        "faulting_thread_id": 7,
        "exception_reason": "EXCEPTION_ACCESS_VIOLATION_READ",
        "assertion": null,
        "modules": modules,
        "threads": [{
            "thread_id": 7,
            "faulting": true,
            "name": "GameThread",
            "unwind_status": "ok",
            "frames_truncated": false,
            "frames": [{
                "instruction": "0x0000000140001000",
                "module": "Game.exe",
                "module_relative": "0x1000",
                "trust": "context",
                "symbol_status": "resolved",
                "function": "Arena::Tick()",
                "source_file": "Game/Source/Arena.cpp",
                "source_line": 42,
                "inlines": [{
                    "function": "Arena::Inner()",
                    "source_file": "Game/Source/Arena.cpp",
                    "source_line": 40
                }]
            }]
        }]
    });
    json!({
        "schema_version": 1,
        "crash_guid": crash_guid,
        "crash_context": crash_context,
        "classification": {
            "crash_type": "crash",
            "confidence": "high",
            "evidence": ["exception"],
            "signals": []
        },
        "log": {
            "name": "Project.log",
            "tail": {"text": hostile_log(), "truncated": false, "invalid_utf8": false}
        },
        "current": {
            "processing_version": 2,
            "parser_version": 1,
            "symbolication": symbolication
        },
        "history": []
    })
}

fn hostile_log() -> &'static str {
    "<script>globalThis.logPwned=true</script>\nC:\\private\\Game.log\n$env:SECRET"
}

fn event_path(scope: &Scope, issue: &SeededIssue) -> String {
    format!(
        "/api/v1/projects/{}/issues/{}/events/{}",
        scope.project, issue.issue_id, issue.event_id
    )
}

fn authorized(request: axum::http::request::Builder) -> axum::http::request::Builder {
    request.header(header::AUTHORIZATION, format!("Bootstrap {SECRET}"))
}

fn assert_no_store(response: &axum::response::Response) {
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
}

fn assert_download_headers(response: &axum::response::Response, content_type: &str) {
    assert_no_store(response);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(content_type)
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("sandbox")
    );
    assert_eq!(
        response
            .headers()
            .get(header::REFERRER_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("no-referrer")
    );
}

async fn json_body(response: axum::response::Response) -> Result<Value, Box<dyn Error>> {
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn assert_isolated_database(database_url: &str) {
    let database_name = database_url
        .rsplit('/')
        .next()
        .and_then(|value| value.split('?').next())
        .unwrap_or_default();
    assert!(
        database_name == "faultlane_296"
            || database_name.starts_with("faultlane_296_")
            || database_name == "faultlane_test"
    );
}
