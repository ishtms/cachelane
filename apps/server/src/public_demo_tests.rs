use std::{env, error::Error, net::SocketAddr, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
};
use object_store::memory::InMemory;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;

use super::{
    configure_read_transaction, parse_issue_key, public_threads, safe_file_name, source_ip,
};
use crate::project_setup::{DATABASE_TEST_LOCK, ServerState, migrate, router};

const SECRET: &str = "public-demo-test-secret-with-32-bytes";

#[test]
fn keys_proxy_addresses_and_stack_projection_are_safe() -> Result<(), Box<dyn Error>> {
    let fingerprint = "a".repeat(64);
    assert_eq!(
        parse_issue_key(&format!("1-{fingerprint}")).map_err(|_| "valid issue key")?,
        (1, fingerprint)
    );
    assert!(parse_issue_key(&format!("1-{}", "A".repeat(64))).is_err());
    assert!(parse_issue_key("0-abc").is_err());
    assert_eq!(
        safe_file_name(r"C:\private\game\Arena.cpp"),
        Some("Arena.cpp".to_owned())
    );

    let trusted = ["127.0.0.0/8".parse()?];
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.9, 127.0.0.2".parse()?);
    assert_eq!(
        source_ip("127.0.0.1".parse()?, &headers, &trusted).map_err(|_| "trusted proxy chain")?,
        "203.0.113.9".parse::<std::net::IpAddr>()?,
    );
    assert_eq!(
        source_ip("198.51.100.8".parse()?, &headers, &trusted).map_err(|_| "direct peer")?,
        "198.51.100.8".parse::<std::net::IpAddr>()?,
    );

    let (threads, truncated) = public_threads(&json!({
        "current": {"symbolication": {"threads": [{
            "thread_id": 7,
            "faulting": true,
            "private_registers": "secret",
            "frames": [{
                "instruction": "0x141234",
                "module": "SyntheticGame.exe",
                "function": "Arena::Tick()",
                "source_file": "C:\\private\\game\\Arena.cpp",
                "source_line": 42,
                "inlines": []
            }]
        }]}}
    }));
    assert!(!truncated);
    assert_eq!(threads.len(), 1);
    assert_eq!(
        threads[0].frames[0].source_file.as_deref(),
        Some("Arena.cpp")
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires FAULTLANE_TEST_DATABASE_URL"]
#[allow(clippy::expect_used)]
#[allow(clippy::too_many_lines)]
async fn public_demo_is_fixed_bounded_read_only_and_redacted() -> Result<(), Box<dyn Error>> {
    let database_url =
        env::var("FAULTLANE_TEST_DATABASE_URL").expect("FAULTLANE_TEST_DATABASE_URL is required");
    let _guard = DATABASE_TEST_LOCK.lock().await;
    assert_isolated_database(&database_url);
    migrate(&database_url).await?;
    migrate(&database_url).await?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    sqlx::query("TRUNCATE users, organizations CASCADE")
        .execute(&pool)
        .await?;

    let demo = insert_issue(&pool, "synthetic-demo-public", "demo-visible", 'a').await?;
    let outside = insert_issue(&pool, "outside-private", "outside-secret", 'b').await?;
    let state = ServerState::dashboard_test(pool.clone(), Arc::new(InMemory::new()), SECRET)
        .with_public_demo(&demo.organization_id, &demo.project_id, 20);
    let app = router("api", state);

    let info_response = app
        .clone()
        .oneshot(request(Method::GET, "/api/v1/demo")?)
        .await?;
    assert_eq!(info_response.status(), StatusCode::OK);
    assert_eq!(
        info_response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=15, stale-while-revalidate=30")
    );
    assert_eq!(json_body(info_response).await?["issue_count"], 1);

    let list_response = app
        .clone()
        .oneshot(request(Method::GET, "/api/v1/demo/issues")?)
        .await?;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list = json_body(list_response).await?;
    assert_eq!(list["synthetic"], true);
    assert_eq!(list["read_only"], true);
    assert_eq!(list["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(list["items"][0]["title"], "demo-visible");
    let list_text = list.to_string();
    assert!(!list_text.contains("outside-secret"));
    assert!(!list_text.contains(&outside.organization_id));
    assert!(!list_text.contains(&demo.issue_id));

    let issue_key = format!("1-{}", "a".repeat(64));
    let detail_response = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/v1/demo/issues/{issue_key}"),
        )?)
        .await?;
    assert_eq!(detail_response.status(), StatusCode::OK);
    let detail = json_body(detail_response).await?;
    assert_eq!(
        detail["threads"][0]["frames"][0]["source_file"],
        "Arena.cpp"
    );
    let detail_text = detail.to_string();
    for excluded in [
        "raw-private-data",
        "private-object-key",
        "private-comment",
        "private-context",
        "private-symbol-identity",
        "C:\\\\private",
        &demo.organization_id,
        &demo.project_id,
        &demo.event_id,
        &demo.issue_id,
    ] {
        assert!(!detail_text.contains(excluded), "leaked {excluded}");
    }

    let mut read_transaction = pool.begin().await?;
    configure_read_transaction(&mut read_transaction)
        .await
        .map_err(|_| "read transaction configuration failed")?;
    assert!(
        sqlx::query("INSERT INTO organizations (name, slug) VALUES ('Denied', 'denied')")
            .execute(&mut *read_transaction)
            .await
            .is_err()
    );
    read_transaction.rollback().await?;

    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM projects")
        .fetch_one(&pool)
        .await?;
    let demo_mutation = app
        .clone()
        .oneshot(request(Method::POST, "/api/v1/demo")?)
        .await?;
    assert_eq!(demo_mutation.status(), StatusCode::METHOD_NOT_ALLOWED);
    let anonymous_routes = [
        ("project", Method::POST, "/api/v1/setup".to_owned()),
        (
            "ingest key",
            Method::POST,
            format!("/api/v1/projects/{}/ingest-keys", demo.project_id),
        ),
        (
            "upload token",
            Method::POST,
            format!(
                "/api/v1/projects/{}/artifact-upload-tokens",
                demo.project_id
            ),
        ),
        (
            "upload",
            Method::POST,
            "/api/v1/projects/synthetic-demo-public/artifact-uploads".to_owned(),
        ),
        (
            "membership",
            Method::PATCH,
            format!(
                "/api/v1/organizations/{}/members/{}",
                demo.organization_id, demo.event_id
            ),
        ),
        (
            "alert",
            Method::POST,
            format!("/api/v1/projects/{}/alert-integrations", demo.project_id),
        ),
        (
            "issue state",
            Method::PUT,
            format!(
                "/api/v1/projects/{}/issues/{}/resolution",
                demo.project_id, demo.issue_id
            ),
        ),
        (
            "reprocessing",
            Method::POST,
            format!("/api/v1/projects/{}/reprocessing", demo.project_id),
        ),
        (
            "raw export",
            Method::GET,
            format!(
                "/api/v1/projects/{}/issues/{}/events/{}/raw",
                demo.project_id, demo.issue_id, demo.event_id
            ),
        ),
        (
            "log export",
            Method::GET,
            format!(
                "/api/v1/projects/{}/issues/{}/events/{}/log",
                demo.project_id, demo.issue_id, demo.event_id
            ),
        ),
    ];
    for (family, method, uri) in anonymous_routes {
        let response = app.clone().oneshot(request(method, &uri)?).await?;
        assert!(
            !response.status().is_success(),
            "anonymous {family} request succeeded"
        );
    }
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM projects")
        .fetch_one(&pool)
        .await?;
    assert_eq!(after, before);

    sqlx::query("TRUNCATE ingest_rate_limits")
        .execute(&pool)
        .await?;
    let limited = router(
        "api",
        ServerState::dashboard_test(pool.clone(), Arc::new(InMemory::new()), SECRET)
            .with_public_demo(&demo.organization_id, &demo.project_id, 1),
    );
    assert_eq!(
        limited
            .clone()
            .oneshot(request(Method::GET, "/api/v1/demo")?)
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        limited
            .oneshot(request(Method::GET, "/api/v1/demo")?)
            .await?
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    let disabled = router(
        "api",
        ServerState::dashboard_test(pool, Arc::new(InMemory::new()), SECRET),
    );
    assert_eq!(
        disabled
            .oneshot(request(Method::GET, "/api/v1/demo/health")?)
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}

#[allow(clippy::struct_field_names)]
struct SeededIssue {
    organization_id: String,
    project_id: String,
    event_id: String,
    issue_id: String,
}

#[allow(clippy::too_many_lines)]
async fn insert_issue(
    pool: &PgPool,
    slug: &str,
    title: &str,
    fingerprint_character: char,
) -> Result<SeededIssue, Box<dyn Error>> {
    let organization_id: String = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text",
    )
    .bind(slug)
    .bind(format!("{slug}-organization"))
    .fetch_one(pool)
    .await?;
    let project_id: String = sqlx::query_scalar(
        "INSERT INTO projects (organization_id, name, slug) VALUES ($1::uuid, $2, $3) RETURNING id::text",
    )
    .bind(&organization_id)
    .bind(slug)
    .bind(format!("{slug}-project"))
    .fetch_one(pool)
    .await?;
    let ingest_key_id: String = sqlx::query_scalar(
        "INSERT INTO project_ingest_keys (organization_id, project_id, secret_hash, display_suffix) VALUES ($1::uuid, $2::uuid, $3, 'demo') RETURNING id::text",
    )
    .bind(&organization_id)
    .bind(&project_id)
    .bind(Sha256::digest(slug.as_bytes()).to_vec())
    .fetch_one(pool)
    .await?;
    let object_id: String = sqlx::query_scalar(
        "INSERT INTO crash_event_objects (id, organization_id, project_id, object_key, checksum, byte_size, media_type) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3, $4, 16, 'application/octet-stream') RETURNING id::text",
    )
    .bind(&organization_id)
    .bind(&project_id)
    .bind(format!("private-object-key/{slug}.uecrash"))
    .bind(Sha256::digest(format!("raw-private-data-{slug}")).to_vec())
    .fetch_one(pool)
    .await?;
    let event_id: String = sqlx::query_scalar(
        "INSERT INTO crash_events (id, organization_id, project_id, ingest_key_id, raw_object_id, crash_guid, environment, processing_state, grouping_state) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, 'demo', 'processed', 'disabled') RETURNING id::text",
    )
    .bind(&organization_id)
    .bind(&project_id)
    .bind(&ingest_key_id)
    .bind(&object_id)
    .bind(format!("UECC-{slug}"))
    .fetch_one(pool)
    .await?;
    let result = json!({
        "private_comment": "private-comment",
        "private_context": "private-context",
        "current": {"symbolication": {
            "private_symbol_identity": "private-symbol-identity",
            "threads": [{
                "thread_id": 7,
                "faulting": true,
                "frames": [{
                    "module": "SyntheticGame.exe",
                    "function": "Arena::Tick()",
                    "source_file": "C:\\private\\source\\Arena.cpp",
                    "source_line": 42,
                    "inlines": []
                }]
            }]
        }}
    });
    let result_id: String = sqlx::query_scalar(
        "INSERT INTO crash_processing_results (id, organization_id, project_id, event_id, schema_version, processing_version, result, checksum) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, 1, 1, $4, $5) RETURNING id::text",
    )
    .bind(&organization_id)
    .bind(&project_id)
    .bind(&event_id)
    .bind(&result)
    .bind(Sha256::digest(serde_json::to_vec(&result)?).to_vec())
    .fetch_one(pool)
    .await?;
    sqlx::query("UPDATE crash_events SET current_result_id = $2::uuid WHERE id = $1::uuid")
        .bind(&event_id)
        .bind(&result_id)
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO crash_event_search (organization_id, project_id, event_id, result_id, search_text, user_comment, crash_type, platform, architecture, engine_version, symbolication_state) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, 'private-comment', 'crash', 'windows', 'x86_64', '5.8.1', 'readable')",
    )
    .bind(&organization_id)
    .bind(&project_id)
    .bind(&event_id)
    .bind(&result_id)
    .bind(title)
    .execute(pool)
    .await?;
    let fingerprint = fingerprint_character.to_string().repeat(64);
    let issue_id: String = sqlx::query_scalar(
        "INSERT INTO issues (id, organization_id, project_id, fingerprint_algorithm, fingerprint_version, fingerprint, title, regression_state, first_seen_at, last_seen_at, event_count, representative_event_id) VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'stack', 1, $3, $4, 'new', now() - interval '1 hour', now(), 1, $5::uuid) RETURNING id::text",
    )
    .bind(&organization_id)
    .bind(&project_id)
    .bind(&fingerprint)
    .bind(title)
    .bind(&event_id)
    .fetch_one(pool)
    .await?;
    sqlx::query(
        "UPDATE crash_events SET issue_id = $2::uuid, grouping_state = 'grouped', fingerprint_algorithm = 'stack', fingerprint_version = 1, fingerprint = $3, variant_fingerprint = $3, grouping_quality = 100, grouped_at = now() WHERE id = $1::uuid",
    )
    .bind(&event_id)
    .bind(&issue_id)
    .bind(&fingerprint)
    .execute(pool)
    .await?;
    Ok(SeededIssue {
        organization_id,
        project_id,
        event_id,
        issue_id,
    })
}

fn request(method: Method, uri: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([203, 0, 113, 10], 40_000))))
        .body(Body::empty())
}

async fn json_body(response: axum::response::Response) -> Result<Value, Box<dyn Error>> {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn assert_isolated_database(database_url: &str) {
    let database_name = database_url
        .rsplit('/')
        .next()
        .and_then(|value| value.split('?').next())
        .unwrap_or_default();
    assert!(database_name == "faultlane_test" || database_name.starts_with("faultlane_296_"));
}
