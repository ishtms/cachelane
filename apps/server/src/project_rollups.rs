use std::{error::Error, fmt, time::Duration};

use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use time::{Date, Month};

use crate::identifiers::valid_uuid;

const MAX_REPAIR_DAYS: i64 = 31;
const SEARCH_BACKFILL_BATCH_SIZE: i64 = 1_000;

#[derive(Serialize)]
pub(crate) struct ProjectRollupRepairReport {
    organization_id: String,
    project_id: String,
    from: String,
    through: String,
    repaired_days: i64,
    drifted_rows: i64,
    stored_rollup_rows: i64,
    issue_vectors_backfilled: i64,
    event_vectors_backfilled: i64,
}

#[derive(Debug)]
pub(crate) enum ProjectRollupRepairError {
    InvalidArgument,
    ProjectNotFound,
    Database(sqlx::Error),
}

impl fmt::Display for ProjectRollupRepairError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument => {
                formatter.write_str("repair bounds or identifiers are invalid")
            }
            Self::ProjectNotFound => formatter.write_str("project was not found"),
            Self::Database(_) => formatter.write_str("project rollup repair failed"),
        }
    }
}

impl Error for ProjectRollupRepairError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::InvalidArgument | Self::ProjectNotFound => None,
        }
    }
}

impl From<sqlx::Error> for ProjectRollupRepairError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

pub(crate) async fn repair_project_rollups(
    database_url: &str,
    organization_id: &str,
    project_id: &str,
    from: &str,
    through: &str,
) -> Result<ProjectRollupRepairReport, ProjectRollupRepairError> {
    if !valid_uuid(organization_id) || !valid_uuid(project_id) {
        return Err(ProjectRollupRepairError::InvalidArgument);
    }
    let (first, last, span) =
        repair_bounds(from, through).ok_or(ProjectRollupRepairError::InvalidArgument)?;

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await?;
    let found: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM projects WHERE organization_id = $1::uuid AND id = $2::uuid)",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(&pool)
    .await?;
    if !found {
        return Err(ProjectRollupRepairError::ProjectNotFound);
    }

    let (drifted_rows, stored_rollup_rows) =
        repair_range(&pool, organization_id, project_id, first, last).await?;

    let issue_vectors_backfilled =
        backfill_issue_vectors(&pool, organization_id, project_id).await?;
    let event_vectors_backfilled =
        backfill_event_vectors(&pool, organization_id, project_id).await?;
    Ok(ProjectRollupRepairReport {
        organization_id: organization_id.to_owned(),
        project_id: project_id.to_owned(),
        from: from.to_owned(),
        through: through.to_owned(),
        repaired_days: span + 1,
        drifted_rows,
        stored_rollup_rows,
        issue_vectors_backfilled,
        event_vectors_backfilled,
    })
}

fn parse_date(value: &str) -> Option<Date> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse().ok()?;
    let month = Month::try_from(parts.next()?.parse::<u8>().ok()?).ok()?;
    let day = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let parsed = Date::from_calendar_date(year, month, day).ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn repair_bounds(from: &str, through: &str) -> Option<(Date, Date, i64)> {
    let first = parse_date(from)?;
    let last = parse_date(through)?;
    let span = (last - first).whole_days();
    (0..MAX_REPAIR_DAYS)
        .contains(&span)
        .then_some((first, last, span))
}

async fn repair_range(
    pool: &PgPool,
    organization_id: &str,
    project_id: &str,
    first: Date,
    last: Date,
) -> Result<(i64, i64), ProjectRollupRepairError> {
    let mut day = first;
    let mut drifted_rows = 0_i64;
    let mut stored_rollup_rows = 0_i64;
    loop {
        let (drifted, stored) = repair_day(pool, organization_id, project_id, day).await?;
        drifted_rows = drifted_rows.saturating_add(drifted);
        stored_rollup_rows = stored_rollup_rows.saturating_add(stored);
        if day == last {
            return Ok((drifted_rows, stored_rollup_rows));
        }
        day = day
            .next_day()
            .ok_or(ProjectRollupRepairError::InvalidArgument)?;
    }
}

async fn repair_day(
    pool: &PgPool,
    organization_id: &str,
    project_id: &str,
    day: Date,
) -> Result<(i64, i64), ProjectRollupRepairError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout = '30s'")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "CREATE TEMP TABLE project_rollup_repair (day date NOT NULL, dimension text NOT NULL, key text NOT NULL, label text NOT NULL, count bigint NOT NULL) ON COMMIT DROP",
    )
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "WITH event_groups AS MATERIALIZED (SELECT COALESCE(release.id::text, 'unmapped') AS release_key, COALESCE(release.version, 'Unmapped') AS release_label, COALESCE(search.platform, 'unknown') AS platform, COALESCE(search.architecture, 'unknown') AS architecture, COALESCE(search.crash_type, 'unknown') AS crash_type, CASE WHEN event.processing_state IN ('failed', 'quarantined') THEN 'failed' WHEN search.symbolication_state IS NOT NULL THEN search.symbolication_state WHEN event.processing_state = 'awaiting_symbols' THEN 'missing' ELSE 'processing' END AS symbolication_state, event.processing_state, count(*)::bigint AS event_count FROM crash_events event LEFT JOIN crash_event_search search ON search.organization_id = event.organization_id AND search.project_id = event.project_id AND search.event_id = event.id AND search.result_id = event.current_result_id LEFT JOIN releases release ON release.organization_id = event.organization_id AND release.project_id = event.project_id AND release.id = event.release_id WHERE event.organization_id = $1::uuid AND event.project_id = $2::uuid AND event.received_at >= ($3::date::timestamp AT TIME ZONE 'UTC') AND event.received_at < (($3::date + 1)::timestamp AT TIME ZONE 'UTC') GROUP BY release.id, release.version, search.platform, search.architecture, search.crash_type, search.symbolication_state, event.processing_state) INSERT INTO project_rollup_repair (day, dimension, key, label, count) SELECT $3::date, 'event_total', 'all', 'Events', sum(event_count)::bigint FROM event_groups HAVING sum(event_count) > 0 UNION ALL SELECT $3::date, 'release', release_key, release_label, sum(event_count)::bigint FROM event_groups GROUP BY release_key, release_label UNION ALL SELECT $3::date, 'platform_architecture', platform || '/' || architecture, initcap(platform) || ' / ' || architecture, sum(event_count)::bigint FROM event_groups GROUP BY platform, architecture UNION ALL SELECT $3::date, 'crash_type', crash_type, initcap(crash_type), sum(event_count)::bigint FROM event_groups GROUP BY crash_type UNION ALL SELECT $3::date, 'symbolication_state', symbolication_state, initcap(symbolication_state), sum(event_count)::bigint FROM event_groups GROUP BY symbolication_state UNION ALL SELECT $3::date, 'processing_state', processing_state, initcap(replace(processing_state, '_', ' ')), sum(event_count)::bigint FROM event_groups GROUP BY processing_state UNION ALL SELECT $3::date, issue_dimensions.dimension, 'all', issue_dimensions.label, count(*)::bigint FROM issues issue CROSS JOIN LATERAL (VALUES ('issue_total'::text, 'Issues'::text), ('issue_new'::text, 'New issues'::text)) AS issue_dimensions(dimension, label) WHERE issue.organization_id = $1::uuid AND issue.project_id = $2::uuid AND issue.first_seen_at >= ($3::date::timestamp AT TIME ZONE 'UTC') AND issue.first_seen_at < (($3::date + 1)::timestamp AT TIME ZONE 'UTC') GROUP BY issue_dimensions.dimension, issue_dimensions.label UNION ALL SELECT $3::date, 'issue_regressed', 'all', 'Regressed issues', count(*)::bigint FROM issues issue WHERE issue.organization_id = $1::uuid AND issue.project_id = $2::uuid AND issue.regression_state = 'regressed' AND issue.last_seen_at >= ($3::date::timestamp AT TIME ZONE 'UTC') AND issue.last_seen_at < (($3::date + 1)::timestamp AT TIME ZONE 'UTC')",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(day)
    .execute(&mut *transaction)
    .await?;
    let drifted: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM project_rollup_repair repair FULL OUTER JOIN project_daily_rollups stored ON stored.organization_id = $1::uuid AND stored.project_id = $2::uuid AND stored.day = $3::date AND stored.day = repair.day AND stored.dimension = repair.dimension AND stored.key = repair.key WHERE repair.count IS DISTINCT FROM stored.count OR repair.label IS DISTINCT FROM stored.label",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(day)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        "DELETE FROM project_daily_rollups WHERE organization_id = $1::uuid AND project_id = $2::uuid AND day = $3::date",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(day)
    .execute(&mut *transaction)
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO project_daily_rollups (organization_id, project_id, day, dimension, key, label, count) SELECT $1::uuid, $2::uuid, day, dimension, left(key, 512), left(label, 512), count FROM project_rollup_repair",
    )
    .bind(organization_id)
    .bind(project_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((
        drifted,
        i64::try_from(inserted.rows_affected()).unwrap_or(i64::MAX),
    ))
}

async fn backfill_issue_vectors(
    pool: &PgPool,
    organization_id: &str,
    project_id: &str,
) -> Result<i64, ProjectRollupRepairError> {
    let mut total = 0_i64;
    loop {
        let updated: i64 = sqlx::query_scalar(
            "WITH batch AS MATERIALIZED (SELECT id FROM issues WHERE organization_id = $1::uuid AND project_id = $2::uuid AND search_vector IS NULL ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $3), updated AS (UPDATE issues issue SET search_vector = to_tsvector('simple', issue.title) FROM batch WHERE issue.organization_id = $1::uuid AND issue.project_id = $2::uuid AND issue.id = batch.id RETURNING 1) SELECT count(*)::bigint FROM updated",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(SEARCH_BACKFILL_BATCH_SIZE)
        .fetch_one(pool)
        .await?;
        total = total.saturating_add(updated);
        if updated < SEARCH_BACKFILL_BATCH_SIZE {
            return Ok(total);
        }
    }
}

async fn backfill_event_vectors(
    pool: &PgPool,
    organization_id: &str,
    project_id: &str,
) -> Result<i64, ProjectRollupRepairError> {
    let mut total = 0_i64;
    loop {
        let updated: i64 = sqlx::query_scalar(
            "WITH batch AS MATERIALIZED (SELECT event_id FROM crash_event_search WHERE organization_id = $1::uuid AND project_id = $2::uuid AND search_vector IS NULL ORDER BY event_id FOR UPDATE SKIP LOCKED LIMIT $3), updated AS (UPDATE crash_event_search search SET search_vector = to_tsvector('simple', search.search_text) FROM batch WHERE search.organization_id = $1::uuid AND search.project_id = $2::uuid AND search.event_id = batch.event_id RETURNING 1) SELECT count(*)::bigint FROM updated",
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(SEARCH_BACKFILL_BATCH_SIZE)
        .fetch_one(pool)
        .await?;
        total = total.saturating_add(updated);
        if updated < SEARCH_BACKFILL_BATCH_SIZE {
            return Ok(total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::repair_bounds;

    #[test]
    fn repair_bounds_are_canonical_ordered_and_capped() {
        assert_eq!(
            repair_bounds("2026-01-01", "2026-01-31").map(|bounds| bounds.2),
            Some(30)
        );
        assert!(repair_bounds("2026-01-01", "2026-02-01").is_none());
        assert!(repair_bounds("2026-01-02", "2026-01-01").is_none());
        assert!(repair_bounds("2026-1-01", "2026-01-01").is_none());
        assert!(repair_bounds("2026-02-29", "2026-02-29").is_none());
    }
}
