ALTER TABLE alert_rules
    ADD COLUMN last_evaluated_at TIMESTAMPTZ;

CREATE INDEX alert_rules_evaluation_due
    ON alert_rules (last_evaluated_at NULLS FIRST, id)
    WHERE enabled;

CREATE INDEX issues_alert_first_seen
    ON issues (organization_id, project_id, first_seen_at, id)
    WHERE status = 'open';

CREATE INDEX issues_alert_regressed
    ON issues (organization_id, project_id, updated_at, id)
    WHERE status = 'open' AND regression_state = 'regressed';
