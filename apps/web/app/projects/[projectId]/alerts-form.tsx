"use client";

import { useActionState, useState } from "react";

import type { ProjectAlerts } from "../../../lib/faultlane";
import {
  type AlertActionState,
  createAlertIntegration,
  createAlertRule,
  setAlertIntegrationEnabled,
  setAlertRuleEnabled,
} from "./alerts-actions";

const initialState: AlertActionState = {};

export function AlertsForm({
  projectId,
  alerts,
}: {
  projectId: string;
  alerts: ProjectAlerts;
}) {
  const integrationAction = createAlertIntegration.bind(null, projectId);
  const ruleAction = createAlertRule.bind(null, projectId);
  const [integrationState, createIntegration, integrationPending] =
    useActionState(integrationAction, initialState);
  const [ruleState, createRule, rulePending] = useActionState(
    ruleAction,
    initialState,
  );
  const [kind, setKind] = useState("email");
  const [condition, setCondition] = useState("first_seen");

  return (
    <div className="alerts-settings">
      {alerts.integrations.length ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Destination</th>
                <th>Type</th>
                <th>Endpoint</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.integrations.map((integration) => (
                <tr key={integration.id}>
                  <td>{integration.name}</td>
                  <td>{integration.kind}</td>
                  <td>{integration.endpoint_host ?? "Member email"}</td>
                  <td>
                    {alerts.can_edit ? (
                      <form
                        action={setAlertIntegrationEnabled.bind(
                          null,
                          projectId,
                          integration.id,
                          !integration.enabled,
                        )}
                      >
                        <button className="button secondary" type="submit">
                          {integration.enabled ? "Disable" : "Enable"}
                        </button>
                      </form>
                    ) : integration.enabled ? (
                      "Enabled"
                    ) : (
                      "Disabled"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty-copy">No alert destinations configured.</p>
      )}

      {alerts.rules.length ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Condition</th>
                <th>Environment</th>
                <th>Delivery state</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.rules.map((rule) => {
                const delivery = alerts.deliveries.find(
                  (item) => item.rule_id === rule.id,
                );
                return (
                  <tr key={rule.id}>
                    <td>{rule.condition_kind.replaceAll("_", " ")}</td>
                    <td>{rule.environment}</td>
                    <td>{delivery?.state ?? "Not triggered"}</td>
                    <td>
                      {alerts.can_edit ? (
                        <form
                          action={setAlertRuleEnabled.bind(
                            null,
                            projectId,
                            rule.id,
                            !rule.enabled,
                          )}
                        >
                          <button className="button secondary" type="submit">
                            {rule.enabled ? "Disable" : "Enable"}
                          </button>
                        </form>
                      ) : rule.enabled ? (
                        "Enabled"
                      ) : (
                        "Disabled"
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty-copy">No alert rules configured.</p>
      )}

      {alerts.can_edit ? (
        <div className="alerts-form-grid">
          <form action={createIntegration}>
            <h3>Add destination</h3>
            <label>
              Name
              <input name="name" maxLength={80} required />
            </label>
            <label>
              Type
              <select
                name="kind"
                value={kind}
                onChange={(event) => setKind(event.target.value)}
              >
                <option value="email">Email me</option>
                <option value="discord">Discord</option>
                <option value="slack">Slack</option>
                <option value="webhook">Signed webhook</option>
              </select>
            </label>
            {kind !== "email" ? (
              <label>
                HTTPS URL
                <input name="url" type="url" maxLength={2048} required />
              </label>
            ) : null}
            <button
              className="button primary"
              type="submit"
              disabled={integrationPending}
            >
              {integrationPending ? "Adding..." : "Add destination"}
            </button>
            <p
              className={
                integrationState.error ? "form-error" : "action-status"
              }
              aria-live="polite"
            >
              {integrationState.error ?? integrationState.message}
            </p>
            {integrationState.signingSecret ? (
              <p className="secret-callout">
                Copy this signing secret now:{" "}
                <code>{integrationState.signingSecret}</code>
              </p>
            ) : null}
          </form>

          <form action={createRule}>
            <h3>Add rule</h3>
            <label>
              Destination
              <select name="integration_id" required defaultValue="">
                <option value="" disabled>
                  Select destination
                </option>
                {alerts.integrations.map((integration) => (
                  <option value={integration.id} key={integration.id}>
                    {integration.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Condition
              <select
                name="condition_kind"
                value={condition}
                onChange={(event) => setCondition(event.target.value)}
              >
                <option value="first_seen">First seen issue</option>
                <option value="regression">Regression</option>
                <option value="volume">Crash volume</option>
                <option value="missing_symbols">Missing symbols</option>
                <option value="processing_failure">Processing failure</option>
                <option value="ingest_silence">Ingest silence</option>
                <option value="quota">Quota threshold</option>
              </select>
            </label>
            <label>
              Environment
              <input
                name="environment"
                defaultValue="production"
                maxLength={32}
                required
              />
            </label>
            {condition === "volume" ? (
              <label>
                Threshold
                <input
                  name="threshold"
                  type="number"
                  min={1}
                  max={1_000_000}
                  required
                />
              </label>
            ) : null}
            {condition === "quota" ? (
              <label>
                Threshold
                <select name="threshold" defaultValue="70">
                  <option value="70">70 percent</option>
                  <option value="90">90 percent</option>
                  <option value="100">100 percent</option>
                  <option value="101">Courtesy buffer exhausted</option>
                </select>
              </label>
            ) : null}
            {condition === "volume" || condition === "ingest_silence" ? (
              <label>
                Window in seconds
                <input
                  name="window_seconds"
                  type="number"
                  min={60}
                  max={604_800}
                  required
                />
              </label>
            ) : null}
            <div className="quiet-hours">
              <label>
                Quiet start, UTC minute
                <input
                  name="quiet_start_minute"
                  type="number"
                  min={0}
                  max={1439}
                />
              </label>
              <label>
                Quiet end, UTC minute
                <input
                  name="quiet_end_minute"
                  type="number"
                  min={0}
                  max={1439}
                />
              </label>
            </div>
            <button
              className="button primary"
              type="submit"
              disabled={rulePending || !alerts.integrations.length}
            >
              {rulePending ? "Adding..." : "Add rule"}
            </button>
            <p
              className={ruleState.error ? "form-error" : "action-status"}
              aria-live="polite"
            >
              {ruleState.error ?? ruleState.message}
            </p>
          </form>
        </div>
      ) : (
        <p className="fine-print">
          Only an organization owner or admin can change alerts.
        </p>
      )}
    </div>
  );
}
