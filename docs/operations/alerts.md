# Alert operations

Project alerts run inside the existing scheduler and worker roles. Apply migrations first, then set `FAULTLANE_ALERTS_ENABLED=true` on the API, scheduler, and worker. Configure exactly one of `FAULTLANE_INTEGRATION_KEY` or `FAULTLANE_INTEGRATION_KEY_FILE` with a base64-encoded 32-byte key. The file form is preferred for hosted deployments. All roles must use the same key.

Email alerts use `FAULTLANE_EMAIL_DELIVERY_URL` and `FAULTLANE_EMAIL_DELIVERY_TOKEN`. Discord, Slack, and generic webhook URLs are configured per project. Customer destinations require HTTPS on port 443. The API and worker resolve the hostname and reject loopback, private, link-local, documentation, multicast, and reserved addresses. Redirects are disabled and the worker pins each request to the validated addresses.

Integration URLs and generic webhook signing secrets are encrypted with XChaCha20-Poly1305. The organization, project, integration, destination kind, and config version are authenticated with the ciphertext. Generic webhooks receive `X-FaultLane-Signature: v1=<hex hmac-sha256>` over the JSON request body. The signing secret is shown only when the webhook is created or rotated.

Alert condition and delivery state is available in the project settings response. Delivery states are `pending`, `leased`, `delivered`, `failed`, `dead`, `suppressed`, and `unknown`. Retryable failures receive at most three attempts. Timeouts and other ambiguous outcomes become `unknown` and are not retried automatically. Logs contain project, delivery, state, and attempt identifiers but never destination URLs, secrets, response bodies, crash payloads, or recipient addresses.

An expired final-attempt lease is moved to `dead` with `lease_expired_final` before the worker claims more delivery work. Alert rules are evaluated least-recently-first in bounded pages, and issue rules finish every keyset page before checking recovery. Monitor the oldest `last_evaluated_at`, rule evaluation duration, issue page count, expired leases, dead deliveries, and fixed failure codes.

Quiet hours use UTC minutes from 0 through 1439. A trigger that recovers before its quiet period ends is suppressed with its recovery so delayed noise is not sent.

To roll back, set `FAULTLANE_ALERTS_ENABLED=false` on all roles and restore the previous application build. The migration is additive. Existing integrations, encrypted configuration, rule evaluation timestamps, condition state, and delivery history remain available for a corrected build. Reconcile expired final-attempt leases with the corrected build before restarting an older alert worker. Do not remove the integration key while queued or historical configuration still needs to be read.
