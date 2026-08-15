# Storage retention

Apply migrations with `faultlane-server migrate` while `FAULTLANE_RETENTION_V2_ENABLED` is unset or false. The migration is additive. Older application builds ignore the storage counter table and raw deletion deadline.

New raw objects receive one deletion deadline from the policy version accepted with the event. Later policy edits apply only to new objects. They do not shorten or extend an existing deadline.

Before enabling the new scheduler, reconcile every project:

```text
faultlane-server reconcile-storage \
  --organization-id <organization-uuid> \
  --project-id <project-uuid>
```

The command backfills missing deadlines in batches, compares maintained bytes with stored raw and available symbol objects, repairs drift, and prints counts without object keys. Require `missing_deadlines` to be zero. Investigate unexpected byte drift before continuing.

Set `FAULTLANE_RETENTION_V2_ENABLED=true` on scheduler instances only after every project is reconciled. A scheduler with any unreconciled project records a fixed waiting message and claims no raw objects. Each instance claims up to 5,000 due objects per transaction with `SKIP LOCKED` and drains for at most 30 seconds per minute.

Monitor scheduled objects, oldest due age, deletion job failures, and reconciliation drift. A raw byte leaves the maintained total only after the object store confirms deletion.

To roll back, set `FAULTLANE_RETENTION_V2_ENABLED=false` and stop scheduler claims before restoring the previous application. Keep the additive counters and deadlines, then reconcile again before resuming retention work.
