# Cloudflare R2 for hosted artifacts

Status: Accepted on August 14, 2026.

## Decision

Use private Cloudflare R2 buckets for hosted crash and symbol artifacts. Use MinIO for local development and self-hosted deployments. Access both through their S3-compatible APIs.

The server uses the official AWS SDK for Rust for multipart symbol upload control and presigning. Hosted R2 configuration uses the account endpoint and region `auto`. MinIO uses a literal loopback endpoint and path-style requests.

Multipart part requests bind the object key, upload ID, part number, content length, `Content-MD5`, and a ten-minute expiry. Automatic optional SDK checksum headers are disabled because R2 does not support every S3 checksum mode for `UploadPart`. FaultLane verifies the complete object size, SHA-256 checksum, and embedded PE or PDB identity before publication.

Buckets remain private. Clients receive only short-lived upload-part URLs. Object credentials, object keys, and raw artifact contents are not returned by FaultLane APIs or written to logs.

Hosted activation waits for issue #311 to move final PE and PDB verification into the bounded worker required by decision 0003. Until then, the upload feature fails startup unless the API binds to a literal loopback address.

## Consequences

- Hosted artifacts avoid S3 egress charges while preserving the S3-compatible storage boundary.
- Local and hosted upload behavior can be tested against MinIO without adding another storage implementation.
- Provider-specific configuration stays at the server boundary.
- A future provider change must preserve multipart resume, tenant isolation, private object access, and completion verification.

## Rollback

Disable artifact upload, restore the prior application version, and retain the additive database schema and completed private objects. Incomplete multipart sessions can be aborted or reconciled after rollback. Changing the hosted provider requires a later decision and migration plan.
