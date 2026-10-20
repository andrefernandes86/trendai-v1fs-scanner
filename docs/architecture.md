# ADR 001: event-driven file processing

Status: implemented baseline; Azure deployment and real SDK validation pending credentials.

No existing application was present in the supplied workspace. This repository is a new implementation.

## Decisions

Use Event Grid BlobCreated completion events for Blob ingestion. The API verifies Entra JWT issuer, signature, audience, expiry and the EventIngestor role before handling validation or delivery. Only PutBlob, PutBlockList, FlushWithClose, SftpCommit and CopyBlob completion notifications are accepted. Source account, container and prefix must match a registered enabled source. Scan asynchronously.

Use Azure Service Bus Premium queues (scan, promote, quarantine, retry) and native dead-letter subqueues. PostgreSQL owns job state. A transaction inserts each unique source identity, transition audit and outbox record. Dispatchers lock one outbox row with SKIP LOCKED, publish, then mark sent. A crash after send causes redelivery; deterministic message IDs and consumers tolerate it. Delayed outbox availability implements bounded exponential backoff.

Identity is SHA-256 of an unambiguous JSON array of source ID, key, version and ETag. Persist source and profile snapshots with each job. Exact-version Blob downloads additionally use If-Match; file downloads compare the returned ETag and exact size. Scanner reads a private temporary file; routing re-downloads the exact identity and checks the scanned SHA-256. A changed source is never promoted.

Use session-scoped PostgreSQL advisory permits for global, tenant, source, profile and individual-job limits. Independent files run concurrently, while each file's state advances through optimistic updates. Workers renew Service Bus locks every 15 seconds. An unsuccessful renewal cancels the processing context. Database session termination releases permits; destination idempotency still protects external effects.

Routing uses deterministic job-ID object names, create-only destination writes and full digest verification, followed by an idempotent routing transaction record and guarded terminal state. Redelivery verifies an existing destination rather than overwriting it. Unknown SDK output, errors and missing verdict fields are held. Never trust an absent scanResult as zero. Simulator output never reaches production destinations.

## Recovery

Retries are durable database outbox records with exponential delay and a configured attempt bound. The reconciler requeues stale in-flight work; the job lock and optimistic revision prevent concurrent transitions. Duplicate discovery creates no second job or initial queue record. Workers shut down on SIGTERM and messages remain available after failed settlement.

Azure Files has its own recursive adapter: a fresh `<filename>.complete` marker and an unchanged ETag/size observation for 60 seconds are required. The marker timestamp must be at least the file timestamp. Producers must write a new marker after every completed modification. No generic SMB stability heuristic can prove completion without a producer protocol.

Blob reconciliation accepts only blobs tagged with metadata `v1fs-complete=true`, including versions. This explicit producer contract avoids treating incomplete SFTP/ADLS writes as completed uploads. Event ingestion does not require that metadata. To recover a missed event automatically, producers must set the metadata on completed uploads. Retain source versions long enough for recovery.

## Deployment separation

The private Sites deployment hosts the React console. Azure Container Apps hosts the Go API and independent dispatch, scan, promote, quarantine, retry and reconciliation processes. Sites cannot host these Go processes. Browser authentication is Microsoft Entra MSAL; the API requires app roles. Secrets are never accepted by the console.

## Current limitations

This baseline is not certified enterprise production readiness. The following specification items require further implementation or environment validation:

- Alerts/notification delivery, priority scheduling, service-wide circuit breaking, adaptive scanner throttling and automatic dead-letter replay are not implemented. Native Service Bus max-delivery and exponential application retries are present.
- Dashboards expose real job-state counts, pending outbox, oldest pending record and SSE. P95/P99 scanner durations, queue-depth metrics, CPU/memory, throughput and worker connectivity are not implemented in the console. Worker /metrics currently exposes Go runtime metrics, not scanner latency histograms. Application Insights is provisioned but OpenTelemetry export is not instrumented.
- Capacity global/tenant/source/profile permits apply dynamically. Per-worker concurrency applies on restart. Replica bounds saved in the console are desired settings; update Bicep to apply KEDA bounds.
- Unknown/error jobs remain HELD in source. The configured hold destination is validated and recorded but no automatic transfer is implemented.
- Automatic source deletion, retention enforcement, SDK quarantine encoding, forensic release and custom notification schedules are disabled or unimplemented. Raw malicious bytes go only to private restricted quarantine storage.
- Storage explorer shows processing records, not arbitrary unscanned storage objects. No arbitrary quarantine download exists.
- Azure live deployment, Event Grid Entra authorization, private networking, real Service Bus redelivery/worker-termination recovery and the official SDK require integration acceptance in the target subscription. Multi-day 10k/hour and 50k/day load scenarios have not been executed.
- All Entra application roles are workspace-wide. The tenant field is a scheduling scope, not an authorization isolation boundary.
