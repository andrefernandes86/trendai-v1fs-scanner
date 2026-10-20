# Reliability implementation status

## Implemented

- [x] Independent scan, transfer/download and source-delete retry budgets, configurable backoff and jitter.
- [x] Transient unknown/request retries before isolation, plus permanent-exception classification.
- [x] Manual/scheduled failed-file recovery with linked history and bounded recovery attempts.
- [x] Historical detection enrichment from verified destination bytes without rewriting old verdicts.
- [x] Per-profile exclusion/hold rules, sizes, deterministic precedence and source preview. Excluded files promote as EXCLUDED / NOT SCANNED.
- [x] Configurable quiet periods and temporary-file ignore patterns.
- [x] Per-source-version durable inventory accounting and repeated paginated reconciliation.
- [x] Four bounded concurrent source monitors; destination folders are not automatically monitored.
- [x] Persisted move records with SHA-256, CRC32C, source/destination identity and independent delete recovery.
- [x] Renewable Blob destination leases during finalization; conditional source ETag deletion.
- [x] Controlled-writer contract gate for share storage; preserve source when ownership cannot be guaranteed.
- [x] Restart recovery after verified copy or source deletion, corruption/change-source tests and separate-stage retry tests.
- [x] Console/API alerts for stale checks, source failures, overdue work and disk pressure.
- [x] Server-side history filters/pagination, previewed retention, full-history CSV and source inventory CSV.
- [x] SMB discovery uses a server name without its TCP port for SRVSVC; blocked enumeration explains why direct share access may still work.
- [x] Desktop/mobile browser tests and screenshots, plus backend fixture/fault tests.
- [x] Restricted systemd unit, administrator installer, health script and rollout/rollback instructions.

## Operator prerequisites / outside application control

- [x] Container-first deployment with internal process watchdog, liveness probes and Docker restart policy. The host Docker service is enabled at boot; no application systemd activation is required.
- [ ] External notifications: explicitly deferred by the user; do not implement or configure delivery yet.
- [x] Automatic persisted source claim/handoff for SMB/NFS/Azure Files, private-path recovery and original-path replacement protection. Storage administrators must reserve scanner claim namespace permissions; share destinations still need controlled writers.
- [ ] Customer-owned validation: load/soak-test the customer's file counts, sizes, NAS servers, scanner quotas and outage durations. Fixture tests do not establish production capacity or compatibility with every server.

## Measured host validation (20 October 2026)

- [x] Real-source 1,000-file burst and 100-files/second upload tests, each fully drained with checksum evidence and source deletion. Twelve genuine ZIP archives also scanned and routed correctly. See [results](docs/performance-results-2026-10-20.md).
- [ ] Throughput enhancements: bounded parallel admission, safe SDK concurrency/configurable workers, and backlog-age/rate indicators. Current measured end-to-end throughput is about 1.5–1.7 files/second for this repeated small-file corpus; upload bursts create queues.
- [ ] Broader archive validation: encrypted archives, nested archives, extraction limits and large archive mixes. Ordinary ZIP detection was verified; this does not establish coverage for every compressed format.

## Explicit limits and optional work

Polling cannot detect files removed before observation. Paused uploads can appear stable. NFS supports v3 TCP AUTH_SYS, not NFSv4/Kerberos. Existing destination names are not retroactively renamed. Broad exclusions reduce malware coverage. Existing encrypted ZIP passwords belong to the uploader; the app preserves original bytes and adds no archive encryption. A managed password/archive conversion feature is optional and has not been requested as a concrete workflow.

Watchdog fault tests cover abrupt child termination and a completely stopped/unresponsive child process. External notification code is unchanged.
