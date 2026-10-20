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

- [ ] Run `sudo deploy/install-systemd.sh`, stop the foreground instance and start the installed service on the real host. This sandbox cannot access the user service manager or gain root, so boot activation is not claimed complete.
- [ ] Configure the customer's external alert delivery/monitoring system to consume authenticated `/api/assurance`. No external notification destination has been provided.
- [ ] Validate share handoff/permissions with actual SMB/NFS/Azure Files producers before enabling controlled-writer finalization. The application cannot make another writer obey an atomic handoff contract.
- [ ] Load/soak-test the customer's file counts, sizes, NAS servers, scanner quotas and outage durations. Fixture tests do not establish production capacity or compatibility with every server.

## Explicit limits and optional work

Polling cannot detect files removed before observation. Paused uploads can appear stable. NFS supports v3 TCP AUTH_SYS, not NFSv4/Kerberos. Existing destination names are not retroactively renamed. Broad exclusions reduce malware coverage. Existing encrypted ZIP passwords belong to the uploader; the app preserves original bytes and adds no archive encryption. A managed password/archive conversion feature is optional and has not been requested as a concrete workflow.
