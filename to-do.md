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
- [x] Independent API/engine processes and watchdog recovery, isolated concurrent SDK calls, configurable global worker capacity, per-profile simultaneous limits, queue/active counts and indexed history reads.
- [x] Profile revisions reuse active source-version jobs; changing concurrency cannot enqueue duplicates.
- [ ] Further throughput/observability: bounded parallel source admission, backlog age/rate indicators and customer-scale/soak validation. Earlier 1.5–1.7 files/second measurements describe the previous serialized runtime, not a capacity promise for the parallel runtime.
- [ ] Broader archive validation: encrypted archives, nested archives, extraction limits and large archive mixes. Ordinary ZIP detection was verified; this does not establish coverage for every compressed format.

- [x] Full counted file history with 100–1000 rows/page, first/last/page navigation and full-history filtering.
- [x] Storage explorer native tags and linked scan results; automatic reserved verdict tags and permission fallback.
- [x] Separate overdue/held alerts and checksum-proven historical supersession without erasing original scan evidence.
- [x] Transparent CPU/RAM/disk/concurrency sizing calculator after Audit log; 12,000 files/day example and illustrated guide.

## Explicit limits and optional work

Polling cannot detect files removed before observation. Paused uploads can appear stable. NFS supports v3 TCP AUTH_SYS, not NFSv4/Kerberos. Existing destination names are not retroactively renamed. Broad exclusions reduce malware coverage. Existing encrypted ZIP passwords belong to the uploader; the app preserves original bytes and adds no archive encryption. A managed password/archive conversion feature is optional and has not been requested as a concrete workflow.

Watchdog fault tests cover abrupt child termination and a completely stopped/unresponsive child process. External notification code is unchanged.

- [x] Remove 2 GiB application rejection; up to 100 GB SDK submission, profile size/oversize policy, streaming verification, disk admission, long-job timeouts and large-file concurrency.
- [ ] Full 100 GB end-to-end and customer-scale throughput/soak validation; distinguish engine inspection limits from submission capability.
- [x] Optional profile-controlled ZIP/ZIP64, TAR and GZIP inspection; up to 20 layers, shared bomb limits, isolated extraction, per-member evidence, incomplete results never clean.

- [ ] Investigate the live VPLE.zip SDK/ATSE -82 response with vendor error-code guidance. Application now submits the original 3.73 GB file; UNKNOWN is retained and bounded retries apply. Do not reclassify as clean from zero detections when the engine reports an error. Archive inspection is available as an opt-in feature; original SDK engine errors are not overridden.

- [ ] Additional extraction formats (7z/RAR/etc.) and encrypted-archive password handling after separate design/security review.

## Console and transfer improvements

- [x] Persistent browser light/dark toggle, including sign-in and mobile layouts.
- [x] Compact outcome-based destination editor, processing assurance cards and removal of the redundant overview banner.
- [x] Four-input basic sizing with expandable expert settings and breakdown.
- [x] Reversible hidden activity records; CSV, accounting, held alerts and history remain intact.
- [x] Verified recursive source listing for Blob and Azure Files/SMB/NFS, with link/depth safety.
- [x] Independent bounded scan/transfer pools; per-profile total/large transfer limits and Blob upload tuning.
- [x] One leased SHA-256/CRC32C Blob readback, capture checksum reuse, stage timings and CSV timing export.
- [ ] New customer-sized performance/soak measurements after transfer optimization; prior benchmark numbers remain historical.

## Guided configuration and monitoring views

- [x] Six-step profile wizard, draft preservation, final review and cross-step validation.
- [x] Short schedule/detection help, with optional and technical settings disclosed on demand.
- [x] Full light sidebar with the official standard logo, alongside the dark inverse logo.
- [x] Compact/expanded profile cards and accessible outcome-card filtering.
- [x] Shared scan-error count/filter definition, including hidden unresolved records on explicit drill-down.

- Track and eliminate remaining govulncheck advisory matches in imported/required code that is currently unreachable from application call paths; repeat the advisory scan on each dependency update.
