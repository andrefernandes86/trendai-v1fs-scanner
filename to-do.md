# Pending work

- [ ] Fix/improve SMB share enumeration interoperability and clear diagnostics when server RPC/IPC discovery is denied but direct share access works. Do not treat enumeration as required for a known share.
- [ ] Add explicit re-scan/reprocess actions for files already in scan-failed storage, retaining history and immutable identities.
- [ ] Add a one-click historical detection-detail enrichment workflow for previously scanned files whose response was not retained.
- [ ] Add a reboot-persistent host service and documented upgrade/rollback workflow.
- [ ] Add browser-based visual regression and end-to-end UI tests across desktop/mobile layouts.
- [ ] Add configurable upload quiet periods and ignore patterns for temporary/in-progress files.
- [ ] Improve source-delete retry handling without losing verified destination records.
- [ ] Add bounded concurrent monitoring per profile so a slow share cannot delay other source checks.
- [ ] Add historical record pagination, richer filters and retention settings.
- [ ] Add managed archive password workflows only if requested; currently ZIPs are preserved as uploaded, with no generated password or ZIP conversion.

## Current limits

NFS supports v3 TCP AUTH_SYS, not NFSv4/Kerberos. Stability checks cannot prove upload completion during a long pause. SMB/NFS identity checks do not equal Blob conditional-version guarantees. Existing destination names are not retroactively renamed. Unknown files previously routed under the old verbose-response parser require rescanning; the fix does not rewrite historical verdicts.

## Customer assurance priorities

- [ ] Separate scan, destination-transfer and source-delete retry budgets. Make limits/backoff/jitter configurable; transient scanner failures must not consume destination retries.
- [ ] Classify transient scanner errors versus permanent exceptions (unsupported format, encrypted archives, size/scan limits). Retry transient UNKNOWN responses before isolation; never infer CLEAN from missing results.
- [ ] Add a recovery queue for scan-failed storage with scheduled/manual rescans, bounded attempts, escalation and immutable history.
- [ ] Add periodic inventory reconciliation: every discovered source version must have a durable processing or exception record, including interrupted/paginated listings.
- [ ] Add alerts for stale source checks, stuck jobs, growing backlog, credential failures, disk pressure and processing deadline breaches.
- [ ] Test recovery during scanner/network outages, credential expiry, large inventories and host termination at each move stage.

## Exclusion policy (requested; not implemented)

- [ ] Add per-profile exclusion rules for explicit paths, filename patterns/extensions and optional size ranges, with preview and match counts before saving.
- [ ] Matching files bypass scanning and route to the configured clean destination as **EXCLUDED / NOT SCANNED**, never as a verified CLEAN verdict. Show the rule, policy revision and bypass reason in activity, tags, audit and CSV.
- [ ] Make precedence deterministic: explicit deny/hold rules must override scan bypass; document case sensitivity and path normalization. Default to scanning when a rule cannot be evaluated.
- [ ] Apply the same transfer-integrity and conditional-source-delete protocol to excluded files. A bypass must not bypass destination verification.
- [ ] Add rule tests, change audit, exclusions reporting and alerts for unexpectedly broad matches. Exclusions reduce malware coverage; label this in the configuration UI.

## Verified copy then conditional delete (requested hardening)

Current routing reads destination bytes back and compares size and SHA-256 before deleting the source. Blob deletion is ETag-conditional; SMB/NFS recheck identity and digest. The stronger protocol below remains pending:

- [ ] Persist a move state machine: DISCOVERED -> SOURCE_CAPTURED -> SCANNED or EXCLUDED -> COPYING -> DESTINATION_VERIFIED -> SOURCE_DELETE_PENDING -> COMPLETED, with explicit isolated/error states.
- [ ] Capture source identity/version, size, SHA-256 and a documented CRC algorithm (CRC32C). Calculate checksums over the exact bytes being copied; CRC is supplemental, not a replacement for SHA-256.
- [ ] Read back the final destination object/file and compare byte count, SHA-256 and CRC32C to the captured source. Presence, filename or storage ETag alone does not prove equivalence. Do not assume Blob ETags or multipart ETags are content checksums.
- [ ] Record destination identity/version and verified checksums durably before any source removal. Prevent destination overwrite/deletion during finalization with storage-specific leases/permissions or a controlled writer contract.
- [ ] Remove only the captured source version using conditional delete where supported. If source identity changes, preserve it and queue the new version separately.
- [ ] Retry deletion independently. After restart, resume a verified move without rescanning or duplicating transfer; if source is already absent, reconcile the verified destination before completing.
- [ ] For SMB/NFS, define a producer handoff/claim protocol or locking contract. Identity checks followed by unlink are not atomic against a concurrent writer; preserve the source when ownership cannot be established.
- [ ] Keep files pending and alert when verification fails; test corruption, same-name replacement, concurrent mutation and crashes immediately before/after deletion.
