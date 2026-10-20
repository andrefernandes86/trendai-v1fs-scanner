# Processing assurance

## Accounting and reconciliation

Every scheduled pass enumerates only the configured source, including continuation pages. Observed versions are persisted by profile, key and ETag in `inventory`. After the quiet period, queue admission associates the version with a durable job. Ignored/held versions carry an explicit policy status; queue admission failures remain ERROR. A later pass retries admission rather than silently dropping the version. Export source inventory from Overview; compare it with all-history CSV job export.

This accounts for **observed** versions. A file created and removed between polls cannot be detected by polling. For a stronger ingestion guarantee, producers must retain source files until this tool removes them, or an event/versioning system must retain every version. No product setting can recover an unobserved file already deleted elsewhere.

Four bounded monitor tasks prevent a slow source from blocking all profiles. Each pass is time-bounded; a failed pass is reported and a future pass starts again from the source. Source checks are scheduled at the profile interval; the quiet period defaults to 10 seconds across separate observations. Ignore patterns, e.g. `*.part`, leave in-progress files at source and account for them in inventory. A long upload pause can still appear stable.

## Exclusion and hold rules

Rules operate on relative source paths with `/` separators and case-sensitive matching. `*` matches within one path component; `**` spans folders; patterns without `/` can match a basename. Optional min/max byte sizes constrain a match; 0 maximum means unlimited. Hold rules take precedence over exclusions; exclusions take precedence over temporary ignore patterns. Rule validation rejects ambiguous actions and invalid sizes. With no match, the file is scanned.

Preview reports scan/exclude/hold/ignore counts and sample matches; previews above 10,000 entries are explicitly truncated. Exclusions route to the clean destination with verdict EXCLUDED, scanned=false tags and an audit entry identifying the rule and policy revision. They are never counted as scanner-verified CLEAN. Size, SHA-256 and CRC32C verification still apply. Broad rules intentionally reduce malware coverage; review the preview before saving.

## Independent retry budgets

Defaults: 5 scan attempts, 8 transfer/download attempts, 12 source-delete attempts, 10-second exponential retry base with jitter and a one-hour cap. Limits are profile settings. A successful scan verdict is reused after a transfer failure, so transfer retries do not consume scan attempts. Scanner request failures and transient unknown responses retry before isolation. Recognized permanent exceptions such as password-protected archives, unsupported formats and scan/decompression limits go to scan-failed review without pretending the file is clean. Review the retained encrypted scanner response for the exact cause.

Exhausted scan attempts route to the scan-failed destination if it can be verified. Exhausted transfer attempts retain the source. Exhausted delete attempts retain the verified destination and leave the job HELD. An explicit Retry resets stage budgets using the immutable job policy snapshot; use failed-file recovery for a new scan with current scanner settings.

## Verified move and restart recovery

The durable move record stores destination, phase, size, SHA-256, CRC32C, source/destination identities, matched rule and verification time. Credentials in this record are encrypted; API/CSV integrity summaries do not expose credentials.

1. Download an identified source version and compute content checksums over the captured bytes.
2. Scan or apply the explicit exclusion policy.
3. Publish exclusively to the selected destination. Read back and compare size/SHA-256, then CRC32C.
4. Persist the verified move before deleting anything at source.
5. Acquire a renewable 60-second Blob destination lease, where applicable. Re-read and verify destination identity/checksums under that lease. Loss of the lease cancels finalization; release uses a bounded independent cleanup context.
6. Persist SOURCE_DELETE_PENDING. Delete only the captured source identity. Blob deletion uses If-Match; shares require the operator's controlled-writer handoff setting plus identity/digest checks.
7. Persist move completion and job outcome. If a crash occurred after deletion, a retry re-verifies the persisted destination and reconciles an already-absent source without rescanning.

CRC32C supplements SHA-256; it does not prove upload completion or make a filename/ETag a content checksum. Conditional Blob deletion rejects a changed source. A renewable destination lease needs the relevant Blob lease/write permissions; failure preserves source and becomes a delete-stage retry.

SMB/NFS/Azure Files do not expose the same atomic check/unlink contract through these connectors. For them, finalization requires the controlled-writer checkbox, meaning producers have closed/handed off the source and external writers cannot replace the destination. The tool cannot enforce another application's cooperation. Leave this disabled if that contract is unavailable: copies remain verified but source deletion is held. Document network-storage permissions and ownership before enabling it.

## Recovery and historical enrichment

Record details offer Rescan isolated file and Refresh detection details. Recovery reads only the specific verified destination linked to the failed job, uses current scanner settings and disables bypass rules. It creates a new immutable job linked to the parent. A clean or malicious recovery marks the historical parent RECOVERED without rewriting its old UNKNOWN verdict. A still-unknown result remains isolated. Optional scheduled recovery uses a per-profile interval and parent recovery budget; it does not monitor every file in destination folders. An active/resolved child prevents duplicate recovery. Historical enrichment checks the destination digest before collecting a response and leaves the old verdict unchanged.

## Alerts, retention and operations

Overview and authenticated `/api/assurance` report stale source checks, source errors, overdue/pending/manual-review files and host disk pressure. Each profile has a deadline. These are console/API alerts; no email/Slack recipient is configured automatically. Connect the authenticated API to the customer's monitoring system for external paging. `/healthz` only reports process availability.

File activity supports server-side filename/profile search, state/verdict/date filters and pagination. Retention requires preview then explicit apply, accepts at least 30 days, removes only old completed/quarantined records and preserves unresolved records and linked recovery history. It never deletes destination files. Back up history before a retention operation.

The systemd installer is in `deploy/install-systemd.sh`. It creates a restricted, restartable service enabled for boot. Run it as administrator on the actual host; activation is not possible from an unprivileged sandbox with no service-manager access. Browser E2E tests use a separate data directory/port and never production credentials.
