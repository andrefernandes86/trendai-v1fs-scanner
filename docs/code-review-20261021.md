# Code review and fixes — 21 October 2026

This review examined the management API/session boundary, encrypted SQLite store, job identity/capture/routing/deletion, retry and recovery paths, archive inspection and its sandbox, connector I/O, scheduler/supervisor health, reporting, console state and deployment instructions. It combines manual review with regression tests and static/dependency checks; it does not prove absence of all bugs.

## Confirmed defects corrected

| Finding | Correction |
|---|---|
| Recovery could inherit an oversized → clean bypass | Recovery holds oversized unknown files; it cannot bypass the required scan |
| Recovery accepted changed isolated bytes | Bind recovery capture to the parent SHA-256 and reject a mismatch before scanning/routing |
| Current recovery prefixes could mix with immutable old mount snapshots | Keep original destination roots and prefixes paired while adopting current scan/retry policy |
| Share recovery moved the file but retained an obsolete parent path | Track the exclusive claim location in the recovery parent, including restart reconciliation |
| Enrichment endpoint could scan an acknowledged file | Reject acknowledged files before any rescan |
| Interrupted source enumeration could report zero errors | Report an incomplete/error check and revisit remaining files |
| Archive capacity waits occupied all scan workers | Defer archive work promptly when admission is full; leave workers available for other files |
| One unknown archive member caused all successful members to be rescanned | Reuse verified CLEAN/MALICIOUS responses only within the same job and matching member name/SHA-256; retry unknown or changed members |
| Old retries jumped ahead of already-ready work | Schedule by readiness time, then creation time and ID |
| Large Blob streams restarted from byte zero after read interruption | Use Azure SDK RetryReader with three bounded stream retries, ETag identity checks and range continuation |
| Download failures hid their underlying error | Record the error with storage credentials/signatures redacted |
| RECOVERED records were missing from the state selector; setup accepted three roots | Add RECOVERED filtering and require four roots in setup readiness |

## Live performance evidence

The inspected `.3mf` samples are ZIP-based containers with 30 entries. Each inspection originally caused 31 scanner calls. A member produced an engine error, keeping coverage incomplete and causing repeated full inspections with archive concurrency set to one. Sample downloads were under a second, while scan/admission wait accumulated and the transfer queue was empty. These fixes reduce duplicated work and worker blocking without reclassifying unknown content as clean. Engine exceptions still require a supported scan result or manual review.

A separate 3.5 GB CSV retry downloaded data, then failed before scanning. Two observed attempts lasted roughly 88 and 101 seconds despite a six-hour job timeout. The earlier implementation discarded partial captures after a stream failure. Resume support and retained underlying errors address that failure path; live completion must be checked independently rather than inferred from the historical CLEAN record for another upload version.

## Password management

The AD account button opens Change password. Current-password verification, confirmation, throttling, encrypted password-hash storage, an audit event and invalidation of previous sessions are included. No production password is changed automatically.

## Validation scope

Regression tests cover changed recovery bytes, bypass prevention, repeated share recovery, acknowledged enrichment, cancellation reporting, archive slot admission, same-job member reuse, retry scheduling, resumed byte ranges with ETag conditions, password verification and session invalidation. Browser checks include account confirmation/errors and existing desktop/mobile workflows. Final test results accompany the release.

The first race run was affected by sandbox socket restrictions and is not counted as a passing run. Dependency-advisory scans require successful network access; unavailable or partial advisory output is not treated as a clean result.

## Remaining operational boundaries

- External notifications remain deferred at the user's request.
- Customer workload/100 GB throughput validation requires the customer's representative files, storage and network. The synthetic resume test proves read continuation, not a large-file throughput guarantee.
- Upload stability is a heuristic when producers do not provide an atomic handoff. Paused uploads can appear stable.
- Share deletion has weaker atomic identity guarantees than leased Blob delivery; retain exclusive producer handoff and controlled destination writers.
- Scanner engine errors and inaccessible storage remain visible and fail closed; the application cannot guarantee a remote tag write while storage is unavailable.
- Recovery keeps the original destination snapshot for traceability; new jobs use the current profile destinations.

## Dependency corrections and final checks

The successful advisory scan identified reachable issues in the prior gRPC and SMB dependencies. gRPC was updated to v1.83.1 ([GO-2026-6348](https://pkg.go.dev/vuln/GO-2026-6348)); the SMB connector moved to the patched cloudsoda revision v0.0.0-20260609183447-7b96c35f5f4b ([GO-2026-5051](https://pkg.go.dev/vuln/GO-2026-5051)), with context-aware DialConn adaptation. The original unmaintained SMB module was removed by go mod tidy.

After these changes, `go test -race ./...`, `go vet ./...`, `govulncheck ./...`, and the complete npm dependency audit passed. The resumable-download test injects a broken stream and verifies continuation at byte 4 with If-Match preserved and the final hash matching.

The post-fix Go scan reports zero reachable vulnerabilities, with advisory matches still present in imported/required code that is not on an application call path. These are tracked as dependency hygiene rather than described as fully absent from the dependency graph.

Final validation also passed 16 desktop/mobile browser checks (including password controls and the Submitted timestamp) and live SDK/Azure safe, EICAR, archive and leased-routing checks in disposable test containers. These live tests did not modify the active customer job.
