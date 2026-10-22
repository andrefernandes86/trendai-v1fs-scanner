# Large CSV ZIP tests — October 22, 2026

Status at 18:08 UTC: both fixtures submitted on the local .52 host, not ACI. The 1.8 GB test completed clean delivery. Two completed 10 GB SDK requests returned ATSE -82; a third attempt is active and further queued retries will be dismissed. Native cloud SDK in us-east-1.

## Fixtures

Both ZIPs contain 10 synthetic, valid CSV entries. Entries are ZIP_STORED (no compression), so the requested size is the actual archive size, not its expanded size. Files are fully allocated, not sparse. ZIP entry CRCs were checked. The 10 GB file uses ZIP64 directory records. Sizes use decimal GB.

- `ten-csv-10gb-20261022.zip`: 10,000,000,000 bytes; 10 CSVs; SHA-256 `8b7628d34347f8c99b77175458c2011fcfdef9e1f6fc75bd9f8024630a92ea9f`.
- `ten-csv-1-8gb-20261022.zip`: 1,800,000,000 bytes; 10 CSVs; SHA-256 `65daf51c0547ee8ddca576f3cb96f3b9c16cfca39c4794cb556c8fc6f78576bc`.

## Execution

A dedicated Azure source container and manual test profile isolate the files from the overlapping local/ACI sources. Synthetic repeated blocks were reused through Azure's supported block-list mechanism to shorten fixture upload; committed blob sizes are exact. The scanner still downloads all archive bytes normally. Fixture-upload timing is not a customer WAN-throughput measurement.

The saved scanner settings were cloned: 100 GB maximum, 6-hour per-attempt timeout, initial scan plus 3 retries, native archive scanning, optional local archive inspection disabled, destination content readback disabled. One large file is admitted at a time for this test profile.

## Pre-existing interruption found during the test

Before SDK analysis, watchdog restarts discarded partial downloads. The heartbeat publisher originally shared the busy writer connection; it now uses an independent read-only connection. Full Go race tests and vet passed. That alone did not resolve all warnings: an inventory reconciliation query scanned the profile's job history for every unmatched inventory row and occupied the sole writer connection. On a consistent database copy, the existence lookup took 14.811 seconds before a `(profile_id,key,created_at DESC)` index and 0.01454 seconds after it. The index was applied live at approximately 17:45 UTC, without restarting the active download. Query-plan regression coverage was added.

The recorded attempts include watchdog restarts, one deliberate deployment restart, and one intentional SIGQUIT for stack diagnosis at about 17:38 UTC. These are not six SDK attempts: the file had not reached SDK analysis. The input source remained intact throughout. Runtime samples preserve the interruptions.

A successful submission or zero detections alone does not prove all archive content was inspected.


## First 10 GB SDK response

The uninterrupted capture download took 837.664 seconds. The captured SHA-256 exactly matches the original fixture. SDK analysis took 70.352 seconds and returned ATSE error code `-82`, message `ErrorOccur: pfcb_status=-82`, with `rsSize: 10000000000` and the correct original filename. No detections were reported, but the error prevents a successful clean verdict. The app kept `UNKNOWN` and scheduled its configured scan retry; it did not promote the file to clean storage. The exact meaning of this engine code has not been established from this response.

The 1.8 GB submission used its own manual test profile (`profile-largezip-20261022-18`) so the 10 GB retry does not prevent the comparison. The profiles use the same scanner and policy defaults, each with one large-file slot. The original 10 GB job's retries remain enabled and can share bandwidth with the comparison.


## 1.8 GB result

The capture SHA-256 exactly matches the original fixture. Download took 421.598 seconds while sharing bandwidth with the 10 GB retry. SDK analysis took 119.329 seconds and returned `CLEAN`, no detections, and no ATSE/TrendX errors. The original archive completed delivery as one file to the configured clean destination. Destination full-content readback remains disabled, matching the original saved policy.

## Operational observations

- The 10 GB SDK retry repeated the same ATSE `-82` error in 82.749 seconds. The job remained `UNKNOWN`, with no clean delivery. Two completed SDK analyses establish reproducibility here; the exact limit or engine cause is unconfirmed.
- Scan retry downloads the complete source again rather than preserving a failed-analysis capture. Large inputs therefore amplify retry network and disk costs.
- A third 10 GB attempt was already active before dismissal. A guarded local test watcher will dismiss only this test job after it next returns to `RETRY_PENDING`, preserving its source and error history; it will not interrupt active processing or change saved retry policy.
- Peak sampled Docker working set during the first SDK analysis was 1.157 GiB. Peak sampled scan subprocess RSS was 121,064 KiB (~118 MiB). Docker working set and process RSS are different metrics; these are sampled peaks, not hard resource bounds.
- No unhealthy engine samples were observed after the inventory index was applied through the latest collected sample. Full Go race suite passed in 103.654 seconds, and vet passed. Fix committed as `02fc733`.
- The data is synthetic and highly repetitive. These results characterize these two fixtures and this scanner configuration; a clean response does not independently prove exhaustive member coverage for arbitrary archives.


## Completed delivery

1.8 GB job `bc7a05f40f7927b9cde64632e1ad424d5a7b4b51085e98b0b79b03fd26170aa7` reached `COMPLETED` at `2026-10-22T18:08:01.09514955Z`, with no error. Its recorded digest is `65daf51c0547ee8ddca576f3cb96f3b9c16cfca39c4794cb556c8fc6f78576bc`. Destination content was not read after handoff.

Recorded timings (seconds):

| Fixture | Stage | Seconds |
|---|---|---:|
| ten-csv-10gb-20261022.zip | queue_wait | 22.067 |
| ten-csv-10gb-20261022.zip | download | 1364.920 |
| ten-csv-10gb-20261022.zip | scan | 153.101 |
| ten-csv-1-8gb-20261022.zip | queue_wait | 1.101 |
| ten-csv-1-8gb-20261022.zip | download | 421.598 |
| ten-csv-1-8gb-20261022.zip | scan | 119.329 |
| ten-csv-1-8gb-20261022.zip | transfer_wait | 0.526 |
| ten-csv-1-8gb-20261022.zip | upload | 279.539 |
| ten-csv-1-8gb-20261022.zip | verify | 0.043 |

The 10 GB timing totals include repeated complete downloads and SDK attempts, but not the downloads discarded by engine restarts before timings were persisted. Use the first-attempt figures above for the first complete download/analysis. 1.8 GB wall time includes bandwidth sharing; these are not isolated throughput benchmarks.
