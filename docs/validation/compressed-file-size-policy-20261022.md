# Compressed-file size policy validation — October 22, 2026

Tested the public standard container at revision `8109550cd960ca40adcf90d4d102d5006bb61292` on the .52 host. Both `latest` and `bash` were anonymously pulled and their revision labels verified before testing. Persistent application data was backed up and preserved. This validation did not redeploy ACI.

## Implemented policy

Regular files remain eligible for SDK analysis up to the configurable 100 GB decimal maximum. Compressed files have a separate configurable limit with a hard ceiling of 2 GB (2,000,000,000 archive bytes). The default oversized action is hold. Each type independently supports hold, move to clean, move to scan failed, or move to a saved storage connection/subfolder outside the source root. Moves are NOT SCANNED, including clean-destination bypasses.

Common extensions permit early hold. Captured signatures also catch recognized renamed archives before analysis; the SDK child independently blocks oversized archives. Legacy profiles/snapshots default to 2 GB/hold. ZIP-based documents use the compressed-file cap. Explicit file rules retain their existing precedence.

## Exact 10 GB fixture and live outcomes

Reused `ten-csv-10gb-20261022.zip`: exactly 10,000,000,000 bytes, 10 synthetic CSV entries, ZIP_STORED, SHA-256 `8b7628d34347f8c99b77175458c2011fcfdef9e1f6fc75bd9f8024630a92ea9f`. A dedicated Azure source and manual profile avoided overlapping automatic source processors. Setup reused repeated Azure block references; committed size remained exactly 10 GB. Application capture and delivery transferred the complete file normally.

1. **Hold:** HELD / NOT_SCANNED, with the compressed-size policy reason. No capture download, SDK analysis, or destination move occurred.
2. **Explicit clean bypass:** changed only the test profile's compressed-file action, creating a new policy revision/job. The complete source was captured and delivered as one original ZIP. Final state COMPLETED; verdict OVERSIZED_CLEAN, never CLEAN. Matched policy `compressed_size_limit`.
3. Captured SHA-256 matches the fixture. The completed move record includes SHA-256, CRC32C, source/destination identity evidence and the compressed policy rule. Azure destination properties independently confirm exactly 10,000,000,000 bytes, and native index tags confirm `scanned=false`, `verdict=not_scanned`, `reason=oversized`.
4. Both jobs have zero scan-results, scan-details, scan-summaries and scan-timing rows. The 10 GB archive never reached the SDK. The first hold demonstration was acknowledged after the successful follow-up move, preserving its initial evidence without leaving a stale held record. The test profile was removed from the console during transfer; the active job completed using its saved policy snapshot, and the profile was not restored.

Full destination-content readback was disabled, matching the original policy. Destination length and index tags were checked after completion; destination file contents were not read back. The test profile used 8 upload requests with 16 MiB blocks to shorten validation. Production profiles/defaults were unchanged; these timings are not a default-network throughput benchmark.

## Timings

| Test | Stage | Seconds |
|---|---|---:|
| Clean bypass | download | 493.975 |
| Clean bypass | queue_wait | 0.256 |
| Clean bypass | transfer_wait | 0.141 |
| Clean bypass | upload | 316.843 |
| Clean bypass | verify | 0.044 |
| Hold | queue_wait | 0.549 |

## Checks and release

- Full Go race suite passed; final localapp run including the manual-delivery regression: 97.369 seconds.
- Go vet, TypeScript checks and production web build passed.
- All 22 Playwright tests passed across desktop and mobile, including policy persistence and invalid archive caps/source destinations.
- Boundary coverage: regular 100 GB inclusive; compressed 2 GB inclusive; over-limit actions and renamed ZIP signatures; SDK-child hard-cap enforcement.
- Hold/clean/failed/custom routing tests verify source retention or complete delivery and NOT SCANNED evidence, with SDK invocation forbidden.
- GitHub CI, vulnerability check, secret scan and both image publications passed.
- Live unhealthy engine samples: 0; observed engine PIDs: [16].
- Light/dark size-policy, custom-routing and Review screenshots were refreshed using an isolated documentation instance.

Explicit administrator delivery without scanning also remains available for oversized archives. A regression test confirms it bypasses the SDK while retaining UNKNOWN, never CLEAN; manual scan retries still obey the cap.
