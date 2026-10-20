# Large-file change validation — 20 October 2026

Build source: commit 659cd62. Application image: 4f42b252a3b1. Current PoC host: port 8095. Original data volume, key, settings and history preserved.

## Automated checks

- Backend full suite and go vet passed.
- Local application race suite passed.
- Sparse 100,000,000,000-byte source file admitted through share metadata and queue path; exact boundary scans, above-boundary default holds. This verifies 64-bit admission only, not 100 GB scanning throughput.
- Oversized hold/clean/failed policies checked with a small threshold: no scanner call, no invented scan result, correct not-scanned tags, SHA-256/CRC32C move evidence and source retention/removal as appropriate.
- Large-file admission cap checked: second large file waits while a small file behind it remains eligible.
- Impossible disk reservation rejected without leaking budget.
- Historical inventory error linked to an existing exact-version durable job.
- Desktop/mobile browser coverage passed for profile controls and persistence, full-history pagination, sizing model and vocabulary. The shared-state test was corrected to check default size in a new profile rather than a profile edited by the previous browser run.
- Console/API and all eight engine workers healthy after deployment.

## Live verification

The previously rejected VPLE.zip (3,727,527,135 bytes) acquired durable job 6c66700d1aa7380a1fdbbb9e7330ed56bd9df802086d78394d87a0b4aa5226a3 at 21:09:46 UTC. Its first attempt entered SCANNING (which includes source capture). Historical unaccounted inventory count dropped from 20 to zero through exact-version accounting and successful admission.

During capture, container memory samples were approximately 36–74 MiB while the capture grew beyond 1.8 GiB; management and engine liveness remained healthy. These are point observations, not a peak-memory benchmark. Final SDK/routing outcome must be read from File activity and verified move evidence. A queued/capturing file must not be reported as successfully scanned.

## Validation boundaries

No full 100 GB end-to-end or customer-scale soak certification is claimed. SDK outcomes remain subject to scanner inspection and format/extraction limits. The original file is not truncated or split by this application. Archive extraction was discussed but not implemented. Customer validation should include supported large documents, representative archives, insufficient disk, scanner timeout, interrupted transfer/restart and verified deletion under load.
