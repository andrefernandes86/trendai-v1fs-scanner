# Large-file planning and downstream ownership — 2026-10-21

## Result

- Default sizing example: 12,000 files/day, 1 GiB average, 100 GB maximum, 180 seconds per 1 GiB file; alternate 3.5 GB / 600-second example.
- Timing scales proportionally with average/reference size. Baselines and CPU/RAM budgets are explicit assumptions, not vendor benchmarks. Host distribution uses an editable planning density rather than treating 32 scans per profile as a host limit.
- Local working space defaults to one captured copy. Destination retention input/output is removed.
- After completed delivery, downstream applications own files. Destination recovery, enrichment and automatic historical readback are removed from the runtime. Old API clients receive 409 before storage access, legacy queued recovery stops before handoff/download, and retries cannot reopen a completed delivered file. Incomplete delivery still finishes configured checks and source cleanup.

## Evidence

The recent 3,500,000,682-byte source completed CLEAN in one attempt. Recorded download was 202.21 seconds, scan 74.82 seconds, upload 269.24 seconds, and size/identity-only final checks 0.04 seconds. These observations informed a rounded illustrative large-file baseline; they are not a throughput guarantee for other formats, archives or storage paths.

Full Go race suite passed (localapp 85.139 seconds). Additional ownership/retry regression tests passed after the final retry guard. Go vet and production frontend build passed. All 20 desktop/mobile browser checks passed after restoring the review step during UI changes; the final sizing formula/density checks then passed all four targeted desktop/mobile tests. Guide screenshots were regenerated against an isolated instance with synthetic configuration.

Production deployment was performed with no scanning or routing jobs active; health check passed afterward. No delivered customer file was read, modified or deleted as part of validation or documentation capture.
