# Management isolation and parallel scan validation — 20 October 2026

## What changed

The management API and processing engine now run as independent supervised processes in one container. Each scan uses an isolated SDK child process, permitting safe parallel requests without mixing endpoint environment settings. The management API has its own SQLite connection pool; WAL and history indexes keep reads independent of worker activity. Browser refresh batches cannot overlap. Profiles control simultaneous active files, bounded by the global worker pool.

A real-path test also exposed duplicate admission when a profile revision changed during a backlog. Admission now reuses an existing active job for the same profile, storage root and source version, preserving the original scan/routing snapshot. A regression test and the repeated live limit-change test cover that fix.

## Results

The repeat test used an isolated API/engine instance with **2,000 synthetic historical rows**, a newly created temporary Azure source container, the configured real cloud scanner and distinct test prefixes in the existing destination containers. Production profiles and source contents were not modified. Inputs were **96 generated benign text files and 48 EICAR antivirus test files**. The profile limit started at one and was raised to four after twelve completed moves.

- 144 inputs → 144 jobs → 144 unique filenames; no duplicate jobs after the profile update.
- 96 CLEAN/COMPLETED and 48 MALICIOUS/QUARANTINED results.
- All 144 moves reached persisted COMPLETED verification/deletion phase with SHA-256 and CRC32C evidence. The empty temporary source container was removed after the test.
- Observed maximum SCANNING count: **1 with limit 1; 4 with limit 4**. This is a scanning-stage measurement, not a claim that all time was spent inside the engine.
- **1,080 authenticated API requests; zero failures** during discovery, scanning and routing. Requests were made in concurrent batches of eight, approximately twice per second.

| Endpoint | Requests | Median | p95 | Maximum |
|---|---:|---:|---:|---:|
| Session | 135 | 2.98 ms | 4.48 ms | 12.40 ms |
| Profiles | 135 | 2.69 ms | 4.11 ms | 9.94 ms |
| Storage connections | 135 | 2.59 ms | 3.92 ms | 9.24 ms |
| Audit | 135 | 4.70 ms | 6.89 ms | 14.03 ms |
| Status | 135 | 3.96 ms | 5.41 ms | 14.42 ms |
| Activity, 100 records | 135 | 7.71 ms | 15.06 ms | 16.77 ms |
| Assurance | 135 | 6.54 ms | 8.53 ms | 15.46 ms |
| Statistics | 135 | 13.80 ms | 19.10 ms | 24.18 ms |

These are local-host timings for this workload and do not establish customer-scale capacity or internet response latency. Percentiles use nearest rank. The original 1,000-file burst and paced tests describe the earlier serialized runtime; see [their report](performance-results-2026-10-20.md).

## Fault and regression checks

The isolated watchdog test killed the engine, froze its replacement with SIGSTOP, and then killed the API. Engine recovery preserved the management PID; API recovery preserved the engine PID. The database reopened and both services returned healthy. Backend race tests and vet passed; desktop/mobile browser checks verified queue statistics, responsive layout and saving a simultaneous-scan value of four.

Unit tests verify atomic per-profile limits, admission for another profile behind a saturated profile, live increases/decreases, active-source deduplication across profile revisions, and management reads while an engine WAL write is open. Opening the management API does not reset SCANNING jobs owned by the engine.

## Reproduce safely

Use `backend/cmd/runtimecheck` to prepare a **new, isolated** data directory from read-only source configuration; it creates its own temporary Azure source container and synthetic history. Never use the production data directory as its target. Source account credentials must permit temporary container creation.

```bash
cd backend
go build -o /private/work/runtimecheck ./cmd/runtimecheck
/private/work/runtimecheck -from /production/data -to /private/work/check-data -profile PROFILE_ID
```

Start a separate container with that target directory mounted as `/data`, publishing its port only at `127.0.0.1:18099`. Run `scripts/probe-runtime.cjs` in a test Node environment with access to that local port and a writable `RUNTIME_PROBE_OUTPUT`; it creates the isolated test administrator and changes only the `runtimecheck` profile. Then upload the test inputs:

```bash
/private/work/runtimecheck -from /production/data -to /private/work/check-data -profile PROFILE_ID -mode upload
```

After the probe reports all 144 finalized, stop the test instance and run `-mode cleanup` with the same arguments. Cleanup refuses a non-empty source or a container outside the test namespace. Keep credentials and generated data private. The separate `scripts/test-watchdog.py` fault test accepts `TEST_BINARY` and uses a fresh temporary directory, without production credentials.
