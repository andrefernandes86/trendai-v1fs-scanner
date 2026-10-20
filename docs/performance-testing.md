# Performance testing

The stress harness reads an existing data directory in read-only SQLite mode, decrypts configuration in memory, and downloads latest successful destination copies from the last 24 hours. It checks each sample against the recorded SHA-256. It omits tool verification inputs and paths below folders; inspect its private `manifest.json` before executing to confirm the intended corpus. Existing failed records and stored user files are not deleted.

Build from `backend`: `go build -o /private/work/stress-runner ./cmd/stress`.

Prepare only: `stress-runner -data /private/data -out /private/work/run -profile PROFILE_ID`.

Run the real source scheduler: add `-execute`. By default, it uploads 1,000 inputs in a concurrent burst, waits for terminal jobs, then uploads another 1,000 in ten groups of 100 scheduled one second apart. `-scenario burst` or `-scenario paced` selects one scenario. Distinct prefixes prevent duplicate input names. The test does not change the profile, scanner or worker configuration. The selected profile must be enabled and have no bypass or ignore rules. These are real storage writes and real scanning requests, not mocked calls.

The regular test changes filenames/extensions while retaining the verified original bytes. Renaming HTML to PDF or ZIP does not convert the format. `-archives -execute` instead creates real ZIP archives, one per original sample, and sends those through the same scheduler. This supplementary mode uses one burst of the sample count.

For long runs, launch the harness in an independent container or service so a terminal interruption does not stop its orchestration. Mount the binary and production data read-only, with a separate writable output directory. A stopped harness does not stop the scanner or lose already-uploaded inputs; do not repeat a completed upload phase just to resume observation.

Generate sanitized metrics with `python3 scripts/stress-report.py --data /private/data --run /private/work/run --out /reports/run` (Python cryptography package required). It exports per-file CSV and aggregate JSON; no configuration snapshots, API keys, storage keys or full scanner responses are exported. Store reports according to customer filename/location privacy requirements.

Latency definitions: upload = client request duration; discovery = upload completion to job creation; queue = creation to first worker start; worker-to-response includes download, SDK serialization/connection and scanner call; routing = response to final job update; end-to-end = upload start to terminal update. Rolling intermediate reports contain pending jobs and must not be presented as final results. Scanner engine timestamps may have millisecond granularity and are not equivalent to full scan latency.

Record machine resources, health/restarts, profile timing, worker count, data sizes, upload timing and stage failures alongside results. Report verdict changes caused by content-based engines separately from transfer errors. Successful movement requires persisted checksum verification and COMPLETED move phase, including source deletion. A held terminal job is accounted for but is not a successful clean/malicious promotion.

After completion, `-check-prefix loadtests/RUN/SCENARIO/` performs an independent read-only source listing and writes `source-check.json`, without uploading anything. The report for the measured host run is [available here](performance-results-2026-10-20.md).
