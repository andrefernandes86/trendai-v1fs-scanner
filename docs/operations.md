# Operations

Build/run instructions are in the root README. The current host listens on port 8095. Set `V1FS_DATA_DIR`, `V1FS_WEB_DIR` and `PORT`; optionally configure `V1FS_TLS_CERT` and `V1FS_TLS_KEY`. Use HTTPS for remote credential administration. The app accepts localhost or host-IP requests and checks request origins.

## Permissions and persistence

Source credentials need list/read/delete. Destination credentials need write/read and, for Blob result tags, tag permissions. Share destinations need directory creation, exclusive publication and staging cleanup. NFS needs hard-link support. Container/share discovery can require additional account/server permissions even if a known share is readable.

Back up the SQLite database, its WAL consistently, and master.key together using a coordinated backup or stopped service. Do not commit runtime data or credentials. A database without its key cannot be decrypted. Persistent data must survive upgrades; never reinitialize it to resolve configuration errors.

The current host runs the supervised Docker container with restart policy and persistent data. Do not start a second scanner against its database.

## Troubleshooting

- No scheduled jobs: verify automatic monitoring is enabled; read the profile's last source check and errors. Wait for a second unchanged observation. Completion markers are no longer required.
- Source-changed errors: verify actual concurrent writes; Azure ETag quotation differences are normalized.
- Unknown result: inspect File activity. Unknown files route to scan-failed and remain HELD for review, never clean.
- Transfer failure: verify destination read/write/tag permissions and staging support. Source is retained until verified transfer.
- Source deletion failure: verify delete permission and whether the file changed. The record retains its verified destination.
- SMB List shares failure with Test share success: share enumeration uses server RPC/IPC permissions and may be blocked independently of direct share access; discovery now strips the TCP port from the SRVSVC server name and explains enumeration permission failures.

Generated safe/EICAR test files enter the configured source and use the real monitor/scanner/routing pipeline. EICAR is a standard antivirus test pattern and is never executed. Diagnostic scanner buttons operate separately from routing. Test requests and responses redact credentials.

Existing unknown files created before the verbose TrendX parsing fix are historical results. Re-upload a copy to the source to scan under the fixed logic; record details now offer explicit failed-file recovery. Do not label old unknown records clean without rescanning their exact bytes.

## Deploy on the current host

Example console address: **http://scanner-host:8095**. Replace the example hostname and `/srv` paths below with your deployment values. Container: `trendai-v1fs-scanner-1`. Repository: `/srv/trendai-v1fs-scanner`.

From that repository, preserve the existing database and key by using the host override:

```bash
export V1FS_HOST_DATA_DIR=/srv/trendai-v1fs-data
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml up -d --build
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml ps
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml logs --tail 100 scanner
curl --fail http://127.0.0.1:8095/livez
```

For an upgrade, first keep a coordinated data/key backup and record the prior image ID. Rebuild and recreate using the same command and data path. Do not remove the data mount or run `down -v`. Sign in after deployment, confirm saved connections and profiles, and verify safe/EICAR routing. Health alone does not validate remote credentials. Roll back by restoring the prior image and recreating the same service; restore a coordinated backup only when a schema downgrade requires it. Preserve failed-state evidence before restoring.

The direct-binary and optional `deploy/` systemd files are alternatives for other installations, not the current host deployment. Never run both alongside the container on the same port/data directory.

## Container-first host deployment

The container independently supervises the management API and processing engine, with isolated SDK child processes for concurrent scanning. Use the normal named volume for a new deployment:

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail 100 scanner
```

To retain the current host's existing encrypted state, use the host override (the scanner runs as UID/GID 1000, matching its existing data ownership):

```bash
export V1FS_HOST_DATA_DIR=/srv/trendai-v1fs-data
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml up -d --build
```

Stop a previous foreground scanner before starting the container so port 8095 and the data lock are free. Do not run both against the same data. Inspect health with `docker compose ps` and `/livez`; verify actual safe/EICAR routing separately. Keep the persistent data mount through rebuilds; never use `down -v` as an upgrade step. Docker must be enabled at host boot; it is enabled on the current host. The earlier systemd application unit is optional for a direct binary deployment, not required for the container.

Set `V1FS_MAX_WORKERS=8` (1–32) when running Compose to control total engine capacity; then set **Schedule → Files scanned at once** per profile in the console. Scan slots cover download and scanning; transfer slots handle routing and finalization separately. Changing the global setting recreates the container; profile limits change live without interrupting active jobs. A profile above the global limit shares only available global slots.

The watchdog uses 20 seconds of startup grace, 5-second checks and 3 failed checks before restart. Optional V1FS_WATCHDOG_STARTUP_SECONDS and V1FS_WATCHDOG_INTERVAL_SECONDS settings can be used in controlled tests. A child gets SIGTERM and up to ten seconds before SIGKILL. Docker stop_grace_period is forty seconds. External scanner/storage outages do not trigger liveness restarts; they remain visible retry/assurance conditions. External notification delivery is deferred at the user's request.

Share sources need read, rename, mkdir and delete rights inside their source root. Reserve `.v1fs-claims` for the scanner account. Do not treat claimed files as lost: their original and private paths appear in record details and persist across restarts. Never manually clear claims while jobs are active. Customer load/scale validation is run separately by the customer.

Management `/livez` returns the API/database result with a separate engine field; it remains available during engine recovery. The Docker healthcheck requires both services. The engine publishes its progress heartbeat every second, with a 15-second freshness limit. Each service restarts independently; never delete queue/transfer evidence to recover a service. Use `docker compose logs` to distinguish `-serve` and `-engine` child PIDs. The browser prevents overlapping automatic refresh batches, and indexed history/read connections keep normal management reads independent of engine writes.

## Large files

The old 2 GiB application cap is removed. Profiles default to 100 GB original-file SDK submission, one concurrent file at least 1 GB and a six-hour per-attempt deadline. See [profile controls and resource behavior](poc-architecture.md#large-files-and-policy). The scanner may inspect selected ranges and impose format/extraction limits; successful submission is not proof of exhaustive byte/member coverage.

Use a persistent data disk with space for simultaneous captures, history and operational reserve. Capacity admission retains 5 GiB and defers capture when insufficient. The implementation conservatively also counts outstanding reservations, so it may wait before physically exhausting disk. Oversized routing still needs room to capture that file; changing the policy does not provision disk. A host with 170 GiB free cannot process two simultaneous 100 GB captures. Configure the large-file cap accordingly.

On engine restart, only its private captures directory is cleaned; scans re-download interrupted sources. Source and verified move records remain durable. Do not put customer uploads/backups in the engine-owned captures directory. An interruption during a large download can therefore incur another transfer; budget network/retry time accordingly.

The processing-deadline alert is separate from the maximum job duration. Set the alert high enough for expected large-file work while keeping a bounded per-attempt timeout. Disk shortage waits do not consume the scan attempt budget. Existing held/retry jobs retain their captured policy; new size-policy changes apply to newly queued work.

To investigate a file: search its name in File activity, inspect state, attempts, scan response and destination evidence. SCANNING includes source capture before SDK invocation. A terminal record and verified destination, rather than disappearance from the source alone, are the completion evidence.

## Archive inspection operations

See [archive limits and sandbox prerequisites](archive-inspection.md). The option defaults to off. No extra capabilities are required; Landlock and seccomp must be available. Unavailable confinement fails closed. Reserve original capture plus the configured expansion budget. Full SDK/member responses live in encrypted detail records; activity uses compact encrypted summaries. Workspace directories are engine-owned and removed after work or on restart. Profile changes do not rewrite queued snapshots.

## Transfer worker controls

`V1FS_TRANSFER_WORKERS` defaults to 4 (maximum 8), independent from `V1FS_MAX_WORKERS`. Profile transfer settings govern destination concurrency and Azure Blob block/request tuning. Lowering limits affects subsequent admissions. See [performance tuning](performance-tuning.md). A restart preserves the database/key volume and reconciles incomplete moves; an unuploaded temporary capture may be downloaded again. It does not delete history. Theme preferences live in each browser.
