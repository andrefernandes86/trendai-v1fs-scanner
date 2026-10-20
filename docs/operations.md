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

The running console is **http://192.168.1.52:8095**. Container: `trendai-v1fs-scanner-1`. Repository: `/home/skynet/Documents/Codex/2026-10-19/files-pasted-by-the-user-vision/trendai-v1fs-scanner`.

From that repository, preserve the existing database and key by using the host override:

```bash
export V1FS_HOST_DATA_DIR=/home/skynet/Documents/Codex/2026-10-19/files-pasted-by-the-user-vision/work/trendai-host-data
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml up -d --build
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml ps
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml logs --tail 100 scanner
curl --fail http://127.0.0.1:8095/livez
```

For an upgrade, first keep a coordinated data/key backup and record the prior image ID. Rebuild and recreate using the same command and data path. Do not remove the data mount or run `down -v`. Sign in after deployment, confirm saved connections and profiles, and verify safe/EICAR routing. Health alone does not validate remote credentials. Roll back by restoring the prior image and recreating the same service; restore a coordinated backup only when a schema downgrade requires it. Preserve failed-state evidence before restoring.

The direct-binary and optional `deploy/` systemd files are alternatives for other installations, not the current host deployment. Never run both alongside the container on the same port/data directory.

## Container-first host deployment

The container includes an internal process supervisor/watchdog. Use the normal named volume for a new deployment:

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail 100 scanner
```

To retain the current host's existing encrypted state, use the host override (the scanner runs as UID/GID 1000, matching its existing data ownership):

```bash
export V1FS_HOST_DATA_DIR=/home/skynet/Documents/Codex/2026-10-19/files-pasted-by-the-user-vision/work/trendai-host-data
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml up -d --build
```

Stop a previous foreground scanner before starting the container so port 8095 and the data lock are free. Do not run both against the same data. Inspect health with `docker compose ps` and `/livez`; verify actual safe/EICAR routing separately. Keep the persistent data mount through rebuilds; never use `down -v` as an upgrade step. Docker must be enabled at host boot; it is enabled on the current host. The earlier systemd application unit is optional for a direct binary deployment, not required for the container.

The watchdog uses 20 seconds of startup grace, 5-second checks and 3 failed checks before restart. Optional V1FS_WATCHDOG_STARTUP_SECONDS and V1FS_WATCHDOG_INTERVAL_SECONDS settings can be used in controlled tests. A child gets SIGTERM and up to ten seconds before SIGKILL. Docker stop_grace_period is forty seconds. External scanner/storage outages do not trigger liveness restarts; they remain visible retry/assurance conditions. External notification delivery is deferred at the user's request.

Share sources need read, rename, mkdir and delete rights inside their source root. Reserve `.v1fs-claims` for the scanner account. Do not treat claimed files as lost: their original and private paths appear in record details and persist across restarts. Never manually clear claims while jobs are active. Customer load/scale validation is run separately by the customer.
