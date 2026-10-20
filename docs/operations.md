# Operations

Build/run instructions are in the root README. The current host listens on port 8095. Set `V1FS_DATA_DIR`, `V1FS_WEB_DIR` and `PORT`; optionally configure `V1FS_TLS_CERT` and `V1FS_TLS_KEY`. Use HTTPS for remote credential administration. The app accepts localhost or host-IP requests and checks request origins.

## Permissions and persistence

Source credentials need list/read/delete. Destination credentials need write/read and, for Blob result tags, tag permissions. Share destinations need directory creation, exclusive publication and staging cleanup. NFS needs hard-link support. Container/share discovery can require additional account/server permissions even if a known share is readable.

Back up the SQLite database, its WAL consistently, and master.key together using a coordinated backup or stopped service. Do not commit runtime data or credentials. A database without its key cannot be decrypted. Persistent data must survive upgrades; never reinitialize it to resolve configuration errors.

The current manual foreground host process is not a reboot-persistent service. Docker Compose is available, but an automatic system service remains pending. Stop the previous process before starting another; a single-instance lock protects the database.

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

The checked-out application is at `/home/skynet/Documents/Codex/2026-10-19/files-pasted-by-the-user-vision/trendai-v1fs-scanner`. Persistent customer state is in the sibling `work/trendai-host-data` directory. The console is served at `http://192.168.1.52:8095`.

Build frontend assets from the repository root:

```bash
npm ci --prefix web
npm run build --prefix web
```

Build the backend using a compatible Go installation (see `backend/go.mod`):

```bash
cd backend
go test ./...
go build -o ../../work/trendai-v1fs-local.next ./cmd/local
```

On this host a downloaded Go installation is available at `../../work/toolchain/go/bin/go` relative to `backend`; the existing build uses `GOPATH=/tmp/trendai-go` and `GOCACHE=/tmp/trendai-gocache`.

Stop the running instance cleanly before replacing its executable. From the parent workspace directory, replace the binary and start it with the existing data directory:

```bash
mv work/trendai-v1fs-local.next work/trendai-v1fs-local
V1FS_DATA_DIR="$PWD/work/trendai-host-data" \
V1FS_WEB_DIR="$PWD/trendai-v1fs-scanner/dist" \
PORT=8095 ./work/trendai-v1fs-local
```

Verify `/healthz`, sign in, confirm the last source check advances, and run a benign test file through a profile to verify a real CLEAN result, destination checksum verification and source removal. An HTTP health response alone does not prove the scanner or storage credentials work. Use EICAR separately to verify malicious routing. Check the job and audit records for deletion errors. Retain a rollback binary and a consistent database/key backup; do not assume database migrations are automatically reversible.

This is a foreground deployment; its lifetime depends on the terminal/process supervisor. A restricted systemd service and root installer are provided in deploy/. Activate them on the host as administrator. Do not create a second instance against the same data directory. Never copy runtime credentials or databases into GitHub.

## Persistent service and rollback

From the repository root, after building and backing up data/key:

```bash
sudo APP_USER=skynet deploy/install-systemd.sh
# Stop the existing foreground process first to release the single-instance lock.
sudo systemctl start trendai-v1fs-scanner
sudo systemctl status trendai-v1fs-scanner
sudo journalctl -u trendai-v1fs-scanner -n 100
```

The installer enables startup at boot but does not kill a foreground instance. Service activation requires real host administrator privileges; this sandbox cannot activate it. Source credentials need delete permission; Blob destinations additionally need lease/tag permissions. For share handoff, producers must stop modifying a transferred file and destination writers must be controlled.

For rollback, stop the service, restore the previous binary/frontend together and restore a coordinated data/key backup if a schema downgrade is needed, then restart and run health plus safe/EICAR end-to-end checks. Preserve the current failed state for investigation rather than overwriting your only backup.

See [reliability](reliability.md) for stage budgets, CRC32C evidence, independent source-delete retries, reconciliation, recovery, retention and alert delivery prerequisites.

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
