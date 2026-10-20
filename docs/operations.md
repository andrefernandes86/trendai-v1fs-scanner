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
- SMB List shares failure with Test share success: share enumeration uses server RPC/IPC permissions and may be blocked independently of direct share access; improved diagnostics/fallback remains pending.

Generated safe/EICAR test files enter the configured source and use the real monitor/scanner/routing pipeline. EICAR is a standard antivirus test pattern and is never executed. Diagnostic scanner buttons operate separately from routing. Test requests and responses redact credentials.

Existing unknown files created before the verbose TrendX parsing fix are historical results. Re-upload a copy to the source to scan under the fixed logic; a dedicated failed-file reprocessing UI is pending. Do not label old unknown records clean without rescanning their exact bytes.

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

This is a foreground deployment; its lifetime depends on the terminal/process supervisor. A supported reboot-persistent service remains a backlog item. Do not create a second instance against the same data directory. Never copy runtime credentials or databases into GitHub.
