# trendai-v1fs-scanner

A host-based Azure Blob, Azure Files, SMB and NFSv3 scanner with a React management console and the official Trend Vision One File Security Go SDK. The management API and scanning engine run in separate supervised processes inside one container. There is no external gateway, Event Grid, Service Bus, Azure deployment, or Entra setup requirement.

## Start here

**New user? Follow the [illustrated step-by-step user guide](docs/user-guide.md)**: connect storage, configure scanning, create a profile, test safe/EICAR routing, monitor files and export results. No coding is required to use the console.

- Current host: [open the console](http://192.168.1.52:8095).
- Administrator: [deploy, back up and upgrade](docs/operations.md#container-first-host-deployment).
- Technical reference: [architecture](docs/architecture.md), [profile options](docs/console.md), [reliability](docs/reliability.md).

## Console workflow

1. Open the host URL and create the administrator password on first use.
2. **Storage connections:** choose Azure Blob, Azure Files, SMB or NFSv3. Azure uses account keys/SAS, SMB uses username/password/domain, and NFSv3 uses server/export plus UID/GID. Credentials are encrypted on the host and omitted from API responses. Test and browse each saved connection.
3. **Vision One config:** enter the API key. Choose **Cloud** and its region, or **Local** and the existing File Security gRPC service's `host:port`. Local TLS is configurable; certificate verification stays enabled with TLS.
4. **Scan profiles:** create multiple profiles, each with a source connection and separate clean, malicious and scan-failed destination connections/prefixes. Set detection options and optional automatic monitoring.
5. **Storage explorer:** browse real containers and shares, select a profile and up to 100 files, then submit scans. Follow verdicts and verified destinations in **File activity**.

Source, clean, malicious and scan-failed storage must be four distinct, non-overlapping roots. Automatic monitoring scans only the source, at a per-profile interval of 10–86400 seconds (default 30). It waits for unchanged identity across checks, at least 10 seconds apart. No completion marker is required. A paused upload can still appear stable.

Clean results go to clean storage, malicious results to malicious storage, and unknown/exhausted scanner failures to scan-failed storage for review. Transfers are read back and SHA-256 verified before the unchanged source is deleted. Delete failures are shown as held records with the verified destination retained. Blob deletion uses an ETag condition; SMB/NFS use identity and digest checks and do not offer the same atomic identity guarantee.

New destination filenames use `original-name_<job-id>.ext`, e.g. `report_<job-id>.zip`. Files retain their original bytes and format: the app does not create ZIP archives or add archive passwords. Existing archive passwords belong to the uploader and cannot be recovered by the app. Earlier transfers retain their previous destination paths.

The Overview, File activity and Audit log pages offer browser-persisted auto-refresh settings. Overview shows Pending scans, Scanning now and rolling minute/hour/day/30-day counts. CSV export includes the entire job history; the activity view offers filtered, paginated history. See [console usage](docs/console.md) and [pending work](to-do.md).

## Run directly

```
npm ci --prefix web
npm run build --prefix web
cd backend
go build -o ../scanner ./cmd/local
cd ..
V1FS_DATA_DIR=./data V1FS_WEB_DIR=./dist PORT=8095 ./scanner
```

Open `http://HOST_IP:8095`. Use the host IP or localhost; arbitrary Host headers are rejected. The server can terminate HTTPS directly with V1FS_TLS_CERT and V1FS_TLS_KEY. Configure HTTPS before using this console across untrusted networks.

Alternatively run `docker compose up -d --build`; the persistent `scanner-data` volume contains the encrypted database and encryption key. Back up both together. An initialized database without its key is rejected.

## Verify

```
cd backend
go test -race ./...
go vet ./...
```

Tests cover secret encryption/redaction, authentication/session invalidation, cross-origin rejection, settings persistence, single-instance locking, concurrent duplicate submission, storage routing, source replacement, and replay without duplicate destination writes. Storage and scanner fixtures are simulated; they do not claim real Azure or Vision One throughput or credential validation. Production scanning uses real SDKs and no simulator is exposed in the console.

See [architecture](docs/architecture.md) and [operations](docs/operations.md).

## Product architecture and deployment guide

The product comprises a React console, a Go API/scheduler, a durable SQLite job queue, direct storage connectors and the official Vision One scanning SDK. Profiles discover only their source, capture stable file versions, scan them, route by verdict, verify destination size/SHA-256, then attempt removal of the unchanged source. Unknown results remain isolated for review. See [architecture](docs/architecture.md) for components, state and trust boundaries, [console usage](docs/console.md) for setup and operation, and [operations](docs/operations.md#deploy-on-the-current-host) for exact deployment paths and commands for the current host.

## Reliability controls (implemented)

Profiles now expose quiet periods, temporary ignore patterns, exclusion/hold rules with preview, independent scan/transfer/delete retry limits, recovery intervals/budgets and processing deadlines. Exclusions reach clean storage as EXCLUDED / NOT SCANNED. Full source-version inventory, assurance alerts, filtered/paginated history and previewed retention make unresolved work visible.

Verified moves persist CRC32C and SHA-256 evidence before source deletion. Blob finalization holds a renewable destination lease and conditionally deletes the captured source ETag. Share sources are automatically handed off into a persisted scanner-private claim namespace; share destinations still require controlled writers. Failed-file recovery and historical detection enrichment operate on recorded destination bytes, with linked audit history.

Read the [reliability guide](docs/reliability.md) for retry defaults, recovery semantics, integrity phases and limitations. Use the supervised container with Docker restart policy for reboot persistence; see [container deployment](docs/operations.md#container-first-host-deployment). The application cannot guarantee files that disappear between polls, enforce third-party writer behavior, or deliver external alerts without a configured monitoring destination.

Run browser checks against an isolated instance with `PLAYWRIGHT_BROWSERS_PATH=/tmp/trendai-browsers npm run test:e2e --prefix web` after installing Playwright Chromium. Default E2E URL is port 18096; override with E2E_BASE_URL. Never point these setup/configuration tests at production data.

## Container availability

The image supervises the management API and processing engine independently. SDK calls use isolated child processes for safe parallel scanning. Configure Simultaneous scans in each profile (default 2); the shared engine defaults to 8 worker slots, configurable with V1FS_MAX_WORKERS (1–32). Engine recovery leaves the console available. Docker handles container exit and host boot via `restart: unless-stopped`. `/livez` reports API/database liveness plus engine status; container health requires both services. External storage/scanner failures use normal processing retries. Share inputs are atomically claimed before scanning, and claimed ownership survives restart. External notifications remain deferred; customer-scale testing is owned by the customer.

### Performance validation

See [performance testing](docs/performance-testing.md) for the real-source 1,000-file burst, 100-files-per-second batches, supplementary genuine ZIP tests, and sanitized latency/verification reports. Renamed-extension load samples retain their original bytes; they are not format conversions.
