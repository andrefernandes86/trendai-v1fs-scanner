# Host operation

The active console is served by cmd/local on port 8095. Configuration is entered inside the console. No Azure gateway URL is needed.

## Initial setup

Open the host URL and create the administrator password (12–72 characters). Add source, clean and quarantine Blob connections, then configure Vision One and create scan profiles. Account-key connections need an Azure account access key, not a full connection string. SAS source browsing requires read/list permissions; destination routing needs create/write/read. Provision containers separately in Azure. Connection testing verifies listing; actual routing verifies destination writes and content.

For cloud scanning, select the region associated with the API key. For local scanning, enter the existing File Security gRPC endpoint as host:port and select whether it uses TLS. A plain HTTP endpoint or ICAP listener will not work. A key is optional only when the local scanner is configured without authentication. Scans, not a settings save, verify actual scanner connectivity.

Profiles default to completion metadata. Upload completed files with metadata `v1fs-complete=true`; clear/reset the marker before any subsequent modification. If this is disabled, manual scanning accepts the currently committed version, and automatic scanning also requires two stable observations. This may not prove producer completion for SFTP/ADLS workloads.

## Durability and recovery

Persist V1FS_DATA_DIR. It contains scanner.db, SQLite WAL/SHM files, master.key, and instance.lock. Only one process may use it. On graceful shutdown the service cancels worker requests and waits for workers before closing the database. Interrupted jobs are requeued at startup and routing reuses persisted verdict/digest evidence. Retain source versions until all jobs finish. Jobs whose source changed are held/retried without promotion.

Back up the whole data directory with the service stopped, or use a SQLite-consistent backup process together with the existing master key. Do not regenerate a lost key. Never commit the directory. Existing job snapshots retain their encrypted credentials even after removing a connection; retain or purge backups according to your policy.

## Deployment

Build/run instructions are in README.md. Docker Compose provides restart: unless-stopped and a persistent named volume. For a direct process, use an OS service manager in your environment for reboot startup. The desktop-managed host process is persistent across chat turns but is not configured as a reboot-start service.

V1FS_TLS_CERT/V1FS_TLS_KEY enable HTTPS. The current host LAN URL uses HTTP, so only use it on a trusted network; TLS protects credential entry over broader networks. Host IPs and localhost are supported by the default anti-rebinding check; a hostname deployment would need an explicit allowlist extension.

## Verification

Run `go test -race ./...` and `go vet ./...` in backend, plus `npm run build --prefix web`. Tests use a fake Azure transport and scanner fixture to prove clean/quarantine routing, unknown-verdict holding, source replacement rejection, duplicate suppression and routing recovery without duplicate writes. They also test encrypted credential storage, API redaction, session lifecycle, CSRF rejection and restart persistence. Live Azure/Trend scans are not claimed until real user credentials are provided.

## Troubleshooting

- Azure connection failures: check account/container spelling, SAS expiry and list/read permissions. Destination routes also need create/write/read.
- Scanner failures: verify key permissions and region, or gRPC endpoint, TLS and the local service's authentication mode. Bounded retries eventually hold the job.
- Unknown verdicts: the service fails closed. Unsupported verbose-engine formats require review rather than automatic clean routing.
- Routing failures: confirm destination credentials, private container access and free host disk. The source remains preserved.
- Credentials changed: existing jobs use their original snapshot. Save a profile revision and submit again for a new credential/destination snapshot; do not force a job to clean.

## Scanner diagnostics

Vision One config offers **Test API key** and **Generate & scan EICAR**. Tests use the form's current endpoint and entered key, or the stored key only when the endpoint matches. Tests do not save draft settings. The key test scans a small benign text file because the SDK has no authentication-only operation. The EICAR action generates the canonical 68-byte pattern, submits it through the official SDK, and passes only on an explicit malicious verdict. See the [official EICAR test-file specification](https://www.eicar.org/download-anti-malware-testfile/).

Both actions show a redacted SDK invocation summary (endpoint, TLS, file content/size/SHA-256 and options) and the real parsed scanner response or error. This is not a raw HTTP/gRPC wire capture. Keys are redacted from request summaries, result fields and errors. The HTTP administration session is separate from scanner API-key authentication: scanner rejection appears in the diagnostic response without signing the administrator out. Local configurations without a key test connectivity, not key authentication.

The request has a 45-second timeout including waiting for a scan slot. Generated files are private temporary files, removed after testing, and never queued or routed into Azure Blob destinations. Diagnostics audit their outcome without persisting response payloads or keys. Unit tests use fixtures; a live check runs only when an authenticated administrator clicks an action.

## Azure connection diagnostics

The mount dialog can **List containers** using the current account and credentials before a container name is known. Returned names are selectable, with continuation support. **Test container** sends a read-only Blob listing request for the selected container/prefix. These tests work with unsaved form data and do not persist credentials or create files. A container name is the segment immediately after `ACCOUNT.blob.core.windows.net/` in a blob URL; it is distinct from the storage account name.

The console shows the actual SDK-generated Azure HTTP method, URL with SAS parameters removed, redacted authentication, response status, safe headers, and up to 256 KiB of the XML response body. Azure errors retain their code and request ID for troubleshooting, while stored keys, SAS signatures and Authorization signatures are redacted. Destination write access is only verified during real file routing. Account-wide container discovery requires account-level list permission; a container-scoped SAS can fail discovery but still pass a container test when its name is entered manually.
