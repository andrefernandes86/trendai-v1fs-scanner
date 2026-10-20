# Host-based Blob scanning

The earlier Azure gateway design was removed from the active application at the user's request. The Go host process serves both the React console and a same-origin authenticated API. It connects directly to Azure Blob Storage and to the selected Vision One scanner. Azure infrastructure provisioning and Entra identity are no longer required.

## Configuration and secrets

SQLite WAL stores configuration, persistent queue records, immutable job snapshots, and audit records. An exclusive OS file lock prevents concurrent host processes from claiming the same database. The data directory is mode 0700. An AES-256-GCM key in master.key (mode 0600) encrypts configuration and job snapshots, including account keys, SAS tokens and scanner credentials. Secrets are never returned to browser clients or written into audit details. Administrator password hashes use bcrypt. Sessions use randomly generated tokens, stored as SHA-256 hashes, with HttpOnly/SameSite cookies and a 12-hour expiry. Mutations reject mismatched browser Origin values. Login attempts are throttled. The API rejects non-IP Host headers except localhost to reduce DNS-rebinding exposure.

Backup protection still depends on the host account: possession of both the data directory and master key permits decryption. HTTPS is supported with explicit certificate/key paths. The currently configured HTTP LAN endpoint does not encrypt browser-to-host traffic.

## Direct storage connections

Each logical mount points to one Azure storage account/container and optional prefix. Users provide either account names and container names or a full Azure container resource ID. Authentication supports account keys or SAS tokens. The Azure SDK signs storage requests; credential-bearing URLs and SDK error details are not exposed in console errors.

Mounting makes containers accessible through the application explorer; it does not create Linux filesystem mounts. The explorer uses continuation markers and lists 200 objects per request. Each profile chooses an independent source and distinct clean/quarantine containers, optionally in other accounts with their own credentials.

## Processing

Manual submissions and the 30-second monitor feed a durable SQLite queue. Automatic discovery observes an unchanged ETag across at least 30 seconds and requires a last-modified age of at least 60 seconds. The monitor checks the ETag again before queueing. Profiles default to requiring producer-set `v1fs-complete=true` metadata; producers must set this only when the upload is finished and clear it before modification. Without a completion contract, stability alone cannot prove completion for SFTP/ADLS.

Identity includes profile ID/revision, source account/container/key, ETag and version. INSERT OR IGNORE suppresses duplicate jobs. Each job encrypts a snapshot of source, destinations, scanner settings and profile. Profile revisions prevent configuration changes from silently changing in-flight destinations.

Two processing workers claim jobs transactionally. Scanner initialization and scan invocation are serialized to isolate the official SDK's process-level endpoint/TLS environment overrides. Source downloads are version-bound with If-Match and exact-size verification and saved into private temporary files. The scanner receives those exact bytes. Only explicit supported clean or malicious verdicts route. Unknown formats, engine errors and invalid responses hold. Files larger than 2 GiB hold under the host's current size policy.

Destination object names contain the deterministic job ID and original key. Writes are create-only, followed by full SHA-256 readback verification. Redelivery verifies existing destinations rather than overwriting. A previously persisted verified verdict/digest is reused after a routing interruption; recovery does not replace it with a new verdict. Originals remain unchanged. Malicious files only route to the profile's quarantine destination, which administrators must restrict in Azure.

Jobs retry up to five times with bounded exponential backoff and then remain HELD. Held/retrying jobs can be requeued from the console. On startup, interrupted SCANNING/ROUTING jobs are requeued with their original encrypted snapshot. Settings changes apply to new jobs; retry preserves original configuration. Save a new profile revision and submit again if a different destination or credential snapshot is required.

## Vision One

Cloud mode uses the official Go SDK with direct Vision One connectivity and a selected supported region. Local mode uses the SDK's documented TM_AM_SERVER_ADDR override for an existing File Security gRPC endpoint; it is not a generic HTTP or ICAP adapter. TLS certificate checks remain enabled when TLS is selected. Cloud credentials are not automatically transferred to a newly selected local endpoint. SDK reference: https://github.com/trendmicro/tm-v1-fs-golang-sdk

## Limits

This is a single-host service, not a distributed Azure gateway. Worker autoscaling, Microsoft Entra, Azure Files, automatic source deletion, retention enforcement, SDK quarantine encoding, alerts and arbitrary file downloads are outside the revised implementation. The telemetry reflects actual local job states. Live Azure credential tests and scans require user configuration; automated routing tests use controlled fixtures and do not measure Vision One throughput.
