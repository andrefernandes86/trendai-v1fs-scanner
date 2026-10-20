# Architecture

The React/Vite console and authenticated Go API run on one host. SQLite stores configuration, jobs, scan timestamps, observations and audit records. Credentials and immutable job configuration snapshots are encrypted with AES-256-GCM using the host master key. Administrator passwords use bcrypt and sessions use HttpOnly cookies. Back up the database and master key together.

## Storage and scheduling

Connections support Azure Blob, Azure Files, SMB2/3 with signing, and NFSv3 TCP AUTH_SYS. They are application connections, not privileged operating-system mounts. Azure credentials use account keys or SAS; SMB supports user/password/domain; NFS uses UID/GID. Discovery permissions may differ from direct access permissions.

Each profile has one source and distinct clean, malicious and scan-failed destinations. Only the source is automatically listed. Intervals default to 30 seconds and allow 10–86400 seconds. Files must remain unchanged across observations at least 10 seconds apart. Completion markers are not required. Stability is a heuristic, not proof against paused uploads. Azure list/property ETag comparisons normalize quotation formatting while downloads/deletes use the original server ETag.

## Scan and routing

Two workers drain the durable job queue. The official Trend Vision One Go SDK connects to a regional cloud scanner or local gRPC scanner. Calls that change SDK process environment settings are serialized. Scanner responses support compact results and verbose ATSE/TrendX results. Missing, unsupported or error-bearing engine results remain unknown; confirmed detections never promote to clean.

Routing copies the captured scan bytes to the selected destination, applies result tags, reads the destination back and verifies SHA-256. New names are `original-name_<job-id>.ext`. Blob tags are native index tags; shares use `.v1fs-tags.json` sidecars. Files are not converted to ZIP or password-protected. Share publication uses private staging and exclusive publication; NFS requires hard-link support.

Only after destination verification does the app remove the unchanged source. Azure Blob uses conditional ETag deletion. Shares recheck identity and digest; concurrent mutation remains a limitation of SMB/NFS. Source deletion failures retain destination details and hold the record for review. Scan-failed files remain HELD even when successfully routed, because their verdict needs review.

Retries reuse encrypted snapshots and verified verdicts; changing a profile affects newly queued jobs. Source identities generate deterministic job IDs to avoid duplicate submissions. Transfer and scan failures have bounded retries; interrupted jobs resume after restart.

## Reporting

Scan timestamps count distinct jobs with responses once. Older records without scan timestamps use last-update estimates. CSV streams all job records with verdicts, hashes, state, dates, attempts, errors and destination details, with spreadsheet formula protection. The UI activity list is limited to 500 records. No credential fields are exported.

Scanner detection details are stored encrypted in `scan_details`, separate from the public job columns. Compact `foundMalwares` and verbose per-engine `malware` entries are supported. API keys are redacted before persistence. Historical responses are not reconstructed from filenames.
