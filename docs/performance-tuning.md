# Transfer performance and queue controls

Scanning and destination transfer use separate, bounded worker pools. A long upload or checksum readback no longer occupies a scan slot. The management API remains a separate process.

## Start with the defaults

1. Open **Scan profiles → Edit profile**.
2. In **Schedule**, choose **Files scanned at once**. These slots cover capture and scanning.
3. In **Options → Transfer speed**, start with:

   | Setting | Default | Allowed |
   | --- | --- | --- |
   | Simultaneous transfers per profile | 2 | 1–10 |
   | Simultaneous large transfers (at least 1 GB) | 1 | 1–2 |
   | Parallel Azure Blob upload requests per file | 2 | 1–8 |
   | Azure Blob upload block size | 8 MiB | 4–32 MiB |

4. Save the profile. Transfer admission limits apply live to waiting jobs; active transfers finish normally. Upload block/request settings and scan/result policy retain their captured job snapshot.
5. On **Overview**, watch **Scanning now**, **Pending scans**, **Transferring** and **Pending transfers**.
6. Open a file's record and read **Processing time** before tuning. It shows queue wait, source download, scanning, transfer wait, upload and destination verification in seconds. Values accumulate across recorded attempts; older files may have no timings. The full CSV includes timings as JSON.

Scan workers follow saved profile limits automatically (default 2, range 1–32 per profile). The pool grows or drains live; the legacy `V1FS_MAX_WORKERS` environment variable no longer overrides console settings. Transfer workers also follow saved profile limits automatically (1–10 per profile). The legacy `V1FS_TRANSFER_WORKERS` environment variable no longer caps the pool. Files below 1,000,000,000 bytes can use all ten slots; larger files also obey the separate large-transfer limit. Large-file and archive limits and available disk capacity still control their respective stages.

Increase one setting at a time. More upload requests consume approximately block size × requests × simultaneous transfers in buffer memory, plus SDK/runtime overhead. Network, storage throttling and scanner quotas may dominate throughput. This release does not establish a new 100 GB throughput benchmark.

## Integrity with less traffic

The Blob worker path uploads the captured file, persists a `DESTINATION_UPLOADED` checkpoint, acquires a renewable destination lease, then checks destination properties. When content readback is enabled, it streams the destination once to calculate SHA-256 and CRC32C together. It checks length and identity, applies result tags under the lease, persists delete intent and conditionally deletes the unchanged source. A failed tag write retains the source. Every resumed incomplete delete attempt repeats the configured checks; completed handoffs never reopen destination files.

For a 3.5 GB file, normal Blob routing now needs approximately 7 GB of payload traffic: 3.5 GB upload and 3.5 GB verification. The previous path used approximately 14 GB because three overlapping destination reads followed upload. This halves routing payload traffic; it is not a promise of halving elapsed time. Source capture and SDK traffic are additional.

SHA-256 and CRC32C are calculated together during source capture. Engine-owned captures carry these checksums to the transfer stage, avoiding an additional local checksum pass. Share storage retains its publication/staging checks because its consistency and handoff guarantees differ from Blob leases.

## Backpressure and restart

The transfer queue admission threshold is twice the global scan-worker count; in-flight scans may add up to one further worker count of handoffs before backpressure stops admission. Disk reservations and a 5 GiB reserve stop new captures when space is insufficient. Files remain at source while waiting; the queue does not silently drop work.

Transfer handoffs are encrypted in SQLite. After engine restart, incomplete jobs return to the durable queue and temporary captures are discarded. The worker recaptures the unchanged source, reuses a persisted clean/malicious result, or resumes an existing move checkpoint. Destination size and identity checks are repeated before deletion; content readback also repeats when enabled in the profile. Restart may add source-read work, but does not discard history or issue a clean verdict without evidence.

## Remaining tuning work

Customer-scale soak tests, storage-specific benchmarks, parallel source admission and rate/backlog-age charts remain follow-up work. External notifications are deliberately deferred.

Archive admission and retries: when the inspection pool is full, the job defers without holding a general scan worker. Same-job retries reuse confirmed member responses only when name/SHA-256 match and retry unknown members. This is not a cross-file scan cache. Keep archive concurrency within the configured limits and inspect individual member errors when coverage remains incomplete.

Blob downloads and destination verification use bounded resumable reads with ETag matching. A dropped stream resumes at its byte offset when possible rather than discarding the complete transfer so far. The file is still checked against expected size and hashes before source deletion.

Checksum audit: `crc32c` uses the Castagnoli polynomial (CRC32C), not IEEE CRC32. It and SHA-256 are produced during the source download even when destination readback is off. The `verify` timing includes size/identity checks and therefore may be nonzero with `destinationVerification=false`. That combination is expected. Full readback-off regression coverage rejects any destination-content GET and permits only the properties request.
