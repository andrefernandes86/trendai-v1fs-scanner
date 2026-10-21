# Operator and tester handoff

Use this checklist when another person installs or evaluates the tool. The [illustrated user guide](user-guide.md) contains the full walkthrough; [architecture and diagrams](poc-architecture.md) describe the components and data flow.

## 1. Prepare the test environment

You need Docker Engine with Docker Compose, Git, a browser, outbound access to the configured Trend File Security endpoint, a File Security API key, and access to test storage. Use four separate test locations: Incoming, Safe, Malicious and Scan failed. For Azure, allow source list/read/delete and destination create/read/write/tag operations. Share connections need read/write/delete and staging/rename support. Use test data and restrict access to malicious storage.

Keep credentials outside Git and enter them in the console. Obtain credentials from the environment owner through your normal secure channel. The repository does not contain a working API key or storage login.

## 2. Install and start a new instance

```bash
git clone https://github.com/andrefernandes86/trendai-v1fs-scanner.git
cd trendai-v1fs-scanner
docker compose up -d --build
docker compose ps
curl --fail http://localhost:8095/livez
```

Open `http://localhost:8095` (or the server hostname on port 8095). Create your own administrator password on first use. Never reuse the demonstration password from screenshot/test scripts. Restrict console access to the test network; use the HTTPS configuration in [operations](operations.md) when appropriate.

The named Docker volume stores configuration, encrypted credentials, job history and the encryption key. A restart preserves them:

```bash
docker compose restart scanner
```

To stop and start without deleting data:

```bash
docker compose stop scanner
docker compose start scanner
```

Do not run `docker compose down -v`: it deletes the data volume. For an existing installation with a host data directory, use the matching overrides in [operations](operations.md), not a fresh empty volume.

## 3. Configure the console

1. **Storage connections:** add the four locations and test access. List shares may require permissions beyond direct share access.
2. **Vision One config:** enter the API key and cloud region, or the local scanner service address. Test scanner connectivity.
3. **Scan profiles → Add profile:** follow Source → Destinations → Schedule → Protection → Options → Review. Select the four locations. Enable automatic scanning, choose the scan interval and concurrency, then save.
4. Upload files only to Incoming. Subfolders are scanned recursively. Wait for upload-stability checks before expecting a job.
5. **Overview** shows queued/scanning/transferring counts. **File activity** shows full paginated history; select a file for scanner details, detections, errors and transfer evidence.

![Profile setup workflow](images/profile-source.png)

![Monitoring overview](images/overview.png)

## 4. Run the acceptance checks

| Test | Expected result |
|---|---|
| Upload a small known-safe document | Clean result, verified Safe destination, matching source removed |
| Use the profile's EICAR test input | Malicious result, Malicious destination, original bytes preserved; never execute the sample |
| Upload into an Incoming subfolder | Discovered and scanned automatically |
| Enable archive inspection and upload a small safe ZIP | Original and members inspected; archive delivered according to result |
| Upload an archive that exceeds the configured limits | Incomplete/unknown result, `scan-failed=true`, isolated in Scan failed storage |
| Inspect an unresolved failure | Error and retry counts visible; exhausted scan attempts isolate it with failure tags |
| Inspect a copy failure | Source retained; exhausted attempts trigger source failure tagging; inaccessible storage produces an explicit tag-write error |
| Acknowledge a held file | ACKNOWLEDGED; no further retries/recovery for that version; file/history remain |
| Restart the container | Connections, profiles, administrator and history remain |
| Export File activity CSV | Matching evidence available independently of the displayed page |

A health check verifies application processes; it does not prove remote credentials or routing permissions work. Check real destinations and integrity evidence during acceptance. Large-file/throughput results depend on your file mix, storage, network and scanner. Run customer-scale tests separately using [performance testing](performance-testing.md).

![Archive inspection controls](images/profile-archives.png)

![Dismiss a held or missing file](images/dismiss-held-file.png)

## 5. Troubleshoot and collect evidence

```bash
docker compose ps
docker compose logs --tail 200 scanner
curl --fail http://localhost:8095/livez
```

- No job: check profile enabled status, source connection, last source check, ignored patterns, upload stability and free disk.
- Held/unknown: open record details and inspect scanner response, archive budgets and retry counts. Never assume an unknown file is clean.
- Copy/tag error: check storage availability and read/write/tag permissions. The source remains until destination verification succeeds.
- Slow processing: inspect scan and transfer queues, concurrency, disk and network; start with the sizing calculator and validate with measurements.
- Stop work on a file: use **Dismiss — stop retrying**, then confirm in the in-app dialog. Missing files can be dismissed without accessing storage; related queued recoveries are stopped too. Hiding only changes the list display.

Provide the tester's version (`git rev-parse HEAD`), redacted logs, record ID, file size/type, profile settings, measured timings and expected/actual result. Do not share API keys, storage credentials, the data volume, `master.key`, browser sessions or unredacted exports.

## 6. Upgrade and hand over

Back up the data directory/volume and encryption key together using the coordinated backup procedure in [operations](operations.md). Record the existing image before changing it. Then:

```bash
git pull --ff-only
docker compose up -d --build
docker compose ps
```

Repeat the safe-file and EICAR checks. Give the next operator the console URL, access procedure, storage ownership, backup location, deployed commit, acceptance results and pending items from [to-do.md](../to-do.md). Transfer any secrets outside the repository through your secure channel.

External notifications remain deferred. Source and destination files are not deleted by history cleanup. Acknowledgement preserves failure evidence and does not certify the file as safe.

Account handover: the next administrator can change the password through **AD → Change password**, using the current password. Previous sessions are invalidated. See the [review findings and regression coverage](code-review-20261021.md) for the latest recovery/scheduling/large-download corrections.

For ADLS Gen2, follow the [ADLS setup, protocol matrix and acceptance checklist](adls-gen2.md). Automated adapter coverage is available; live HNS account acceptance must be completed with the customer's connection.
