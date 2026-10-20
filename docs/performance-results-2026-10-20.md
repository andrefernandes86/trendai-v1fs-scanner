# Scanner performance validation — 20 October 2026

## Outcome

| Test | Inputs | Clean | Malicious | Failed | Checksum verified and source deleted | Wall time |
|---|---:|---:|---:|---:|---:|---:|
| 1,000 concurrent uploads | 1000 | 417 | 583 | 0 | 1000 | 595.84s |
| 100 uploads/second, ten batches | 1000 | 417 | 583 | 0 | 1000 | 646.63s |
| Real ZIP supplement (queued behind burst) | 12 | 5 | 7 | 0 | 12 | 485.36s |

All input counts were reconciled with the complete job database, rather than the latest-500 UI view. No final failed or missing files, verdict changes from the original verified samples, or application-stage retries were observed. Persisted COMPLETED move records prove the application completed destination readback/size/SHA-256/CRC32C verification and source deletion. Independent Azure source listings also found zero remaining inputs under all three test prefixes. This report does not independently re-download every destination after completion.

## Latency (seconds)

| Phase | Burst mean | Burst p95 | Paced mean | Paced p95 |
|---|---:|---:|---:|---:|
| Upload request | 0.922 | 1.843 | 0.212 | 0.506 |
| Upload completion → job creation | 89.726 | 147.538 | 65.964 | 104.686 |
| Job creation → first worker start | 220.586 | 415.951 | 280.700 | 504.282 |
| Worker start → scan response | 0.377 | 0.586 | 0.424 | 0.722 |
| Scan response → finalization | 0.673 | 1.518 | 0.727 | 2.286 |
| Upload start → finalization | 312.283 | 565.251 | 348.027 | 610.357 |

Burst throughput including upload, discovery and drain: **1.678 files/s**. Paced throughput on the same basis: **1.546 files/s**. Burst uploads completed in 2.397s; paced uploads completed in 9.853s. The ten paced batch starts were one second apart, within 5 ms of the intended offsets. Fast storage ingestion does not imply equal scan throughput.

Worker-to-response includes source download, waiting for the SDK lock, connection setup and scanning. It is not pure engine execution time. Routing includes verified copy, checksum readback, destination lease and conditional source deletion. Percentiles are nearest-rank. ZIP wall time includes its intentional backlog behind the first burst and must not be used as standalone archive throughput.

## Corpus and environment

Twelve latest successfully scanned user samples from the preceding 24 hours were read from their verified destinations and checked against recorded SHA-256 hashes. Older failed records did not disqualify a later verified copy, as requested. Unresolved failures and tool-generated verification files were excluded from the corpus, not deleted from storage. The corpus includes seven detected malicious inputs and five clean inputs, including the previously problematic screenshot. Samples were copied as inert bytes and never executed.

Each load run cycled these twelve samples into 1,000 unique names with common extensions: PDF, DOCX, XLSX, PPTX, TXT, PNG, JPG, HTML, ZIP and DOC. **Extensions were renamed, not converted into valid documents or archives.** The separate twelve-file ZIP test created genuine ZIP archives containing the original samples. No password was added.

Deployment: local Docker container, 16 visible virtual CPUs, approximately 15.6 GiB RAM; two processing workers; SDK calls serialized because its endpoint settings use process environment variables. Enabled source-only profile: 10-second polling, default 10-second quiet period, no bypass/ignore rules, Azure Blob source and distinct clean/malicious/scan-failed destinations, Vision One cloud scanner. Existing profile settings were not changed for the tests. These repeated small samples are not a general capacity claim for large, varied or customer-scale content.

The original burst orchestration terminal was interrupted after uploading all inputs. The independent production container continued processing them. Observation resumed from persisted records without re-uploading that burst. Paced and ZIP orchestration ran in separate containers. Twelve ZIP jobs briefly shared the burst tail; this small overlap is included in the measurements.

## Resource observations

192 Docker resource samples, from 2026-10-20T13:02:54.247Z to 2026-10-20T13:22:06.198Z. Maximum sampled memory: 50.77 MiB (Docker usage, including cache); CPU: 101.69% (100% = one CPU); processes/threads: 36. Container restarts: 0; sampled health states: healthy. Sampling began after the initial burst upload, so these are sampled maxima rather than guaranteed full-run peaks. The host also runs unrelated services.

## Findings and next validation

- No missing-file or unsafe-promotion defect was observed in these runs.
- Poll interval is not a scan-completion SLA: per-file metadata admission and the durable queue dominate burst latency. The first burst took up to 153 seconds to admit all inputs and about ten minutes to drain.
- Consider bounded parallel admission, safe SDK concurrency/configurable workers, and backlog-age/rate indicators before promising higher throughput. Preserve integrity verification and retry semantics when optimizing.
- This successful run does not exercise scan/storage failures, quota throttling, prolonged outages, or larger archives; earlier fault-fixture/watchdog tests address some failure paths. Customer NAS compatibility, large-file mixes, long soak runs and scanner quotas remain customer-scale validation work.
- Real ZIP scanning was verified. Password-protected, unsupported or archive-limit exceptions must remain unknown/scan failed; this run did not test encrypted archives, nested-archive limits or decompression bombs. External notifications remain deferred.

## Files

- `burst-files.csv`: every first-run file and its timings, verdict, hashes, verification phase and destination.
- `../stress-paced-20261020/paced-files.csv`: every second-run file.
- `../archive-check-20261020/burst-files.csv`: genuine ZIP results.
- `combined-summary.json`: aggregate metrics for all three tests.
- `resources-summary.json`: sampled resource and health summary.

No API keys, storage credentials, encrypted snapshots, raw sample bytes or full scanner responses are included in these deliverables. File paths, filenames and destination locations remain operational data.
