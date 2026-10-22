# CSV ZIP scan rerun — October 22, 2026

Completed on the .52 host using the published `latest` image at revision `d56434b06c685f42d53abaac8ecd0a76b25d59d8`. Both archives were submitted as new jobs, sequentially, through a dedicated Azure source and manual test profile. The original saved production profile was unchanged. This test did not run on ACI.

## Outcomes

| ZIP size (decimal bytes) | CSV entries | SDK outcome | Final test-job status |
|---:|---:|---|---|
| 10,000,000,000 | 10 | ATSE error `-82`, `ErrorOccur: pfcb_status=-82`; UNKNOWN | Further test retries dismissed after the first analysis; source retained; no clean delivery |
| 1,800,000,000 | 10 | CLEAN; no engine errors or detections | COMPLETED; delivered to clean storage |

Both fixtures are unchanged, valid synthetic CSV ZIPs using ZIP_STORED. Go's independent ZIP reader streamed all entries and passed their CRC checks; each entry's CSV header was checked. The original generation also validated CRCs in Python. Both captured SHA-256 digests match the original fixture manifests exactly. The 10 GB archive requires ZIP64 directory records.

One scan attempt was made per fixture. For the failed 10 GB test, the normal retry was observed and then dismissed while queued, preserving UNKNOWN and the original source. Saved retry defaults were not changed. The 1.8 GB archive followed normal delivery, with full destination-content readback disabled as in the original policy. No destination content was read after handoff.

## Timings

Seconds recorded by the application; SDK analysis includes request/response time.

| Fixture | Stage | Seconds |
|---|---|---:|
| ten-csv-1-8gb-20261022.zip | download | 88.674 |
| ten-csv-1-8gb-20261022.zip | queue_wait | 1.190 |
| ten-csv-1-8gb-20261022.zip | scan | 61.748 |
| ten-csv-1-8gb-20261022.zip | transfer_wait | 0.214 |
| ten-csv-1-8gb-20261022.zip | upload | 285.708 |
| ten-csv-1-8gb-20261022.zip | verify | 0.078 |
| ten-csv-10gb-20261022.zip | download | 497.252 |
| ten-csv-10gb-20261022.zip | queue_wait | 0.052 |
| ten-csv-10gb-20261022.zip | scan | 76.050 |

These are observed timings for these synthetic inputs and this connection, not a general throughput guarantee. Fixture preparation reused repeated Azure block references to reduce setup upload traffic; committed blob sizes remained exact and the application downloaded each full archive normally.

## Runtime and verification

- Engine unhealthy samples: 0; observed engine PIDs: [16]. No engine restart interrupted either job.
- Peak sampled Docker working set: 1524.7 MiB. This is a container working-set measurement, not process heap size or a hard resource bound.
- Full Go race suite rerun passed; localapp package completed in 106.079 seconds.
- Both original filenames and exact sizes appeared in the SDK responses.
- Results reproduce the first comparison: the smaller archive completes cleanly; the larger archive returns an engine error and is not treated as clean.

## Interpreting -82

[Trend Micro's Scan Engine documentation for InterScan](https://success.trendmicro.com/en-US/solution/KA-0001842) maps `-82` to `BAD_ZIP_ERR`. This is documentation for another product and provides a diagnostic lead, not proof of the precise File Security failure. Both fixture archives pass independent CRC checks. An archive-format/ZIP64 compatibility issue is a possible explanation; this rerun does not establish the cause or a supported maximum archive size. No engine-error bypass or clean-verdict override was enabled.
