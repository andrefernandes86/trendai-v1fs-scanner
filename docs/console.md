# Console guide

1. Create storage connections and use Test or discovery before saving. Discovery names can be selected. For SMB, a server can permit a known share while denying enumeration.
2. Configure Vision One: API key plus cloud region, or local scanner host:port and TLS.
3. Create a profile with four distinct locations: source, clean, malicious and scan failed. Set optional prefixes, detection options and scan frequency. Enable automatic scanning.
4. Upload ordinary files to the source. The monitor observes stability; no upload markers or manual tagging are needed. Destination folders are not scheduled scan sources for this profile.
5. Follow source counts and File activity. Clean -> COMPLETED; malicious -> QUARANTINED; unknown -> HELD in scan-failed storage. A verified destination precedes source deletion.
6. Use Safe file/EICAR file buttons to create test inputs in the source. Normal scanning handles them.

## Tags and files

Enter comma-separated key=value tags. Common tags combine with clean/malicious tags; verdict-specific values override duplicate keys. Blob uses native tags, shares JSON sidecars. The app copies original bytes, does not create ZIPs and adds no passwords. Names preserve the original filename stem followed by a unique job ID and extension. If an uploaded archive already has a password, obtain it from its uploader.

## Refresh and export

Overview, File activity and Audit log offer Off/5s/10s/30s/1m/5m auto-refresh. Settings persist in the browser. Other pages do not automatically refresh. Manual Refresh is available. CSV export covers all historical jobs, not only the current table or filter, and includes verdict, malicious/unknown status, hash presence and SHA-256, timestamps, state, source, destination, errors and attempts. JSON export on File activity/Audit log covers currently loaded records.

## Detection details and older uploads

New scans retain an encrypted scanner response. Record details show malware names, detection engines and affected files, with an authenticated Show scanner response action. CSV includes malware names and engines. Old records explicitly say names were not recorded; do not infer a malware name from a filename. Earlier uploads show when a newer version of the same source filename completed, keeping historical failures distinct from the current result.

## Planned exclusion and verification settings

Exclusion controls are backlog items, not current console options. The proposed workflow is to define per-profile path/filename rules, preview matches, then save a versioned policy. A match would promote to clean storage with an EXCLUDED / NOT SCANNED label, not a clean scan verdict. The transfer would still require content verification before source deletion. Broad rules can bypass malware detection and must be visible in activity/export.

The proposed move-verification controls will show source/destination size, SHA-256, CRC32C and source-delete state. At present, routing already verifies size and SHA-256; supplemental CRC32C and durable independent deletion recovery remain pending.

## Reliability settings

Profile sections 6–8 configure quiet periods/temporary ignores, retries, exclusions/hold rules and isolated-file recovery. Preview exclusion matches before saving. Share deletion requires confirming the producer handoff and controlled destination-writer contract. Overview exposes processing alerts and inventory export; File activity provides date/verdict filters, pages and explicit retention preview/apply. Record details show integrity evidence and manual recovery/enrichment actions. See [reliability](reliability.md) for operational semantics.
