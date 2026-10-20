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
