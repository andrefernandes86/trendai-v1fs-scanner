# Profile wizard and monitoring validation — 20 October 2026

## Configuration and presentation

- Six steps preserve the profile draft: Source, Destinations, Schedule, Protection, Options and Review.
- Forward navigation checks preceding steps; Save checks all native form constraints, opens an invalid field's disclosure and returns to its step. Server-side policy validation still applies.
- An initial browser check caught the final Next button submitting immediately when React reused it as Save. Distinct button identities and explicit types fixed it. Regression coverage requires a separate review/save click.
- Desktop/mobile tests exercise empty required fields, a polling interval below its minimum, a hidden invalid timeout, rule/recovery choices, archive limits and saved policy persistence.
- Compact cards expand monitoring, destinations, detection and test controls. Edit and Scan remain visible.
- Light mode includes the full sidebar and unmodified official standard logo; dark mode retains the inverse logo.
- Scan-error totals and the history drill-down share one predicate: UNKNOWN verdict and HELD/RETRY_PENDING state. Explicit card drill-down includes hidden records; resolved/recovered and intentional NOT_SCANNED holds are excluded.
- Clean/quarantine/submitted cards open matching full-history filters. Clear filters removes the scan-issue filter.

## Checks

- Full Go test suite, full localapp race suite and `go vet` passed.
- All 12 desktop/mobile browser checks passed. Coverage includes the wizard, outcome filters, 1,000-file history pagination/hiding, sizing and theme persistence.
- Live official SDK checks: generated safe ZIP was CLEAN; EICAR ZIP was MALICIOUS; archive extraction completed with original/member evidence.
- Live disposable Azure storage checks: safe text COMPLETED and EICAR QUARANTINED, with SHA-256/CRC32C evidence, native scanned=true tags and source deletion. Temporary containers were removed.
- Final-image extraction probes under non-root/read-only/no-network/no-capabilities restrictions accepted a 20-layer archive and rejected the high-expansion fixture.
- The illustrated user guide includes all wizard steps, compact/expanded profiles, light/dark overview, error filtering and the main console pages. Images use an isolated demonstration instance and placeholder storage credentials.

These checks cover functional behavior and integration with the configured cloud scanner/Azure account. Customer-scale/soak validation and other customers' share-server compatibility remain separate acceptance work; no new throughput benchmark is claimed.
