# Optional archive inspection validation — 20 October 2026

The feature is disabled by default and enabled per scan profile. See [configuration and limits](../archive-inspection.md).

Validated:

- ZIP/ZIP64, TAR and GZIP nested extraction; 20 layers accepted and layer 21 rejected.
- Shared entry, expanded-byte and ratio budgets; traversal, duplicate paths, links, encrypted/unsupported and corrupt archives fail closed.
- Actual restricted Docker helper: non-root, read-only container, no capabilities, no network; 20-layer fixture completes and expansion-ratio fixture is rejected.
- Landlock filesystem boundaries and seccomp socket restrictions exercised by subprocess tests; failed sandbox setup does not fall back to unrestricted extraction.
- Aggregation: clean requires original and every required member to be clean; malware dominates unknown siblings; incomplete coverage without malware remains unknown.
- Safe ZIP and EICAR ZIP submitted through the configured official cloud SDK: CLEAN and MALICIOUS respectively; extraction complete, two member evidence records each (original plus member).
- Full encrypted evidence and compact activity summaries; original archive bytes routed unchanged.
- Desktop/mobile editor saves archive limits, including maximum depth 20.

The existing VPLE archive's scanner error is not overridden by clean member results. This is a fault/functional validation, not a 100 GB throughput certificate. Password handling and additional compression formats remain deferred.
