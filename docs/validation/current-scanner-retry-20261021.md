# Current scanner configuration on explicit retry/resubmission

Verified 21 October 2026 (America/Chicago).

The saved scanner was cloud/us-east-1, but both EICAR ZIP resubmissions inherited the original local endpoint. Explicit Retry and Resubmit now refresh scanner settings from saved configuration while preserving file identity, destination ownership guards and scan history.

Validation:
- Race tests passed for current-scanner Retry/Resubmit and existing manual resolution/claim/ownership cases.
- Both actual customer EICAR ZIPs scanned through the saved cloud SDK configuration without errors and detected Eicar_test_file_9. One ZIP contains eicar.com; the other contains the first ZIP.
- Production updated while idle; both existing resubmission requests requeued using the current saved scanner. Both completed as QUARANTINED / MALICIOUS with no errors; production health check passed.
- No credentials are recorded in this report.
