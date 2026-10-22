# Scan error retries and explicit resolution

Validated 21 October 2026 (America/Chicago).

- Default scan budget is four attempts: the initial scan plus three retries, exactly 60 seconds apart. Saved production profile updated to four total attempts.
- Unknown/permanent scanner exceptions no longer bypass retries. Incomplete archive coverage is retried and routed as unknown after exhaustion; original detection evidence remains recorded.
- Explicit Resubmit / move actions create fresh jobs for exact recorded source/destination identity. A completed delivery is accessed only upon this administrator-confirmed request.
- Manual moves retain UNKNOWN and scan-failed labels, use the configured destination and verified delivery pipeline, and resolve as ACKNOWLEDGED. They never fabricate a CLEAN verdict.
- Concurrent/duplicate requests are rejected transactionally; original evidence remains unchanged, and audit entries link parent/new jobs.
- Tests cover three 60-second retry waits, four scanner calls before isolation, explicit manual delivery without scanning, duplicate rejection, and destination identity for resubmission, and successful rescan after transferring an existing private share claim.
- Full Go race suite passed (localapp 209.584 seconds). Targeted race tests after final changes passed (17.443 seconds). Go vet and frontend build passed.
- All 22 desktop/mobile browser checks passed, including both resolution actions.
- Production was idle before restart. Health check passed and current frontend is index-QnJfJM71.js. Existing 32 scan / 10 transfer profile settings preserved.
- Guide screenshots refreshed on isolated documentation instance; manual resolution dialog added.
