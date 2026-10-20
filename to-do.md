# Pending work

- [ ] Fix/improve SMB share enumeration interoperability and clear diagnostics when server RPC/IPC discovery is denied but direct share access works. Do not treat enumeration as required for a known share.
- [ ] Add explicit re-scan/reprocess actions for files already in scan-failed storage, retaining history and immutable identities.
- [ ] Persist encrypted raw scanner responses and expose redacted engine errors in record details.
- [ ] Add a reboot-persistent host service and documented upgrade/rollback workflow.
- [ ] Add browser-based visual regression and end-to-end UI tests across desktop/mobile layouts.
- [ ] Add configurable upload quiet periods and ignore patterns for temporary/in-progress files.
- [ ] Improve source-delete retry handling without losing verified destination records.
- [ ] Add bounded concurrent monitoring per profile so a slow share cannot delay other source checks.
- [ ] Add historical record pagination, richer filters and retention settings.
- [ ] Add managed archive password workflows only if requested; currently ZIPs are preserved as uploaded, with no generated password or ZIP conversion.

## Current limits

NFS supports v3 TCP AUTH_SYS, not NFSv4/Kerberos. Stability checks cannot prove upload completion during a long pause. SMB/NFS identity checks do not equal Blob conditional-version guarantees. Existing destination names are not retroactively renamed. Unknown files previously routed under the old verbose-response parser require rescanning; the fix does not rewrite historical verdicts.
