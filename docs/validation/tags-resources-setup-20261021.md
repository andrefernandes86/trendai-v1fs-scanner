# Tags, container status and simplified overview

Verified 21 October 2026 (America/Chicago).

Changes:
- Separate Vision One scan-event tags from delivered storage labels. Six custom scan tags plus two automatic app/profile tags, with the SDK's eight-tag / 63-byte limits enforced before profile save and SDK submission.
- Storage help explicitly distinguishes Azure Blob native tags, ADLS metadata and Azure Files/SMB/NFS JSON sidecars.
- Sidebar shows quota-aware CPU allocation, cgroup memory usage/limit, shared data filesystem used/total, engine heartbeat and cached scanner endpoint connectivity. Endpoint status is TCP/TLS reachability, not an authentication/scan guarantee.
- Workflow/checklist moved from Overview to the top-bar Setup guide.
- Source files heading gains a target icon consistent with destination icons.
- Schedule accepts 5 seconds in HTML, API validation and runtime interval; 10 seconds remains recommended. Existing profile intervals unchanged.

Validation:
- Full Go race suite passed (localapp 110.586 seconds); Go vet passed.
- Targeted race checks after the interval change passed.
- Live saved-cloud SDK scan returned both custom tags and both automatic tags. The opt-in test uses a harmless generated file and logs no credentials.
- All 22 desktop/mobile browser checks passed before final cosmetic/interval changes; the affected desktop/mobile wizard, dashboard and theme checks subsequently passed (wizard rerun confirmed a persisted five-second interval and multiple tags).
- Frontend production build passed. Guide screenshots regenerated from an isolated documentation instance, including profile tags, source target icon and Setup guide.

Production updated while idle; post-deployment engine health passed. Saved scan/transfer budgets and polling intervals preserved.
