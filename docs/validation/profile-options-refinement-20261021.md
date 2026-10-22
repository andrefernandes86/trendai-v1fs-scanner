# Profile options and scanner card refinement

Implemented 21 October 2026 (America/Chicago).

- Local archive inspection hidden and disabled for production, retaining implementation, configuration fields and algorithm tests. Original ZIPs continue to the SDK.
- Configurable failure storage labels, with canonical failure evidence retained and contradictions rejected. Labels apply to delivered failures and retained failed sources.
- Oversized files and matching move rules can select a saved storage connection/subfolder, or remain at source. Moves preserve NOT SCANNED / excluded or oversized verdicts. Source-root destinations are rejected.
- Delivery verification moved to its own Options section.
- New profiles use 10-second polling, 120-second upload quiet time and 30-second storage retry base; explicit existing settings preserved. Slow-job warning now displays minutes, with behavior explained.
- Exclusive file-share writes clarified; redundant destination-handoff note removed.
- Source fields placed inside a destination-style target card.
- Scanner card collapses; expanded view includes effective memory total/available, normalized CPU utilization and TCP/TLS latency. SaaS/local mode and colored connectivity indicator replace generic deployment wording.

Validation includes end-to-end storage tests for custom routing/failure labels, native SDK ZIP scan with extraction disabled, 32 overlapping scan calls, full Go race suite, desktop/mobile browser validation, and regenerated documentation screenshots. The first race run caught a worker profile update occurring after heartbeat goroutine startup; normalization was moved before goroutine startup, and the full suite passed afterward.

Final checks:
- Full Go race suite passed (localapp 78.767 seconds); additional resource/routing/32-way concurrency race checks passed (5.634 seconds).
- Final full browser run passed 21 of 22 checks; the remaining mobile wizard fixture contained a rule saved by desktop. After isolating that fixture, desktop and mobile wizard reruns both passed. All capabilities passed their checks.
- Final Go vet and frontend build passed. Source-card and container-card screenshots visually inspected.
- Production updated while idle; post-deployment health passed. Existing saved profile settings retained; no delivered files accessed or modified by rollout.
