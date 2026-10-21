# Container sizing validation — 21 October 2026

Sizing assumes one scan profile per container. Both input validation and the UI enforce 1–32 simultaneous scans per container. The default workload needs 600 aggregate active-file slots and is distributed across 19 containers with 32 scans per profile. CPU, RAM and disk cards are labeled per container. Container count does not imply separate physical hosts.

Validation:
- Frontend type checking and production build passed.
- Four sizing checks passed across desktop and mobile, including the 33-slot rejection, 16-slot distribution and default 19-container calculation.
- Main guide screenshots and sizing legend regenerated on an isolated documentation instance. Existing focused feature screenshots remain in the guide.
- All user-guide screenshot references resolve.
- Production restarted only after confirming no scanning/routing jobs. Health check passed after engine startup; live frontend is index-CPEFLKkZ.js.
- Backend behavior and downstream destination ownership are unchanged.
