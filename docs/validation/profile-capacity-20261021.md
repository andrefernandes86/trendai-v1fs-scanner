# Profile-controlled scan capacity — 2026-10-21

The saved profile concurrency is now the admission limit. Scan workers resize live from the sum of saved profile settings, rather than the legacy eight-worker environment default. The overview reports this configured total. Manual profiles also reserve configured capacity. Large-file, archive, disk and transfer settings remain separate controls.

Validation:

- Full Go race suite passed; localapp completed in 76.144 seconds.
- Go vet and frontend production build passed.
- Admission test accepted 20 jobs with legacy `V1FS_MAX_WORKERS=8`, rejected the 21st, honored a live reduction and summed independent profile budgets.
- Worker-pool test grew from 2 to 20 and drained to 3 without restart.
- Sixteen other desktop/mobile browser checks passed. The expanded wizard check initially timed out because the test navigated away before checking the profile card. After moving the assertion to the correct point, both desktop and mobile wizard checks passed, including saved limit 20, dashboard 20 and engine report 20.
- Deployed while no SCANNING or ROUTING jobs were active. Production health check passed and the processing engine reported healthy with workerLimit 20.

![Configured capacity 20](../images/profile-concurrency.png)
