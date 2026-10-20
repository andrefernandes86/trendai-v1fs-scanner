package localapp

import "time"

// Timings accumulate across attempts so slow retries remain visible.
func (a *App) recordTiming(id, stage string, start time.Time) {
	_, _ = a.DB.Exec("INSERT INTO job_timings(job_id,stage,seconds) VALUES(?,?,?) ON CONFLICT(job_id,stage) DO UPDATE SET seconds=seconds+excluded.seconds", id, stage, time.Since(start).Seconds())
}
