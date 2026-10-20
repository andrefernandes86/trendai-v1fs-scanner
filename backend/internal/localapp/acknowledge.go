package localapp

import "net/http"

// Acknowledgement preserves the failed verdict and storage; it only ends further work.
func (a *App) acknowledgeJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tx, err := a.DB.Begin()
	if err != nil {
		problem(w, 500, "Acknowledgement unavailable.")
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE jobs SET state='ACKNOWLEDGED',updated_at=?,error=error || ' Administrator acknowledged: do not scan this file version again.' WHERE id=? AND state='HELD' AND NOT EXISTS(SELECT 1 FROM recovery_links l JOIN jobs child ON child.id=l.child_id WHERE l.parent_id=jobs.id AND child.state IN ('QUEUED','SCANNING','ROUTING','RETRY_PENDING'))`, stamp(), id)
	if err != nil {
		problem(w, 500, "Could not acknowledge file.")
		return
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		problem(w, 409, "Only held files without active recovery can be acknowledged. Wait for active recovery to finish.")
		return
	}
	if _, err = tx.Exec("INSERT INTO audit(at,action,object_id,detail) VALUES(?,?,?,?)", stamp(), "job.acknowledged", id, "Administrator stopped scanning this file version; verdict, file and history preserved."); err != nil {
		problem(w, 500, "Could not record acknowledgement.")
		return
	}
	if err = tx.Commit(); err != nil {
		problem(w, 500, "Could not save acknowledgement.")
		return
	}
	respond(w, 200, map[string]bool{"acknowledged": true})
}
