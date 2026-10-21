package localapp

import (
	"database/sql"
	"net/http"
)

// Dismissal is a local queue operation. It must work even when storage credentials
// have expired, the mount was removed, or the source/destination file is gone.
func (a *App) acknowledgeJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tx, err := a.DB.Begin()
	if err != nil {
		problem(w, 500, "Dismissal unavailable.")
		return
	}
	defer tx.Rollback()
	var state string
	if err = tx.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state); err == sql.ErrNoRows {
		problem(w, 404, "Record not found.")
		return
	} else if err != nil {
		problem(w, 500, "Could not read record.")
		return
	}
	if state != "HELD" && state != "QUEUED" && state != "RETRY_PENDING" && state != "ACKNOWLEDGED" {
		problem(w, 409, "Only held or queued records can be dismissed. Active scans and transfers must finish first.")
		return
	}
	// Include ancestors and descendants so a dismissed recovery does not leave a
	// phantom held parent in assurance, or allow a queued sibling to start later.
	rows, err := tx.Query(`WITH RECURSIVE family(id) AS (
 SELECT ? UNION SELECT l.parent_id FROM recovery_links l JOIN family f ON l.child_id=f.id
 UNION SELECT l.child_id FROM recovery_links l JOIN family f ON l.parent_id=f.id
 ) SELECT j.id,j.state FROM jobs j JOIN family f ON j.id=f.id`, id)
	if err != nil {
		problem(w, 500, "Could not read related retries.")
		return
	}
	ids := []string{}
	active := false
	for rows.Next() {
		var key, status string
		if err = rows.Scan(&key, &status); err != nil {
			break
		}
		if status == "SCANNING" || status == "ROUTING" {
			active = true
		}
		if status == "HELD" || status == "QUEUED" || status == "RETRY_PENDING" {
			ids = append(ids, key)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		problem(w, 500, "Could not read related retries.")
		return
	}
	if active {
		problem(w, 409, "A related scan or transfer is active. Dismiss this record after that operation finishes; queued retries can be dismissed immediately.")
		return
	}
	for _, key := range ids {
		var transfers int
		if err = tx.QueryRow("SELECT count(*) FROM transfer_queue WHERE job_id=?", key).Scan(&transfers); err != nil {
			problem(w, 500, "Could not check delivery queue.")
			return
		}
		if transfers != 0 {
			problem(w, 409, "A related delivery is pending. Wait for it to finish before dismissing.")
			return
		}
		if _, err = tx.Exec("UPDATE jobs SET state='ACKNOWLEDGED',updated_at=?,error=error || ' Administrator dismissed: scanning and retries stopped for this file version.' WHERE id=?", stamp(), key); err != nil {
			problem(w, 500, "Could not dismiss record.")
			return
		}
		if _, err = tx.Exec("INSERT INTO audit(at,action,object_id,detail) VALUES(?,?,?,?)", stamp(), "job.acknowledged", key, "Administrator dismissed queue record and related pending recoveries; verdict and history preserved. No storage file was read or deleted."); err != nil {
			problem(w, 500, "Could not audit dismissal.")
			return
		}
	}
	if err = tx.Commit(); err != nil {
		problem(w, 500, "Could not save dismissal.")
		return
	}
	respond(w, 200, map[string]any{"acknowledged": true, "dismissedRecords": len(ids)})
}
