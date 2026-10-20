package localapp

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *App) queryJobs(r *http.Request) ([]Job, error) {
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 || limit > 500 {
		limit = 500
	}
	parts := []string{}
	args := []any{}
	for name, column := range map[string]string{"state": "j.state", "verdict": "j.verdict", "profile": "j.profile_id"} {
		if v := q.Get(name); v != "" {
			parts = append(parts, column+"=?")
			args = append(args, v)
		}
	}
	if v := q.Get("q"); v != "" {
		parts = append(parts, "(instr(lower(j.key),lower(?))>0 OR instr(lower(j.profile_name),lower(?))>0 OR j.id=?)")
		args = append(args, v, v, v)
	}
	if v := q.Get("from"); v != "" {
		if _, e := time.Parse(time.RFC3339, v); e == nil {
			parts = append(parts, "j.created_at>=?")
			args = append(args, v)
		}
	}
	if v := q.Get("to"); v != "" {
		if _, e := time.Parse(time.RFC3339, v); e == nil {
			parts = append(parts, "j.created_at<=?")
			args = append(args, v)
		}
	}
	where := ""
	if len(parts) > 0 {
		where = " WHERE " + strings.Join(parts, " AND ")
	}
	return a.jobsPage(where, args, limit, offset)
}
func (a *App) retention(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Days  int  `json:"days"`
		Apply bool `json:"apply"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Days < 30 {
		problem(w, 400, "Retention must be at least 30 days. Unresolved records are never removed.")
		return
	}
	cutoff := time.Now().AddDate(0, 0, -input.Days).UTC().Format(time.RFC3339Nano)
	filter := "state IN ('COMPLETED','QUARANTINED') AND updated_at<? AND id NOT IN (SELECT parent_id FROM recovery_links UNION SELECT child_id FROM recovery_links)"
	var n int
	if e := a.DB.QueryRow("SELECT count(*) FROM jobs WHERE "+filter, cutoff).Scan(&n); e != nil {
		problem(w, 500, "Could not preview retention.")
		return
	}
	if !input.Apply {
		respond(w, 200, map[string]any{"eligibleRecords": n, "applied": false, "unresolvedPreserved": true})
		return
	}
	tx, e := a.DB.Begin()
	if e != nil {
		problem(w, 500, "Retention unavailable.")
		return
	}
	defer tx.Rollback()
	for _, table := range []string{"scan_details", "scan_results", "stage_attempts", "move_records", "source_claims"} {
		if _, e = tx.Exec("DELETE FROM "+table+" WHERE job_id IN (SELECT id FROM jobs WHERE "+filter+")", cutoff); e != nil {
			problem(w, 500, "Retention failed.")
			return
		}
	}
	if _, e = tx.Exec("DELETE FROM jobs WHERE "+filter, cutoff); e != nil {
		problem(w, 500, "Retention failed.")
		return
	}
	if e = tx.Commit(); e != nil {
		problem(w, 500, "Retention commit failed.")
		return
	}
	a.Audit("retention.applied", "jobs", "Removed "+strconv.Itoa(n)+" resolved records older than "+strconv.Itoa(input.Days)+" days; destination files were not deleted.")
	respond(w, 200, map[string]any{"removed": n, "destinationFilesUntouched": true})
}
