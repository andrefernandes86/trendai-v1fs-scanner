package localapp

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Presentation filtering must use the same predicate as the dashboard total.
const scanIssuePredicate = "j.verdict='UNKNOWN' AND j.state IN ('HELD','RETRY_PENDING')"

func (a *App) queryJobs(r *http.Request) ([]Job, error) {
	where, args, limit, offset := jobQuery(r, 500)
	return a.jobsPage(where, args, limit, offset)
}
func jobQuery(r *http.Request, maximum int) (string, []any, int, int) {
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 || limit > maximum {
		limit = maximum
	}
	parts := []string{}
	if q.Get("issues") == "scan_errors" {
		parts = append(parts, "("+scanIssuePredicate+")")
	}
	if q.Get("visibility") == "visible" {
		parts = append(parts, "NOT EXISTS(SELECT 1 FROM hidden_jobs h WHERE h.job_id=j.id)")
	}
	if q.Get("visibility") == "hidden" {
		parts = append(parts, "EXISTS(SELECT 1 FROM hidden_jobs h WHERE h.job_id=j.id)")
	}
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
	return where, args, limit, offset
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
	for _, table := range []string{"job_timings", "hidden_jobs", "scan_summaries", "scan_details", "scan_results", "stage_attempts", "move_records", "source_claims"} {
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

func (a *App) jobHistory(w http.ResponseWriter, r *http.Request) {
	where, args, limit, offset := jobQuery(r, 1000)
	var total int
	if err := a.DB.QueryRowContext(r.Context(), "SELECT count(*) FROM jobs j"+where, args...).Scan(&total); err != nil {
		problem(w, 500, "Could not count job history.")
		return
	}
	// Keep a now-empty last page in range after retention/filter changes.
	if total == 0 {
		offset = 0
	} else if offset >= total {
		offset = ((total - 1) / limit) * limit
	}
	items, err := a.jobsPage(where, args, limit, offset)
	if err != nil {
		problem(w, 500, "Could not read job history.")
		return
	}
	respond(w, 200, map[string]any{"items": items, "total": total, "offset": offset, "limit": limit})
}

// Visibility is presentation only: accounting, alerts, exports and retries remain intact.
func (a *App) jobVisibility(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Hidden bool `json:"hidden"`
	}
	if !decode(w, r, &input) {
		return
	}
	id := r.PathValue("id")
	var exists int
	if a.DB.QueryRow("SELECT count(*) FROM jobs WHERE id=?", id).Scan(&exists) != nil || exists == 0 {
		problem(w, 404, "Job not found.")
		return
	}
	var err error
	if input.Hidden {
		_, err = a.DB.Exec("INSERT OR IGNORE INTO hidden_jobs(job_id) VALUES(?)", id)
	} else {
		_, err = a.DB.Exec("DELETE FROM hidden_jobs WHERE job_id=?", id)
	}
	if err != nil {
		problem(w, 500, "Could not update visibility.")
		return
	}
	a.Audit("job.visibility", id, "Hidden from default activity views: "+strconv.FormatBool(input.Hidden))
	respond(w, 200, map[string]bool{"hidden": input.Hidden})
}
