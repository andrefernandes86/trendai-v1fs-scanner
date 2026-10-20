package localapp

import (
	"encoding/csv"
	"fmt"
	"net/http"
)

func (a *App) inventoryCSV(w http.ResponseWriter, r *http.Request) {
	rows, e := a.DB.QueryContext(r.Context(), "SELECT profile_id,key,etag,size,last_seen,status,reason,job_id FROM inventory ORDER BY profile_id,key,last_seen DESC")
	if e != nil {
		problem(w, 500, "Inventory unavailable.")
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="v1fs-source-inventory.csv"`)
	out := csv.NewWriter(w)
	_ = out.Write([]string{"profile_id", "file", "source_etag", "size_bytes", "last_seen_utc", "accounting_status", "reason", "job_id"})
	for rows.Next() {
		var profile, key, etag, at, status, reason, job string
		var size int64
		if rows.Scan(&profile, &key, &etag, &size, &at, &status, &reason, &job) != nil {
			return
		}
		row := []string{profile, key, etag, fmt.Sprint(size), at, status, reason, job}
		for i := range row {
			row[i] = csvText(row[i])
		}
		if out.Write(row) != nil {
			return
		}
	}
	out.Flush()
}
