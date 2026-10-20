package localapp

import (
	"net/http"
)

func (a *App) attachStorageResults(m Mount, files []BlobEntry) {
	for i := range files {
		f := &files[i]
		destination := m.BaseURL() + "/" + f.Key
		var payload []byte
		var id, verdict, actual string
		query := "SELECT j.id,j.verdict,j.destination,coalesce(d.payload,X'') FROM jobs j LEFT JOIN scan_details d ON d.job_id=j.id WHERE j.destination=? ORDER BY j.updated_at DESC LIMIT 1"
		if a.DB.QueryRow(query, destination).Scan(&id, &verdict, &actual, &payload) != nil || actual != destination {
			continue
		}
		f.ScanJobID = id
		f.Verdict = verdict
		if len(payload) > 0 {
			var details ScanDetails
			if a.Unseal(payload, &details) == nil {
				f.Detections = details.Detections
				f.ScanResponseRecorded = true
			}
		}
	}
}
func (a *App) jobRecord(w http.ResponseWriter, r *http.Request) {
	items, err := a.jobsPage(" WHERE j.id=?", []any{r.PathValue("id")}, 1, 0)
	if err != nil {
		problem(w, 500, "Could not read record.")
		return
	}
	if len(items) == 0 {
		problem(w, 404, "Record not found.")
		return
	}
	respond(w, 200, items[0])
}
