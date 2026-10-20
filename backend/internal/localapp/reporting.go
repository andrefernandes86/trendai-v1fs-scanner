package localapp

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *App) statistics(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	counts := map[string]int{}
	var scanningNow int
	if err := a.DB.QueryRow("SELECT count(*) FROM jobs WHERE state='SCANNING'").Scan(&scanningNow); err != nil {
		problem(w, 500, "Scan statistics unavailable.")
		return
	}
	for label, start := range map[string]time.Time{"minute": now.Add(-time.Minute), "hour": now.Add(-time.Hour), "day": now.Add(-24 * time.Hour), "month": now.Add(-30 * 24 * time.Hour)} {
		var countsTemp int
		// Older records have no scan timestamp; use their last update as a labeled estimate.
		err := a.DB.QueryRow(`SELECT count(*) FROM jobs j LEFT JOIN scan_results s ON s.job_id=j.id WHERE (s.job_id IS NOT NULL OR j.verdict IN ('CLEAN','MALICIOUS')) AND julianday(COALESCE(s.scanned_at,j.updated_at))>=julianday(?)`, start.Format(time.RFC3339Nano)).Scan(&countsTemp)
		if err != nil {
			problem(w, 500, "Scan statistics unavailable.")
			return
		}
		counts[label] = countsTemp
	}
	respond(w, 200, map[string]any{"counts": counts, "scanningNow": scanningNow, "observedAt": now.Format(time.RFC3339Nano), "note": "Scanning now counts jobs in the scanning stage, including source download and waiting for the scanner. Queued jobs and destination transfers are excluded. Historical totals count distinct file-version jobs with a scanner response once. Rolling windows; month = 30 days. Older records use their last update time when no scan timestamp was recorded."})
}

// Prevent spreadsheet programs from interpreting user-controlled fields as formulas.
func csvText(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) || strings.HasPrefix(value, "\t") || strings.HasPrefix(value, "\r") || strings.HasPrefix(value, "\n") {
		return "'" + value
	}
	return value
}
func (a *App) exportJobsCSV(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.QueryContext(r.Context(), `SELECT j.id,j.key,j.profile_id,j.profile_name,j.source_id,j.etag,j.version,j.size,j.state,j.verdict,j.digest,j.destination,j.error,j.attempts,j.created_at,j.updated_at,COALESCE(s.scanned_at,''),COALESCE(s.verdict,''),COALESCE(d.payload,X''),COALESCE(m.payload,X'') FROM jobs j LEFT JOIN scan_results s ON s.job_id=j.id LEFT JOIN scan_details d ON d.job_id=j.id LEFT JOIN move_records m ON m.job_id=j.id ORDER BY j.created_at DESC,j.id`)
	if err != nil {
		problem(w, 500, "Could not export file records.")
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="v1fs-all-files.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	writer := csv.NewWriter(w)
	if err = writer.Write([]string{"job_id", "file", "profile_id", "profile_name", "source_connection_id", "source_etag", "source_version", "size_bytes", "state", "verdict", "malicious", "hash_collected", "hash_algorithm", "sha256", "destination", "error", "attempts", "created_at_utc", "updated_at_utc", "scanned_at_utc", "scanner_verdict", "malware_names", "detection_engines", "scan_response_recorded", "crc32c", "move_phase", "matched_rule"}); err != nil {
		return
	}
	for rows.Next() {
		var j Job
		var scannedAt, scanVerdict string
		var payload, moveBytes []byte
		if err = rows.Scan(&j.ID, &j.Key, &j.ProfileID, &j.ProfileName, &j.SourceID, &j.ETag, &j.Version, &j.Size, &j.State, &j.Verdict, &j.Digest, &j.Destination, &j.Error, &j.Attempts, &j.CreatedAt, &j.UpdatedAt, &scannedAt, &scanVerdict, &payload, &moveBytes); err != nil {
			return
		}
		malicious := "unknown"
		if j.Verdict == "CLEAN" {
			malicious = "false"
		}
		if j.Verdict == "MALICIOUS" {
			malicious = "true"
		}
		algorithm := ""
		if j.Digest != "" {
			algorithm = "SHA-256"
		}
		names, engines := []string{}, []string{}
		recorded := false
		if len(payload) > 0 {
			var d ScanDetails
			if a.Unseal(payload, &d) == nil {
				recorded = true
				for _, v := range d.Detections {
					names = append(names, v.Name)
					engines = append(engines, v.Engine)
				}
			}
		}
		var move MoveRecord
		if len(moveBytes) > 0 {
			_ = a.Unseal(moveBytes, &move)
		}
		row := []string{j.ID, j.Key, j.ProfileID, j.ProfileName, j.SourceID, j.ETag, j.Version, strconv.FormatInt(j.Size, 10), j.State, j.Verdict, malicious, strconv.FormatBool(j.Digest != ""), algorithm, j.Digest, j.Destination, j.Error, strconv.Itoa(j.Attempts), j.CreatedAt, j.UpdatedAt, scannedAt, scanVerdict, strings.Join(names, "; "), strings.Join(engines, "; "), strconv.FormatBool(recorded), move.CRC32C, move.Phase, move.Rule}
		for i := range row {
			row[i] = csvText(row[i])
		}
		if err = writer.Write(row); err != nil {
			return
		}
	}
	writer.Flush()
}
