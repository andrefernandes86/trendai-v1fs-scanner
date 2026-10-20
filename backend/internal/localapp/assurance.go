package localapp

import (
	"encoding/json"
	"net/http"
	"syscall"
	"time"
)

func (a *App) assurance(w http.ResponseWriter, r *http.Request) {
	alerts := []map[string]any{}
	profiles, _ := a.List("profiles")
	for _, raw := range profiles {
		var p Profile
		if json.Unmarshal(raw, &p) != nil {
			continue
		}
		var s struct {
			CheckedAt string `json:"checkedAt"`
			Errors    int    `json:"errors"`
		}
		if p.Enabled {
			e := a.Get("monitorStatus", p.ID, &s)
			at, _ := time.Parse(time.RFC3339Nano, s.CheckedAt)
			if e != nil || time.Since(at) > max(3*p.Interval(), 5*time.Minute) {
				alerts = append(alerts, map[string]any{"code": "STALE_SOURCE", "profileId": p.ID, "severity": "critical", "message": "Scheduled source checks are stale."})
			}
			if s.Errors > 0 {
				alerts = append(alerts, map[string]any{"code": "SOURCE_ERRORS", "profileId": p.ID, "severity": "critical", "message": "Source enumeration or queue admission has errors."})
			}
		}
		var overdue int
		_ = a.DB.QueryRow("SELECT count(*) FROM jobs WHERE profile_id=? AND state IN ('QUEUED','SCANNING','ROUTING','RETRY_PENDING') AND julianday(created_at)<julianday(?)", p.ID, time.Now().Add(-time.Duration(defaultInt(p.ProcessingDeadlineSeconds, 3600))*time.Second).UTC().Format(time.RFC3339Nano)).Scan(&overdue)
		if overdue > 0 {
			alerts = append(alerts, map[string]any{"code": "OVERDUE_FILES", "profileId": p.ID, "count": overdue, "severity": "warning", "message": "Active files exceeded the processing deadline. Check queue size, scanner response and storage errors."})
		}
	}
	var excluded, total int
	_ = a.DB.QueryRow("SELECT count(*),COALESCE(sum(CASE WHEN verdict='EXCLUDED' THEN 1 ELSE 0 END),0) FROM jobs WHERE julianday(created_at)>=julianday(?)", time.Now().Add(-24*time.Hour).UTC().Format(time.RFC3339Nano)).Scan(&total, &excluded)
	if total >= 10 && excluded*2 > total {
		alerts = append(alerts, map[string]any{"code": "BROAD_EXCLUSIONS", "severity": "warning", "count": excluded, "message": "More than half of recent jobs bypassed scanning. Review exclusion scope."})
	}
	var unresolved, unaccounted int
	_ = a.DB.QueryRow("SELECT count(*) FROM jobs WHERE state='HELD'").Scan(&unresolved)
	if unresolved > 0 {
		alerts = append(alerts, map[string]any{"code": "HELD_FILES", "severity": "warning", "count": unresolved, "message": "Files are held for review. Open File activity, filter HELD, and inspect each error before retrying or recovering."})
	}
	_ = a.DB.QueryRow("SELECT count(*) FROM inventory WHERE status IN ('DISCOVERED','ERROR')").Scan(&unaccounted)
	var disk syscall.Statfs_t
	if syscall.Statfs(a.DataDir, &disk) == nil && disk.Blocks > 0 && disk.Bavail*100/disk.Blocks < 10 {
		alerts = append(alerts, map[string]any{"code": "DISK_PRESSURE", "severity": "critical", "message": "Host data disk has less than 10 percent available."})
	}
	respond(w, 200, map[string]any{"alerts": alerts, "heldFiles": unresolved, "unaccountedSourceVersions": unaccounted, "observedAt": stamp(), "notificationMode": "Console and authenticated API; external notification delivery must be configured by the operator."})
}
