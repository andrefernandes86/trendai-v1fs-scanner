package localapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func (a *App) recoverJob(ctx context.Context, parent string, enrich bool) (string, error) {
	var payload []byte
	var destination, verdict, state string
	if e := a.DB.QueryRow("SELECT snapshot,destination,verdict,state FROM jobs WHERE id=?", parent).Scan(&payload, &destination, &verdict, &state); e != nil {
		return "", e
	}
	if destination == "" {
		return "", fmt.Errorf("No verified destination is available; retry the source job instead.")
	}
	if !enrich && (state != "HELD" || verdict != "UNKNOWN") {
		return "", fmt.Errorf("Only isolated unknown files can be recovered.")
	}
	var s Snapshot
	if e := a.Unseal(payload, &s); e != nil {
		return "", e
	}

	source := s.Failed
	if verdict == "CLEAN" || verdict == "EXCLUDED" {
		source = s.Good
	}
	if verdict == "MALICIOUS" {
		source = s.Bad
	}
	key := strings.TrimPrefix(destination, source.BaseURL()+"/")
	if !strings.HasPrefix(destination, source.BaseURL()+"/") {
		return "", fmt.Errorf("Destination does not match the immutable policy snapshot.")
	}
	s.Source = source
	s.Key = key
	s.Version = ""
	if source.Type() == "blob" {
		b, e := source.BlobClient(key, "")
		if e != nil {
			return "", e
		}
		v, e := b.GetProperties(ctx, nil)
		if e != nil {
			return "", e
		}
		s.ETag = string(*v.ETag)
		s.Size = *v.ContentLength
	} else {
		v, e := shareProperties(ctx, source, key)
		if e != nil {
			return "", e
		}
		s.ETag = v.ETag
		s.Size = v.Size
	}
	// Current scanner credentials/policy are explicit for recovery; source identity remains the captured isolated file.
	var current Profile
	if a.Get("profiles", s.Profile.ID, &current) == nil {
		s.Profile = current
	}
	if a.Get("scanner", "default", &s.Scanner) != nil {
		return "", fmt.Errorf("Scanner configuration unavailable.")
	}
	if enrich {
		local, digest, e := Download(ctx, s, a.DataDir)
		if e != nil {
			return "", e
		}
		defer os.Remove(local)
		var previous string
		_ = a.DB.QueryRow("SELECT digest FROM jobs WHERE id=?", parent).Scan(&previous)
		if previous != "" && previous != digest {
			return "", fmt.Errorf("Destination no longer matches historical bytes.")
		}
		raw, e := a.Scan(ctx, local, s.Scanner, s.Profile)
		if e != nil {
			return "", e
		}
		if e = a.recordScanDetails(parent, raw, s.Scanner.APIKey); e != nil {
			return "", e
		}
		a.Audit("scan.enriched", parent, "Detection details collected from the exact historical destination bytes; historical verdict unchanged.")
		return parent, nil
	}
	var children int
	_ = a.DB.QueryRow("SELECT count(*) FROM recovery_links WHERE parent_id=?", parent).Scan(&children)
	if children >= defaultInt(s.Profile.RecoveryAttempts, 3) {
		return "", fmt.Errorf("Recovery budget exhausted.")
	}
	var active int
	_ = a.DB.QueryRow("SELECT count(*) FROM recovery_links l JOIN jobs j ON j.id=l.child_id WHERE l.parent_id=? AND j.state IN ('QUEUED','SCANNING','ROUTING','RETRY_PENDING','COMPLETED','QUARANTINED')", parent).Scan(&active)
	if active > 0 {
		return "", fmt.Errorf("A recovery is already active or resolved.")
	}
	// Keep the source's original name on retry, including compatibility for old paths.
	s.Profile.Rules = nil
	s.Profile.IgnorePatterns = "" // recovery always scans; never bypass an unknown file
	s.Profile.Revision += int64(children+1) * 1000000
	// If the result remains unknown, retain it in the existing isolated location rather than recopying to the same root.

	id, e := a.insertJob(s)
	if e != nil {
		return "", e
	}
	_, e = a.DB.Exec("INSERT OR IGNORE INTO recovery_links(parent_id,child_id,created_at) VALUES(?,?,?)", parent, id, stamp())
	if e != nil {
		return "", e
	}
	a.Audit("scan.recovered", parent, "Queued recovery job "+id)
	return id, nil
}
func (a *App) recoverHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	id, e := a.recoverJob(ctx, r.PathValue("id"), r.URL.Query().Get("enrich") == "true")
	if e != nil {
		problem(w, 409, e.Error())
		return
	}
	respond(w, 202, map[string]string{"jobId": id})
}
func (a *App) recoverySweep(ctx context.Context) {
	rows, e := a.DB.Query("SELECT id,profile_id,updated_at FROM jobs WHERE state='HELD' AND verdict='UNKNOWN' AND destination!='' AND id NOT IN (SELECT child_id FROM recovery_links) ORDER BY updated_at LIMIT 100")
	if e != nil {
		return
	}
	type item struct{ id, p, at string }
	var all []item
	for rows.Next() {
		var x item
		if rows.Scan(&x.id, &x.p, &x.at) == nil {
			all = append(all, x)
		}
	}
	rows.Close()
	for _, x := range all {
		if ctx.Err() != nil {
			return
		}
		var p Profile
		if a.Get("profiles", x.p, &p) != nil || !p.RecoveryEnabled {
			continue
		}
		var latest string
		_ = a.DB.QueryRow("SELECT COALESCE(max(created_at),'') FROM recovery_links WHERE parent_id=?", x.id).Scan(&latest)
		if latest > x.at {
			x.at = latest
		}
		at, _ := time.Parse(time.RFC3339Nano, x.at)
		if time.Since(at) < time.Duration(defaultInt(p.RecoverySeconds, 3600))*time.Second {
			continue
		}
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, _ = a.recoverJob(c, x.id, false)
		cancel()
	}
}
func (a *App) previewPolicy(w http.ResponseWriter, r *http.Request) {
	var p Profile
	if !decode(w, r, &p) {
		return
	}
	if e := p.ReliabilityValidate(); e != nil {
		problem(w, 400, e.Error())
		return
	}
	var m Mount
	if a.Get("mounts", p.SourceMount, &m) != nil {
		problem(w, 400, "Select a saved source connection.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	marker := ""
	counts := map[string]int{"scan": 0, "exclude": 0, "hold": 0, "ignore": 0}
	samples := []map[string]any{}
	total := 0
	for {
		files, next, e := ListBlobs(ctx, m, p.Prefix, marker)
		if e != nil {
			problem(w, 502, "Cannot enumerate source for policy preview.")
			return
		}
		for _, f := range files {
			action, rule := p.FilePolicy(strings.TrimPrefix(f.Key, m.Prefix+p.Prefix), f.Size)
			counts[action]++
			total++
			if len(samples) < 100 {
				samples = append(samples, map[string]any{"file": f.Key, "action": action, "rule": rule})
			}
		}
		if next == "" {
			break
		}
		marker = next
		if total >= 10000 {
			respond(w, 200, map[string]any{"counts": counts, "samples": samples, "truncated": true})
			return
		}
	}
	respond(w, 200, map[string]any{"counts": counts, "samples": samples, "truncated": false})
}

// Decode helper shared by monitoring/recovery when API queries return raw JSON profiles.
func decodeProfile(raw json.RawMessage) (Profile, error) {
	var p Profile
	e := json.Unmarshal(raw, &p)
	return p, e
}
