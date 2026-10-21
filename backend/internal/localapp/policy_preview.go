package localapp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

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
