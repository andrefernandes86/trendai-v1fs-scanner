package localapp

import (
	"context"
	"net/http"
	"strings"
	"time"
)

func (a *App) beat(name string) {
	a.healthMu.Lock()
	if a.heartbeats == nil {
		a.heartbeats = map[string]time.Time{}
	}
	a.heartbeats[name] = time.Now()
	a.healthMu.Unlock()
}
func (a *App) liveStatus(ctx context.Context) (map[string]any, bool) {
	checks := map[string]any{}
	healthy := true
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if e := a.DB.PingContext(probe); e != nil {
		checks["database"] = "unresponsive"
		healthy = false
	} else {
		checks["database"] = "ok"
	}
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	for name, at := range a.heartbeats {
		limit := 15 * time.Second
		if strings.HasPrefix(name, "source:") {
			limit = 4 * time.Minute
		} else if name != "monitor" {
			limit = 12 * time.Minute
		}
		age := time.Since(at)
		checks[name] = map[string]any{"ageSeconds": int(age.Seconds()), "healthy": age < limit}
		if age >= limit {
			healthy = false
		}
	}
	if a.started.IsZero() {
		checks["runtime"] = "not started"
		healthy = false
	}
	return checks, healthy
}
func (a *App) liveness(w http.ResponseWriter, r *http.Request) {
	checks, ok := a.liveStatus(r.Context())
	status := 200
	if !ok {
		status = 503
	}
	respond(w, status, map[string]any{"healthy": ok, "checks": checks, "scope": "API, database, scheduler and worker progress. Remote storage/scanner outages are processing-readiness failures, not restart triggers."})
}

func (a *App) stopBeat(name string) {
	a.healthMu.Lock()
	delete(a.heartbeats, name)
	a.healthMu.Unlock()
}
