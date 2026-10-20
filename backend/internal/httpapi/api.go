package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"github.com/coreos/go-oidc/v3/oidc"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type API struct {
	Store     *core.Store
	Verifier  *oidc.IDTokenVerifier
	Origin    string
	Simulated bool
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if a.Store.DB.Ping(ctx) != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		write(w, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/status", a.status)
	mux.HandleFunc("GET /api/events", a.events)
	mux.HandleFunc("GET /api/jobs", a.jobs)
	mux.HandleFunc("GET /api/audit", a.audit)
	mux.HandleFunc("GET /api/config/{kind}", a.config)
	mux.HandleFunc("PUT /api/config/{kind}/{id}", a.save)
	mux.HandleFunc("POST /api/eventgrid", a.eventGrid)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.Header.Get("Origin") == a.Origin && a.Origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", a.Origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/healthz" {
			mux.ServeHTTP(w, r)
			return
		}
		if a.Verifier == nil {
			http.Error(w, "identity provider unavailable", 503)
			return
		}
		token, e := a.Verifier.Verify(r.Context(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if e != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		var c struct {
			Roles []string `json:"roles"`
			OID   string   `json:"oid"`
		}
		if token.Claims(&c) != nil {
			http.Error(w, "invalid claims", 401)
			return
		}
		want := "Viewer"
		if r.Method != "GET" {
			want = "Admin"
		}
		if r.URL.Path == "/api/eventgrid" {
			want = "EventIngestor"
		}
		ok := false
		for _, role := range c.Roles {
			if role == want || (role == "Admin" && want != "EventIngestor") {
				ok = true
			}
		}
		if !ok {
			http.Error(w, "forbidden", 403)
			return
		}
		ctx := context.WithValue(r.Context(), actorKey{}, c.OID)
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

type actorKey struct{}

func (a *API) config(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "sources" && kind != "profiles" && kind != "capacity" {
		http.NotFound(w, r)
		return
	}
	v, e := a.Store.List(r.Context(), kind)
	if e != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	write(w, v)
}
func (a *API) save(w http.ResponseWriter, r *http.Request) {
	kind, id := r.PathValue("kind"), r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var v any
	switch kind {
	case "sources":
		var s core.Source
		if dec.Decode(&s) != nil || s.ID != id || s.Validate() != nil {
			http.Error(w, "invalid source or routing configuration", 400)
			return
		}
		var p core.Profile
		if a.Store.Config(r.Context(), "profiles", s.ProfileID, &p) != nil {
			http.Error(w, "scan profile does not exist", 400)
			return
		}
		v = s
	case "profiles":
		var p core.Profile
		if dec.Decode(&p) != nil || p.ID != id || len(id) > 50 || p.Name == "" || p.Concurrency < 1 || p.Concurrency > 128 {
			http.Error(w, "invalid profile", 400)
			return
		}
		v = p
	case "capacity":
		var c core.Capacity
		if dec.Decode(&c) != nil || id != "default" || c.Global < 1 || c.Global > 256 || c.Tenant < 1 || c.Tenant > c.Global || c.PerWorker < 1 || c.PerWorker > 32 || c.MaxAttempts < 1 || c.MaxAttempts > 10 || c.MinReplicas < 0 || c.MaxReplicas < c.MinReplicas || c.MaxReplicas > 100 {
			http.Error(w, "invalid capacity limits", 400)
			return
		}
		v = c
	default:
		http.NotFound(w, r)
		return
	}
	actor, _ := r.Context().Value(actorKey{}).(string)
	if a.Store.Save(r.Context(), kind, id, actor, v) != nil {
		http.Error(w, "configuration could not be saved", 503)
		return
	}
	write(w, map[string]bool{"saved": true})
}
func (a *API) status(w http.ResponseWriter, r *http.Request) {
	v, e := a.snapshot(r.Context())
	if e != nil {
		http.Error(w, "telemetry unavailable", 503)
		return
	}
	write(w, v)
}
func (a *API) snapshot(ctx context.Context) (any, error) {
	rows, e := a.Store.DB.Query(ctx, "SELECT state,count(*) FROM jobs GROUP BY state")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	states := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if e = rows.Scan(&k, &n); e != nil {
			return nil, e
		}
		states[k] = n
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	var pending int64
	var oldest *time.Time
	e = a.Store.DB.QueryRow(ctx, "SELECT count(*),min(available_at) FROM outbox WHERE sent_at IS NULL").Scan(&pending, &oldest)
	if e != nil {
		return nil, e
	}
	return map[string]any{"states": states, "pendingOutbox": pending, "oldestPending": oldest, "observedAt": time.Now().UTC(), "simulatedScanner": a.Simulated, "telemetrySource": "PostgreSQL job ledger", "workerMetrics": "unavailable"}, nil
}
func (a *API) events(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	end := time.NewTimer(5 * time.Minute)
	defer end.Stop()
	for {
		v, e := a.snapshot(r.Context())
		if e != nil {
			return
		}
		b, _ := json.Marshal(v)
		if _, e = fmt.Fprintf(w, "event: telemetry\ndata: %s\n\n", b); e != nil {
			return
		}
		f.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-end.C:
			return
		case <-t.C:
		}
	}
}
func (a *API) jobs(w http.ResponseWriter, r *http.Request) {
	rows, e := a.Store.DB.Query(r.Context(), "SELECT id FROM jobs ORDER BY created_at DESC LIMIT 200")
	if e != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	out := []core.Job{}
	for _, id := range ids {
		j, e := a.Store.Job(r.Context(), id)
		if e != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		out = append(out, j)
	}
	write(w, out)
}
func (a *API) audit(w http.ResponseWriter, r *http.Request) {
	rows, e := a.Store.DB.Query(r.Context(), "SELECT seq,at,actor,action,object_id,correlation_id,detail FROM audit ORDER BY seq DESC LIMIT 200")
	if e != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var seq int64
		var at time.Time
		var actor, action, id, corr string
		var detail json.RawMessage
		if rows.Scan(&seq, &at, &actor, &action, &id, &corr, &detail) != nil {
			http.Error(w, "invalid audit record", 500)
			return
		}
		out = append(out, map[string]any{"seq": seq, "at": at, "actor": actor, "action": action, "objectId": id, "correlationId": corr, "detail": detail})
	}
	write(w, out)
}

type GridEvent struct {
	ID        string `json:"id"`
	Topic     string `json:"topic"`
	EventType string `json:"eventType"`
	Data      struct {
		URL            string `json:"url"`
		API            string `json:"api"`
		ETag           string `json:"eTag"`
		Length         int64  `json:"contentLength"`
		Version        string `json:"versionId"`
		ValidationCode string `json:"validationCode"`
	} `json:"data"`
}

func (a *API) eventGrid(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	b, e := io.ReadAll(r.Body)
	var events []GridEvent
	if e != nil || json.Unmarshal(b, &events) != nil || len(events) > 100 {
		http.Error(w, "invalid event batch", 400)
		return
	}
	sources, e := a.Store.List(r.Context(), "sources")
	if e != nil {
		http.Error(w, "database unavailable", 503)
		return
	}
	for _, ev := range events {
		if ev.EventType == "Microsoft.EventGrid.SubscriptionValidationEvent" {
			write(w, map[string]string{"validationResponse": ev.Data.ValidationCode})
			return
		}
		if ev.EventType != "Microsoft.Storage.BlobCreated" {
			continue
		}
		switch ev.Data.API {
		case "PutBlob", "PutBlockList", "FlushWithClose", "SftpCommit", "CopyBlob":
		default:
			continue
		}
		u, e := url.Parse(ev.Data.URL)
		if e != nil || u.Scheme != "https" || u.RawQuery != "" || u.User != nil {
			http.Error(w, "invalid blob URL", 400)
			return
		}
		matched := false
		for _, b := range sources {
			var s core.Source
			if json.Unmarshal(b, &s) != nil || !s.Enabled || s.Kind != "blob" {
				continue
			}
			if u.Host != s.Account+".blob.core.windows.net" {
				continue
			}
			prefix := "/" + s.Container + "/"
			if !strings.HasPrefix(u.Path, prefix) {
				continue
			}
			key := strings.TrimPrefix(u.Path, prefix)
			if !strings.HasPrefix(key, s.Prefix) {
				continue
			}
			matched = true
			j := core.Job{SourceID: s.ID, Tenant: s.Tenant, ProfileID: s.ProfileID, Key: key, Version: ev.Data.Version, ETag: ev.Data.ETag, Size: ev.Data.Length}
			if e = a.Store.Discover(r.Context(), j); e != nil {
				http.Error(w, "event persistence failed", 503)
				return
			}
		}
		if !matched {
			http.Error(w, "source not registered", 400)
			return
		}
	}
	w.WriteHeader(202)
	write(w, map[string]bool{"accepted": true})
}
