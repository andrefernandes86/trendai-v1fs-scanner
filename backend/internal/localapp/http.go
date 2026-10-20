package localapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		problem(w, 400, "Invalid request fields.")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		problem(w, 400, "Only one request object is accepted.")
		return false
	}
	return true
}
func hashToken(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func (a *App) authenticated(r *http.Request) bool {
	c, e := r.Cookie("v1fs_session")
	if e != nil {
		return false
	}
	var expires int64
	e = a.DB.QueryRow("SELECT expires FROM sessions WHERE token=?", hashToken(c.Value)).Scan(&expires)
	return e == nil && expires > time.Now().Unix()
}
func (a *App) setupRequired() bool {
	var n int
	e := a.DB.QueryRow("SELECT count(*) FROM config WHERE kind='admin' AND id='default'").Scan(&n)
	return e == nil && n == 0
}
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]bool{"setupRequired": a.setupRequired(), "authenticated": a.authenticated(r)})
	})
	mux.HandleFunc("POST /api/setup", a.setup)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, e := r.Cookie("v1fs_session"); e == nil {
			_, _ = a.DB.Exec("DELETE FROM sessions WHERE token=?", hashToken(c.Value))
		}
		http.SetCookie(w, &http.Cookie{Name: "v1fs_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Secure: r.TLS != nil})
		respond(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/mounts", a.mountList)
	mux.HandleFunc("PUT /api/mounts/{id}", a.mountSave)
	mux.HandleFunc("DELETE /api/mounts/{id}", a.mountDelete)
	mux.HandleFunc("POST /api/mounts/{id}/test", a.mountTest)
	mux.HandleFunc("GET /api/mounts/{id}/blobs", a.blobs)
	mux.HandleFunc("GET /api/profiles", a.profiles)
	mux.HandleFunc("PUT /api/profiles/{id}", a.profileSave)
	mux.HandleFunc("DELETE /api/profiles/{id}", func(w http.ResponseWriter, r *http.Request) { a.remove(w, r, "profiles") })
	mux.HandleFunc("GET /api/scanner", a.scannerGet)
	mux.HandleFunc("PUT /api/scanner", a.scannerSave)
	mux.HandleFunc("POST /api/scan", a.scan)
	mux.HandleFunc("GET /api/jobs", func(w http.ResponseWriter, r *http.Request) {
		j, e := a.Jobs()
		if e != nil {
			problem(w, 500, "Could not read jobs.")
			return
		}
		respond(w, 200, j)
	})
	mux.HandleFunc("POST /api/jobs/{id}/retry", a.retryJob)
	mux.HandleFunc("GET /api/status", a.status)
	mux.HandleFunc("GET /api/audit", a.audit)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]string{"status": "ok", "service": "trendai-v1fs-local"})
	})
	mux.Handle("/", http.FileServer(http.Dir(a.WebDir)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		host := r.Host
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		if host != "localhost" && net.ParseIP(host) == nil {
			problem(w, 403, "Use this host's IP address or localhost.")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			origin := r.Header.Get("Origin")
			if origin != "" {
				u, e := url.Parse(origin)
				if e != nil || u.Host != r.Host {
					problem(w, 403, "Cross-origin requests are rejected.")
					return
				}
			}
		}
		public := r.URL.Path == "/api/session" || r.URL.Path == "/api/setup" || r.URL.Path == "/api/login" || r.URL.Path == "/healthz"
		if strings.HasPrefix(r.URL.Path, "/api/") && !public && !a.authenticated(r) {
			problem(w, 401, "Sign in to administer the scanner.")
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	if len(v.Password) < 12 || len(v.Password) > 72 {
		problem(w, 400, "Use an administrator password between 12 and 72 characters.")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.setupRequired() {
		problem(w, 409, "Administrator is already configured.")
		return
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(v.Password), 12)
	if e != nil {
		problem(w, 500, "Password setup failed.")
		return
	}
	if e = a.Save("admin", "default", string(hash)); e != nil {
		problem(w, 500, "Password setup failed.")
		return
	}
	a.session(w, r)
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	a.mu.Lock()
	var last string
	_ = a.Get("authThrottle", "last", &last)
	t, _ := time.Parse(time.RFC3339Nano, last)
	if time.Since(t) < 2*time.Second {
		a.mu.Unlock()
		problem(w, 429, "Please wait before trying again.")
		return
	}
	_ = a.Save("authThrottle", "last", stamp())
	a.mu.Unlock()
	var hash string
	if a.Get("admin", "default", &hash) != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(v.Password)) != nil {
		a.Audit("auth.login_failed", "admin", "")
		problem(w, 401, "Incorrect password.")
		return
	}
	a.session(w, r)
}
func (a *App) session(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		problem(w, 500, "Session creation failed.")
		return
	}
	token := hex.EncodeToString(b)
	if _, e := a.DB.Exec("INSERT INTO sessions(token,expires) VALUES(?,?)", hashToken(token), time.Now().Add(12*time.Hour).Unix()); e != nil {
		problem(w, 500, "Session creation failed.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "v1fs_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 43200})
	a.Audit("auth.login", "admin", "")
	respond(w, 200, map[string]bool{"authenticated": true})
}
func (a *App) mountList(w http.ResponseWriter, r *http.Request) {
	raw, e := a.List("mounts")
	if e != nil {
		problem(w, 500, "Could not read connections.")
		return
	}
	out := []Mount{}
	for _, b := range raw {
		var m Mount
		if json.Unmarshal(b, &m) != nil {
			problem(w, 500, "Could not decrypt connection.")
			return
		}
		m.CredentialSaved = m.Secret != ""
		m.Secret = ""
		out = append(out, m)
	}
	respond(w, 200, out)
}
func (a *App) mountSave(w http.ResponseWriter, r *http.Request) {
	var m Mount
	if !decode(w, r, &m) {
		return
	}
	if m.ID != r.PathValue("id") {
		problem(w, 400, "Connection ID mismatch.")
		return
	}
	var old Mount
	if a.Get("mounts", m.ID, &old) == nil && m.Secret == "" && m.AuthType == old.AuthType && m.Account == old.Account && m.ResourceID == old.ResourceID {
		m.Secret = old.Secret
	}
	if e := m.Validate(); e != nil {
		problem(w, 400, e.Error())
		return
	}
	if e := a.Save("mounts", m.ID, m); e != nil {
		problem(w, 500, "Could not save connection.")
		return
	}
	respond(w, 200, map[string]bool{"saved": true})
}
func (a *App) mountDelete(w http.ResponseWriter, r *http.Request) {
	profiles, e := a.List("profiles")
	if e != nil {
		problem(w, 500, "Could not check profile references.")
		return
	}
	for _, b := range profiles {
		var p Profile
		_ = json.Unmarshal(b, &p)
		id := r.PathValue("id")
		if p.SourceMount == id || p.GoodMount == id || p.BadMount == id {
			problem(w, 409, "Remove this connection from scan profiles first.")
			return
		}
	}
	a.remove(w, r, "mounts")
}
func (a *App) remove(w http.ResponseWriter, r *http.Request, kind string) {
	if _, e := a.DB.Exec("DELETE FROM config WHERE kind=? AND id=?", kind, r.PathValue("id")); e != nil {
		problem(w, 500, "Delete failed.")
		return
	}
	a.Audit(kind+".deleted", r.PathValue("id"), "")
	respond(w, 200, map[string]bool{"deleted": true})
}
func (a *App) mountTest(w http.ResponseWriter, r *http.Request) {
	var m Mount
	if a.Get("mounts", r.PathValue("id"), &m) != nil {
		problem(w, 404, "Connection not found.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	_, _, e := ListBlobs(ctx, m, "", "")
	if e != nil {
		problem(w, 502, "Azure connection failed. Check account, container, credentials, network, and list permissions.")
		return
	}
	respond(w, 200, map[string]string{"status": "Connected", "detail": "Container listing verified. Destination write permission is checked during routing."})
}
func (a *App) blobs(w http.ResponseWriter, r *http.Request) {
	var m Mount
	if a.Get("mounts", r.PathValue("id"), &m) != nil {
		problem(w, 404, "Connection not found.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	files, next, e := ListBlobs(ctx, m, r.URL.Query().Get("prefix"), r.URL.Query().Get("marker"))
	if e != nil {
		problem(w, 502, "Cannot list Azure blobs. Test this connection and check permissions.")
		return
	}
	respond(w, 200, map[string]any{"files": files, "nextMarker": next})
}
func (a *App) profiles(w http.ResponseWriter, r *http.Request) {
	p, e := a.List("profiles")
	if e != nil {
		problem(w, 500, "Could not read profiles.")
		return
	}
	respond(w, 200, p)
}
func (a *App) profileSave(w http.ResponseWriter, r *http.Request) {
	var p Profile
	if !decode(w, r, &p) {
		return
	}
	if p.ID != r.PathValue("id") || !idPattern.MatchString(p.ID) || p.Name == "" {
		problem(w, 400, "A profile ID and name are required.")
		return
	}
	for _, s := range []string{p.Prefix, p.GoodPrefix, p.BadPrefix} {
		if s != "" && !core.ValidKey(s) {
			problem(w, 400, "Invalid path prefix.")
			return
		}
	}
	var mounts [3]Mount
	for i, id := range []string{p.SourceMount, p.GoodMount, p.BadMount} {
		if a.Get("mounts", id, &mounts[i]) != nil {
			problem(w, 400, "Select existing source, clean, and malicious container connections.")
			return
		}
	}
	for i := 0; i < 3; i++ {
		for j := i + 1; j < 3; j++ {
			if mounts[i].BaseURL() == mounts[j].BaseURL() {
				problem(w, 400, "Source, clean, and malicious destinations must use distinct containers.")
				return
			}
		}
	}
	if p.Enabled {
		var s Scanner
		if a.Get("scanner", "default", &s) != nil || s.Validate() != nil {
			problem(w, 400, "Configure Vision One before enabling automatic scanning.")
			return
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var old Profile
	_ = a.Get("profiles", p.ID, &old)
	if old.Revision != 0 && p.Revision != old.Revision {
		problem(w, 409, "This profile changed. Reload before saving.")
		return
	}
	p.Revision = old.Revision + 1
	if e := a.Save("profiles", p.ID, p); e != nil {
		problem(w, 500, "Could not save profile.")
		return
	}
	respond(w, 200, map[string]bool{"saved": true})
}
func (a *App) scannerGet(w http.ResponseWriter, r *http.Request) {
	s := Scanner{Type: "cloud", Region: "us-east-1", TLS: true}
	e := a.Get("scanner", "default", &s)
	if e != nil && e != sql.ErrNoRows {
		problem(w, 500, "Cannot decrypt scanner settings.")
		return
	}
	s.KeySaved = s.APIKey != ""
	s.APIKey = ""
	respond(w, 200, s)
}
func (a *App) scannerSave(w http.ResponseWriter, r *http.Request) {
	var s Scanner
	if !decode(w, r, &s) {
		return
	}
	var old Scanner
	if a.Get("scanner", "default", &old) == nil && s.APIKey == "" && s.Type == old.Type && ((s.Type == "cloud" && s.Region == old.Region) || (s.Type == "local" && s.Address == old.Address)) {
		s.APIKey = old.APIKey
	}
	if e := s.Validate(); e != nil {
		problem(w, 400, e.Error())
		return
	}
	if s.Type == "cloud" {
		s.TLS = true
	}
	if e := a.Save("scanner", "default", s); e != nil {
		problem(w, 500, "Could not save scanner settings.")
		return
	}
	respond(w, 200, map[string]bool{"saved": true})
}
func (a *App) scan(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ProfileID string   `json:"profileId"`
		Keys      []string `json:"keys"`
	}
	if !decode(w, r, &v) {
		return
	}
	if len(v.Keys) == 0 || len(v.Keys) > 100 {
		problem(w, 400, "Select between 1 and 100 files.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	ids := []string{}
	for _, key := range v.Keys {
		id, e := a.Enqueue(ctx, v.ProfileID, key)
		if e != nil {
			respond(w, 400, map[string]any{"error": e.Error(), "accepted": ids})
			return
		}
		ids = append(ids, id)
	}
	respond(w, 202, map[string]any{"queued": ids})
}
func (a *App) retryJob(w http.ResponseWriter, r *http.Request) {
	res, e := a.DB.Exec("UPDATE jobs SET state='QUEUED',attempts=0,error='',available_at=?,updated_at=? WHERE id=? AND state IN ('HELD','RETRY_PENDING')", time.Now().Unix(), stamp(), r.PathValue("id"))
	if e != nil {
		problem(w, 500, "Retry failed.")
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		problem(w, 409, "Only held or retrying jobs can be retried.")
		return
	}
	a.Audit("job.retry", r.PathValue("id"), "Administrator requested retry")
	respond(w, 200, map[string]bool{"queued": true})
}
func (a *App) status(w http.ResponseWriter, r *http.Request) {
	rows, e := a.DB.Query("SELECT state,count(*) FROM jobs GROUP BY state")
	if e != nil {
		problem(w, 500, "Telemetry unavailable.")
		return
	}
	states := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		rows.Scan(&s, &n)
		states[s] = n
	}
	rows.Close()
	respond(w, 200, map[string]any{"states": states, "observedAt": stamp(), "mode": "local-host", "scannerConfigured": func() bool { var s Scanner; return a.Get("scanner", "default", &s) == nil }()})
}
func (a *App) audit(w http.ResponseWriter, r *http.Request) {
	rows, e := a.DB.Query("SELECT id,at,action,object_id,detail FROM audit WHERE action!='authThrottle.saved' ORDER BY id DESC LIMIT 300")
	if e != nil {
		problem(w, 500, "Audit unavailable.")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var at, action, object, detail string
		if rows.Scan(&id, &at, &action, &object, &detail) != nil {
			continue
		}
		out = append(out, map[string]any{"id": id, "at": at, "action": action, "objectId": object, "detail": detail})
	}
	respond(w, 200, out)
}
