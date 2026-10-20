package localapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testApp(t *testing.T) *App {
	t.Helper()
	a, e := Open(t.TempDir(), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Close() })
	return a
}
func TestSecretsEncryptedAndRedacted(t *testing.T) {
	a := testApp(t)
	m := testMount("source", "incoming")
	if e := a.Save("mounts", m.ID, m); e != nil {
		t.Fatal(e)
	}
	var raw []byte
	if e := a.DB.QueryRow("SELECT value FROM config WHERE kind='mounts'").Scan(&raw); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte(m.Secret)) {
		t.Fatal("credential stored in plaintext")
	}
	var restored Mount
	if e := a.Get("mounts", m.ID, &restored); e != nil || restored.Secret != m.Secret {
		t.Fatal("credential did not round-trip")
	}
	w := httptest.NewRecorder()
	a.mountList(w, httptest.NewRequest("GET", "http://localhost/api/mounts", nil))
	if strings.Contains(w.Body.String(), m.Secret) || strings.Contains(w.Body.String(), `"secret"`) {
		t.Fatal("credential exposed by API")
	}
	if !strings.Contains(w.Body.String(), `"credentialSaved":true`) {
		t.Fatal("missing saved credential indicator")
	}
	tamper := append([]byte{}, raw...)
	tamper[len(tamper)-1] ^= 1
	if a.Unseal(tamper, &restored) == nil {
		t.Fatal("ciphertext tampering accepted")
	}
}
func testMount(id, container string) Mount {
	return Mount{ID: id, Name: id, Account: "testaccount", Container: container, AuthType: "accountKey", Secret: base64.StdEncoding.EncodeToString([]byte("integration-test-secret-key-00000"))}
}
func TestAuthenticationAndOriginProtection(t *testing.T) {
	a := testApp(t)
	h := a.Handler()
	request := func(method, path, body string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost:8095"+path, strings.NewReader(body))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/mounts", "", nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/setup", `{"password":"long-test-password"}`, nil, "http://evil.test"); w.Code != 403 {
		t.Fatal("CSRF setup accepted")
	}
	w := request("POST", "/api/setup", `{"password":"long-test-password"}`, nil, "http://localhost:8095")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	if w = request("GET", "/api/mounts", "", cookies[0], ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w = request("POST", "/api/setup", `{"password":"other-password-123"}`, nil, ""); w.Code != 409 {
		t.Fatal("admin overwritten")
	}
	w = request("POST", "/api/logout", `{}`, cookies[0], "http://localhost:8095")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w = request("GET", "/api/mounts", "", cookies[0], ""); w.Code != 401 {
		t.Fatal("session survived logout")
	}
}
func TestMountAndScannerValidation(t *testing.T) {
	m := testMount("source", "incoming")
	m.ResourceID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/blobaccount/blobServices/default/containers/uploads"
	if e := m.Validate(); e != nil || m.Account != "blobaccount" || m.Container != "uploads" {
		t.Fatal(e)
	}
	for _, address := range []string{"http://scanner:50051", "scanner", "scanner:50051/path", ""} {
		if (Scanner{Type: "local", Address: address}).Validate() == nil {
			t.Fatal(address)
		}
	}
	if e := (Scanner{Type: "local", Address: "192.168.1.10:50051", TLS: true}).Validate(); e != nil {
		t.Fatal(e)
	}
	if (Scanner{Type: "cloud", Region: "us-east-1"}).Validate() == nil {
		t.Fatal("cloud key missing accepted")
	}
	if (Scanner{Type: "cloud", Region: "invalid", APIKey: "secret"}).Validate() == nil {
		t.Fatal("invalid region accepted")
	}
}
func TestPersistenceAndExclusiveInstance(t *testing.T) {
	dir := t.TempDir()
	a, e := Open(dir, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Open(dir, t.TempDir()); e == nil {
		t.Fatal("two hosts opened same database")
	}
	if e = a.Save("scanner", "default", Scanner{Type: "local", Address: "scanner:50051", APIKey: "private-key"}); e != nil {
		t.Fatal(e)
	}
	a.Close()
	b, e := Open(dir, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	var s Scanner
	if e = b.Get("scanner", "default", &s); e != nil || s.APIKey != "private-key" {
		t.Fatal("lost settings")
	}
	b.Close()
	os.Remove(filepath.Join(dir, "master.key"))
	if _, e = Open(dir, t.TempDir()); e == nil {
		t.Fatal("silently replaced missing key")
	}
}

type fakeAzure struct {
	mu      sync.Mutex
	objects map[string][]byte
	writes  map[string]int
	etag    string
}

func (f *fakeAzure) Do(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := make(http.Header)
	h.Set("ETag", f.etag)
	h.Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	h.Set("x-ms-version", "2023-11-03")
	h.Set("x-ms-meta-v1fs-complete", "true")
	key := r.URL.Path
	status := 200
	var b []byte
	if r.Method == "PUT" {
		if _, ok := f.objects[key]; ok && r.Header.Get("If-None-Match") == "*" {
			status = 412
		} else {
			b, _ = io.ReadAll(r.Body)
			f.objects[key] = b
			f.writes[key]++
			status = 201
		}
	} else if data, ok := f.objects[key]; ok {
		b = data
		if match := r.Header.Get("If-Match"); match != "" && match != f.etag {
			status = 412
			b = nil
		}
	} else {
		status = 404
	}
	h.Set("Content-Length", fmt.Sprint(len(b)))
	body := b
	if r.Method == "HEAD" {
		body = nil
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(b)), Request: r}, nil
}
func TestRealStorageAdapterRoutingAndRecovery(t *testing.T) {
	a := testApp(t)
	fake := &fakeAzure{objects: map[string][]byte{"/incoming/report.txt": []byte("file content")}, writes: map[string]int{}, etag: `"v1"`}
	storageTransport = fake
	t.Cleanup(func() { storageTransport = nil })
	source, good, bad := testMount("source", "incoming"), testMount("good", "clean"), testMount("bad", "quarantine")
	base := Snapshot{Source: source, Good: good, Bad: bad, Scanner: Scanner{Type: "local", Address: "scanner:50051"}, Profile: Profile{ID: "policy", Name: "Policy", Revision: 1, GoodPrefix: "approved", BadPrefix: "blocked"}, Key: "report.txt", ETag: `"v1"`, Size: 12}
	for _, tc := range []struct{ name, raw, state, container string }{{"clean", `{"scanId":"test","scanResult":0}`, "COMPLETED", "/clean/"}, {"malicious", `{"scanId":"test","scanResult":1}`, "QUARANTINED", "/quarantine/"}, {"unknown", `{}`, "HELD", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.Profile.ID = tc.name
			a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) { return []byte(tc.raw), nil }
			id, e := a.insertJob(s)
			if e != nil {
				t.Fatal(e)
			}
			id2, e := a.insertJob(s)
			if e != nil || id2 != id {
				t.Fatal("duplicate job identity changed")
			}
			claimed, snap, attempt, e := a.claim()
			if e != nil || claimed != id {
				t.Fatal(e)
			}
			a.process(context.Background(), id, snap, attempt)
			var state, dest string
			if e = a.DB.QueryRow("SELECT state,destination FROM jobs WHERE id=?", id).Scan(&state, &dest); e != nil || state != tc.state {
				var msg string
				a.DB.QueryRow("SELECT error FROM jobs WHERE id=?", id).Scan(&msg)
				t.Fatalf("state=%s error=%s query=%v", state, msg, e)
			}
			if tc.container != "" && !strings.Contains(dest, tc.container) {
				t.Fatal("wrong destination")
			}
			if tc.name == "malicious" {
				for key := range fake.writes {
					if strings.HasPrefix(key, "/clean/") && strings.Contains(key, id) {
						t.Fatal("malware in clean storage")
					}
				}
			}
			if state == "COMPLETED" {
				_, e = a.DB.Exec("UPDATE jobs SET state='QUEUED' WHERE id=?", id)
				if e != nil {
					t.Fatal(e)
				}
				a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
					t.Fatal("verified routing retry rescanned file")
					return nil, nil
				}
				_, snap, attempt, e = a.claim()
				if e != nil {
					t.Fatal(e)
				}
				a.process(context.Background(), id, snap, attempt)
				for key, n := range fake.writes {
					if strings.Contains(key, id) && n != 1 {
						t.Fatal("duplicate destination write")
					}
				}
			}
		})
	}
	before := len(fake.writes)
	s := base
	s.Profile.ID = "changed"
	s.ETag = `"old"`
	id, _ := a.insertJob(s)
	_, snap, attempt, e := a.claim()
	if e != nil {
		t.Fatal(e)
	}
	a.process(context.Background(), id, snap, attempt)
	if len(fake.writes) != before {
		t.Fatal("source replacement routed content")
	}
}
func TestConcurrentDiscoveryDeduplicates(t *testing.T) {
	a := testApp(t)
	s := Snapshot{Source: testMount("source", "incoming"), Profile: Profile{ID: "policy", Revision: 1}, Key: "report", ETag: "etag"}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := a.insertJob(s); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	var count int
	a.DB.QueryRow("SELECT count(*) FROM jobs").Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
	var b []byte
	a.DB.QueryRow("SELECT snapshot FROM jobs").Scan(&b)
	if bytes.Contains(b, []byte(s.Source.Secret)) {
		t.Fatal("snapshot credentials unencrypted")
	}
}
func TestScannerEndpointChangeDoesNotReuseKey(t *testing.T) {
	a := testApp(t)
	if e := a.Save("scanner", "default", Scanner{Type: "cloud", Region: "us-east-1", APIKey: "private-cloud-key", TLS: true}); e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("PUT", "http://localhost/api/scanner", strings.NewReader(`{"type":"local","address":"localhost:50051","tls":false}`))
	w := httptest.NewRecorder()
	a.scannerSave(w, r)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var s Scanner
	a.Get("scanner", "default", &s)
	if s.APIKey != "" {
		t.Fatal("cloud credential sent to new local endpoint")
	}
	w = httptest.NewRecorder()
	a.scannerGet(w, httptest.NewRequest("GET", "http://localhost/api/scanner", nil))
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["apiKey"] != nil {
		t.Fatal("API key leaked")
	}
}

func TestMultipleProfileDestinationsAndContainerIsolation(t *testing.T) {
	a := testApp(t)
	for _, m := range []Mount{testMount("incoming", "incoming"), testMount("good", "clean"), testMount("bad", "quarantine"), testMount("alias", "incoming")} {
		if e := a.Save("mounts", m.ID, m); e != nil {
			t.Fatal(e)
		}
	}
	if e := a.Save("scanner", "default", Scanner{Type: "local", Address: "scanner:50051"}); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		p := Profile{ID: fmt.Sprintf("policy%d", i), Name: "Profile", SourceMount: "incoming", GoodMount: "good", BadMount: "bad", GoodPrefix: fmt.Sprintf("approved/%d", i), BadPrefix: fmt.Sprintf("blocked/%d", i)}
		body, _ := json.Marshal(p)
		r := httptest.NewRequest("PUT", "http://localhost/api/profiles/"+p.ID, bytes.NewReader(body))
		r.SetPathValue("id", p.ID)
		w := httptest.NewRecorder()
		a.profileSave(w, r)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	p := Profile{ID: "unsafe", Name: "Unsafe", SourceMount: "incoming", GoodMount: "alias", BadMount: "bad"}
	body, _ := json.Marshal(p)
	r := httptest.NewRequest("PUT", "http://localhost/api/profiles/unsafe", bytes.NewReader(body))
	r.SetPathValue("id", "unsafe")
	w := httptest.NewRecorder()
	a.profileSave(w, r)
	if w.Code != 400 {
		t.Fatal("same source/destination container accepted through alias")
	}
	list, e := a.List("profiles")
	if e != nil || len(list) != 2 {
		t.Fatal("multiple profiles did not persist")
	}
	var saved Profile
	if e = a.Get("profiles", "policy1", &saved); e != nil || saved.GoodPrefix != "approved/1" || saved.BadPrefix != "blocked/1" {
		t.Fatal("profile destinations lost")
	}
}
