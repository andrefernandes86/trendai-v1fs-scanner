package localapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	if r.Method == "PUT" && r.URL.Query().Get("comp") == "lease" {
		status = 201
		h.Set("x-ms-lease-id", r.Header.Get("x-ms-proposed-lease-id"))
	} else if r.Method == "DELETE" {
		status = 202
	} else if r.Method == "PUT" && r.URL.Query().Get("comp") == "tags" {
		status = 204
	} else if r.Method == "PUT" {
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
	base := Snapshot{Source: source, Good: good, Bad: bad, Failed: testMount("failed", "scan-failed"), Scanner: Scanner{Type: "local", Address: "scanner:50051"}, Profile: Profile{ID: "policy", Name: "Policy", Revision: 1, ScanAttempts: 1, GoodPrefix: "approved", BadPrefix: "blocked"}, Key: "report.txt", ETag: `"v1"`, Size: 12}
	for _, tc := range []struct{ name, raw, state, container string }{{"clean", `{"scanId":"test","scanResult":0}`, "COMPLETED", "/clean/"}, {"malicious", `{"scanId":"test","scanResult":1}`, "QUARANTINED", "/quarantine/"}, {"unknown", `{}`, "HELD", "/scan-failed/"}} {
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
	for _, m := range []Mount{testMount("incoming", "incoming"), testMount("good", "clean"), testMount("bad", "quarantine"), testMount("alias", "incoming"), testMount("failed", "scan-failed")} {
		if e := a.Save("mounts", m.ID, m); e != nil {
			t.Fatal(e)
		}
	}
	if e := a.Save("scanner", "default", Scanner{Type: "local", Address: "scanner:50051"}); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		p := Profile{ID: fmt.Sprintf("policy%d", i), Name: "Profile", SourceMount: "incoming", GoodMount: "good", BadMount: "bad", FailedMount: "failed", GoodPrefix: fmt.Sprintf("approved/%d", i), BadPrefix: fmt.Sprintf("blocked/%d", i)}
		body, _ := json.Marshal(p)
		r := httptest.NewRequest("PUT", "http://localhost/api/profiles/"+p.ID, bytes.NewReader(body))
		r.SetPathValue("id", p.ID)
		w := httptest.NewRecorder()
		a.profileSave(w, r)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	p := Profile{ID: "unsafe", Name: "Unsafe", SourceMount: "incoming", GoodMount: "alias", BadMount: "bad", FailedMount: "failed"}
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

func TestDiagnosticsEICARAndCredentialRedaction(t *testing.T) {
	a := testApp(t)
	secret := "private-diagnostic-api-key"
	if e := a.Save("scanner", "default", Scanner{Type: "cloud", Region: "us-east-1", APIKey: secret, TLS: true}); e != nil {
		t.Fatal(e)
	}
	var path string
	a.scanFn = func(ctx context.Context, p string, s Scanner, profile Profile) ([]byte, error) {
		path = p
		if s.APIKey != secret {
			t.Fatal("stored key not used")
		}
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		if len(b) != 68 || string(b) != eicarContent {
			t.Fatal("incorrect EICAR bytes")
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" {
			t.Fatal("noncanonical EICAR hash")
		}
		if !profile.Digest {
			t.Fatal("digest disabled")
		}
		return []byte(`{"scanId":"diagnostic","scanResult":1,"apiKey":"` + secret + `","nested":{"authorization":"Bearer sensitive","echo":"` + secret + `"}}`), nil
	}
	r := httptest.NewRequest("POST", "http://localhost/api/scanner/test", strings.NewReader(`{"kind":"eicar","scanner":{"type":"cloud","region":"us-east-1","tls":true}}`))
	w := httptest.NewRecorder()
	a.scannerTest(w, r)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "Bearer sensitive") {
		t.Fatal("diagnostic leaked a credential")
	}
	var v map[string]any
	if json.Unmarshal(w.Body.Bytes(), &v) != nil || v["success"] != true {
		t.Fatal(w.Body.String())
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("diagnostic file not removed")
	}
	var n int
	a.DB.QueryRow("SELECT count(*) FROM jobs").Scan(&n)
	if n != 0 {
		t.Fatal("diagnostic added a routable job")
	}
	r = httptest.NewRequest("POST", "http://localhost/api/scanner/test", strings.NewReader(`{"kind":"eicar","scanner":{"type":"cloud","region":"us-east-1"}}`))
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("diagnostic accessible without authentication")
	}
}
func TestDiagnosticErrorsAndUnexpectedResults(t *testing.T) {
	a := testApp(t)
	for _, test := range []struct {
		name, kind, raw string
		err             error
	}{{"auth error", "key", "", fmt.Errorf("authentication rejected secret-key")}, {"EICAR unexpectedly clean", "eicar", `{"scanId":"x","scanResult":0}`, nil}, {"unknown response", "key", `{}`, nil}, {"benign key check", "key", `{"scanId":"x","scanResult":0}`, nil}} {
		t.Run(test.name, func(t *testing.T) {
			a.scanFn = func(_ context.Context, path string, _ Scanner, _ Profile) ([]byte, error) {
				b, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if test.kind == "key" && bytes.Contains(b, []byte("EICAR")) {
					t.Fatal("key test is not benign")
				}
				return []byte(test.raw), test.err
			}
			r := httptest.NewRequest("POST", "http://localhost/api/scanner/test", strings.NewReader(`{"kind":"`+test.kind+`","scanner":{"type":"cloud","region":"us-east-1","apiKey":"secret-key"}}`))
			w := httptest.NewRecorder()
			a.scannerTest(w, r)
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			if strings.Contains(w.Body.String(), "secret-key") {
				t.Fatal("error exposed API key")
			}
			var out map[string]any
			json.Unmarshal(w.Body.Bytes(), &out)
			want := test.name == "benign key check"
			if out["success"] != want {
				t.Fatal(w.Body.String())
			}
		})
	}
}

func TestDiagnosticScanSlotHonorsCancellation(t *testing.T) {
	a := testApp(t)
	a.scanMu.Lock()
	defer a.scanMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, e := a.Scan(ctx, "unused", Scanner{}, Profile{})
	if e != context.DeadlineExceeded {
		t.Fatalf("waiting scan ignored timeout: %v", e)
	}
}

type storageDiagnosticFixture struct {
	code      int
	body      string
	lastURL   string
	signature string
}

func (f *storageDiagnosticFixture) Do(r *http.Request) (*http.Response, error) {
	f.lastURL = r.URL.String()
	auth := r.Header.Get("Authorization")
	if i := strings.LastIndex(auth, ":"); i >= 0 {
		f.signature = auth[i+1:]
	}
	body := strings.ReplaceAll(f.body, "AUTH_SIGNATURE", f.signature)
	return &http.Response{StatusCode: f.code, Header: http.Header{"Content-Type": []string{"application/xml"}, "X-Ms-Request-Id": []string{"fixture-request"}, "X-Ms-Error-Code": []string{"AuthenticationFailed"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: r}, nil
}
func TestStorageDiscoveryAndDraftContainerDiagnostics(t *testing.T) {
	a := testApp(t)
	fixture := &storageDiagnosticFixture{code: 200, body: `<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://testaccount.blob.core.windows.net/"><Containers><Container><Name>incoming</Name></Container><Container><Name>clean</Name></Container><Container><Name>quarantine</Name></Container></Containers><NextMarker>next-page</NextMarker></EnumerationResults>`}
	storageTransport = fixture
	t.Cleanup(func() { storageTransport = nil })
	m := testMount("draft", "unused")
	m.Container = ""
	body, _ := json.Marshal(map[string]any{"kind": "containers", "mount": m})
	w := httptest.NewRecorder()
	a.storageTest(w, httptest.NewRequest("POST", "http://localhost/api/storage/test", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var out struct {
		Success    bool     `json:"success"`
		Containers []string `json:"containers"`
		Next       string   `json:"nextMarker"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Success || len(out.Containers) != 3 || out.Containers[0] != "incoming" || out.Next != "next-page" {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), m.Secret) || strings.Contains(w.Body.String(), fixture.signature) {
		t.Fatal("credential or request signature leaked")
	}
	var n int
	a.DB.QueryRow("SELECT count(*) FROM config WHERE kind='mounts'").Scan(&n)
	if n != 0 {
		t.Fatal("draft test persisted credentials")
	}
	// Testing a blank target must discover containers instead of rejecting the form.
	body, _ = json.Marshal(map[string]any{"kind": "container", "mount": m})
	w = httptest.NewRecorder()
	a.storageTest(w, httptest.NewRequest("POST", "http://localhost/api/storage/test", bytes.NewReader(body)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"kind":"containers"`) || !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(fixture.lastURL, "restype=container") || strings.Contains(fixture.lastURL, "/discovery") {
		t.Fatal("blank-target discovery requested a container instead of the account")
	}
	fixture.body = `<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://testaccount.blob.core.windows.net/" ContainerName="incoming"><Blobs/><NextMarker/></EnumerationResults>`
	m.Container = "incoming"
	body, _ = json.Marshal(map[string]any{"kind": "container", "mount": m})
	w = httptest.NewRecorder()
	a.storageTest(w, httptest.NewRequest("POST", "http://localhost/api/storage/test", bytes.NewReader(body)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatal(w.Body.String())
	}
	if !strings.Contains(fixture.lastURL, "/incoming?") {
		t.Fatal("container test did not target selected container")
	}
}
func TestStorageDiagnosticSASFailureRedaction(t *testing.T) {
	a := testApp(t)
	fixture := &storageDiagnosticFixture{code: 403, body: `<?xml version="1.0"?><Error><Code>AuthenticationFailed</Code><Message>Denied sig=private-signature</Message></Error>`}
	storageTransport = fixture
	t.Cleanup(func() { storageTransport = nil })
	m := Mount{ID: "draft", Name: "Draft", Account: "testaccount", Container: "incoming", AuthType: "sas", Secret: "sv=2023-11-03&sp=rl&sig=private-signature"}
	body, _ := json.Marshal(map[string]any{"kind": "container", "mount": m})
	w := httptest.NewRecorder()
	a.storageTest(w, httptest.NewRequest("POST", "http://localhost/api/storage/test", bytes.NewReader(body)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"success":false`) || !strings.Contains(w.Body.String(), `"statusCode":403`) {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private-signature") || strings.Contains(w.Body.String(), m.Secret) {
		t.Fatal("SAS exposed in diagnostic output")
	}
	if !strings.Contains(fixture.lastURL, "sig=private-signature") {
		t.Fatal("SAS was not used for actual request")
	}
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("POST", "http://localhost/api/storage/test", bytes.NewReader(body)))
	if w.Code != 401 {
		t.Fatal("storage diagnostic lacks authentication")
	}
}
