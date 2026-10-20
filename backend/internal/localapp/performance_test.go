package localapp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBlobFinalizationOneLeasedReadAndCorruptionRetry(t *testing.T) {
	for _, corruptFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "single-pass", true: "corruption-retry"}[corruptFirst], func(t *testing.T) {
			a := testApp(t)
			fake := &fakeAzure{objects: map[string][]byte{"/incoming/file.txt": []byte("123456789")}, writes: map[string]int{}, etag: `"v1"`}
			reads, deletes, tags := 0, 0, 0
			corrupt := corruptFirst
			leased := false
			storageTransport = tagsTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Query().Get("comp") == "lease" {
					switch testHeader(r, "x-ms-lease-action") {
					case "acquire", "renew":
						leased = true
					case "release":
						leased = false
					}
				}
				if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/clean/") {
					reads++
					if !leased {
						t.Error("readback without lease")
					}
				}
				if r.URL.Query().Get("comp") == "tags" {
					tags++
					if !leased || testHeader(r, "x-ms-lease-id") == "" {
						t.Error("tags not lease protected")
					}
				}
				if r.Method == "DELETE" {
					deletes++
					if !leased || tags == 0 || testHeader(r, "If-Match") == "" {
						t.Error("unsafe source deletion")
					}
				}
				response, err := fake.Do(r)
				if corrupt && r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/clean/") {
					response.Body = io.NopCloser(bytes.NewReader([]byte("987654321")))
				}
				return response, err
			})
			t.Cleanup(func() { storageTransport = nil })
			s := Snapshot{Source: testMount("s", "incoming"), Good: testMount("g", "clean"), Bad: testMount("b", "bad"), Failed: testMount("f", "failed"), Profile: Profile{ID: "p", TransferAttempts: 3}, Key: "file.txt", ETag: `"v1"`, Size: 9}
			a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
				return []byte(`{"scanId":"test","scanResult":0}`), nil
			}
			id, err := a.insertJob(s)
			if err != nil {
				t.Fatal(err)
			}
			_, snap, attempt, err := a.claim()
			if err != nil {
				t.Fatal(err)
			}
			a.process(context.Background(), id, snap, attempt)
			if corruptFirst {
				if deletes != 0 || tags != 0 {
					t.Fatal("corrupt destination published or source removed")
				}
				m, e := a.loadMove(id)
				if e != nil || m.Phase != "DESTINATION_UPLOADED" {
					t.Fatal(m, e)
				}
				corrupt = false
				a.process(context.Background(), id, snap, attempt+1)
			}
			want := 1
			if corruptFirst {
				want = 2
			}
			if reads != want || deletes != 1 || tags != 1 {
				t.Fatalf("reads=%d deletes=%d tags=%d", reads, deletes, tags)
			}
			var state string
			a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state)
			if state != "COMPLETED" {
				t.Fatal(state)
			}
		})
	}
}
func TestIndependentTransferQueueAndLimits(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	s.Profile.SimultaneousScans = 1
	s.Profile.SimultaneousTransfers = 2
	s.Profile.LargeFileTransfers = 1
	if err := a.Save("profiles", s.Profile.ID, s.Profile); err != nil {
		t.Fatal(err)
	}
	id, err := a.insertJob(s)
	if err != nil {
		t.Fatal(err)
	}
	a.transferEnabled = true
	if err = a.enqueueTransfer(id, s, "/private/capture", "sha", "CLEAN", "", ""); err != nil {
		t.Fatal(err)
	}
	s.Key = "second.txt"
	s.Size = 2e9
	id2, _ := a.insertJob(s)
	claimed, _, _, err := a.claim()
	if err != nil || claimed != id2 {
		t.Fatal("transfer occupied scan capacity", claimed, err)
	}
	if err = a.enqueueTransfer(id2, s, "/private/capture2", "sha", "CLEAN", "", ""); err != nil {
		t.Fatal(err)
	}
	if got, _, e := a.claimTransfer(); e != nil || got != id {
		t.Fatal(got, e)
	}
	if got, _, e := a.claimTransfer(); e != nil || got != id2 {
		t.Fatal(got, e)
	}
	s.Key = "third.txt"
	id3, _ := a.insertJob(s)
	a.enqueueTransfer(id3, s, "/private/capture3", "sha", "CLEAN", "", "")
	if _, _, e := a.claimTransfer(); e == nil {
		t.Fatal("transfer limit exceeded")
	}
	a.DB.Exec("DELETE FROM transfer_queue WHERE job_id=?", id)
	if _, _, e := a.claimTransfer(); e == nil {
		t.Fatal("large transfer limit exceeded")
	}
	a.DB.Exec("DELETE FROM transfer_queue WHERE job_id=?", id2)
	if got, _, e := a.claimTransfer(); e != nil || got != id3 {
		t.Fatal("capacity not released", got, e)
	}
}
func TestHiddenHistoryPreservesAccounting(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	id, _ := a.insertJob(s)
	a.transition(id, "HELD", "UNKNOWN", "", "", "review", 0)
	req := httptest.NewRequest("POST", "http://localhost/api/jobs/"+id+"/visibility", strings.NewReader(`{"hidden":true}`))
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	a.jobVisibility(w, req)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	where, args, limit, offset := jobQuery(httptest.NewRequest("GET", "http://localhost/api/jobs/page?visibility=visible", nil), 1000)
	jobs, e := a.jobsPage(where, args, limit, offset)
	if e != nil || len(jobs) != 0 {
		t.Fatal(jobs, e)
	}
	jobs, e = a.Jobs()
	if e != nil || len(jobs) != 1 || !jobs[0].Hidden || jobs[0].State != "HELD" {
		t.Fatal(jobs, e)
	}
	req = httptest.NewRequest("POST", "http://localhost/", strings.NewReader(`{"hidden":false}`))
	req.SetPathValue("id", id)
	a.jobVisibility(httptest.NewRecorder(), req)
	jobs, _ = a.Jobs()
	if jobs[0].Hidden {
		t.Fatal("restore failed")
	}
}

func TestTransferRestartRecapturesWithoutRescanning(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	a.transferEnabled = true
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		return []byte(`{"scanId":"test","scanResult":0}`), nil
	}
	id, _ := a.insertJob(s)
	_, snap, n, e := a.claim()
	if e != nil {
		t.Fatal(e)
	}
	a.process(context.Background(), id, snap, n)
	var pending int
	a.DB.QueryRow("SELECT count(*) FROM transfer_queue").Scan(&pending)
	if pending != 1 {
		t.Fatal("handoff not durable")
	}
	data, web := a.DataDir, a.WebDir
	a.Close()
	b, e := Open(data, web)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	b.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		t.Fatal("restart repeated completed scan")
		return nil, nil
	}
	claimed, snap, n, e := b.claim()
	if e != nil || claimed != id {
		t.Fatal(claimed, e)
	}
	b.process(context.Background(), id, snap, n)
	var state string
	b.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state)
	if state != "COMPLETED" {
		t.Fatal(state)
	}
	if _, e = stores["source"].Stat(s.Key); e == nil {
		t.Fatal("source retained after verified transfer")
	}
}

func testHeader(r *http.Request, name string) string {
	for key, values := range r.Header {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func TestRecursiveShareDiscoveryIncludesDeepSourceAndOmitsLinks(t *testing.T) {
	_, s, stores := reliabilityFixture(t)
	root := stores["source"].root
	for _, key := range []string{"team/a/report.txt", "team/a/b/deeper.txt", "other/outside.txt"} {
		if e := os.MkdirAll(filepath.Dir(filepath.Join(root, key)), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(root, key), []byte("safe"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Symlink(filepath.Join(root, "other"), filepath.Join(root, "team", "link")); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"azureFiles", "smb", "nfs"} {
		s.Source.Kind = kind
		files, _, e := ListBlobs(context.Background(), s.Source, "team/", "")
		if e != nil || len(files) != 2 {
			t.Fatal(kind, files, e)
		}
	}
}

func TestTransferPoolRoutesCapturedBytesAndCleansHandoff(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	a.transferEnabled = true
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		return []byte(`{"scanId":"test","scanResult":0}`), nil
	}
	id, _ := a.insertJob(s)
	_, snap, n, e := a.claim()
	if e != nil {
		t.Fatal(e)
	}
	a.process(context.Background(), id, snap, n)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.transferWorker(ctx, 0) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var state string
		var queued int
		a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state)
		a.DB.QueryRow("SELECT count(*) FROM transfer_queue").Scan(&queued)
		if state == "COMPLETED" && queued == 0 {
			if _, e = stores["source"].Stat(s.Key); e == nil {
				t.Fatal("source remains")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("transfer pool did not drain")
}

func TestPersistedMoveRetryUsesTransferPool(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	s.Profile.ControlledWriter = false
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		return []byte(`{"scanId":"test","scanResult":0}`), nil
	}
	id, _ := a.insertJob(s)
	_, snap, n, e := a.claim()
	if e != nil {
		t.Fatal(e)
	}
	a.process(context.Background(), id, snap, n)
	if _, e = a.loadMove(id); e != nil {
		t.Fatal(e)
	}
	a.transferEnabled = true
	a.process(context.Background(), id, snap, n+1)
	queued, task, e := a.claimTransfer()
	if e != nil || queued != id || task.Local != "" || task.Verdict != "CLEAN" {
		t.Fatal("move retry did not hand off without recapture", queued, task.Local, e)
	}
}
