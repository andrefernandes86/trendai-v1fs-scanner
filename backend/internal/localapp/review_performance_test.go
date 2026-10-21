package localapp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReviewArchiveRetryReusesOnlyVerifiedMembers(t *testing.T) {
	a := testApp(t)
	old := extractArchiveProcess
	extractArchiveProcess = ExtractArchive
	defer func() { extractArchiveProcess = old }()
	local := filepath.Join(t.TempDir(), "bundle.zip")
	os.WriteFile(local, zipFixture(t, "leaf.txt", []byte("retry-me")), 0600)
	digest, _, _, _ := checksums(local)
	calls := 0
	failed := false
	a.scanFn = func(_ context.Context, file string, _ Scanner, _ Profile) ([]byte, error) {
		calls++
		data, _ := os.ReadFile(file)
		if string(data) == "retry-me" && !failed {
			failed = true
			return []byte(`{"scanId":"x","foundErrors":[{"description":"temporary scanner error"}]}`), nil
		}
		return []byte(`{"scanId":"x","scanResult":0}`), nil
	}
	p := Profile{ID: "archive-cache", Archive: ArchiveOptions{Enabled: true}}
	first, err := a.scanWithArchives(context.Background(), local, "bundle.zip", Scanner{}, p, digest)
	if err != nil {
		t.Fatal(err)
	}
	var prior struct {
		Evidence ArchiveEvidence `json:"archiveInspection"`
	}
	json.Unmarshal(first, &prior)
	if calls != 2 || prior.Evidence.Complete {
		t.Fatal(calls)
	}
	second, err := a.scanWithArchives(context.Background(), local, "bundle.zip", Scanner{}, p, digest, &prior.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Evidence ArchiveEvidence `json:"archiveInspection"`
		Calls    int             `json:"scannerCalls"`
	}
	json.Unmarshal(second, &result)
	if calls != 3 || !result.Evidence.Complete || result.Calls != 1 || !result.Evidence.Members[0].Reused {
		t.Fatal(calls, result.Calls)
	}
	os.WriteFile(local, zipFixture(t, "leaf.txt", []byte("different")), 0600)
	digest, _, _, _ = checksums(local)
	if _, err = a.scanWithArchives(context.Background(), local, "bundle.zip", Scanner{}, p, digest, &prior.Evidence); err != nil || calls != 5 {
		t.Fatal(calls, err)
	}
}

func TestReviewArchiveCapacityDoesNotBlockWorker(t *testing.T) {
	release, err := archivePermit(context.Background(), "capacity-test", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	start := time.Now()
	if _, err = archivePermit(context.Background(), "capacity-test", 1); err != errArchiveCapacity {
		t.Fatal(err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("archive wait occupied scan worker")
	}
}

func TestReviewRetryDoesNotJumpOlderReadyWork(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	first, _ := a.insertJob(s)
	s.ETag = "new-upload"
	next, _ := a.insertJob(s)
	a.DB.Exec("UPDATE jobs SET state='RETRY_PENDING',available_at=? WHERE id=?", time.Now().Unix()-1, first)
	a.DB.Exec("UPDATE jobs SET available_at=? WHERE id=?", time.Now().Unix()-30, next)
	id, _, _, err := a.claim()
	if err != nil || id != next {
		t.Fatal(id, err)
	}
}
