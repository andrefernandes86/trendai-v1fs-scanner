package localapp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func resolveRequest(t *testing.T, a *App, id, action string) (int, map[string]string) {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/jobs/"+id+"/resolve", strings.NewReader(`{"action":"`+action+`","confirm":true}`))
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	a.resolveScanError(w, r)
	var result map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	return w.Code, result
}
func TestManualResolutionPreservesUnknownAndMovesOnExplicitRequest(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	id, _ := a.insertJob(s)
	_ = a.transition(id, "HELD", "UNKNOWN", "", "", "failed scan", 0)
	code, result := resolveRequest(t, a, id, "clean")
	if code != 200 {
		t.Fatal(code, result)
	}
	if code, _ = resolveRequest(t, a, id, "clean"); code != 409 {
		t.Fatal("duplicate resolution accepted", code)
	}
	child, snap, n, err := a.claim()
	if err != nil || child != result["jobId"] {
		t.Fatal(child, err)
	}
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		t.Fatal("manual move invoked scanner")
		return nil, nil
	}
	a.process(context.Background(), child, snap, n)
	m, err := a.loadMove(child)
	if err != nil || m.Phase != "COMPLETED" || m.Target.ID != "good" || m.Verdict != "UNKNOWN" || m.FinalState != "ACKNOWLEDGED" {
		t.Fatal(m, err)
	}
	var verdict string
	a.DB.QueryRow("SELECT verdict FROM jobs WHERE id=?", id).Scan(&verdict)
	if verdict != "UNKNOWN" {
		t.Fatal(verdict)
	}
}
func TestScanRetryDelayIsExactlyOneMinute(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	s.Profile.ScanAttempts = 4
	id, _ := a.insertJob(s)
	for attempt := 1; attempt <= 3; attempt++ {
		before := time.Now().Unix()
		a.retryStage(id, "scan", s.Profile, "UNKNOWN", "", "", "scan failed")
		var at int64
		var state string
		a.DB.QueryRow("SELECT available_at,state FROM jobs WHERE id=?", id).Scan(&at, &state)
		if state != "RETRY_PENDING" || at < before+60 || at > time.Now().Unix()+60 {
			t.Fatal(at, state)
		}
	}
}
func TestResubmitDeliveredFailedFileUsesRecordedIdentity(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	id, _ := a.insertJob(s)
	_ = a.transition(id, "HELD", "UNKNOWN", "digest", "failed/file", "failed", 0)
	_ = a.saveMove(id, MoveRecord{Phase: "COMPLETED", Target: s.Failed, Key: "failed.csv", DestinationETag: "exact-etag", Digest: "digest", Size: 9, Verdict: "UNKNOWN"})
	code, result := resolveRequest(t, a, id, "rescan")
	if code != 200 {
		t.Fatal(code, result)
	}
	_, child, _, err := a.claim()
	if err != nil || child.Source.ID != s.Failed.ID || child.ETag != "exact-etag" || child.ExpectedDigest != "digest" || child.Profile.ScanAttempts != 4 {
		t.Fatal(child, err)
	}
}

func TestPermanentUnknownGetsThreeRetriesBeforeFailedDelivery(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	s.Profile.ScanAttempts = 4
	calls := 0
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		calls++
		return []byte(`{"scanResult":-1,"foundErrors":[{"description":"password protected archive"}]}`), nil
	}
	id, _ := a.insertJob(s)
	for i := 1; i <= 4; i++ {
		a.process(context.Background(), id, s, i)
		var state string
		a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state)
		if i < 4 && state != "RETRY_PENDING" {
			t.Fatal(i, state)
		}
		if i < 4 {
			if _, err := a.loadMove(id); err == nil {
				t.Fatal("delivered before three retries")
			}
		}
	}
	m, err := a.loadMove(id)
	if err != nil || calls != 4 || m.Target.ID != "failed" || m.Phase != "COMPLETED" {
		t.Fatal(calls, m, err)
	}
}

func TestResubmitUsesClaimedShareLocation(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	s.Profile.ScanAttempts = 4
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		return []byte(`{"scanResult":-1}`), nil
	}
	parent, _ := a.insertJob(s)
	a.process(context.Background(), parent, s, 1)
	claim, err := a.loadClaim(parent)
	if err != nil {
		t.Fatal(err)
	}
	code, result := resolveRequest(t, a, parent, "rescan")
	if code != 200 {
		t.Fatal(code, result)
	}
	id, snap, n, err := a.claim()
	if err != nil || snap.Key != s.Key || snap.ExpectedDigest != claim.Digest {
		t.Fatal(snap.Key, err)
	}
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		return []byte(`{"scanId":"new-scan","scanResult":0}`), nil
	}
	a.process(context.Background(), id, snap, n)
	m, err := a.loadMove(id)
	if err != nil || m.Phase != "COMPLETED" || m.Verdict != "CLEAN" {
		var state, message string
		a.DB.QueryRow("SELECT state,error FROM jobs WHERE id=?", id).Scan(&state, &message)
		t.Fatal(m, err, state, message)
	}
}
