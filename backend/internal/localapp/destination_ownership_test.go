package localapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDestinationRecoveryEndpointNeverAccessesStorage(t *testing.T) {
	a := testApp(t)
	storageTransport = tagsTransport(func(*http.Request) (*http.Response, error) { t.Fatal("delivered storage accessed"); return nil, nil })
	defer func() { storageTransport = nil }()
	for _, suffix := range []string{"", "?enrich=true"} {
		r := httptest.NewRequest("POST", "/api/jobs/delivered/recover"+suffix, nil)
		r.SetPathValue("id", "delivered")
		w := httptest.NewRecorder()
		a.recoverHTTP(w, r)
		if w.Code != 409 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestLegacyQueuedRecoveryDoesNotTouchDeliveredFile(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	parent, _ := a.insertJob(s)
	_ = a.transition(parent, "HELD", "UNKNOWN", "digest", "external/delivered", "", 0)
	s.ETag = "legacy-child"
	child, err := a.insertJob(s, parent)
	if err != nil {
		t.Fatal(err)
	}
	_, snap, n, err := a.claim()
	if err != nil {
		t.Fatal(err)
	}
	original := remoteOpen
	remoteOpen = func(context.Context, Mount) (remoteFS, error) {
		t.Fatal("legacy recovery accessed destination")
		return nil, nil
	}
	defer func() { remoteOpen = original }()
	a.process(context.Background(), child, snap, n)
	var state string
	a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", child).Scan(&state)
	if state != "ACKNOWLEDGED" {
		t.Fatal(state)
	}
}

func TestCompletedMoveReconcilesWithoutStorageAccess(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	id, _ := a.insertJob(s)
	if err := a.saveMove(id, MoveRecord{Phase: "COMPLETED", FinalState: "COMPLETED", Verdict: "CLEAN", Destination: "external/result", Digest: "digest"}); err != nil {
		t.Fatal(err)
	}
	original := remoteOpen
	remoteOpen = func(context.Context, Mount) (remoteFS, error) {
		t.Fatal("completed move accessed storage")
		return nil, nil
	}
	defer func() { remoteOpen = original }()
	a.process(context.Background(), id, s, 1)
	var state string
	a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state)
	if state != "COMPLETED" {
		t.Fatal(state)
	}
}

func TestDeliveredHeldRecordCannotRestartThroughRetry(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	id, _ := a.insertJob(s)
	_ = a.transition(id, "HELD", "UNKNOWN", "digest", "external/result", "scan failed", 0)
	_ = a.saveMove(id, MoveRecord{Phase: "COMPLETED", FinalState: "HELD", Verdict: "UNKNOWN", Destination: "external/result"})
	r := httptest.NewRequest("POST", "/", nil)
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	a.retryJob(w, r)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	var state string
	a.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state)
	if state != "HELD" {
		t.Fatal(state)
	}
}
