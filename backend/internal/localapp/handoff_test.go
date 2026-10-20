package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestShareClaimPreservesConcurrentReplacement(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	id, _ := a.insertJob(s)
	if e := a.handoffSource(context.Background(), id, &s); e != nil {
		t.Fatal(e)
	}
	if s.ClaimedKey == "" {
		t.Fatal("no private claim")
	}
	if _, e := stores["source"].Stat(s.Key); !os.IsNotExist(e) {
		t.Fatal("source not handed off")
	}
	// A producer creates the next version under the original name while this job owns the claimed bytes.
	if e := os.WriteFile(stores["source"].p(s.Key), []byte("next upload"), 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte("123456789"))
	if e := a.removeVerifiedSource(context.Background(), s, hex.EncodeToString(sum[:])); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(stores["source"].p(s.Key))
	if e != nil || string(got) != "next upload" {
		t.Fatal("new producer upload was deleted")
	}
}
func TestClaimResumesRenameBeforeDatabaseCommit(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	id, _ := a.insertJob(s)
	if e := a.handoffSource(context.Background(), id, &s); e != nil {
		t.Fatal(e)
	}
	claim, _ := a.loadClaim(id)
	claim.Phase = "CLAIMING"
	claim.ETag = ""
	if e := a.saveClaim(id, claim); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(stores["source"].p(s.Key), []byte("next version"), 0600)
	original := s
	s.ClaimedKey = ""
	s.ClaimedETag = ""
	if e := a.handoffSource(context.Background(), id, &s); e != nil {
		t.Fatal(e)
	}
	if s.ClaimedKey != original.ClaimedKey {
		t.Fatal("claim path changed on recovery")
	}
	files, _, e := ListBlobs(context.Background(), s.Source, "", "")
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range files {
		if reservedSharePath(f.Key) {
			t.Fatal("private claims rediscovered")
		}
	}
}
func TestClaimRejectsChangedOrCollidingSource(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	id, _ := a.insertJob(s)
	os.WriteFile(stores["source"].p(s.Key), []byte("changed source"), 0600)
	if e := a.handoffSource(context.Background(), id, &s); e == nil {
		t.Fatal("changed source claimed")
	}
	if _, e := stores["source"].Stat(s.Key); e != nil {
		t.Fatal("changed source lost")
	}
}
func TestRuntimeLivenessDetectsStalledComponents(t *testing.T) {
	a := testApp(t)
	a.healthMu.Lock()
	a.started = time.Now()
	a.heartbeats = map[string]time.Time{"monitor": time.Now(), "worker-0": time.Now(), "worker-1": time.Now()}
	a.healthMu.Unlock()
	if _, ok := a.liveStatus(context.Background()); !ok {
		t.Fatal("healthy runtime not live")
	}
	a.healthMu.Lock()
	a.heartbeats["worker-1"] = time.Now().Add(-13 * time.Minute)
	a.healthMu.Unlock()
	if _, ok := a.liveStatus(context.Background()); ok {
		t.Fatal("stalled worker not detected")
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/livez", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	a.beat("worker-1")
	a.healthMu.Lock()
	a.heartbeats["monitor"] = time.Now().Add(-time.Minute)
	a.healthMu.Unlock()
	if _, ok := a.liveStatus(context.Background()); ok {
		t.Fatal("stalled monitor not detected")
	}
}
