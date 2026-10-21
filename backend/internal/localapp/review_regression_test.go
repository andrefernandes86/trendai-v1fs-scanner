package localapp

import (
	"context"
	"os"
	"strings"
	"testing"
)

func isolatedRecoveryFixture(t *testing.T) (*App, Snapshot, map[string]*diskShare, string) {
	a, s, stores := reliabilityFixture(t)
	s.Profile.RecoveryAttempts = 3
	s.Profile.SourceMount, s.Profile.GoodMount, s.Profile.BadMount, s.Profile.FailedMount = s.Source.ID, s.Good.ID, s.Bad.ID, s.Failed.ID
	for _, m := range []Mount{s.Source, s.Good, s.Bad, s.Failed} {
		if err := a.Save("mounts", m.ID, m); err != nil {
			t.Fatal(err)
		}
	}
	a.Save("profiles", s.Profile.ID, s.Profile)
	a.Save("scanner", "default", Scanner{Type: "local", Address: "scanner:50051"})
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		return []byte(`{"scanId":"x","foundErrors":[{"description":"unsupported format"}]}`), nil
	}
	parent, err := a.insertJob(s)
	if err != nil {
		t.Fatal(err)
	}
	_, snap, n, err := a.claim()
	if err != nil {
		t.Fatal(err)
	}
	a.process(context.Background(), parent, snap, n)
	return a, s, stores, parent
}

func TestReviewRecoveryCannotBypassSizePolicy(t *testing.T) {
	a, s, _, parent := isolatedRecoveryFixture(t)
	s.Profile.MaxScanBytes = 1
	s.Profile.OversizeAction = "clean"
	s.Profile.GoodPrefix = "changed"
	s.Profile.GoodMount = "changed"
	a.Save("profiles", s.Profile.ID, s.Profile)
	child, err := a.recoverJob(context.Background(), parent, false)
	if err != nil {
		t.Fatal(err)
	}
	id, snap, n, err := a.claim()
	if err != nil || id != child {
		t.Fatal(id, err)
	}
	if snap.ExpectedDigest == "" || snap.Profile.OversizeAction != "hold" || snap.Profile.GoodPrefix != "" || snap.Profile.GoodMount != s.Good.ID {
		t.Fatal("unsafe recovery snapshot")
	}
	a.process(context.Background(), id, snap, n)
	var state, verdict string
	a.DB.QueryRow("SELECT state,verdict FROM jobs WHERE id=?", child).Scan(&state, &verdict)
	if state != "HELD" || verdict != "NOT_SCANNED" {
		t.Fatal(state, verdict)
	}
}

func TestReviewRecoveryRejectsChangedBytes(t *testing.T) {
	a, _, stores, parent := isolatedRecoveryFixture(t)
	move, err := a.loadMove(parent)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(stores["failed"].p(move.Key), []byte("different"), 0600)
	calls := 0
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		calls++
		return []byte(`{"scanId":"x","scanResult":0}`), nil
	}
	child, err := a.recoverJob(context.Background(), parent, false)
	if err != nil {
		t.Fatal(err)
	}
	id, snap, n, err := a.claim()
	if err != nil || id != child {
		t.Fatal(id, err)
	}
	a.process(context.Background(), id, snap, n)
	var state, message string
	a.DB.QueryRow("SELECT state,error FROM jobs WHERE id=?", child).Scan(&state, &message)
	if state != "HELD" || calls != 0 || !strings.Contains(message, "differs") {
		t.Fatal(state, calls, message)
	}
}

func TestReviewRepeatedShareRecoveryTracksMovedSource(t *testing.T) {
	a, _, _, parent := isolatedRecoveryFixture(t)
	first, err := a.recoverJob(context.Background(), parent, false)
	if err != nil {
		t.Fatal(err)
	}
	id, snap, n, err := a.claim()
	if err != nil || id != first {
		t.Fatal(id, err)
	}
	a.process(context.Background(), id, snap, n)
	second, err := a.recoverJob(context.Background(), parent, false)
	if err != nil || second == first {
		t.Fatal(second, err)
	}
}

func TestReviewAcknowledgedCannotEnrich(t *testing.T) {
	a, _, _, parent := isolatedRecoveryFixture(t)
	a.DB.Exec("UPDATE jobs SET state='ACKNOWLEDGED' WHERE id=?", parent)
	if _, err := a.recoverJob(context.Background(), parent, true); err == nil {
		t.Fatal("rescanned acknowledged file")
	}
}

func TestReviewCancelledMonitorReportsError(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	a.Save("mounts", s.Source.ID, s.Source)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.monitorProfile(ctx, s.Profile)
	var status struct {
		Errors int `json:"errors"`
	}
	if err := a.Get("monitorStatus", s.Profile.ID, &status); err != nil || status.Errors == 0 {
		t.Fatal(status, err)
	}
}
