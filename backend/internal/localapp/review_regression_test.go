package localapp

import (
	"context"
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

func TestReviewDeliveredRecoveryDisabled(t *testing.T) {
	a, _, _, parent := isolatedRecoveryFixture(t)
	for _, enrich := range []bool{false, true} {
		if _, err := a.recoverJob(context.Background(), parent, enrich); err == nil {
			t.Fatal("destination access permitted")
		}
	}
	var children int
	a.DB.QueryRow("SELECT count(*) FROM recovery_links WHERE parent_id=?", parent).Scan(&children)
	if children != 0 {
		t.Fatal("created recovery work after handoff")
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
