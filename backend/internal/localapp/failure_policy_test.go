package localapp

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCustomFailureLabelsReachRetainedSource(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	s.Profile.FailedTags = "processing-status=failed,review=required"
	id, err := a.insertJob(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.tagExhaustedSource(id, "download", "UNKNOWN"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(stores["source"].p(s.Key + ".v1fs-tags.json"))
	if err != nil || !strings.Contains(string(body), `"processing-status":"failed"`) || !strings.Contains(string(body), `"scan-failed":"true"`) {
		t.Fatal(string(body), err)
	}
	tags, err := routingTags(s.Profile, "UNKNOWN")
	if err != nil || tags["review"] != "required" || tags["scanned"] != "false" {
		t.Fatal(tags, err)
	}
	clean, err := routingTags(s.Profile, "CLEAN")
	if err != nil || clean["review"] != "" {
		t.Fatal(clean, err)
	}
	s.Profile.FailedTags = "scanned=true"
	if _, err = s.Profile.FailureTags(); err == nil {
		t.Fatal("accepted contradictory evidence")
	}
}
func TestOversizedCustomDestinationSkipsScanAndRetainsNotScannedLabels(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	s.Profile.MaxScanBytes = 1
	s.Profile.OversizeAction = "custom"
	s.Profile.OversizePrefix = "review"
	s.Oversized = s.Bad
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		t.Fatal("oversized bypass invoked scanner")
		return nil, nil
	}
	id, err := a.insertJob(s)
	if err != nil {
		t.Fatal(err)
	}
	a.process(context.Background(), id, s, 1)
	m, err := a.loadMove(id)
	if err != nil || m.Target.ID != s.Bad.ID || m.Verdict != "OVERSIZED" || !strings.Contains(m.Key, "review/") || m.Phase != "COMPLETED" {
		t.Fatal(m, err)
	}
	tags, err := routingTags(s.Profile, m.Verdict)
	if err != nil || tags["scanned"] != "false" || tags["verdict"] != "not_scanned" {
		t.Fatal(tags, err)
	}
}

func TestRuleMoveUsesSelectedConnectionWithoutCleanVerdict(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	s.Profile.Rules = []FileRule{{ID: "move-reports", Pattern: "*.png", Action: "route", DestinationMount: s.Bad.ID, DestinationPrefix: "manual-review"}}
	s.RuleDestinations = map[string]Mount{"move-reports": s.Bad}
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		t.Fatal("rule bypass invoked SDK")
		return nil, nil
	}
	id, err := a.insertJob(s)
	if err != nil {
		t.Fatal(err)
	}
	a.process(context.Background(), id, s, 1)
	m, err := a.loadMove(id)
	if err != nil || m.Target.ID != s.Bad.ID || m.Verdict != "EXCLUDED" || !strings.Contains(m.Key, "manual-review/") {
		t.Fatal(m, err)
	}
	tags, _ := routingTags(s.Profile, m.Verdict)
	if tags["scanned"] != "false" || tags["verdict"] == "clean" {
		t.Fatal(tags)
	}
	p := s.Profile
	p.Rules = append(p.Rules, FileRule{ID: "hold", Pattern: "*.png", Action: "hold"})
	if action, _ := p.FilePolicy("photo.png", 9); action != "hold" {
		t.Fatal("hold must win", action)
	}
}
