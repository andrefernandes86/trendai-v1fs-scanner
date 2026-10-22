package localapp

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestExhaustedCopyTagsClaimedSourceAndPreservesReplacement(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	s.Profile.TransferAttempts = 2
	id, err := a.insertJob(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.handoffSource(context.Background(), id, &s); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(stores["source"].p(s.Key), []byte("replacement upload"), 0600); err != nil {
		t.Fatal(err)
	}
	a.retryStage(id, "transfer", s.Profile, "CLEAN", "", "", "Copy unavailable.")
	if _, err = os.Stat(stores["source"].p(s.sourceKey() + ".v1fs-tags.json")); !os.IsNotExist(err) {
		t.Fatal("tagged before retry exhaustion")
	}
	a.retryStage(id, "transfer", s.Profile, "CLEAN", "", "", "Copy unavailable.")
	data, err := os.ReadFile(stores["source"].p(s.sourceKey() + ".v1fs-tags.json"))
	if err != nil || !strings.Contains(string(data), `"verdict":"scan_failed"`) || !strings.Contains(string(data), `"failure-stage":"transfer"`) {
		t.Fatal(string(data), err)
	}
	if strings.Contains(string(data), `"scanned":"false"`) {
		t.Fatal("erased confirmed scan status")
	}
	if _, err = os.Stat(stores["source"].p(s.Key + ".v1fs-tags.json")); !os.IsNotExist(err) {
		t.Fatal("tagged replacement")
	}
	var state, message string
	a.DB.QueryRow("SELECT state,error FROM jobs WHERE id=?", id).Scan(&state, &message)
	if state != "HELD" || !strings.Contains(message, "Configured failure labels applied") {
		t.Fatal(state, message)
	}
	if _, err = os.Stat(stores["source"].p(s.sourceKey())); err != nil {
		t.Fatal("removed retained source", err)
	}
}

func TestExhaustedTagWriteFailureIsRecorded(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	s.Profile.TransferAttempts = 1
	id, _ := a.insertJob(s)
	os.Remove(stores["source"].p(s.Key))
	a.retryStage(id, "download", s.Profile, "UNKNOWN", "", "", "Download unavailable.")
	var message string
	a.DB.QueryRow("SELECT error FROM jobs WHERE id=?", id).Scan(&message)
	if !strings.Contains(message, "Configured failure labels applied") || !strings.Contains(message, "could not be written") {
		t.Fatal(message)
	}
}

func TestUnknownRecoveryRetainsIsolationAndFailureTag(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	s.Failed = s.Source // recovery reads the already-isolated location
	id, err := a.insertJob(s)
	if err != nil {
		t.Fatal(err)
	}
	a.routeCapturedNow(context.Background(), id, s, "", "", "UNKNOWN", "", "All scan attempts exhausted.")
	var state, verdict, destination, message string
	a.DB.QueryRow("SELECT state,verdict,destination,error FROM jobs WHERE id=?", id).Scan(&state, &verdict, &destination, &message)
	if state != "HELD" || verdict != "UNKNOWN" || destination != s.Source.BaseURL()+"/"+s.Key || !strings.Contains(message, "Configured failure labels applied") {
		t.Fatal(state, verdict, destination, message)
	}
	tags, err := os.ReadFile(stores["source"].p(s.Key + ".v1fs-tags.json"))
	if err != nil || !strings.Contains(string(tags), `"verdict":"scan_failed"`) || !strings.Contains(string(tags), `"scanned":"false"`) {
		t.Fatal(string(tags), err)
	}
	if _, err := stores["source"].Stat(s.Key); err != nil {
		t.Fatal("isolated file removed", err)
	}
}
