package localapp

import (
	"context"
	"os"
	"testing"
)

func TestMonitorScansOnlySourceAndReportsMarkerSkips(t *testing.T) {
	a := testApp(t)
	fs := &diskShare{root: t.TempDir()}
	original := remoteOpen
	remoteOpen = func(_ context.Context, m Mount) (remoteFS, error) {
		if m.ID != "source" {
			t.Fatalf("monitor opened destination %s", m.ID)
		}
		return fs, nil
	}
	defer func() { remoteOpen = original }()
	for _, id := range []string{"source", "good", "bad", "failed"} {
		if e := a.Save("mounts", id, Mount{ID: id, Kind: "smb", Server: "nas", Share: id}); e != nil {
			t.Fatal(e)
		}
	}
	if e := a.Save("scanner", "default", Scanner{Type: "local", Address: "localhost:50051"}); e != nil {
		t.Fatal(e)
	}
	p := Profile{ID: "p", Name: "Policy", SourceMount: "source", GoodMount: "good", BadMount: "bad", FailedMount: "failed", RequireMarker: true, Enabled: true}
	if e := a.Save("profiles", p.ID, p); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(fs.p("ready.txt"), []byte("safe"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(fs.p("ready.txt.complete"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(fs.p("pending.txt"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	a.monitorProfile(context.Background(), p)
	jobs, e := a.Jobs()
	if e != nil || len(jobs) != 1 || jobs[0].Key != "ready.txt" {
		t.Fatalf("jobs %v %v", jobs, e)
	}
	var summary struct {
		WaitingForMarker int `json:"waitingForMarker"`
		Queued           int `json:"queued"`
	}
	if e = a.Get("monitorStatus", p.ID, &summary); e != nil || summary.WaitingForMarker != 1 || summary.Queued != 1 {
		t.Fatalf("summary %+v %v", summary, e)
	}
	a.monitorProfile(context.Background(), p)
	jobs, e = a.Jobs()
	if e != nil || len(jobs) != 1 {
		t.Fatal("scheduled polling duplicated jobs")
	}
}
