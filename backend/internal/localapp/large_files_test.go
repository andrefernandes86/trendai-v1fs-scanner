package localapp

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestLargeSizeAdmissionAndBoundary(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	for _, m := range []Mount{s.Source, s.Good, s.Bad, s.Failed} {
		if e := a.Save("mounts", m.ID, m); e != nil {
			t.Fatal(e)
		}
	}
	s.Profile.SourceMount = "source"
	s.Profile.GoodMount = "good"
	s.Profile.BadMount = "bad"
	s.Profile.FailedMount = "failed"
	if e := a.Save("profiles", s.Profile.ID, s.Profile); e != nil {
		t.Fatal(e)
	}
	if e := a.Save("scanner", "default", Scanner{Type: "local", Address: "localhost:50051"}); e != nil {
		t.Fatal(e)
	}
	f, e := os.Create(stores["source"].p("large.doc"))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(DefaultMaxScanBytes); e != nil {
		t.Fatal(e)
	}
	f.Close()
	id, e := a.Enqueue(context.Background(), s.Profile.ID, "large.doc")
	if e != nil || id == "" {
		t.Fatal("100 GB admission rejected", e)
	}
	action, _ := s.Profile.FilePolicy("large.doc", DefaultMaxScanBytes)
	if action != "scan" {
		t.Fatal(action)
	}
	action, _ = s.Profile.FilePolicy("large.doc", DefaultMaxScanBytes+1)
	if action != "hold" {
		t.Fatal(action)
	}
	s.Profile.OversizeAction = "clean"
	action, _ = s.Profile.FilePolicy("large.doc", DefaultMaxScanBytes+1)
	if action != "oversize_clean" {
		t.Fatal(action)
	}
	s.Profile.MaxScanBytes = DefaultMaxScanBytes + 1
	if s.Profile.ReliabilityValidate() == nil {
		t.Fatal("unsupported size accepted")
	}
}

func TestOversizeRoutingIsNotAScan(t *testing.T) {
	for _, mode := range []string{"clean", "failed", "hold"} {
		t.Run(mode, func(t *testing.T) {
			a, s, stores := reliabilityFixture(t)
			s.Profile.MaxScanBytes = 1
			s.Profile.OversizeAction = mode
			a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
				t.Fatal("oversized bypass called scanner")
				return nil, nil
			}
			id, e := a.insertJob(s)
			if e != nil {
				t.Fatal(e)
			}
			_, snapshot, n, e := a.claim()
			if e != nil {
				t.Fatal(e)
			}
			a.process(context.Background(), id, snapshot, n)
			var state, verdict, destination string
			a.DB.QueryRow("SELECT state,verdict,destination FROM jobs WHERE id=?", id).Scan(&state, &verdict, &destination)
			if mode == "hold" {
				if state != "HELD" || verdict != "NOT_SCANNED" {
					t.Fatal(state, verdict)
				}
				if _, e = stores["source"].Stat(s.Key); e != nil {
					t.Fatal("held source missing")
				}
			} else {
				if mode == "clean" && (state != "COMPLETED" || verdict != "OVERSIZED_CLEAN") {
					t.Fatal(state, verdict)
				}
				if mode == "failed" && (state != "HELD" || verdict != "OVERSIZED") {
					t.Fatal(state, verdict)
				}
				m, e := a.loadMove(id)
				if e != nil || m.Phase != "COMPLETED" || m.CRC32C != "e3069283" {
					t.Fatal(m, e)
				}
				var tagsPath = stores[m.Target.ID].p(m.Key + ".v1fs-tags.json")
				data, readErr := os.ReadFile(tagsPath)
				var evidence struct {
					Tags map[string]string `json:"tags"`
				}
				if readErr != nil || json.Unmarshal(data, &evidence) != nil || evidence.Tags["scanned"] != "false" || evidence.Tags["verdict"] != "not_scanned" || evidence.Tags["reason"] != "oversized" {
					t.Fatal("incorrect oversized tags", string(data), readErr)
				}
				if _, e = os.Stat(tagsPath); e != nil {
					t.Fatal("oversize evidence missing", e)
				}
			}
			var scans int
			a.DB.QueryRow("SELECT count(*) FROM scan_results WHERE job_id=?", id).Scan(&scans)
			if scans != 0 {
				t.Fatal("fabricated scan result")
			}
		})
	}
}
func TestLargeConcurrencyKeepsSmallFilesEligible(t *testing.T) {
	a := testApp(t)
	p := Profile{ID: "p", SimultaneousScans: 4, LargeFileScans: 1}
	a.Save("profiles", p.ID, p)
	for i, key := range []string{"large-one", "large-two", "small"} {
		size := int64(3_500_000_000)
		if i == 2 {
			size = 10
		}
		if _, e := a.insertJob(Snapshot{Profile: p, Source: Mount{ID: "source", Account: "example", Container: "source"}, Key: key, ETag: "one", Size: size}); e != nil {
			t.Fatal(e)
		}
	}
	_, s, _, e := a.claim()
	if e != nil || s.Key != "large-one" {
		t.Fatal(s.Key, e)
	}
	_, s, _, e = a.claim()
	if e != nil || s.Key != "small" {
		t.Fatal("large file blocked small work", s.Key, e)
	}
	if _, _, _, e = a.claim(); e == nil {
		t.Fatal("large concurrency exceeded")
	}
}

func TestCaptureCapacityWaitPreservesSource(t *testing.T) {
	release, e := reserveCapture(t.TempDir(), int64(1)<<60)
	if e == nil {
		release()
		t.Fatal("admitted impossible disk reservation")
	}
	if captureBudget.bytes != 0 {
		t.Fatal("failed reservation leaked budget")
	}
}

func TestInventoryReconcilesExactDurableVersion(t *testing.T) {
	a := testApp(t)
	p := Profile{ID: "p"}
	s := Snapshot{Profile: p, Source: Mount{ID: "source", Account: "example", Container: "incoming"}, Key: "previous", ETag: "same"}
	id, e := a.insertJob(s)
	if e != nil {
		t.Fatal(e)
	}
	_, e = a.DB.Exec("INSERT INTO inventory(profile_id,key,etag,size,last_seen,status,reason) VALUES('p','previous','same',1,?,'ERROR','Queue admission failed')", stamp())
	if e != nil {
		t.Fatal(e)
	}
	a.monitorProfile(context.Background(), p)
	var status, job string
	a.DB.QueryRow("SELECT status,job_id FROM inventory").Scan(&status, &job)
	if status != "ACCOUNTED" || job != id {
		t.Fatal(status, job)
	}
}
