package localapp

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCompressedPolicyLimitsAndLegacyDefaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int64
		want string
	}{
		{"report.csv", 100_000_000_000, "scan"}, {"report.csv", 100_000_000_001, "hold"},
		{"data.ZIP", 2_000_000_000, "scan"}, {"data.zip", 2_000_000_001, "hold"},
		{"data.tar.gz", 10_000_000_000, "hold"}, {"document.docx", 2_000_000_001, "hold"},
	} {
		if got, _ := (Profile{}).FilePolicy(tc.name, tc.size); got != tc.want {
			t.Fatalf("%s/%d: %s", tc.name, tc.size, got)
		}
	}
	p := Profile{MaxScanBytes: 1, MaxCompressedScanBytes: 10, CompressedOversizeAction: "clean"}
	if got, _ := p.FilePolicy("data.zip", 10); got != "scan" {
		t.Fatal("regular limit changed archive limit", got)
	}
	if got, rule := p.FilePolicy("data.zip", 11); got != "oversize_clean" || rule != "compressed_size_limit" {
		t.Fatal(got, rule)
	}
	for _, p := range []Profile{{MaxCompressedScanBytes: 2_000_000_001}, {MaxCompressedScanBytes: -1}, {CompressedOversizeAction: "delete"}, {CompressedOversizeAction: "custom"}} {
		if p.ReliabilityValidate() == nil {
			t.Fatal("invalid compressed policy accepted", p)
		}
	}
}

func TestCompressedOversizeActionsNeverScan(t *testing.T) {
	for _, renamed := range []bool{false, true} {
		for _, mode := range []string{"hold", "clean", "failed", "custom"} {
			name := mode
			if renamed {
				name += "-renamed"
			}
			t.Run(name, func(t *testing.T) {
				a, s, stores := reliabilityFixture(t)
				s.Key = "archive.zip"
				if renamed {
					s.Key = "archive.dat"
				}
				body := []byte("PK\x03\x04synthetic archive bytes")
				if err := os.WriteFile(stores["source"].p(s.Key), body, 0600); err != nil {
					t.Fatal(err)
				}
				info, _ := stores["source"].Stat(s.Key)
				s.ETag = infoTag(info)
				s.Size = int64(len(body))
				s.Profile.MaxCompressedScanBytes = 1
				s.Profile.CompressedOversizeAction = mode
				s.Profile.CompressedOversizeMount = s.Bad.ID
				s.Profile.CompressedOversizePrefix = "archive-review"
				s.CompressedOversized = s.Bad
				a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
					t.Fatal("oversized archive reached SDK")
					return nil, nil
				}
				id, err := a.insertJob(s)
				if err != nil {
					t.Fatal(err)
				}
				a.process(context.Background(), id, s, 1)
				var state, verdict string
				a.DB.QueryRow("select state,verdict from jobs where id=?", id).Scan(&state, &verdict)
				var scans int
				a.DB.QueryRow("select count(*) from scan_results where job_id=?", id).Scan(&scans)
				if scans != 0 {
					t.Fatal("invented scan result")
				}
				if mode == "hold" {
					if state != "HELD" || verdict != "NOT_SCANNED" {
						t.Fatal(state, verdict)
					}
					key := s.Key
					if claim, claimErr := a.loadClaim(id); claimErr == nil {
						key = claim.Key
					}
					retained, readErr := os.ReadFile(stores["source"].p(key))
					if readErr != nil || string(retained) != string(body) {
						t.Fatal("held source changed or disappeared", readErr)
					}

					return
				}
				m, err := a.loadMove(id)
				if err != nil || m.Phase != "COMPLETED" || m.Rule != "compressed_size_limit" {
					t.Fatal(m, err)
				}
				target := s.Failed.ID
				if mode == "clean" {
					target = s.Good.ID
					if verdict != "OVERSIZED_CLEAN" {
						t.Fatal(verdict)
					}
				}
				if mode == "custom" {
					target = s.Bad.ID
					if !strings.HasPrefix(m.Key, "archive-review/") {
						t.Fatal(m.Key)
					}
				}
				if m.Target.ID != target || verdict == "CLEAN" {
					t.Fatal(m.Target.ID, verdict)
				}
				raw, err := os.ReadFile(stores[target].p(m.Key + ".v1fs-tags.json"))
				if err != nil {
					t.Fatal(err)
				}
				var labels struct {
					Tags map[string]string `json:"tags"`
				}
				json.Unmarshal(raw, &labels)
				if labels.Tags["scanned"] != "false" || labels.Tags["verdict"] != "not_scanned" || labels.Tags["reason"] != "oversized" {
					t.Fatal(string(raw))
				}
			})
		}
	}
}

func TestSDKChildRejectsOversizedRenamedArchive(t *testing.T) {
	a := testApp(t)
	file := t.TempDir() + "/renamed.bin"
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("PK\x03\x04")); err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(DefaultMaxCompressedScanBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	_, err = a.ScanDirect(context.Background(), file, Scanner{}, Profile{MaxCompressedScanBytes: DefaultMaxCompressedScanBytes + 1})
	if err == nil || !strings.Contains(err.Error(), "SDK submission blocked") {
		t.Fatal("SDK child did not enforce hard archive cap", err)
	}
}

func TestExplicitManualDeliveryCanMoveArchiveAboveCapWithoutScanning(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	s.Key = "manual.zip"
	s.Profile.MaxCompressedScanBytes = 1
	s.Profile.CompressedOversizeAction = "hold"
	body := []byte("PK\x03\x04manual archive delivery")
	if err := os.WriteFile(stores["source"].p(s.Key), body, 0600); err != nil {
		t.Fatal(err)
	}
	info, _ := stores["source"].Stat(s.Key)
	s.ETag = infoTag(info)
	s.Size = int64(len(body))
	s.ManualAction = "clean"
	s.Failed = s.Good
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		t.Fatal("manual archive delivery reached SDK")
		return nil, nil
	}
	id, err := a.insertJob(s)
	if err != nil {
		t.Fatal(err)
	}
	a.process(context.Background(), id, s, 1)
	m, err := a.loadMove(id)
	if err != nil || m.Phase != "COMPLETED" || m.Target.ID != s.Good.ID || m.FinalState != "ACKNOWLEDGED" || m.Verdict != "UNKNOWN" {
		t.Fatal(m, err)
	}
}
