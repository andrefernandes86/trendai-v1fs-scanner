package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHistoricalResolutionRequiresExactVerifiedBytes(t *testing.T) {
	for _, scenario := range []string{"identical", "corrupted", "source-still-present", "missing-scan-evidence"} {
		t.Run(scenario, func(t *testing.T) {
			a := testApp(t)
			data := []byte("identical bytes")
			sum := sha256.Sum256(data)
			digest := hex.EncodeToString(sum[:])
			fake := &fakeAzure{objects: map[string][]byte{"/clean/file.txt": data}, writes: map[string]int{}, etag: `"v1"`}
			if scenario == "corrupted" {
				fake.objects["/clean/file.txt"] = []byte("corrupted bytes")
			}
			if scenario == "source-still-present" {
				fake.objects["/incoming/file.txt"] = data
			}
			storageTransport = fake
			t.Cleanup(func() { storageTransport = nil })
			s := Snapshot{Source: testMount("source", "incoming"), Good: testMount("good", "clean"), Profile: Profile{ID: "profile", Revision: 1}, Key: "file.txt", ETag: `"v1"`, Size: int64(len(data))}
			old, e := a.insertJob(s)
			if e != nil {
				t.Fatal(e)
			}
			_ = a.transition(old, "HELD", "UNKNOWN", digest, "", "Source download failed; historical error", 0)
			s.ETag = `"v2"`
			newer, e := a.insertJob(s)
			if e != nil {
				t.Fatal(e)
			}
			_ = a.transition(newer, "COMPLETED", "CLEAN", digest, s.Good.BaseURL()+"/file.txt", "", 0)
			if scenario != "missing-scan-evidence" {
				_, e = a.DB.Exec("INSERT INTO scan_results(job_id,scanned_at,verdict) VALUES(?,?,'CLEAN')", newer, stamp())
				if e != nil {
					t.Fatal(e)
				}
			}
			e = a.resolveHistorical(context.Background(), old)
			var state, verdict, originalError string
			_ = a.DB.QueryRow("SELECT state,verdict,error FROM jobs WHERE id=?", old).Scan(&state, &verdict, &originalError)
			if scenario == "identical" {
				if e != nil || state != "SUPERSEDED" || verdict != "UNKNOWN" || originalError != "Source download failed; historical error" {
					t.Fatal("historical evidence not preserved", state, e)
				}
			} else if e == nil || state != "HELD" {
				t.Fatal("unsafe historical resolution", scenario, e, state)
			}
		})
	}
}
func TestMandatoryResultTags(t *testing.T) {
	p := Profile{}
	for _, verdict := range []string{"CLEAN", "MALICIOUS"} {
		tags, e := p.ResultTags(verdict)
		if e != nil || tags["scanned"] != "true" || tags["verdict"] == "" {
			t.Fatal(tags, e)
		}
	}
	p.CleanTags = "scanned=false"
	if _, e := p.ResultTags("CLEAN"); e == nil {
		t.Fatal("accepted a misleading reserved scan tag")
	}
}
