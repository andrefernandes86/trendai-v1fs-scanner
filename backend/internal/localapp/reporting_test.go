package localapp

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStatisticsAndFullCSVExport(t *testing.T) {
	a := testApp(t)
	tx, e := a.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 505; i++ {
		verdict, digest := "UNKNOWN", ""
		if i == 0 {
			verdict, digest = "CLEAN", "sha256value"
		}
		if i == 1 {
			verdict = "MALICIOUS"
		}
		_, e = tx.Exec(`INSERT INTO jobs(id,key,profile_id,profile_name,source_id,etag,version,size,state,verdict,digest,created_at,updated_at,available_at,snapshot) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, fmt.Sprint(i), "=unsafe,\"quoted\"\nfile.txt", "p", "Profile", "source", "etag", "", 1, "HELD", verdict, digest, stamp(), stamp(), 0, []byte("unused"))
		if e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	// Include active jobs outside the latest-500 table, but exclude queued/routing jobs.
	if _, e = a.DB.Exec("UPDATE jobs SET state='SCANNING' WHERE id IN ('3','504'); UPDATE jobs SET state='QUEUED' WHERE id='4'; UPDATE jobs SET state='ROUTING' WHERE id='5'; UPDATE jobs SET state='RETRY_PENDING' WHERE id='6'; UPDATE jobs SET state='RETRY_PENDING' WHERE id='0'"); e != nil {
		t.Fatal(e)
	}
	// One historical clean result, one old malicious result, and one new unknown response.
	old := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, e = a.DB.Exec("INSERT INTO scan_results(job_id,scanned_at,verdict) VALUES('1',?,'MALICIOUS'),('2',?,'UNKNOWN')", old, stamp()); e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	a.statistics(w, httptest.NewRequest("GET", "http://localhost/api/statistics", nil))
	var out struct {
		Counts       map[string]int `json:"counts"`
		ScanningNow  int            `json:"scanningNow"`
		PendingScans int            `json:"pendingScans"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	if out.PendingScans != 2 {
		t.Fatalf("pending scans=%d, want queued and unknown retry only", out.PendingScans)
	}
	if out.ScanningNow != 2 {
		t.Fatalf("scanning now = %d, want 2", out.ScanningNow)
	}
	if out.Counts["minute"] != 2 || out.Counts["hour"] != 2 || out.Counts["day"] != 3 || out.Counts["month"] != 3 {
		t.Fatal(out.Counts)
	}
	w = httptest.NewRecorder()
	a.exportJobsCSV(w, httptest.NewRequest("GET", "http://localhost/api/jobs/export.csv", nil))
	records, e := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if e != nil || len(records) != 506 {
		t.Fatalf("rows=%d error=%v", len(records), e)
	}
	if records[1][1] != "'=unsafe,\"quoted\"\nfile.txt" {
		t.Fatal("CSV escaping or formula protection failed")
	}
	seenClean, seenUnknown := false, false
	for _, row := range records[1:] {
		if row[0] == "0" {
			seenClean = row[10] == "false" && row[11] == "true" && row[13] == "sha256value"
		}
		if row[0] == "2" {
			seenUnknown = row[10] == "unknown" && row[11] == "false" && row[19] != ""
		}
	}
	if !seenClean || !seenUnknown {
		t.Fatal("verdict, hash, or date export incorrect")
	}
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/api/jobs/export.csv", nil))
	if w.Code != 401 {
		t.Fatal("export is not authenticated")
	}
}

func TestScanIssueCountMatchesHistoryFilterAndPreservesHiddenIssues(t *testing.T) {
	a := testApp(t)
	for _, tc := range []struct{ state, verdict string }{{"HELD", "UNKNOWN"}, {"RETRY_PENDING", "UNKNOWN"}, {"QUEUED", "UNKNOWN"}, {"HELD", "NOT_SCANNED"}, {"COMPLETED", "CLEAN"}, {"RECOVERED", "UNKNOWN"}} {
		s := Snapshot{Profile: Profile{ID: tc.state + tc.verdict}, Key: "sample.txt"}
		id, e := a.insertJob(s)
		if e != nil {
			t.Fatal(e)
		}
		if e = a.transition(id, tc.state, tc.verdict, "", "", "", 0); e != nil {
			t.Fatal(e)
		}
		if tc.state == "HELD" && tc.verdict == "UNKNOWN" {
			if _, e = a.DB.Exec("INSERT INTO hidden_jobs(job_id) VALUES(?)", id); e != nil {
				t.Fatal(e)
			}
		}
	}
	w := httptest.NewRecorder()
	a.statistics(w, httptest.NewRequest("GET", "http://localhost/api/statistics", nil))
	var result struct {
		ScanErrors int `json:"scanErrors"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil || result.ScanErrors != 2 {
		t.Fatal(w.Body.String(), e)
	}
	where, args, limit, offset := jobQuery(httptest.NewRequest("GET", "http://localhost/api/jobs/page?issues=scan_errors&visibility=all", nil), 1000)
	jobs, e := a.jobsPage(where, args, limit, offset)
	if e != nil || len(jobs) != result.ScanErrors {
		t.Fatal(jobs, e)
	}
	for _, j := range jobs {
		if j.Verdict != "UNKNOWN" || (j.State != "HELD" && j.State != "RETRY_PENDING") {
			t.Fatal(j)
		}
	}
}
