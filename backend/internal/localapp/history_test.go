package localapp

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestFullHistoryPaginationBeyondThousand(t *testing.T) {
	a := testApp(t)
	tx, e := a.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	for i := 0; i < 1107; i++ {
		state, verdict := "COMPLETED", "CLEAN"
		if i%2 == 1 {
			state, verdict = "QUARANTINED", "MALICIOUS"
		}
		_, e = tx.Exec("INSERT INTO jobs(id,key,profile_id,profile_name,source_id,etag,version,size,state,verdict,created_at,updated_at,available_at,snapshot) VALUES(?,?,'stress','Stress','source','one','',1,?,?,?, ?,0,X'')", fmt.Sprintf("%04d", i), fmt.Sprintf("loadtest/file-%04d.txt", i), state, verdict, stamp(), stamp())
		if e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	type page struct {
		Items  []Job `json:"items"`
		Total  int   `json:"total"`
		Offset int   `json:"offset"`
		Limit  int   `json:"limit"`
	}
	read := func(query string) page {
		t.Helper()
		w := httptest.NewRecorder()
		a.jobHistory(w, httptest.NewRequest("GET", "http://localhost/api/jobs/page?"+query, nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var result page
		if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
			t.Fatal(e)
		}
		return result
	}
	seen := map[string]bool{}
	for offset := 0; offset < 1107; offset += 100 {
		p := read(fmt.Sprintf("limit=100&offset=%d", offset))
		if p.Total != 1107 {
			t.Fatal(p.Total)
		}
		for _, j := range p.Items {
			if seen[j.ID] {
				t.Fatal("duplicate page item", j.ID)
			}
			seen[j.ID] = true
		}
	}
	if len(seen) != 1107 {
		t.Fatal("history truncated", len(seen))
	}
	if p := read("limit=1000"); len(p.Items) != 1000 || p.Limit != 1000 {
		t.Fatal("1000 row selection truncated", len(p.Items))
	}
	if p := read("limit=100&offset=999999"); p.Offset != 1100 || len(p.Items) != 7 {
		t.Fatal("out of range page not clamped", p.Offset, len(p.Items))
	}
	if p := read("limit=1000&verdict=CLEAN"); p.Total != 554 || len(p.Items) != 554 {
		t.Fatal("filtered totals incorrect", p.Total)
	}
	if p := read("q=file-0000"); p.Total != 1 || p.Items[0].ID != "0000" {
		t.Fatal("search did not cover oldest file")
	}
	if p := read("state=HELD&offset=1000"); p.Total != 0 || p.Offset != 0 || len(p.Items) != 0 {
		t.Fatal("empty filtered page incorrect")
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/api/jobs/page", nil))
	if w.Code != 401 {
		t.Fatal("history endpoint not authenticated", w.Code)
	}
}
