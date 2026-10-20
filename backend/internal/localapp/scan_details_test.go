package localapp

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanDetectionDetails(t *testing.T) {
	for _, raw := range []string{
		`{"scanId":"x","scanResult":1,"foundMalwares":[{"malwareName":"EICAR_TEST_FILE","engine":"atse","fileName":"eicar.com"}]}`,
		`{"scanId":"x","result":{"atse":{"malwareCount":1,"malware":[{"name":"EICAR_TEST_FILE","fileName":"eicar.com"}]}},"apiKey":"private-secret"}`,
	} {
		got := extractDetections([]byte(raw))
		if len(got) != 1 || got[0].Name != "EICAR_TEST_FILE" || got[0].Engine != "atse" {
			t.Fatal(got)
		}
	}
	a := testApp(t)
	if e := a.recordScanDetails("job", []byte(`{"scanId":"x","foundMalwares":[{"malwareName":"EICAR_TEST_FILE"}],"token":"private-secret"}`), "private-secret"); e != nil {
		t.Fatal(e)
	}
	var sealed []byte
	a.DB.QueryRow("SELECT payload FROM scan_details WHERE job_id='job'").Scan(&sealed)
	if strings.Contains(string(sealed), "EICAR") || strings.Contains(string(sealed), "private-secret") {
		t.Fatal("details stored in cleartext")
	}
	r := httptest.NewRequest("GET", "http://localhost/api/jobs/job/scan-result", nil)
	r.SetPathValue("id", "job")
	w := httptest.NewRecorder()
	a.scanDetails(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "EICAR_TEST_FILE") || strings.Contains(w.Body.String(), "private-secret") {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/api/jobs/job/scan-result", nil))
	if w.Code != 401 {
		t.Fatal("unprotected response")
	}
}
