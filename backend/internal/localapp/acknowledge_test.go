package localapp

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
)

func TestAcknowledgeStopsThisVersionAndRecovery(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	id, _ := a.insertJob(s)
	a.DB.Exec("UPDATE jobs SET state='HELD',verdict='UNKNOWN',error='scan failed' WHERE id=?", id)
	r := httptest.NewRequest("POST", "/api/jobs/"+id+"/acknowledge", nil)
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	a.acknowledgeJob(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var state, verdict string
	a.DB.QueryRow("SELECT state,verdict FROM jobs WHERE id=?", id).Scan(&state, &verdict)
	if state != "ACKNOWLEDGED" || verdict != "UNKNOWN" {
		t.Fatal(state, verdict)
	}
	s.Profile.Revision++
	repeated, err := a.insertJob(s)
	if err != nil || repeated != id {
		t.Fatal("requeued acknowledged version", repeated, err)
	}
	s.ETag = "new-version"
	next, err := a.insertJob(s)
	if err != nil || next == id {
		t.Fatal("blocked new upload", next, err)
	}
	if _, err = a.insertJob(s, id); err == nil {
		t.Fatal("recovery allowed after acknowledgement")
	}
	w = httptest.NewRecorder()
	a.retryJob(w, r)
	if w.Code != 409 {
		t.Fatal("retry accepted", w.Code)
	}
	var audits int
	a.DB.QueryRow("SELECT count(*) FROM audit WHERE object_id=? AND action='job.acknowledged'", id).Scan(&audits)
	if audits != 1 {
		t.Fatal(audits)
	}
}

func TestAcknowledgeRejectsRunningButDismissesQueuedRecovery(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	id, _ := a.insertJob(s)
	a.DB.Exec("UPDATE jobs SET state='HELD' WHERE id=?", id)
	s.ETag = "child"
	child, err := a.insertJob(s, id)
	if err != nil {
		t.Fatal(err)
	}
	a.DB.Exec("UPDATE jobs SET state='SCANNING' WHERE id=?", child)
	r := httptest.NewRequest("POST", "/", nil)
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	a.acknowledgeJob(w, r)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	a.DB.Exec("UPDATE jobs SET state='QUEUED' WHERE id=?", child)
	r.SetPathValue("id", id)
	w = httptest.NewRecorder()
	a.acknowledgeJob(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var remaining int
	a.DB.QueryRow("SELECT count(*) FROM jobs WHERE id IN (?,?) AND state != 'ACKNOWLEDGED'", id, child).Scan(&remaining)
	if remaining != 0 {
		t.Fatal("related held/recovery records not dismissed")
	}
	s.ETag = "another-child"
	if _, err := a.insertJob(s, id); err == nil {
		t.Fatal("recovery restarted after child acknowledgement")
	}
}

func TestDismissMissingHiddenFileClearsAssuranceWithoutStorage(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	if err := os.Remove(stores["source"].p(s.Key)); err != nil {
		t.Fatal(err)
	}
	id, _ := a.insertJob(s)
	a.DB.Exec("UPDATE jobs SET state='HELD',verdict='UNKNOWN' WHERE id=?", id)
	if _, err := a.DB.Exec("INSERT INTO hidden_jobs(job_id) VALUES(?)", id); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.SetPathValue("id", id)
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		a.acknowledgeJob(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	a.assurance(w, httptest.NewRequest("GET", "/", nil))
	var result struct {
		HeldFiles int `json:"heldFiles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.HeldFiles != 0 {
		t.Fatal(w.Body.String(), err)
	}
	var state, verdict string
	a.DB.QueryRow("SELECT state,verdict FROM jobs WHERE id=?", id).Scan(&state, &verdict)
	if state != "ACKNOWLEDGED" || verdict != "UNKNOWN" {
		t.Fatal(state, verdict)
	}
}
