package localapp

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestConnectionDeletionChecksEveryActiveProfileReference(t *testing.T) {
	for _, role := range []string{"source", "clean", "malicious", "failed", "oversized", "compressed", "rule", "unused"} {
		t.Run(role, func(t *testing.T) {
			a := testApp(t)
			m := Mount{ID: "target", Name: "Target", Kind: "blob"}
			if err := a.Save("mounts", m.ID, m); err != nil {
				t.Fatal(err)
			}
			p := Profile{ID: "profile", Name: "Profile"}
			switch role {
			case "source":
				p.SourceMount = m.ID
			case "clean":
				p.GoodMount = m.ID
			case "malicious":
				p.BadMount = m.ID
			case "failed":
				p.FailedMount = m.ID
			case "oversized":
				p.OversizeAction = "custom"
				p.OversizeMount = m.ID
			case "compressed":
				p.CompressedOversizeAction = "custom"
				p.CompressedOversizeMount = m.ID
			case "rule":
				p.Rules = []FileRule{{Action: "route", DestinationMount: m.ID}}
			}
			if err := a.Save("profiles", p.ID, p); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("DELETE", "/api/mounts/target", nil)
			r.SetPathValue("id", m.ID)
			w := httptest.NewRecorder()
			a.mountDelete(w, r)
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal("delete did not return one JSON response", err)
			}
			var remaining int
			a.DB.QueryRow("select count(*) from config where kind='mounts' and id=?", m.ID).Scan(&remaining)
			if role == "unused" {
				if w.Code != 200 || body["deleted"] != true || remaining != 0 {
					t.Fatal(w.Code, body, remaining)
				}
			} else if w.Code != 409 || body["error"] == nil || remaining != 1 {
				t.Fatal(w.Code, body, remaining)
			}
		})
	}
}

func TestProfileDeletionRetainsHistoricalSnapshot(t *testing.T) {
	a, s, _ := reliabilityFixture(t)
	if err := a.Save("profiles", s.Profile.ID, s.Profile); err != nil {
		t.Fatal(err)
	}
	id, err := a.insertJob(s)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("DELETE", "/api/profiles/"+s.Profile.ID, nil)
	r.SetPathValue("id", s.Profile.ID)
	w := httptest.NewRecorder()
	a.remove(w, r, "profiles")
	var body map[string]any
	if err = json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 200 || body["deleted"] != true {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	var payload []byte
	if err = a.DB.QueryRow("select snapshot from jobs where id=?", id).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var snapshot Snapshot
	if err = a.Unseal(payload, &snapshot); err != nil || snapshot.Profile.ID != s.Profile.ID || snapshot.Key != s.Key {
		t.Fatal("history snapshot changed", err)
	}
	var remaining int
	a.DB.QueryRow("select count(*) from config where kind='profiles' and id=?", s.Profile.ID).Scan(&remaining)
	if remaining != 0 {
		t.Fatal("profile not deleted")
	}
}
