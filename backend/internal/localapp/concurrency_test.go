package localapp

import (
	"context"
	"testing"
	"time"
)

func TestProfileConcurrencyAndFairAdmission(t *testing.T) {
	t.Setenv("V1FS_MAX_WORKERS", "8")
	a := testApp(t)
	one := Profile{ID: "one", SimultaneousScans: 1}
	two := Profile{ID: "two", SimultaneousScans: 2}
	for _, p := range []Profile{one, two} {
		if e := a.Save("profiles", p.ID, p); e != nil {
			t.Fatal(e)
		}
	}
	add := func(p Profile, key string) {
		t.Helper()
		if _, e := a.insertJob(Snapshot{Profile: p, Source: Mount{ID: "source", Account: "example", Container: "incoming"}, Key: key, ETag: "version"}); e != nil {
			t.Fatal(e)
		}
	}
	for _, key := range []string{"a", "b", "c"} {
		add(one, key)
	}
	add(two, "d")
	add(two, "e")
	id, s, _, e := a.claim()
	if e != nil || s.Profile.ID != "one" {
		t.Fatalf("first claim %s %v", s.Profile.ID, e)
	}
	for i := 0; i < 2; i++ {
		_, s, _, e = a.claim()
		if e != nil || s.Profile.ID != "two" {
			t.Fatalf("saturated first profile blocked second: %s %v", s.Profile.ID, e)
		}
	}
	if _, _, _, e = a.claim(); e == nil {
		t.Fatal("admitted beyond per-profile budgets")
	}
	// A live control update can release capacity without changing queued snapshots.
	one.SimultaneousScans = 2
	if e = a.Save("profiles", one.ID, one); e != nil {
		t.Fatal(e)
	}
	if _, s, _, e = a.claim(); e != nil || s.Profile.ID != "one" {
		t.Fatal("updated limit did not release queued work", e)
	}
	one.SimultaneousScans = 1
	_ = a.Save("profiles", one.ID, one)
	_ = a.transition(id, "COMPLETED", "CLEAN", "", "", "", 0)
	if _, _, _, e = a.claim(); e == nil {
		t.Fatal("lowered limit must wait for remaining active file")
	}
}
func TestManagementOpenDoesNotRequeueRunningEngine(t *testing.T) {
	data := t.TempDir()
	engine, e := OpenEngine(data, "")
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	id, e := engine.insertJob(Snapshot{Profile: Profile{ID: "profile"}, Key: "input", Source: Mount{Account: "example", Container: "source"}, ETag: "one"})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = engine.claim(); e != nil {
		t.Fatal(e)
	}
	api, e := OpenAPI(data, "")
	if e != nil {
		t.Fatal(e)
	}
	defer api.Close()
	api.StartManagement()
	var state string
	if e = api.DB.QueryRow("SELECT state FROM jobs WHERE id=?", id).Scan(&state); e != nil || state != "SCANNING" {
		t.Fatal("API startup reset engine-owned work", state, e)
	}
	tx, e := engine.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE jobs SET error='write in flight' WHERE id=?", id); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = api.DB.QueryRowContext(ctx, "SELECT state FROM jobs WHERE id=?", id).Scan(&state); e != nil {
		t.Fatal("management read blocked by engine WAL writer", e)
	}
}

func TestProfileEditReusesActiveSourceVersion(t *testing.T) {
	a := testApp(t)
	s := Snapshot{Profile: Profile{ID: "profile", Revision: 1}, Source: Mount{ID: "source", Account: "account", Container: "incoming"}, Key: "file.txt", ETag: "unchanged"}
	first, e := a.insertJob(s)
	if e != nil {
		t.Fatal(e)
	}
	s.Profile.Revision = 2
	s.Profile.SimultaneousScans = 4
	second, e := a.insertJob(s)
	if e != nil || first != second {
		t.Fatal("profile edit duplicated an active source version", first, second, e)
	}
	var count int
	_ = a.DB.QueryRow("SELECT count(*) FROM jobs").Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
	s.ETag = "new upload"
	third, e := a.insertJob(s)
	if e != nil || third == first {
		t.Fatal("new source version must get its own job", e)
	}
}
