package localapp

import (
	"context"
	"fmt"
	"os"
	"strings"
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

func TestProfileTwentyOverridesLegacyEightWorkerEnvironment(t *testing.T) {
	t.Setenv("V1FS_MAX_WORKERS", "8")
	a := testApp(t)
	p := Profile{ID: "twenty", SimultaneousScans: 20}
	if err := a.Save("profiles", p.ID, p); err != nil {
		t.Fatal(err)
	}
	if a.ScanCapacity() != 20 {
		t.Fatal("capacity does not follow profile", a.ScanCapacity())
	}
	for i := 0; i < 21; i++ {
		if _, err := a.insertJob(Snapshot{Profile: p, Source: Mount{ID: "source"}, Key: fmt.Sprint(i), ETag: "v1"}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		if _, _, _, err := a.claim(); err != nil {
			t.Fatalf("only admitted %d of 20: %v", i, err)
		}
	}
	if _, _, _, err := a.claim(); err == nil {
		t.Fatal("exceeded configured 20")
	}
	p.SimultaneousScans = 4
	_ = a.Save("profiles", p.ID, p)
	if a.ScanCapacity() != 4 {
		t.Fatal("lower capacity not applied")
	}
	if _, _, _, err := a.claim(); err == nil {
		t.Fatal("lowering admitted while old work active")
	}
	second := Profile{ID: "second", SimultaneousScans: 12}
	_ = a.Save("profiles", second.ID, second)
	if a.ScanCapacity() != 16 {
		t.Fatal("profiles share an implicit cap", a.ScanCapacity())
	}
}

func TestWorkerPoolGrowsLiveBeyondEight(t *testing.T) {
	a := testApp(t)
	p := Profile{ID: "p", SimultaneousScans: 2}
	_ = a.Save("profiles", p.ID, p)
	ctx, cancel := context.WithCancel(context.Background())
	a.wg.Add(1)
	go func() { defer a.wg.Done(); a.manageScanWorkers(ctx) }()
	defer func() { cancel(); a.wg.Wait() }()
	count := func() int {
		a.healthMu.Lock()
		defer a.healthMu.Unlock()
		n := 0
		for name := range a.heartbeats {
			if strings.HasPrefix(name, "worker-") {
				n++
			}
		}
		return n
	}
	wait := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if count() == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("workers=%d want=%d", count(), want)
	}
	wait(2)
	p.SimultaneousScans = 20
	_ = a.Save("profiles", p.ID, p)
	wait(20)
	p.SimultaneousScans = 3
	_ = a.Save("profiles", p.ID, p)
	wait(3)
}

func TestThirtyTwoScanCallsOverlap(t *testing.T) {
	a, s, stores := reliabilityFixture(t)
	s.Profile.SimultaneousScans = 32
	_ = a.Save("profiles", s.Profile.ID, s.Profile)
	a.transferEnabled = true
	for i := 0; i < 32; i++ {
		s.Key = fmt.Sprintf("parallel-%d", i)
		if e := os.WriteFile(stores["source"].p(s.Key), []byte("123456789"), 0600); e != nil {
			t.Fatal(e)
		}
		info, _ := stores["source"].Stat(s.Key)
		s.ETag = infoTag(info)
		if _, e := a.insertJob(s); e != nil {
			t.Fatal(e)
		}
	}
	entered := make(chan struct{}, 32)
	release := make(chan struct{})
	a.scanFn = func(ctx context.Context, _ string, _ Scanner, _ Profile) ([]byte, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return []byte(`{"scanId":"parallel","scanResult":0}`), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.wg.Add(1)
	go func() { defer a.wg.Done(); a.manageScanWorkers(ctx) }()
	defer func() { cancel(); a.wg.Wait() }()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for i := 0; i < 32; i++ {
		select {
		case <-entered:
		case <-timer.C:
			close(release)
			t.Fatalf("only %d simultaneous calls entered", i)
		}
	}
	close(release)
}
