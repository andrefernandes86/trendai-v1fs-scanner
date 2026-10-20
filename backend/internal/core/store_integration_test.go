package core

import (
	"context"
	"fmt"
	"github.com/andrefernandes86/trendai-v1fs-scanner/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"sync"
	"testing"
)

func TestDurableDuplicateBurst(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	if _, e = pool.Exec(ctx, migrations.SQL); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, "TRUNCATE audit,outbox,routing,jobs,observations,settings RESTART IDENTITY CASCADE"); e != nil {
		t.Fatal(e)
	}
	s := &Store{DB: pool}
	src := Source{ID: "s", Name: "source", Kind: "blob", Account: "account", Container: "uploads", Tenant: "t", ProfileID: "p", Enabled: true, Concurrency: 2, MaxBytes: 1024, Clean: "https://a.blob.core.windows.net/safe", Quarantine: "https://a.blob.core.windows.net/quarantine", Hold: "https://a.blob.core.windows.net/hold"}
	if e = s.Save(ctx, "sources", "s", "test", src); e != nil {
		t.Fatal(e)
	}
	if e = s.Save(ctx, "profiles", "p", "test", Profile{ID: "p", Name: "policy", Concurrency: 2}); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 2000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			j := Job{SourceID: "s", Tenant: "t", ProfileID: "p", Key: fmtKey(i % 1000), Version: "v1", ETag: "etag", Size: 1}
			if e := s.Discover(ctx, j); e != nil {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	var jobs, outbox int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM jobs").Scan(&jobs); e != nil {
		t.Fatal(e)
	}
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM outbox").Scan(&outbox); e != nil {
		t.Fatal(e)
	}
	if jobs != 1000 || outbox != 1000 {
		t.Fatalf("lost or duplicated jobs=%d outbox=%d", jobs, outbox)
	}
	j, e := s.Job(ctx, Identity("s", fmtKey(0), "v1", "etag"))
	if e != nil {
		t.Fatal(e)
	}
	stale := j
	if e = s.Move(ctx, &j, "SCANNING", "", 0); e != nil {
		t.Fatal(e)
	}
	if e = s.Move(ctx, &stale, "SCANNING", "", 0); e == nil {
		t.Fatal("stale transition accepted")
	}
	release, e := s.Permits(ctx, j, Capacity{Global: 1, Tenant: 1})
	if e != nil {
		t.Fatal(e)
	}
	if r, e := s.Permits(ctx, j, Capacity{Global: 1, Tenant: 1}); e == nil {
		r()
		t.Fatal("global concurrency exceeded")
	}
	release()
	release, e = s.Permits(ctx, j, Capacity{Global: 1, Tenant: 1})
	if e != nil {
		t.Fatal(e)
	}
	release()
}
func fmtKey(i int) string { return fmt.Sprintf("file-%04d.txt", i) }
