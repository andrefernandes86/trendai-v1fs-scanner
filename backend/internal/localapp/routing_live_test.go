package localapp

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in creates two private, disposable containers, uses only generated
// safe/EICAR bytes, and removes those containers. Production files/config stay untouched.
func TestRoutingLiveLeasedVerification(t *testing.T) {
	data, profile := os.Getenv("V1FS_LIVE_ROUTING_DATA_DIR"), os.Getenv("V1FS_LIVE_ROUTING_PROFILE_ID")
	if data == "" || profile == "" || archiveRaceBuild {
		t.Skip("explicit live routing configuration required")
	}
	saved, e := OpenReadOnly(data)
	if e != nil {
		t.Fatal(e)
	}
	defer saved.Close()
	var p Profile
	var scanner Scanner
	var source Mount
	if saved.Get("profiles", profile, &p) != nil || saved.Get("scanner", "default", &scanner) != nil || saved.Get("mounts", p.SourceMount, &source) != nil || source.Type() != "blob" {
		t.Fatal("live Blob configuration unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	suffix := time.Now().UTC().Format("20060102t150405")
	source.ID = "live-source"
	source.Container = "v1fs-check-source-" + suffix
	source.Prefix = ""
	source.ResourceID = ""
	target := source
	target.ID = "live-target"
	target.Container = "v1fs-check-target-" + suffix
	for _, m := range []Mount{source, target} {
		c, err := m.ContainerClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.Create(ctx, nil); err != nil {
			t.Fatal(err)
		}
		defer c.Delete(context.Background(), nil)
	}
	a := testApp(t)
	direct := &App{}
	a.scanFn = func(ctx context.Context, path string, s Scanner, p Profile) ([]byte, error) {
		return direct.ScanDirect(ctx, path, s, p)
	}
	for _, tc := range []struct{ name, content, want string }{{"safe.txt", "Benign transfer verification", "COMPLETED"}, {"eicar.com", eicarContent, "QUARANTINED"}} {
		c, _ := source.ContainerClient()
		if _, e = c.NewBlockBlobClient(tc.name).UploadBuffer(ctx, []byte(tc.content), nil); e != nil {
			t.Fatal(e)
		}
		b, _ := source.BlobClient(tc.name, "")
		props, e := b.GetProperties(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		s := Snapshot{Source: source, Good: target, Bad: target, Failed: target, Scanner: scanner, Profile: Profile{ID: "live-" + tc.name, ScanAttempts: 1}, Key: tc.name, Size: int64(len(tc.content)), ETag: string(*props.ETag)}
		id, e := a.insertJob(s)
		if e != nil {
			t.Fatal(e)
		}
		_, snap, n, e := a.claim()
		if e != nil {
			t.Fatal(e)
		}
		a.process(ctx, id, snap, n)
		var state, reason string
		a.DB.QueryRow("SELECT state,error FROM jobs WHERE id=?", id).Scan(&state, &reason)
		if state != tc.want {
			t.Fatalf("%s: state=%s reason=%s", tc.name, state, reason)
		}
		move, e := a.loadMove(id)
		if e != nil {
			t.Fatal(e)
		}
		dest, _ := target.BlobClient(move.Key, "")
		tags, e := dest.GetTags(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		tagData := []byte{}
		for _, item := range tags.BlobTagSet {
			tagData = append(tagData, []byte(*item.Key+"="+*item.Value+";")...)
		}
		if !bytes.Contains(tagData, []byte("scanned=true")) || !strings.Contains(move.VerifiedAt, "T") {
			t.Fatal("verification or tags missing")
		}
		if _, e = b.GetProperties(ctx, nil); e == nil {
			t.Fatal("source not deleted")
		}
		t.Logf("%s: %s; SHA-256/CRC32C verified, native scanned=true tag, source absent", tc.name, state)
	}
}
