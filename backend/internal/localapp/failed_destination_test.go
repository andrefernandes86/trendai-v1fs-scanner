package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestUnknownVerdictRoutesOnlyToFailedDestination(t *testing.T) {
	a := testApp(t)
	fs := &diskShare{root: t.TempDir()}
	original := remoteOpen
	remoteOpen = func(_ context.Context, m Mount) (remoteFS, error) {
		if m.ID != "failed" {
			t.Fatalf("unexpected destination %s", m.ID)
		}
		return fs, nil
	}
	defer func() { remoteOpen = original }()
	content := []byte("unverified scan bytes")
	local := filepath.Join(t.TempDir(), "input.txt")
	if e := os.WriteFile(local, content, 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	s := Snapshot{Failed: Mount{ID: "failed", Kind: "smb", Server: "nas", Share: "failed"}, Profile: Profile{FailedPrefix: "review"}, Key: "input.txt", Size: int64(len(content))}
	a.routeScanFailure(context.Background(), "job", s, local, digest, "Unknown verdict")
	got, e := os.ReadFile(fs.p("review/input_job.txt"))
	if e != nil || string(got) != string(content) {
		t.Fatalf("copy %q %v", got, e)
	}
	if _, e := os.Stat(local); e != nil {
		t.Fatal("source removed")
	}
}
