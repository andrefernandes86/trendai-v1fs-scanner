package localapp

import (
	"context"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestDisabledLocalArchiveStillScansOriginalZIP(t *testing.T) {
	a := testApp(t)
	local := filepath.Join(t.TempDir(), "original.zip")
	if err := os.WriteFile(local, zipFixture(t, "eicar.com", []byte(eicarContent)), 0600); err != nil {
		t.Fatal(err)
	}
	original := Profile{ID: "profile", Archive: ArchiveOptions{Enabled: true, MaxFiles: 42}}
	p := applyFeatureAvailability(original)
	if p.Archive.Enabled || p.Archive.MaxFiles != 42 || !original.Archive.Enabled {
		t.Fatal("feature availability must disable extraction while retaining its settings")
	}
	calls := 0
	a.scanFn = func(ctx context.Context, file string, _ Scanner, policy Profile) ([]byte, error) {
		calls++
		if file != local || policy.Archive.Enabled || scanIdentifier(ctx, file) != "original.zip" {
			t.Fatal("SDK did not receive original archive with local extraction off")
		}
		return []byte(`{"scanId":"sdk","scanResult":1}`), nil
	}
	raw, err := a.scanWithArchives(context.Background(), local, "original.zip", Scanner{}, p, "")
	if err != nil || calls != 1 || core.Normalize(raw) != "MALICIOUS" {
		t.Fatal(calls, err)
	}
}
