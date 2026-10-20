package localapp

import (
	"context"
	"encoding/json"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in only: reads existing configuration, sends generated safe/EICAR ZIPs
// to the configured service, and never writes production DB/storage objects.
func TestArchiveLiveSDK(t *testing.T) {
	data, profile, helper := os.Getenv("V1FS_LIVE_ARCHIVE_DATA_DIR"), os.Getenv("V1FS_LIVE_ARCHIVE_PROFILE_ID"), os.Getenv("V1FS_LIVE_ARCHIVE_HELPER")
	if data == "" || profile == "" || helper == "" {
		t.Skip("requires explicit live data/profile/helper environment")
	}
	if archiveRaceBuild {
		t.Skip("live helper uses non-race executable")
	}
	a, e := OpenReadOnly(data)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	var p Profile
	var s Scanner
	if e = a.Get("profiles", profile, &p); e != nil {
		t.Fatal(e)
	}
	if e = a.Get("scanner", "default", &s); e != nil {
		t.Fatal(e)
	}
	p.Archive = ArchiveOptions{Enabled: true, MaxDepth: 20}.Defaults()
	old := extractArchiveProcess
	extractArchiveProcess = func(ctx context.Context, r ExtractRequest) ExtractManifest {
		return launchArchiveHelperAt(ctx, r, helper)
	}
	defer func() { extractArchiveProcess = old }()
	direct := &App{}
	a.scanFn = func(ctx context.Context, path string, s Scanner, p Profile) ([]byte, error) {
		return direct.ScanDirect(ctx, path, s, p)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, tc := range []struct{ name, content, want string }{{"safe.txt", "Benign archive validation", "CLEAN"}, {"eicar.com", eicarContent, "MALICIOUS"}} {
		file := filepath.Join(t.TempDir(), "sample.zip")
		os.WriteFile(file, zipFixture(t, tc.name, []byte(tc.content)), 0600)
		digest, _, _, _ := checksums(file)
		raw, e := a.scanWithArchives(ctx, file, "validation.zip", s, p, digest)
		if e != nil {
			t.Fatal(e)
		}
		var v struct{ ArchiveInspection ArchiveEvidence }
		json.Unmarshal(raw, &v)
		actual := core.Normalize(raw)
		t.Logf("%s: verdict=%s extractionComplete=%v members=%d depth=%d", tc.name, actual, v.ArchiveInspection.ExtractionComplete, len(v.ArchiveInspection.Members), v.ArchiveInspection.Depth)
		if actual != tc.want || !v.ArchiveInspection.ExtractionComplete || len(v.ArchiveInspection.Members) != 2 {
			t.Fatal("live archive result did not match expected outcome; inspect configured scanner")
		}
	}
}
