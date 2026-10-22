package localapp

import (
	"context"
	"encoding/json"
	client "github.com/trendmicro/tm-v1-fs-golang-sdk"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScanIdentityUsesCapturedBytesAndOriginalKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-random")
	if err := os.WriteFile(path, []byte("captured bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := client.InitFileReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	original := "invoices/Original report.txt"
	named := namedScanReader{reader, original}
	if named.Identifier() != original {
		t.Fatal(named.Identifier())
	}
	data, err := named.ReadBytes(0, 8)
	if err != nil || string(data) != "captured" {
		t.Fatal(string(data), err)
	}
	size, err := named.DataSize()
	if err != nil || size != int64(len("captured bytes")) {
		t.Fatal(size, err)
	}
	ctx := WithScanIdentifier(context.Background(), original)
	wire, err := json.Marshal(ScanRequest{Path: path, Identifier: scanIdentifier(ctx, path)})
	if err != nil {
		t.Fatal(err)
	}
	var request ScanRequest
	if err = json.Unmarshal(wire, &request); err != nil {
		t.Fatal(err)
	}
	if scanIdentifier(WithScanIdentifier(context.Background(), request.Identifier), request.Path) != original {
		t.Fatal(request)
	}
	if scanIdentifier(context.Background(), path) != "scan-random" {
		t.Fatal("fallback exposed capture directory")
	}
}

func TestLiveOriginalFilename(t *testing.T) {
	data := os.Getenv("V1FS_LIVE_TAGS_DATA_DIR")
	if data == "" {
		t.Skip("explicit opt-in cloud SDK check")
	}
	a, err := OpenReadOnly(data)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var scanner Scanner
	if err = a.Get("scanner", "default", &scanner); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "scan-random")
	os.WriteFile(path, []byte("Benign original filename validation.\n"), 0600)
	original := "reports/original-filename-validation.txt"
	ctx, cancel := context.WithTimeout(WithScanIdentifier(context.Background(), original), 30*time.Second)
	defer cancel()
	raw, err := a.ScanDirect(ctx, path, scanner, Profile{ID: "filename-validation", Name: "Filename validation", Verbose: true, Digest: true})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		FileName string `json:"fileName"`
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.FileName != original {
		t.Fatalf("SDK reported %q instead of %q", result.FileName, original)
	}
	t.Logf("SDK confirmed original file name: %s", result.FileName)
}
