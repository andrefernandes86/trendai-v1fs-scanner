package localapp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestVisionOneTagsAreDistinctFromStorageLabels(t *testing.T) {
	p := Profile{ID: "policy", Name: "Deloitte Demo", VisionOneTags: "team:finance, environment:production\nowner:operations", ScannedTags: "storage=only"}
	tags, err := p.SDKTags()
	if err != nil || !reflect.DeepEqual(tags, []string{"app:trendai-v1fs", "profile:Deloitte Demo", "team:finance", "environment:production", "owner:operations"}) {
		t.Fatal(tags, err)
	}
	labels, err := routingTags(p, "CLEAN")
	if err != nil {
		t.Fatal(err)
	}
	if labels["storage"] != "only" || labels["team"] != "" {
		t.Fatal(labels)
	}
	p.VisionOneTags = strings.Repeat("x,", 7)
	if _, err = p.SDKTags(); err == nil {
		t.Fatal("accepted >8 total tags")
	}
	p.VisionOneTags = strings.Repeat("x", 64)
	if _, err = p.SDKTags(); err == nil {
		t.Fatal("accepted 64-byte tag")
	}
	p.VisionOneTags = strings.Repeat("é", 32)
	if _, err = p.SDKTags(); err == nil {
		t.Fatal("accepted multibyte overflow")
	}
	p.VisionOneTags = strings.Repeat("x", 63)
	if _, err = p.SDKTags(); err != nil {
		t.Fatal(err)
	}
	p.VisionOneTags = "a,b,c,d,e,f"
	if _, err = p.SDKTags(); err != nil {
		t.Fatal(err)
	}
}
func TestLiveVisionOneCustomTags(t *testing.T) {
	data := os.Getenv("V1FS_LIVE_TAGS_DATA_DIR")
	if data == "" {
		t.Skip("explicit opt-in cloud SDK check")
	}
	a, err := OpenReadOnly(data)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var s Scanner
	if err = a.Get("scanner", "default", &s); err != nil {
		t.Fatal(err)
	}
	p := Profile{ID: "tag-validation", Verbose: true, Digest: true, VisionOneTags: "purpose:tag-validation\nenvironment:test"}
	file := filepath.Join(t.TempDir(), "benign.txt")
	os.WriteFile(file, []byte("Benign Vision One custom tag validation.\n"), 0600)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := a.ScanDirect(ctx, file, s, p)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Tags []string `json:"tags"`
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	want, _ := p.SDKTags()
	if !reflect.DeepEqual(result.Tags, want) {
		t.Fatal("SDK did not return all configured tags", result.Tags)
	}
	t.Log("SDK returned both automatic tags and both custom tags")
}

func TestVisionOneProfileNameTagLimit(t *testing.T) {
	p := Profile{ID: "internal-id", Name: strings.Repeat("n", 55)}
	tags, err := p.SDKTags()
	if err != nil || tags[1] != "profile:"+p.Name {
		t.Fatal(tags, err)
	}
	p.Name += "n"
	if _, err := p.SDKTags(); err == nil {
		t.Fatal("accepted oversized profile name tag")
	}
}
