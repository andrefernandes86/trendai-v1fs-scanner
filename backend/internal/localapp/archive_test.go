package localapp

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
)

func zipFixture(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	f, e := z.Create(name)
	if e != nil {
		t.Fatal(e)
	}
	f.Write(data)
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func unpackFixture(t *testing.T, data []byte, name string, o ArchiveOptions) ExtractManifest {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "source")
	if e := os.WriteFile(file, data, 0600); e != nil {
		t.Fatal(e)
	}
	workspace := filepath.Join(dir, "out")
	os.Mkdir(workspace, 0700)
	return ExtractArchive(context.Background(), ExtractRequest{Source: file, Name: name, Workspace: workspace, Options: o})
}
func TestArchiveDepthTwentyAndTwentyOne(t *testing.T) {
	data := []byte("benign")
	for n := 1; n <= 21; n++ {
		data = zipFixture(t, "nested.zip", data)
		if n == 1 { // first member is plaintext despite extension; use real leaf
			data = zipFixture(t, "leaf.txt", []byte("benign"))
		}
		if n >= 20 {
			m := unpackFixture(t, data, "outer.zip", ArchiveOptions{MaxDepth: 20, MaxFiles: 100})
			if n == 20 && !m.Complete {
				t.Fatal(m.Error)
			}
			if n == 21 && (m.Complete || !strings.Contains(m.Error, "depth")) {
				t.Fatal(m)
			}
		}
	}
}
func TestArchiveBombAndPathLimits(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "C:/escape", "safe/../../escape", "safe\\escape"} {
		m := unpackFixture(t, zipFixture(t, name, []byte("x")), "root.zip", ArchiveOptions{})
		if m.Complete || !strings.Contains(m.Error, "path") {
			t.Fatal(name, m)
		}
	}
	bomb := zipFixture(t, "large.txt", bytes.Repeat([]byte("0"), 2<<20))
	for _, o := range []ArchiveOptions{{MaxRatio: 2}, {MaxEntryBytes: 1024}, {MaxBytes: 1024, MaxEntryBytes: 1024}} {
		m := unpackFixture(t, bomb, "bomb.zip", o)
		if m.Complete {
			t.Fatal("bomb passed", o)
		}
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for i := 0; i < 3; i++ {
		f, _ := z.Create(string(rune('a' + i)))
		f.Write([]byte("x"))
	}
	z.Close()
	if m := unpackFixture(t, b.Bytes(), "many.zip", ArchiveOptions{MaxFiles: 2}); m.Complete {
		t.Fatal("count budget reset")
	}
	if m := unpackFixture(t, []byte("PK\x03\x04broken"), "broken.zip", ArchiveOptions{}); m.Complete {
		t.Fatal("corrupt ZIP accepted")
	}
	if m := unpackFixture(t, []byte("Rar!unavailable"), "data.rar", ArchiveOptions{}); m.Complete {
		t.Fatal("unsupported archive passed")
	}
}
func TestArchiveSymlinksAndEncryptedZipRejected(t *testing.T) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	h := &zip.FileHeader{Name: "link"}
	h.SetMode(os.ModeSymlink | 0777)
	f, _ := z.CreateHeader(h)
	f.Write([]byte("/etc/passwd"))
	z.Close()
	if m := unpackFixture(t, b.Bytes(), "link.zip", ArchiveOptions{}); m.Complete {
		t.Fatal("symlink accepted")
	}
	data := zipFixture(t, "a", []byte("safe"))
	central := bytes.Index(data, []byte("PK\x01\x02"))
	data[central+8] |= 1
	if m := unpackFixture(t, data, "encrypted.zip", ArchiveOptions{}); m.Complete || !strings.Contains(m.Error, "Encrypted") {
		t.Fatal(m)
	}
}
func TestArchiveTarGzipAndGlobalBudget(t *testing.T) {
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	tw.WriteHeader(&tar.Header{Name: "safe.txt", Size: 4, Mode: 0600})
	tw.Write([]byte("safe"))
	tw.Close()
	var gb bytes.Buffer
	gw := gzip.NewWriter(&gb)
	gw.Name = "inner.tar"
	gw.Write(tb.Bytes())
	gw.Close()
	m := unpackFixture(t, gb.Bytes(), "sample.tgz", ArchiveOptions{})
	if !m.Complete || m.Depth != 2 || len(m.Entries) != 2 {
		t.Fatal(m)
	}
	m = unpackFixture(t, gb.Bytes(), "sample.tgz", ArchiveOptions{MaxDepth: 1})
	if m.Complete {
		t.Fatal("gzip/tar depth was not counted")
	}
	m = unpackFixture(t, gb.Bytes(), "sample.tgz", ArchiveOptions{MaxBytes: int64(tb.Len() + 2), MaxEntryBytes: int64(tb.Len() + 2)})
	if m.Complete {
		t.Fatal("nested size budgets reset")
	}
	corrupt := append(gb.Bytes(), []byte("trailing")...)
	if m := unpackFixture(t, corrupt, "bad.gz", ArchiveOptions{}); m.Complete {
		t.Fatal("trailing gzip ignored")
	}
	var links bytes.Buffer
	tr := tar.NewWriter(&links)
	tr.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"})
	tr.Close()
	if m := unpackFixture(t, links.Bytes(), "link.tar", ArchiveOptions{}); m.Complete {
		t.Fatal("hard link accepted")
	}
}
func TestArchiveAggregateNeverHidesFailure(t *testing.T) {
	a := testApp(t)
	old := extractArchiveProcess
	extractArchiveProcess = ExtractArchive
	t.Cleanup(func() { extractArchiveProcess = old })
	local := filepath.Join(t.TempDir(), "root")
	os.WriteFile(local, zipFixture(t, "member.txt", []byte("payload")), 0600)
	p := Profile{ID: "archive", Archive: ArchiveOptions{Enabled: true}}
	for _, outcome := range []string{"CLEAN", "UNKNOWN", "MALICIOUS"} {
		calls := 0
		a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
			calls++
			if calls == 2 && outcome == "UNKNOWN" {
				return []byte("{\"scanId\":\"x\",\"scanResult\":-1}"), nil
			}
			if calls == 2 && outcome == "MALICIOUS" {
				return []byte("{\"scanId\":\"x\",\"foundMalwares\":[{\"name\":\"EICAR\"}],\"scanResult\":1}"), nil
			}
			return []byte("{\"scanId\":\"x\",\"scanResult\":0}"), nil
		}
		raw, e := a.scanWithArchives(context.Background(), local, "root.zip", Scanner{}, p, "digest")
		if e != nil {
			t.Fatal(e)
		}
		if core.Normalize(raw) != outcome || calls != 2 {
			t.Fatal(string(raw), calls)
		}
		var v map[string]any
		json.Unmarshal(raw, &v)
		if v["archiveInspection"] == nil {
			t.Fatal("missing archive evidence")
		}
		if outcome == "MALICIOUS" {
			d := extractDetections(raw)
			if len(d) != 1 || d[0].File != "root.zip!/member.txt" {
				t.Fatal(d)
			}
		}
	}
	p.Archive.MaxFiles = 1
	os.WriteFile(local, zipFixture(t, "../escape", []byte("x")), 0600)
	a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
		t.Fatal("blocked archive invoked SDK")
		return nil, nil
	}
	raw, e := a.scanWithArchives(context.Background(), local, "root.zip", Scanner{}, p, "digest")
	if e != nil || core.Normalize(raw) != "UNKNOWN" || scanException(raw) != "permanent" {
		t.Fatal(string(raw), e)
	}
	if p.Archive.MaxDepth = 21; p.Archive.Validate() == nil {
		t.Fatal("accepted depth 21")
	}
}

func TestArchiveRoutesOriginalAndBlockedNeverCountsAsScanned(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "malicious", true: "blocked"}[blocked], func(t *testing.T) {
			a, s, stores := reliabilityFixture(t)
			old := extractArchiveProcess
			extractArchiveProcess = ExtractArchive
			t.Cleanup(func() { extractArchiveProcess = old })
			name := "malware.txt"
			if blocked {
				name = "../escape"
			}
			original := zipFixture(t, name, []byte("test payload"))
			s.Key = "bundle.zip"
			s.Size = int64(len(original))
			s.Profile.Archive = ArchiveOptions{Enabled: true}
			os.WriteFile(stores["source"].p(s.Key), original, 0600)
			v, _ := stores["source"].Stat(s.Key)
			s.ETag = infoTag(v)
			calls := 0
			a.scanFn = func(context.Context, string, Scanner, Profile) ([]byte, error) {
				calls++
				if blocked {
					t.Fatal("blocked archive scanned")
				}
				if calls == 1 {
					return []byte("{\"scanId\":\"root\",\"scanResult\":0}"), nil
				}
				return []byte("{\"scanId\":\"member\",\"foundMalwares\":[{\"name\":\"EICAR\"}],\"scanResult\":1}"), nil
			}
			id, e := a.insertJob(s)
			if e != nil {
				t.Fatal(e)
			}
			_, snap, n, e := a.claim()
			if e != nil {
				t.Fatal(e)
			}
			a.process(context.Background(), id, snap, n)
			move, e := a.loadMove(id)
			if e != nil || move.Phase != "COMPLETED" {
				t.Fatal(move, e)
			}
			stored, e := os.ReadFile(stores[move.Target.ID].p(move.Key))
			if e != nil || !bytes.Equal(stored, original) {
				t.Fatal("original archive altered")
			}
			want := "MALICIOUS"
			if blocked {
				want = "UNKNOWN"
			}
			if move.Verdict != want {
				t.Fatal(move.Verdict)
			}
			var scans int
			a.DB.QueryRow("SELECT count(*) FROM scan_results WHERE job_id=?", id).Scan(&scans)
			if blocked && scans != 0 {
				t.Fatal("blocked extraction counted as scanned")
			}
			jobs, e := a.Jobs()
			if e != nil || len(jobs) != 1 || jobs[0].ArchiveInspection == nil {
				t.Fatal("missing compact archive evidence", e)
			}
			var compact []byte
			a.DB.QueryRow("SELECT payload FROM scan_summaries WHERE job_id=?", id).Scan(&compact)
			var d ScanDetails
			if e = a.Unseal(compact, &d); e != nil || len(d.Response) != 0 {
				t.Fatal("bulk summary includes full SDK evidence", e)
			}
		})
	}
}

func TestArchiveEntrySettings(t *testing.T) {
	if got := (ArchiveOptions{}).Defaults().MaxFiles; got != 10 {
		t.Fatalf("default entries = %d", got)
	}
	for _, n := range []int{10, 100} {
		if err := (ArchiveOptions{MaxFiles: n}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
