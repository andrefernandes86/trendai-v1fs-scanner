// Stress exercises the real source scheduler. It reads configuration without opening App
// or changing production settings. Sample bytes stay in the private work directory.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/localapp"
	_ "modernc.org/sqlite"
)

type Sample struct {
	Name    string `json:"name"`
	Verdict string `json:"verdict"`
	Digest  string `json:"sha256"`
	Data    []byte `json:"-"`
}
type Upload struct {
	Key      string    `json:"key"`
	Sample   string    `json:"sample"`
	Expected string    `json:"originalVerdict"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Error    string    `json:"error,omitempty"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	data := flag.String("data", "", "Existing production data directory (read only)")
	out := flag.String("out", "", "Private work directory")
	profile := flag.String("profile", "", "Enabled source profile ID")
	count := flag.Int("count", 1000, "Uploads per scenario")
	checkPrefix := flag.String("check-prefix", "", "Read-only source listing for a completed test prefix; no uploads")
	waitPrefix := flag.String("wait-prefix", "", "Wait for an earlier 1000-file scenario to drain before uploading")
	archives := flag.Bool("archives", false, "Supplementary real ZIP archive test using each verified sample")
	scenarioOnly := flag.String("scenario", "", "Run only burst or paced (default both)")
	execute := flag.Bool("execute", false, "Actually upload and await scheduled routing")
	flag.Parse()
	if *data == "" || *out == "" || *profile == "" {
		return fmt.Errorf("data, out and profile are required")
	}
	if e := os.MkdirAll(*out, 0700); e != nil {
		return e
	}
	key, e := os.ReadFile(filepath.Join(*data, "master.key"))
	if e != nil {
		return e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	unseal := func(b []byte, v any) error {
		n := aead.NonceSize()
		if len(b) < n {
			return fmt.Errorf("short encrypted record")
		}
		p, e := aead.Open(nil, b[:n], b[n:], nil)
		if e != nil {
			return e
		}
		return json.Unmarshal(p, v)
	}
	db, e := sql.Open("sqlite", "file:"+filepath.Join(*data, "scanner.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if e != nil {
		return e
	}
	defer db.Close()
	get := func(kind, id string, v any) error {
		var b []byte
		if e := db.QueryRow("SELECT value FROM config WHERE kind=? AND id=?", kind, id).Scan(&b); e != nil {
			return e
		}
		return unseal(b, v)
	}
	var p localapp.Profile
	if e = get("profiles", *profile, &p); e != nil {
		return e
	}
	if !p.Enabled || len(p.Rules) > 0 || p.IgnorePatterns != "" {
		return fmt.Errorf("profile must be enabled without bypass/ignore rules for this test")
	}
	var source localapp.Mount
	if e = get("mounts", p.SourceMount, &source); e != nil {
		return e
	}
	if source.Type() != "blob" {
		return fmt.Errorf("stress runner currently supports Blob sources")
	}
	client, e := source.ContainerClient()
	if e != nil {
		return e
	}
	if *checkPrefix != "" {
		marker := ""
		remaining := 0
		for {
			entries, next, err := localapp.ListBlobs(context.Background(), source, strings.TrimPrefix(*checkPrefix, source.Prefix), marker)
			if err != nil {
				return err
			}
			remaining += len(entries)
			if next == "" {
				break
			}
			marker = next
		}
		report := map[string]any{"prefix": *checkPrefix, "remainingSourceFiles": remaining, "checkedAt": time.Now().UTC()}
		payload, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(filepath.Join(*out, "source-check.json"), payload, 0600); err != nil {
			return err
		}
		fmt.Println(string(payload))
		return nil
	}
	rows, e := db.Query("SELECT key,verdict,digest,destination,snapshot FROM jobs WHERE state IN ('COMPLETED','QUARANTINED') AND verdict IN ('CLEAN','MALICIOUS') AND updated_at>=? ORDER BY updated_at DESC", time.Now().Add(-24*time.Hour).Format(time.RFC3339Nano))
	if e != nil {
		return e
	}
	type candidate struct {
		name, verdict, digest, destination string
		snapshot                           []byte
	}
	var candidates []candidate
	seen := map[string]bool{}
	for rows.Next() {
		var c candidate
		if e = rows.Scan(&c.name, &c.verdict, &c.digest, &c.destination, &c.snapshot); e != nil {
			return e
		}
		if seen[c.name] || strings.Contains(c.name, "/") || strings.Contains(c.name, "verification-") {
			continue
		}
		seen[c.name] = true
		candidates = append(candidates, c)
	}
	rows.Close()
	var samples []Sample
	ctx := context.Background()
	for _, c := range candidates {
		var s localapp.Snapshot
		if e = unseal(c.snapshot, &s); e != nil {
			return e
		}
		m := s.Good
		if c.verdict == "MALICIOUS" {
			m = s.Bad
		}
		if !strings.HasPrefix(c.destination, m.BaseURL()+"/") {
			return fmt.Errorf("sample destination mismatch")
		}
		s.Source = m
		s.Key = strings.TrimPrefix(c.destination, m.BaseURL()+"/")
		s.Version = ""
		s.ClaimedKey = ""
		s.ClaimedETag = ""
		b, e := m.BlobClient(s.Key, "")
		if e != nil {
			return e
		}
		props, e := b.GetProperties(ctx, nil)
		if e != nil {
			return fmt.Errorf("sample properties %q: %w", c.name, e)
		}
		s.ETag = string(*props.ETag)
		s.Size = *props.ContentLength
		path, digest, e := localapp.Download(ctx, s, *out)
		if e != nil {
			return fmt.Errorf("sample download %q: %w", c.name, e)
		}
		if digest != c.digest {
			return fmt.Errorf("sample checksum mismatch %q", c.name)
		}
		bytes, e := os.ReadFile(path)
		os.Remove(path)
		if e != nil {
			return e
		}
		samples = append(samples, Sample{c.name, c.verdict, digest, bytes})
	}
	if len(samples) == 0 {
		return fmt.Errorf("no verified user samples")
	}
	manifest, _ := json.MarshalIndent(samples, "", "  ")
	if e = os.WriteFile(filepath.Join(*out, "manifest.json"), manifest, 0600); e != nil {
		return e
	}
	fmt.Printf("Prepared %d checksum-verified samples; profile interval %ds; renamed bytes are not format conversions.\n", len(samples), p.ScanIntervalSeconds)
	if !*execute {
		return nil
	}
	if *archives {
		for i := range samples {
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			entry, err := zw.Create(samples[i].Name)
			if err != nil {
				return err
			}
			if _, err = entry.Write(samples[i].Data); err != nil {
				return err
			}
			if err = zw.Close(); err != nil {
				return err
			}
			samples[i].Data = buf.Bytes()
			samples[i].Name += ".zip"
			digest := sha256.Sum256(samples[i].Data)
			samples[i].Digest = hex.EncodeToString(digest[:])
		}
		*count = len(samples)
		*scenarioOnly = "burst"
	}
	if *waitPrefix != "" {
		for {
			var total, pending int
			if err := db.QueryRow("SELECT count(*),coalesce(sum(CASE WHEN state NOT IN ('COMPLETED','QUARANTINED','HELD','RECOVERED') THEN 1 ELSE 0 END),0) FROM jobs WHERE key LIKE ?", *waitPrefix+"/%").Scan(&total, &pending); err != nil {
				return err
			}
			fmt.Printf("Prior scenario: %d jobs, %d pending\n", total, pending)
			if total >= 1000 && pending == 0 {
				break
			}
			time.Sleep(15 * time.Second)
		}
	}
	extensions := []string{".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".png", ".jpg", ".html", ".zip", ".doc"}
	if *archives {
		extensions = []string{".zip"}
	}
	runID := time.Now().UTC().Format("20060102T150405Z")
	for _, scenario := range []string{"burst", "paced"} {
		if *scenarioOnly != "" && scenario != *scenarioOnly {
			continue
		}
		prefix := strings.Trim(strings.Join([]string{source.Prefix, p.Prefix, "loadtests", runID, scenario}, "/"), "/")
		prefix = strings.ReplaceAll(prefix, "//", "/")
		uploads := make([]Upload, *count)
		var wg sync.WaitGroup
		barrier := make(chan struct{})
		scenarioStart := time.Now()
		for i := 0; i < *count; i++ {
			if scenario == "paced" && i%100 == 0 {
				target := scenarioStart.Add(time.Duration(i/100) * time.Second)
				time.Sleep(time.Until(target))
			}
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if scenario == "burst" {
					<-barrier
				}
				sample := samples[i%len(samples)]
				stem := strings.TrimSuffix(sample.Name, filepath.Ext(sample.Name))
				name := fmt.Sprintf("%s/%06d_%s%s", prefix, i, stem, extensions[i%len(extensions)])
				u := Upload{Key: name, Sample: sample.Name, Expected: sample.Verdict, Started: time.Now().UTC()}
				_, err := client.NewBlockBlobClient(name).UploadBuffer(ctx, sample.Data, nil)
				u.Finished = time.Now().UTC()
				if err != nil {
					u.Error = err.Error()
				}
				uploads[i] = u
			}(i)
		}
		close(barrier)
		wg.Wait()
		encoded, _ := json.MarshalIndent(uploads, "", "  ")
		if e = os.WriteFile(filepath.Join(*out, scenario+"-uploads.json"), encoded, 0600); e != nil {
			return e
		}
		fmt.Printf("%s uploaded in %s; awaiting scheduler\n", scenario, time.Since(scenarioStart).Round(time.Millisecond))
		deadline := time.Now().Add(90 * time.Minute)
		for {
			var terminal, total int
			if e = db.QueryRow("SELECT count(*),coalesce(sum(CASE WHEN state IN ('COMPLETED','QUARANTINED','HELD','RECOVERED') THEN 1 ELSE 0 END),0) FROM jobs WHERE profile_id=? AND key LIKE ?", p.ID, prefix+"/%").Scan(&total, &terminal); e != nil {
				return e
			}
			success := 0
			for _, u := range uploads {
				if u.Error == "" {
					success++
				}
			}
			fmt.Printf("%s jobs=%d terminal=%d uploaded=%d elapsed=%s\n", scenario, total, terminal, success, time.Since(scenarioStart).Round(time.Second))
			if terminal >= success {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("scenario deadline reached; pending jobs retained")
			}
			time.Sleep(15 * time.Second)
		}
	}
	return nil
}
