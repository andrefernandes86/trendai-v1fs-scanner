// Runtimecheck prepares an isolated real-storage validation instance. No production configuration is changed.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/localapp"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	from := flag.String("from", "", "Read-only production data")
	to := flag.String("to", "", "Isolated test data")
	profile := flag.String("profile", "", "Production profile ID")
	cleanupContainer := flag.String("cleanup-container", "", "Explicit empty temporary container to remove")
	mode := flag.String("mode", "prepare", "prepare/upload/cleanup/purge-test-inputs")
	flag.Parse()
	ctx := context.Background()
	if *from == "" || *to == "" || *profile == "" || filepath.Clean(*from) == filepath.Clean(*to) {
		return fmt.Errorf("distinct from/to data directories and profile required")
	}
	if *mode == "prepare" {
		if _, e := os.Stat(filepath.Join(*to, "scanner.db")); e == nil {
			return fmt.Errorf("test database already exists")
		}
		key, e := os.ReadFile(filepath.Join(*from, "master.key"))
		if e != nil {
			return e
		}
		b, e := aes.NewCipher(key)
		if e != nil {
			return e
		}
		ae, e := cipher.NewGCM(b)
		if e != nil {
			return e
		}
		db, e := sql.Open("sqlite", "file:"+filepath.Join(*from, "scanner.db")+"?mode=ro")
		if e != nil {
			return e
		}
		defer db.Close()
		get := func(kind, id string, v any) error {
			var encrypted []byte
			if e := db.QueryRow("SELECT value FROM config WHERE kind=? AND id=?", kind, id).Scan(&encrypted); e != nil {
				return e
			}
			n := ae.NonceSize()
			if len(encrypted) < n {
				return fmt.Errorf("invalid record")
			}
			plain, e := ae.Open(nil, encrypted[:n], encrypted[n:], nil)
			if e != nil {
				return e
			}
			return json.Unmarshal(plain, v)
		}
		var p localapp.Profile
		if e = get("profiles", *profile, &p); e != nil {
			return e
		}
		var scanner localapp.Scanner
		if e = get("scanner", "default", &scanner); e != nil {
			return e
		}
		var mounts []localapp.Mount
		for _, id := range []string{p.SourceMount, p.GoodMount, p.BadMount, p.FailedMount} {
			var m localapp.Mount
			if e = get("mounts", id, &m); e != nil {
				return e
			}
			mounts = append(mounts, m)
		}
		if mounts[0].Type() != "blob" {
			return fmt.Errorf("requires Blob source")
		}
		mounts[0].Container = "v1fs-check-" + time.Now().UTC().Format("20060102t150405")
		mounts[0].Prefix = ""
		client, e := mounts[0].ContainerClient()
		if e != nil {
			return e
		}
		if _, e = client.Create(ctx, nil); e != nil {
			return fmt.Errorf("cannot create isolated source container: %w", e)
		}
		fmt.Println("Created isolated source container:", mounts[0].Container)
		a, e := localapp.Open(*to, "")
		if e != nil {
			return e
		}
		defer a.Close()
		for _, m := range mounts {
			if e = a.Save("mounts", m.ID, m); e != nil {
				return e
			}
		}
		if e = a.Save("scanner", "default", scanner); e != nil {
			return e
		}
		p.ID = "runtimecheck"
		p.Name = "Runtime isolation validation"
		p.Prefix = ""
		p.GoodPrefix = "runtimecheck/" + mounts[0].Container + "/"
		p.BadPrefix = p.GoodPrefix
		p.FailedPrefix = p.GoodPrefix
		p.Rules = nil
		p.IgnorePatterns = ""
		p.Enabled = true
		p.SimultaneousScans = 1
		p.ScanIntervalSeconds = 10
		p.QuietSeconds = 10
		p.RecoveryEnabled = false
		if e = a.Save("profiles", p.ID, p); e != nil {
			return e
		}
		// Synthetic historical rows exercise the real indexed history page during live scanning.
		tx, e := a.DB.Begin()
		if e != nil {
			return e
		}
		defer tx.Rollback()
		for i := 0; i < 2000; i++ {
			if _, e = tx.Exec("INSERT INTO jobs(id,key,profile_id,profile_name,source_id,etag,version,size,state,verdict,created_at,updated_at,available_at,snapshot) VALUES(?,?, 'history','Synthetic history','history','one','',0,'COMPLETED','CLEAN',?,?,0,X'')", fmt.Sprintf("history-%d", i), fmt.Sprintf("history-%d.txt", i), "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z"); e != nil {
				return e
			}
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		fmt.Println("Prepared isolated test source:", mounts[0].Container)
		return nil
	}
	// Non-owning read connection: never Open an active API/engine data directory.
	key, e := os.ReadFile(filepath.Join(*to, "master.key"))
	if e != nil {
		return e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	ae, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	db, e := sql.Open("sqlite", "file:"+filepath.Join(*to, "scanner.db")+"?mode=ro")
	if e != nil {
		return e
	}
	defer db.Close()
	var encrypted []byte
	var p localapp.Profile
	decode := func(b []byte, v any) error {
		n := ae.NonceSize()
		if len(b) < n {
			return fmt.Errorf("invalid record")
		}
		plain, e := ae.Open(nil, b[:n], b[n:], nil)
		if e != nil {
			return e
		}
		return json.Unmarshal(plain, v)
	}
	if e = db.QueryRow("SELECT value FROM config WHERE kind='profiles' AND id='runtimecheck'").Scan(&encrypted); e != nil {
		return e
	}
	if e = decode(encrypted, &p); e != nil {
		return e
	}
	var source localapp.Mount
	if e = db.QueryRow("SELECT value FROM config WHERE kind='mounts' AND id=?", p.SourceMount).Scan(&encrypted); e != nil {
		return e
	}
	if e = decode(encrypted, &source); e != nil {
		return e
	}
	if (*mode == "cleanup" || *mode == "purge-test-inputs") && *cleanupContainer != "" {
		source.Container = *cleanupContainer
	}
	if !strings.HasPrefix(source.Container, "v1fs-check-") {
		return fmt.Errorf("refusing non-test source")
	}
	client, e := source.ContainerClient()
	if e != nil {
		return e
	}
	if *mode == "purge-test-inputs" {
		if *cleanupContainer == "" {
			return fmt.Errorf("explicit temporary container required")
		}
		entries, next, err := localapp.ListBlobs(ctx, source, "", "")
		if err != nil {
			return err
		}
		if next != "" {
			return fmt.Errorf("unexpected large test container")
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Key, "runtime-") || !strings.HasSuffix(entry.Key, ".txt") {
				return fmt.Errorf("refusing unexpected content")
			}
		}
		for _, entry := range entries {
			if _, err = client.NewBlobClient(entry.Key).Delete(ctx, nil); err != nil {
				return err
			}
		}
		_, err = client.Delete(ctx, nil)
		return err
	}
	if *mode == "cleanup" {
		entries, _, err := localapp.ListBlobs(ctx, source, "", "")
		if err != nil {
			return err
		}
		if len(entries) > 0 {
			return fmt.Errorf("source not empty; retained for investigation")
		}
		_, err = client.Delete(ctx, nil)
		return err
	}
	if *mode != "upload" {
		return fmt.Errorf("unknown mode")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 144)
	for i := 0; i < 144; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := []byte(strings.Repeat("Benign document for runtime isolation validation.\n", 2048))
			if i%3 == 0 {
				data = []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
			}
			_, e := client.NewBlockBlobClient(fmt.Sprintf("runtime-%03d.txt", i)).UploadBuffer(ctx, data, nil)
			if e != nil {
				errs <- e
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		return e
	}
	fmt.Println("Uploaded 144 test files (96 benign, 48 EICAR)")
	return nil
}
