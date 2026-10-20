package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"os"
	"strings"
	"time"
)

func (a *App) ProfileSnapshot(id, key string) (Snapshot, error) {
	var s Snapshot
	if e := a.Get("profiles", id, &s.Profile); e != nil {
		return s, e
	}
	if e := a.Get("mounts", s.Profile.SourceMount, &s.Source); e != nil {
		return s, e
	}
	if e := a.Get("mounts", s.Profile.GoodMount, &s.Good); e != nil {
		return s, e
	}
	if e := a.Get("mounts", s.Profile.BadMount, &s.Bad); e != nil {
		return s, e
	}
	if s.Profile.FailedMount != "" {
		if e := a.Get("mounts", s.Profile.FailedMount, &s.Failed); e != nil {
			return s, e
		}
	}
	if e := a.Get("scanner", "default", &s.Scanner); e != nil {
		return s, errors.New("configure Vision One first")
	}
	if e := s.Scanner.Validate(); e != nil {
		return s, e
	}
	if !core.ValidKey(key) || !strings.HasPrefix(key, s.Source.Prefix+s.Profile.Prefix) {
		return s, errors.New("file is outside profile prefix")
	}
	s.Key = key
	return s, nil
}
func (a *App) Enqueue(ctx context.Context, id, key string) (string, error) {
	return a.enqueueExpected(ctx, id, key, "")
}
func (a *App) enqueueExpected(ctx context.Context, id, key, expected string) (string, error) {
	s, e := a.ProfileSnapshot(id, key)
	if e != nil {
		return "", e
	}
	if s.Source.Type() != "blob" {
		info, e := shareProperties(ctx, s.Source, key)
		if e != nil {
			return "", errors.New("cannot read share file; check connection, path and permissions")
		}
		s.ETag = info.ETag
		s.Size = info.Size
		if expected != "" && s.ETag != expected {
			return "", errors.New("file changed during discovery; waiting for stability")
		}
		if s.Profile.RequireMarker && !info.Complete {
			return "", errors.New("profile requires a fresh filename.complete sidecar after upload completion")
		}
		if s.Size > 2<<30 {
			return "", errors.New("file exceeds 2 GiB host policy")
		}
	} else {
		c, e := s.Source.BlobClient(key, "")
		if e != nil {
			return "", e
		}
		props, e := c.GetProperties(ctx, nil)
		if e != nil {
			return "", errors.New("cannot read blob properties; verify connection credentials and path")
		}
		if props.ETag == nil || props.ContentLength == nil {
			return "", errors.New("blob has no stable identity")
		}
		s.ETag = string(*props.ETag)
		if expected != "" && s.ETag != expected {
			return "", errors.New("source changed during discovery; waiting for stability")
		}
		s.Size = *props.ContentLength
		if s.Size > 2<<30 {
			return "", errors.New("file exceeds 2 GiB host policy")
		}
		if props.VersionID != nil {
			s.Version = *props.VersionID
		}
		if s.Profile.RequireMarker {
			if !completeMetadata(props.Metadata) {
				return "", errors.New("profile requires v1fs-complete=true metadata on completed uploads")
			}
		}
	}
	return a.insertJob(s)
}
func (a *App) insertJob(s Snapshot) (string, error) {
	encoded, _ := json.Marshal([]any{s.Profile.ID, s.Profile.Revision, s.Source.BaseURL(), s.Key, s.ETag, s.Version})
	if s.Source.Type() == "blob" {
		encoded, _ = json.Marshal([]any{s.Profile.ID, s.Profile.Revision, s.Source.Account, s.Source.Container, s.Key, s.ETag, s.Version})
	}
	h := sha256.Sum256(encoded)
	id := hex.EncodeToString(h[:])
	payload, e := a.Seal(s)
	if e != nil {
		return "", e
	}
	tx, e := a.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	r, e := tx.Exec("INSERT OR IGNORE INTO jobs(id,key,profile_id,profile_name,source_id,etag,version,size,state,created_at,updated_at,available_at,snapshot) VALUES(?,?,?,?,?,?,?,?,'QUEUED',?,?,?,?)", id, s.Key, s.Profile.ID, s.Profile.Name, s.Source.ID, s.ETag, s.Version, s.Size, stamp(), stamp(), time.Now().Unix(), payload)
	if e != nil {
		return "", e
	}
	n, _ := r.RowsAffected()
	if n > 0 {
		_, e = tx.Exec("INSERT INTO audit(at,action,object_id,detail) VALUES(?,?,?,?)", stamp(), "job.queued", id, s.Key)
		if e != nil {
			return "", e
		}
	}
	if e = tx.Commit(); e != nil {
		return "", e
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
	return id, nil
}
func (a *App) Jobs() ([]Job, error) {
	rows, e := a.DB.Query("SELECT id,key,profile_id,profile_name,source_id,etag,version,size,state,verdict,digest,destination,error,attempts,created_at,updated_at FROM jobs ORDER BY created_at DESC LIMIT 500")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		if e = rows.Scan(&j.ID, &j.Key, &j.ProfileID, &j.ProfileName, &j.SourceID, &j.ETag, &j.Version, &j.Size, &j.State, &j.Verdict, &j.Digest, &j.Destination, &j.Error, &j.Attempts, &j.CreatedAt, &j.UpdatedAt); e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (a *App) transition(id, state, verdict, digest, destination, message string, delay time.Duration) error {
	tx, e := a.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE jobs SET state=?,verdict=?,digest=?,destination=?,error=?,updated_at=?,available_at=? WHERE id=?", state, verdict, digest, destination, message, stamp(), time.Now().Add(delay).Unix(), id); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT INTO audit(at,action,object_id,detail) VALUES(?,?,?,?)", stamp(), "job."+strings.ToLower(state), id, message); e != nil {
		return e
	}
	return tx.Commit()
}
func (a *App) claim() (string, Snapshot, int, error) {
	var s Snapshot
	tx, e := a.DB.Begin()
	if e != nil {
		return "", s, 0, e
	}
	defer tx.Rollback()
	var id string
	var b []byte
	var attempts int
	e = tx.QueryRow("SELECT id,snapshot,attempts FROM jobs WHERE state IN ('QUEUED','RETRY_PENDING') AND available_at<=? ORDER BY created_at LIMIT 1", time.Now().Unix()).Scan(&id, &b, &attempts)
	if e != nil {
		return "", s, 0, e
	}
	if e = a.Unseal(b, &s); e != nil {
		return "", s, 0, e
	}
	r, e := tx.Exec("UPDATE jobs SET state='SCANNING',attempts=attempts+1,updated_at=? WHERE id=? AND state IN ('QUEUED','RETRY_PENDING')", stamp(), id)
	if e != nil {
		return "", s, 0, e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return "", s, 0, errors.New("claim conflict")
	}
	if _, e = tx.Exec("INSERT INTO audit(at,action,object_id,detail) VALUES(?,?,?,?)", stamp(), "job.scanning", id, ""); e != nil {
		return "", s, 0, e
	}
	if e = tx.Commit(); e != nil {
		return "", s, 0, e
	}
	return id, s, attempts + 1, nil
}
func (a *App) worker(ctx context.Context) {
	for ctx.Err() == nil {
		id, s, attempt, e := a.claim()
		if e != nil {
			select {
			case <-ctx.Done():
				return
			case <-a.wake:
			case <-time.After(2 * time.Second):
			}
			continue
		}
		a.process(ctx, id, s, attempt)
	}
}
func (a *App) process(parent context.Context, id string, s Snapshot, attempt int) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	verdict, verifiedDigest := "UNKNOWN", ""
	if e := a.DB.QueryRow("SELECT verdict,digest FROM jobs WHERE id=?", id).Scan(&verdict, &verifiedDigest); e != nil {
		return
	}
	fail := func(message string) {
		state := "RETRY_PENDING"
		if attempt >= 5 {
			state = "HELD"
		}
		_ = a.transition(id, state, verdict, verifiedDigest, "", message, time.Duration(1<<min(attempt, 8))*10*time.Second)
	}
	path, digest, e := Download(ctx, s, a.DataDir)
	if e != nil {
		fail("Source download failed or source identity changed. Check Azure credentials, permissions, and upload completion.")
		return
	}
	defer os.Remove(path)
	if verifiedDigest != "" && (verdict == "CLEAN" || verdict == "MALICIOUS") {
		if digest != verifiedDigest {
			_ = a.transition(id, "HELD", "UNKNOWN", digest, "", "Content differs from previously scanned bytes.", 0)
			return
		}
	} else {
		raw, scanErr := a.Scan(ctx, path, s.Scanner, s.Profile)
		if scanErr != nil {
			if attempt >= 5 {
				a.routeScanFailure(ctx, id, s, path, digest, "Scanner failed after retries. Manual review required.")
			} else {
				fail("Scanner request failed. Check the API key, cloud region or local address, TLS, and connectivity.")
			}
			return
		}
		verdict = core.Normalize(raw)
		if verdict != "CLEAN" && verdict != "MALICIOUS" {
			a.routeScanFailure(ctx, id, s, path, digest, "Scanner returned an unverified result. Manual review required.")
			return
		}
		verifiedDigest = digest
	}

	dest, prefix, state := s.Good, s.Profile.GoodPrefix, "COMPLETED"
	if verdict == "MALICIOUS" {
		dest, prefix, state = s.Bad, s.Profile.BadPrefix, "QUARANTINED"
	}
	name := strings.Trim(prefix, "/")
	if name != "" {
		name += "/"
	}
	name += id + "/" + s.Key
	fullKey := name
	if dest.Prefix != "" {
		fullKey = strings.Trim(dest.Prefix, "/") + "/" + name
	}
	if !core.ValidKey(fullKey) {
		_ = a.transition(id, "HELD", verdict, digest, "", "Invalid destination key.", 0)
		return
	}
	if e = a.transition(id, "ROUTING", verdict, digest, "", "", 0); e != nil {
		return
	}
	tags, e := s.Profile.ResultTags(verdict)
	if e != nil {
		fail(e.Error())
		return
	}
	if e = Route(ctx, dest, fullKey, path, digest, id, verdict, s.Size, tags); e != nil {
		fail("Destination copy or SHA-256 verification failed. Original file preserved.")
		return
	}
	if e = a.transition(id, state, verdict, digest, dest.BaseURL()+"/"+fullKey, "", 0); e == nil {
		a.cleanupTestFile(ctx, s, digest)
	}
}
func (a *App) monitor(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	lastRun := map[string]time.Time{}
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		profiles, e := a.List("profiles")
		if e != nil {
			continue
		}
		for _, raw := range profiles {
			var p Profile
			if json.Unmarshal(raw, &p) != nil || !p.Enabled {
				continue
			}
			if last, ok := lastRun[p.ID]; ok && time.Since(last) < p.Interval() {
				continue
			}
			lastRun[p.ID] = time.Now()
			var m Mount
			if a.Get("mounts", p.SourceMount, &m) != nil {
				continue
			}
			marker := ""
			for ctx.Err() == nil {
				cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				files, next, e := ListBlobs(cctx, m, p.Prefix, marker)
				cancel()
				if e != nil {
					a.Audit("monitor.error", p.ID, "Cannot list source; verify stored Azure credentials and permissions.")
					break
				}
				for _, f := range files {
					if p.RequireMarker && !f.Complete {
						continue
					}
					modified, e := time.Parse(time.RFC3339, f.Modified)
					if e != nil || time.Since(modified) < 60*time.Second {
						continue
					}
					var first int64
					e = a.DB.QueryRow("INSERT INTO observations(profile_id,key,etag,first_seen) VALUES(?,?,?,?) ON CONFLICT(profile_id,key) DO UPDATE SET first_seen=CASE WHEN observations.etag=excluded.etag THEN observations.first_seen ELSE excluded.first_seen END,etag=excluded.etag RETURNING first_seen", p.ID, f.Key, f.ETag, time.Now().Unix()).Scan(&first)
					if e != nil || time.Now().Unix()-first < 30 {
						continue
					}
					cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
					_, e = a.enqueueExpected(cctx, p.ID, f.Key, f.ETag)
					cancel()
					if e != nil {
						a.Audit("monitor.skipped", p.ID, fmt.Sprintf("File not eligible: %s", f.Key))
					}
				}
				if next == "" {
					break
				}
				marker = next
			}
		}
	}
}

// Unverified bytes are isolated in the failed destination, never in the clean destination.
func (a *App) routeScanFailure(ctx context.Context, id string, s Snapshot, local, digest, reason string) {
	if s.Failed.ID == "" {
		_ = a.transition(id, "HELD", "UNKNOWN", digest, "", reason+" Configure a scan failed destination for new jobs.", 0)
		return
	}
	key := strings.Trim(s.Failed.Prefix+s.Profile.FailedPrefix, "/")
	if key != "" {
		key += "/"
	}
	key += id + "/" + s.Key
	if !core.ValidKey(key) {
		_ = a.transition(id, "HELD", "UNKNOWN", digest, "", reason+" Invalid failed destination path.", 0)
		return
	}
	if err := Route(ctx, s.Failed, key, local, digest, id, "UNKNOWN", s.Size, map[string]string{"scanned": "false", "verdict": "scan_failed"}); err != nil {
		_ = a.transition(id, "HELD", "UNKNOWN", digest, "", reason+" Failed destination transfer failed; original preserved.", 0)
		return
	}
	_ = a.transition(id, "HELD", "UNKNOWN", digest, s.Failed.BaseURL()+"/"+key, reason, 0)
}
