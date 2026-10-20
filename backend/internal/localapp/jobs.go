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
		if expected != "" && strings.Trim(s.ETag, "\"") != strings.Trim(expected, "\"") {
			return "", errors.New("file changed during discovery; waiting for stability")
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
		if expected != "" && strings.Trim(s.ETag, "\"") != strings.Trim(expected, "\"") {
			return "", errors.New("source changed during discovery; waiting for stability")
		}
		s.Size = *props.ContentLength
		if s.Size > 2<<30 {
			return "", errors.New("file exceeds 2 GiB host policy")
		}
		if props.VersionID != nil {
			s.Version = *props.VersionID
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
	rows, e := a.DB.Query("SELECT j.id,j.key,j.profile_id,j.profile_name,j.source_id,j.etag,j.version,j.size,j.state,j.verdict,j.digest,j.destination,j.error,j.attempts,j.created_at,j.updated_at,COALESCE(d.payload,X''),COALESCE((SELECT n.id FROM jobs n WHERE n.source_id=j.source_id AND n.key=j.key AND n.profile_id=j.profile_id AND n.created_at>j.created_at AND n.state IN ('COMPLETED','QUARANTINED') ORDER BY n.created_at DESC LIMIT 1),'') FROM jobs j LEFT JOIN scan_details d ON d.job_id=j.id ORDER BY j.created_at DESC LIMIT 500")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		var details []byte
		if e = rows.Scan(&j.ID, &j.Key, &j.ProfileID, &j.ProfileName, &j.SourceID, &j.ETag, &j.Version, &j.Size, &j.State, &j.Verdict, &j.Digest, &j.Destination, &j.Error, &j.Attempts, &j.CreatedAt, &j.UpdatedAt, &details, &j.NewerCompletedJobID); e != nil {
			return nil, e
		}
		j.Detections = []Detection{}
		if len(details) > 0 {
			var d ScanDetails
			if a.Unseal(details, &d) == nil {
				j.Detections = d.Detections
				j.ScanResponseRecorded = true
			}
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
	} else if verifiedDigest != "" && verdict == "UNKNOWN" {
		var recorded string
		if a.DB.QueryRow("SELECT verdict FROM scan_results WHERE job_id=?", id).Scan(&recorded) == nil && recorded == "UNKNOWN" {
			a.routeScanFailure(ctx, id, s, path, digest, "Scanner returned an unverified result. Manual review required.")
			return
		}
		a.routeScanFailure(ctx, id, s, path, digest, "Scanner failed after retries. Manual review required.")
		return
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
		if err := a.recordScanDetails(id, raw, s.Scanner.APIKey); err != nil {
			fail("Could not retain scanner details.")
			return
		}
		verdict = core.Normalize(raw)
		if _, e := a.DB.Exec("INSERT INTO scan_results(job_id,scanned_at,verdict) VALUES(?,?,?) ON CONFLICT(job_id) DO NOTHING", id, stamp(), verdict); e != nil {
			fail("Could not record scan result.")
			return
		}
		if verdict != "CLEAN" && verdict != "MALICIOUS" {
			a.routeScanFailure(ctx, id, s, path, digest, "Scanner returned an unverified result. Manual review required.")
			return
		}
		verifiedDigest = digest
	}

	if e = a.transition(id, "ROUTING", verdict, digest, "", "", 0); e != nil {
		return
	}
	destination, state, e := routeResult(ctx, id, s, path, digest, verdict)
	if e != nil {
		fail("Destination transfer, tags or SHA-256 verification failed. Check destination write/read and tag permissions. Original preserved.")
		a.Audit("routing.failed", id, "Verified scan result could not be published to its configured destination.")
		return
	}
	if e = a.transition(id, state, verdict, digest, destination, "", 0); e == nil {
		a.Audit("routing.verified", id, "Published and SHA-256 verified: "+destination)
		if err := a.removeVerifiedSource(ctx, s, digest); err != nil {
			_ = a.transition(id, "HELD", verdict, digest, destination, "Destination verified, but source removal failed. Check delete permissions or whether the source changed.", 0)
		}
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
			a.monitorProfile(ctx, p)
		}
	}
}

// Unverified bytes are isolated in the failed destination, never in the clean destination.
func (a *App) routeScanFailure(ctx context.Context, id string, s Snapshot, local, digest, reason string) {
	if e := a.transition(id, "ROUTING", "UNKNOWN", digest, "", reason, 0); e != nil {
		return
	}
	destination, _, err := routeResult(ctx, id, s, local, digest, "UNKNOWN")
	if err != nil {
		state := "RETRY_PENDING"
		var attempts int
		_ = a.DB.QueryRow("SELECT attempts FROM jobs WHERE id=?", id).Scan(&attempts)
		if attempts >= 5 {
			state = "HELD"
		}
		_ = a.transition(id, state, "UNKNOWN", digest, "", reason+" Failed destination unavailable; original preserved.", time.Minute)
		a.Audit("routing.failed", id, "Scan failed destination could not be verified.")
		return
	}
	if err := a.removeVerifiedSource(ctx, s, digest); err != nil {
		reason += " Destination verified, but source removal failed; check delete permissions."
	}
	_ = a.transition(id, "HELD", "UNKNOWN", digest, destination, reason, 0)
	a.Audit("routing.verified", id, "Unverified scan isolated for review: "+destination)
}

// monitorProfile reads only the profile source; destinations are used only when routing.
func (a *App) monitorProfile(ctx context.Context, p Profile) {
	var m Mount
	summary := map[string]any{"checkedAt": stamp(), "sourceMount": p.SourceMount, "listed": 0, "queued": 0, "waitingForMarker": 0, "waitingForStability": 0, "errors": 0}
	defer func() {
		if b, e := a.Seal(summary); e == nil {
			_, _ = a.DB.Exec("INSERT INTO config(kind,id,value) VALUES('monitorStatus',?,?) ON CONFLICT(kind,id) DO UPDATE SET value=excluded.value", p.ID, b)
		}
	}()
	if a.Get("mounts", p.SourceMount, &m) != nil {
		summary["message"] = "Source connection is unavailable."
		summary["errors"] = 1
		return
	}
	marker := ""
	listed, queued, missing, waiting, failures := 0, 0, 0, 0, 0
	for ctx.Err() == nil {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		files, next, e := ListBlobs(cctx, m, p.Prefix, marker)
		cancel()
		if e != nil {
			failures++
			summary["message"] = "Cannot list source. Check its credentials and read permissions."
			break
		}
		for _, f := range files {
			listed++

			// Completed uploads are eligible on this poll. Unmarked uploads must remain unchanged across polls.
			{
				var first int64
				e = a.DB.QueryRow("INSERT INTO observations(profile_id,key,etag,first_seen) VALUES(?,?,?,?) ON CONFLICT(profile_id,key) DO UPDATE SET first_seen=CASE WHEN observations.etag=excluded.etag THEN observations.first_seen ELSE excluded.first_seen END,etag=excluded.etag RETURNING first_seen", p.ID, f.Key, f.ETag, time.Now().Unix()).Scan(&first)
				if e != nil {
					failures++
					continue
				}
				if time.Now().Unix()-first < 10 {
					waiting++
					continue
				}
			}
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			_, e = a.enqueueExpected(cctx, p.ID, f.Key, f.ETag)
			cancel()
			if e != nil {
				failures++
				summary["lastError"] = redactString(redactString(e.Error(), m.Secret), sasSignature(m.Secret))
				continue
			}
			queued++
		}
		if next == "" {
			break
		}
		marker = next
	}
	summary["listed"], summary["queued"], summary["waitingForMarker"], summary["waitingForStability"], summary["errors"] = listed, queued, missing, waiting, failures
	if _, ok := summary["message"]; !ok {
		summary["message"] = fmt.Sprintf("Source only: %d files checked; %d eligible (existing jobs reused); %d waiting for completion marker; %d waiting for stability; %d errors.", listed, queued, missing, waiting, failures)
	}
}
