package localapp

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// A profile edit must not create a second owner for the same active source version.
	var existingID string
	var existingSnapshot []byte
	lookupErr := tx.QueryRow("SELECT id,snapshot FROM jobs WHERE profile_id=? AND source_id=? AND key=? AND etag=? AND version=? AND state IN ('QUEUED','SCANNING','ROUTING','RETRY_PENDING') ORDER BY created_at LIMIT 1", s.Profile.ID, s.Source.ID, s.Key, s.ETag, s.Version).Scan(&existingID, &existingSnapshot)
	if lookupErr == nil {
		var previous Snapshot
		if err := a.Unseal(existingSnapshot, &previous); err != nil {
			return "", err
		}
		if previous.Source.BaseURL() == s.Source.BaseURL() {
			return existingID, nil
		}
	} else if lookupErr != sql.ErrNoRows {
		return "", lookupErr
	}
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
func (a *App) Jobs() ([]Job, error) { return a.jobsPage("", nil, 500, 0) }
func (a *App) jobsPage(where string, args []any, limit, offset int) ([]Job, error) {
	query := "SELECT j.id,j.key,j.profile_id,j.profile_name,j.source_id,j.etag,j.version,j.size,j.state,j.verdict,j.digest,j.destination,j.error,j.attempts,j.created_at,j.updated_at,COALESCE(d.payload,X''),COALESCE(m.payload,X''),COALESCE(c.payload,X''),COALESCE((SELECT json_group_object(stage,attempts) FROM stage_attempts WHERE job_id=j.id),'{}'),COALESCE((SELECT n.id FROM jobs n WHERE n.source_id=j.source_id AND n.key=j.key AND n.profile_id=j.profile_id AND n.created_at>j.created_at AND n.state IN ('COMPLETED','QUARANTINED') ORDER BY n.created_at DESC LIMIT 1),'') FROM jobs j LEFT JOIN scan_details d ON d.job_id=j.id LEFT JOIN move_records m ON m.job_id=j.id LEFT JOIN source_claims c ON c.job_id=j.id" + where + " ORDER BY j.created_at DESC,j.id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, e := a.DB.Query(query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		var details, moveBytes, claimBytes []byte
		var stages string
		if e = rows.Scan(&j.ID, &j.Key, &j.ProfileID, &j.ProfileName, &j.SourceID, &j.ETag, &j.Version, &j.Size, &j.State, &j.Verdict, &j.Digest, &j.Destination, &j.Error, &j.Attempts, &j.CreatedAt, &j.UpdatedAt, &details, &moveBytes, &claimBytes, &stages, &j.NewerCompletedJobID); e != nil {
			return nil, e
		}
		if len(claimBytes) > 0 {
			var c sourceClaim
			if a.Unseal(claimBytes, &c) == nil {
				j.SourceClaim = map[string]any{"phase": c.Phase, "originalKey": c.OriginalKey, "claimedKey": c.Key, "sha256": c.Digest}
			}
		}
		if len(moveBytes) > 0 {
			var m MoveRecord
			if a.Unseal(moveBytes, &m) == nil {
				j.Integrity = publicMove(m)
			}
		}
		_ = json.Unmarshal([]byte(stages), &j.StageAttempts)
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
	profiles, err := a.List("profiles")
	if err != nil {
		return "", s, 0, err
	}
	largeLimits := "CASE j.profile_id"
	limits := "CASE j.profile_id"
	parameters := []any{time.Now().Unix()}
	for _, raw := range profiles {
		var p Profile
		if json.Unmarshal(raw, &p) == nil {
			largeLimits += fmt.Sprintf(" WHEN '%s' THEN %d", strings.ReplaceAll(p.ID, "'", "''"), defaultInt(p.LargeFileScans, 1))
			limits += " WHEN ? THEN ?"
			parameters = append(parameters, p.ID, min(defaultInt(p.SimultaneousScans, 2), WorkerLimit()))
		}
	}
	limits += " ELSE 2 END"
	largeLimits += " ELSE 1 END"
	if len(parameters) == 1 {
		limits = "2"
		largeLimits = "1"
	}
	tx, e := a.DB.Begin()
	if e != nil {
		return "", s, 0, e
	}
	defer tx.Rollback()
	var id string
	var b []byte
	var attempts int
	e = tx.QueryRow("SELECT j.id,j.snapshot,j.attempts FROM jobs j WHERE j.state IN ('QUEUED','RETRY_PENDING') AND j.available_at<=? AND (SELECT count(*) FROM jobs active WHERE active.profile_id=j.profile_id AND active.state IN ('SCANNING','ROUTING')) < "+limits+" AND (j.size < 1000000000 OR (SELECT count(*) FROM jobs active WHERE active.profile_id=j.profile_id AND active.size>=1000000000 AND active.state IN ('SCANNING','ROUTING')) < "+largeLimits+") ORDER BY j.created_at,j.id LIMIT 1", parameters...).Scan(&id, &b, &attempts)
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
func (a *App) worker(ctx context.Context) { a.workerNamed(ctx, "worker-test") }
func (a *App) workerNamed(ctx context.Context, name string) {
	for ctx.Err() == nil {
		a.beat(name)
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
		func() {
			done := make(chan struct{})
			go func() {
				ticker := time.NewTicker(5 * time.Second)
				deadline := time.NewTimer(s.Profile.JobTimeout() + time.Minute)
				defer deadline.Stop()
				defer ticker.Stop()
				for {
					select {
					case <-done:
						return
					case <-deadline.C:
						return
					case <-ctx.Done():
						return
					case <-ticker.C:
						a.beat(name)
					}
				}
			}()
			defer close(done)
			a.process(ctx, id, s, attempt)
		}()
	}
}
func (a *App) process(parent context.Context, id string, s Snapshot, attempt int) {
	ctx, cancel := context.WithTimeout(parent, s.Profile.JobTimeout())
	defer cancel()
	if action, rule := s.Profile.FilePolicy(strings.TrimPrefix(s.Key, s.Source.Prefix+s.Profile.Prefix), s.Size); action == "hold" || action == "ignore" {
		_ = a.transition(id, "HELD", "NOT_SCANNED", "", "", "Policy "+action+": "+rule, 0)
		return
	}
	if e := a.handoffSource(ctx, id, &s); e != nil {
		a.retryStage(id, "download", s.Profile, "UNKNOWN", "", "", "Share handoff unavailable or source changed; original/claimed file retained.")
		return
	}
	if move, e := a.loadMove(id); e == nil {
		if move.Phase == "COMPLETED" {
			_ = a.transition(id, move.FinalState, move.Verdict, move.Digest, move.Destination, move.Reason, 0)
			return
		}
		a.finalizeMove(ctx, id, s, move)
		return
	}
	verdict, verifiedDigest := "UNKNOWN", ""
	if e := a.DB.QueryRow("SELECT verdict,digest FROM jobs WHERE id=?", id).Scan(&verdict, &verifiedDigest); e != nil {
		return
	}
	captureDir := filepath.Join(a.DataDir, "captures")
	if e := os.MkdirAll(captureDir, 0700); e != nil {
		a.retryStage(id, "download", s.Profile, verdict, verifiedDigest, "", "Cannot prepare capture storage; source retained.")
		return
	}
	releaseSpace, spaceErr := reserveCapture(captureDir, s.Size)
	if spaceErr != nil {
		_ = a.transition(id, "RETRY_PENDING", verdict, verifiedDigest, "", spaceErr.Error(), time.Minute)
		return
	}
	defer releaseSpace()
	local, digest, e := Download(ctx, s, captureDir)
	if e != nil {
		a.retryStage(id, "download", s.Profile, verdict, verifiedDigest, "", "Source download failed, identity changed or source is unavailable.")
		return
	}
	defer os.Remove(local)
	if verifiedDigest != "" && verifiedDigest != digest {
		_ = a.transition(id, "HELD", "UNKNOWN", digest, "", "Source differs from previously captured bytes.", 0)
		return
	}
	relative := strings.TrimPrefix(s.Key, s.Source.Prefix+s.Profile.Prefix)
	action, rule := s.Profile.FilePolicy(relative, s.Size)
	if action == "hold" || action == "ignore" {
		_ = a.transition(id, "HELD", "NOT_SCANNED", digest, "", "Policy "+action+": "+rule, 0)
		return
	}
	if action == "oversize_clean" || action == "oversize_failed" {
		v := "OVERSIZED"
		if action == "oversize_clean" {
			v = "OVERSIZED_CLEAN"
		}
		a.Audit("scan.oversized", id, "NOT SCANNED; "+action)
		a.routeCaptured(ctx, id, s, local, digest, v, rule, "Oversized file; NOT SCANNED; explicit profile action: "+action)
		return
	}
	if action == "exclude" {
		a.Audit("scan.excluded", id, "Rule "+rule+"; profile revision "+fmt.Sprint(s.Profile.Revision))
		a.routeCaptured(ctx, id, s, local, digest, "EXCLUDED", rule, "Excluded by policy; NOT SCANNED. Rule: "+rule)
		return
	}
	if verifiedDigest != "" && (verdict == "CLEAN" || verdict == "MALICIOUS") {
		a.routeCaptured(ctx, id, s, local, digest, verdict, "", "")
		return
	}
	var used int
	_ = a.DB.QueryRow("SELECT attempts FROM stage_attempts WHERE job_id=? AND stage='scan'", id).Scan(&used)
	if used >= defaultInt(s.Profile.ScanAttempts, 5) {
		a.routeCaptured(ctx, id, s, local, digest, "UNKNOWN", "", "Scan attempts exhausted; isolated for review.")
		return
	}
	raw, scanErr := a.Scan(ctx, local, s.Scanner, s.Profile)
	if scanErr != nil {
		if used+1 >= defaultInt(s.Profile.ScanAttempts, 5) {
			_, _ = a.stageAttempt(id, "scan")
			a.routeCaptured(ctx, id, s, local, digest, "UNKNOWN", "", "Scan request attempts exhausted.")
		} else {
			a.retryStage(id, "scan", s.Profile, "UNKNOWN", digest, "", "Scanner request failed.")
		}
		return
	}
	if e = a.recordScanDetails(id, raw, s.Scanner.APIKey); e != nil {
		a.retryStage(id, "scan", s.Profile, "UNKNOWN", digest, "", "Could not persist scanner response.")
		return
	}
	verdict = core.Normalize(raw)
	_, e = a.DB.Exec("INSERT INTO scan_results(job_id,scanned_at,verdict) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET verdict=excluded.verdict", id, stamp(), verdict)
	if e != nil {
		return
	}
	if verdict == "UNKNOWN" {
		if scanException(raw) == "permanent" {
			a.routeCaptured(ctx, id, s, local, digest, "UNKNOWN", "", "Permanent scanner exception; inspect scanner response.")
			return
		}
		if used+1 >= defaultInt(s.Profile.ScanAttempts, 5) {
			_, _ = a.stageAttempt(id, "scan")
			a.routeCaptured(ctx, id, s, local, digest, "UNKNOWN", "", "Scan result remained unknown after retries.")
		} else {
			a.retryStage(id, "scan", s.Profile, "UNKNOWN", digest, "", "Transient or unsupported scanner result; scan retry pending.")
		}
		return
	}
	a.routeCaptured(ctx, id, s, local, digest, verdict, "", "")
}
func (a *App) monitor(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	lastRun := map[string]time.Time{}
	active := map[string]bool{}
	var activeMu sync.Mutex
	slots := make(chan struct{}, 4)
	var monitors sync.WaitGroup
	defer monitors.Wait()
	lastRecovery := time.Now().Add(-time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if time.Since(lastRecovery) > time.Minute {
			lastRecovery = time.Now()
			monitors.Add(1)
			go func() {
				defer monitors.Done()
				c, cancel := context.WithTimeout(ctx, 50*time.Second)
				defer cancel()
				a.reconcileHistorical(c)
				a.recoverySweep(c)
			}()
		}
		a.beat("monitor")
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
			activeMu.Lock()
			running := active[p.ID]
			if !running {
				select {
				case slots <- struct{}{}:
					active[p.ID] = true
				default:
					running = true
				}
			}
			activeMu.Unlock()
			if running {
				continue
			}
			lastRun[p.ID] = time.Now()
			monitors.Add(1)
			go func(p Profile) {
				a.beat("source:" + p.ID)
				defer a.stopBeat("source:" + p.ID)
				defer monitors.Done()
				defer func() { <-slots; activeMu.Lock(); delete(active, p.ID); activeMu.Unlock() }()
				c, cancel := context.WithTimeout(ctx, 3*time.Minute)
				defer cancel()
				a.monitorProfile(c, p)
			}(p)
		}
	}
}

// Unverified bytes are isolated in the failed destination, never in the clean destination.
func (a *App) routeScanFailure(ctx context.Context, id string, s Snapshot, local, digest, reason string) {
	a.routeCaptured(ctx, id, s, local, digest, "UNKNOWN", "", reason)
}

// monitorProfile reads only the profile source; destinations are used only when routing.
func (a *App) monitorProfile(ctx context.Context, p Profile) {
	var m Mount
	_, _ = a.DB.Exec(`UPDATE inventory SET status='ACCOUNTED',reason='Exact source version has durable job',job_id=(SELECT j.id FROM jobs j WHERE j.profile_id=inventory.profile_id AND j.key=inventory.key AND trim(j.etag,'"')=trim(inventory.etag,'"') ORDER BY j.created_at DESC LIMIT 1) WHERE profile_id=? AND status IN ('ERROR','DISCOVERED') AND EXISTS(SELECT 1 FROM jobs j WHERE j.profile_id=inventory.profile_id AND j.key=inventory.key AND trim(j.etag,'"')=trim(inventory.etag,'"'))`, p.ID)
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
			relative := strings.TrimPrefix(f.Key, m.Prefix+p.Prefix)
			action, rule := p.FilePolicy(relative, f.Size)
			_, _ = a.DB.Exec("INSERT INTO inventory(profile_id,key,etag,size,last_seen,status,reason) VALUES(?,?,?,?,?,'DISCOVERED','') ON CONFLICT(profile_id,key,etag) DO UPDATE SET size=excluded.size,last_seen=excluded.last_seen", p.ID, f.Key, f.ETag, f.Size, stamp())
			if action == "ignore" || action == "hold" {
				_, _ = a.DB.Exec("UPDATE inventory SET status=?,reason=? WHERE profile_id=? AND key=? AND etag=?", strings.ToUpper(action), rule, p.ID, f.Key, f.ETag)
				continue
			}

			// Completed uploads are eligible on this poll. Unmarked uploads must remain unchanged across polls.
			{
				var first int64
				e = a.DB.QueryRow("INSERT INTO observations(profile_id,key,etag,first_seen) VALUES(?,?,?,?) ON CONFLICT(profile_id,key) DO UPDATE SET first_seen=CASE WHEN observations.etag=excluded.etag THEN observations.first_seen ELSE excluded.first_seen END,etag=excluded.etag RETURNING first_seen", p.ID, f.Key, f.ETag, time.Now().Unix()).Scan(&first)
				if e != nil {
					failures++
					continue
				}
				if time.Now().Unix()-first < int64(defaultInt(p.QuietSeconds, 10)) {
					waiting++
					continue
				}
			}
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			jobID, queueErr := a.enqueueExpected(cctx, p.ID, f.Key, f.ETag)
			e = queueErr
			cancel()
			if e != nil {
				failures++
				_, _ = a.DB.Exec("UPDATE inventory SET status='ERROR',reason=? WHERE profile_id=? AND key=? AND etag=?", redactString(redactString(e.Error(), m.Secret), sasSignature(m.Secret)), p.ID, f.Key, f.ETag)
				summary["lastError"] = redactString(redactString(e.Error(), m.Secret), sasSignature(m.Secret))
				continue
			}
			queued++
			_, _ = a.DB.Exec("UPDATE inventory SET status='ACCOUNTED',reason='Durable job exists',job_id=? WHERE profile_id=? AND key=? AND etag=?", jobID, p.ID, f.Key, f.ETag)
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
