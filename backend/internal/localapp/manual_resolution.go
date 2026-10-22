package localapp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

// Explicit operator requests are the only exception to destination handoff.
// They create a new job and never rewrite historical scan evidence.
func (a *App) resolveScanError(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action  string `json:"action"`
		Confirm bool   `json:"confirm"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || !req.Confirm || (req.Action != "rescan" && req.Action != "clean" && req.Action != "malicious" && req.Action != "failed") {
		problem(w, 400, "Confirm a rescan or a configured destination.")
		return
	}
	parent := r.PathValue("id")
	var state, verdict string
	var payload []byte
	if a.DB.QueryRow("SELECT state,verdict,snapshot FROM jobs WHERE id=?", parent).Scan(&state, &verdict, &payload) != nil || verdict != "UNKNOWN" || (state != "HELD" && state != "RETRY_PENDING") {
		problem(w, 409, "Only held or retrying scan errors can be resolved.")
		return
	}
	var s Snapshot
	if a.Unseal(payload, &s) != nil {
		problem(w, 500, "Cannot read job snapshot.")
		return
	}
	// Use current policy for the new scan; preserve exact source identity.
	var policy Profile
	if a.Get("profiles", s.Profile.ID, &policy) == nil {
		s.Profile = policy
	}
	s.Profile.ScanAttempts = 4
	s.CaptureSHA = ""
	s.CaptureCRC = ""
	s.ExpectedDigest = ""
	s.ManualAction = ""
	var inheritedClaim []byte
	if claim, err := a.loadClaim(parent); err == nil && claim.Phase == "CLAIMED" {
		s.ExpectedDigest = claim.Digest
		inheritedClaim, err = a.Seal(claim)
		if err != nil {
			problem(w, 500, "Cannot preserve source handoff.")
			return
		}
	}
	if m, err := a.loadMove(parent); err == nil {
		if m.Phase != "COMPLETED" {
			problem(w, 409, "An incomplete delivery must be retried or dismissed before resolving this file.")
			return
		}
		inheritedClaim = nil
		s.Source = m.Target
		s.Key = m.Key
		s.ETag = m.DestinationETag
		s.Version = ""
		s.Size = m.Size
		s.ExpectedDigest = m.Digest
		s.ClaimedKey = ""
		s.ClaimedETag = ""
	}
	// No storage calls here. The worker conditionally reads this exact identity.
	if req.Action != "rescan" {
		switch req.Action {
		case "clean":
			s.Failed = s.Good
			s.Profile.FailedPrefix = s.Profile.GoodPrefix
		case "malicious":
			s.Failed = s.Bad
			s.Profile.FailedPrefix = s.Profile.BadPrefix
		}
		if s.Failed.ID == "" || sameStorageRoot(s.Source, s.Failed) {
			problem(w, 409, "Choose a configured destination different from the file's current storage location.")
			return
		}
		s.ManualAction = req.Action
	}
	// Explicit source-based actions must not be bypassed by exclusions.
	s.Profile.Rules = nil
	s.Profile.Prefix = ""
	s.Profile.OversizeAction = "hold"
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		problem(w, 500, "Cannot create request.")
		return
	}
	id := hex.EncodeToString(nonce[:])
	sealed, err := a.Seal(s)
	if err != nil {
		problem(w, 500, "Cannot save request.")
		return
	}
	tx, err := a.DB.Begin()
	if err != nil {
		problem(w, 500, "Cannot queue request.")
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE jobs SET state='ACKNOWLEDGED',updated_at=? WHERE id=? AND state IN ('HELD','RETRY_PENDING') AND NOT EXISTS(SELECT 1 FROM transfer_queue WHERE job_id=? AND active=1)", stamp(), parent, parent)
	if err != nil {
		problem(w, 500, "Cannot reserve file.")
		return
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		problem(w, 409, "File is active or already resolved.")
		return
	}
	_, err = tx.Exec("INSERT INTO jobs(id,profile_id,profile_name,source_id,key,etag,version,size,state,verdict,snapshot,available_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'QUEUED','UNKNOWN',?,?,?,?)", id, s.Profile.ID, s.Profile.Name, s.Source.ID, s.Key, s.ETag, s.Version, s.Size, sealed, time.Now().Unix(), stamp(), stamp())
	if err != nil {
		problem(w, 500, "Cannot create linked request.")
		return
	}
	if inheritedClaim != nil {
		if _, err = tx.Exec("INSERT INTO source_claims(job_id,payload) VALUES(?,?)", id, inheritedClaim); err != nil {
			problem(w, 500, "Cannot transfer source handoff.")
			return
		}
	}
	if _, err = tx.Exec("DELETE FROM transfer_queue WHERE job_id=?", parent); err != nil {
		problem(w, 500, "Cannot cancel pending delivery.")
		return
	}
	if err = tx.Commit(); err != nil {
		problem(w, 500, "Cannot commit request.")
		return
	}
	a.Audit("job.manual-resolution", id, "Parent "+parent+"; administrator requested "+req.Action+"; original verdict preserved")
	respond(w, 200, map[string]string{"jobId": id, "parentJobId": parent, "action": req.Action})
}
