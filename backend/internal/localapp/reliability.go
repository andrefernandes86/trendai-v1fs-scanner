package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
)

type MoveRecord struct {
	SkipDestinationVerification bool   `json:"skipDestinationVerification"`
	Phase                       string `json:"phase"`
	Destination                 string `json:"destination"`
	Target                      Mount  `json:"target"`
	Key                         string `json:"key"`
	FinalState                  string `json:"finalState"`
	Verdict                     string `json:"verdict"`
	Digest                      string `json:"sha256"`
	CRC32C                      string `json:"crc32c"`
	Size                        int64  `json:"size"`
	SourceETag                  string `json:"sourceETag"`
	DestinationETag             string `json:"destinationETag"`
	Rule                        string `json:"matchedRule,omitempty"`
	Reason                      string `json:"reason,omitempty"`
	VerifiedAt                  string `json:"verifiedAt"`
}

func checksums(file string) (string, string, int64, error) {
	f, e := os.Open(file)
	if e != nil {
		return "", "", 0, e
	}
	defer f.Close()
	sha := sha256.New()
	crc := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	n, e := io.Copy(io.MultiWriter(sha, crc), f)
	return hex.EncodeToString(sha.Sum(nil)), fmt.Sprintf("%08x", crc.Sum32()), n, e
}
func (a *App) saveMove(id string, m MoveRecord) error {
	b, e := a.Seal(m)
	if e != nil {
		return e
	}
	_, e = a.DB.Exec("INSERT INTO move_records(job_id,payload) VALUES(?,?) ON CONFLICT(job_id) DO UPDATE SET payload=excluded.payload", id, b)
	return e
}
func (a *App) loadMove(id string) (MoveRecord, error) {
	var m MoveRecord
	var b []byte
	e := a.DB.QueryRow("SELECT payload FROM move_records WHERE job_id=?", id).Scan(&b)
	if e == nil {
		e = a.Unseal(b, &m)
	}
	return m, e
}
func (a *App) stageAttempt(id, stage string) (int, error) {
	var n int
	e := a.DB.QueryRow("INSERT INTO stage_attempts(job_id,stage,attempts) VALUES(?,?,1) ON CONFLICT(job_id,stage) DO UPDATE SET attempts=attempts+1 RETURNING attempts", id, stage).Scan(&n)
	return n, e
}
func (a *App) retryStage(id, stage string, p Profile, verdict, digest, dest, message string) {
	n, e := a.stageAttempt(id, stage)
	if e != nil {
		_ = a.transition(id, "HELD", verdict, digest, dest, "Could not persist retry state.", 0)
		return
	}
	limit := defaultInt(p.ScanAttempts, 5)
	if stage == "transfer" {
		limit = defaultInt(p.TransferAttempts, 8)
	}
	if stage == "delete" {
		limit = defaultInt(p.DeleteAttempts, 12)
	}
	if stage == "download" {
		limit = defaultInt(p.TransferAttempts, 8)
	}
	state := "RETRY_PENDING"
	if n >= limit {
		state = "HELD"
		message += " Retry budget exhausted; operator action required."
		if stage == "scan" || stage == "transfer" || stage == "download" {
			message += " scan-failed=true; failure-stage=" + stage + "."
			if err := a.tagExhaustedSource(id, stage, verdict); err != nil {
				message += " Source failure tag could not be written; storage access or source identity needs review."
			}
		}
	}
	delay := time.Duration(defaultInt(p.RetryBaseSeconds, 10)*(1<<min(n-1, 8))) * time.Second
	delay = min(delay, time.Hour)
	delay += time.Duration(rand.IntN(1000)) * time.Millisecond
	_ = a.transition(id, state, verdict, digest, dest, message, delay)
}
func (a *App) verifyDestination(ctx context.Context, m *MoveRecord) error {
	var s Snapshot
	s.Source = m.Target
	s.Key = m.Key
	s.Size = m.Size
	if m.Target.Type() == "blob" {
		b, e := m.Target.BlobClient(m.Key, "")
		if e != nil {
			return e
		}
		props, e := b.GetProperties(ctx, nil)
		if e != nil {
			return e
		}
		if props.ETag == nil {
			return errors.New("destination identity unavailable")
		}
		s.ETag = string(*props.ETag)
		if props.ContentLength == nil || *props.ContentLength != m.Size {
			return errors.New("destination size changed")
		}
	} else {
		v, e := shareProperties(ctx, m.Target, m.Key)
		if e != nil {
			return e
		}
		s.ETag = v.ETag
		if v.Size != m.Size {
			return errors.New("destination size changed")
		}
	}
	if m.DestinationETag != "" && m.DestinationETag != s.ETag {
		return errors.New("destination identity changed after verification")
	}
	if m.SkipDestinationVerification {
		m.DestinationETag = s.ETag
		m.VerifiedAt = ""
		return nil
	}
	sha, crc, n, e := streamChecksums(ctx, s)
	if e != nil {
		return e
	}
	if sha != m.Digest || crc != m.CRC32C || n != m.Size {
		return errors.New("destination SHA-256/CRC32C verification failed")
	}
	m.DestinationETag = s.ETag
	m.VerifiedAt = stamp()
	return nil
}
func (a *App) finalizeMove(ctx context.Context, id string, s Snapshot, m MoveRecord) {
	// Reverify persisted destination before every delete attempt, including restart recovery.
	if ((s.Source.Type() != "blob" && s.ClaimedKey == "") || m.Target.Type() != "blob") && !s.Profile.ControlledWriter {
		_ = a.transition(id, "HELD", m.Verdict, m.Digest, m.Destination, "Source retained: confirm an exclusive producer handoff and controlled destination writers for share storage.", 0)
		return
	}
	locked, release, e := leaseDestination(ctx, id, m)
	if e != nil {
		a.retryStage(id, "delete", s.Profile, m.Verdict, m.Digest, m.Destination, "Destination lease unavailable; source preserved.")
		return
	}
	defer release()
	ctx = locked
	verifyStart := time.Now()
	verifyErr := a.verifyDestination(ctx, &m)
	a.recordTiming(id, "verify", verifyStart)
	if verifyErr != nil {
		a.retryStage(id, "transfer", s.Profile, m.Verdict, m.Digest, m.Destination, "Destination changed or could not be verified. Source preserved.")
		return
	}

	if m.Target.Type() == "blob" {
		tags, err := a.jobRoutingTags(id, s.Profile, m.Verdict)
		if err == nil {
			b, e := m.Target.BlobClient(m.Key, "")
			err = e
			if err == nil {
				if m.Target.Kind == "adls" {
					props, readErr := b.GetProperties(ctx, nil)
					err = readErr
					if err == nil {
						metadata := props.Metadata
						if metadata == nil {
							metadata = map[string]*string{}
						}
						metadata["v1fs_result_tags"] = to.Ptr(encodeADLSTags(tags))
						result, writeErr := b.SetMetadata(ctx, metadata, &blob.SetMetadataOptions{AccessConditions: &blob.AccessConditions{LeaseAccessConditions: &blob.LeaseAccessConditions{LeaseID: to.Ptr(destinationLeaseID(id))}, ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: props.ETag}}})
						err = writeErr
						if err == nil {
							if result.ETag == nil {
								err = errors.New("destination metadata identity unavailable")
							} else {
								m.DestinationETag = string(*result.ETag)
							}
						}
					}
				} else {
					_, err = b.SetTags(ctx, tags, &blob.SetTagsOptions{AccessConditions: &blob.AccessConditions{LeaseAccessConditions: &blob.LeaseAccessConditions{LeaseID: to.Ptr(destinationLeaseID(id))}}})
				}
			}
		}
		if err != nil {
			a.retryStage(id, "transfer", s.Profile, m.Verdict, m.Digest, m.Destination, "Destination tags unavailable; source preserved.")
			return
		}
	}
	m.Phase = "SOURCE_DELETE_PENDING"
	if e := a.saveMove(id, m); e != nil {
		return
	}
	if s.Source.Type() != "blob" && s.ClaimedKey == "" && !s.Profile.ControlledWriter {
		_ = a.transition(id, "HELD", m.Verdict, m.Digest, m.Destination, "Destination verified. Source retained until a controlled-writer handoff contract is enabled for this SMB/NFS/Azure Files source.", 0)
		return
	}
	// Missing source is acceptable only when the recorded destination still verifies.
	if e := a.removeVerifiedSource(ctx, s, m.Digest); e != nil {
		absent := os.IsNotExist(e)
		var re *azcore.ResponseError
		if errors.As(e, &re) && re.StatusCode == 404 {
			absent = true
		}
		if !absent {
			a.retryStage(id, "delete", s.Profile, m.Verdict, m.Digest, m.Destination, "Verified destination retained; source delete failed or identity changed.")
			return
		}
	}
	m.Phase = "COMPLETED"
	if e := a.saveMove(id, m); e != nil {
		return
	}
	_ = a.transition(id, m.FinalState, m.Verdict, m.Digest, m.Destination, m.Reason, 0)
	if m.FinalState == "COMPLETED" || m.FinalState == "QUARANTINED" {
		_, _ = a.DB.Exec("UPDATE jobs SET state='RECOVERED',error=?,updated_at=? WHERE id IN (SELECT parent_id FROM recovery_links WHERE child_id=?)", "Recovered by job "+id, stamp(), id)
	}
	message := "Destination verified with size, SHA-256 and CRC32C; source deletion reconciled."
	if m.SkipDestinationVerification {
		message = "Destination size and identity checked; content readback disabled by profile; source deletion reconciled."
	}
	a.Audit("routing.finalized", id, message)
}
func scanException(raw []byte) string {
	var v map[string]any
	if json.Unmarshal(raw, &v) != nil {
		return "transient"
	}
	if blocked, _ := v["archivePolicyBlocked"].(bool); blocked {
		return "permanent"
	}
	text := strings.ToLower(string(raw))
	for _, s := range []string{"password protected", "password-protected", "encrypted archive", "unsupported file", "unsupported format", "file too large", "maximum file size", "scan limit exceeded", "decompression limit"} {
		if strings.Contains(text, s) {
			return "permanent"
		}
	}
	return "transient"
}
func (a *App) routeCaptured(ctx context.Context, id string, s Snapshot, local, digest, verdict, rule, reason string) {
	if a.transferEnabled {
		if err := a.enqueueTransfer(id, s, local, digest, verdict, rule, reason); err != nil {
			a.retryStage(id, "transfer", s.Profile, verdict, digest, "", "Could not persist transfer handoff; source preserved.")
		}
		return
	}
	a.routeCapturedNow(ctx, id, s, local, digest, verdict, rule, reason)
}
func (a *App) routeCapturedNow(ctx context.Context, id string, s Snapshot, local, digest, verdict, rule, reason string) {
	if verdict == "UNKNOWN" && sameStorageRoot(s.Source, s.Failed) {
		message := reason + " Recovery result still unknown; isolated source retained. scan-failed=true."
		if err := a.tagExhaustedSource(id, "scan", verdict); err != nil {
			message += " Source failure tag could not be written; storage access or source identity needs review."
		}
		_ = a.transition(id, "HELD", "UNKNOWN", digest, s.Source.BaseURL()+"/"+s.sourceKey(), message, 0)
		return
	}
	sha, crc, n, e := s.CaptureSHA, s.CaptureCRC, s.Size, error(nil)
	if sha == "" || crc == "" {
		sha, crc, n, e = checksums(local)
	} else {
		var info os.FileInfo
		info, e = os.Stat(local)
		if e == nil {
			n = info.Size()
		}
	}
	if e != nil || sha != digest || n != s.Size {
		_ = a.transition(id, "HELD", "UNKNOWN", digest, "", "Captured source integrity failed.", 0)
		return
	}
	_ = a.transition(id, "ROUTING", verdict, digest, "", reason, 0)
	uploadStart := time.Now()
	tags, tagErr := a.jobRoutingTags(id, s.Profile, verdict)
	if tagErr != nil {
		a.retryStage(id, "transfer", s.Profile, verdict, digest, "", "Could not read scan-result tags; source preserved.")
		return
	}
	destination, state, e := routeResult(ctx, id, s, local, digest, verdict, tags)
	a.recordTiming(id, "upload", uploadStart)
	if e != nil {
		a.retryStage(id, "transfer", s.Profile, verdict, digest, "", "Destination transfer or verification failed; source preserved.")
		return
	}
	target := s.Failed
	if verdict == "CLEAN" || verdict == "EXCLUDED" || verdict == "OVERSIZED_CLEAN" {
		target = s.Good
	}
	if verdict == "MALICIOUS" {
		target = s.Bad
	}
	key := strings.TrimPrefix(destination, target.BaseURL()+"/")
	m := MoveRecord{SkipDestinationVerification: s.Profile.SkipDestinationVerification, Phase: "DESTINATION_VERIFIED", Destination: destination, Target: target, Key: key, FinalState: state, Verdict: verdict, Digest: digest, CRC32C: crc, Size: n, SourceETag: s.sourceETag(), Rule: rule, Reason: reason}
	if target.Type() == "blob" {
		m.Phase = "DESTINATION_UPLOADED"
	} else if e = a.verifyDestination(ctx, &m); e != nil {
		a.retryStage(id, "transfer", s.Profile, verdict, digest, destination, "Destination CRC32C verification failed; source preserved.")
		return
	}
	if e = a.saveMove(id, m); e != nil {
		_ = a.transition(id, "HELD", verdict, digest, destination, "Could not persist verified move. Source preserved.", 0)
		return
	}
	_ = a.transition(id, "ROUTING", verdict, digest, destination, "Destination uploaded; leased verification and source deletion pending.", 0)
	a.finalizeMove(ctx, id, s, m)
}

func publicMove(m MoveRecord) map[string]any {
	algorithms := []string{}
	if m.Digest != "" {
		algorithms = append(algorithms, "SHA-256")
	}
	if m.CRC32C != "" {
		algorithms = append(algorithms, "CRC32C")
	}
	return map[string]any{"sourceChecksumAlgorithms": algorithms, "destinationVerification": !m.SkipDestinationVerification, "phase": m.Phase, "sha256": m.Digest, "crc32c": m.CRC32C, "sizeBytes": m.Size, "sourceETag": m.SourceETag, "destinationETag": m.DestinationETag, "verifiedAt": m.VerifiedAt, "matchedRule": m.Rule, "reason": m.Reason}
}
