package localapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"strings"
)

type sourceClaim struct {
	Digest       string `json:"digest"`
	OriginalKey  string `json:"originalKey"`
	OriginalETag string `json:"originalETag"`
	Key          string `json:"key"`
	ETag         string `json:"etag"`
	Phase        string `json:"phase"`
	Size         int64  `json:"size"`
}
type claimFS interface{ Claim(string, string) error }

func (s Snapshot) sourceKey() string {
	if s.ClaimedKey != "" {
		return s.ClaimedKey
	}
	return s.Key
}
func (s Snapshot) sourceETag() string {
	if s.ClaimedETag != "" {
		return s.ClaimedETag
	}
	return s.ETag
}
func (a *App) saveClaim(id string, c sourceClaim) error {
	b, e := a.Seal(c)
	if e != nil {
		return e
	}
	_, e = a.DB.Exec("INSERT INTO source_claims(job_id,payload) VALUES(?,?) ON CONFLICT(job_id) DO UPDATE SET payload=excluded.payload", id, b)
	return e
}
func (a *App) loadClaim(id string) (sourceClaim, error) {
	var c sourceClaim
	var b []byte
	e := a.DB.QueryRow("SELECT payload FROM source_claims WHERE job_id=?", id).Scan(&b)
	if e == nil {
		e = a.Unseal(b, &c)
	}
	return c, e
}
func (a *App) handoffSource(ctx context.Context, id string, s *Snapshot) error {
	if s.Source.Type() == "blob" {
		return nil
	}
	claim, e := a.loadClaim(id)
	if e == nil && claim.Phase == "CLAIMED" {
		s.ClaimedKey, s.ClaimedETag = claim.Key, claim.ETag
		return nil
	}
	fs, e := remoteOpen(ctx, s.Source)
	if e != nil {
		return e
	}
	defer fs.Close()
	mover, ok := fs.(claimFS)
	if !ok {
		return errors.New("storage connector does not support source handoff")
	}
	if claim.Key == "" {
		claim = sourceClaim{OriginalKey: s.Key, OriginalETag: s.ETag, Key: path.Join(s.Source.Prefix, ".v1fs-claims", id, path.Base(s.Key)), Phase: "CLAIMING", Size: s.Size}
		original, e := fs.Stat(claim.OriginalKey)
		if e != nil {
			return e
		}
		if infoTag(original) != claim.OriginalETag || original.Size() != claim.Size {
			return errors.New("source changed before handoff")
		}
		r, e := fs.Open(claim.OriginalKey)
		if e != nil {
			return e
		}
		hash := sha256.New()
		n, e := io.Copy(hash, io.LimitReader(r, claim.Size+1))
		r.Close()
		if e != nil {
			return e
		}
		after, e := fs.Stat(claim.OriginalKey)
		if e != nil {
			return e
		}
		if n != claim.Size || infoTag(after) != claim.OriginalETag {
			return errors.New("source changed while preparing handoff")
		}
		claim.Digest = hex.EncodeToString(hash.Sum(nil))
		if e = a.saveClaim(id, claim); e != nil {
			return e
		}
	}
	// An interrupted move can leave the claimed path populated before its DB phase is updated.
	target, targetErr := fs.Stat(claim.Key)
	if targetErr == nil {
		if !target.Mode().IsRegular() || target.Size() != claim.Size {
			return errors.New("claim path has unexpected content")
		}
		// If both paths still exist, never guess which source version the target represents.
		if original, e := fs.Stat(claim.OriginalKey); e == nil && infoTag(original) == claim.OriginalETag {
			return errors.New("claim collision: original identity still present")
		} else if e != nil && !os.IsNotExist(e) {
			return e
		}
		if claim.Digest == "" {
			return errors.New("incomplete claim intent has no content proof")
		}
		if e := verifyRemote(fs, claim.Key, claim.Digest, claim.Size); e != nil {
			return e
		}
	} else {
		if !os.IsNotExist(targetErr) {
			return targetErr
		}
		original, e := fs.Stat(claim.OriginalKey)
		if e != nil {
			return e
		}
		if infoTag(original) != claim.OriginalETag || original.Size() != claim.Size {
			return errors.New("source changed before handoff")
		}
		if e = ensureRemoteDirs(fs, path.Dir(claim.Key)); e != nil {
			return e
		}
		if e = noLinks(fs, path.Dir(claim.Key)); e != nil {
			return e
		}
		if e = mover.Claim(claim.OriginalKey, claim.Key); e != nil {
			return e
		}
	}
	target, e = fs.Stat(claim.Key)
	if e != nil {
		return e
	}
	if !target.Mode().IsRegular() || target.Size() != claim.Size {
		return errors.New("source changed during handoff")
	}
	if e = verifyRemote(fs, claim.Key, claim.Digest, claim.Size); e != nil {
		return e
	}
	claim.ETag = infoTag(target)
	claim.Phase = "CLAIMED"
	if e = a.saveClaim(id, claim); e != nil {
		return e
	}
	s.ClaimedKey, s.ClaimedETag = claim.Key, claim.ETag
	a.Audit("source.claimed", id, "Source handed off into scanner-owned .v1fs-claims namespace; original key remains in history.")
	return nil
}

// Reserved paths are never discovered as new work; only the owning job resumes them.
func reservedSharePath(key string) bool {
	for _, component := range strings.Split(key, "/") {
		if component == ".v1fs-claims" || component == ".v1fs-staging" {
			return true
		}
	}
	return false
}
