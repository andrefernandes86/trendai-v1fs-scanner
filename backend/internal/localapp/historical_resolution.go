package localapp

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"os"
	"strings"
)

// Resolve only old source-read failures whose exact bytes have a later successful scan
// and a presently verified destination. No file is deleted or reclassified as clean.
func (a *App) reconcileHistorical(ctx context.Context) {
	rows, e := a.DB.Query("SELECT id FROM jobs WHERE state='HELD' AND verdict='UNKNOWN' AND destination='' AND digest<>'' AND error LIKE 'Source download%' LIMIT 20")
	if e != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		_ = a.resolveHistorical(ctx, id)
	}
}
func (a *App) resolveHistorical(ctx context.Context, id string) error {
	var old Snapshot
	var payload []byte
	var digest, key, profile, source, created string
	e := a.DB.QueryRow("SELECT snapshot,digest,key,profile_id,source_id,created_at FROM jobs WHERE id=? AND state='HELD' AND verdict='UNKNOWN' AND destination='' AND digest<>'' AND error LIKE 'Source download%'", id).Scan(&payload, &digest, &key, &profile, &source, &created)
	if e != nil {
		return e
	}
	if e = a.Unseal(payload, &old); e != nil {
		return e
	}
	if old.Source.Type() != "blob" {
		return errors.New("historical automatic resolution currently requires Blob identities")
	}
	var later Snapshot
	var replacement, destination, verdict string
	e = a.DB.QueryRow("SELECT j.id,j.snapshot,j.destination,j.verdict FROM jobs j JOIN scan_results s ON s.job_id=j.id AND s.verdict=j.verdict WHERE j.profile_id=? AND j.source_id=? AND j.key=? AND j.digest=? AND j.created_at>? AND j.state IN ('COMPLETED','QUARANTINED') AND j.verdict IN ('CLEAN','MALICIOUS') AND j.destination<>'' ORDER BY j.created_at DESC LIMIT 1", profile, source, key, digest, created).Scan(&replacement, &payload, &destination, &verdict)
	if e != nil {
		return e
	}
	if e = a.Unseal(payload, &later); e != nil {
		return e
	}
	if old.Source.BaseURL() != later.Source.BaseURL() {
		return errors.New("source root changed")
	}
	original, e := old.Source.BlobClient(old.Key, "")
	if e != nil {
		return e
	}
	props, err := original.GetProperties(ctx, nil)
	if err == nil {
		if props.ETag == nil || strings.Trim(string(*props.ETag), "\"") == strings.Trim(old.ETag, "\"") {
			return errors.New("original source identity still present")
		}
	} else {
		var re *azcore.ResponseError
		if !errors.As(err, &re) || re.StatusCode != 404 {
			return err
		}
	}
	target := later.Good
	if verdict == "MALICIOUS" {
		target = later.Bad
	}
	if !strings.HasPrefix(destination, target.BaseURL()+"/") {
		return errors.New("destination root mismatch")
	}
	later.Source = target
	later.Key = strings.TrimPrefix(destination, target.BaseURL()+"/")
	later.Version = ""
	later.ClaimedKey = ""
	later.ClaimedETag = ""
	blob, e := target.BlobClient(later.Key, "")
	if e != nil {
		return e
	}
	p, e := blob.GetProperties(ctx, nil)
	if e != nil {
		return e
	}
	if p.ETag == nil || p.ContentLength == nil {
		return errors.New("destination identity unavailable")
	}
	later.ETag = string(*p.ETag)
	later.Size = *p.ContentLength
	local, actual, e := Download(ctx, later, a.DataDir)
	if e != nil {
		return e
	}
	defer os.Remove(local)
	if actual != digest {
		return errors.New("later destination checksum differs")
	}
	tx, e := a.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	result, e := tx.Exec("UPDATE jobs SET state='SUPERSEDED',updated_at=? WHERE id=? AND state='HELD' AND digest=?", stamp(), id, digest)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("historical state changed")
	}
	if _, e = tx.Exec("INSERT INTO audit(at,action,object_id,detail) VALUES(?,?,?,?)", stamp(), "job.superseded", id, "Historical source-read failure resolved by later scanned job "+replacement+"; destination SHA-256 reverified. Original verdict/error retained."); e != nil {
		return e
	}
	return tx.Commit()
}
