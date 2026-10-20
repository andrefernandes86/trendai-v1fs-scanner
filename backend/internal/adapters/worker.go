package adapters

import (
	"context"
	"errors"
	"github.com/andrefernandes86/trendai-v1fs-scanner/internal/core"
	"os"
	"time"
)

type Worker struct {
	Store    *core.Store
	Storage  *Storage
	Scanner  *Scanner
	Capacity core.Capacity
}

func (w *Worker) Handle(ctx context.Context, id string) error {
	j, e := w.Store.Job(ctx, id)
	if e != nil {
		return e
	}
	switch j.State {
	case "COMPLETED", "QUARANTINED", "HELD", "CANCELLED", "FAILED":
		return nil
	}
	cap := w.Capacity
	_ = w.Store.Config(ctx, "capacity", "default", &cap)
	permitJob := j
	var currentSource core.Source
	if w.Store.Config(ctx, "sources", j.SourceID, &currentSource) == nil {
		permitJob.Source.Concurrency = currentSource.Concurrency
	}
	var currentProfile core.Profile
	if w.Store.Config(ctx, "profiles", j.ProfileID, &currentProfile) == nil {
		permitJob.Profile.Concurrency = currentProfile.Concurrency
	}
	release, e := w.Store.Permits(ctx, permitJob, cap)
	if e != nil {
		return e
	}
	defer release()
	j, e = w.Store.Job(ctx, id)
	if e != nil {
		return e
	}
	if j.State == "RETRY_PENDING" {
		next := "QUEUED"
		if j.Digest != "" && j.Verdict != "UNKNOWN" {
			next = "PROMOTION_PENDING"
		}
		if e = w.Store.Move(ctx, &j, next, "", 0); e != nil {
			return e
		}
	}
	if j.State == "QUEUED" || j.State == "SCANNING" {
		if j.State == "QUEUED" {
			if e = w.Store.Move(ctx, &j, "SCANNING", "", 0); e != nil {
				return e
			}
		}
		path, digest, e := w.Storage.Download(ctx, j.Source, j)
		if e != nil {
			return w.retry(ctx, &j, e)
		}
		defer os.Remove(path)
		scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		result, e := w.Scanner.Scan(scanCtx, path, j.Profile)
		cancel()
		if e != nil {
			return w.retry(ctx, &j, e)
		}
		j.Result = result
		j.Digest = digest
		j.Verdict = core.Normalize(result)
		if e = w.Store.Move(ctx, &j, "SCANNED", "", 0); e != nil {
			return e
		}
	}
	if j.State == "SCANNED" {
		if j.Verdict != "CLEAN" && j.Verdict != "MALICIOUS" {
			return w.Store.Move(ctx, &j, "HELD", "", 0)
		}
		q := "promote"
		if j.Verdict == "MALICIOUS" {
			q = "quarantine"
		}
		return w.Store.Move(ctx, &j, "PROMOTION_PENDING", q, 0)
	}
	if j.State == "PROMOTION_PENDING" || j.State == "PROMOTING" {
		if j.Verdict != "CLEAN" && j.Verdict != "MALICIOUS" {
			return errors.New("unverified routing denied")
		}
		if w.Scanner.Simulated {
			return w.Store.Move(ctx, &j, "HELD", "", 0)
		}
		if j.State == "PROMOTION_PENDING" {
			if e = w.Store.Move(ctx, &j, "PROMOTING", "", 0); e != nil {
				return e
			}
		}
		path, digest, e := w.Storage.Download(ctx, j.Source, j)
		if e != nil {
			return w.retry(ctx, &j, e)
		}
		defer os.Remove(path)
		if digest != j.Digest {
			return w.Store.Move(ctx, &j, "HELD", "", 0)
		}
		dest, terminal := j.Source.Clean, "COMPLETED"
		if j.Verdict == "MALICIOUS" {
			dest, terminal = j.Source.Quarantine, "QUARANTINED"
		}
		target, e := w.Storage.Route(ctx, dest, j, path)
		if e != nil {
			return w.retry(ctx, &j, e)
		}
		_, e = w.Store.DB.Exec(ctx, "INSERT INTO routing(job_id,destination,digest) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", j.ID, target, j.Digest)
		if e != nil {
			return e
		}
		return w.Store.Move(ctx, &j, terminal, "", 0)
	}
	return nil
}
func (w *Worker) retry(ctx context.Context, j *core.Job, cause error) error {
	if ctx.Err() != nil {
		return cause
	}
	j.Attempts++
	limit := w.Capacity.MaxAttempts
	if limit < 1 {
		limit = 5
	}
	if j.Attempts >= limit {
		return w.Store.Move(ctx, j, "HELD", "", 0)
	}
	delay := time.Second * 10 * time.Duration(1<<min(j.Attempts, 8))
	return w.Store.Move(ctx, j, "RETRY_PENDING", "retry", delay)
}
