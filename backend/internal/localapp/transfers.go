package localapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Separate bounded pools let scan workers progress while files are routed.
// Jobs are durable. On restart the unchanged source is recaptured or its move
// checkpoint is resumed; a persisted clean/malicious result is not rescanned.
type transferTask struct {
	Snapshot                             Snapshot
	Local, Digest, Verdict, Rule, Reason string
}

func TransferWorkerLimit() int {
	n, _ := strconv.Atoi(os.Getenv("V1FS_TRANSFER_WORKERS"))
	if n < 1 {
		n = 4
	}
	return min(n, 8)
}
func (a *App) enqueueTransfer(id string, s Snapshot, local, digest, verdict, rule, reason string) error {
	payload, err := a.Seal(transferTask{s, local, digest, verdict, rule, reason})
	if err != nil {
		return err
	}
	tx, err := a.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("INSERT INTO transfer_queue(job_id,profile_id,size,active,payload) VALUES(?,?,?,0,?)", id, s.Profile.ID, s.Size, payload); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE jobs SET state='ROUTING',verdict=?,digest=?,error=?,updated_at=? WHERE id=?", verdict, digest, "Waiting for transfer slot.", stamp(), id); err != nil {
		return err
	}
	return tx.Commit()
}
func (a *App) claimTransfer() (string, transferTask, error) {
	var task transferTask
	var id string
	tx, err := a.DB.Begin()
	if err != nil {
		return "", task, err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT job_id,payload FROM transfer_queue WHERE active=0 ORDER BY rowid")
	if err != nil {
		return "", task, err
	}
	type candidate struct {
		id      string
		payload []byte
	}
	items := []candidate{}
	for rows.Next() {
		var c candidate
		if err = rows.Scan(&c.id, &c.payload); err != nil {
			rows.Close()
			return "", task, err
		}
		items = append(items, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", task, err
	}
	for _, c := range items {
		if err = a.Unseal(c.payload, &task); err != nil {
			return "", task, err
		}
		var active, large int
		if err = tx.QueryRow("SELECT count(*),coalesce(sum(size>=1000000000),0) FROM transfer_queue WHERE active=1 AND profile_id=?", task.Snapshot.Profile.ID).Scan(&active, &large); err != nil {
			return "", task, err
		}
		if active >= defaultInt(task.Snapshot.Profile.SimultaneousTransfers, 2) || task.Snapshot.Size >= 1000000000 && large >= defaultInt(task.Snapshot.Profile.LargeFileTransfers, 1) {
			continue
		}
		id = c.id
		break
	}
	if id == "" {
		return "", task, errors.New("no transfer ready")
	}
	r, err := tx.Exec("UPDATE transfer_queue SET active=1 WHERE job_id=? AND active=0", id)
	if err != nil {
		return "", task, err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return "", task, errors.New("transfer claim conflict")
	}
	return id, task, tx.Commit()
}
func (a *App) transferWorker(ctx context.Context, index int) {
	name := fmt.Sprintf("transfer-%d", index)
	for ctx.Err() == nil {
		a.beat(name)
		id, task, err := a.claimTransfer()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		func() {
			var queuedAt string
			if a.DB.QueryRow("SELECT updated_at FROM jobs WHERE id=?", id).Scan(&queuedAt) == nil {
				if at, e := time.Parse(time.RFC3339Nano, queuedAt); e == nil {
					a.recordTiming(id, "transfer_wait", at)
				}
			}
			jobctx, cancel := context.WithTimeout(ctx, task.Snapshot.Profile.JobTimeout())
			defer cancel()
			done := make(chan struct{})
			defer close(done)
			go func() {
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-done:
						return
					case <-jobctx.Done():
						return
					case <-ticker.C:
						a.beat(name)
					}
				}
			}()
			defer func() { _, _ = a.DB.Exec("DELETE FROM transfer_queue WHERE job_id=?", id); os.Remove(task.Local) }()
			if m, e := a.loadMove(id); e == nil {
				a.finalizeMove(jobctx, id, task.Snapshot, m)
			} else {
				a.routeCapturedNow(jobctx, id, task.Snapshot, task.Local, task.Digest, task.Verdict, task.Rule, task.Reason)
			}
		}()
	}
}
