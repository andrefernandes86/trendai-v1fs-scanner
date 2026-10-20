package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type Store struct{ DB *pgxpool.Pool }

func (s *Store) Audit(ctx context.Context, tx pgx.Tx, actor, action, id, corr string, detail any) error {
	b, e := json.Marshal(detail)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO audit(actor,action,object_id,correlation_id,detail) VALUES($1,$2,$3,$4,$5)", actor, action, id, corr, b)
	return e
}
func (s *Store) Config(ctx context.Context, kind, id string, out any) error {
	var b []byte
	e := s.DB.QueryRow(ctx, "SELECT value FROM settings WHERE kind=$1 AND id=$2", kind, id).Scan(&b)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, out)
}
func (s *Store) List(ctx context.Context, kind string) ([]json.RawMessage, error) {
	r, e := s.DB.Query(ctx, "SELECT value FROM settings WHERE kind=$1 ORDER BY id", kind)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := []json.RawMessage{}
	for r.Next() {
		var b json.RawMessage
		if e = r.Scan(&b); e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, r.Err()
}
func (s *Store) Save(ctx context.Context, kind, id, actor string, value any) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO settings(kind,id,value) VALUES($1,$2,$3) ON CONFLICT(kind,id) DO UPDATE SET value=excluded.value,revision=settings.revision+1", kind, id, b)
	if e != nil {
		return e
	}
	if e = s.Audit(ctx, tx, actor, "configuration.updated", kind+":"+id, "", value); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) Discover(ctx context.Context, j Job) error {
	if !ValidKey(j.Key) || j.ETag == "" || j.Size < 0 {
		return errors.New("invalid immutable source identity")
	}
	if e := s.Config(ctx, "sources", j.SourceID, &j.Source); e != nil {
		return e
	}
	if e := s.Config(ctx, "profiles", j.ProfileID, &j.Profile); e != nil {
		return e
	}
	if !j.Source.Enabled {
		return errors.New("source disabled")
	}
	sb, _ := json.Marshal(j.Source)
	pb, _ := json.Marshal(j.Profile)
	j.ID = Identity(j.SourceID, j.Key, j.Version, j.ETag)
	j.CorrelationID = j.ID
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, "INSERT INTO jobs(id,source_id,tenant,profile_id,object_key,version,etag,size,source_snapshot,profile_snapshot,state,correlation_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'QUEUED',$1) ON CONFLICT DO NOTHING", j.ID, j.SourceID, j.Tenant, j.ProfileID, j.Key, j.Version, j.ETag, j.Size, sb, pb)
	if e != nil || tag.RowsAffected() == 0 {
		return e
	}
	for _, state := range []string{"DISCOVERED", "READY", "QUEUED"} {
		if e = s.Audit(ctx, tx, "ingestion", "state."+state, j.ID, j.ID, map[string]string{"etag": j.ETag, "version": j.Version}); e != nil {
			return e
		}
	}
	if e = s.Enqueue(ctx, tx, j.ID, "scan", 0); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) Enqueue(ctx context.Context, tx pgx.Tx, id, queue string, delay time.Duration) error {
	var rev int64
	if e := tx.QueryRow(ctx, "SELECT revision FROM jobs WHERE id=$1", id).Scan(&rev); e != nil {
		return e
	}
	b, _ := json.Marshal(map[string]any{"id": id, "revision": rev})
	_, e := tx.Exec(ctx, "INSERT INTO outbox(job_id,queue,payload,available_at) VALUES($1,$2,$3,now()+$4::interval) ON CONFLICT DO NOTHING", id, queue, b, fmt.Sprintf("%f seconds", delay.Seconds()))
	return e
}
func (s *Store) Job(ctx context.Context, id string) (Job, error) {
	var j Job
	var sb, pb []byte
	e := s.DB.QueryRow(ctx, "SELECT id,source_id,tenant,profile_id,object_key,version,etag,size,state,verdict,digest,revision,attempts,correlation_id,result,source_snapshot,profile_snapshot FROM jobs WHERE id=$1", id).Scan(&j.ID, &j.SourceID, &j.Tenant, &j.ProfileID, &j.Key, &j.Version, &j.ETag, &j.Size, &j.State, &j.Verdict, &j.Digest, &j.Revision, &j.Attempts, &j.CorrelationID, &j.Result, &sb, &pb)
	if e == nil {
		e = json.Unmarshal(sb, &j.Source)
		if e == nil {
			e = json.Unmarshal(pb, &j.Profile)
		}
	}
	return j, e
}
func (s *Store) Move(ctx context.Context, j *Job, to string, queue string, delay time.Duration) error {
	if !Transition(j.State, to, j.Verdict) {
		return fmt.Errorf("forbidden transition %s -> %s", j.State, to)
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, "UPDATE jobs SET state=$1,verdict=$2,digest=$3,result=$4,attempts=$5,revision=revision+1,updated_at=now() WHERE id=$6 AND revision=$7 AND state=$8", to, j.Verdict, j.Digest, j.Result, j.Attempts, j.ID, j.Revision, j.State)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("optimistic concurrency conflict")
	}
	if e = s.Audit(ctx, tx, "worker", "state."+to, j.ID, j.CorrelationID, map[string]string{"from": j.State, "verdict": j.Verdict}); e != nil {
		return e
	}
	if queue != "" {
		if e = s.Enqueue(ctx, tx, j.ID, queue, delay); e != nil {
			return e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	j.State = to
	j.Revision++
	return nil
}
