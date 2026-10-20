package core

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
)

// Session locks are released by PostgreSQL when a worker loses its connection.
func (s *Store) Permits(ctx context.Context, j Job, c Capacity) (func(), error) {
	conn, e := pgx.Connect(ctx, s.DB.Config().ConnConfig.ConnString())
	if e != nil {
		return nil, e
	}
	keys := []string{}
	release := func() {
		for _, k := range keys {
			_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtextextended($1,0))", k)
		}
		conn.Close(context.Background())
	}
	scopes := []struct {
		name string
		n    int
	}{{"global", c.Global}, {"tenant:" + j.Tenant, c.Tenant}, {"source:" + j.SourceID, j.Source.Concurrency}, {"profile:" + j.ProfileID, j.Profile.Concurrency}, {"job:" + j.ID, 1}}
	for _, scope := range scopes {
		acquired := false
		for n := 0; n < scope.n; n++ {
			key := fmt.Sprintf("%s:%d", scope.name, n)
			var ok bool
			e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&ok)
			if e != nil {
				release()
				return nil, e
			}
			if ok {
				keys = append(keys, key)
				acquired = true
				break
			}
		}
		if !acquired {
			release()
			return nil, fmt.Errorf("capacity unavailable: %s", scope.name)
		}
	}
	return release, nil
}
