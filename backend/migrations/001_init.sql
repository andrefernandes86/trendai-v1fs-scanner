CREATE TABLE IF NOT EXISTS settings (kind text NOT NULL, id text NOT NULL, value jsonb NOT NULL, revision bigint NOT NULL DEFAULT 1, PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS jobs (
 id text PRIMARY KEY, source_id text NOT NULL, tenant text NOT NULL, profile_id text NOT NULL,
 object_key text NOT NULL, version text NOT NULL, etag text NOT NULL, size bigint NOT NULL CHECK(size>=0),
 source_snapshot jsonb NOT NULL, profile_snapshot jsonb NOT NULL, state text NOT NULL, verdict text NOT NULL DEFAULT 'UNKNOWN', digest text NOT NULL DEFAULT '', result jsonb,
 revision bigint NOT NULL DEFAULT 1, attempts int NOT NULL DEFAULT 0, correlation_id text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(source_id,object_key,version,etag));
CREATE TABLE IF NOT EXISTS audit (seq bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), actor text NOT NULL, action text NOT NULL, object_id text NOT NULL, correlation_id text NOT NULL, detail jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS outbox (id bigserial PRIMARY KEY, job_id text NOT NULL REFERENCES jobs(id), queue text NOT NULL, payload jsonb NOT NULL, available_at timestamptz NOT NULL DEFAULT now(), sent_at timestamptz, UNIQUE(job_id,queue,payload));
CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(available_at) WHERE sent_at IS NULL;
CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state,updated_at);
CREATE TABLE IF NOT EXISTS routing (job_id text PRIMARY KEY REFERENCES jobs(id), destination text NOT NULL, digest text NOT NULL, completed_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS observations (source_id text NOT NULL, object_key text NOT NULL, etag text NOT NULL, size bigint NOT NULL, first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(source_id,object_key));
