# Deployment and operations

## Required access

Supply a target Azure subscription, resource group and region, a registry image digest, a Vision One API key with the SDK scan permission, an Entra API application and a public SPA application. The host did not have Azure CLI or a logged-in subscription during implementation.

The private Sites console URL is a separate frontend deployment. Configure its connection dialog with the deployed Azure API origin, tenant ID, SPA client ID, and `api://<api-client-id>/Gateway.Access` delegated scope. Add the exact Sites origin as an Entra SPA redirect URI and API CONSOLE_ORIGIN. Enable v2 access tokens for the API application. Register Viewer/Admin user app roles and EventIngestor for the authorized Event Grid service principal; grant assignments explicitly. Do not assign EventIngestor to normal users. Confirm Event Grid's documented secure-webhook app-role assignment procedure before subscribing.

## Build and provision

```
docker build -t YOUR_REGISTRY/trendai-v1fs-scanner:VERSION backend
docker push YOUR_REGISTRY/trendai-v1fs-scanner:VERSION
az deployment group create --resource-group YOUR_RG --template-file infra/main.bicep --parameters @PRIVATE_PARAMETERS.json
```

Use an Azure-supported zone-redundant region. This configuration provisions paid PostgreSQL HA, Service Bus Premium, ZRS storage and private endpoints. Never commit PRIVATE_PARAMETERS.json. Supply passwords through a secure deployment system; Key Vault references deliver them to apps. For a private registry, add Container Apps registry managed-identity configuration and AcrPull on the registry; the supplied template assumes the image can already be pulled.

Run database migrations from inside the VNet using the same image with `MODE=migrate` and the Key Vault DATABASE_URL. Execute migrations before sending traffic; do not run schema changes on every API startup. The SQL bootstrap is idempotent for a fresh installation. Future changes require new numbered migrations and an upgrade runner.

Grant the managed identity Storage Blob Data Reader on each source account and the required Azure Files privileged reader role for backup-intent OAuth. Set up private endpoints and DNS for each source. Destination storage is private, shared-key access is disabled, and only the worker identity gets Blob Data Contributor. Keep downstream safe-container readers separate from quarantine; do not grant them account-wide storage roles. For strict separation, use separate destination accounts and identities rather than the single baseline destination account.

Create a profile in the console, then an enabled source with three distinct destination container URLs. Deploy `infra/eventgrid.bicep` against the source storage account after assigning Event Grid's Entra role. Confirm webhook validation. Existing source accounts may need Blob versioning enabled; use ETag conditions as the minimum replacement defense. For SFTP/ADLS configurations where versioning is unavailable, changed objects hold safely and producers must not replace files before processing finishes.

## Local development

Copy `.env.example` to `.env` and supply Entra and Azure development credentials. `docker compose up --build` starts PostgreSQL, a migration process and each service role. Service Bus and storage remain real Azure dependencies; this Compose file does not claim to emulate them. Authentication stays enabled locally. Build the console with `npm ci --prefix web && npm run build --prefix web`; serve `dist` on localhost:4173. Use test credentials with minimum privilege.

## Validation

```
cd backend
TEST_DATABASE_URL=postgres://USER:PASS@localhost:5432/TEST_DB?sslmode=disable go test -race ./...
go vet ./...
RUN_REAL_SDK_TEST=true TM_AM_AUTH_KEY=... TM_REGION=us-east-1 go test ./internal/adapters -run TestOfficialSDKIntegration
```

The database test truncates its tables: use a dedicated test database. It submits 2,000 concurrent discovery calls over 1,000 unique files and checks one job/outbox record per identity, revision conflicts and distributed permits. Scanner unit tests are simulated and carry no throughput claim. Real SDK tests require an explicit flag and credentials. Live SDK cost and quotas apply.

`scripts/load.py` drives real Event Grid ingestion using a manifest of existing uploaded blob identities. EVENT_INGEST_TOKEN must be an authorized short-lived Entra token. Use `--count 1000` for a burst, `--count 10000 --duration 3600` for hourly traffic, and `--count 50000 --duration 86400` for daily traffic. Unique source files are required to measure distinct-file work; cycling a short manifest measures duplicate handling. The script measures ingestion HTTP acceptance only. Separately verify destination digests, terminal counts, no malicious safe objects, memory and actual scan latency. Do not claim those load suites passed unless run end to end.

## Runbook

- Scanner outage: leave queue messages durable; bounded retries move jobs to HELD. Tune global limits conservatively to measured service quotas. This release has no global circuit breaker.
- Source replaced/deleted: hold/retry; restore the exact source version or discover the new ETag as a separate identity. Never manually force COMPLETED.
- Destination failure: preserve source, check IAM/network, then requeue the same job after remediation. Create-only routing verifies the existing digest.
- Poison messages: inspect the native `$DeadLetterQueue`, retain message/correlation evidence, fix the cause and replay deliberately. There is no automated replay tool yet.
- Lost completion event: set `v1fs-complete=true` only after Blob upload completion; for Azure Files renew `.complete` after a closed upload. Reconciliation rediscovers by immutable identity.
- Stale operations: reconciliation reissues jobs older than 15 minutes. PostgreSQL and Service Bus locks prevent ordinary concurrent processing. Investigate repeated stalls in JSON logs.
- Secrets: rotate Key Vault versions, wait for Container Apps secret refresh and restart workers to recreate SDK clients. Never log SDK DumpConfig. Revoke any token pasted into a chat after use.
- Recovery: restore PostgreSQL PITR into the same private network, pause ingestion, validate job/routing/outbox/audit consistency, verify stored destination digests, restart dispatch/consumers, and replay retained Event Grid events or completion-marked inventory. PostgreSQL is authoritative; never rebuild state solely from queue depth. Run a restore drill before production acceptance.

## Deployment status

Bicep syntax/type validation is distinct from an Azure what-if/deployment. No Azure resources have been created by this build without a subscription login. The console deployment does not activate scanning. See architecture.md for outstanding enterprise features and acceptance tests.
