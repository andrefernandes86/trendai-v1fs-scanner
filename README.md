# trendai-v1fs-scanner

Event-driven Azure file-security gateway with Go services, PostgreSQL job state, Azure Service Bus, official Trend Vision One File Security SDK v1.7.2 and a React/TypeScript console.

The console is deployable through Sites. Backend services require Azure Container Apps; a frontend deployment alone does not scan files. No fake operational data is seeded.

## Implemented

- Authenticated Event Grid completion ingestion and Azure Files completion-marker adapter.
- Immutable source/configuration snapshots, PostgreSQL transactional outbox, optimistic state transitions and audit trails.
- Distributed scan permits, message-lock renewal, bounded backoff and stale-job reconciliation.
- Real official SDK options, conservative verdict normalization, create-only clean/quarantine routing with SHA-256 verification.
- Entra roles, configuration validation, live SSE job-ledger dashboard and management console.
- Docker Compose, Bicep with private endpoints, CI, database burst tests, simulator tests and an opt-in real-SDK integration test.

## Start

Read [operations](docs/operations.md) for prerequisites, local development and Azure deployment. Read [architecture and known gaps](docs/architecture.md) before a production rollout. The baseline has not completed live Azure/Trend acceptance or the entire requested enterprise feature set.

```
npm ci --prefix web
npm run build --prefix web
cd backend
go test ./...
```

`.env.example` documents required settings. Never commit credentials. The Azure API requires Entra even in development. Simulator mode is accepted only with `ENVIRONMENT=test` and routing is disabled.
