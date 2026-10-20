# trendai-v1fs-scanner

A host-based Azure Blob, Azure Files, SMB and NFSv3 scanner with a React management console and the official Trend Vision One File Security Go SDK. The console and Go API run together. There is no external gateway, Event Grid, Service Bus, Azure deployment, or Entra setup requirement.

## Console workflow

1. Open the host URL and create the administrator password on first use.
2. **Storage connections:** choose Azure Blob, Azure Files, SMB or NFSv3. Azure uses account keys/SAS, SMB uses username/password/domain, and NFSv3 uses server/export plus UID/GID. Credentials are encrypted on the host and omitted from API responses. Test and browse each saved connection.
3. **Vision One config:** enter the API key. Choose **Cloud** and its region, or **Local** and the existing File Security gRPC service's `host:port`. Local TLS is configurable; certificate verification stays enabled with TLS.
4. **Scan profiles:** create multiple profiles, each with a source connection and separate good-file and bad-file destination connections/prefixes. Set detection options and optional automatic monitoring.
5. **Storage explorer:** browse real containers and shares, select a profile and up to 100 files, then submit scans. Follow verdicts and verified destinations in **File activity**.

Source, clean, and quarantine must be distinct containers or non-overlapping shares/exports. No automatic source deletion occurs. Unverified results stay HELD and never go to the good-file destination. Automatic monitoring runs every 30 seconds with stability observations and optional required `v1fs-complete=true` upload metadata for Blob or a fresh `filename.complete` sidecar for shares. The default profile requires the marker, including for manual requests; disable that option only if your producer's committed-upload contract is suitable.

## Run directly

```
npm ci --prefix web
npm run build --prefix web
cd backend
go build -o ../scanner ./cmd/local
cd ..
V1FS_DATA_DIR=./data V1FS_WEB_DIR=./dist PORT=8095 ./scanner
```

Open `http://HOST_IP:8095`. Use the host IP or localhost; arbitrary Host headers are rejected. The server can terminate HTTPS directly with V1FS_TLS_CERT and V1FS_TLS_KEY. Configure HTTPS before using this console across untrusted networks.

Alternatively run `docker compose up -d --build`; the persistent `scanner-data` volume contains the encrypted database and encryption key. Back up both together. An initialized database without its key is rejected.

## Verify

```
cd backend
go test -race ./...
go vet ./...
```

Tests cover secret encryption/redaction, authentication/session invalidation, cross-origin rejection, settings persistence, single-instance locking, concurrent duplicate submission, storage routing, source replacement, and replay without duplicate destination writes. Storage and scanner fixtures are simulated; they do not claim real Azure or Vision One throughput or credential validation. Production scanning uses real SDKs and no simulator is exposed in the console.

See [architecture](docs/architecture.md) and [operations](docs/operations.md).
