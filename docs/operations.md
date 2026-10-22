# Operations

Build/run instructions are in the root README. The current host listens on port 8095. Set `V1FS_DATA_DIR`, `V1FS_WEB_DIR` and `PORT`; optionally configure `V1FS_TLS_CERT` and `V1FS_TLS_KEY`. Use HTTPS for remote credential administration. The app accepts localhost or host-IP requests and checks request origins.

## Permissions and persistence

Source credentials need list/read/delete. Destination credentials need write/read and, for Blob result tags, tag permissions. Share destinations need directory creation, exclusive publication and staging cleanup. NFS needs hard-link support. Container/share discovery can require additional account/server permissions even if a known share is readable.

Back up the SQLite database, its WAL consistently, and master.key together using a coordinated backup or stopped service. Do not commit runtime data or credentials. A database without its key cannot be decrypted. Persistent data must survive upgrades; never reinitialize it to resolve configuration errors.

The current host runs the supervised Docker container with restart policy and persistent data. Do not start a second scanner against its database.

## Troubleshooting

- No scheduled jobs: verify automatic monitoring is enabled; read the profile's last source check and errors. Wait for a second unchanged observation. Completion markers are no longer required.
- Source-changed errors: verify actual concurrent writes; Azure ETag quotation differences are normalized.
- Unknown result: inspect File activity. Unknown files route to scan-failed and remain HELD for review, never clean.
- Transfer failure: verify destination read/write/tag permissions and staging support. Source is retained until verified transfer.
- Source deletion failure: verify delete permission and whether the file changed. The record retains its verified destination.
- SMB List shares failure with Test share success: share enumeration uses server RPC/IPC permissions and may be blocked independently of direct share access; discovery now strips the TCP port from the SRVSVC server name and explains enumeration permission failures.

Generated safe/EICAR test files enter the configured source and use the real monitor/scanner/routing pipeline. EICAR is a standard antivirus test pattern and is never executed. Diagnostic scanner buttons operate separately from routing. Test requests and responses redact credentials.

Existing unknown files created before the verbose TrendX parsing fix are historical results. Re-upload a copy to the source to scan under the fixed logic; delivered files are not rescanned in place. Record refresh reloads saved history only. Do not label old unknown records clean without rescanning their exact bytes.

## Container-first host deployment

Use a Linux host with Docker Engine, Docker Compose, outbound access to the configured storage/scanner, and enough free disk for active file captures. Run the commands below on the Docker host. Enable Docker at boot with `sudo systemctl enable --now docker` on a systemd host.

**Recommended: bind `/data` to an absolute host directory.** Everything needed to retain settings and work belongs in this directory: the encrypted SQLite database, `master.key`, queue/history, transfer evidence and temporary captures. Removing or replacing the container must not replace this directory.

### 1. Pull the published image

The published image targets **Linux amd64**. On an amd64 Docker host:

```bash
docker pull ghcr.io/andrefernandes86/trendai-v1fs-scanner:latest
```

`latest` is the current release. For a fixed version, use `ghcr.io/andrefernandes86/trendai-v1fs-scanner:sha-FULL_COMMIT_SHA` instead. Every publication has a commit-specific tag.

To build from source instead:

```bash
git clone https://github.com/andrefernandes86/trendai-v1fs-scanner.git
cd trendai-v1fs-scanner
docker build -t ghcr.io/andrefernandes86/trendai-v1fs-scanner:latest .
```

### 2. Create the host data directory — new installation only

```bash
sudo install -d -m 0700 -o 65532 -g 65532 /srv/trendai-v1fs-data
```

This directory must be on a persistent filesystem with sufficient free space. The example runs the scanner as UID/GID `65532:65532`. For an **existing installation**, keep its existing directory and owner; do not create an empty replacement or change ownership blindly.

### 3. Start with Docker and an explicit host mount

```bash
docker run -d \
  --name trendai-v1fs-scanner \
  --restart unless-stopped \
  --init \
  --stop-timeout 40 \
  --user 65532:65532 \
  --read-only \
  --tmpfs /tmp:size=512m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 8095:8095 \
  -e PORT=8095 \
  -e V1FS_DATA_DIR=/data \
  -e V1FS_WEB_DIR=/app/dist \
  -v /srv/trendai-v1fs-data:/data \
  ghcr.io/andrefernandes86/trendai-v1fs-scanner:latest
```

Open `http://HOST_IP:8095`, create your own administrator password, then configure storage, Vision One and a scan profile. Use HTTPS through a reverse proxy or the optional TLS parameters below before administering credentials across an untrusted network.

| Parameter | Meaning / value to change |
|---|---|
| `-v /srv/trendai-v1fs-data:/data` | Left side is the **persistent directory on the host**. Right side is the application's directory inside the container. Change only the left side when choosing a different host location. |
| `-e V1FS_DATA_DIR=/data` | Must match the right side of the data mount. Keep `/data` for these examples. |
| `--user 65532:65532` | Must match the UID/GID owning the host directory. For existing data, use `stat -c '%u:%g' /path/to/existing-data`. |
| `-p 8095:8095` | Host port is on the left. For host port 8096, use `-p 8096:8095`; keep `PORT=8095` inside the container. |
| `--restart unless-stopped` | Restart on failure and host reboot when Docker starts; an explicitly stopped container stays stopped. |
| `--read-only`, `--tmpfs /tmp:...` | Keep the container filesystem read-only while providing writable temporary space. Persistent writes go to the mounted `/data`. |
| `--name trendai-v1fs-scanner` | Name used by the Docker run health, backup and upgrade commands below. |

The data mount does **not** mount Azure, SMB or NFS destinations. Configure those remote connections in the console; they use their network connectors. Do not put unrelated customer uploads or backups inside `/data/captures`; that workspace is cleaned by the engine.

Optional direct HTTPS: add these parameters to the same `docker run` command. Certificate files must be readable by the selected container UID.

```bash
-v /srv/trendai-v1fs-tls:/tls:ro \
-e V1FS_TLS_CERT=/tls/server.crt \
-e V1FS_TLS_KEY=/tls/server.key
```

Then use `https://HOST_IP:8095` with a certificate valid for the hostname/IP you use. Do not copy private keys into the image or repository.

### Compose alternative — use instead of Docker run

Obtain the Compose files first with `git clone https://github.com/andrefernandes86/trendai-v1fs-scanner.git` and `cd trendai-v1fs-scanner` (or enter your existing checkout). This alternative uses the **same host directory**, not the default named volume. Docker Compose must support the `!override` volume syntax in `compose.host.yaml`.

```bash
export V1FS_HOST_DATA_DIR=/srv/trendai-v1fs-data
export SCANNER_UID=65532
export SCANNER_GID=65532
docker pull ghcr.io/andrefernandes86/trendai-v1fs-scanner:latest
docker tag ghcr.io/andrefernandes86/trendai-v1fs-scanner:latest trendai-v1fs-scanner:current
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml config
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml up -d --no-build
```

The rendered configuration must show a bind mount with `source: /srv/trendai-v1fs-data` and `target: /data`. Re-export these variables in a new shell before running Compose commands. The Compose container is named `trendai-v1fs-scanner-1`; it is different from the Docker run name above. **Do not run both deployments against the same data or source folders.**

Without `compose.host.yaml`, `docker compose -p trendai-v1fs up -d --build` uses the Docker-managed `scanner-data` named volume instead. That is persistent but does not use your chosen `/srv` directory. Do not switch between these methods on an existing installation without migrating the entire data directory and its ownership while the scanner is stopped.

### 4. Verify the data mount and service

For the Docker run deployment:

```bash
docker inspect trendai-v1fs-scanner --format '{{range .Mounts}}{{println .Type .Source "->" .Destination}}{{end}}'
docker exec trendai-v1fs-scanner /app/scanner -healthcheck
docker logs --tail 100 trendai-v1fs-scanner
curl --fail http://127.0.0.1:8095/livez
```

Confirm the inspection output contains `bind /srv/trendai-v1fs-data -> /data`. For Compose, substitute `trendai-v1fs-scanner-1` in these commands. Use HTTPS and the configured port if you changed them. Health checks validate the local API/engine, not remote credentials; use the console storage/scanner tests and then a safe/EICAR routing test.

### 5. Upgrade without losing settings or history

1. Wait for active scans/transfers to finish, then stop the scanner. Use the backup procedure below before replacing its image.
2. Record the running image for rollback: `docker tag "$(docker inspect --format '{{.Image}}' trendai-v1fs-scanner)" trendai-v1fs-scanner:previous`. For Compose, use the container name `trendai-v1fs-scanner-1`.
3. Pull the new release with `docker pull ghcr.io/andrefernandes86/trendai-v1fs-scanner:latest`. For a source build, pull the source and rebuild the same image tag.
4. For Docker run: remove only the stopped container with `docker rm trendai-v1fs-scanner`, then repeat the full Docker run command above with the **same host path and UID/GID**.
5. For Compose: export the same host path/UID/GID, retag the pulled image as `trendai-v1fs-scanner:current`, then run the same two-file `up -d --no-build` command. This recreates the service while retaining its bind mount.
6. Sign in with the existing administrator password. Confirm that saved connections, profiles and history remain. Run the health check.

Never use `docker compose down -v` as an upgrade step. Never delete the host data directory, `master.key`, SQLite files or transfer/claim evidence to repair a startup error. To roll back the image, tag `trendai-v1fs-scanner:previous` as `ghcr.io/andrefernandes86/trendai-v1fs-scanner:latest` (and as `trendai-v1fs-scanner:current` for Compose), then recreate with the same data mount without pulling again. Restore a coordinated backup only if a database schema downgrade requires it.

### Backup and restore — keep the database and key together

These commands are for the Docker run deployment. For Compose, substitute `trendai-v1fs-scanner-1` in stop/start commands. Backups contain credentials and must remain private.

```bash
sudo install -d -m 0700 /srv/trendai-v1fs-backups
docker stop trendai-v1fs-scanner
sudo sh -c 'umask 077; tar -C /srv -czpf "/srv/trendai-v1fs-backups/scanner-$(date +%Y%m%d-%H%M%S).tar.gz" trendai-v1fs-data'
docker start trendai-v1fs-scanner
```

The stopped-service archive includes the entire data directory, including SQLite/WAL files and `master.key`, and preserves ownership. Copy the archive to your protected backup storage. A database backup without the matching key cannot decrypt the saved configuration.

To restore, stop the scanner, preserve the current data directory separately, and extract the chosen archive under `/srv` with `sudo tar -xzpf BACKUP.tar.gz -C /srv`. Verify the restored directory owner matches the container UID/GID before starting. Restore into an empty target location; do not overlay a live or partly restored database. Start with the same mount and sign in with the credentials from that backup.

## Deploy on the current host

For an existing deployment, use its **actual existing** host data path and owner, not the new-installation example values. In the repository:

```bash
export V1FS_HOST_DATA_DIR=/absolute/path/to/existing/scanner-data
export SCANNER_UID=$(stat -c '%u' "$V1FS_HOST_DATA_DIR")
export SCANNER_GID=$(stat -c '%g' "$V1FS_HOST_DATA_DIR")
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml config
docker compose -p trendai-v1fs -f compose.yaml -f compose.host.yaml up -d --build
```

A fresh setup screen where an existing login is expected means the wrong or empty data directory was mounted. Stop the new container and correct the mount; do not initialize another administrator over the wrong state. Do not start a direct binary or systemd service alongside the container against the same data.

## Runtime controls

Set **Schedule → Files scanned at once** in each profile (1–32). Worker capacity follows saved profile settings live; `V1FS_MAX_WORKERS` is ignored. Transfers have their own profile-controlled pool. Lowering limits lets active work finish.

The supervisor restarts the API and engine independently. `/livez` reports API/database liveness plus engine state; Docker health requires both services. Storage/scanner outages use normal retries, not liveness restarts. Share sources require read, rename, mkdir and delete rights; reserve `.v1fs-claims` for the scanner and never clear active claims manually.

## Large files

The old 2 GiB application cap is removed. Profiles default to 100 GB original-file SDK submission, one concurrent file at least 1 GB and a six-hour per-attempt deadline. See [profile controls and resource behavior](poc-architecture.md#large-files-and-policy). The scanner may inspect selected ranges and impose format/extraction limits; successful submission is not proof of exhaustive byte/member coverage.

Use a persistent data disk with space for simultaneous captures, history and operational reserve. Capacity admission retains 5 GiB and defers capture when insufficient. The implementation conservatively also counts outstanding reservations, so it may wait before physically exhausting disk. Oversized routing still needs room to capture that file; changing the policy does not provision disk. A host with 170 GiB free cannot process two simultaneous 100 GB captures. Configure the large-file cap accordingly.

On engine restart, only its private captures directory is cleaned; scans re-download interrupted sources. Source and verified move records remain durable. Do not put customer uploads/backups in the engine-owned captures directory. An interruption during a large download can therefore incur another transfer; budget network/retry time accordingly.

The processing-deadline alert is separate from the maximum job duration. Set the alert high enough for expected large-file work while keeping a bounded per-attempt timeout. Disk shortage waits do not consume the scan attempt budget. Existing held/retry jobs retain their captured policy; new size-policy changes apply to newly queued work.

To investigate a file: search its name in File activity, inspect state, attempts, scan response and destination evidence. SCANNING includes source capture before SDK invocation. A terminal record and verified destination, rather than disappearance from the source alone, are the completion evidence.

## Archive inspection operations

See [archive limits and sandbox prerequisites](archive-inspection.md). The optional local archive-inspection feature is hidden and disabled; its implementation is retained for future review. No extra capabilities are required; Landlock and seccomp must be available. Unavailable confinement fails closed. Reserve original capture plus the configured expansion budget. Full SDK/member responses live in encrypted detail records; activity uses compact encrypted summaries. Workspace directories are engine-owned and removed after work or on restart. Profile changes do not rewrite queued snapshots.

## Transfer worker controls

Transfer workers follow saved profile limits (1–10) live, independently of scan capacity. The legacy `V1FS_TRANSFER_WORKERS` environment variable is ignored; remove it from older deployment files. Profile transfer settings govern destination concurrency and Azure Blob block/request tuning. Lowering limits affects subsequent admissions. See [performance tuning](performance-tuning.md). A restart preserves the database/key volume and reconciles incomplete moves; an unuploaded temporary capture may be downloaded again. It does not delete history. Theme preferences live in each browser.

## Publishing the container

The **Publish container** GitHub Actions workflow builds the clean repository Dockerfile after a successful **Build and correctness** run on `main`, or when manually dispatched. It publishes `latest` and `sha-FULL_COMMIT_SHA` to GHCR using the workflow's `GITHUB_TOKEN` with `packages: write`; no registry password belongs in source.

For the first publication, the package owner must set **Package settings → Change visibility → Public**. Repository visibility does not by itself make a new container package public. Verify access with `docker --config /tmp/empty-docker-config pull ghcr.io/andrefernandes86/trendai-v1fs-scanner:latest` using an empty Docker configuration. See [GitHub container registry visibility](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

## Bash-enabled image

Use `ghcr.io/andrefernandes86/trendai-v1fs-scanner:bash` when an interactive shell is needed. It runs the same scanner, remains non-root by default, and includes `/bin/bash`, curl and process tools. The standard `latest` image remains shell-free. Both variants require durable data storage for retained state.

```bash
docker pull ghcr.io/andrefernandes86/trendai-v1fs-scanner:bash
```

Use the full deployment command above with `:bash` as the image tag. Leave the scanner startup command unchanged; Bash is an additional exec session, not the container's main command.

On ACI, use **Containers → Connect → /bin/bash → Connect**, or run this from Azure Cloud Shell:

```bash
az container exec \
  --resource-group YOUR_RESOURCE_GROUP \
  --name YOUR_CONTAINER_GROUP \
  --exec-command /bin/bash
```

Application logs remain available through the Azure **Logs** tab or `az container logs --resource-group YOUR_RESOURCE_GROUP --name YOUR_CONTAINER_GROUP --follow`.

**Existing ACI default-storage deployments:** switching images requires a lifecycle operation that can lose local state. Back up the existing `/data` before replacing that container. Do not assume a Bash image makes ACI's default storage persistent.

For a source build: `docker build --target bash -t scanner:bash .`. A build without `--target bash` still produces the standard minimal image.
