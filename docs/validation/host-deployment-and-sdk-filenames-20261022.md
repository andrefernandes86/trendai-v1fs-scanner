# Host persistence and SDK filename validation — October 22, 2026

## Host deployment

Validated the documented Docker run restrictions (read-only root filesystem, tmpfs, dropped capabilities, no-new-privileges, explicit UID/GID, restart policy and host bind mount) against an isolated instance on port 18098. Used a temporary host directory with matching ownership; production data was not used.

Created an administrator and a synthetic storage connection, stopped and removed the container, recreated it with the same host directory, and signed in using the same password. The saved connection remained present. Docker inspection confirmed a `bind` mount targeting `/data`; the health check passed after replacement.

Rendered `compose.yaml` plus `compose.host.yaml` with `V1FS_HOST_DATA_DIR=/srv/trendai-v1fs-data`, `SCANNER_UID=65532` and `SCANNER_GID=65532`. Verified user `65532:65532`, mount type `bind`, source `/srv/trendai-v1fs-data` and target `/data`.

## Original SDK filename

The SDK previously received a local capture path through `ScanFileWithContext`, so Vision One displayed `/data/captures/scan-*`. The app now supplies the original source key as the SDK reader identifier, independently of the local captured-file path. The identifier is carried through the isolated scan-child request. The reader uses the same captured file; there is no extra disk copy or whole-file memory buffer.

The unit check confirms that a logical name containing a folder and spaces reads bytes and size from the private capture. The existing disabled-local-archive test confirms the original ZIP name reaches the scan call. An opt-in real cloud SDK scan of harmless text confirmed `fileName: reports/original-filename-validation.txt` in the response. No stored scanner credentials were logged or changed. Existing Vision One history retains the old filename; the change applies to new scan submissions.

The new fixture initially expected an incorrect byte count; corrected it to derive the expected size from the fixture content. The corrected targeted and live checks passed.

## Container publication

The Publish container workflow builds the clean repository Dockerfile for Linux amd64. It publishes `latest` and `sha-FULL_COMMIT_SHA` after successful main-branch push CI or an explicit manual dispatch. Pull-request/fork workflow runs cannot publish. Login uses only the Actions-provided token, with contents-read/packages-write permissions. The image does not mount or copy production data.

GHCR package visibility must be verified separately from successful upload. GitHub documents that newly published packages default to private. A public source repository does not establish anonymous image access. See the publication instructions in the operations guide.
