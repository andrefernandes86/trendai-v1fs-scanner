# Repository, documentation and credential review — October 21, 2026

## Scope and findings

Reviewed tracked files, all reachable Git history, GitHub repository visibility and CI results, current documentation and UI screenshots. No credentials were removed or rotated, and repository visibility was not changed.

GitHub reported this repository **public** during the review. Gitleaks v8.30.0 found **zero likely live secrets** in 61 reachable commits and a separate exported snapshot of tracked files. Manual inspection found the explicit synthetic passwords and credential fixtures listed below. This is a detection result, not proof that every possible secret is absent. Unreachable/deleted remote objects, external service credentials and GitHub encrypted Actions secret values are outside this review. Production credentials were not decrypted.

Only `.env.example` is tracked among environment/database/private-key filenames. It contains paths/port and empty TLS fields. Runtime `.env`, data databases, master keys and PEM/key files are ignored. The remote URL contains no token.

## Literal passwords and tokens retained for owner review

These values are test/demo fixtures, not verified live account credentials. They remain in source at the owner's request. Never reuse the published demo passwords in a deployment.

| Exact value | Location / purpose |
|---|---|
| `documentation-only-password` | `scripts/capture-guide.mjs:10`, `scripts/capture-acknowledgement.mjs:8`; isolated screenshot administrator |
| `test-only-password-2026` | `web/e2e/console.spec.ts:5` and other browser tests; isolated test administrator |
| `new-test-password-2026` | `web/e2e/account.spec.ts:8`; password-change fixture |
| `different-password-only` | `web/e2e/account.spec.ts:8`; intentional mismatch |
| `long-test-password` | `backend/internal/localapp/local_test.go:83`; setup/auth test |
| `other-password-123` | `backend/internal/localapp/local_test.go:97`; setup-rejection test |
| `password` | `backend/internal/localapp/shares_test.go:69`; SMB fixture |
| `sig=documentation-placeholder` | `scripts/capture-guide.mjs:12`; dummy Azure SAS |
| `sig=illustration-only` | `web/e2e/adls.spec.ts:7`; dummy Azure SAS |
| `sig=test-only` | `web/e2e/console.spec.ts:7`; dummy Azure SAS |
| `sv=2023-11-03&sp=rl&sig=private-signature` | `backend/internal/localapp/local_test.go:550`; SAS/redaction fixture |
| `sv=2023-11-03&sp=rl&sig=private-file-signature` | `backend/internal/localapp/shares_test.go:322`; Azure Files SAS/redaction fixture |
| `private-key`, `private-cloud-key` | `backend/internal/localapp/local_test.go:138`, `:311`; fake scanner credentials |
| `private-diagnostic-api-key` | `backend/internal/localapp/local_test.go:376`; diagnostic redaction fixture |
| `private-secret` | `backend/internal/localapp/scan_details_test.go:12`; encrypted response/redaction fixture |
| `Bearer sensitive` | `backend/internal/localapp/local_test.go:400`; authorization-redaction fixture |
| `secret-key` | `backend/internal/localapp/local_test.go:435`; authentication/redaction fixture |
| `test-key` | `backend/internal/localapp/manual_resolution_test.go:147`; scanner-change fixture |
| `secret`, `key`, `eicar` | Local/core diagnostic and validation tests; short placeholders, not real API keys |
| `integration-test-secret-key-00000` | `backend/internal/localapp/local_test.go`; input for a synthetic encoded storage key |

The SAS signatures also occur separately in assertion/error strings. These are the same dummy values. The literal `accountKey` in the UI is an authentication-mode identifier, not a credential.

## Validation and repairs

- Full Go race suite passed, including local application tests (131.354 seconds).
- Go vet passed. Frontend TypeScript/build passed.
- Browser suite: 21 of 22 initially passed. The mobile resource assertion tried to inspect a sidebar intentionally hidden at mobile width. Corrected the assertion to expand at desktop width and restore mobile width. Both desktop/mobile dashboard reruns passed, including the new memory labels. All 22 scenarios are covered by passing results across these runs.
- npm audit reported zero vulnerabilities.
- Go vulnerability scan using Go 1.27.3 reported no affected symbols. One imported-package and one required-module advisory were reported as not called by this code.
- GitHub's previous test job failed on 13 standard-library findings because `go-version-file` selected Go 1.27.0. Updated `backend/go.mod` to Go 1.27.3, matching the existing Docker builder and local toolchain. The vulnerability check remains enabled. The corrected GitHub run is [39721703369](https://github.com/andrefernandes86/trendai-v1fs-scanner/actions/runs/39721703369).
- Updated stale failure-label and upload-wait documentation. Current default upload wait is 10 seconds; existing saved profile settings remain intact.
- Refreshed guide screenshots using synthetic, paused configuration on an isolated instance. Added an upload-wait/retry screenshot and corrected disclosure screenshots so sticky wizard navigation does not cover their headings.
- Memory display now separates container usage, container limit, host total and host available RAM. Host capacity is not shown as a reserved container allocation.

## Decisions left to the owner

Choose whether to retain or replace the published test/demo literals and whether the repository should remain public. No secret removal, history rewriting, password rotation or visibility change was performed.

The memory-label correction was deployed after active scans and transfers reached zero; the production health check passed.
