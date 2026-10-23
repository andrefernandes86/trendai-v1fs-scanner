# Configuration deletion regression — October 23, 2026

Storage connections expose a `kind` such as `blob`, `adls`, `azureFiles`, `smb` or `nfs`. Spreading that object after `{kind: "mounts"}` overwrote the intended API collection, sending DELETE to an unsupported route. The resulting plain-text 404 caused the browser JSON parsing error in the removal dialog.

Deletion now uses an explicit typed target containing only resource collection, ID and name. Connection type cannot overwrite the endpoint. The API client handles non-JSON responses with a readable HTTP-status message, and removal errors are local to the dialog and cleared on reopening/retry. Profile deletion retains history and encrypted snapshots.

The server also prevents deleting a connection referenced by scan-failed, regular/compressed oversized-file or rule destinations, in addition to source/clean/malicious destinations. Only active custom/routing references are considered.

Regression coverage verifies deletion of all five connection types and profiles on desktop/mobile, real DELETE URLs and responses, plain-text 404 handling, retry and cancellation, referenced-connection protection, and retention of historical snapshots. No production configuration or storage objects were removed by these tests.

Validation: full Go race suite passed (localapp: 109.541 seconds); Go vet and the TypeScript/production build passed; all 26 Playwright tests passed across desktop and mobile (1.8 minutes). The removal dialog layout is unchanged, so existing layout screenshots remain applicable.
