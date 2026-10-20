# Transfer and console validation — 20 October 2026

## Verified behavior

- Blob worker finalization performs one full destination read under a renewable lease, calculates SHA-256 and CRC32C together, applies result tags under that lease and conditionally deletes the source afterward.
- Corrupted readback prevents tagging and deletion. Retry reads the destination again before finalization.
- Independent transfer admission enforces per-profile total and large-file limits; queued transfers do not occupy scan slots.
- An engine restart discards temporary captures, preserves the persisted scan result and completes the verified move after recapturing the unchanged source without another SDK scan.
- A real background transfer worker drains its encrypted handoff and cleans the private capture.
- Recursive share discovery includes nested files for Azure Files, SMB and NFS and omits symlink traversal.
- Hidden records remain held/accounted and can be restored. Full CSV includes hidden records and stage timing JSON.

Backend tests, the full race suite and `go vet` passed. Additional targeted race tests cover the new background transfer drain and corruption/restart/visibility cases.

## Real service check

Using two unique private disposable Azure containers and generated samples:

| Sample | Final state | Checks |
| --- | --- | --- |
| Safe text | COMPLETED | SHA-256/CRC32C verified, native `scanned=true`, source absent |
| EICAR | QUARANTINED | SHA-256/CRC32C verified, native `scanned=true`, source absent |

Both disposable containers were removed. Production files and configuration were untouched. The check completed in about three seconds for these small samples; it does not establish large-file throughput.

## Console

Desktop and mobile browser checks cover the profile editor, archive controls, 1,000-record pagination/filtering, basic/advanced sizing, theme persistence through reload/sign-out, and dark form surfaces. Hide/restore flow is exercised with controlled history fixtures. Guide images were captured from a separate demonstration instance with placeholder credentials.

The transfer optimization reduces normal Blob routing payload traffic from approximately four file lengths to two (upload plus one readback). No post-change 1,000-file or 100 GB benchmark is claimed. Customer-sized soak/load validation remains pending.
