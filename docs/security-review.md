# Repository publication review — 20 October 2026

A Gitleaks v8.30.0 scan found **zero matches** in the 42 reachable Git commits available at the start of this review, covering all fetched branches/tags, and in the working directory. The final handoff changes are rescanned before pushing. No finding values or credentials are included in this report.

Additional checks:

- No tracked database, encryption master key, private key, or real `.env` file was found. `.env.example` contains host settings with empty TLS paths.
- Screenshot generation uses an isolated documentation instance with example storage names, placeholder credentials and a demonstration password. These are fixtures, not production credentials. Never use the fixture password for a real deployment.
- Current public-facing instructions use a generic host and `/srv` example paths rather than the operator's private IP address and home directory. Earlier Git revisions retain that non-secret environment information; it was not rewritten.
- A CI secret-scanning job scans full reachable history on pushes and pull requests with findings redacted.
- Data volumes, keys, database files, `.env`, logs and browser state must remain outside Git. Keep backups and real credentials private even when publishing the source.

These checks do not prove that no secret can exist. Pattern scanners may miss unknown formats, encrypted data and credentials inside binary media. GitHub issues, external attachments, Actions logs/artifacts, releases, forks and unreachable/deleted remote objects are outside this repository scan. Review those separately if they have been used for sensitive material. Repository visibility was not changed.

## Repeat before publication

Install the pinned scanner outside the repository, then run from the repository root:

```bash
go install github.com/zricethezav/gitleaks/v8@v8.30.0
git fetch --all --tags --prune
gitleaks git . --log-opts='--all' --redact=100
gitleaks dir . --redact=100
```

If a real credential is ever detected, revoke/rotate it first. Removing it from the current file does not remove it from history. Coordinate any history rewrite with other operators before force-pushing, then rescan all references and inspect GitHub-hosted artifacts. Do not paste a suspected value into an issue or chat.
