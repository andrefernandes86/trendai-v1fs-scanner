#!/usr/bin/env bash
set -euo pipefail
scanner_url=${V1FS_URL:-http://127.0.0.1:8095}
curl --fail --silent --show-error --max-time 10 "$scanner_url/healthz"
# For business-processing alerts, an authorized monitoring agent should poll /api/assurance
# using an authenticated session. Health alone does not assert scanner/storage availability.
