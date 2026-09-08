#!/usr/bin/env bash
# Compatibility entrypoint. Exit 0 now means APPROVED under a pinned policy.
# Old V1-V9 scores and --v6 never grant approval. See references/acceptance.md.
set -euo pipefail
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify.py" "$@"
