#!/usr/bin/env bash
# Re-run a detector OFFLINE on a dumped sweep or funcskip capture (no emulator).
# Usage:  scripts/detect.sh DUMPDIR [extra ucpqc args, e.g. --detector structural]
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/_venv.sh
PY="$(_pick_python)"
DUMP="${1:?usage: scripts/detect.sh DUMPDIR [--detector X]}"
shift || true
exec "$PY" -m ucpqc detect "$DUMP" "$@"
