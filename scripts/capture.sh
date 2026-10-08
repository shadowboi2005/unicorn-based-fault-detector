#!/usr/bin/env bash
# Build a persistent funcskip CAPTURE CACHE: one 2N-signing pass that records every
# target function's I/O, so `funcskip --captures DIR` later replays any target with no
# re-signing (reused across targets, reruns and sessions).
# Usage:  scripts/capture.sh [ELF] [N] [JOBS] [OUT] [extra ucpqc args...]
#   ELF   firmware               (default: firmware/ml-dsa-44_m4f_test.elf)
#   N     signatures per key     (default: 40)
#   JOBS  worker count, 0=all    (default: 0)   [free-threaded 3.14t for real parallelism]
#   OUT   cache directory        (default: captures)
# Add e.g.  --target poly_add  to capture a single function.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/_venv.sh
PY="$(_pick_python)"
ELF="${1:-firmware/ml-dsa-44_m4f_test.elf}"
N="${2:-40}"
JOBS="${3:-0}"
OUT="${4:-captures}"
shift $(( $# < 4 ? $# : 4 )) || true
exec "$PY" -m ucpqc capture "$ELF" --n "$N" -j "$JOBS" --out "$OUT" "$@"
