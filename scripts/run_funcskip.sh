#!/usr/bin/env bash
# Intra-function instruction-skip sweep (capture-and-replay), parallel by default.
# Usage:  scripts/run_funcskip.sh [ELF] [N] [JOBS] [extra ucpqc args...]
#   ELF   firmware to analyse   (default: firmware/ml-dsa-44_m4f_test.elf)
#   N     signatures per key    (default: 12)
#   JOBS  worker count, 0=all CPUs, 1=serial   (default: 0)
# Add e.g.  --target y_sampler  or  --backend snapshot  as extra args.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/_venv.sh
PY="$(_pick_python)"

ELF="${1:-firmware/ml-dsa-44_m4f_test.elf}"
N="${2:-12}"
JOBS="${3:-0}"
shift $(( $# < 3 ? $# : 3 )) || true

exec "$PY" -m ucpqc funcskip "$ELF" --n "$N" -j "$JOBS" "$@"
