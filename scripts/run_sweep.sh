#!/usr/bin/env bash
# Whole-call fault sweep (ALAFA-style), parallel by default.
# Usage:  scripts/run_sweep.sh [ELF] [N] [JOBS] [extra ucpqc args...]
#   ELF   firmware to analyse   (default: firmware/ml-dsa-44_m4f_test.elf)
#   N     signatures per key    (default: 12)
#   JOBS  worker count, 0=all CPUs, 1=serial   (default: 0)
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/_venv.sh
PY="$(_pick_python)"

ELF="${1:-firmware/ml-dsa-44_m4f_test.elf}"
N="${2:-12}"
JOBS="${3:-0}"
shift $(( $# < 3 ? $# : 3 )) || true

exec "$PY" -m ucpqc sweep "$ELF" --n "$N" -j "$JOBS" "$@"
