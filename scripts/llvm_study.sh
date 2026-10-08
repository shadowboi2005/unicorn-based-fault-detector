#!/usr/bin/env bash
# LLVM-IR -> ARM-binary fault-leakage translation study (Dilithium / ML-DSA-44):
# capture ONCE, replay every Dilithium target from the cache, then build the
# comparison report report/llvm_vs_arm.md (+ region plots).
# Usage:  scripts/llvm_study.sh [N] [JOBS]
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/_venv.sh
PY="$(_pick_python)"
ELF=firmware/ml-dsa-44_m4f_test.elf
N="${1:-40}"; JOBS="${2:-14}"
echo ">> [1/3] capturing all targets once (n=$N, -j$JOBS)"
"$PY" -m ucpqc capture "$ELF" --n "$N" -j "$JOBS" --out captures
echo ">> [2/3] replaying each target from the cache (no re-signing)"
TARGETS=$("$PY" -c "from ucpqc.profiles import dilithium_targets as d; print(' '.join(d.TARGETS))")
mkdir -p dumps/run_log
for t in $TARGETS; do
  echo "   $t"
  "$PY" -m ucpqc funcskip "$ELF" --target "$t" --captures captures --detector per_coord \
      --dumpdir dumps 2>&1 | tee "dumps/run_log/$t.log" | grep -E "leaking|dumped" | tail -2 || true
done
echo ">> [3/3] building report/llvm_vs_arm.md + plots"
"$PY" scripts/build_llvm_report.py
echo "done -> report/llvm_vs_arm.md"
