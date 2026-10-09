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
# how many targets to replay concurrently x threads each (PT*PJ ~= cores); the captures
# are cached, so replay is cheap and we fan out ACROSS targets to use all cores.
PT="${PT:-5}"; PJ="${PJ:-4}"

if [ -f captures/manifest.json ]; then
  echo ">> [1/3] capture cache present -> skipping capture (rm -rf captures to rebuild)"
else
  echo ">> [1/3] capturing all targets once (n=$N, -j$JOBS)"
  "$PY" -m ucpqc capture "$ELF" --n "$N" -j "$JOBS" --out captures
fi

echo ">> [2/3] replaying the ${PT}-at-a-time, -j$PJ each, from the cache (no re-signing)"
# only targets actually reached during signing (A>0); the rest are inlined/verify-only in m4f
TARGETS=$("$PY" -c "import json; from ucpqc.profiles import dilithium_targets as d; \
m=json.load(open('captures/manifest.json'))['targets']; \
print(' '.join(t for t in d.TARGETS if m.get(t,{}).get('A',0)>0))")
mkdir -p dumps/run_log
printf '%s\n' $TARGETS | xargs -P "$PT" -I{} bash -c '
  t="$1"
  '"$PY"' -m ucpqc funcskip '"$ELF"' --target "$t" --captures captures --detector per_coord \
      -j '"$PJ"' --dumpdir dumps > dumps/run_log/"$t".log 2>&1 \
    && echo "   done $t -> $(grep -oE "[0-9]+ leaking site" dumps/run_log/$t.log | head -1)" \
    || echo "   FAILED $t"
' _ {}

echo ">> [3/3] building report/llvm_vs_arm.md + plots"
"$PY" scripts/build_llvm_report.py
# plots need matplotlib: use .venv (3.12) which has it, falling back to $PY
PLOTPY=".venv/bin/python"; [ -x "$PLOTPY" ] || PLOTPY="$PY"
"$PLOTPY" scripts/plot_regions.py || echo "   (plots skipped -- matplotlib unavailable)"
echo "done -> report/llvm_vs_arm.md"
