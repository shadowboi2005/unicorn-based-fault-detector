#!/usr/bin/env bash
# One-command baseline-vs-hardened candidate comparison for ucpqc.
#
#   scripts/cm_compare.sh BASE_ELF HARDENED_ELF [SCHEME]
#
# Runs the SAME funcskip candidate sweep on two firmware builds into separate dump dirs,
# then writes a per-build candidate report for each plus a diff (report/cm_compare.md)
# showing which fault candidates a countermeasure closes / leaves / newly introduces.
# The framework stays a candidate LOCATOR -- this only compares candidate counts.
#
# Env knobs:
#   N        signings/key              (default 24)
#   RB       per-replay insn budget    (default 500000)
#   J        funcskip -j jobs          (default 1; needs a free-threaded venv)
#   TARGETS  "a b c" to limit targets  (default: all sign-path targets from the profile)
#   OUTDIR   dump root                 (default runs)
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=/dev/null
source scripts/_venv.sh
PY="$(_pick_python)"

BASE_ELF="${1:?usage: cm_compare.sh BASE_ELF HARDENED_ELF [SCHEME]}"
HARD_ELF="${2:?usage: cm_compare.sh BASE_ELF HARDENED_ELF [SCHEME]}"
SCHEME="${3:-}"
N="${N:-24}"; RB="${RB:-500000}"; J="${J:-1}"; OUTDIR="${OUTDIR:-runs}"; REPORTDIR="${REPORTDIR:-report}"

jflag=(); [ "$J" != "1" ] && jflag=(-j "$J")

# --- target set: explicit TARGETS env, else all sign-path targets from the profile ---
if [ -n "${TARGETS:-}" ]; then
    read -r -a TGTS <<< "${TARGETS//,/ }"
else
    echo ">> listing sign-path targets from the profile ..."
    mapfile -t TGTS < <("$PY" - "$BASE_ELF" "$SCHEME" <<'PY'
import sys
sys.path.insert(0, ".")
elf, scheme = sys.argv[1], (sys.argv[2] or None)
from ucpqc import Machine, Scheme, profiles
sch = Scheme.bind(Machine.from_elf(elf))
prof = profiles.profile_for(sch)
for t in sorted(prof.targets().keys()):
    print(t)
PY
)
fi
[ "${#TGTS[@]}" -gt 0 ] || { echo "no targets (pass TARGETS=\"a b c\")"; exit 1; }
echo ">> ${#TGTS[@]} target(s): ${TGTS[*]}"

sweep() {   # sweep <tag> <elf>
    local tag="$1" elf="$2" db="$OUTDIR/$1/dumps" t
    mkdir -p "$db"
    echo ">> sweeping '$tag' ($elf) -> $db   (n=$N rb=$RB jobs=$J)"
    for t in "${TGTS[@]}"; do
        if "$PY" -m ucpqc funcskip "$elf" --target "$t" --dumpdir "$db" \
                --n "$N" --replay-budget "$RB" "${jflag[@]}" >/dev/null 2>&1; then
            echo "   ok   $t"
        else
            echo "   skip $t (not reachable / failed)"
        fi
    done
}

btag="$(basename "${BASE_ELF%.elf}")"
htag="$(basename "${HARD_ELF%.elf}")"
# keep dirs/report names distinct even when the two ELFs share a basename
# (the established pattern for a variant build is a parallel dir, same filename)
if [ "$btag" = "$htag" ]; then btag="base-$btag"; htag="hard-$htag"; fi

sweep "$btag" "$BASE_ELF"
sweep "$htag" "$HARD_ELF"

echo ">> building per-build reports + diff ..."
"$PY" scripts/cm_compare.py "$OUTDIR/$btag/dumps" "$OUTDIR/$htag/dumps" \
    --base-elf "$BASE_ELF" --hardened-elf "$HARD_ELF" \
    --base-tag "$btag" --hardened-tag "$htag" --outdir "$REPORTDIR" \
    ${SCHEME:+--scheme "$SCHEME"}
echo ">> done -> $REPORTDIR/cm_compare.md (+ candidates_${btag}.md, candidates_${htag}.md)"
