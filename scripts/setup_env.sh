#!/usr/bin/env bash
# Set up the standard Python environment (.venv) for ucpqc.
# Usage:  scripts/setup_env.sh        # override interpreter with PYTHON=python3.12
#
# The multiprocessing sweep backend needs no special interpreter -- any CPython
# 3.10+ works. (The free-threading backend, on the parallel-freethreading branch,
# has its own setup_env.sh that builds a no-GIL .venv314t instead.)
set -euo pipefail
cd "$(dirname "$0")/.."

VENV=.venv
PY="${PYTHON:-python3}"

echo ">> creating $VENV with $PY ($("$PY" --version 2>&1))"
"$PY" -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip >/dev/null

echo ">> installing requirements + plotting extras (scipy, matplotlib)"
"$VENV/bin/pip" install -r requirements.txt scipy matplotlib

echo ">> verifying"
"$VENV/bin/python" -c "import unicorn, numpy, capstone, elftools; \
print('OK  unicorn', unicorn.__version__, ' numpy', numpy.__version__)"

echo
echo "Done. Run the sweep with:  scripts/run_sweep.sh"
echo "     or the test suite:    scripts/run_tests.sh"
