#!/usr/bin/env bash
# Run the ucpqc test suite (includes the serial-vs-parallel parity test).
# Usage:  scripts/run_tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/_venv.sh
PY="$(_pick_python)"
exec "$PY" tests/run_tests.py
