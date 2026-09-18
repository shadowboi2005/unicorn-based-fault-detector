#!/usr/bin/env bash
# Set up the free-threaded (no-GIL) Python 3.14t environment for the parallel
# fault-analysis sweep: creates .venv314t and installs every dependency.
#
# Why this is not just `pip install -r requirements.txt`:
#   * needs a *free-threaded* interpreter (python3.14t, Py_GIL_DISABLED);
#   * Debian strips bundled pip, so `ensurepip` fails and pip is bootstrapped;
#   * unicorn's published 2.1.4 wheel is abi3, which is tag-incompatible with
#     free-threading (pip rejects it) and a source build trips setuptools#4420 --
#     but the package is pure ctypes + a bundled libunicorn.so, so its 2.1.4
#     files run unchanged on 3.14t. We fetch the abi3 wheel (forcing tags) and
#     install its contents.
#
# Usage:  scripts/setup_env.sh        # build .venv314t
set -euo pipefail
cd "$(dirname "$0")/.."

VENV=.venv314t
PY=python3.14t

if ! command -v "$PY" >/dev/null 2>&1; then
    echo "error: '$PY' not found. Install the free-threaded CPython 3.14 build:"
    echo "    sudo apt install python3.14-nogil        # Debian/Ubuntu (deadsnakes PPA)"
    echo "  or build one with pyenv:  pyenv install 3.14t-dev"
    exit 1
fi

echo ">> creating $VENV with $PY"
rm -rf "$VENV"
"$PY" -m venv "$VENV" || true            # ensurepip may fail on Debian; venv still made

if ! "$VENV/bin/python" -m pip --version >/dev/null 2>&1; then
    echo ">> bootstrapping pip (ensurepip is stripped on Debian)"
    curl -fsSL https://bootstrap.pypa.io/get-pip.py | "$VENV/bin/python"
fi

echo ">> installing free-threaded wheels: numpy scipy sympy capstone pyelftools"
"$VENV/bin/pip" install --only-binary=:all: numpy scipy sympy capstone pyelftools

echo ">> installing unicorn 2.1.4 (abi3 wheel contents; pure ctypes)"
SP="$(echo "$VENV"/lib/python3.14t/site-packages)"
if ! "$VENV/bin/pip" install --only-binary=:all: unicorn==2.1.4 2>/dev/null; then
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    # force the abi3 tags so pip will fetch the (otherwise-rejected) wheel
    "$VENV/bin/pip" download --only-binary=:all: --no-deps \
        --implementation cp --abi abi3 --platform manylinux2014_x86_64 \
        --python-version 37 unicorn==2.1.4 -d "$TMP"
    WHL="$(ls "$TMP"/unicorn-2.1.4-*.whl | head -1)"
    "$VENV/bin/python" -m zipfile -e "$WHL" "$TMP/x"
    rm -rf "$SP/unicorn" "$SP"/unicorn-2.1.4.dist-info
    cp -r "$TMP/x/unicorn" "$SP/unicorn"
    cp -r "$TMP/x/unicorn-2.1.4.dist-info" "$SP/" 2>/dev/null || true
    find "$SP/unicorn" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
fi

echo ">> verifying"
"$VENV/bin/python" - <<'PY'
import sys, unicorn, numpy, scipy, sympy
assert not sys._is_gil_enabled(), "GIL is enabled -- not a free-threaded interpreter"
print(f"OK  python {sys.version.split()[0]} (GIL disabled)  "
      f"unicorn {unicorn.__version__}  numpy {numpy.__version__}  "
      f"scipy {scipy.__version__}  sympy {sympy.__version__}")
PY

echo
echo "Done. Run the sweep with:  scripts/run_sweep.sh"
echo "     or the test suite:    scripts/run_tests.sh"
