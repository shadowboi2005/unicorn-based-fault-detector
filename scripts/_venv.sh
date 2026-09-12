#!/usr/bin/env bash
# Shared helper: pick the interpreter. Prefers the free-threaded .venv314t (this
# branch's environment); falls back to the standard .venv, then to `python3`.
# Override explicitly with VENV=/path/to/venv.
_pick_python() {
    if [ -n "${VENV:-}" ]; then echo "$VENV/bin/python"; return; fi
    if [ -x .venv314t/bin/python ]; then echo .venv314t/bin/python; return; fi
    if [ -x .venv/bin/python ]; then echo .venv/bin/python; return; fi
    command -v python3
}
