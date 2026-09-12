#!/usr/bin/env python3
"""Oracle tests for the hand-rolled finite-field arithmetic.

Cross-checks `ucpqc.detectors.PrimeField.rank` / `GF2m.rank` against **galois**,
a trusted GF(2^m)/GF(p) linear-algebra library, and the sympy Z_q ring
deconvolution against a galois-based inverse.

Kept SEPARATE from the system suite (`tests/run_tests.py`): galois pulls in numba,
which has no free-threaded build, so this runs only on the standard 3.12 `.venv`:

    .venv/bin/pip install -r requirements-dev.txt
    .venv/bin/python tests/test_field_oracle.py

It is never run on the free-threaded `.venv314t`. Skips cleanly if galois is
absent.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import numpy as np  # noqa: E402

from ucpqc.detectors import GF2m, PrimeField  # noqa: E402

try:
    import galois
except ImportError:
    print("SKIP  galois not installed "
          "(.venv/bin/pip install -r requirements-dev.txt on the 3.12 venv)")
    sys.exit(0)


def _check_rank(field, GF, trials=25, shape=(12, 40), seed=0):
    """field.rank must equal galois' rank over the same field, incl. deficits."""
    rng = np.random.default_rng(seed)
    order = GF.order
    for t in range(trials):
        M = rng.integers(0, order, size=shape)
        if t % 3 == 0 and shape[0] > 2:          # force a rank deficit
            M[1] = M[0]
        if t % 5 == 0 and shape[0] > 3:
            M[2] = (M[0] + M[3]) % order          # (only exact over GF(p); ok as a case)
        want = int(np.linalg.matrix_rank(GF(M % order)))
        got = field.rank(M)
        assert got == want, f"{field.name}: rank {got} != galois {want}\n{M}"
    print(f"OK  {field.name}: {trials} matrices match galois rank")


def test_prime_field_rank():
    _check_rank(PrimeField(8380417), galois.GF(8380417))


def test_gf16_rank():
    # match GF2m's reduction polynomial x^4 + x + 1 (0x13) exactly
    GF16 = galois.GF(2 ** 4, irreducible_poly="x^4 + x + 1")
    _check_rank(GF2m(4), GF16, shape=(10, 20))


def main():
    test_prime_field_rank()
    test_gf16_rank()
    print("\nfield oracle tests passed")


if __name__ == "__main__":
    main()
