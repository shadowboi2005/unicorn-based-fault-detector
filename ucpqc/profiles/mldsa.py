"""Analysis profile for CRYSTALS-Dilithium / ML-DSA.

Lifts the ML-DSA-44 specifics that were copy-pasted across examples 07/09/10:
the parameters, the signing-loop fault-site table, the signature/buffer decoders,
and the matched-filter feature.  Implements the `AnalysisProfile` interface so the
mode engine (`ucpqc.assess`) can drive it without knowing it is Dilithium.
"""

import struct

import numpy as np

from ..detectors import PrimeField, matched_filter
from ..replay import Target
from . import AnalysisProfile, register

# -- ML-DSA-44 parameters ---------------------------------------------------
Q = 8380417
GAMMA1 = 1 << 17
GAMMA2 = (Q - 1) // 88
BETA = 78
TAU = 39
ETA = 2
N_COEFFS = 256
L = 4
K = 4
CTILDE_BYTES = 32
POLYZ_BYTES = N_COEFFS * 18 // 8
SIGLEN = CTILDE_BYTES + POLYZ_BYTES * L + 84
POLYVECL_BYTES = L * N_COEFFS * 4
R0_BOUND = GAMMA2 - BETA                     # gamma2 - beta, the r0 reject bound


# -- negacyclic deconvolution over Z_q (for the structural feature) ---------
# The response z = c*s1 (mod X^256+1, mod Q) once the mask y is skipped.  With c
# known we recover s1 = z * c^{-1} in the ring Z_q[x]/(x^256+1); when leaking,
# every signature yields the SAME s1 -> the rows collapse to rank 1, while masked
# z stays full rank.  The polynomial-ring inverse is done by sympy (a well-tested
# library) rather than a hand-rolled NTT.  sympy is pure-Python, so this stays
# free-threading-safe (no GIL re-enable on the 3.14t venv).
from sympy import GF as _GF, Poly as _Poly, invert as _invert, symbols as _symbols  # noqa: E402
from sympy.polys.polyerrors import NotInvertible as _NotInvertible                  # noqa: E402

_X = _symbols("x")
_RING = {}                                   # lazy: {dom, g = x^N + 1}
_CINV = {}                                   # cache: c.bytes -> c^{-1} Poly (or None)


def _ring():
    if not _RING:
        dom = _GF(Q, symmetric=False)        # Z_q with representatives in [0, Q)
        _RING["dom"] = dom
        _RING["g"] = _Poly(_X ** N_COEFFS + 1, _X, domain=dom)
    return _RING["dom"], _RING["g"]


def _c_inverse(c):
    """c^{-1} in Z_q[x]/(x^N+1), cached by challenge (same c reused across sites);
    None if c is not a unit (rare) so that signature contributes no low-rank row."""
    key = (np.asarray(c, dtype=np.int64) % Q).tobytes()
    if key not in _CINV:
        dom, g = _ring()
        cp = _Poly.from_list(list((np.asarray(c, dtype=object) % Q)[::-1]), _X, domain=dom)
        try:
            _CINV[key] = _invert(cp, g)
        except _NotInvertible:
            _CINV[key] = None
    return _CINV[key]


def negacyclic_deconv(c, z):
    """Recover per-poly ``s1`` estimates from ``z`` given challenge ``c`` over Z_q,
    via the sympy ring inverse ``s1 = z * c^{-1}`` in ``Z_q[x]/(x^N+1)``.  ``c`` is
    length-N, ``z`` is ``(L, N)``; returns ``(L, N)`` ints in ``[0, Q)``."""
    dom, g = _ring()
    cinv = _c_inverse(c)
    z = np.atleast_2d(np.asarray(z, dtype=object) % Q)
    out = np.zeros((z.shape[0], N_COEFFS), dtype=np.int64)
    if cinv is None:
        return out
    for r in range(z.shape[0]):
        s1p = (_Poly.from_list(list(z[r][::-1]), _X, domain=dom) * cinv) % g
        for k, co in enumerate(s1p.all_coeffs()[::-1]):
            out[r, k] = int(co) % Q
    return out


class MLDSAProfile(AnalysisProfile):
    patterns = ("ml-dsa-*", "dilithium*")
    op = "sign"
    artifact_len = SIGLEN
    field = PrimeField(Q)                    # Dilithium coefficients live in Z_q

    def __init__(self):
        self._cbuf = None                    # persistent scratch for poly_challenge

    def setup(self, machine):
        if self._cbuf is None:
            self._cbuf = machine.alloc(4 * N_COEFFS)

    # sweep sites are auto-discovered by the base AnalysisProfile.fault_sites
    # (disassembly of the signing function) -- no hard-coded address table.

    # -- feature extraction -------------------------------------------------
    def challenge(self, machine, artifact):
        """Expand c_tilde (first 32 bytes of the signature) back into the sparse
        challenge polynomial `c`, via the firmware's own SampleInBall."""
        if self._cbuf is None:               # lazy fallback if setup() not called
            self._cbuf = machine.alloc(4 * N_COEFFS)
        mark = machine.scratch_mark()
        seed = machine.alloc_bytes(bytes(artifact[:CTILDE_BYTES]))
        machine.call("pqcrystals_dilithium_poly_challenge", [self._cbuf, seed])
        c = np.array(struct.unpack(f"<{N_COEFFS}i", machine.read(self._cbuf, 4 * N_COEFFS)),
                     float)
        machine.scratch_reset(mark)
        return c

    def response_from_signature(self, artifact):
        """Decode the response polyvec z (L x 256) from a released signature's
        18-bit gamma1 packing."""
        off, z = CTILDE_BYTES, []
        for _ in range(L):
            a = artifact[off:off + POLYZ_BYTES]; off += POLYZ_BYTES
            for i in range(N_COEFFS // 4):
                b = a[9 * i:9 * i + 9]
                z += [GAMMA1 - (b[0] | b[1] << 8 | (b[2] & 3) << 16),
                      GAMMA1 - ((b[2] >> 2) | b[3] << 6 | (b[4] & 15) << 14),
                      GAMMA1 - ((b[4] >> 4) | b[5] << 4 | (b[6] & 63) << 12),
                      GAMMA1 - ((b[6] >> 6) | b[7] << 2 | b[8] << 10)]
        return np.array(z, float).reshape(L, N_COEFFS)

    def response_from_output(self, output):
        """Decode a polyvecl (L x 256 int32) from a raw captured buffer."""
        return np.array(struct.unpack(f"<{L * N_COEFFS}i", output),
                        float).reshape(L, N_COEFFS)

    def feature(self, context, response):
        return matched_filter(context, response)

    def structural_feature(self, context, response):
        """Row of Z_q elements for the structural detector: the per-signature
        `s1` estimate recovered by deconvolving the challenge `c` (`context`) from
        the response `z`.  When the mask is off (`z = c*s1`) every signature
        yields the same `s1`, so the rows collapse to a rank-1, key-dependent
        subspace; when masked, `z` is randomised and the rows stay full rank."""
        return negacyclic_deconv(context, response).ravel().astype(int)

    # -- targets / detector role -------------------------------------------
    #: the r0 reject bound, used by the spec-aware detector
    reject_bound = R0_BOUND

    def targets(self):
        """Named funcskip targets (short name -> replay.Target)."""
        pv = (("out", POLYVECL_BYTES), ("in", POLYVECL_BYTES), ("in", POLYVECL_BYTES))
        return {
            "polyvecl_add": Target(func="pqcrystals_dilithium_polyvecl_add",
                                   nth=-1, args=pv, out=0, label="polyvecl_add (z=z+y)"),
            "polyvecl_reduce": Target(func="pqcrystals_dilithium_polyvecl_reduce",
                                      nth=-1, args=(("in", POLYVECL_BYTES),), out=0,
                                      label="polyvecl_reduce (control)"),
            "y_sampler": Target(func="pqcrystals_dilithium_polyvecl_uniform_gamma1",
                                nth=-1, args=(("out", POLYVECL_BYTES), ("in", 64),
                                              "scalar"), out=0,
                                label="polyvecl_uniform_gamma1 (y)"),
        }

    def default_target(self):
        """The z = z + y mask add -- the intra-function funcskip target."""
        return self.targets()["polyvecl_add"]

    def detector_for(self, target):
        name = getattr(target, "name", str(target))
        if "uniform_gamma1" in name:          # the y nonce sampler
            return "uniformity"
        if "chknorm" in name or "r0" in name:
            return "spec_aware"
        return "two_key"


def unpack_s1(sk):
    """Decode the secret vector s1 (L x 256, eta=2, 3-bit packing) from the
    secret key -- used only for validation/attribution, not by the detectors."""
    off, s1 = 128, []                        # S1 offset for ML-DSA-44
    for _ in range(L):
        for i in range(N_COEFFS // 8):
            b = sk[off + 3 * i:off + 3 * i + 3]
            t = b[0] | b[1] << 8 | b[2] << 16
            s1 += [ETA - ((t >> (3 * j)) & 7) for j in range(8)]
        off += 96
    return np.array(s1, float).reshape(L, N_COEFFS)


register(MLDSAProfile)
