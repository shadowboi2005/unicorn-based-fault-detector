"""Analysis profile for CRYSTALS-Dilithium / ML-DSA.

Lifts the ML-DSA-44 specifics that were copy-pasted across examples 07/09/10:
the parameters, the signing-loop fault-site table, the signature/buffer decoders,
and the matched-filter feature.  Implements the `AnalysisProfile` interface so the
mode engine (`ucpqc.assess`) can drive it without knowing it is Dilithium.
"""

import struct

import numpy as np

from ..detectors import matched_filter
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

# -- signing-loop fault sites (specific to firmware/ml-dsa-44_m4f_test.elf) --
# One (bl address, label) per operation call in the reject-and-retry loop.
SIGNING_SITES = [
    (0x4c7c, "sample y (uniform_gamma1)"), (0x4c90, "memcpy"),
    (0x4c9a, "y -> NTT (polyvecl_ntt)"), (0x4cb0, "w = A*y (matrix_pointwise)"),
    (0x4cc4, "w -> invNTT"), (0x4ce0, "decompose w"), (0x4cec, "pack w1"),
    (0x4d18, "shake squeeze (c_tilde)"), (0x4d22, "poly_challenge (c)"),
    (0x4d4c, "c*s1 (basemul_invntt)"), (0x4d5e, "z = z + y (polyvecl_add)"),
    (0x4d68, "reduce z"), (0x4d74, "z-norm check (chknorm)"),
    (0x4d88, "pack z into sig"), (0x4dbc, "c*s2 (basemul_invntt)"),
    (0x4dca, "w0 - c*s2 (poly_sub)"), (0x4dd8, "r0 check (chknorm)"),
    (0x4dec, "c*t0 (pointwise)"), (0x4e0e, "ct0 check (chknorm)"),
    (0x4e32, "make_hint"),
]
# Named singles used by the intra-function / rejection-region demos.
MASK_ADD = 0x4d5e        # bl polyvecl_add, z = z + y (the mask add)
R0_CHKNORM = 0x4dd8      # bl poly_chknorm for the r0 check
R0_CMP = 0x4ddc          # cmp r0,#0 after it
R0_BRANCH = 0x4dde       # bne to reject -- the load-bearing rejection branch
R0_ACCEPT = 0x4de0       # fall-through accept path
R0_REJECT = 0x4e86       # reject / restart target


class MLDSAProfile(AnalysisProfile):
    patterns = ("ml-dsa-*", "dilithium*")
    op = "sign"
    artifact_len = SIGLEN

    def __init__(self):
        self._cbuf = None                    # persistent scratch for poly_challenge

    def setup(self, machine):
        if self._cbuf is None:
            self._cbuf = machine.alloc(4 * N_COEFFS)

    # -- sweep sites --------------------------------------------------------
    def fault_sites(self, image):
        return list(SIGNING_SITES)

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
