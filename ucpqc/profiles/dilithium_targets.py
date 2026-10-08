"""Extra funcskip targets: the Dilithium functions the sibling `Dilithium-LLVM` project
fault-analysed at the LLVM-IR level (its `taintResults/`), mapped from the reference C
names (`pqcrystals_dilithium2_ref_FOO`) to the ARM m4f symbols (`pqcrystals_dilithium_FOO`).
Used for the LLVM-IR -> ARM-binary fault-leakage translation study; merged into
`MLDSAProfile.targets()`.

Calling convention (AAPCS): r0..r3 = the C arguments in order; r0 is the output pointer
for every void op here except `chknorm` (r0 = input poly, result in the return value).
`nth=-1` captures the LAST invocation during one signing.  Sizes for ML-DSA-44 (N=256,
L=K=4): one poly = 1024 B, a polyvecl/polyveck = 4096 B, the matrix[K] = 16384 B.
"""

from ..replay import Target

_P = 256 * 4          # one poly (256 int32 coefficients)
_V = 4 * _P           # polyvecl / polyveck (L = K = 4)
_MAT = 4 * _V         # matrix[K] of polyvecl
_SEED, _CRH, _CTILDE = 32, 64, 32


def _t(sym, args, out=0, label=None):
    return Target(func=f"pqcrystals_dilithium_{sym}", nth=-1, args=args, out=out,
                  label=label or sym)


#: funcskip targets reachable during SIGNING (the funcskip capture path), keyed by the
#: reference function name so dumps land in dumps/<name>_instrskip/.
TARGETS = {
    # -- per-poly bodies (reached via the polyvec* wrappers in the signing loop) --------
    "poly_add":            _t("poly_add",  (("out", _P), ("in", _P), ("in", _P))),
    "poly_sub":            _t("poly_sub",  (("out", _P), ("in", _P), ("in", _P))),
    "poly_decompose":      _t("poly_decompose", (("out", _P), ("out", _P), ("in", _P)),
                              out=1, label="poly_decompose (a0/r0)"),   # capture the low part r0
    "poly_make_hint":      _t("poly_make_hint", (("out", _P), ("in", _P), ("in", _P)), out=0),
    "poly_chknorm":        _t("poly_chknorm", (("in", _P), "scalar"), out="ret"),
    "poly_uniform":        _t("poly_uniform", (("out", _P), ("in", _SEED), "scalar")),
    "poly_uniform_gamma1": _t("poly_uniform_gamma1", (("out", _P), ("in", _CRH), "scalar")),
    "poly_challenge":      _t("poly_challenge", (("out", _P), ("in", _CTILDE))),
    # -- in-place asm workers (the 4B C thunks tail-call these) -------------------------
    "ntt":                 _t("ntt", (("in", _P),), out=0),
    "invntt_tomont":       _t("invntt_tomont", (("in", _P),), out=0),
    # -- polyvecl wrappers (L-iteration loop bodies) -----------------------------------
    "polyvecl_add":        _t("polyvecl_add", (("out", _V), ("in", _V), ("in", _V))),
    "polyvecl_ntt":        _t("polyvecl_ntt", (("in", _V),), out=0),
    "polyvecl_invntt_tomont": _t("polyvecl_invntt_tomont", (("in", _V),), out=0),
    "polyvecl_reduce":     _t("polyvecl_reduce", (("in", _V),), out=0),
    "polyvecl_chknorm":    _t("polyvecl_chknorm", (("in", _V), "scalar"), out="ret"),
    "polyvecl_pointwise_poly_montgomery":
        _t("polyvecl_pointwise_poly_montgomery", (("out", _V), ("in", _P), ("in", _V))),
    "polyvecl_pointwise_acc_montgomery":
        _t("polyvecl_pointwise_acc_montgomery", (("out", _P), ("in", _V), ("in", _V)), out=0),
    "polyvecl_uniform_gamma1":
        _t("polyvecl_uniform_gamma1", (("out", _V), ("in", _CRH), "scalar")),
    # -- polyveck wrappers (K-iteration loop bodies) -----------------------------------
    "polyveck_add":        _t("polyveck_add", (("out", _V), ("in", _V), ("in", _V))),
    "polyveck_sub":        _t("polyveck_sub", (("out", _V), ("in", _V), ("in", _V))),
    "polyveck_caddq":      _t("polyveck_caddq", (("in", _V),), out=0),
    "polyveck_decompose":  _t("polyveck_decompose", (("out", _V), ("out", _V), ("in", _V)),
                              out=1, label="polyveck_decompose (v0/r0)"),
    "polyveck_make_hint":  _t("polyveck_make_hint", (("out", _V), ("in", _V), ("in", _V)), out=0),
    "polyveck_reduce":     _t("polyveck_reduce", (("in", _V),), out=0),
    "polyveck_ntt":        _t("polyveck_ntt", (("in", _V),), out=0),
    "polyveck_invntt_tomont": _t("polyveck_invntt_tomont", (("in", _V),), out=0),
    "polyveck_pointwise_poly_montgomery":
        _t("polyveck_pointwise_poly_montgomery", (("out", _V), ("in", _P), ("in", _V))),
    "polyveck_chknorm":    _t("polyveck_chknorm", (("in", _V), "scalar"), out="ret"),
    # -- matrix * vector ----------------------------------------------------------------
    "polyvec_matrix_pointwise_montgomery":
        _t("polyvec_matrix_pointwise_montgomery", (("out", _V), ("in", _MAT), ("in", _V))),
}

#: LLVM-study functions NOT reachable by signing-time funcskip (sampled in keygen only).
KEYGEN_ONLY = {"poly_uniform_eta", "polyvecl_uniform_eta", "polyveck_uniform_eta",
               "polyveck_shiftl"}

#: 4B C thunks with no interior skip surface -> the arithmetic lives in the worker/wrapper
#: listed, which is the funcskip target that actually exercises it.
THUNK_REDIRECT = {
    "poly_ntt": "ntt",
    "poly_invntt_tomont": "invntt_tomont",
    "poly_caddq": "polyveck_caddq",
    "poly_pointwise_montgomery": "polyvecl_pointwise_poly_montgomery",
}
