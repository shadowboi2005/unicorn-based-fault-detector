"""Scheme-analysis profiles -- the extendability layer.

`ucpqc.scheme` already detects *what* a firmware is (SIGN/KEM, sizes, landmarks)
from the ELF, agnostic of the concrete scheme.  A **profile** supplies the
scheme-specific *analysis* knowledge the assess engine needs but the emulator
does not: which fault sites to sweep, how to turn a released signature or a
captured function output into a detector feature, and which detector fits a
target.  The `assess` engine is written against the `AnalysisProfile` interface,
so supporting a new PQC scheme is a new module here -- no engine changes.

Adding a scheme:
    from ucpqc.profiles import AnalysisProfile, register

    class MyProfile(AnalysisProfile):
        patterns = ("my-scheme-*",)
        def fault_sites(self, image): ...
        def challenge(self, machine, sig): ...
        def response_from_signature(self, sig): ...
        def response_from_output(self, output): ...
        def feature(self, context, response): ...

    register(MyProfile)

The profile is selected automatically from `scheme.name` via `profile_for`.
"""

import fnmatch

__all__ = ["AnalysisProfile", "register", "profile_for", "profile_by_name",
           "profiles", "discover_call_sites", "signing_body"]


class AnalysisProfile:
    """Interface the assess engine calls; subclass per scheme.

    All feature extraction routes through `challenge` + `response_*` + `feature`
    so the two modes (sweep over released signatures, funcskip over captured
    function outputs) share one implementation.
    """

    #: globs matched against `scheme.name` to auto-select this profile
    patterns = ()
    #: operation the modes drive ("sign" or "decaps")
    op = "sign"
    #: expected released-artifact length, for a validity check (0 = skip)
    artifact_len = 0
    #: default funcskip target (a symbol name or a replay.Target), or None
    default_target = None
    #: arithmetic backend for the "structural" detector (a detectors.Field), or
    #: None if the scheme supplies no field-aware structural feature yet
    field = None

    # -- lifecycle ----------------------------------------------------------
    def setup(self, machine):
        """Allocate any *persistent* scratch the feature extraction needs, once,
        before the per-signing scratch mark is taken (so it survives the
        per-iteration `scratch_reset`).  Default: nothing."""

    # -- sweep-site enumeration ---------------------------------------------
    def fault_sites(self, machine, op_func):
        """Return `[(addr, label), ...]` -- the whole-call sweep sites in the
        operation's inner loop.

        Default: auto-discover them by disassembling the operation's body,
        descending through thin wrappers (:func:`signing_body`) to the function
        that holds the loop.  `op_func` is the resolved operation entry symbol
        (the engine passes `scheme.binding.symbols['signature'|'dec']`).  Override
        only if a scheme needs curated/filtered sites."""
        return discover_call_sites(machine, signing_body(machine, op_func))

    # -- feature extraction (shared by both modes) --------------------------
    def challenge(self, machine, artifact):
        """The per-artifact context the feature needs (e.g. the expanded
        challenge `c`), recomputed from a released signature."""
        raise NotImplementedError

    def response_from_signature(self, artifact):
        """The secret-masked response polynomials, decoded from a released
        signature (sweep mode)."""
        raise NotImplementedError

    def response_from_output(self, output):
        """The response polynomials, decoded from a captured function-output
        buffer (funcskip mode)."""
        raise NotImplementedError

    def feature(self, context, response):
        """Combine context + response into a detector feature vector (e.g. the
        matched filter of `c` against the response)."""
        raise NotImplementedError

    def structural_feature(self, context, response):
        """Map one (context, response) into a row of FIELD ELEMENTS over
        ``self.field`` for the "structural" detector -- built so a leak shows up
        as a low-rank, key-dependent subspace.  Distinct from ``feature`` (a
        real-valued classifier feature): the structural leak is *algebraic*.
        Where the leak lives is the scheme's job to express (e.g. MAYO: the
        exposed oil bytes as GF(16) elements; Dilithium: the per-signature ``s1``
        estimate over Z_q, deconvolving the known challenge from the response).
        Only needed if the profile sets ``field`` and offers the "structural"
        detector.  Default: unsupported."""
        raise NotImplementedError

    # -- detector role mapping ----------------------------------------------
    def detector_for(self, target):
        """Which detector fits a target: "two_key" (secret-masked response),
        "uniformity" (a nonce that must be uniform), or "spec_aware" (a
        rejection-bound quantity).  Default: two_key."""
        return "two_key"

    # -- controlled key difference (#1) -------------------------------------
    def sibling_key(self, sk):
        """Return a copy of secret key `sk` differing by ONE byte, for a controlled
        minimal-difference A/B experiment (`--key-mode sibling`).  The tiny secret
        difference makes the leak signal small -- a more stringent sensitivity test.
        Default: flip the last byte; override per scheme to target the *leaking*
        secret (e.g. Dilithium's s1)."""
        b = bytearray(sk)
        b[-1] ^= 0x01
        return bytes(b)


# --- helpers ---------------------------------------------------------------
def _scan_calls(machine, func):
    """Every `bl`/`blx` in `func`'s body as `[(addr, target, label)]`.  `target`
    is the branch destination address (from a `#imm` operand) or None for a
    register-indirect call; `label` is `bl <symbol>` when the target resolves."""
    start, end = machine.image.extent_of(func)
    calls, pc = [], start
    while pc < end:
        addr, size, text = machine.disasm_one(pc)
        if text.startswith("bl ") or text.startswith("blx "):
            target, label = None, text
            if "#" in text:
                try:
                    target = int(text.split("#")[-1], 16)
                    label = f"bl {machine.image.describe(target)}"
                except ValueError:
                    pass
            calls.append((addr, target, label))
        pc += size or 2
    return calls


def discover_call_sites(machine, func):
    """Every `bl`/`blx` inside `func`'s body as `[(addr, label)]`, labelling the
    callee by symbol -- a firmware-agnostic alternative to a hard-coded site
    table (`fault_sites` can just return this)."""
    return [(addr, label) for addr, _, label in _scan_calls(machine, func)]


def signing_body(machine, func, max_depth=4):
    """Descend from `func` through thin wrappers to the function that holds the
    operation loop.  A wrapper is a body whose only internal-function call is a
    tail-call to another function's start (e.g. MAYO's `crypto_sign_signature`
    -> `mayo_sign_signature`); descend into it.  A body with many calls (e.g.
    Dilithium's inline reject loop) is returned as-is."""
    for _ in range(max_depth):
        callees = []
        for _addr, target, _label in _scan_calls(machine, func):
            if target is None:
                continue
            fn = machine.image.func_at(target)
            if fn is not None and fn.addr == target:      # a call to a function start
                callees.append(fn.name)
        distinct = set(callees)
        if len(distinct) != 1:                            # not a thin wrapper -> the body
            return func
        func = distinct.pop()                             # descend into the sole callee
    return func


# --- registry --------------------------------------------------------------
profiles = []


def register(profile_cls):
    """Register a profile class for auto-selection.  Idempotent."""
    if profile_cls not in profiles:
        profiles.append(profile_cls)
    return profile_cls


def profile_for(scheme, override=None):
    """Select the profile for `scheme` (or force one via `override`, a glob
    matched against profile patterns).  Raises a helpful error if none matches."""
    if override:
        for cls in profiles:
            if any(fnmatch.fnmatch(p, override) or fnmatch.fnmatch(override, p)
                   for p in cls.patterns):
                return cls()
        raise ValueError(f"no analysis profile matching --profile {override!r}")
    return profile_by_name(scheme.name)


def profile_by_name(name):
    """Select the profile for a scheme *name string* alone -- no `scheme` object and
    no machine.  Used by the offline `detect` path (:func:`assess.assess_from_dump`),
    which reconstructs features from a dump: the methods it calls
    (`response_from_signature`, `feature`, `structural_feature`) never touch the
    emulator.  Same name matching as :func:`profile_for`."""
    for cls in profiles:
        if any(fnmatch.fnmatch(name, pat) for pat in cls.patterns):
            return cls()
    known = sorted({p for cls in profiles for p in cls.patterns})
    raise ValueError(
        f"no analysis profile for scheme {name!r}; add one in ucpqc/profiles/ "
        f"(registered patterns: {', '.join(known) or 'none'})")


# import built-in profiles so they self-register on `import ucpqc.profiles`
from . import mayo, mldsa  # noqa: E402,F401
