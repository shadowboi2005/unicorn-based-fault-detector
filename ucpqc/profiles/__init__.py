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

__all__ = ["AnalysisProfile", "register", "profile_for", "profiles"]


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

    # -- lifecycle ----------------------------------------------------------
    def setup(self, machine):
        """Allocate any *persistent* scratch the feature extraction needs, once,
        before the per-signing scratch mark is taken (so it survives the
        per-iteration `scratch_reset`).  Default: nothing."""

    # -- sweep-site enumeration ---------------------------------------------
    def fault_sites(self, image):
        """Return `[(addr, label), ...]` -- the whole-call sweep sites in the
        operation's inner loop (may be hard-coded per firmware or discovered)."""
        raise NotImplementedError

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

    # -- detector role mapping ----------------------------------------------
    def detector_for(self, target):
        """Which detector fits a target: "two_key" (secret-masked response),
        "uniformity" (a nonce that must be uniform), or "spec_aware" (a
        rejection-bound quantity).  Default: two_key."""
        return "two_key"


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
    name = scheme.name
    for cls in profiles:
        if any(fnmatch.fnmatch(name, pat) for pat in cls.patterns):
            return cls()
    known = sorted({p for cls in profiles for p in cls.patterns})
    raise ValueError(
        f"no analysis profile for scheme {name!r}; add one in ucpqc/profiles/ "
        f"(registered patterns: {', '.join(known) or 'none'})")


# import built-in profiles so they self-register on `import ucpqc.profiles`
from . import mldsa  # noqa: E402,F401
