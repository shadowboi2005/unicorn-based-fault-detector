"""The scheme-agnostic assessment engine -- two modes over any PQC scheme.

Both modes ask the same question -- "does faulting this location make the output
leak the secret key?" -- and share the same spine (two keys, N artifacts each, a
feature per artifact, a detector, LEAK/ok/crash verdicts).  They differ only in
the fault surface and how the faulted feature is produced:

  * `sweep_sites`    (mode "sweep")    -- whole-call skips over the operation's
    inner loop, re-running the operation per trial (generalizes example 09).
  * `sweep_function` (mode "funcskip") -- instruction skips inside one function,
    via capture-and-replay (generalizes example 10).

Everything scheme-specific (fault sites, feature extraction, detector role) comes
from an `AnalysisProfile`, so this engine never mentions Dilithium.
"""

from dataclasses import dataclass, field

import numpy as np

from . import detectors
from .faults import SKIP, FaultSpec, Injector
from .machine import EmulationError
from .replay import Recorder, skip_sweep

LEAK_THRESHOLD = 0.80
CHANCE = 0.50
UNIFORMITY_SPIKE = 0.10                # bin share above which a nonce looks biased
DEFAULT_KEYS = (b"secret-key-AAAA", b"secret-key-BBBB")
DEFAULT_N = 24
CAP = 20_000_000


# --------------------------------------------------------------------------
# result model
# --------------------------------------------------------------------------
@dataclass
class SiteResult:
    addr: object                       # int address, or None for the control row
    label: str
    metric: object                     # the detector metric, or None if crashed
    status: str                        # "LEAK" | "ok" | "crash" | "control"
    ran: int = 0
    crashed: int = 0


@dataclass
class AssessmentResult:
    scheme: str
    mode: str
    detector: str
    n: int
    rows: list = field(default_factory=list)

    def leaks(self):
        return [r for r in self.rows if r.status == "LEAK"]


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------
def standard_messages(n):
    return [f"msg-{i}".encode() for i in range(n)]


def _keypair(scheme, seed):
    scheme.machine.stub_randombytes(seed)
    return scheme.keypair()


def _operation(scheme):
    """Return a `(sk_or_ct, run(msg)) `-style driver for the scheme's op."""
    from .scheme import SIGN
    if scheme.kind == SIGN:
        return "sign"
    return "decaps"


def _detector_metric(name, feats, profile):
    """Aggregate per-key feature lists into (metric, is_leak) for a detector."""
    A = np.array(feats["A"]); B = np.array(feats.get("B", []))
    if name == "two_key":
        if len(A) < 3 or len(B) < 3:
            return None, False
        acc = detectors.two_key_accuracy(A, B)
        return acc, acc >= LEAK_THRESHOLD
    if name == "uniformity":
        if len(A) < 1:
            return None, False
        pool = A.ravel()
        _, _, spike = detectors.uniformity_divergence(pool, pool.min(), pool.max())
        return spike, spike > UNIFORMITY_SPIKE
    if name == "spec_aware":
        bound = getattr(profile, "reject_bound", None)
        if bound is None or len(A) < 1:
            return None, False
        pool = A.ravel()
        frac = detectors.band_count(pool, bound) / max(pool.size, 1)
        return frac, frac > 0
    raise ValueError(f"unknown detector {name!r}")


def _status(metric, is_leak, ran, crashed, control=False):
    if control:
        return "control"
    if ran < 3 or metric is None:
        return "crash"
    return "LEAK" if is_leak else "ok"


# --------------------------------------------------------------------------
# mode "sweep" -- whole-call skips over the operation loop
# --------------------------------------------------------------------------
def sweep_sites(scheme, profile, keys=DEFAULT_KEYS, n=DEFAULT_N,
                detector="two_key", budget=CAP, progress=None):
    """Sweep every fault site from `profile.fault_sites`, re-running the
    operation with a persistent whole-call skip and scoring the two-key leak of
    the released artifacts.  Returns an `AssessmentResult`."""
    m = scheme.machine
    sk = {k: _keypair(scheme, seed)[1] for k, seed in zip("AB", keys)}
    profile.setup(m)
    messages = standard_messages(n)
    sites = [(None, "no fault (control)")] + list(profile.fault_sites(m))

    def collect(site):
        feats = {"A": [], "B": []}
        crashed = 0
        for key in "AB":
            m.stub_randombytes(f"nonce-{key}".encode())
            mark = m.scratch_mark()
            inj = Injector(m, FaultSpec(kind=SKIP, pc=site, hit=0)) if site else None
            try:
                for msg in messages:
                    m.scratch_reset(mark)
                    try:
                        art = scheme.sign(msg, sk[key], max_instructions=budget)
                    except EmulationError:
                        crashed += 1
                        raise _Unstable
                    if profile.artifact_len and len(art) != profile.artifact_len:
                        crashed += 1
                        raise _Unstable
                    c = profile.challenge(m, art)
                    feats[key].append(profile.feature(c, profile.response_from_signature(art)))
            except _Unstable:
                return feats, crashed, True
            finally:
                if inj:
                    inj.detach()
        return feats, crashed, False

    rows = []
    for site, label in sites:
        try:
            feats, crashed, unstable = collect(site)
        except EmulationError:
            feats, crashed, unstable = {"A": [], "B": []}, n, True
        ran = len(feats["A"]) + len(feats["B"])
        if unstable:
            metric, is_leak = None, False
        else:
            metric, is_leak = _detector_metric(detector, feats, profile)
        status = _status(metric, is_leak, min(len(feats["A"]), len(feats["B"])),
                         crashed, control=(site is None))
        row = SiteResult(site, label, metric, status, ran, crashed)
        rows.append(row)
        if progress:
            progress(row)
    return AssessmentResult(scheme.name, "sweep", detector, n, rows)


# --------------------------------------------------------------------------
# mode "funcskip" -- instruction skips inside one function (capture-replay)
# --------------------------------------------------------------------------
def sweep_function(scheme, profile, target=None, keys=DEFAULT_KEYS, n=DEFAULT_N,
                   detector=None, backend="call", budget=5_000_000, progress=None):
    """Capture one function's I/O across N signings per key, then replay it under
    an instruction skip at every interior site and score the leak.  `target` is a
    `replay.Target` (defaults to `profile.default_target()`).  Returns an
    `AssessmentResult`."""
    m = scheme.machine
    target = target or profile.default_target()
    detector = detector or profile.detector_for(target)
    sk = {k: _keypair(scheme, seed)[1] for k, seed in zip("AB", keys)}
    profile.setup(m)
    messages = standard_messages(n)

    def capture(key):
        m.stub_randombytes(f"nonce-{key}".encode())
        rec = Recorder(m, target, snapshot=(backend == "snapshot"))
        mark = m.scratch_mark()
        caps = []
        for msg in messages:
            m.scratch_reset(mark)
            rec.arm()
            art = scheme.sign(msg, sk[key], max_instructions=CAP)   # full signing
            cap = rec.take(key)
            if cap is not None:
                cap.c = profile.challenge(m, art)      # context for the feature
                caps.append(cap)
        rec.detach()
        return caps

    caps_by_key = {k: capture(k) for k in ("A", "B")}

    def featurize(cap, out):
        resp = profile.response_from_output(out)
        if detector == "two_key":
            return profile.feature(cap.c, resp)
        return resp.ravel()                            # uniformity / spec_aware

    def detect(feats):
        metric, is_leak = _detector_metric(detector, feats, profile)
        return {"metric": metric, "leak": is_leak}

    swept = skip_sweep(m, target, caps_by_key, featurize, detect,
                       backend=backend, persistent=True, budget=budget)
    rows = []
    for r in swept:
        metric, is_leak = r.get("metric"), r.get("leak", False)
        status = _status(metric, is_leak, r["ran"], r["crashed"])
        row = SiteResult(r["pc"], r["text"], metric, status, r["ran"], r["crashed"])
        rows.append(row)
        if progress:
            progress(row)
    return AssessmentResult(scheme.name, "funcskip", detector, n, rows)


class _Unstable(Exception):
    pass
