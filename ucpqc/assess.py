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

# -- calibrated verdict (default): every LEAK is a permutation/analytic p-value
# combined across the swept sites by a multiple-testing rule ------------------
ALPHA = 0.01                           # per-test level (per_coord / uniformity analytic tail)
FDR_Q = 0.01                           # sweep-wide false-discovery-rate level (the verdict)
DEFAULT_N_PERM = detectors.DEFAULT_N_PERM   # key-label shuffles per permutation test
# -- legacy fixed thresholds (kept for --legacy-thresholds / calibrate=False) -
LEAK_THRESHOLD = 0.80                  # two_key / subspace accuracy -> leak
UNIFORMITY_SPIKE = 0.10                # bin share above which a nonce looks biased
STRUCTURAL_THRESHOLD = 0.50            # structural_leak score -> leak
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
    status: str                        # "LEAK" | "ok" | "crash" | "control" | "pending"
    ran: int = 0
    crashed: int = 0
    pvalue: object = None              # calibrated per-site p-value (None in legacy mode)


@dataclass
class AssessmentResult:
    scheme: str
    mode: str
    detector: str
    n: int
    rows: list = field(default_factory=list)
    calibrate: bool = True             # calibrated p-value + FDR verdict (vs legacy cutoffs)
    fdr_q: float = FDR_Q               # sweep-wide FDR level (when calibrated)
    correction: str = "bh"             # "bh" (Benjamini-Hochberg) | "holm" (Bonferroni)
    n_perm: int = DEFAULT_N_PERM       # permutation count used (when calibrated)

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


def _tvla_threshold(d, alpha=ALPHA):
    """Bonferroni-corrected |t| threshold for a maximum over ``d`` coordinates at
    family-wise level ``alpha`` (two-sided), via a normal approximation.  Used only
    by the legacy per_coord verdict; the calibrated path uses its p-value dual."""
    from scipy import stats
    return float(stats.norm.isf(0.5 * alpha / max(d, 1)))


def _tvla_pvalue(max_t, d):
    """Per-site p-value dual of :func:`_tvla_threshold`: the Bonferroni (over the
    ``d`` within-site coordinates) two-sided normal-tail probability of the maximum
    ``|t|``.  Small p => at least one output coordinate separates the keys.  The
    across-site FDR pass then composes this with the other sites' p-values."""
    from scipy import stats
    return float(min(1.0, d * 2.0 * stats.norm.sf(max_t)))


def _structural_nperm(field, n_perm):
    """Cap the permutation count for the structural detector.  Its field-rank score
    has a DEGENERATE null (~0 with no leak: permuted groups stay full rank), so the
    studentised tail is razor-sharp -- a real collapse gets ``p_tail ~ 0`` and clears
    a sweep-wide threshold at any site count, while golden stays at ``p = 1``.  A
    small count therefore suffices, and the field rank (over a ~1024-wide matrix) is
    the costly inner loop, so we cap it low."""
    return min(n_perm, 60)


def _score_and_pvalue(name, feats, profile, calibrate, n_perm):
    """Score one detector on the per-key feature lists -> ``(metric, pvalue)``.

    ``metric`` is the raw statistic (``None`` if there is too little data, which the
    caller turns into a crash row).  ``pvalue`` is the calibrated per-site p-value
    when ``calibrate`` is set, else ``None`` (legacy mode decides from the metric
    alone, in :func:`_legacy_leak`).  Calibration is detector-appropriate: the
    classifier/structural detectors are permutation-calibrated under exchangeable key
    labels; per_coord and uniformity have exact analytic tails; a spec violation is
    deterministic (certain when present)."""
    A = np.array(feats["A"]); B = np.array(feats.get("B", []))
    if name in ("two_key", "subspace", "structural", "per_coord", "mmd") \
            and (len(A) < 3 or len(B) < 3):
        return None, None

    if name in ("two_key", "subspace", "structural"):
        if name == "two_key":
            stat = detectors.two_key_accuracy
        elif name == "subspace":
            stat = detectors.lda_accuracy
        else:                                     # structural: field-aware rank collapse
            if profile.field is None:
                return None, None
            field = profile.field
            stat = lambda a, b: detectors.structural_leak(a, b, field)   # noqa: E731
        metric = float(stat(A, B))
        if not calibrate:
            return metric, None
        nperm = _structural_nperm(profile.field, n_perm) if name == "structural" else n_perm
        _, p_emp, p_tail = detectors.perm_pvalue(stat, A, B, n_perm=nperm)
        return metric, detectors._resolve_p(p_emp, p_tail, nperm)

    if name == "per_coord":                       # detector A: per-coordinate max|t|
        max_t, _ = detectors.tvla_max(A, B)
        d = A.shape[1] if A.ndim > 1 else 1
        return max_t, (None if not calibrate else _tvla_pvalue(max_t, d))

    if name == "mmd":                             # model-agnostic two-sample (calibrated-only)
        obs, null, p_emp = detectors.mmd_test(A, B, n_perm=n_perm)
        if not calibrate:
            return obs, None
        from scipy import stats
        sd = float(null.std(ddof=1))
        z = (obs - float(null.mean())) / sd if sd > 0 else np.inf
        return obs, detectors._resolve_p(p_emp, float(stats.norm.sf(z)), n_perm)

    if name == "uniformity":
        if len(A) < 1:
            return None, None
        pool = A.ravel()
        chi2, dof, spike = detectors.uniformity_divergence(pool, pool.min(), pool.max())
        if not calibrate:
            return spike, None
        from scipy import stats
        return spike, float(stats.chi2.sf(chi2, dof))

    if name == "spec_aware":
        bound = getattr(profile, "reject_bound", None)
        if bound is None or len(A) < 1:
            return None, None
        pool = A.ravel()
        frac = detectors.band_count(pool, bound) / max(pool.size, 1)
        return frac, (0.0 if frac > 0 else 1.0)   # a spec violation is certain, not statistical

    raise ValueError(f"unknown detector {name!r}")


def _legacy_leak(name, metric, feats, profile):
    """The pre-calibration fixed-threshold verdict, kept for ``--legacy-thresholds``."""
    if metric is None:
        return False
    if name in ("two_key", "subspace"):
        return metric >= LEAK_THRESHOLD
    if name == "structural":
        return metric >= STRUCTURAL_THRESHOLD
    if name == "per_coord":
        A = np.array(feats["A"])
        return metric >= _tvla_threshold(A.shape[1] if A.ndim > 1 else 1)
    if name == "uniformity":
        return metric > UNIFORMITY_SPIKE
    if name == "spec_aware":
        return metric > 0
    if name == "mmd":
        return False                              # mmd is a calibrated-only detector
    raise ValueError(f"unknown detector {name!r}")


def _apply_correction(rows, fdr_q, correction):
    """Finalize the "pending" detector rows with a sweep-wide multiple-testing rule
    on their per-site p-values -- Benjamini-Hochberg FDR at level ``fdr_q`` (default)
    or Holm-Bonferroni FWER.  Control and crash rows are excluded, so the verdict
    reads "these sites leak at FDR <= q across the whole sweep"."""
    pend = [r for r in rows if r.status == "pending"]
    if not pend:
        return
    pvals = np.array([r.pvalue for r in pend], float)
    reject = (detectors.bh_fdr(pvals, fdr_q) if correction == "bh"
              else detectors.holm_bonferroni(pvals, fdr_q))
    for r, rej in zip(pend, reject):
        r.status = "LEAK" if rej else "ok"


# --------------------------------------------------------------------------
# mode "sweep" -- whole-call skips over the operation loop
# --------------------------------------------------------------------------
def _run_site(scheme, profile, sk, messages, site, label, detector, budget,
              calibrate=True, n_perm=DEFAULT_N_PERM):
    """Run ONE sweep site (whole-call skip) and return its `SiteResult`.

    Pure and deterministic given its arguments, so the serial `sweep_sites` and
    the parallel backends share it and produce identical rows.  `site` is an int
    address, or None for the control row.  This is the reusable, machine-in-arg
    seam the parallel executors hook into (`scheme.machine` is the live engine).

    Sites must be independent: a faulted/hung signing leaves the guest machine
    dirty, so without isolation the next site inherits that state and its verdict
    depends on which site ran before it -- reproducible in a fixed serial order,
    but non-deterministic once a pool schedules sites across workers.  We snapshot
    on entry and restore on exit so every site starts from identical clean state;
    this makes the serial and both parallel backends agree exactly and removes the
    spurious near-threshold "leaks" small-N sweeps used to show."""
    m = scheme.machine
    guard = m.snapshot()                         # leave the machine as we found it
    feats = {"A": [], "B": []}
    crashed = 0
    unstable = False
    try:
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
                    resp = profile.response_from_signature(art)
                    # structural uses the field-element feature; all others use
                    # the real-valued classifier feature (unchanged path)
                    feats[key].append(
                        profile.structural_feature(c, resp) if detector == "structural"
                        else profile.feature(c, resp))
            except _Unstable:
                unstable = True
                break
            finally:
                if inj:
                    inj.detach()
    except EmulationError:                       # matches the serial outer guard
        feats, crashed, unstable = {"A": [], "B": []}, len(messages), True
    finally:
        m.restore(guard)                         # isolate the next site from this one
    ran = len(feats["A"]) + len(feats["B"])
    if unstable:
        metric, pvalue = None, None
    else:
        metric, pvalue = _score_and_pvalue(detector, feats, profile, calibrate, n_perm)
    ran_ok = min(len(feats["A"]), len(feats["B"]))
    if site is None:
        status = "control"
    elif ran_ok < 3 or metric is None:
        status = "crash"
    elif not calibrate:
        status = "LEAK" if _legacy_leak(detector, metric, feats, profile) else "ok"
    else:
        status = "pending"                        # finalized by the sweep-wide FDR pass
    return SiteResult(site, label, metric, status, ran, crashed, pvalue=pvalue)


def sweep_sites(scheme, profile, keys=DEFAULT_KEYS, n=DEFAULT_N,
                detector="two_key", budget=CAP, progress=None,
                calibrate=True, n_perm=DEFAULT_N_PERM, fdr_q=FDR_Q, correction="bh"):
    """Sweep every fault site from `profile.fault_sites`, re-running the operation
    with a persistent whole-call skip and scoring the leak of the released
    artifacts.  By default the verdict is calibrated: each site gets a permutation/
    analytic p-value, then a sweep-wide Benjamini-Hochberg pass flags leaks at FDR
    `fdr_q` (`calibrate=False` restores the legacy fixed cutoffs, decided per-site).
    Returns an `AssessmentResult`."""
    from .scheme import SIGN
    m = scheme.machine
    sk = {k: _keypair(scheme, seed)[1] for k, seed in zip("AB", keys)}
    profile.setup(m)
    messages = standard_messages(n)
    op_func = scheme.binding.symbols["signature" if scheme.kind == SIGN else "dec"]
    sites = [(None, "no fault (control)")] + list(profile.fault_sites(m, op_func))

    rows = []
    for site, label in sites:
        row = _run_site(scheme, profile, sk, messages, site, label, detector, budget,
                        calibrate=calibrate, n_perm=n_perm)
        rows.append(row)
        if progress:
            progress(row)
    if calibrate:
        _apply_correction(rows, fdr_q, correction)
    return AssessmentResult(scheme.name, "sweep", detector, n, rows,
                            calibrate=calibrate, fdr_q=fdr_q, correction=correction,
                            n_perm=n_perm)


# --------------------------------------------------------------------------
# mode "funcskip" -- instruction skips inside one function (capture-replay)
# --------------------------------------------------------------------------
def _capture_funcskip(scheme, profile, target, backend, keys, n):
    """Capture the target's I/O across N signings per key -> {key: [Capture]}.

    The expensive funcskip prelude (2*N full signings).  Factored out so a
    parallel driver can capture once on the coordinator and ship the (pure-data,
    for the call backend) captures to workers.  Shared by the serial path."""
    m = scheme.machine
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

    return {k: capture(k) for k in ("A", "B")}


def _make_featurize(profile, detector):
    """Build the funcskip featurizer (shared by serial + parallel)."""
    def featurize(cap, out):
        resp = profile.response_from_output(out)
        # two_key / per_coord / subspace are different classifiers over the SAME
        # (challenge-aware) feature; only the raw-coefficient detectors bypass it.
        if detector in ("two_key", "per_coord", "subspace"):
            return profile.feature(cap.c, resp)
        if detector == "structural":
            return profile.structural_feature(cap.c, resp)
        return resp.ravel()                            # uniformity / spec_aware
    return featurize


def _make_detect(profile, detector, calibrate, n_perm):
    """Build the funcskip detector (shared by serial + parallel).  Returns the
    per-site metric and its calibrated p-value; in legacy mode it also carries the
    fixed-threshold verdict here, where the per-key features are still in scope."""
    def detect(feats):
        metric, pvalue = _score_and_pvalue(detector, feats, profile, calibrate, n_perm)
        out = {"metric": metric, "pvalue": pvalue}
        if not calibrate:
            out["leak"] = _legacy_leak(detector, metric, feats, profile)
        return out
    return detect


def sweep_function(scheme, profile, target=None, keys=DEFAULT_KEYS, n=DEFAULT_N,
                   detector=None, backend="call", budget=5_000_000, progress=None,
                   calibrate=True, n_perm=DEFAULT_N_PERM, fdr_q=FDR_Q, correction="bh"):
    """Capture one function's I/O across N signings per key, then replay it under
    an instruction skip at every interior site and score the leak.  `target` is a
    `replay.Target` (defaults to `profile.default_target()`).  Verdict is calibrated
    by default (per-site p-value + sweep-wide FDR `fdr_q`); `calibrate=False` uses
    the legacy fixed cutoffs.  Returns an `AssessmentResult`."""
    m = scheme.machine
    target = target or profile.default_target()
    detector = detector or profile.detector_for(target)
    caps_by_key = _capture_funcskip(scheme, profile, target, backend, keys, n)
    featurize = _make_featurize(profile, detector)
    detect = _make_detect(profile, detector, calibrate, n_perm)

    swept = skip_sweep(m, target, caps_by_key, featurize, detect,
                       backend=backend, persistent=True, budget=budget)
    rows = []
    for r in swept:
        metric, pvalue = r.get("metric"), r.get("pvalue")
        ran, crashed = r["ran"], r["crashed"]
        if ran < 3 or metric is None:
            status = "crash"
        elif not calibrate:
            status = "LEAK" if r.get("leak") else "ok"
        else:
            status = "pending"                    # finalized by the sweep-wide FDR pass
        row = SiteResult(r["pc"], r["text"], metric, status, ran, crashed, pvalue=pvalue)
        rows.append(row)
        if progress:
            progress(row)
    if calibrate:
        _apply_correction(rows, fdr_q, correction)
    return AssessmentResult(scheme.name, "funcskip", detector, n, rows,
                            calibrate=calibrate, fdr_q=fdr_q, correction=correction,
                            n_perm=n_perm)


class _Unstable(Exception):
    pass
