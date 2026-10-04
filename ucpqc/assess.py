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
    ineffective: object = None         # fraction of faulted outputs identical to golden (#2)


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
    key_mode: str = "independent"      # "independent" | "sibling" (one-byte key diff, #1)

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


def _make_keys(scheme, keys, key_mode, profile):
    """The two secret keys for the A/B comparison.  'independent' (default): one key
    per seed.  'sibling' (#1): key A from the first seed, key B = profile.sibling_key(skA)
    -- a controlled one-byte difference, so only a minimal secret change separates them."""
    if key_mode == "sibling":
        skA = _keypair(scheme, keys[0])[1]
        return {"A": skA, "B": profile.sibling_key(skA)}
    return {k: _keypair(scheme, seed)[1] for k, seed in zip("AB", keys)}


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


def _structural_nperm(n_perm):
    """Cap the permutation count for the structural detector.  Its field-rank score
    has a DEGENERATE null (~0 with no leak: permuted groups stay full rank), so the
    studentised tail is razor-sharp -- a real collapse gets ``p_tail ~ 0`` and clears
    a sweep-wide threshold at any site count, while golden stays at ``p = 1``.  A
    small count therefore suffices, and the field rank (over a ~1024-wide matrix) is
    the costly inner loop, so we cap it low."""
    return min(n_perm, 60)


# -- per-detector scoring ---------------------------------------------------
# Each scorer maps (A, B, profile, calibrate, n_perm) -> (metric, pvalue):
#   metric  -- the raw statistic, or None when there is too little data (the caller
#              turns that into a crash row);
#   pvalue  -- the calibrated per-site p-value, or None in legacy mode (where the
#              verdict is the fixed threshold in the _DETECTORS registry instead).
# The families differ only in HOW the p-value is calibrated: a key-label permutation
# test (classifiers + structural + mmd), an exact analytic tail (per_coord,
# uniformity), or certainty (a spec violation is not statistical).

def _feature_dim(A):
    return A.shape[1] if A.ndim > 1 else 1


def _permutation_scored(stat, A, B, calibrate, n_perm):
    """(metric, pvalue) for a statistic calibrated by a key-label permutation test."""
    metric = float(stat(A, B))
    if not calibrate:
        return metric, None
    _, p_emp, p_tail = detectors.perm_pvalue(stat, A, B, n_perm=n_perm)
    return metric, detectors._resolve_p(p_emp, p_tail, n_perm)


def _tail_resolved(obs, null, p_emp, n_perm):
    """Resolve an empirical p-value below its floor using the Gaussian tail of a
    precomputed null-sample array (for a detector that returns its own null)."""
    from scipy import stats
    sd = float(null.std(ddof=1))
    z = (obs - float(null.mean())) / sd if sd > 0 else np.inf
    return detectors._resolve_p(p_emp, float(stats.norm.sf(z)), n_perm)


def _score_two_key(A, B, profile, calibrate, n_perm):
    return _permutation_scored(detectors.two_key_accuracy, A, B, calibrate, n_perm)


def _score_subspace(A, B, profile, calibrate, n_perm):
    return _permutation_scored(detectors.lda_accuracy, A, B, calibrate, n_perm)


def _score_structural(A, B, profile, calibrate, n_perm):
    if profile.field is None:                     # scheme supplied no field-aware feature
        return None, None
    field = profile.field
    stat = lambda a, b: detectors.structural_leak(a, b, field)   # noqa: E731
    return _permutation_scored(stat, A, B, calibrate, _structural_nperm(n_perm))


def _score_mmd(A, B, profile, calibrate, n_perm):
    obs, null, p_emp = detectors.mmd_test(A, B, n_perm=n_perm)
    if not calibrate:
        return obs, None
    return obs, _tail_resolved(obs, null, p_emp, n_perm)


def _score_per_coord(A, B, profile, calibrate, n_perm):
    max_t, _ = detectors.tvla_max(A, B)
    return max_t, (None if not calibrate else _tvla_pvalue(max_t, _feature_dim(A)))


def _score_uniformity(A, B, profile, calibrate, n_perm):
    if len(A) < 1:
        return None, None
    pool = A.ravel()
    chi2, dof, spike = detectors.uniformity_divergence(pool, pool.min(), pool.max())
    if not calibrate:
        return spike, None
    from scipy import stats
    return spike, float(stats.chi2.sf(chi2, dof))


def _score_spec_aware(A, B, profile, calibrate, n_perm):
    bound = getattr(profile, "reject_bound", None)
    if bound is None or len(A) < 1:
        return None, None
    frac = detectors.band_count(A.ravel(), bound) / max(A.size, 1)
    return frac, (0.0 if frac > 0 else 1.0)       # a spec violation is certain, not statistical


def _score_differential(A, B, profile, calibrate, n_perm, golden=None):
    """#3: flag a key-dependent fault EFFECT.  Per item the effect is the magnitude of
    change from the golden (unfaulted) output, ``||faulted_z[i] - golden_z[i]||``, and
    the detector asks whether that effect is key-separable -- i.e. the fault matters for
    one key but not the other.  Magnitude (not the signed delta) keeps it nonce-neutral:
    mask removal (delta = -y) changes both keys similarly and does NOT fire here (that
    leak is two_key's); only a key-dependent *effectiveness* does.  Needs the golden
    baseline (returns None without it)."""
    if golden is None:
        return None, None
    gA = np.asarray(golden.get("A", []), float); gB = np.asarray(golden.get("B", []), float)
    nA, nB = min(len(A), len(gA)), min(len(B), len(gB))
    if nA < 3 or nB < 3:
        return None, None
    effect_A = np.linalg.norm(A[:nA] - gA[:nA], axis=1)[:, None]   # per-item change magnitude
    effect_B = np.linalg.norm(B[:nB] - gB[:nB], axis=1)[:, None]
    # the effects are same-sign magnitudes, so a Welch t (not the sign-based two_key
    # classifier) is the right 2-sample test; metric is |t|, with the analytic tail.
    max_t, _ = detectors.tvla_max(effect_A, effect_B)
    return max_t, (None if not calibrate else _tvla_pvalue(max_t, 1))


def _score_r0_reject(A, B, profile, calibrate, n_perm):
    """#4 (Finding-a-Polytope): A = per-signing out-of-spec r0 coefficient counts (from
    the profile's r0 observer).  Flag if ANY accepted signature had an out-of-spec r0
    (coeffs >= gamma2-beta); `frac` is the share of such signatures.  Deterministic
    (>0 is a real leak), like spec_aware but on the captured accepted r0."""
    pool = np.asarray(A, float).ravel()
    if pool.size < 1:
        return None, None
    frac = float(np.mean(pool > 0))
    return frac, (0.0 if frac > 0 else 1.0)


# name -> (scorer, legacy_verdict).  legacy_verdict(metric, A) -> bool is the
# pre-calibration fixed-threshold rule, kept beside each detector for
# --legacy-thresholds.  Detectors in _TWO_SAMPLE compare against a whole population
# and need >= 3 items per key; the rest guard inside their own scorer.
_DETECTORS = {
    "two_key":    (_score_two_key,    lambda metric, A: metric >= LEAK_THRESHOLD),
    "subspace":   (_score_subspace,   lambda metric, A: metric >= LEAK_THRESHOLD),
    "structural": (_score_structural, lambda metric, A: metric >= STRUCTURAL_THRESHOLD),
    "per_coord":  (_score_per_coord,  lambda metric, A: metric >= _tvla_threshold(_feature_dim(A))),
    "mmd":        (_score_mmd,        lambda metric, A: False),   # calibrated-only detector
    "uniformity": (_score_uniformity, lambda metric, A: metric > UNIFORMITY_SPIKE),
    "spec_aware": (_score_spec_aware, lambda metric, A: metric > 0),
    "r0_reject":  (_score_r0_reject,  lambda metric, A: metric > 0),   # #4: out-of-spec accepted r0 (Finding-a-Polytope)
    "differential": (_score_differential, lambda metric, A: metric >= _tvla_threshold(1)),
}
_TWO_SAMPLE = ("two_key", "subspace", "structural", "per_coord", "mmd", "differential")


def _detector(name):
    try:
        return _DETECTORS[name]
    except KeyError:
        raise ValueError(f"unknown detector {name!r}") from None


def _score_and_pvalue(name, feats, profile, calibrate, n_perm, golden=None):
    """Score one detector on the per-key feature lists -> (metric, pvalue), via its
    scorer in the _DETECTORS registry.  `golden` (the control baseline's per-key
    features) is only used by the `differential` detector."""
    A = np.array(feats["A"]); B = np.array(feats.get("B", []))
    if name in _TWO_SAMPLE and (len(A) < 3 or len(B) < 3):
        return None, None
    scorer = _detector(name)[0]
    if name == "differential":
        return scorer(A, B, profile, calibrate, n_perm, golden)
    return scorer(A, B, profile, calibrate, n_perm)


def _legacy_leak(name, metric, feats, profile):
    """The pre-calibration fixed-threshold verdict, kept for --legacy-thresholds."""
    if metric is None:
        return False
    return _detector(name)[1](metric, np.array(feats["A"]))


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
class _Unstable(Exception):
    """Raised internally to abandon a site whose signing crashed or hung."""


def _feature_for(profile, detector, machine, artifact):
    """This detector's feature for one released signature: the raw response for the
    `differential` detector (its effect is computed against the golden baseline),
    the field-element feature for `structural`, else the real-valued classifier
    feature."""
    resp = profile.response_from_signature(artifact)
    if detector == "differential":
        return np.asarray(resp, float).ravel()   # raw z; no challenge expansion needed
    c = profile.challenge(machine, artifact)
    if detector == "structural":
        return profile.structural_feature(c, resp)
    return profile.feature(c, resp)


def _collect_key_features(scheme, profile, sk, messages, site, detector, budget):
    """Sign every message under both keys with the site's whole-call skip installed,
    turning each released signature into this detector's feature AND keeping the raw
    artifact bytes.  Returns ``(feats, arts, crashed, unstable)``; the raw artifacts
    (paired with the golden baseline by nonce) feed the ineffective-fault and
    differential measurements.  The `r0_reject` detector instead captures the accepted
    r0 polyveck during signing (a scheme-internal quantity, via the profile's r0
    observer) as its feature.  A crashed/hung signing or a wrong-length artifact
    abandons the site (``unstable``), which then scores as a crash row."""
    m = scheme.machine
    feats = {"A": [], "B": []}
    arts = {"A": [], "B": []}
    crashed = 0
    obs = (profile.r0_observer(m) if detector == "r0_reject"
           and hasattr(profile, "r0_observer") else None)
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
                    arts[key].append(bytes(art))
                    if obs is not None:                   # r0_reject: per-signing out-of-spec r0 count
                        feats[key].append(obs.take())
                    else:
                        feats[key].append(_feature_for(profile, detector, m, art))
            except _Unstable:
                return feats, arts, crashed, True
            finally:
                if inj:
                    inj.detach()
    except EmulationError:                       # a fault outside signing (e.g. re-expanding c)
        return {"A": [], "B": []}, {"A": [], "B": []}, len(messages), True
    finally:
        if obs is not None:
            obs.detach()
    return feats, arts, crashed, False


def _ineffective_fraction(arts, golden_arts):
    """Fraction of faulted artifacts byte-identical to the golden (unfaulted) artifact
    for the same (key, item) -- i.e. the fault was a no-op (#2).  None when there is no
    golden baseline (the control row) or nothing ran."""
    if golden_arts is None:
        return None
    same = total = 0
    for key in ("A", "B"):
        g = golden_arts.get(key, [])
        for i, art in enumerate(arts.get(key, [])):
            if i < len(g):
                total += 1
                same += (art == g[i])
    return (same / total) if total else None


def _provisional_status(site, feats, metric, calibrate, detector, profile):
    """The row's status before the sweep-wide correction: control and crash are
    decided here; a calibrated detector row is 'pending' (finalized by
    :func:`_apply_correction`), a legacy row is decided now by its fixed threshold."""
    if site is None:
        return "control"
    if min(len(feats["A"]), len(feats["B"])) < 3 or metric is None:
        return "crash"
    if not calibrate:
        return "LEAK" if _legacy_leak(detector, metric, feats, profile) else "ok"
    return "pending"


def _run_site(scheme, profile, sk, messages, site, label, detector, budget,
              calibrate=True, n_perm=DEFAULT_N_PERM, golden=None):
    """Run ONE sweep site (whole-call skip) and return ``(SiteResult, collected)``.

    Pure and deterministic given its arguments, so the serial `sweep_sites` and the
    parallel backends share it and produce identical rows.  `site` is an int address,
    or None for the control row.  `golden` is the control row's `collected` data
    (``{feats, arts}``); the caller feeds the control's output back in as the baseline
    for every faulted site (ineffective-fault metric and differential detector).

    Site isolation matters: a faulted/hung signing leaves the guest dirty, so without
    a reset the next site inherits that state and its verdict depends on execution
    order -- fine serially, but non-deterministic once a pool schedules sites across
    workers.  We snapshot on entry and restore on exit so every site starts clean,
    which makes serial and both parallel backends agree exactly."""
    m = scheme.machine
    guard = m.snapshot()                         # leave the machine as we found it
    try:
        feats, arts, crashed, unstable = _collect_key_features(
            scheme, profile, sk, messages, site, detector, budget)
    finally:
        m.restore(guard)                         # isolate the next site from this one
    if unstable:
        metric, pvalue = None, None
    else:
        golden_feats = golden["feats"] if golden else None
        metric, pvalue = _score_and_pvalue(detector, feats, profile, calibrate, n_perm,
                                            golden_feats)
    status = _provisional_status(site, feats, metric, calibrate, detector, profile)
    ran = len(feats["A"]) + len(feats["B"])
    ineffective = None if site is None else _ineffective_fraction(
        arts, golden["arts"] if golden else None)
    row = SiteResult(site, label, metric, status, ran, crashed,
                     pvalue=pvalue, ineffective=ineffective)
    return row, {"feats": feats, "arts": arts}


def sweep_sites(scheme, profile, keys=DEFAULT_KEYS, n=DEFAULT_N,
                detector="two_key", budget=CAP, progress=None,
                calibrate=True, n_perm=DEFAULT_N_PERM, fdr_q=FDR_Q, correction="bh",
                key_mode="independent"):
    """Sweep every fault site from `profile.fault_sites`, re-running the operation
    with a persistent whole-call skip and scoring the leak of the released
    artifacts.  By default the verdict is calibrated: each site gets a permutation/
    analytic p-value, then a sweep-wide Benjamini-Hochberg pass flags leaks at FDR
    `fdr_q` (`calibrate=False` restores the legacy fixed cutoffs, decided per-site).
    Returns an `AssessmentResult`."""
    from .scheme import SIGN
    m = scheme.machine
    sk = _make_keys(scheme, keys, key_mode, profile)
    profile.setup(m)
    messages = standard_messages(n)
    op_func = scheme.binding.symbols["signature" if scheme.kind == SIGN else "dec"]
    sites = [(None, "no fault (control)")] + list(profile.fault_sites(m, op_func))

    rows = []
    golden = None                                # the control row becomes the baseline
    for site, label in sites:
        row, collected = _run_site(scheme, profile, sk, messages, site, label, detector,
                                   budget, calibrate=calibrate, n_perm=n_perm, golden=golden)
        rows.append(row)
        if site is None:
            golden = collected                   # unfaulted outputs, paired by nonce
        if progress:
            progress(row)
    if calibrate:
        _apply_correction(rows, fdr_q, correction)
    return AssessmentResult(scheme.name, "sweep", detector, n, rows,
                            calibrate=calibrate, fdr_q=fdr_q, correction=correction,
                            n_perm=n_perm, key_mode=key_mode)


# --------------------------------------------------------------------------
# mode "funcskip" -- instruction skips inside one function (capture-replay)
# --------------------------------------------------------------------------
def _capture_funcskip(scheme, profile, target, backend, keys, n, key_mode="independent"):
    """Capture the target's I/O across N signings per key -> {key: [Capture]}.

    The expensive funcskip prelude (2*N full signings).  Factored out so a
    parallel driver can capture once on the coordinator and ship the (pure-data,
    for the call backend) captures to workers.  Shared by the serial path."""
    m = scheme.machine
    sk = _make_keys(scheme, keys, key_mode, profile)
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
                   calibrate=True, n_perm=DEFAULT_N_PERM, fdr_q=FDR_Q, correction="bh",
                   key_mode="independent"):
    """Capture one function's I/O across N signings per key, then replay it under
    an instruction skip at every interior site and score the leak.  `target` is a
    `replay.Target` (defaults to `profile.default_target()`).  Verdict is calibrated
    by default (per-site p-value + sweep-wide FDR `fdr_q`); `calibrate=False` uses
    the legacy fixed cutoffs.  Returns an `AssessmentResult`."""
    m = scheme.machine
    target = target or profile.default_target()
    detector = detector or profile.detector_for(target)
    caps_by_key = _capture_funcskip(scheme, profile, target, backend, keys, n, key_mode)
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
                            n_perm=n_perm, key_mode=key_mode)
