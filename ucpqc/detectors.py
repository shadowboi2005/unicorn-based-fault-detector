"""Distribution detectors for leakage / fault assessment.

These were developed and validated in examples 07-09 (two-key matched-filter
classifier, TVLA t-test, permutation p-value) and example 08 (spec-aware
band-localized r0 tests, MMD), where they lived as copy-pasted script-local
functions.  They are collected here so the ALAFA sweep (example 09) and the
intra-function skip tool (example 10) share one implementation.

Every detector consumes per-item feature vectors, shape ``(N, D)`` (or ``(N,)``
for scalar features), with the two populations passed as separate arrays.  The
right detector depends on the faulted quantity's *role*:

  * output is secret-dependent (c*s1, z, r0)  -> two_key_accuracy / tvla_t
  * output must be uniform (the nonce y)      -> uniformity_divergence
  * inline rejection decision (out-of-spec r0)-> band_levene / band_count
"""

import numpy as np

__all__ = [
    "matched", "loo_scores", "two_key_accuracy", "tvla_t", "perm_pvalue",
    "mmd_test", "uniformity_divergence", "band_count", "band_levene",
]


# --------------------------------------------------------------------------
# feature extraction
# --------------------------------------------------------------------------
def matched(c, z):
    """c-aware feature: negacyclic correlation of the sparse challenge ``c``
    against each response polynomial.

    ``c`` is a length-``NC`` array (the expanded challenge, mostly zero);
    ``z`` is an ``(L, NC)`` array of response polynomials.  Returns a flat
    ``L*NC`` feature vector.  z's *marginal* is secret-independent by design, so
    a plain histogram is blind -- the leak lives in the joint (c, z) relation
    this projection extracts.
    """
    z = np.asarray(z, float)
    L, NC = z.shape
    supp = np.nonzero(c)[0]
    cs = np.asarray(c, float)[supp]
    mf = np.zeros((L, NC))
    for l in range(L):
        zl = z[l]
        for lag in range(NC):
            idx = supp + lag
            mf[l, lag] = np.sum(cs * np.where(idx >= NC, -1.0, 1.0) * zl[idx % NC])
    return mf.ravel()


# --------------------------------------------------------------------------
# two-key (secret-dependence) tests -- example 07/09
# --------------------------------------------------------------------------
def loo_scores(F0, F1):
    """Leave-one-out signed discriminant score per item.

    ``score(x) = <x, g_own_LOO> - <x, g_other>`` against per-key mean templates,
    leaving x out of its own template so it never helps classify itself.  Key-0
    items should score > 0, key-1 items < 0.  Returns ``(s0, s1)``.
    """
    F0, F1 = np.asarray(F0, float), np.asarray(F1, float)
    g1, g0 = F1.mean(0), F0.mean(0)
    s0 = np.array([F0[i] @ ((F0.sum(0) - F0[i]) / (len(F0) - 1)) - F0[i] @ g1
                   for i in range(len(F0))])
    s1 = np.array([F1[i] @ g0 - F1[i] @ ((F1.sum(0) - F1[i]) / (len(F1) - 1))
                   for i in range(len(F1))])
    return s0, s1


def two_key_accuracy(F0, F1):
    """Fraction of items classified to the correct key (0.5 = indistinguishable,
    1.0 = fully separable).  This is the ALAFA leak metric of example 09."""
    s0, s1 = loo_scores(F0, F1)
    return (np.mean(s0 > 0) + np.mean(s1 < 0)) / 2


def tvla_t(F0, F1):
    """Per-coordinate Welch t between the two populations (length-D vector).
    TVLA flags a leak if any |t| > 4.5 (~ two-sided p < 1e-5)."""
    F0, F1 = np.asarray(F0, float), np.asarray(F1, float)
    n0, n1 = len(F0), len(F1)
    m0, m1 = F0.mean(0), F1.mean(0)
    v0, v1 = F0.var(0, ddof=1), F1.var(0, ddof=1)
    denom = np.sqrt(v0 / n0 + v1 / n1)
    denom = np.where(denom == 0, np.inf, denom)      # constant coords -> t = 0
    return (m0 - m1) / denom


def perm_pvalue(F0, F1, n_perm=2000, rng=None):
    """Assumption-free permutation p-value on two_key_accuracy: how often does a
    random key-label shuffle reach the observed separability.  Returns
    ``(observed_accuracy, p)``.  p at the 1/(n_perm+1) floor means chance never
    matched the real labels."""
    rng = np.random.default_rng(0) if rng is None else rng
    obs = two_key_accuracy(F0, F1)
    X = np.vstack([np.asarray(F0, float), np.asarray(F1, float)])
    n = len(F0)
    ge = 1                                            # observed counts as itself
    for _ in range(n_perm):
        idx = rng.permutation(len(X))
        if two_key_accuracy(X[idx[:n]], X[idx[n:]]) >= obs:
            ge += 1
    return obs, ge / (n_perm + 1)


def mmd_test(A, B, n_perm=1000, rng=None):
    """Kernel two-sample MMD^2 with a Gaussian (median-bandwidth) kernel and a
    permutation-calibrated p-value.  Model-agnostic 'are these two point clouds
    different' test; returns ``(observed_mmd2, null_samples, p)``."""
    rng = np.random.default_rng(0) if rng is None else rng
    A, B = np.asarray(A, float), np.asarray(B, float)
    Z = np.vstack([A, B])
    n0, tot = len(A), len(Z)
    sq = np.sum(Z * Z, 1)[:, None] + np.sum(Z * Z, 1)[None, :] - 2 * Z @ Z.T
    np.maximum(sq, 0, out=sq)
    K = np.exp(-sq / (np.median(sq[sq > 0]) + 1e-12))

    def mmd2(i0, i1):
        return (K[np.ix_(i0, i0)].mean() + K[np.ix_(i1, i1)].mean()
                - 2 * K[np.ix_(i0, i1)].mean())

    obs = mmd2(np.arange(n0), np.arange(n0, tot))
    null = np.empty(n_perm)
    for i in range(n_perm):
        p = rng.permutation(tot)
        null[i] = mmd2(p[:n0], p[n0:])
    return obs, null, (1 + int(np.sum(null >= obs))) / (1 + n_perm)


# --------------------------------------------------------------------------
# uniformity / bias test -- for a nonce that must be uniform (y)
# --------------------------------------------------------------------------
def uniformity_divergence(samples, lo, hi, bins=64, ref_counts=None):
    """Chi-square divergence of a coefficient distribution from uniform (or from
    a supplied golden reference histogram ``ref_counts``) over ``[lo, hi)``.

    A fresh Dilithium nonce y is uniform on (-gamma1, gamma1]; a loop-abort
    leaves a block of coefficients at a constant, spiking the histogram.  Returns
    ``(chi2, dof, spike_fraction)`` where spike_fraction is the largest single
    bin's share (a blunt 'how concentrated' readout)."""
    x = np.asarray(samples, float).ravel()
    edges = np.linspace(lo, hi, bins + 1)
    obs, _ = np.histogram(x, bins=edges)
    if ref_counts is None:
        exp = np.full(bins, obs.sum() / bins, float)
    else:
        ref = np.asarray(ref_counts, float)
        exp = ref * (obs.sum() / ref.sum())
    exp = np.where(exp == 0, 1e-9, exp)
    chi2 = float(np.sum((obs - exp) ** 2 / exp))
    spike = float(obs.max() / obs.sum()) if obs.sum() else 0.0
    return chi2, bins - 1, spike


# --------------------------------------------------------------------------
# spec-aware / rejection-boundary tests -- example 08
# --------------------------------------------------------------------------
def band_count(coeffs, bound):
    """How many coefficients (across the flattened array) reach or exceed the
    spec bound in magnitude -- the count that is 0 for every accepted golden
    signature and non-zero once a rejection check is bypassed."""
    return int(np.sum(np.abs(np.asarray(coeffs, float)) >= bound))


def band_levene(golden, fault, band):
    """Brown-Forsythe (median-centered Levene) equal-variance test restricted to
    the edge band ``|coeff| >= band`` -- the localized second-order test that
    sees the rejection-boundary spill a global variance test misses.  Returns
    ``(W, p)`` or ``(nan, nan)`` if either side has too few band samples."""
    from scipy import stats
    g = np.abs(np.asarray(golden, float).ravel()); g = g[g >= band]
    f = np.abs(np.asarray(fault, float).ravel()); f = f[f >= band]
    if g.size < 3 or f.size < 3:
        return float("nan"), float("nan")
    return stats.levene(g, f, center="median")
