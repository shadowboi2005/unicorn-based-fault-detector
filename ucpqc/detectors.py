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
    "matched_filter", "loo_scores", "two_key_accuracy", "tvla_t", "tvla_max",
    "lda_accuracy", "Field", "PrimeField", "GF2m", "structural_leak",
    "perm_pvalue", "mmd_test", "uniformity_divergence",
    "band_count", "band_levene",
]


# --------------------------------------------------------------------------
# feature extraction
# --------------------------------------------------------------------------
def matched_filter(c, z):
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


def tvla_max(F0, F1):
    """Detector A -- per-coordinate leak localization.

    Reduces the per-coordinate TVLA (:func:`tvla_t`) to one statistic: the
    maximum ``|t|`` over all D coordinates, plus how many coordinates clear the
    classic 4.5 threshold.  Where ``two_key_accuracy`` builds one whole-vector
    mean template (and so *dilutes* a leak that lives in a few coordinates across
    all D dims), this asks "does ANY single output position separate the keys?"
    -- catching a secret coefficient exposed at a fixed byte.  The caller applies
    a multiple-comparison-corrected threshold (D coordinates were tested).
    Returns ``(max_abs_t, n_over_4p5)``."""
    at = np.abs(tvla_t(F0, F1))
    return (float(np.nanmax(at)) if at.size else 0.0,
            int(np.sum(at > 4.5)))


def lda_accuracy(F0, F1, shrink=0.1):
    """Detector B -- covariance-aware (structural) separability.

    The generalization of :func:`two_key_accuracy`: whiten both populations by
    their pooled within-key covariance (shrunk toward a scaled identity so it
    inverts when D >> N), then run the same leave-one-out nearest-mean classifier
    in the whitened space.  Nearest-mean (``two_key``) assumes identity
    covariance and so only sees a whole-vector *mean shift*; after whitening the
    same classifier is a regularized linear discriminant that also separates keys
    differing in a **low-dimensional / correlated subspace** -- the structure the
    piece-by-piece accumulation attacks (faulted outputs confined to a
    key-dependent subspace, e.g. MAYO's oil space; Dilithium's ``z = c*s1``)
    reveal but a mean template misses.  ``two_key`` is the ``shrink=1`` (identity
    whitening) special case; per-coordinate (:func:`tvla_max`) is the diagonal
    case.  Returns leave-one-out accuracy in ``[0, 1]`` (0.5 = chance).

    LDA needs an estimable within-key covariance, so when D >> N we first project
    onto the top ``<= N-2`` principal components of the pooled data; this bounds
    the covariance rank and stops the whitening from over-fitting spurious
    high-dimensional directions (which otherwise inflates accuracy on pure noise).
    Even so, treat B as trustworthy only with N well above the retained component
    count -- at small N it is optimistic and should be permutation-calibrated."""
    F0, F1 = np.asarray(F0, float), np.asarray(F1, float)
    n0, n1 = len(F0), len(F1)
    if n0 < 2 or n1 < 2:
        return two_key_accuracy(F0, F1)
    X = np.vstack([F0, F1])
    X = X[:, None] if X.ndim == 1 else X
    Xc = X - X.mean(0)
    ncomp = max(1, min(X.shape[1], n0 + n1 - 2))            # bound cov rank at N-2
    _, _, Vt = np.linalg.svd(Xc, full_matrices=False)
    P = Vt[:ncomp].T                                        # D x ncomp PCA basis
    G0, G1 = F0 @ P, F1 @ P
    d = ncomp
    C0, C1 = G0 - G0.mean(0), G1 - G1.mean(0)
    S = (C0.T @ C0 + C1.T @ C1) / max(n0 + n1 - 2, 1)       # pooled within-key cov
    S = np.atleast_2d(S)
    mu = np.trace(S) / d
    Sr = (1.0 - shrink) * S + shrink * mu * np.eye(d)       # shrink -> invertible
    vals, vecs = np.linalg.eigh(Sr)
    W = vecs @ np.diag(np.clip(vals, 1e-12, None) ** -0.5) @ vecs.T   # Sr^{-1/2}
    return two_key_accuracy(G0 @ W, G1 @ W)                 # nearest-mean, whitened


# --------------------------------------------------------------------------
# field-parameterized structural / recoverability detector -- the algebra-aware
# generalization of B: a leak shows as the faulted outputs collapsing to a
# low-dimensional, key-dependent subspace OVER THE SCHEME'S OWN FIELD.  The
# arithmetic (rank over the field) is a pluggable backend so one detector serves
# GF(16) (MAYO) and Z_q (Dilithium) alike; the scheme supplies the feature rows.
# --------------------------------------------------------------------------
class Field:
    """Linear algebra over a scheme's algebra.  Subclasses implement ``rank`` of
    an integer matrix over the field; that is all ``structural_leak`` needs."""
    name = "field"

    def rank(self, M):                        # pragma: no cover - interface
        raise NotImplementedError


class PrimeField(Field):
    """GF(p) for a prime modulus -- Dilithium's coefficient field Z_q."""

    def __init__(self, p):
        self.p = int(p)
        self.name = f"GF({p})"

    def rank(self, M):
        p = self.p
        A = (np.asarray(M, dtype=object) % p).tolist()      # exact integer mod p
        rows, cols = len(A), (len(A[0]) if A else 0)
        r = 0
        for c in range(cols):
            piv = next((i for i in range(r, rows) if A[i][c] % p), None)
            if piv is None:
                continue
            A[r], A[piv] = A[piv], A[r]
            inv = pow(A[r][c], p - 2, p)                     # Fermat inverse (p prime)
            A[r] = [(v * inv) % p for v in A[r]]
            for i in range(rows):
                if i != r and A[i][c] % p:
                    f = A[i][c]
                    A[i] = [(a - f * b) % p for a, b in zip(A[i], A[r])]
            r += 1
            if r == rows:
                break
        return r


class GF2m(Field):
    """GF(2^m) via log/antilog tables (add = XOR) -- MAYO's field is GF(16)."""

    def __init__(self, m=4, poly=0x13):
        self.m, self.q = m, 1 << m
        self.name = f"GF(2^{m})"
        self._exp = [0] * (2 * self.q); self._log = [0] * self.q
        x = 1
        for i in range(self.q - 1):
            self._exp[i] = x; self._log[x] = i
            x <<= 1
            if x & self.q:
                x ^= poly
        for i in range(self.q - 1, 2 * self.q):
            self._exp[i] = self._exp[i - (self.q - 1)]

    def _mul(self, a, b):
        return 0 if a == 0 or b == 0 else self._exp[self._log[a] + self._log[b]]

    def _inv(self, a):
        return self._exp[(self.q - 1) - self._log[a]]

    def rank(self, M):
        A = [[int(v) & (self.q - 1) for v in row] for row in np.asarray(M).tolist()]
        rows, cols = len(A), (len(A[0]) if A else 0)
        r = 0
        for c in range(cols):
            piv = next((i for i in range(r, rows) if A[i][c]), None)
            if piv is None:
                continue
            A[r], A[piv] = A[piv], A[r]
            inv = self._inv(A[r][c])
            A[r] = [self._mul(v, inv) for v in A[r]]
            for i in range(rows):
                if i != r and A[i][c]:
                    f = A[i][c]
                    A[i] = [a ^ self._mul(f, b) for a, b in zip(A[i], A[r])]
            r += 1
            if r == rows:
                break
        return r


def structural_leak(F0, F1, field):
    """Detector B* -- field-aware structural / recoverability test.

    ``F0``/``F1`` are ``(N, D)`` integer matrices of FIELD ELEMENTS (the scheme's
    structural feature, e.g. MAYO's exposed oil bytes over GF(16), or Dilithium's
    per-signature ``s1`` estimate over Z_q).  A genuine leak makes each key's rows
    collapse to a low-dimensional subspace over ``field`` and makes the two keys'
    subspaces *differ* -- the structure accumulation attacks reveal and solve.
    Returns ``(score in [0,1], is_leak)``::

        collapse   = 1 - max(rank F0, rank F1) / full   # each key in few dims
        separation = (rank[F0;F1] - max) / min(rank)    # subspaces are key-specific
        score      = collapse * separation

    Golden/masked outputs stay full-rank -> collapse ~ 0 -> no leak."""
    F0 = np.asarray(F0); F1 = np.asarray(F1)
    if F0.ndim == 1:
        F0 = F0[:, None]; F1 = F1[:, None]
    # per-key ambient rank: a non-leaking key is full-rank (rank == its own N),
    # so collapse == 0; only a genuine subspace collapse (rank << N) is flagged.
    full = min(min(F0.shape[0], F1.shape[0]), F0.shape[1])
    rA, rB = field.rank(F0), field.rank(F1)
    rAB = field.rank(np.vstack([F0, F1]))
    collapse = 1.0 - max(rA, rB) / max(full, 1)
    separation = (rAB - max(rA, rB)) / max(min(rA, rB), 1)
    score = max(0.0, collapse) * max(0.0, separation)
    return float(score), score >= STRUCTURAL_THRESHOLD


STRUCTURAL_THRESHOLD = 0.5                    # score below which no structural leak


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
