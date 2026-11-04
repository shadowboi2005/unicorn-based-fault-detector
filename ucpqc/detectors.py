"""Statistical primitives for the two retained detectors.

Scope note: the platform's fault model is single-signature **instruction skip**, so
it keeps exactly two detectors (see `report/detector_inventory.md`):

  * **per_coord** -- per-coordinate TVLA (:func:`tvla_max`): does ANY single output
    coordinate separate the two keys?  The one detector with a confirmed hit
    (`polyvecl_add`).  Maps to the LLVM study's `correction` oracle.
  * **per-position phi_IF** -- key-dependent ineffectiveness, per output position
    (`ucpqc.phi`).  Maps to the LLVM study's `ineffective` oracle.  Uses
    :func:`bh_fdr` here and scipy's Fisher exact test.

Both sweep over many sites, so both compose their per-site/per-position p-values with
a multiple-testing correction (:func:`bh_fdr` / :func:`holm_bonferroni`).

The richer detectors (two_key/subspace/structural/mmd/uniformity/spec_aware/
differential/sifa and their primitives) targeted fault models this platform does not
run; they were removed on branch `refactor/trim-detectors-instr-skip` and can be
restored from git history if a data-fault / MAYO / multi-signature regime is added
back.  `report/detector_inventory.md` records the rationale per detector.
"""

import numpy as np

__all__ = ["matched_filter", "tvla_t", "tvla_max", "bh_fdr", "holm_bonferroni"]

TVLA_T = 4.5           # classic per-coordinate TVLA |t| flag (informational count)


# --------------------------------------------------------------------------
# feature extraction (per_coord's challenge-aware feature)
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
    support = np.nonzero(c)[0]                        # the sparse challenge's nonzero positions
    c_support = np.asarray(c, float)[support]
    filtered = np.zeros((L, NC))
    for poly in range(L):
        z_poly = z[poly]
        for lag in range(NC):
            idx = support + lag
            sign = np.where(idx >= NC, -1.0, 1.0)     # negacyclic wrap: x^NC = -1
            filtered[poly, lag] = np.sum(c_support * sign * z_poly[idx % NC])
    return filtered.ravel()


# --------------------------------------------------------------------------
# per_coord -- per-coordinate TVLA leak localization
# --------------------------------------------------------------------------
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
    """Detector `per_coord` -- per-coordinate leak localization.

    Reduces the per-coordinate TVLA (:func:`tvla_t`) to one statistic: the
    maximum ``|t|`` over all D coordinates, plus how many coordinates clear the
    classic 4.5 threshold.  Asks "does ANY single output position separate the
    keys?" -- catching a secret coefficient exposed at a fixed byte.  The caller
    applies a multiple-comparison-corrected threshold (D coordinates were tested).
    Returns ``(max_abs_t, n_over)`` where n_over counts coordinates past the
    classic ``TVLA_T`` flag (informational; the verdict uses the corrected
    threshold)."""
    at = np.abs(tvla_t(F0, F1))
    return (float(np.nanmax(at)) if at.size else 0.0,
            int(np.sum(at > TVLA_T)))


# --------------------------------------------------------------------------
# multiple-testing corrections (shared by per_coord sweeps and per-position phi)
# --------------------------------------------------------------------------
def bh_fdr(pvals, q):
    """Benjamini-Hochberg step-up rejection mask controlling the false-discovery
    rate at level ``q``.  ``pvals`` is a 1-D array; returns a bool array (input
    order) that is True where the null is rejected -- i.e. a genuine leak among the
    many sites tested, with an expected false-discovery proportion <= ``q``."""
    p = np.asarray(pvals, float)
    m = p.size
    if m == 0:
        return np.zeros(0, dtype=bool)
    order = np.argsort(p)
    passing = p[order] <= q * (np.arange(1, m + 1) / m)
    mask = np.zeros(m, dtype=bool)
    hits = np.nonzero(passing)[0]
    if hits.size:                                     # reject up to the largest passing rank
        mask[order[: int(hits.max()) + 1]] = True
    return mask


def holm_bonferroni(pvals, alpha):
    """Holm-Bonferroni step-down rejection mask controlling the family-wise error
    rate at level ``alpha`` (stricter, fewer discoveries than :func:`bh_fdr`)."""
    p = np.asarray(pvals, float)
    m = p.size
    if m == 0:
        return np.zeros(0, dtype=bool)
    order = np.argsort(p)
    passing = p[order] <= alpha / (m - np.arange(m))
    stop = m if passing.all() else int(np.nonzero(~passing)[0][0])
    mask = np.zeros(m, dtype=bool)
    mask[order[:stop]] = True
    return mask
