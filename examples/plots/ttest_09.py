"""t-test leakage assessment for the ALAFA sweep (example 09).

The sweep reports a classifier accuracy.  Here we express the same "are the two
keys distinguishable?" question as proper statistical tests:

  1. TVLA per-coordinate Welch t  (the classic leakage t-test)
     For each of the 1024 matched-filter coordinates, a two-sample Welch t
     between key A's and key B's signatures.  No data-derived direction -> the
     p-values are honest.  Standard TVLA flags |t| > 4.5  (~ two-sided p < 1e-5).
     NB: a per-coordinate t-test on the RAW z coefficients is blind here
     (max|t| ~ 3.4) -- z's marginal is secret-independent by design.  The point
     of this file is that the SAME t-test, applied to the c-aware matched-filter
     feature, is no longer blind at a leaky site.

  2. Welch t on the 1D discriminant score  (effect size of the whole detector)
     t-test of the leave-one-out score s0 (key A) vs s1 (key B).  Descriptive:
     the score uses data-derived templates, so its parametric p is optimistic --
     which is exactly why we also run...

  3. Permutation p-value on the classifier accuracy  (assumption-free)
     Shuffle the key labels, recompute the leave-one-out accuracy, repeat.
     p = fraction of shuffles at least as separable as the real labels.  Immune
     to the data-derived-direction concern.

Outputs (examples/plots/9/):
  tvla_trace.png   per-coordinate |t| across the 1024 features, per site,
                   with the 4.5 TVLA threshold band
  tvla_maxt.png    max|t| per fault site (log scale) -- the t-test verdict

    .venv/bin/python examples/plots/ttest_09.py [firmware.elf] [n_per_key]
"""

import struct
import sys

sys.path.insert(0, ".")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

from ucpqc import Machine, Scheme

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 28
CAP = 20_000_000
OUT = "examples/plots/9"
TVLA_THRESH = 4.5
N_PERM = 2000
rng = np.random.default_rng(0)

L, NC, GAMMA1 = 4, 256, 1 << 17
CT, POLYZ = 32, NC * 18 // 8
SIGLEN = CT + POLYZ * L + 84

m = Machine.from_elf(ELF)
scheme = Scheme.bind(m)
m.boot()
cbuf = m.alloc(4 * NC)


def challenge(ctilde):
    m.call("pqcrystals_dilithium_poly_challenge", [cbuf, m.alloc_bytes(ctilde)])
    return np.array(struct.unpack(f"<{NC}i", m.read(cbuf, 4 * NC)), float)


def unpack_z(sig):
    off, z = CT, []
    for _ in range(L):
        a = sig[off:off + POLYZ]; off += POLYZ
        for i in range(NC // 4):
            b = a[9 * i:9 * i + 9]
            z += [GAMMA1 - (b[0] | b[1] << 8 | (b[2] & 3) << 16),
                  GAMMA1 - ((b[2] >> 2) | b[3] << 6 | (b[4] & 15) << 14),
                  GAMMA1 - ((b[4] >> 4) | b[5] << 4 | (b[6] & 63) << 12),
                  GAMMA1 - ((b[6] >> 6) | b[7] << 2 | b[8] << 10)]
    return np.array(z, float).reshape(L, NC)


def matched_filter(c, z):
    supp = np.nonzero(c)[0]; cs = c[supp]
    mf = np.zeros((L, NC))
    for l in range(L):
        zl = z[l]
        for lag in range(NC):
            idx = supp + lag
            mf[l, lag] = np.sum(cs * np.where(idx >= NC, -1.0, 1.0) * zl[idx % NC])
    return mf.ravel()


def make_key(seed):
    m.stub_randombytes(seed); return scheme.keypair()


k0 = make_key(b"secret-key-AAAA")[1]
k1 = make_key(b"secret-key-BBBB")[1]
messages = [f"msg-{i}".encode() for i in range(N)]


class Unstable(Exception):
    pass


def collect(sk, seed):
    m.stub_randombytes(seed); hwm = m._alloc_ptr
    feats = []
    for msg in messages:
        m._alloc_ptr = hwm
        try:
            sig = scheme.sign(msg, sk, max_instructions=CAP)
        except Exception:
            raise Unstable("sign failed")
        if len(sig) != SIGLEN:
            raise Unstable("malformed signature")
        feats.append(matched_filter(challenge(sig[:CT]), unpack_z(sig)))
    return np.array(feats)


def tvla_t(F0, F1):
    """Per-coordinate Welch t between the two key populations (1024-vector)."""
    n0, n1 = len(F0), len(F1)
    m0, m1 = F0.mean(0), F1.mean(0)
    v0, v1 = F0.var(0, ddof=1), F1.var(0, ddof=1)
    denom = np.sqrt(v0 / n0 + v1 / n1)
    denom[denom == 0] = np.inf                    # constant coords -> t = 0
    return (m0 - m1) / denom


def loo_scores_from(F0, F1):
    g1, g0 = F1.mean(0), F0.mean(0)
    s0 = np.array([F0[i] @ ((F0.sum(0) - F0[i]) / (len(F0) - 1)) - F0[i] @ g1
                   for i in range(len(F0))])
    s1 = np.array([F1[i] @ g0 - F1[i] @ ((F1.sum(0) - F1[i]) / (len(F1) - 1))
                   for i in range(len(F1))])
    return s0, s1


def accuracy(F0, F1):
    s0, s1 = loo_scores_from(F0, F1)
    return (np.mean(s0 > 0) + np.mean(s1 < 0)) / 2


def perm_pvalue(F0, F1):
    """How often do shuffled key labels reach the real labels' separability?"""
    obs = accuracy(F0, F1)
    X = np.vstack([F0, F1]); n = len(F0)
    ge = 1                                         # +1: observed counts as itself
    for _ in range(N_PERM):
        idx = rng.permutation(len(X))
        if accuracy(X[idx[:n]], X[idx[n:]]) >= obs:
            ge += 1
    return obs, ge / (N_PERM + 1)


SITES = [
    (None,   "no fault (control)"),
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
FEATURED = [None, 0x4d5e, 0x4cc4, 0x4cec, 0x4d68, 0x4dca]
label_of = dict(SITES)


def run_site(pc):
    h = None
    if pc is not None:
        h = m.hook_code(lambda mm, a, s, _pc=pc: mm.set_pc(_pc + 4),
                        begin=pc, end=pc, precise=False)
    try:
        F0, F1 = collect(k0, b"nonce-0"), collect(k1, b"nonce-1")
    except Unstable:
        return None
    finally:
        if h is not None:
            m.uc.hook_del(h); m.uc.ctl_flush_tb()
    return F0, F1


print(f"{scheme.name}  t-test leakage assessment  N={N}/key  perms={N_PERM}\n")
hdr = f"  {'site':<30} {'acc':>5} {'TVLA max|t|':>12} {'#>4.5':>6} " \
      f"{'discr t':>9} {'discr p':>10} {'perm p':>9}"
print(hdr); print("  " + "-" * (len(hdr) - 2))

data = {}
for pc, label in SITES:
    fb = run_site(pc)
    if fb is None:
        print(f"  {label:<30} {'crash/hang':>5}")
        data[pc] = None
        continue
    F0, F1 = fb
    t = tvla_t(F0, F1)
    maxt = np.max(np.abs(t)); nexc = int(np.sum(np.abs(t) > TVLA_THRESH))
    s0, s1 = loo_scores_from(F0, F1)
    dt = stats.ttest_ind(s0, s1, equal_var=False)
    obs, pp = perm_pvalue(F0, F1)
    data[pc] = dict(t=t, maxt=maxt, nexc=nexc, acc=obs,
                    disc_t=dt.statistic, disc_p=dt.pvalue, perm_p=pp)
    print(f"  {label:<30} {obs:5.0%} {maxt:12.1f} {nexc:6d} "
          f"{dt.statistic:9.2f} {dt.pvalue:10.1e} {pp:9.4f}")

print(f"\n  TVLA rule: a site leaks if any coordinate exceeds |t| = {TVLA_THRESH} "
      f"(~ p < 1e-5).")
print(f"  Reference: the same t-test on the RAW z coefficients gives max|t| ~ 3.4 "
      "(blind).")

# ---- plot 1: per-coordinate t traces for featured sites --------------------
feat = [pc for pc in FEATURED if data.get(pc) is not None]
ncol = 3
nrow = int(np.ceil(len(feat) / ncol))
fig, axes = plt.subplots(nrow, ncol, figsize=(4.6 * ncol, 3.0 * nrow),
                         squeeze=False)
for ax, pc in zip(axes.ravel(), feat):
    d = data[pc]
    ax.plot(np.abs(d["t"]), lw=0.6, color="#333333")
    ax.axhline(TVLA_THRESH, color="#c44e52", ls="--", lw=1)
    for b in range(1, L):
        ax.axvline(b * NC, color="#cccccc", lw=0.5)      # poly boundaries
    leak = d["maxt"] > TVLA_THRESH and pc is not None
    title = "control (no fault)" if pc is None else label_of[pc]
    ax.set_title(f"{title}\nmax|t|={d['maxt']:.1f}" + ("  ← LEAK" if leak else ""),
                 fontsize=9, color="#c44e52" if leak else "black")
    ax.set_xlabel("matched-filter coordinate"); ax.set_ylabel("|t|")
for ax in axes.ravel()[len(feat):]:
    ax.axis("off")
fig.suptitle("TVLA per-coordinate Welch t between the two keys "
             f"(dashed = {TVLA_THRESH} threshold)", fontsize=11)
fig.tight_layout(rect=(0, 0, 1, 0.95))
fig.savefig(f"{OUT}/tvla_trace.png", dpi=130)
plt.close(fig)
print(f"\n  wrote {OUT}/tvla_trace.png")

# ---- plot 2: max|t| per site (log scale) -----------------------------------
names, vals, colors = [], [], []
for pc, label in SITES:
    d = data[pc]
    names.append(label)
    if d is None:
        vals.append(np.nan); colors.append("#bdbdbd")
    else:
        vals.append(max(d["maxt"], 0.1))
        if pc is None:
            colors.append("#4c72b0")
        elif d["maxt"] > TVLA_THRESH:
            colors.append("#c44e52")
        else:
            colors.append("#55a868")

fig, ax = plt.subplots(figsize=(9, 7))
y = np.arange(len(names))[::-1]
plotted = [v if not np.isnan(v) else 0 for v in vals]
ax.barh(y, plotted, color=colors, edgecolor="white", log=True)
ax.axvline(TVLA_THRESH, color="#c44e52", ls="--", lw=1,
           label=f"TVLA threshold ({TVLA_THRESH})")
for yi, v in zip(y, vals):
    ax.text(0.12, yi, "crash/hang" if np.isnan(v) else f"{v:.1f}",
            va="center", ha="left", fontsize=7.5, color="black")
ax.set_yticks(y); ax.set_yticklabels(names, fontsize=8)
ax.set_xlabel("max |t| over 1024 matched-filter coordinates  (log scale)")
ax.set_xlim(0.1, max(v for v in vals if not np.isnan(v)) * 2)
ax.set_title(f"TVLA t-test per skip-fault site — {scheme.name} (N={N}/key)")
ax.legend(loc="lower right", fontsize=8)
fig.tight_layout()
fig.savefig(f"{OUT}/tvla_maxt.png", dpi=130)
plt.close(fig)
print(f"  wrote {OUT}/tvla_maxt.png")
print("done.")
