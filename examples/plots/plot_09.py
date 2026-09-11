"""Render the distributions behind the ALAFA sweep (example 09) as PNGs.

The sweep collapses each fault site to ONE number: two-key classifier accuracy.
This script keeps the underlying distributions so we can look at them.  For every
non-crashing site it runs the same two-key leakage test, but retains:

  * the per-signature feature vectors (matched-filter of challenge c against z),
  * the leave-one-out signed score for each signature -- exactly the quantity the
    classifier thresholds:  score(x) = <x, g_own_LOO> - <x, g_other>.
    x belongs to key0 -> score should be > 0; key1 -> < 0.  The two score
    populations are the "distributions" the detector compares; separation == leak.

Outputs (examples/plots/9/):
  alafa_accuracy.png     bar chart of two-key accuracy for all 20 sites
  distributions.png      grid: the two-key score distribution at representative
                         sites (control, the flagged LEAK, and masked/ok sites)
  score_<pc>.png         one panel per representative site, standalone

    .venv/bin/python examples/plots/plot_09.py [firmware.elf] [n_per_key]
"""

import struct
import sys

sys.path.insert(0, ".")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from ucpqc import Machine, Scheme

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 28
CAP = 20_000_000
OUT = "examples/plots/9"

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


def loo_scores(F0, F1):
    """Leave-one-out signed score per signature: <x, g_own_LOO> - <x, g_other>.
    key0 sigs -> s0 (want >0), key1 sigs -> s1 (want <0).  Sign == classifier."""
    g1, g0 = F1.mean(0), F0.mean(0)
    s0 = np.array([F0[i] @ ((F0.sum(0) - F0[i]) / (len(F0) - 1)) - F0[i] @ g1
                   for i in range(len(F0))])
    s1 = np.array([F1[i] @ g0 - F1[i] @ ((F1.sum(0) - F1[i]) / (len(F1) - 1))
                   for i in range(len(F1))])
    return s0, s1


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

# representative sites to draw score distributions for (skip if they crash)
FEATURED = [None, 0x4d5e, 0x4cc4, 0x4cec, 0x4d68, 0x4dca]


def run_site(pc):
    """Return (acc, s0, s1) or None if the fault destabilises signing."""
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
    s0, s1 = loo_scores(F0, F1)
    acc = (np.mean(s0 > 0) + np.mean(s1 < 0)) / 2
    return acc, s0, s1


print(f"{scheme.name}  plotting ALAFA distributions  N={N}/key  -> {OUT}/")
results = {}
for pc, label in SITES:
    r = run_site(pc)
    tag = "control" if pc is None else f"{pc:#06x}"
    if r is None:
        print(f"  {label:<30} crash/hang")
        results[pc] = None
    else:
        acc = r[0]
        flag = "LEAK" if (pc is not None and acc >= 0.80) else "ok"
        print(f"  {label:<30} acc={acc:4.0%}   {flag}")
        results[pc] = r

label_of = dict(SITES)

# ---- plot 1: accuracy bar chart across all sites ---------------------------
order = SITES
names, accs, colors = [], [], []
for pc, label in order:
    r = results[pc]
    names.append(label)
    if r is None:
        accs.append(0.0); colors.append("#bdbdbd")            # grey = crash/hang
    else:
        a = r[0]; accs.append(a)
        if pc is None:
            colors.append("#4c72b0")                          # blue = control
        elif a >= 0.80:
            colors.append("#c44e52")                          # red = LEAK
        else:
            colors.append("#55a868")                          # green = ok

fig, ax = plt.subplots(figsize=(9, 7))
y = np.arange(len(names))[::-1]
ax.barh(y, [a * 100 for a in accs], color=colors, edgecolor="white")
ax.axvline(80, color="#c44e52", ls="--", lw=1, label="leak threshold (80%)")
ax.axvline(50, color="#888888", ls=":", lw=1, label="chance (50%)")
for yi, (pc, _), a in zip(y, order, accs):
    txt = "crash/hang" if results[pc] is None else f"{a:.0%}"
    ax.text(2, yi, txt, va="center", ha="left", fontsize=7.5,
            color="white" if (results[pc] is not None and a > 0.15) else "black")
ax.set_yticks(y); ax.set_yticklabels(names, fontsize=8)
ax.set_xlim(0, 100); ax.set_xlabel("two-key classifier accuracy (%)")
ax.set_title(f"ALAFA sweep — {scheme.name}: leakage per skip-fault site (N={N}/key)")
ax.legend(loc="lower right", fontsize=8)
fig.tight_layout()
fig.savefig(f"{OUT}/alafa_accuracy.png", dpi=130)
plt.close(fig)
print(f"  wrote {OUT}/alafa_accuracy.png")

# ---- plot 2: score distributions at representative sites -------------------
feat = [pc for pc in FEATURED if results.get(pc) is not None]
ncol = 3
nrow = int(np.ceil(len(feat) / ncol))
fig, axes = plt.subplots(nrow, ncol, figsize=(4.4 * ncol, 3.2 * nrow),
                         squeeze=False)


def draw_scores(ax, pc):
    acc, s0, s1 = results[pc]
    both = np.concatenate([s0, s1])
    mu, sd = both.mean(), both.std() or 1.0
    z0, z1 = (s0 - mu) / sd, (s1 - mu) / sd
    bound = (0 - mu) / sd                          # classifier boundary (raw 0)
    lo, hi = min(z0.min(), z1.min()), max(z0.max(), z1.max())
    bins = np.linspace(lo, hi, 16)
    ax.hist(z0, bins=bins, alpha=0.6, color="#4c72b0", label="key A")
    ax.hist(z1, bins=bins, alpha=0.6, color="#dd8452", label="key B")
    ax.axvline(bound, color="black", ls="--", lw=1)
    leak = pc is not None and acc >= 0.80
    title = ("control (no fault)" if pc is None else label_of[pc])
    ax.set_title(f"{title}\nacc={acc:.0%}" + ("  ← LEAK" if leak else ""),
                 fontsize=9, color="#c44e52" if leak else "black")
    ax.set_xlabel("key-A-ness score (standardized)"); ax.set_ylabel("# sigs")
    ax.legend(fontsize=7)


for ax, pc in zip(axes.ravel(), feat):
    draw_scores(ax, pc)
for ax in axes.ravel()[len(feat):]:
    ax.axis("off")
fig.suptitle("Two-key score distributions the ALAFA detector compares "
             "(overlap = hidden, separated = leak)", fontsize=11)
fig.tight_layout(rect=(0, 0, 1, 0.96))
fig.savefig(f"{OUT}/distributions.png", dpi=130)
plt.close(fig)
print(f"  wrote {OUT}/distributions.png")

# ---- per-site standalone panels -------------------------------------------
for pc in feat:
    fig, ax = plt.subplots(figsize=(5, 3.6))
    draw_scores(ax, pc)
    fig.tight_layout()
    name = "control" if pc is None else f"{pc:04x}"
    fig.savefig(f"{OUT}/score_{name}.png", dpi=130)
    plt.close(fig)
print(f"  wrote {OUT}/score_<site>.png  ({len(feat)} panels)")
print("done.")
