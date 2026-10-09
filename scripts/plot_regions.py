#!/usr/bin/env python3
"""Per-instruction ARM TVLA maps for the bigger Dilithium functions, annotated with the
function's LLVM-IR tainted-instruction breakdown -- to line up the leaking ARM code
regions against the IR instructions the Dilithium-LLVM tool flagged.
Writes examples/plots/<fn>_by_instr.png for each.  Run after the dumps exist."""
import os, json, sys, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); os.chdir(ROOT)
import numpy as np, matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from ucpqc import Machine, Scheme, assess

TAINT = "../Dilithium-LLVM/llvm/taintResults"
BIG = ["polyvecl_add", "ntt", "invntt_tomont", "poly_uniform", "poly_decompose",
       "poly_make_hint", "poly_sub", "polyvec_matrix_pointwise_montgomery"]
TH = 4.5

def llvm_taint(fn):
    """{IR-instruction-type: count} for this function, from the taint results."""
    p = os.path.join(TAINT, f"pqcrystals_dilithium2_ref_{fn}.json")
    if not os.path.exists(p):
        return {}
    d = json.load(open(p))
    return collections.Counter(v["type"] for v in d.values())

def plot(fn, m):
    dumpdir = f"dumps/{fn}_instrskip"
    if not os.path.exists(os.path.join(dumpdir, "meta.json")):
        print("  (no dump)", fn); return
    res = assess.assess_funcskip_from_dump(dumpdir, detector="per_coord")
    byaddr = {r.addr: r for r in res.rows}
    sym = f"pqcrystals_dilithium_{fn}"
    try:
        s, e = m.image.extent_of(sym)
    except Exception:
        print("  (no symbol)", fn); return
    instrs, pc = [], s
    while pc < e:
        _, sz, txt = m.disasm_one(pc); instrs.append((pc, txt)); pc += sz or 2
    vals, cols, crash = [], [], []
    for pc, _ in instrs:
        r = byaddr.get(pc)
        if not r or r.metric is None:
            vals.append(0); cols.append("#d9dde1"); crash.append(True)
        else:
            vals.append(r.metric); cols.append("#c0392b" if r.status == "LEAK" else "#8a97a4"); crash.append(False)
    taint = llvm_taint(fn)
    tstr = ", ".join(f"{n}×{t.replace('Inst','')}" for t, n in taint.most_common()) or "none"
    wide = len(instrs) > 60                               # too many instrs to label individually
    fig, ax = plt.subplots(figsize=(min(22, max(8, len(instrs) * 0.5)), 4.6))
    x = np.arange(len(instrs))
    ax.bar(x, vals, color=cols, width=0.9 if wide else 0.72)
    ax.axhline(TH, color="#555", ls="--", lw=1)
    if wide:
        ax.set_xlabel(f"instruction index  (0..{len(instrs)-1};  {len(instrs)} instrs, "
                      f"{sum(crash)} skip-crashes)")
    else:
        for i, c in enumerate(crash):
            if c: ax.text(i, 0.1, "crash", ha="center", va="bottom", fontsize=6, color="#8a97a4", rotation=90)
        ax.set_xticks(x); ax.set_xticklabels([f"{pc:#06x} {t}" for pc, t in instrs],
                                             rotation=55, ha="right", fontsize=6.5, family="monospace")
    ax.set_ylabel("max |Welch t| (A vs B)")
    ax.set_title(f"ARM per-instruction TVLA — pqcrystals_dilithium_{fn}  (n={res.n})\n"
                 f"red=LEAK (FDR≤0.01), grey=no leak, light=crash   |   "
                 f"LLVM IR tainted: {sum(taint.values())} instrs ({tstr})", fontsize=9.5, loc="left")
    ax.spines[['top', 'right']].set_visible(False); ax.margins(x=0.01)
    fig.tight_layout()
    out = f"examples/plots/{fn}_by_instr.png"
    fig.savefig(out, dpi=140, bbox_inches="tight"); plt.close(fig)
    nleak = sum(1 for r in res.rows if r.status == "LEAK")
    print(f"  wrote {out}  (ARM {nleak} LEAK sites; LLVM {sum(taint.values())} tainted IR instrs)")

def main():
    m = Machine.from_elf("firmware/ml-dsa-44_m4f_test.elf"); Scheme.bind(m)
    os.makedirs("examples/plots", exist_ok=True)
    for fn in BIG:
        plot(fn, m)

if __name__ == "__main__":
    main()
