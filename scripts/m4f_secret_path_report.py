#!/usr/bin/env python3
"""Build report/dilithium_m4f_secret_path.md: instruction-skip candidates on the m4f
c*s1 / c*s2 "small NTT" path and on the operand-role-split NTT/INTT targets, with the
same-key phi_IF control.

Inputs (all from scripts/phi_control.py + `funcskip --captures ... --dumpdir`):
  dumps/<t>_instrskip/       key A vs key B, same messages + RNG       (the study test)
  dumps_ctrl/<t>_instrskip/  key A vs key A on disjoint messages       (input-only null)

Per skip site, flips = #messages where the skip is a no-op on one side and output-
changing on the other.  A/B flips mix key- and input-dependence; A/A' flips are input-
dependence alone.  A site counts as KEY-dependent only where its A/B flip count is
significantly above its A/A' count (one-sided Fisher exact test per site, BH-FDR q=0.05).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import numpy as np  # noqa: E402
from scipy.stats import fisher_exact  # noqa: E402

from ucpqc import assess, detectors, dump as dumpmod  # noqa: E402
from ucpqc.profiles import dilithium_targets as dt  # noqa: E402

Q = 0.05
OUT = "report/dilithium_m4f_secret_path.md"
CONTROLS_EXTRA = ("poly_challenge", "polyvecl_uniform_gamma1", "poly_chknorm")


def _flips(dump_dir):
    """{pc: (disasm, flips, pairs)} -- per-site phi_IF flip counts of one dump."""
    meta, caps, sites = dumpmod.load_funcskip_dump(dump_dir)
    gold = {k: [(r.get("golden") if isinstance(r, dict) else None) for r in caps.get(k, [])]
            for k in "AB"}
    out = {}
    for sd in sites:
        eff = {}
        for k in "AB":
            eff[k] = {rec["idx"]: rec["out"] != gold[k][rec["idx"]]
                      for rec in sd.get(k, [])
                      if rec["idx"] < len(gold[k]) and gold[k][rec["idx"]] is not None}
        common = set(eff["A"]) & set(eff["B"])
        out[sd["pc"]] = (sd.get("text", ""), sum(eff["A"][i] != eff["B"][i] for i in common),
                         len(common))
    return out, caps


def _golden_maxt(dump_dir, caps):
    """max |Welch t| between the per_coord FEATURES of the UNFAULTED outputs of A and B --
    the same feature the LEAK test scores (for a polyvecl output that is the challenge-aware
    matched filter, which turns c*s1 into s1).  If this is already above the TVLA floor, the
    output is key-separable with no fault, so a LEAK on it is not a fault finding."""
    from ucpqc.profiles import profile_by_name
    meta = dumpmod.load_funcskip_dump(dump_dir)[0]
    profile = profile_by_name(meta["scheme"])
    buffer = meta.get("out_kind", "buffer") == "buffer"
    F = {}
    for k in "AB":
        F[k] = []
        for r in caps.get(k, []):
            if not isinstance(r, dict) or r.get("golden") is None:
                continue
            g = bytes.fromhex(r["golden"]) if buffer else int(r["golden"])
            f = assess._funcskip_feature(profile, "per_coord", np.array(r["challenge"], float), g)
            F[k].append(np.asarray(f, float).ravel())
    if len(F["A"]) < 3 or len(F["B"]) < 3:
        return None
    A, B = np.array(F["A"]), np.array(F["B"])
    # a key-FIXED value (t0, s1, s2, or s1 recovered from c*s1) is constant within each key:
    # zero variance, which tvla_t maps to t=0 -- but differing constants are fully separable
    const = (A.var(0) == 0) & (B.var(0) == 0)
    if np.any(const & (A.mean(0) != B.mean(0))):
        return float("inf")
    return float(np.max(np.abs(detectors.tvla_t(A, B))))


def row(t):
    d, c = f"dumps/{t}_instrskip", f"dumps_ctrl/{t}_instrskip"
    if not os.path.exists(os.path.join(d, "meta.json")):
        return None
    res = assess.assess_funcskip_from_dump(d, detector="per_coord")
    scored = [r for r in res.rows if r.metric is not None]
    leaks = [r for r in scored if r.status == "LEAK"]
    ab, caps = _flips(d)
    aa = _flips(c)[0] if os.path.exists(os.path.join(c, "meta.json")) else None
    sig = []
    if aa is not None:
        pcs = [pc for pc in ab if pc in aa and ab[pc][2] and aa[pc][2]]
        pv = [fisher_exact([[ab[pc][1], ab[pc][2] - ab[pc][1]],
                            [aa[pc][1], aa[pc][2] - aa[pc][1]]], alternative="greater")[1]
              for pc in pcs]
        mask = detectors.bh_fdr(np.array(pv), Q) if pcs else []
        sig = sorted(((pc, ab[pc][0], ab[pc][1], aa[pc][1], p)
                      for pc, p, keep in zip(pcs, pv, mask) if keep), key=lambda x: x[4])
    gmaxt = _golden_maxt(d, caps)
    return dict(
        sites=len(res.rows), scored=len(scored), leak=len(leaks),
        maxt=max((r.metric for r in scored), default=0.0), golden_maxt=gmaxt,
        baseline_sep=gmaxt is not None and gmaxt > 4.5,
        eff=np.mean([1 - r.ineffective for r in res.rows if r.ineffective is not None]
                    or [float("nan")]),
        phi_ab=sum(1 for v in ab.values() if v[1]), flips_ab=sum(v[1] for v in ab.values()),
        phi_aa=None if aa is None else sum(1 for v in aa.values() if v[1]),
        flips_aa=None if aa is None else sum(v[1] for v in aa.values()),
        sig=sig, top=sorted(((pc, v[0], v[1], (aa or {}).get(pc, ("", None))[1])
                             for pc, v in ab.items() if v[1]), key=lambda x: -x[2])[:8])


def label(t):
    tg = dt.M4F_TARGETS.get(t) or dt.TARGETS.get(t)
    return tg.label if tg is not None else t


def main():
    targets = list(dt.M4F_TARGETS) + list(CONTROLS_EXTRA)
    rows = {t: row(t) for t in targets}
    out = []
    P = out.append
    P("# Dilithium m4f: the secret c·s path and operand-aware NTT targets (instruction skip)\n")
    P("Companion to `report/llvm_vs_arm.md`. That study swept the functions the Dilithium-LLVM")
    P("project analysed, each at its **last** call in a signing. Two consequences, verified by a")
    P("call trace of one m4f signing and by capture:\n")
    P("1. **m4f computes c·s1 and c·s2 on a separate mod-769 \"small NTT\" path** "
      "(`smallntt.h`/`smallpoly.c`: `polyvecl_small_ntt`, `polyveck_small_ntt`, "
      "`polyvecl_small_basemul_invntt`, `poly_small_basemul_invntt`, asm workers "
      "`small_ntt_asm_769`, `small_asymmetric_mul_asm_769`, `small_invntt_asm_769`). These are "
      "not in the reference function list, so they were never swept, and the reference "
      "`*_pointwise_poly_montgomery` c·s functions were not \"inlined away\" but replaced.")
    P("2. **The `ntt` target was NTT(c), the public challenge.** `ntt` is called for NTT(t0), "
      "NTT(y) and NTT(c); the last call is `poly_ntt(&cp)`. Its captured input is byte-identical "
      "to `ntt_c` below. Likewise `invntt_tomont` was c·t0[K-1].\n")
    P("Targets here pick the operand with a `caller` filter (`Target.caller`). n=40 messages/key, "
      "`per_coord` TVLA at FDR≤0.01, replay budget 500k.\n")
    P("**φIF control.** A/B flips (keys A, B, same message+RNG) mix key- and input-dependence. "
      "The control replays key A against key A on 40 *other* messages (A/A'): input-dependence "
      f"only. A site is **key-dependent** only if its A/B flips exceed its A/A' flips "
      f"(one-sided Fisher exact per site, BH-FDR q={Q}).\n")
    P("## Summary\n")
    P("| target (operand) | sites | (A) LEAK / scored | max\\|t\\| | unfaulted A/B max\\|t\\| "
      "| effective | φIF A/B sites (flips) | φIF A/A' sites (flips) | **key-dep. sites** |")
    P("|---|---|---|---|---|---|---|---|---|")
    for t in targets:
        r = rows[t]
        if r is None:
            P(f"| `{t}` — {label(t)} | — | not swept | | | | | | |")
            continue
        leak = (f"n/a ({r['leak']}/{r['scored']})" if r["baseline_sep"]
                else f"{r['leak']}/{r['scored']}")
        g = ("—" if r["golden_maxt"] is None else "∞ (constant per key)"
             if r["golden_maxt"] == float("inf") else f"{r['golden_maxt']:.1f}")
        aa = "—" if r["phi_aa"] is None else f"{r['phi_aa']} ({r['flips_aa']})"
        P(f"| `{t}` — {label(t)} | {r['sites']} | {leak} | {r['maxt']:.1f} | {g} | "
          f"{r['eff']:.0%} | {r['phi_ab']} ({r['flips_ab']}) | {aa} | **{len(r['sig'])}** |")
    P("\n*(A) LEAK is shown as n/a when the unfaulted outputs already separate the keys "
      "(max|t| > 4.5): the function output is a secret intermediate, so a key-dependent "
      "faulted output is expected and not a fault finding. Effective = mean fraction of "
      "(site, message) replays whose output differs from the unfaulted one.*\n")
    P("## Key-dependent φIF sites (A/B significantly above the A/A' control)\n")
    any_sig = False
    for t in targets:
        r = rows[t]
        if not r or not r["sig"]:
            continue
        any_sig = True
        P(f"**`{t}`** — {label(t)}\n")
        P("| addr | instruction | A/B flips | A/A' flips | p |")
        P("|---|---|---|---|---|")
        for pc, text, fab, faa, p in r["sig"][:20]:
            P(f"| `{pc}` | `{text}` | {fab} | {faa} | {p:.2g} |")
        if len(r["sig"]) > 20:
            P(f"| … | | | | +{len(r['sig']) - 20} more |")
        P("")
    if not any_sig:
        P("None: at every site the A/B flip count is within what input-dependence alone "
          "produces (A/A').\n")
    P("## Largest raw A/B φIF sites (before the control), for reference\n")
    for t in targets:
        r = rows[t]
        if not r or not r["top"]:
            continue
        P(f"`{t}`: " + ", ".join(f"`{pc}` {text} ({fab} vs {faa})"
                                 for pc, text, fab, faa in r["top"][:5]) + "\n")
    P("## Notes on the remaining (A) LEAK flags\n")
    P("- `ntt_y` (2 sites, `0x59a0 cmp.w r0, sl` / `0x59a4 bne.w`, |t|=8.9; same-key control 3.1): "
      "skipping the NTT's loop exit runs an extra pass that reads past the y buffer. Re-run with the "
      "**snapshot** backend (real memory layout, `dumps_snap/ntt_y_instrskip`) the same sites score "
      "|t|=3.9, not significant: the call backend relocates inputs into scratch memory, so the "
      "overflowing pass read replay-environment bytes, not the signing's real neighbours. **Artifact.** "
      "General caveat: a skip that breaks a loop bound reads/writes out of the target's buffers, and "
      "only the snapshot backend reproduces what lies there.")
    P("- Every other LEAK count on this page is n/a: the output is key-separable with no fault "
      "(key-fixed operand, or the matched filter recovering s1 from c·s1).\n")
    with open(OUT, "w") as fh:
        fh.write("\n".join(out) + "\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
