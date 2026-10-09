#!/usr/bin/env python3
"""Build report/llvm_vs_arm.md from the funcskip dumps under dumps/<fn>_instrskip/ and
the LLVM-IR detection numbers transcribed from the Dilithium-LLVM summary image.

ARM axes: leak/correction-analog = `per_coord` (TVLA) LEAK at FDR<=0.01; ineffective
axis = max over sites of the fraction of skip-replays byte-identical to the unfaulted
output; sifa z = key-dependence (2-proportion z) of that ineffective rate (A vs B).
"""
import os, json, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
from ucpqc import assess, dump as dumpmod
from ucpqc.profiles import dilithium_targets as dt

# LLVM-IR results (ineffective d/t, correction d/t), transcribed from the summary image
LLVM = {
 "invntt_tomont":(0,18,0,18), "ntt":(0,13,0,13), "poly_add":(1,4,1,4), "poly_caddq":(1,1,0,1),
 "poly_decompose":(0,1,1,1), "poly_invntt_tomont":(0,1,0,1), "poly_make_hint":(1,5,1,5),
 "poly_ntt":(1,1,0,1), "poly_pointwise_montgomery":(4,5,1,5), "poly_sub":(1,4,1,4),
 "poly_uniform":(2,3,0,3), "poly_uniform_eta":(1,2,1,2), "poly_uniform_gamma1":(2,2,2,2),
 "polyvec_matrix_pointwise_montgomery":(0,1,0,1), "polyveck_add":(0,1,0,1),
 "polyveck_caddq":(1,1,0,1), "polyveck_decompose":(1,1,1,1), "polyveck_invntt_tomont":(0,1,0,1),
 "polyveck_ntt":(0,1,0,1), "polyveck_pointwise_poly_montgomery":(1,1,0,1), "polyveck_reduce":(1,1,0,1),
 "polyveck_shiftl":(1,1,1,1), "polyveck_sub":(0,1,0,1), "polyveck_uniform_eta":(1,1,1,1),
 "polyvecl_add":(1,1,1,1), "polyvecl_invntt_tomont":(0,1,0,1), "polyvecl_ntt":(0,1,0,1),
 "polyvecl_pointwise_acc_montgomery":(1,3,0,3), "polyvecl_pointwise_poly_montgomery":(1,1,0,1),
 "polyvecl_uniform_eta":(1,1,1,1), "polyvecl_uniform_gamma1":(1,1,1,1),
 "signature_internal":(15,23,11,22),
}
INEFF_THRESH = 0.5   # a site counts as "ineffective-detected" if >=50% of its faults are no-ops

# functions whose symbol exists but that the m4f SIGNING path never calls (inlined, or
# only used in verify) -> read empirically from the capture manifest (A == 0)
NOT_REACHED = set()
_man = "captures/manifest.json"
if os.path.exists(_man):
    _m = json.load(open(_man))["targets"]
    NOT_REACHED = {t for t, v in _m.items() if v.get("A", 0) == 0}

def arm_row(fn):
    d = f"dumps/{fn}_instrskip"
    if not os.path.exists(os.path.join(d, "meta.json")):
        return None
    res = assess.assess_funcskip_from_dump(d, detector="per_coord")
    scored = [r for r in res.rows if r.metric is not None]
    leaks = [r for r in scored if r.status == "LEAK"]
    maxt = max((r.metric for r in scored), default=0.0)
    maxineff = max((r.ineffective for r in res.rows if r.ineffective is not None), default=0.0)
    meta, caps, sites = dumpmod.load_funcskip_dump(d)
    gold = {k:[(r.get("golden") if isinstance(r,dict) else None) for r in caps.get(k,[])] for k in "AB"}
    na={"A":0,"B":0}; sa={"A":0,"B":0}
    for sd in sites:
        for k in "AB":
            for rec in sd.get(k,[]):
                g = gold[k][rec["idx"]] if rec["idx"]<len(gold[k]) else None
                if g is not None:
                    na[k]+=1; sa[k]+= (rec["out"]==g)
    pa=sa["A"]/na["A"] if na["A"] else 0.0; pb=sa["B"]/na["B"] if na["B"] else 0.0
    pooled=(sa["A"]+sa["B"])/(na["A"]+na["B"]) if (na["A"]+na["B"]) else 0.0
    se=(pooled*(1-pooled)*(1/max(na["A"],1)+1/max(na["B"],1)))**0.5
    sifa_z=abs(pa-pb)/se if se>0 else 0.0
    return dict(scored=len(scored), leak=len(leaks), maxt=maxt, maxineff=maxineff, sifa_z=sifa_z)

def fmt(dt_): return f"{dt_[0]}/{dt_[1]}" if dt_ else "-"

rows=[]
for fn in sorted(set(list(LLVM)+list(dt.TARGETS))):
    note=None
    if fn in dt.KEYGEN_ONLY: note="keygen-only (not sign-reachable)"
    elif fn in NOT_REACHED: note="not called in m4f signing (inlined / verify-only)"
    elif fn in dt.THUNK_REDIRECT: note=f"4B thunk -> `{dt.THUNK_REDIRECT[fn]}`"
    elif fn=="signature_internal": note="whole-sign top level (see `sweep` mode)"
    a = None if note else arm_row(fn)
    rows.append((fn, LLVM.get(fn), note, a))

# aggregate translation rates over REACHABLE functions with a dump
reach=[(fn,l,a) for fn,l,n,a in rows if a is not None and l is not None]
corr_llvm=[(fn,a) for fn,l,a in reach if l[2]>0]
ineff_llvm=[(fn,a) for fn,l,a in reach if l[0]>0]
corr_arm=sum(1 for fn,a in corr_llvm if a["leak"]>0)
ineff_arm=sum(1 for fn,a in ineff_llvm if a["maxineff"]>=INEFF_THRESH)
sifa_sig=sum(1 for fn,l,a in reach if a["sifa_z"]>3)        # key-DEPENDENT ineffectiveness
arm_leakers=sorted(fn for fn,l,a in reach if a["leak"]>0)

out=[]
P=out.append
P("# LLVM-IR → ARM-binary fault-leakage translation (Dilithium / ML-DSA-44)\n")
P("How many of the `Dilithium-LLVM` IR-level fault findings reproduce on the **ARM binary**")
P("via this platform's `funcskip` instruction-skip + detector repertoire.\n")
P("- **LLVM** has two IR-fault tests: *ineffective* (SIFA-style no-op faults) and *correction*")
P("  (output-changing faults). Numbers (detected/total) are transcribed from the project's summary image.")
P("- **ARM** (n=40/key): *leak* = `per_coord`/TVLA sites flagged LEAK at FDR≤0.01 (the correction")
P("  analog); *ineffective* = max over sites of the share of skip-replays byte-identical to the")
P(f"  unfaulted output; *sifa z* = key-dependence of that rate. A function counts as ARM-ineffective-")
P(f"  detected when that max fraction ≥ {INEFF_THRESH}.")
P("- Fault models differ (IR bit/value faults vs whole-instruction skip), and funcskip captures")
P("  only functions **reached during signing**, so this is a *translation* study, not 1:1.\n")
P("## Aggregate translation rate (reachable functions with an ARM dump)\n")
P(f"- **Correction → ARM leak:** {corr_arm}/{len(corr_llvm)} of LLVM-correction-flagged functions also leak on ARM "
  f"(the ARM leakers: {', '.join('`%s`'%x for x in arm_leakers) or 'none'}).")
P(f"- **Ineffective faults present:** {ineff_arm}/{len(ineff_llvm)} of LLVM-ineffective-flagged functions have an ARM skip site that is a no-op ≥{INEFF_THRESH} of the time.")
P(f"- **SIFA (key-DEPENDENT ineffectiveness):** {sifa_sig}/{len(reach)} functions show a significant `sifa z` (>3) -- i.e. the ineffective *rate itself* differs by key.\n")
P("## Takeaways\n")
P("- Under whole-instruction skip, the ARM binary leaks the key at essentially **one** place -- the mask add "
  "`polyvecl_add` (`z = z + y`), matching the canonical Exploiting-Determinism fault -- while every other reachable "
  "function shows **0** leaking sites. LLVM's value-level *correction* faults therefore translate **poorly** to "
  "instruction-skip key leakage: a whole-instruction skip is a much coarser fault than an IR bit/value corruption.")
P("- *Ineffective* (no-op) faults are **common** on the skip surface (most functions have a site where skipping is a "
  "no-op), but the **SIFA signal -- key-dependent ineffectiveness -- is absent** (`sifa z ≈ 0` everywhere): the no-op "
  "rate is the same for both keys. This matches our earlier conclusion that SIFA needs a **data** fault, not a skip.")
P("- The m4f optimising compiler **inlines 8 of the reference functions out of the signing path** "
  "(`polyveck_add/sub/chknorm/make_hint`, the `c·s` `*_pointwise_poly_montgomery` multiplies, "
  "`polyvecl_invntt_tomont`/`pointwise_acc`), so the ARM fault surface is **smaller** than the IR the LLVM tool "
  "analysed -- compilation itself changes what can be faulted.\n")
P("## Per-function\n")
P("| function | LLVM ineff | LLVM corr | ARM leak (LEAK/scored, max\\|t\\|) | ARM ineff (max frac, sifa z) | note |")
P("|---|---|---|---|---|---|")
for fn,l,note,a in rows:
    li = fmt((l[0],l[1]) if l else None); lc = fmt((l[2],l[3]) if l else None)
    if a is None:
        P(f"| `{fn}` | {li} | {lc} | — | — | {note or 'no dump'} |")
    else:
        P(f"| `{fn}` | {li} | {lc} | {a['leak']}/{a['scored']}, |t|={a['maxt']:.1f} | {a['maxineff']:.2f}, z={a['sifa_z']:.1f} | |")

os.makedirs("report", exist_ok=True)
with open("report/llvm_vs_arm.md","w") as fh: fh.write("\n".join(out)+"\n")
print("wrote report/llvm_vs_arm.md")
print(f"correction->ARM leak: {corr_arm}/{len(corr_llvm)}   ineffective->ARM ineff: {ineff_arm}/{len(ineff_llvm)}")
