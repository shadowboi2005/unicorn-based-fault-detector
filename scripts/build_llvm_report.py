#!/usr/bin/env python3
"""Build report/llvm_vs_arm.md from the funcskip dumps under dumps/<fn>_instrskip/
and the LLVM-IR detection numbers transcribed from the Dilithium-LLVM summary image."""
import os, json, sys
import numpy as np
sys.path.insert(0, "/home/imnothackr/mnt/sidechannel/btp1/unicorn")
from ucpqc import assess, dump as dumpmod
from ucpqc.profiles import dilithium_targets as dt

# --- LLVM-IR results (detected/total), transcribed from the summary image -----------
LLVM = {  # function: (ineffective d, ineffective t, correction d, correction t)
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

def arm_row(fn):
    """ARM funcskip summary for one dumped function: (scored, #leak, max_t, max_ineff, sifa_z)."""
    d = f"dumps/{fn}_instrskip"
    if not os.path.exists(os.path.join(d, "meta.json")):
        return None
    res = assess.assess_funcskip_from_dump(d, detector="per_coord")
    scored = [r for r in res.rows if r.metric is not None]
    leaks = [r for r in scored if r.status == "LEAK"]
    maxt = max((r.metric for r in scored), default=0.0)
    ineffs = [r.ineffective for r in res.rows if r.ineffective is not None]
    maxineff = max(ineffs, default=0.0)
    # per-key ineffective (sifa): rate(faulted==golden) for A vs B over all site/items
    meta, caps, sites = dumpmod.load_funcskip_dump(d)
    gold = {k:[ (r.get("golden") if isinstance(r,dict) else None) for r in caps.get(k,[]) ] for k in "AB"}
    na={"A":0,"B":0}; sa={"A":0,"B":0}
    for sd in sites:
        for k in "AB":
            for rec in sd.get(k,[]):
                g = gold[k][rec["idx"]] if rec["idx"]<len(gold[k]) else None
                if g is not None:
                    na[k]+=1; sa[k]+= (rec["out"]==g)
    pa = sa["A"]/na["A"] if na["A"] else 0.0; pb = sa["B"]/na["B"] if na["B"] else 0.0
    pooled=(sa["A"]+sa["B"])/(na["A"]+na["B"]) if (na["A"]+na["B"]) else 0.0
    se=(pooled*(1-pooled)*(1/max(na["A"],1)+1/max(na["B"],1)))**0.5
    sifa_z = abs(pa-pb)/se if se>0 else 0.0
    return dict(scored=len(scored), leak=len(leaks), maxt=maxt, maxineff=maxineff,
                sifa_z=sifa_z, total=len(res.rows))

# --- assemble rows (study targets + N/A rows for keygen/thunk/signature) -------------
run = list(dt.TARGETS)
rows=[]
for fn in sorted(set(list(LLVM)+run)):
    status=None
    if fn in dt.KEYGEN_ONLY: status="keygen-only (not sign-reachable)"
    elif fn in dt.THUNK_REDIRECT: status=f"4B thunk -> {dt.THUNK_REDIRECT[fn]}"
    elif fn=="signature_internal": status="whole-sign (see sweep mode)"
    a = None if status else arm_row(fn)
    rows.append((fn, LLVM.get(fn), status, a))

def fmt_llvm(l): return f"{l[0]}/{l[1]}" if l else "-"
out=["# LLVM-IR -> ARM-binary fault-leakage translation (Dilithium / ML-DSA-44)","",
 "Comparison of the `Dilithium-LLVM` IR-level fault analysis (two tests: **ineffective** =",
 "SIFA-style no-op faults, **correction** = output-changing faults) against this platform's",
 "ARM-binary **funcskip** instruction-skip + detector repertoire (n=40/key, `per_coord`/TVLA",
 "for the leak/correction axis; `ineffective` = share of skip-replays byte-identical to the",
 "unfaulted output; `sifa z` = key-dependence of that ineffective rate). Fault models differ",
 "(IR bit/value faults vs whole-instruction skip), so this is a *translation* study.","",
 "| function | LLVM ineff | LLVM corr | ARM leak (LEAK/scored, max\\|t\\|) | ARM ineff (max frac, sifa z) | note |",
 "|---|---|---|---|---|---|"]
for fn,l,st,a in rows:
    if a is None:
        out.append(f"| `{fn}` | {fmt_llvm((l[0],l[1]) if l else None)} | {fmt_llvm((l[2],l[3]) if l else None)} | - | - | {st or 'no dump'} |")
    else:
        arm_leak=f"{a['leak']}/{a['scored']}, |t|={a['maxt']:.1f}"
        arm_ineff=f"{a['maxineff']:.2f}, z={a['sifa_z']:.1f}"
        out.append(f"| `{fn}` | {fmt_llvm((l[0],l[1]) if l else None)} | {fmt_llvm((l[2],l[3]) if l else None)} | {arm_leak} | {arm_ineff} | |")
print("\n".join(out))
