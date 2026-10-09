#!/usr/bin/env python3
"""Build report/llvm_vs_arm.md from the funcskip dumps under dumps/<fn>_instrskip/ and
the LLVM-IR detection numbers transcribed from the Dilithium-LLVM summary image.

ARM axes: leak/correction-analog = `per_coord` (TVLA) LEAK at FDR<=0.01; φIF = the
LLVM *ineffective* fault, i.e. KEY-DEPENDENT ineffectiveness -- per skip site, with A
and B signing the same message + RNG (only sk differs), count sites where some message
has the skip be a no-op for one key but output-changing for the other.
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
    # phi_IF (key-DEPENDENT ineffective fault): per site, for each message index i (same public
    # p for A and B now that the RNG is shared), does skipping flip between ineffective for one
    # key and effective for the other?  A site is phi_IF if >=1 such flip.
    phi_sites = phi_flips = 0
    for sd in sites:
        effA = {rec["idx"]: (rec["out"] != gold["A"][rec["idx"]])
                for rec in sd.get("A", []) if rec["idx"] < len(gold["A"]) and gold["A"][rec["idx"]] is not None}
        effB = {rec["idx"]: (rec["out"] != gold["B"][rec["idx"]])
                for rec in sd.get("B", []) if rec["idx"] < len(gold["B"]) and gold["B"][rec["idx"]] is not None}
        flips = sum(1 for i in (set(effA) & set(effB)) if effA[i] != effB[i])
        phi_flips += flips
        if flips: phi_sites += 1
    leak_sites = [(r.addr, r.label, r.metric) for r in sorted(leaks, key=lambda r: r.addr)]
    return dict(scored=len(scored), leak=len(leaks), maxt=maxt, maxineff=maxineff,
                phi_sites=phi_sites, phi_flips=phi_flips, leak_sites=leak_sites)

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
ineff_arm_phi=sum(1 for fn,a in ineff_llvm if a["phi_sites"]>0)   # LLVM-ineffective fns with ARM phi_IF
reach_all=[(fn,a) for fn,l,n,a in rows if a is not None]          # every function with an ARM dump
phi_funcs=sum(1 for fn,a in reach_all if a["phi_sites"]>0)        # any key-dependent-ineffective site
phi_total=sum(a["phi_sites"] for fn,a in reach_all)
arm_leakers=sorted(fn for fn,l,a in reach if a["leak"]>0)
phi_fns=sorted(((fn,a["phi_sites"]) for fn,a in reach_all if a["phi_sites"]>0), key=lambda x:-x[1])

out=[]
P=out.append
P("# LLVM-IR → ARM-binary fault-leakage translation (Dilithium / ML-DSA-44)\n")
P("How many of the `Dilithium-LLVM` IR-level fault findings reproduce on the **ARM binary**")
P("via this platform's `funcskip` instruction-skip + detector repertoire.\n")
P("- **LLVM** has two IR-fault tests: *ineffective* (SIFA-style no-op faults) and *correction*")
P("  (output-changing faults). Numbers (detected/total) are transcribed from the project's summary image.")
P("- **ARM** (n=40/key): *leak* = `per_coord`/TVLA sites flagged LEAK at FDR≤0.01 (the correction")
P("  analog); *φIF* = number of skip sites that are **key-dependent ineffective** (defined below).")
P("- Fault models differ (IR bit/value faults vs whole-instruction skip), and funcskip captures")
P("  only functions **reached during signing**, so this is a *translation* study, not 1:1.\n")
P("The **ineffective test is φIF** -- a *key-dependent* ineffective fault: ∃ public `p`, ∃ secrets")
P("`s1,s2` where the same skip is ineffective for `s1` (Δ=0) but effective for `s2` (Δ≠0). On ARM")
P("we test it per skip site with A and B signing the **same message + RNG** (only `sk` differs):")
P("a site is **φIF** if, for some message, skipping is a no-op for one key but changes the output")
P("for the other. (`correction` stays the leak axis = `per_coord`/TVLA LEAK.)\n")
P("## Aggregate translation rate (reachable functions with an ARM dump)\n")
P(f"- **Correction → ARM leak:** {corr_arm}/{len(corr_llvm)} of LLVM-correction-flagged functions also leak on ARM "
  f"(the ARM leakers: {', '.join('`%s`'%x for x in arm_leakers) or 'none'}).")
P(f"- **Ineffective (φIF) → ARM φIF:** {ineff_arm_phi}/{len(ineff_llvm)} of LLVM-ineffective-flagged functions have a "
  f"**key-dependent ineffective** site on ARM.")
P(f"- Across all {len(reach_all)} reachable functions: **{phi_funcs}** have ≥1 φIF site "
  f"(**{phi_total}** key-dependent-ineffective sites in total)"
  + (": " + ", ".join(f"`{fn}`({n})" for fn,n in phi_fns) if phi_fns else "") + ".\n")
P("## Takeaways\n")
P("- Under whole-instruction skip, the ARM binary leaks the key (correction axis) at essentially **one** place -- the "
  "mask add `polyvecl_add` (`z = z + y`), the canonical Exploiting-Determinism fault -- while every other reachable "
  "function shows **0** leaking sites. LLVM's value-level correction faults translate **poorly** to instruction-skip "
  "key leakage (a skip is a coarser fault than an IR bit/value corruption).")
P(f"- **φIF (key-dependent ineffective, = SIFA-exploitable):** {phi_total} such sites across {phi_funcs} functions. "
  "These are the skip points where whether the fault is a no-op *depends on the secret key* -- the actual target of "
  "the LLVM ineffective test, now measured with A/B sharing the public input so the key is the only variable.")
P("- The m4f optimising compiler **inlines 8 of the reference functions out of the signing path** "
  "(`polyveck_add/sub/chknorm/make_hint`, the `c·s` `*_pointwise_poly_montgomery` multiplies, "
  "`polyvecl_invntt_tomont`/`pointwise_acc`), so the ARM fault surface is **smaller** than the IR the LLVM tool "
  "analysed -- compilation itself changes what can be faulted.\n")
P("## Where the key leaks (correction axis)\n")
_leakers = [(fn, a) for fn, l, note, a in rows if a is not None and a.get("leak_sites")]
if _leakers:
    for fn, a in _leakers:
        P(f"**`{fn}`** -- {a['leak']} LEAK site(s) (max\\|t\\|={a['maxt']:.1f}):\n")
        P("| addr | max\\|t\\| | instruction |")
        P("|---|---|---|")
        for addr, text, m in a["leak_sites"]:
            P(f"| `{addr:#06x}` | {m:.1f} | `{text}` |")
        P("")
    P("`polyvecl_add` is the response mask add `z = z + y` looped over the L=4 secret polynomials; "
      "skipping the output-pointer setup (`mov r7,r0`), the per-poly `bl poly_add`, or the loop control "
      "(`cmp`/`bne`) drops one or more adds, so the emitted `z` exposes the deterministic `c·s1` term -- "
      "the canonical *Exploiting Determinism* fault. The |t|≈16.9 here sits far above the ~3-4.5 no-leak "
      "floor seen at every other site.\n")
else:
    P("No ARM function showed a LEAK site at FDR≤0.01.\n")
P("## Per-function\n")
P("| function | LLVM ineff | LLVM corr | ARM leak (LEAK/scored, max\\|t\\|) | ARM φIF sites (flips) | note |")
P("|---|---|---|---|---|---|")
for fn,l,note,a in rows:
    li = fmt((l[0],l[1]) if l else None); lc = fmt((l[2],l[3]) if l else None)
    if a is None:
        P(f"| `{fn}` | {li} | {lc} | — | — | {note or 'no dump'} |")
    else:
        P(f"| `{fn}` | {li} | {lc} | {a['leak']}/{a['scored']}, |t|={a['maxt']:.1f} | {a['phi_sites']} ({a['phi_flips']}) | |")

# plots: per-instruction ARM TVLA maps (built by scripts/plot_regions.py), leaker first
PLOT_ORDER = ["polyvecl_add", "ntt", "invntt_tomont", "poly_uniform", "poly_decompose",
              "poly_make_hint", "poly_sub", "polyvec_matrix_pointwise_montgomery"]
_plots = [fn for fn in PLOT_ORDER if os.path.exists(f"examples/plots/{fn}_by_instr.png")]
if _plots:
    P("## Plots\n")
    P("Per-instruction ARM TVLA maps (max\\|Welch t\\|, A vs B) across each function body, annotated with the")
    P("function's LLVM-IR tainted-instruction count. **Red** = LEAK (FDR≤0.01), grey = no leak, light = skip-crash;")
    P("the dashed line is the |t|≈4.5 flag threshold. Paths are relative to this file (`report/`).\n")
    for fn in _plots:
        tag = " — the key leak (mask add `z=z+y`)" if fn == "polyvecl_add" else ""
        P(f"### `pqcrystals_dilithium_{fn}`{tag}\n")
        P(f"![{fn} per-instruction TVLA](../examples/plots/{fn}_by_instr.png)\n")

os.makedirs("report", exist_ok=True)
with open("report/llvm_vs_arm.md","w") as fh: fh.write("\n".join(out)+"\n")
print("wrote report/llvm_vs_arm.md")
print(f"correction->ARM leak: {corr_arm}/{len(corr_llvm)}   "
      f"ineffective(phi_IF)->ARM: {ineff_arm_phi}/{len(ineff_llvm)}   "
      f"({phi_total} phi_IF sites across {phi_funcs} fns)")
