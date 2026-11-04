#!/usr/bin/env python3
"""Arm A (SCOPE) of the "why does the LLVM tool find 93 and we find ~1" experiment.

The CSV `fault_report_dilithium.csv` (the Dilithium-LLVM reference study) gets 83/93 of its
detections from WHOLE-CALL skips, 53 of them skipping each callee of the top-level signing
function `signature_internal` -- including Keccak, memcpy, pack_sig, unpack_sk.  Our shipped
study swept *inside* individual functions (funcskip) and never skipped the signing body's
calls, and it ran on the m4f binary (which inlines many of those functions away).

This script closes that SCOPE gap on the same footing as the CSV:
  * target the in-repo CLEAN build (PQClean reference-C, nothing inlined) whose signing body
    calls exactly the CSV's callee set;
  * snapshot the signing body at entry and, for every `bl` to a callee, SKIP that whole call
    (persistent) and run entry->ret, comparing the RELEASED SIGNATURE to the golden run;
  * score phi_IF (key-dependent ineffectiveness == the CSV's `ineffective` oracle) with the
    same-key A/A' control: A vs B are two keys signing the SAME messages+RNG (only sk differs);
    A vs A' is key A on DISJOINT messages (input-dependence only).  A callee is key-dependent
    only where its A/B flip count significantly exceeds A/A' (one-sided Fisher, BH-FDR).

It deliberately scores only the phi_IF (ineffective) axis: a per_coord/TVLA "correction" leak
between two different keys on the *whole released signature* is confounded by baseline
separability (A and B produce different signatures with no fault), so it is not meaningful at
the released-signature level -- the correction axis belongs on a captured function output, which
the funcskip dumps already cover.  Here we mirror the CSV's dominant `ineffective` detections.

Usage:  scripts/llvm_gap_scope.py [--n 6] [--budget 40000000] [--nested] [--only SUBSTR]
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import numpy as np  # noqa: E402
from scipy.stats import fisher_exact  # noqa: E402

from ucpqc import Machine, Scheme, assess, detectors, profiles as pm  # noqa: E402
from ucpqc.profiles import signing_body, _scan_calls  # noqa: E402
from ucpqc.faults import FaultSpec, SKIP  # noqa: E402
from ucpqc.replay import Injector  # noqa: E402


def _phi_counts(caps, sites):
    """Whole-output phi_IF flip counter (self-contained; the engine's old
    candidates._phi_counts was retired with the whole-output detector).  Returns
    `(phi_sites, phi_flips, [(pc, text, flips)])`: a site flips on a message when the
    skip changed the released signature for one key but not the other."""
    gold = {k: [r.get("golden") for r in caps.get(k, [])] for k in "AB"}
    phi_sites = phi_flips = 0
    detail = []
    for sd in sites:
        effA = {r["idx"]: (r["out"] != gold["A"][r["idx"]]) for r in sd["A"]
                if r["idx"] < len(gold["A"]) and gold["A"][r["idx"]] is not None}
        effB = {r["idx"]: (r["out"] != gold["B"][r["idx"]]) for r in sd["B"]
                if r["idx"] < len(gold["B"]) and gold["B"][r["idx"]] is not None}
        flips = sum(1 for i in (set(effA) & set(effB)) if effA[i] != effB[i])
        phi_flips += flips
        if flips:
            phi_sites += 1
        detail.append((sd["pc"], sd.get("text", ""), flips))
    return phi_sites, phi_flips, detail

ELF = "firmware/ml-dsa-44_clean_test.elf"
SIG_BYTES = 2420            # ML-DSA-44 CRYPTO_BYTES
Q = 0.05
OUT = "report/llvm_gap_experiment.md"       # scope section is written by this script


def enumerate_sites(m, body, nested):
    """[(pc, callee_label)] for every bl in the signing body (and, if nested, one level
    into each internal callee, to reach e.g. the per-sampler Keccak calls the CSV lists
    under poly_uniform*)."""
    seen, sites = set(), []
    for pc, target, label in _scan_calls(m, body):
        if pc not in seen:
            seen.add(pc)
            sites.append((pc, label))
    if nested:
        for _pc, target, _label in _scan_calls(m, body):
            if target is None:
                continue
            fn = m.image.func_at(target)
            if fn is None or fn.addr != target:
                continue
            for pc, _t, label in _scan_calls(m, fn.name):
                if pc not in seen:
                    seen.add(pc)
                    sites.append((pc, f"{fn.name} > {label}"))
    return sites


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=6, help="messages per side")
    ap.add_argument("--budget", type=int, default=40_000_000, help="max instrs per replay")
    ap.add_argument("--nested", action="store_true", help="also skip calls one level into callees")
    ap.add_argument("--only", default=None, help="restrict to callees whose label contains this")
    a = ap.parse_args()
    n = a.n

    m = Machine.from_elf(ELF)
    sch = Scheme.bind(m)
    m.boot()
    prof = pm.profile_for(sch)
    sk = assess._make_keys(sch, assess.DEFAULT_KEYS, "independent", prof)
    prof.setup(m)
    m.stub_cycle_counter()
    stream = m.stub_randombytes(b"seed")
    clean = m.snapshot()
    msgs = assess.standard_messages(2 * n)
    sign_fn = sch.binding.symbols["signature"]
    entry = m.addr_of(sign_fn)
    body = signing_body(m, sign_fn)
    sites = enumerate_sites(m, body, a.nested)
    if a.only:
        sites = [(pc, lbl) for pc, lbl in sites if a.only in lbl]

    sides = {"A": [("A", i) for i in range(n)], "B": [("B", i) for i in range(n)],
             "C": [("A", n + i) for i in range(n)]}

    def capture_entry(key, j):
        m.restore(clean)
        stream.reset(f"nonce-{j}".encode())
        box = {}

        def on_entry(mm, addr, size):
            if "snap" not in box:
                box["snap"] = mm.snapshot()
                box["ret"] = mm.reg("lr") & ~1
                box["sig"] = mm.reg("r0")          # 1st arg = sig buffer
                mm.uc.emu_stop()
        h = m.hook_code(on_entry, begin=entry, end=entry, precise=False)
        try:
            sch.sign(msgs[j], sk[key], max_instructions=80_000_000)
        except Exception:
            pass
        finally:
            m.unhook(h)
        return box

    def run(box, pc=None):
        m.restore(box["snap"])
        inj = Injector(m, FaultSpec(kind=SKIP, pc=pc, hit=0)) if pc is not None else None
        try:
            m._emu_start(entry | 1, box["ret"], count=a.budget)
        except Exception:
            return None                            # crash/runaway == output changed (effective)
        finally:
            if inj:
                inj.detach()
        return bytes(m.uc.mem_read(box["sig"], SIG_BYTES))

    print(f"capturing golden runs: {n} msgs x 3 sides ...", file=sys.stderr)
    caps_box = {sd: [capture_entry(k, j) for k, j in items] for sd, items in sides.items()}
    golden = {sd: [run(b) for b in caps_box[sd]] for sd in sides}

    # Build the funcskip-dump-shaped structures for the local _phi_counts flip counter.
    caps = {"A": [{"golden": golden["A"][i]} for i in range(n)],
            "B": [{"golden": golden["B"][i]} for i in range(n)]}
    capsC = {"A": [{"golden": golden["A"][i]} for i in range(n)],
             "B": [{"golden": golden["C"][i]} for i in range(n)]}  # A/A' control: B-slot := A'

    rows_ab, rows_aa = [], []
    for si, (pc, lbl) in enumerate(sites):
        recsA = [{"idx": i, "out": run(caps_box["A"][i], pc)} for i in range(n)]
        recsB = [{"idx": i, "out": run(caps_box["B"][i], pc)} for i in range(n)]
        recsC = [{"idx": i, "out": run(caps_box["C"][i], pc)} for i in range(n)]
        rows_ab.append({"pc": f"{pc:#06x}", "text": lbl, "A": recsA, "B": recsB})
        rows_aa.append({"pc": f"{pc:#06x}", "text": lbl, "A": recsA, "B": recsC})
        print(f"  [{si+1}/{len(sites)}] {lbl}", file=sys.stderr)

    _, flips_ab, detail_ab = _phi_counts(caps, rows_ab)
    _, flips_aa, detail_aa = _phi_counts(capsC, rows_aa)
    fab = {d[0]: d[2] for d in detail_ab}        # pc-str -> A/B flips
    faa = {d[0]: d[2] for d in detail_aa}        # pc-str -> A/A' flips

    # per-site one-sided Fisher (A/B flips vs A/A' flips), BH-FDR
    pcs = [r["pc"] for r in rows_ab]
    pv = [fisher_exact([[fab.get(pc, 0), n - fab.get(pc, 0)],
                        [faa.get(pc, 0), n - faa.get(pc, 0)]], alternative="greater")[1]
          for pc in pcs]
    keep = detectors.bh_fdr(np.array(pv), Q) if pcs else []

    out = []
    P = out.append
    P("# Why our sweep finds ~nothing vs the LLVM tool: experiment\n")
    P(f"Target `{ELF}` (PQClean reference-C 'clean' build; nothing inlined). Fault model held "
      f"constant = whole-call **skip**, the primitive both tools share. n={n} messages/side.\n")
    P("## Arm A - SCOPE: skip each callee of the signing body (phi_IF / `ineffective`)\n")
    P(f"Signing body `{body}` has {len(sites)} `bl` sites"
      f"{' (incl. one level into callees)' if a.nested else ' (direct callees)'}. For each we "
      f"skip the whole call and compare the released {SIG_BYTES}-byte signature. phi_IF A/B = "
      f"messages where the skip changed the signature for one key but not the other; A/A' is the "
      f"same for key A on disjoint messages (input-only control). Key-dependent = A/B above A/A' "
      f"(one-sided Fisher, BH-FDR q={Q}).\n")
    P("| callee (bl) | A/B flips | A/A' flips | key-dep? |")
    P("|---|---|---|---|")
    ndet = 0
    for (pc, lbl), p, k in sorted(zip(sites, pv, keep), key=lambda z: -fab.get(f"{z[0][0]:#06x}", 0)):
        pcs_ = f"{pc:#06x}"
        kd = "**yes** (p=%.2g)" % p if k else "no"
        if k:
            ndet += 1
        P(f"| `{lbl}` | {fab.get(pcs_, 0)}/{n} | {faa.get(pcs_, 0)}/{n} | {kd} |")
    P(f"\n**{ndet}/{len(sites)} callees** are key-dependent-ineffective (A/B above the A/A' "
      f"control). Compare to the CSV's `loopOrFuncSkip ... fnSkip` detections on "
      f"`signature_internal`.\n")
    with open(OUT, "w") as fh:
        fh.write("\n".join(out) + "\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
