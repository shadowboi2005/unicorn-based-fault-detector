#!/usr/bin/env python3
"""Generic per-build fault-candidate report for ucpqc.

Reads ONE build's funcskip dump tree and writes a self-identifying Markdown report of the
fault *candidates* per function, for BOTH detectors:
  (A) correction/leak -- `per_coord`/TVLA LEAK sites (output distribution differs by key)
  (B) phi_IF          -- key-dependent ineffective sites (a skip is a no-op for one key but
                         output-changing for the other), with per-site `flips`

Nothing here is specific to Dilithium/MAYO or to any study -- it works for any scheme whose
funcskip dumps are on disk.  Two such reports (baseline ELF vs hardened ELF) can be read
side by side, which is the countermeasure use case (see scripts/cm_compare.py/.sh).

Usage:
  candidate_report.py --dump-base DIR [--manifest captures/manifest.json]
                      [--scheme NAME] [--elf PATH] [--functions a,b,c]
                      [--detector per_coord] [--top 20] [-o OUT.md]
"""
import argparse
import os
import sys
import json
import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from ucpqc import candidates  # noqa: E402


def first_meta(dump_base, functions):
    """meta.json of the first function that has a dump (for scheme / n), else {}."""
    for fn in functions:
        mp = os.path.join(dump_base, fn + candidates.INSTRSKIP, "meta.json")
        if os.path.exists(mp):
            return json.load(open(mp))
    return {}


def build(dump_base, scheme=None, elf=None, functions=None, manifest=None,
          detector="per_coord", top=20):
    """Return `(markdown, counts)` for one build's dump tree."""
    counts = candidates.candidate_counts(dump_base, functions=functions,
                                         detector=detector, manifest=manifest)
    meta = first_meta(dump_base, list(counts))
    n = meta.get("n", "?")
    scheme = scheme or meta.get("scheme", "?")
    today = datetime.date.today().isoformat()

    out = []
    P = out.append
    P(f"# Fault-candidate report -- `{scheme}`\n")
    P(f"- **scheme:** `{scheme}`")
    if elf:
        P(f"- **firmware ELF:** `{elf}`")
    P(f"- **dump base:** `{dump_base}`")
    P(f"- **n:** {n} signings/key   **detector:** `{detector}`   **generated:** {today}\n")
    P("Two DISTINCT candidate detectors (do not conflate):")
    P("- **(A) correction/leak** -- `per_coord`/TVLA LEAK at FDR<=0.01 (output distribution differs by key).")
    P("- **(B) phi_IF** -- key-dependent ineffective: a skip is a no-op for one key but output-changing for the other.\n")

    tot_leak = sum(v["leak"] for v in counts.values())
    tot_phi = sum(v["phi_sites"] for v in counts.values())
    leak_fns = sorted(fn for fn, v in counts.items() if v["leak"] > 0)
    phi_fns = sorted(((fn, v["phi_sites"]) for fn, v in counts.items() if v["phi_sites"] > 0),
                     key=lambda x: -x[1])
    P(f"**Totals:** (A) **{tot_leak}** LEAK site(s) across {len(leak_fns)} function(s)"
      + (" (" + ", ".join(f"`{fn}`" for fn in leak_fns) + ")" if leak_fns else "")
      + f"; (B) **{tot_phi}** phi_IF site(s) across {len(phi_fns)} function(s)"
      + (": " + ", ".join(f"`{fn}`({k})" for fn, k in phi_fns) if phi_fns else "") + ".\n")

    P("## Per-function candidate counts\n")
    P("| function | reached | (A) leak (LEAK/scored, max\\|t\\|) | (B) phi_IF sites (flips) |")
    P("|---|---|---|---|")
    for fn in sorted(counts):
        v = counts[fn]
        if not v["reached"] and v["scored"] == 0:
            P(f"| `{fn}` | no | — | — |")
        else:
            P(f"| `{fn}` | {'yes' if v['reached'] else 'no'} | "
              f"{v['leak']}/{v['scored']}, \\|t\\|={v['maxt']:.1f} | {v['phi_sites']} ({v['phi_flips']}) |")
    P("")

    P("## (A) Distribution-difference (leak) sites\n")
    leakers = [(fn, counts[fn]) for fn in sorted(counts) if counts[fn]["leak_sites"]]
    if leakers:
        for fn, v in leakers:
            P(f"**`{fn}`** -- {v['leak']} LEAK site(s) (max\\|t\\|={v['maxt']:.1f}):\n")
            P("| addr | max\\|t\\| | instruction |")
            P("|---|---|---|")
            for addr, text, m in v["leak_sites"]:
                P(f"| `{addr:#06x}` | {m:.1f} | `{text}` |")
            P("")
    else:
        P("None at FDR<=0.01.\n")

    P("## (B) Key-dependent ineffective (phi_IF) sites\n")
    phis = [(fn, counts[fn]) for fn in sorted(counts, key=lambda f: -counts[f]["phi_sites"])
            if counts[fn]["phi_detail"]]
    if phis:
        for fn, v in phis:
            d = v["phi_detail"]
            P(f"**`{fn}`** -- {v['phi_sites']} phi_IF site(s), {v['phi_flips']} flips"
              + (f" (top {top} by flips)" if len(d) > top else "") + ":\n")
            P("| addr | flips | instruction |")
            P("|---|---|---|")
            for pc, text, flips in d[:top]:
                P(f"| `{pc}` | {flips} | `{text}` |")
            if len(d) > top:
                P(f"| ... | | +{len(d) - top} more |")
            P("")
    else:
        P("None.\n")

    return "\n".join(out) + "\n", counts


def main():
    ap = argparse.ArgumentParser(description="Generic per-build fault-candidate report.")
    ap.add_argument("--dump-base", required=True, help="dir holding <fn>_instrskip/ dumps")
    ap.add_argument("--manifest", default=None, help="captures/manifest.json for reachability")
    ap.add_argument("--scheme", default=None, help="scheme label (else inferred from a dump)")
    ap.add_argument("--elf", default=None, help="firmware ELF path, for the report header")
    ap.add_argument("--functions", default=None, help="comma-separated subset (else all dumps)")
    ap.add_argument("--detector", default="per_coord")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("-o", "--out", default=None, help="output .md (else stdout)")
    a = ap.parse_args()
    functions = a.functions.split(",") if a.functions else None
    md, counts = build(a.dump_base, scheme=a.scheme, elf=a.elf, functions=functions,
                       manifest=a.manifest, detector=a.detector, top=a.top)
    if a.out:
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        with open(a.out, "w") as fh:
            fh.write(md)
        print(f"wrote {a.out}  ((A) {sum(v['leak'] for v in counts.values())} leak, "
              f"(B) {sum(v['phi_sites'] for v in counts.values())} phi_IF)")
    else:
        sys.stdout.write(md)


if __name__ == "__main__":
    main()
