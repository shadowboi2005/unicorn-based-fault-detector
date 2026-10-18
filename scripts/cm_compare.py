#!/usr/bin/env python3
"""Baseline-vs-hardened candidate comparison (analysis half).

Given TWO already-produced funcskip dump trees -- one per firmware build -- write:
  * a self-identifying per-build candidate report for each (via candidate_report.build), and
  * a diff report `cm_compare.md` inferring, per function and per detector, whether a
    countermeasure **closes**, **leaves**, or **newly introduces** fault candidates.

This does NOT run the emulator; scripts/cm_compare.sh runs the two sweeps first and then
calls this.  Matching is by **symbol name**, comparing **candidate counts** (not addresses),
so address shifts between the two different binaries do not matter; a function present in
only one build surfaces as introduced/removed.

Usage:
  cm_compare.py BASE_DUMP_BASE HARD_DUMP_BASE --base-elf E1 --hardened-elf E2
                [--scheme NAME] [--functions a,b,c]
                [--manifest-base M1] [--manifest-hardened M2] [--outdir report]
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ucpqc import candidates  # noqa: E402
import candidate_report  # noqa: E402


def _tag(elf):
    return os.path.splitext(os.path.basename(elf))[0]


def classify(b, h):
    """status for one function present in both builds, from the two count dicts."""
    dl = h["leak"] - b["leak"]
    dp = h["phi_sites"] - b["phi_sites"]
    if dl > 0 or dp > 0:
        return "introduces", dl, dp
    if dl < 0 or dp < 0:
        return "closes", dl, dp
    return "unchanged", dl, dp


def diff_markdown(scheme, base_elf, hard_elf, base, hard):
    out = []
    P = out.append
    P(f"# Candidate comparison -- `{scheme}`: baseline vs hardened\n")
    P(f"- **baseline:** `{base_elf}`")
    P(f"- **hardened:** `{hard_elf}`\n")
    P("Per function, per detector: does the hardened build **close**, **leave**, or **newly "
      "introduce** fault candidates? (A) = `per_coord`/TVLA leak sites; (B) = phi_IF "
      "key-dependent-ineffective sites. Matched by symbol; counts, not addresses -- so a "
      "renamed protected function shows as removed + introduced.\n")

    fns = sorted(set(base) | set(hard))
    tb_leak = sum(base.get(f, {}).get("leak", 0) for f in fns)
    th_leak = sum(hard.get(f, {}).get("leak", 0) for f in fns)
    tb_phi = sum(base.get(f, {}).get("phi_sites", 0) for f in fns)
    th_phi = sum(hard.get(f, {}).get("phi_sites", 0) for f in fns)
    P(f"**Totals:** (A) leak {tb_leak} -> {th_leak} ({th_leak - tb_leak:+d}); "
      f"(B) phi_IF {tb_phi} -> {th_phi} ({th_phi - tb_phi:+d}).\n")

    P("| function | (A) base->hard (Δ) | (B) base->hard (Δ) | status |")
    P("|---|---|---|---|")
    for fn in fns:
        b, h = base.get(fn), hard.get(fn)
        if b is None:
            P(f"| `{fn}` | — -> {h['leak']} | — -> {h['phi_sites']} ({h['phi_flips']}) | **introduced (new fn)** |")
        elif h is None:
            P(f"| `{fn}` | {b['leak']} -> — | {b['phi_sites']} ({b['phi_flips']}) -> — | removed (fn gone) |")
        else:
            st, dl, dp = classify(b, h)
            mark = {"introduces": "**introduces**", "closes": "closes", "unchanged": "unchanged"}[st]
            P(f"| `{fn}` | {b['leak']} -> {h['leak']} ({dl:+d}) | "
              f"{b['phi_sites']} -> {h['phi_sites']} ({dp:+d}) | {mark} |")
    P("")
    intro = [f for f in fns if f in base and f in hard and classify(base[f], hard[f])[0] == "introduces"]
    closed = [f for f in fns if f in base and f in hard and classify(base[f], hard[f])[0] == "closes"]
    if intro:
        P("> **Newly introduced candidates** in: " + ", ".join(f"`{f}`" for f in intro)
          + " -- a hardening change that *adds* fault surface; inspect these.\n")
    if closed:
        P("> **Closed** candidates in: " + ", ".join(f"`{f}`" for f in closed) + ".\n")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Baseline-vs-hardened candidate comparison.")
    ap.add_argument("base_dump_base")
    ap.add_argument("hardened_dump_base")
    ap.add_argument("--base-elf", required=True)
    ap.add_argument("--hardened-elf", required=True)
    ap.add_argument("--scheme", default=None)
    ap.add_argument("--functions", default=None, help="comma-separated subset (else union of dumps)")
    ap.add_argument("--manifest-base", default=None)
    ap.add_argument("--manifest-hardened", default=None)
    ap.add_argument("--base-tag", default=None, help="report filename tag (else ELF basename)")
    ap.add_argument("--hardened-tag", default=None)
    ap.add_argument("--detector", default="per_coord")
    ap.add_argument("--outdir", default="report")
    a = ap.parse_args()
    functions = a.functions.split(",") if a.functions else None

    base_md, base_counts = candidate_report.build(
        a.base_dump_base, scheme=a.scheme, elf=a.base_elf, functions=functions,
        manifest=a.manifest_base, detector=a.detector)
    hard_md, hard_counts = candidate_report.build(
        a.hardened_dump_base, scheme=a.scheme, elf=a.hardened_elf, functions=functions,
        manifest=a.manifest_hardened, detector=a.detector)
    scheme = a.scheme or candidate_report.first_meta(
        a.base_dump_base, list(base_counts)).get("scheme", "?")

    os.makedirs(a.outdir, exist_ok=True)
    p_base = os.path.join(a.outdir, f"candidates_{a.base_tag or _tag(a.base_elf)}.md")
    p_hard = os.path.join(a.outdir, f"candidates_{a.hardened_tag or _tag(a.hardened_elf)}.md")
    p_diff = os.path.join(a.outdir, "cm_compare.md")
    with open(p_base, "w") as fh:
        fh.write(base_md)
    with open(p_hard, "w") as fh:
        fh.write(hard_md)
    with open(p_diff, "w") as fh:
        fh.write(diff_markdown(scheme, a.base_elf, a.hardened_elf, base_counts, hard_counts))

    tb = sum(v["leak"] for v in base_counts.values()), sum(v["phi_sites"] for v in base_counts.values())
    th = sum(v["leak"] for v in hard_counts.values()), sum(v["phi_sites"] for v in hard_counts.values())
    print(f"wrote {p_base}\nwrote {p_hard}\nwrote {p_diff}")
    print(f"  baseline : (A) {tb[0]} leak, (B) {tb[1]} phi_IF")
    print(f"  hardened : (A) {th[0]} leak, (B) {th[1]} phi_IF")
    print(f"  Δ        : (A) {th[0]-tb[0]:+d} leak, (B) {th[1]-tb[1]:+d} phi_IF")


if __name__ == "__main__":
    main()
