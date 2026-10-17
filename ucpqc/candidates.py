"""Candidate-count primitive -- per-function tallies of the two fault-candidate detectors
from a funcskip dump tree, as reusable library code.

This is the framework primitive the baseline-vs-hardened candidate comparison is built on.
It is deliberately decoupled from any study/report: it reads only a dump tree and returns
plain dicts.  (The LLVM/MAYO study scripts carry their own inline copies of the phi_IF
flip logic; they MAY later delegate here to remove that duplication.)

Two DISTINCT detectors (do not conflate):
  (A) correction / leak -- `per_coord`/TVLA: the faulted OUTPUT distribution differs by key
      (LEAK at FDR<=0.01).  Counted via :func:`assess.assess_funcskip_from_dump`.
  (B) phi_IF -- key-dependent ineffective: with keys A and B signing the SAME message + RNG
      (only `sk` differs), a site is phi_IF if, for some message, skipping that one
      instruction is a no-op for one key but output-changing for the other.  "flips" = how
      many messages show that key-split.  A site is phi_IF iff flips >= 1.
"""
import os
import glob
import json

from . import assess, dump as dumpmod

INSTRSKIP = "_instrskip"


def _phi_counts(caps, sites):
    """`(phi_sites, phi_flips, phi_detail)` from a funcskip dump's `caps` (per-key golden
    baselines) and per-site faulted records.  `phi_detail` = `[(pc, disasm, flips)]` sorted
    most-key-dependent first.  This is the phi_IF flip-counter as a library function."""
    gold = {k: [(r.get("golden") if isinstance(r, dict) else None) for r in caps.get(k, [])]
            for k in "AB"}
    phi_sites = phi_flips = 0
    phi_detail = []
    for sd in sites:
        effA = {rec["idx"]: (rec["out"] != gold["A"][rec["idx"]])
                for rec in sd.get("A", [])
                if rec["idx"] < len(gold["A"]) and gold["A"][rec["idx"]] is not None}
        effB = {rec["idx"]: (rec["out"] != gold["B"][rec["idx"]])
                for rec in sd.get("B", [])
                if rec["idx"] < len(gold["B"]) and gold["B"][rec["idx"]] is not None}
        flips = sum(1 for i in (set(effA) & set(effB)) if effA[i] != effB[i])
        phi_flips += flips
        if flips:
            phi_sites += 1
            phi_detail.append((sd["pc"], sd.get("text", ""), flips))
    phi_detail.sort(key=lambda t: -t[2])
    return phi_sites, phi_flips, phi_detail


def counts_for_dump(dump_dir, detector="per_coord"):
    """Per-function candidate counts for ONE funcskip dump dir, or `None` if there is no
    dump there.  Returns a dict with both detector axes:

      scored     -- # skip sites that produced a metric (did not crash)
      leak       -- # (A) LEAK sites (per_coord/TVLA at FDR<=0.01)
      maxt       -- max |t| over scored sites
      maxineff   -- max ineffective fraction over sites
      phi_sites  -- # (B) key-dependent-ineffective sites
      phi_flips  -- total phi_IF flips across sites
      leak_sites -- [(addr, disasm, metric)] for the LEAK sites, by address
      phi_detail -- [(pc, disasm, flips)] for the phi_IF sites, most key-dependent first
      has_golden -- whether a golden baseline was captured for both keys (reachability hint)
    """
    if not os.path.exists(os.path.join(dump_dir, "meta.json")):
        return None
    res = assess.assess_funcskip_from_dump(dump_dir, detector=detector)
    scored = [r for r in res.rows if r.metric is not None]
    leaks = [r for r in scored if r.status == "LEAK"]
    maxt = max((r.metric for r in scored), default=0.0)
    maxineff = max((r.ineffective for r in res.rows if r.ineffective is not None), default=0.0)
    _, caps, sites = dumpmod.load_funcskip_dump(dump_dir)
    phi_sites, phi_flips, phi_detail = _phi_counts(caps, sites)
    leak_sites = [(r.addr, r.label, r.metric) for r in sorted(leaks, key=lambda r: r.addr)]
    return dict(scored=len(scored), leak=len(leaks), maxt=maxt, maxineff=maxineff,
                phi_sites=phi_sites, phi_flips=phi_flips,
                leak_sites=leak_sites, phi_detail=phi_detail,
                has_golden=bool(caps.get("A")) and bool(caps.get("B")))


def _empty_row(reached=False):
    return dict(scored=0, leak=0, maxt=0.0, maxineff=0.0, phi_sites=0, phi_flips=0,
                leak_sites=[], phi_detail=[], has_golden=False, reached=reached)


def discover_functions(dump_base):
    """Function names that have a `<fn>_instrskip/` dump under `dump_base`, sorted."""
    pat = os.path.join(dump_base, "*" + INSTRSKIP)
    return sorted(os.path.basename(d)[:-len(INSTRSKIP)] for d in glob.glob(pat)
                  if os.path.isdir(d))


def candidate_counts(dump_base, functions=None, detector="per_coord", manifest=None):
    """Per-function candidate counts over a dump base dir holding `<fn>_instrskip/` subdirs.

    Returns `{fn: {...counts..., reached: bool}}`.  `functions` optionally restricts/orders
    the set (otherwise every dump under `dump_base` is used).  `manifest` (a
    `captures/manifest.json` path) supplies authoritative reachability (`targets[fn].A == 0`
    => not reached); without it, a function counts as reached iff its dump captured a golden
    baseline for both keys.
    """
    reached_map = None
    if manifest and os.path.exists(manifest):
        tgts = json.load(open(manifest)).get("targets", {})
        reached_map = {t: (v.get("A", 0) > 0) for t, v in tgts.items()}
    if functions is None:
        functions = discover_functions(dump_base)
    out = {}
    for fn in functions:
        c = counts_for_dump(os.path.join(dump_base, fn + INSTRSKIP), detector=detector)
        if c is None:
            out[fn] = _empty_row(reached=(reached_map.get(fn, False) if reached_map else False))
            continue
        c["reached"] = reached_map.get(fn, c["has_golden"]) if reached_map is not None else c["has_golden"]
        out[fn] = c
    return out
