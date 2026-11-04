"""Per-function LEAK tallies from a funcskip dump tree, as reusable library code.

Reads a funcskip dump tree and returns plain dicts of the `per_coord` LEAK counts per
function -- the primitive the baseline-vs-hardened candidate comparison is built on.
Decoupled from any study/report.

Scope note: the old whole-output phi_IF counter that lived here (`_phi_counts`) was the
low-recall key-dependent-ineffective detector; it was removed with `sifa` when the
platform narrowed to instruction-skip scope.  The `ineffective` axis is now the
per-position phi_IF detector (`ucpqc.phi`), which runs live (K keygens) rather than from
a funcskip dump tree.  See `report/detector_inventory.md`.
"""
import os
import glob

from . import assess, dump as dumpmod

INSTRSKIP = "_instrskip"


def counts_for_dump(dump_dir, detector="per_coord"):
    """Per-function LEAK counts for ONE funcskip dump dir, or `None` if there is no
    dump there.  Returns a dict:

      scored     -- # skip sites that produced a metric (did not crash)
      leak       -- # LEAK sites (per_coord/TVLA at FDR<=0.01)
      maxt       -- max |t| over scored sites
      maxineff   -- max ineffective fraction over sites
      leak_sites -- [(addr, disasm, metric)] for the LEAK sites, by address
      has_golden -- whether a golden baseline was captured for both keys (reachability hint)
    """
    if not os.path.exists(os.path.join(dump_dir, "meta.json")):
        return None
    res = assess.assess_funcskip_from_dump(dump_dir, detector=detector)
    scored = [r for r in res.rows if r.metric is not None]
    leaks = [r for r in scored if r.status == "LEAK"]
    maxt = max((r.metric for r in scored), default=0.0)
    maxineff = max((r.ineffective for r in res.rows if r.ineffective is not None), default=0.0)
    _, caps, _sites = dumpmod.load_funcskip_dump(dump_dir)
    leak_sites = [(r.addr, r.label, r.metric) for r in sorted(leaks, key=lambda r: r.addr)]
    return dict(scored=len(scored), leak=len(leaks), maxt=maxt, maxineff=maxineff,
                leak_sites=leak_sites,
                has_golden=bool(caps.get("A")) and bool(caps.get("B")))


def _empty_row(reached=False):
    return dict(scored=0, leak=0, maxt=0.0, maxineff=0.0, leak_sites=[],
                has_golden=False, reached=reached)


def discover_functions(dump_base):
    """Function names that have a `<fn>_instrskip/` dump under `dump_base`, sorted."""
    pat = os.path.join(dump_base, "*" + INSTRSKIP)
    return sorted(os.path.basename(d)[:-len(INSTRSKIP)] for d in glob.glob(pat)
                  if os.path.isdir(d))


def candidate_counts(dump_base, functions=None, detector="per_coord", manifest=None):
    """Per-function LEAK counts over a dump base dir holding `<fn>_instrskip/` subdirs.

    Returns `{fn: {...counts..., reached: bool}}`.  `functions` optionally restricts/orders
    the set (otherwise every dump under `dump_base` is used).  `manifest` (a
    `captures/manifest.json` path) supplies authoritative reachability (`targets[fn].A == 0`
    => not reached); without it, a function counts as reached iff its dump captured a golden
    baseline for both keys.
    """
    import json
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
