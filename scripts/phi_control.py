"""Same-key control capture for the phi_IF (key-dependent-ineffective) test.

phi_IF compares keys A and B signing the SAME message: a site "flips" when the skip is a
no-op for one key and output-changing for the other.  But A and B also feed DIFFERENT
INPUTS to the faulted function (different c, y, w ...), so a flip conflates genuine
key-dependence with ordinary input-dependence.

This builds the null: a capture cache whose side "A" is key A on messages 0..n-1 (the
same signings as the main cache) and whose side "B" is key A AGAIN on messages n..2n-1.
Only the input changes between the two sides, so replaying it (`ucpqc funcskip
--captures <out>`) gives the flip count input-dependence alone produces.  A site is a
key-dependence candidate only where the A/B flips exceed this A/A' rate.

Usage:  python scripts/phi_control.py [--out captures_ctrl] [--n 40] [-j 0] TARGET ...
"""
import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ucpqc import assess, captures as capmod, profiles as profilemod  # noqa: E402
from ucpqc.machine import Machine  # noqa: E402
from ucpqc.platform import PLATFORMS  # noqa: E402
from ucpqc.replay import cap_to_dict  # noqa: E402
from ucpqc.scheme import Scheme  # noqa: E402

ELF = "firmware/ml-dsa-44_m4f_test.elf"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--elf", default=ELF)
    ap.add_argument("--out", default="captures_ctrl")
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("-j", "--jobs", type=int, default=0)
    a = ap.parse_args()

    m = Machine.from_elf(a.elf, platform=PLATFORMS["mps2-an386"])
    scheme = Scheme.bind(m)
    m.boot()
    allt = profilemod.profile_for(scheme).targets()
    items = tuple((t, allt[t]) for t in a.targets)
    args = (a.elf, "mps2-an386", assess.DEFAULT_KEYS, "independent", None)
    msgs = assess.standard_messages(2 * a.n)

    # side A: key A, messages 0..n-1 (identical to the main cache's A); side B: key A, n..2n-1
    jobs = [("A", i, i) for i in range(a.n)] + [("B", i, a.n + i) for i in range(a.n)]
    raw = {t: {"A": {}, "B": {}} for t in a.targets}
    with ThreadPoolExecutor(max_workers=a.jobs or os.cpu_count() or 1) as pool:
        futs = {pool.submit(capmod._capture_item, args, items, "A", j, msgs[j], assess.CAP):
                (side, i) for side, i, j in jobs}
        for f, (side, i) in futs.items():
            _, _, caps = f.result()
            for t, cap in caps.items():
                cap.key = side
                raw[t][side][i] = cap

    os.makedirs(a.out, exist_ok=True)
    manifest = {"scheme": scheme.name, "platform": "mps2-an386", "n": a.n,
                "key_mode": "same-key control (A vs A on disjoint messages)",
                "budget": assess.CAP, "targets": {}}
    for t in a.targets:
        d = {k: [cap_to_dict(raw[t][k][i]) for i in sorted(raw[t][k])] for k in ("A", "B")}
        with open(os.path.join(a.out, f"{t}.captures.json"), "w") as fh:
            json.dump(d, fh)
        manifest["targets"][t] = {"A": len(d["A"]), "B": len(d["B"])}
    with open(os.path.join(a.out, capmod.MANIFEST), "w") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"control captures -> {a.out}/  {manifest['targets']}")


if __name__ == "__main__":
    main()
