#!/usr/bin/env python3
"""Arm B (ORACLE) of the "why does the LLVM tool find 93 and we find ~1" experiment.

Our shipped phi_IF asks "do TWO RANDOM keys differ in fault effectiveness, over the WHOLE
output?".  The LLVM tool instead holds the public background fixed, SWEEPS THE SECRET, and
asks per OUTPUT POSITION "is there a secret s1 making the fault a no-op and a secret s2 making
it effective?" (detail strings: "s1=0 ineffective, s2=32864 effective; pair on each public
seed").  That is a controlled, isolated, worst-case search; ours is average-case.

This arm reproduces their oracle by SAMPLING instead of enumerating, with no key packer needed:
  * target a few callees of the signing body that the CSV flags;
  * SECRET arm -- K independent keys all signing the SAME message+RNG (public background fixed,
    only sk differs), skip the callee, and record per-signature-byte effectiveness
    (faulted != that key's own golden);
  * INPUT control -- ONE key signing K different messages (secret fixed, background varies);
  * a byte position is a phi_IF (ineffective) WITNESS if effectiveness is key-split there
    (some keys ineffective, some effective) significantly MORE under secret variation than
    under input variation (one-sided Fisher per position, BH-FDR).  This is the "exists s1
    ineffective, s2 effective" test, recovered by sampling.

The point: a site DARK under our shipped 2-key / whole-output phi_IF can light up under this
many-key / per-position oracle -- isolating the ORACLE half of the gap from the SCOPE half.
Each key's s1 (via the existing read-only unpack_s1) attributes a flagged position to a
coefficient, mirroring the CSV's "s1=.." witnesses.

Appends its section to report/llvm_gap_experiment.md (run AFTER scripts/llvm_gap_scope.py).

Usage:  scripts/llvm_gap_oracle.py [--k 32] [--budget 40000000] [--sites polyvecl_add,poly_challenge,polyveck_decompose]
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
from ucpqc.profiles.mldsa import unpack_s1  # noqa: E402
from ucpqc.faults import FaultSpec, SKIP  # noqa: E402
from ucpqc.replay import Injector  # noqa: E402

ELF = "firmware/ml-dsa-44_clean_test.elf"
SIG_BYTES = 2420
Q = 0.05
OUT = "report/llvm_gap_experiment.md"
DEFAULT_SITES = "polyvecl_add,poly_challenge,polyveck_decompose"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=32, help="keys (secret arm) / messages (input arm)")
    ap.add_argument("--budget", type=int, default=40_000_000)
    ap.add_argument("--sites", default=DEFAULT_SITES, help="comma-separated callee label substrings")
    a = ap.parse_args()
    K = a.k
    wanted = [s.strip() for s in a.sites.split(",") if s.strip()]

    m = Machine.from_elf(ELF)
    sch = Scheme.bind(m)
    m.boot()
    prof = pm.profile_for(sch)
    prof.setup(m)
    m.stub_cycle_counter()
    stream = m.stub_randombytes(b"seed")
    clean = m.snapshot()
    sign_fn = sch.binding.symbols["signature"]
    entry = m.addr_of(sign_fn)
    body = signing_body(m, sign_fn)

    # resolve the chosen callee labels to bl PCs (first occurrence of each)
    sites = []
    for pc, _t, label in _scan_calls(m, body):
        for w in wanted:
            if w in label and not any(w == s[2] for s in sites):
                sites.append((pc, label, w))
    print(f"targets: {[s[1] for s in sites]}", file=sys.stderr)

    # K independent keys (each its own keygen) + their s1 labels
    keys, s1s = [], []
    for i in range(K):
        _pk, sk = assess._keypair(sch, f"key-{i:03d}".encode())
        keys.append(sk)
        s1s.append(unpack_s1(sk))
    keyA = keys[0]

    def capture(sk, j):
        """Snapshot the signing body at entry for secret `sk` signing message j (RNG=nonce-j)."""
        m.restore(clean)
        stream.reset(f"nonce-{j}".encode())
        box = {}

        def on_entry(mm, addr, size):
            if "snap" not in box:
                box["snap"] = mm.snapshot()
                box["ret"] = mm.reg("lr") & ~1
                box["sig"] = mm.reg("r0")
                mm.uc.emu_stop()
        h = m.hook_code(on_entry, begin=entry, end=entry, precise=False)
        try:
            sch.sign(assess.standard_messages(j + 1)[j], sk, max_instructions=80_000_000)
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
            return None
        finally:
            if inj:
                inj.detach()
        return bytes(m.uc.mem_read(box["sig"], SIG_BYTES))

    # SECRET arm: K keys, SAME message (j=0, RNG nonce-0) -> only sk varies.
    print(f"secret arm: {K} keys, fixed message ...", file=sys.stderr)
    sec_boxes = [capture(keys[i], 0) for i in range(K)]
    sec_gold = [run(b) for b in sec_boxes]
    # INPUT control: key A, K messages -> only background varies.
    print(f"input arm: key A, {K} messages ...", file=sys.stderr)
    inp_boxes = [capture(keyA, j) for j in range(K)]
    inp_gold = [run(b) for b in inp_boxes]

    def eff_matrix(boxes, golds, pc):
        """K x SIG_BYTES bool: did skipping `pc` change byte p of this signing vs its golden."""
        M = np.zeros((len(boxes), SIG_BYTES), bool)
        for i, (box, g) in enumerate(zip(boxes, golds)):
            f = run(box, pc)
            if f is None or g is None:
                M[i, :] = True                 # crash/runaway == fully effective
            else:
                M[i, :] = np.frombuffer(f, np.uint8) != np.frombuffer(g, np.uint8)
        return M

    out = ["\n## Arm B - ORACLE: many-key, per-position phi_IF (the `ineffective` witness)\n",
           f"Our shipped phi_IF uses 2 random keys over the whole {SIG_BYTES}-byte signature. "
           f"Here, for each site, the SECRET arm holds the message+RNG fixed and varies the key "
           f"over K={K} independent keygens (only sk differs); the INPUT control holds the key "
           f"fixed and varies the message over K. A byte POSITION is a key-dependent-ineffective "
           f"witness if the skip is effective for some keys but not others there, significantly "
           f"more under secret variation than input variation (one-sided Fisher per position, "
           f"BH-FDR q={Q}). This samples the LLVM tool's 'exists s1 ineffective, s2 effective'.\n",
           "| callee (bl) | shipped 2-key whole-output phi_IF | many-key witness positions | "
           "example attribution |",
           "|---|---|---|---|"]

    for pc, label, short in sites:
        Msec = eff_matrix(sec_boxes, sec_gold, pc)
        Minp = eff_matrix(inp_boxes, inp_gold, pc)
        # shipped oracle proxy: 2 random keys (first two of the secret arm), whole-output flip?
        two = Msec[:2].any(1)                  # per-key: did the whole signature change?
        shipped = "flag" if (two[0] != two[1]) else "no flag"
        # per-position secret-split vs input-split
        sec_eff = Msec.sum(0)                  # per-position effective count across K keys
        inp_eff = Minp.sum(0)
        pos_witness, pv = [], []
        for p in range(SIG_BYTES):
            se, ie = int(sec_eff[p]), int(inp_eff[p])
            if 0 < se < K:                     # key-split at this position (the witness shape)
                pv.append(fisher_exact([[se, K - se], [ie, K - ie]], alternative="greater")[1])
                pos_witness.append(p)
        keep = detectors.bh_fdr(np.array(pv), Q) if pv else []
        flagged = [p for p, k in zip(pos_witness, keep) if k]
        # attribute the first flagged position to the most-separating s1 coefficient
        attr = "-"
        if flagged:
            p0 = flagged[0]
            eff = Msec[:, p0]                   # which keys were effective at p0
            s1flat = np.array([s.ravel() for s in s1s])     # K x (L*256)
            # coefficient whose value best separates effective vs ineffective keys
            diff = np.abs(s1flat[eff].mean(0) - s1flat[~eff].mean(0)) if eff.any() and (~eff).any() else None
            if diff is not None:
                c = int(np.argmax(diff))
                attr = (f"pos {p0}: s1[{c // 256},{c % 256}] "
                        f"mean {s1flat[~eff][:, c].mean():.1f} (ineff) vs "
                        f"{s1flat[eff][:, c].mean():.1f} (eff)")
        out.append(f"| `{label}` | {shipped} | **{len(flagged)}** / {len(pos_witness)} split | {attr} |")

    out.append(f"\nPositions flagged here are invisible to the shipped 2-key/whole-output phi_IF "
               f"but are exactly the LLVM tool's per-position `ineffective` witnesses. A nonzero "
               f"'many-key witness positions' with a 'no flag' shipped column is direct evidence "
               f"that the ORACLE (average-case 2-key vs worst-case per-position secret search), "
               f"not the fault model, is what hides these sites from us.\n")
    with open(OUT, "a") as fh:
        fh.write("\n".join(out) + "\n")
    print("appended Arm B to", OUT)


if __name__ == "__main__":
    main()
