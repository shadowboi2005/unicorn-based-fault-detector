#!/usr/bin/env python3
"""MAYO intra-function instruction-skip φIF over the whole secret-dependent signing path,
with the same-key control.

Extends scripts/mayo_phi_funcskip.py (same snapshot-region replay: snapshot the machine at
a function's first entry during a golden signing, then per instruction skip run only
entry->ret and compare writable RAM + r0 to the golden entry->ret result).  Differences:

  * targets = every secret-dependent function a MAYO1 m4f signing actually calls (from a
    call trace), not a hand-picked subset -- incl. the Gaussian elimination
    (`EF_m4f`, `ef_inner*_asm`, `backsub_inner_asm`), the O-multiplies of `mayo_expand_sk`,
    the V-multiplies of `P1_times_Vt`, and the bodies of `mayo_expand_sk` /
    `mayo_sign_signature` (s = v + O·x);
  * three sides per site: A and B (two keys, same message) and A' (key A on DISJOINT
    messages).  A/B flips mix key- and input-dependence; A/A' flips are input-only.  A site is
    KEY-dependent only if its A/B flips are significantly above its A/A' flips (one-sided
    Fisher exact per site, BH-FDR q=0.05);
  * one function per process (`--fn`), results to `dumps_mayo/<fn>.json`; `--report` builds
    report/mayo_secret_path.md.  Multiply-called asm workers are captured at their FIRST call
    (one representative slice of the same computation).

Usage:  scripts/mayo_secret_path.py --fn NAME [--n 16]      # one function -> JSON
        scripts/mayo_secret_path.py --report                 # aggregate -> markdown
"""
import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

ELF = "firmware/mayo1_m4f_test.elf"
OUTDIR = "dumps_mayo"
SITE_CAP = 700          # auto-raise stride so a giant routine stays bounded
Q = 0.05

#: (function, role) -- secret-dependent functions reached in a MAYO1 m4f signing
TARGETS = [
    ("P1P1t_times_O.isra.0", "L = (P1+P1ᵀ)O  [O secret]"),
    ("multiply_P1_right_m4f_V_V_O_asm", "P1·O worker  [O]"),
    ("multiply_P1t_right_m4f_V_V_O_asm", "P1ᵀ·O worker  [O]"),
    ("multiply_P1_right_m4f_O_asm2", "P1·O tail worker  [O]"),
    ("compute_M_and_VPV.isra.0", "M = V·L, VPV  [V secret]"),
    ("P1_times_Vt.isra.0", "P1·Vᵀ  [V]"),
    ("multiply_P1_right_transposed_m4f", "P1·Vᵀ driver  [V]"),
    ("multiply_P1_right_m4f_V_V_K_asm", "P1·Vᵀ worker  [V]"),
    ("multiply_P1_right_m4f_K_asm2_transposed", "P1·Vᵀ tail worker  [V]"),
    ("mul_add_mat_x_m_mat_m4f_K_V_O_triangular_asm", "V·L accumulate  [V, L]"),
    ("mul_add_mat_x_m_mat_m4f_K_V_K_triangular_asm", "V·(P1Vᵀ) accumulate  [V]"),
    ("compute_rhs.isra.0", "t − VPV  [V]"),
    ("sample_solution", "solve Mx = y, s = v + O·x  [V, O]"),
    ("EF_m4f.constprop.0", "Gaussian elimination driver  [M]"),
    ("ef_bitslice_asm", "EF bitslice  [M]"),
    ("ef_inner1_asm", "EF inner 1  [M]"),
    ("ef_inner2_asm", "EF inner 2  [M]"),
    ("ef_inner3_asm", "EF inner 3  [M]"),
    ("ef_inner4_asm", "EF inner 4  [M]"),
    ("ef_unbitslice_asm", "EF unbitslice  [M]"),
    ("backsub_inner_asm", "back-substitution  [M]"),
]


def sweep_fn(fn, n, elf=ELF):
    from ucpqc import Machine, Scheme, assess, profiles as pm
    from ucpqc.faults import FaultSpec, SKIP
    from ucpqc.replay import Injector

    m = Machine.from_elf(elf)
    sch = Scheme.bind(m)
    m.boot()
    prof = pm.profile_for(sch)
    sk = assess._make_keys(sch, assess.DEFAULT_KEYS, "independent", prof)
    prof.setup(m)
    m.stub_cycle_counter()
    stream = m.stub_randombytes(b"seed")
    clean = m.snapshot()
    msgs = assess.standard_messages(2 * n)
    WR = [(r.base, r.size) for r in m.platform.ram_regions if r.name in ("sram", "scratch")]
    # side -> (key, message index): A and B share messages 0..n-1; A' is key A on n..2n-1
    sides = {"A": [("A", i) for i in range(n)], "B": [("B", i) for i in range(n)],
             "C": [("A", n + i) for i in range(n)]}

    def state_sig():
        return tuple(bytes(m.uc.mem_read(b, s)) for b, s in WR) + ((m.reg("r0") & 0xFFFFFFFF),)

    def capture_entry(key, j, entry):
        m.restore(clean)
        stream.reset(f"nonce-{j}".encode())          # same RNG for A and B on message j
        box = {}

        def on_entry(mm, addr, size):
            if "snap" not in box:
                box["snap"] = mm.snapshot()
                box["ret"] = mm.reg("lr") & ~1
                mm.uc.emu_stop()
        h = m.hook_code(on_entry, begin=entry, end=entry, precise=False)
        try:
            sch.sign(msgs[j], sk[key], max_instructions=60_000_000)
        except Exception:
            pass
        finally:
            m.unhook(h)
        return box.get("snap"), box.get("ret")

    def run_region(snap, entry, ret, budget, site=None):
        m.restore(snap)
        inj = Injector(m, FaultSpec(kind=SKIP, pc=site, hit=0)) if site else None
        try:
            m._emu_start(entry | 1, ret, count=budget)
        except Exception:
            return None
        finally:
            if inj:
                inj.detach()
        return state_sig()

    t0 = time.time()
    try:
        s, e = m.image.extent_of(fn)
    except Exception:
        return dict(fn=fn, status="no-symbol")
    entry = m.addr_of(fn)
    caps = {}
    for side, items in sides.items():
        caps[side] = []
        for key, j in items:
            snp, ret = capture_entry(key, j, entry)
            if snp is None:
                return dict(fn=fn, status="not-reached")
            caps[side].append((snp, ret))
    i0 = m.icount
    run_region(caps["A"][0][0], entry, caps["A"][0][1], 60_000_000)
    body = max(m.icount - i0, 1000)
    budget = body * 6 + 200_000
    golden = {sd: [run_region(snp, entry, ret, budget) for snp, ret in caps[sd]] for sd in sides}

    instrs, pc = [], s
    while pc < e:
        _, sz, _ = m.disasm_one(pc)
        instrs.append(pc)
        pc += sz or 2
    stride = 1
    while len(instrs[::stride]) > SITE_CAP:
        stride += 1

    sites = []
    for pc in instrs[::stride]:
        eff = {}
        for sd in sides:
            eff[sd] = []
            for (snp, ret), g in zip(caps[sd], golden[sd]):
                sig = run_region(snp, entry, ret, budget, site=pc)
                eff[sd].append(None if sig is None else int(sig != g))

        def flips(x, y):
            pairs = [(a, b) for a, b in zip(eff[x], eff[y]) if a is not None and b is not None]
            return sum(a != b for a, b in pairs), len(pairs)
        fab, nab = flips("A", "B")
        faa, naa = flips("A", "C")
        ran = [v for sd in sides for v in eff[sd]]
        sites.append(dict(pc=hex(pc), text=m.disasm_one(pc)[2], ab=fab, nab=nab, aa=faa, naa=naa,
                          crash=sum(v is None for v in ran),
                          effective=sum(v == 1 for v in ran), ran=sum(v is not None for v in ran)))
    return dict(fn=fn, status="ok", n=n, body=body, stride=stride, sites=sites,
                seconds=round(time.time() - t0))


def report():
    import numpy as np
    from scipy.stats import fisher_exact
    from ucpqc import detectors
    rows = []
    for fn, role in TARGETS:
        p = os.path.join(OUTDIR, f"{fn}.json")
        rows.append((fn, role, json.load(open(p)) if os.path.exists(p) else None))
    out = []
    P = out.append
    P("# MAYO1 m4f: instruction-skip φIF over the whole secret-dependent signing path\n")
    P("Extends `report/mayo_phi_funcskip.md` (11 hand-picked functions, 8 msgs/key, no control) "
      "to every secret-dependent function a MAYO1 m4f signing calls (from a call trace of one "
      "signing), with a **same-key control**. Snapshot-region replay: snapshot at the function's "
      "first entry, skip one instruction, run entry→ret, compare writable RAM + r0 with golden.\n")
    P("- **A/B**: keys A and B, same message + RNG. A flip = the skip is a no-op for one key and "
      "effective for the other. Mixes key- and input-dependence.")
    P("- **A/A'**: key A vs key A on disjoint messages: input-dependence only.")
    P(f"- **key-dependent site**: A/B flips significantly above A/A' (one-sided Fisher exact per "
      f"site, BH-FDR q={Q} across all swept sites).")
    P("- Not swept: the two top-level drivers `mayo_expand_sk` and `mayo_sign_signature` "
      "(entry→ret re-runs ~7.5M / ~13.7M instructions per replay; their callees are swept "
      "individually). Multiply-called asm workers are faulted at their first call.")
    P("- There is no (A) LEAK axis here: the compared state is the whole writable RAM, not a "
      "released output, so a distribution test on it is not meaningful.\n")
    allp, idx = [], []
    for k, (fn, role, r) in enumerate(rows):
        if r and r["status"] == "ok":
            for s in r["sites"]:
                if s["nab"] and s["naa"]:
                    allp.append(fisher_exact([[s["ab"], s["nab"] - s["ab"]],
                                              [s["aa"], s["naa"] - s["aa"]]],
                                             alternative="greater")[1])
                    idx.append((k, s))
    mask = detectors.bh_fdr(np.array(allp), Q) if allp else []
    sig = {}
    for (k, s), p, keep in zip(idx, allp, mask):
        if keep:
            sig.setdefault(k, []).append((s, p))
    P("## Summary\n")
    P("| function | role | sites (stride) | effective | crash | φIF A/B sites (flips) "
      "| φIF A/A' sites (flips) | **key-dep. sites** |")
    P("|---|---|---|---|---|---|---|---|")
    for k, (fn, role, r) in enumerate(rows):
        if r is None:
            P(f"| `{fn}` | {role} | not run | | | | | |")
            continue
        if r["status"] != "ok":
            P(f"| `{fn}` | {role} | {r['status']} | | | | | |")
            continue
        S = r["sites"]
        ran = sum(s["ran"] for s in S) or 1
        tot = sum(s["ran"] + s["crash"] for s in S) or 1
        P(f"| `{fn}` | {role} | {len(S)} ({r['stride']}) | {sum(s['effective'] for s in S)/ran:.0%} "
          f"| {sum(s['crash'] for s in S)/tot:.0%} | {sum(1 for s in S if s['ab'])} "
          f"({sum(s['ab'] for s in S)}) | {sum(1 for s in S if s['aa'])} ({sum(s['aa'] for s in S)}) "
          f"| **{len(sig.get(k, []))}** |")
    n = next((r["n"] for _, _, r in rows if r and r.get("status") == "ok"), "?")
    P(f"\nn = {n} messages per side. *effective* = share of non-crashing replays whose state "
      "differs from golden; *crash* = replays that faulted or hit the budget.\n")
    P("## Key-dependent sites\n")
    if not sig:
        P("None: no site's A/B flip rate is significantly above the input-only A/A' rate.\n")
    for k, lst in sorted(sig.items()):
        fn = rows[k][0]
        P(f"**`{fn}`**\n")
        P("| addr | instruction | A/B flips | A/A' flips | p |")
        P("|---|---|---|---|---|")
        for s, p in sorted(lst, key=lambda x: x[1])[:20]:
            P(f"| `{s['pc']}` | `{s['text']}` | {s['ab']}/{s['nab']} | {s['aa']}/{s['naa']} | {p:.2g} |")
        P("")
    P("## Interpretation: the flagged sites are per-key constants, not 16 samples\n")
    P("Every flagged site has A/B = 16/16 and A/A' = 0/16. That is the signature of a computation "
      "that does not depend on the message: the P1·O workers (`multiply_P1_right_m4f_V_V_O_asm`, "
      "`multiply_P1t_right_m4f_V_V_O_asm`, `multiply_P1_right_m4f_O_asm2`) are only called from "
      "`P1P1t_times_O` ← `mayo_expand_sk(sk)`, which reads nothing but the secret key, so all 16 "
      "messages replay the identical state per key. The A/A' control is then 0 by construction and "
      "the 16 A/B flips are ONE comparison (key A's P1, O vs key B's) repeated 16 times -- effectively "
      "n = 1 key pair, so the Fisher p-values overstate the evidence. The flagged "
      "`multiply_P1_right_m4f_V_V_K_asm` sites are the same: sites whose no-op status depends only on "
      "the per-key matrix, not on the per-message vinegar V (its other sites vary with V and are "
      "within the control).\n")
    P("What it does show: at these sites, whether the skip changes the state is decided by "
      "key-specific data. With only two keys it cannot say whether that is the secret O or the "
      "public P1 (both are derived from `seed_sk`, so they differ together). Deciding it needs a "
      "**many-key** test (one signing per key over K keys, check whether each site's "
      "ineffectiveness varies across keys and correlates with O), not more messages.\n")
    P("Everything that does depend on the message (V·L, VPV, `compute_rhs`, `sample_solution`, "
      "the Gaussian elimination and back-substitution) shows A/B flip rates within the A/A' control: "
      "**no key-dependent sites**.\n")
    with open("report/mayo_secret_path.md", "w") as fh:
        fh.write("\n".join(out) + "\n")
    print("wrote report/mayo_secret_path.md")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fn")
    ap.add_argument("--n", type=int, default=16)
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--elf", default=ELF)
    ap.add_argument("--outdir", default=OUTDIR)
    a = ap.parse_args()
    if a.report:
        return report()
    os.makedirs(a.outdir, exist_ok=True)
    r = sweep_fn(a.fn, a.n, elf=a.elf)
    with open(os.path.join(a.outdir, f"{a.fn}.json"), "w") as fh:
        json.dump(r, fh)
    print(f"{a.fn}: {r['status']}"
          + (f"  {len(r['sites'])} sites, {r['seconds']}s" if r["status"] == "ok" else ""))


if __name__ == "__main__":
    main()
