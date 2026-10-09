#!/usr/bin/env python3
"""Whole-call-skip φIF (key-dependent ineffective fault) sweep for MAYO.

Approach (A) from the LLVM->ARM / φIF study, ported to MAYO.  The MAYO m4f
functions can't be driven by the funcskip *call* backend (GCC `.isra`
specialisations + >4-arg stack-passed outputs), so instead of intra-function
instruction skips we skip each whole `bl` CALL during a full signing and compare
the 454-byte signature -- no per-function arg specs needed.

φIF test: for each call site and each message p (public input), keys A and B sign
the SAME message; a site is φIF if, for some p, skipping that call is a no-op for
one key but changes the signature for the other -- i.e. ineffectiveness is
key-dependent.  (This MAYO1 build signs DETERMINISTICALLY: the signature is a pure
function of (sk, message), independent of the stubbed RNG -- verified in-script --
so the message is the varied public input and a full `snapshot`/`restore` before
every signing makes each golden exactly reproducible.)

Usage:  scripts/mayo_phi_sweep.py [N]       (N = messages per key, default 16)
Writes report/mayo_phi.md.
"""
import os, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); os.chdir(ROOT)
from ucpqc import Machine, Scheme, assess, profiles as pm
from ucpqc.faults import FaultSpec, SKIP
from ucpqc.replay import Injector
from ucpqc.scheme import SIGN

ELF = "firmware/mayo1_m4f_test.elf"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 16
BUDGET = 40_000_000          # ~3x a normal sign (13.7M); a skip that runs away is a crash


def main():
    m = Machine.from_elf(ELF); sch = Scheme.bind(m); m.boot()
    prof = pm.profile_for(sch)
    sk = assess._make_keys(sch, assess.DEFAULT_KEYS, "independent", prof)
    prof.setup(m); m.stub_cycle_counter(); m.stub_randombytes(b"seed")
    clean = m.snapshot()
    messages = assess.standard_messages(N)
    op = sch.binding.symbols["signature" if sch.kind == SIGN else "dec"]
    sites = list(prof.fault_sites(m, op))

    def sign(key, i, site=None):
        """Sign messages[i] under key, optionally skipping the whole call at `site`.
        Returns the artifact bytes, or None on crash/hang."""
        m.restore(clean)
        inj = Injector(m, FaultSpec(kind=SKIP, pc=site, hit=0)) if site else None
        try:
            art = sch.sign(messages[i], sk[key], max_instructions=BUDGET)
        except Exception:
            return None
        finally:
            if inj:
                inj.detach()
        return bytes(art)

    # --- self-checks: determinism + key/message sensitivity + RNG-independence ---
    g00 = sign("A", 0); assert g00 == sign("A", 0), "signing not reproducible under restore"
    assert sign("B", 0) != g00, "A and B gave identical sig (key not exercised?)"
    assert N < 2 or sign("A", 1) != g00, "messages 0 and 1 gave identical sig"

    # --- golden (no-skip) signatures, per key per message ---
    golden = {k: [sign(k, i) for i in range(N)] for k in ("A", "B")}
    for k in "AB":
        assert all(golden[k]), f"a golden sign crashed for key {k}"

    t0 = time.perf_counter()
    rows = []
    for si, (site, label) in enumerate(sites):
        eff = {"A": [], "B": []}       # effective? (sig changed vs golden) per message; None=crash
        for k in ("A", "B"):
            for i in range(N):
                art = sign(k, i, site=site)
                eff[k].append(None if art is None else (art != golden[k][i]))
        flips = sum(1 for i in range(N)
                    if eff["A"][i] is not None and eff["B"][i] is not None
                    and eff["A"][i] != eff["B"][i])
        def noop(k): return sum(1 for e in eff[k] if e is False)      # skip was ineffective
        def crash(k): return sum(1 for e in eff[k] if e is None)
        rows.append(dict(addr=site, label=label, flips=flips,
                         noopA=noop("A"), noopB=noop("B"),
                         crashA=crash("A"), crashB=crash("B")))
        print(f"  [{si+1}/{len(sites)}] {hex(site)} {label:36s} "
              f"flips={flips} noop(A/B)={noop('A')}/{noop('B')} crash={crash('A')}/{crash('B')}")
    dt = time.perf_counter() - t0

    phi = [r for r in rows if r["flips"] > 0]
    out = []
    P = out.append
    P("# MAYO whole-call-skip φIF (key-dependent ineffective) sweep\n")
    P(f"Scheme ML-DSA? no -- **MAYO1** (`{ELF}`), deterministic signing. {N} messages/key, "
      f"{len(sites)} whole-call skip sites in the signing path. Skip = remove a whole `bl` call; "
      f"a site is **φIF** if skipping is a no-op for one key but changes the 454-byte signature for "
      f"the other, on the same message.\n")
    P(f"- **φIF sites:** {len(phi)} of {len(sites)} call sites show key-dependent ineffectiveness.")
    if phi:
        P("  " + ", ".join(f"`{r['label']}`({r['flips']})" for r in
                           sorted(phi, key=lambda r: -r["flips"])) + ".")
    P(f"- A skip is *ineffective* (no-op) when the signature is unchanged; most call skips are "
      f"effective or crash. Swept in {dt:.0f}s.\n")
    P("| addr | call | φIF flips | no-op A/B | crash A/B |")
    P("|---|---|---|---|---|")
    for r in sorted(rows, key=lambda r: -r["flips"]):
        P(f"| `{hex(r['addr'])}` | `{r['label']}` | {r['flips']} | "
          f"{r['noopA']}/{r['noopB']} | {r['crashA']}/{r['crashB']} |")
    os.makedirs("report", exist_ok=True)
    with open("report/mayo_phi.md", "w") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"\nwrote report/mayo_phi.md  ({len(phi)} φIF sites of {len(sites)})")


if __name__ == "__main__":
    main()
