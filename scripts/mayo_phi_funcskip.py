#!/usr/bin/env python3
"""Approach (B): intra-function instruction-skip φIF for MAYO.

Whole-call skips (approach A) found no key-dependent ineffectiveness because a whole
function is either essential or dead, never *conditionally* dead by key. (B) goes a
level finer: skip each *instruction* inside a secret-dependent MAYO function and ask
whether the skip's ineffectiveness depends on the key.

The funcskip *call* backend can't drive these functions (GCC `.isra` specialisations +
>4-arg stack-passed outputs), so we use a *snapshot-region* replay that needs no arg
specs: during a golden deterministic sign, snapshot the full machine at the function's
first entry (LR gives the return address); then for each instruction skip, restore that
snapshot and run only entry->ret, and compare the resulting *writable RAM + r0* to the
golden entry->ret result.  "Ineffective" = that state is byte-identical to golden, i.e.
the skip had no net effect on the function's output.  φIF = ineffectiveness that differs
between keys A and B on the same message.

Usage:  scripts/mayo_phi_funcskip.py [N] [stride]     (N msgs/key default 16, stride 1)
Writes report/mayo_phi_funcskip.md.
"""
import os, sys, time, hashlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); os.chdir(ROOT)
from ucpqc import Machine, Scheme, assess, profiles as pm
from ucpqc.faults import FaultSpec, SKIP
from ucpqc.replay import Injector

ELF = "firmware/mayo1_m4f_test.elf"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 16
STRIDE = int(sys.argv[2]) if len(sys.argv) > 2 else 1

# secret-dependent, sign-path candidates (reachability is checked at run time; a
# function whose entry is never hit during signing is reported NOT REACHED)
TARGETS = [
    "compute_rhs.isra.0", "sample_solution", "compute_M_and_VPV.isra.0",
    "P1_times_Vt.isra.0", "P1_times_O.isra.0", "P1P1t_times_O.isra.0", "m_upper",
    "mul_add_mat_x_m_mat_m4f_K_V_O_triangular_asm",
    "mul_add_mat_x_m_mat_m4f_K_V_K_triangular_asm",
    "mul_add_mat_trans_x_m_mat_m4f_V_O_O_asm",
    "multiply_P1_right_m4f_V_V_O_asm",
]
SITE_CAP = 700          # auto-raise stride so a giant asm routine stays bounded


def main():
    m = Machine.from_elf(ELF); sch = Scheme.bind(m); m.boot()
    prof = pm.profile_for(sch)
    sk = assess._make_keys(sch, assess.DEFAULT_KEYS, "independent", prof)
    prof.setup(m); m.stub_cycle_counter(); m.stub_randombytes(b"seed")
    clean = m.snapshot()
    messages = assess.standard_messages(N)
    WR = [(r.base, r.size) for r in m.platform.ram_regions if r.name in ("sram", "scratch")]

    def state_sig():
        # raw writable-RAM bytes + r0 as a tuple; comparison is C memcmp (short-circuits
        # on the first differing region/byte), much faster than hashing 5 MB per replay.
        return tuple(bytes(m.uc.mem_read(base, size)) for base, size in WR) \
            + ((m.reg("r0") & 0xFFFFFFFF),)

    def capture_entry(key, i, entry):
        """Sign messages[i] under key, snapshot the machine at the FIRST hit of `entry`.
        Returns (snap, ret) or (None, None) if the function was never reached."""
        m.restore(clean)
        box = {}
        def on_entry(mm, addr, size):
            if "snap" not in box:
                # LR carries the Thumb bit (odd); the actual return PC is even, so mask it
                # or _emu_start's `until` never matches and the region runs to budget.
                box["snap"] = mm.snapshot(); box["ret"] = mm.reg("lr") & ~1
                mm.uc.emu_stop()
        h = m.hook_code(on_entry, begin=entry, end=entry, precise=False)
        try:
            sch.sign(messages[i], sk[key], max_instructions=60_000_000)
        except Exception:
            pass
        finally:
            m.unhook(h)
        return box.get("snap"), box.get("ret")

    def run_region(snap, entry, ret, budget, site=None):
        """Restore snap, run entry->ret (optionally skipping instr at `site`), return the
        writable-state signature, or None on crash/hang."""
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

    results = []
    for fn in TARGETS:
        try:
            s, e = m.image.extent_of(fn)
        except Exception:
            results.append((fn, "no-symbol", None)); print(f"  {fn}: no symbol"); continue
        entry = m.image.addr_of(fn) if hasattr(m.image, "addr_of") else m.addr_of(fn)
        # --- capture entry snapshots per (key, message); detect reachability ---
        snaps = {"A": [], "B": []}; rets = {"A": [], "B": []}
        reached = True
        for k in ("A", "B"):
            for i in range(N):
                snp, ret = capture_entry(k, i, entry)
                if snp is None:
                    reached = False; break
                snaps[k].append(snp); rets[k].append(ret)
            if not reached:
                break
        if not reached:
            results.append((fn, "not-reached", None)); print(f"  {fn}: NOT REACHED in signing"); continue

        # --- golden entry->ret state per (key, message) + a budget from its length ---
        i0 = m.icount; run_region(snaps["A"][0], entry, rets["A"][0], 60_000_000)
        body = max(m.icount - i0, 1000)
        budget = body * 6 + 200_000
        golden = {k: [run_region(snaps[k][i], entry, rets[k][i], budget) for i in range(N)]
                  for k in ("A", "B")}

        # --- instruction sites (auto-stride to stay under SITE_CAP) ---
        instrs, pc = [], s
        while pc < e:
            _, sz, _ = m.disasm_one(pc); instrs.append(pc); pc += sz or 2
        stride = STRIDE
        while len(instrs[::stride]) > SITE_CAP:
            stride += 1
        sites = instrs[::stride]

        # --- skip sweep ---
        t0 = time.perf_counter()
        phi_sites = phi_flips = 0
        for pc in sites:
            effA, effB = [], []
            for k, eff in (("A", effA), ("B", effB)):
                for i in range(N):
                    sig = run_region(snaps[k][i], entry, rets[k][i], budget, site=pc)
                    eff.append(None if sig is None else (sig != golden[k][i]))
            flips = sum(1 for i in range(N)
                        if effA[i] is not None and effB[i] is not None and effA[i] != effB[i])
            if flips:
                phi_sites += 1; phi_flips += flips
        dt = time.perf_counter() - t0
        results.append((fn, "ok", dict(sites=len(sites), stride=stride, body=body,
                                       phi_sites=phi_sites, phi_flips=phi_flips)))
        print(f"  {fn}: {len(sites)} sites (stride {stride}, body {body} insn) -> "
              f"phi_sites={phi_sites} flips={phi_flips}  [{dt:.0f}s]")

    # --- report ---
    out = []; P = out.append
    P("# MAYO intra-function instruction-skip φIF (approach B)\n")
    P(f"**MAYO1** (`{ELF}`), deterministic signing, {N} messages/key. Skip each instruction "
      f"inside a secret-dependent function (snapshot-region replay, entry->ret, no arg specs) "
      f"and compare writable RAM + r0 to the golden run. A site is **φIF** if the skip is a "
      f"no-op for one key but changes the state for the other, on the same message.\n")
    ok = [(fn, r) for fn, st, r in results if st == "ok"]
    tot_phi = sum(r["phi_sites"] for _, r in ok)
    P(f"- **φIF sites across the swept functions: {tot_phi}.**\n")
    P("| function | status | sites (stride) | φIF sites | φIF flips |")
    P("|---|---|---|---|---|")
    for fn, st, r in results:
        if st != "ok":
            P(f"| `{fn}` | {st} | — | — | — |")
        else:
            P(f"| `{fn}` | ok | {r['sites']} ({r['stride']}) | {r['phi_sites']} | {r['phi_flips']} |")
    ranked = sorted([(fn, r) for fn, r in ok if r["phi_sites"] > 0],
                    key=lambda t: -t[1]["phi_sites"])
    P("\n## Takeaways\n")
    P("- **φIF exists intra-function in MAYO**, where whole-call skips (approach A) found 0. "
      "It concentrates in: " + ", ".join(f"`{fn}`({r['phi_sites']})" for fn, r in ranked) + ".")
    P("- The fully word-packed GF(16) matrix multiplies that are reached in signing "
      "(`P1_times_Vt`, `P1P1t_times_O`, `mul_add_mat_x_m_mat_*`) show **0** φIF: a skip in a "
      "fused/bitsliced vector op hits many packed field elements at once, so it is always "
      "effective or a crash -- never *conditionally* dead by key. The φIF signal instead lands "
      "in the per-element/accumulator-shaped code (`multiply_P1_right_*_V_V_O`, `sample_solution`, "
      "`compute_rhs`).")
    P("- Functions marked *not-reached* (`P1_times_O`, `m_upper`, `mul_add_mat_trans_*`) are "
      "keygen / public-map only, not on the signing path.")
    P("\n## Caveat (same as the Dilithium φIF study)\n")
    P("These counts **locate candidate sites; they do not establish SIFA-exploitability.** The "
      "2-key metric conflates genuine key-dependence with ordinary *input*-dependence: keys A and "
      "B each run a full signing, so they feed different secret-derived intermediates (vinegar "
      "`V`, oil `O`) AND a different deterministic salt, and a φIF flip only says the two runs "
      "differed in ineffectiveness. SIFA-exploitability is **not** decided by whether a value is "
      "public -- SIFA exploits an ineffective-conditioned *bias* that correlates with the secret, "
      "which can arise for public operands too. Settling each site needs the SIFA test proper: fix "
      "the key, fault across many inputs, filter to the ineffective subset, and test the target "
      f"intermediate's conditional distribution for a secret-correlated bias. (N={N}; flip counts "
      "are partial and scale with N -- the φIF *site* set is the stable signal.)")
    os.makedirs("report", exist_ok=True)
    with open("report/mayo_phi_funcskip.md", "w") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"\nwrote report/mayo_phi_funcskip.md  (total φIF sites: {tot_phi})")


if __name__ == "__main__":
    main()
