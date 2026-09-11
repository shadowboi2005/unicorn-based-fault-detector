"""Diagnose WHY each skip-fault site crashes or hangs: memory fault vs runaway."""
import sys
sys.path.insert(0, ".")
from ucpqc import Machine, Scheme
from ucpqc.machine import EmulationError

ELF = "firmware/ml-dsa-44_m4f_test.elf"
CAP = 20_000_000
m = Machine.from_elf(ELF); scheme = Scheme.bind(m); m.boot()
m.stub_randombytes(b"secret-key-AAAA"); pk, sk = scheme.keypair()
hwm = m._alloc_ptr

SITES = [
    (0x4c7c, "sample y (uniform_gamma1)"), (0x4ce0, "decompose w"),
    (0x4d18, "shake squeeze (c_tilde)"), (0x4d22, "poly_challenge (c)"),
    (0x4d4c, "c*s1 (basemul_invntt)"), (0x4d74, "z-norm check (chknorm)"),
    (0x4dbc, "c*s2 (basemul_invntt)"), (0x4dd8, "r0 check (chknorm)"),
    (0x4dec, "c*t0 (pointwise)"), (0x4e0e, "ct0 check (chknorm)"),
    (0x4e32, "make_hint"),
    (0x4d5e, "z = z + y (the LEAK, for contrast)"),
]

for pc, label in SITES:
    h = m.hook_code(lambda mm, a, s, _pc=pc: mm.set_pc(_pc + 4),
                    begin=pc, end=pc, precise=False)
    m._alloc_ptr = hwm
    before = m.icount
    try:
        m.stub_randombytes(b"seed"); pk2, sk2 = pk, sk
        sig = scheme.sign(b"probe", sk, max_instructions=CAP)
        used = scheme.last_cost["signature"]
        verdict = f"OK  ({used:,} insns, siglen={len(sig)})"
    except EmulationError as e:
        used = m.icount - before
        msg = str(e).split("\n")[0][:70]
        if "budget" in msg or "exhausted" in msg:
            verdict = f"HANG  (ran {used:,} insns to the {CAP:,} cap -> infinite loop)"
        else:
            verdict = f"CRASH ({used:,} insns) {msg}"
    except Exception as e:
        verdict = f"OTHER {type(e).__name__}: {str(e)[:60]}"
    finally:
        m.uc.hook_del(h); m.uc.ctl_flush_tb()
    print(f"  {label:<34} {verdict}")
