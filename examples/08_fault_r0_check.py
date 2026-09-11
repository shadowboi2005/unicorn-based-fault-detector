"""Fault the r0 rejection check -- taking the mask off the transcript.

Example 07 showed that z is statistically independent of the secret *because*
rejection sampling filters every signing attempt.  The rejection checks ARE the
zero-knowledge mask.  So the way to make a Dilithium transcript leak is to fault
one of those checks.  Here we target the r0 check.

Dilithium's signing loop rejects a candidate unless all of:
    ||z||inf   < gamma1 - beta     (protects the s1 branch)
    ||r0||inf  < gamma2 - beta     (protects the s2 branch)   <-- we fault this
    ||ct0||inf < gamma2
Disassembly of crypto_sign_signature_ctx in this firmware pins the r0 check to:
    0x4dd8  bl   poly_chknorm       ; r0 = (||r0||inf >= gamma2-beta) ? 1 : 0
    0x4ddc  cmp  r0, #0
    0x4dde  bne  #0x4e86            ; reject -> loop with a fresh nonce
(the bound 95154 = gamma2-beta = 8380417//88 - 78 confirms which chknorm it is).

The fault: a single persistent code hook forces the check's result to 0
("in bounds") every iteration, so the r0 rejection never fires.  This models a
stuck-at / instruction-effect fault holding the compare result.

    python examples/08_fault_r0_check.py [firmware.elf] [n_messages]
"""

import statistics
import sys

sys.path.insert(0, ".")

from ucpqc import Machine, Scheme

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 100

R0_CMP = 0x4ddc          # cmp r0,#0 right after the r0 chknorm returns
GAMMA2_MINUS_BETA = (8380417 - 1) // 88 - 78   # 95154, the bound just verified

m = Machine.from_elf(ELF)
scheme = Scheme.bind(m)
m.boot()
m.stub_randombytes(b"rowhammer-victim")
print(f"{scheme.name}   r0 check at {R0_CMP:#06x}, bound gamma2-beta={GAMMA2_MINUS_BETA}\n")

pk, sk = scheme.keypair()
hwm = m._alloc_ptr
messages = [f"msg-{i}".encode() for i in range(N)]


def campaign():
    """Sign every message once; return per-sign costs, verify count, and the
    number of accepted sigs whose r0 was *really* out of bounds (+ how many of
    those still verify)."""
    costs, verified, forbidden, forbidden_ok = [], 0, 0, 0
    for msg in messages:
        m._alloc_ptr = hwm
        sig = scheme.sign(msg, sk)
        costs.append(scheme.last_cost["signature"])
        ok = scheme.verify(sig, msg, pk)
        verified += ok
        if last_real[0] == 1:            # accepting iteration violated the r0 bound
            forbidden += 1
            forbidden_ok += ok
    return costs, verified, forbidden, forbidden_ok


# last real r0-chknorm verdict seen in the current sign (1 = out of bounds).
# Stays 0 during the golden run because the hook is not installed yet.
last_real = [0]

# --- golden run -------------------------------------------------------------
c0, v0, _, _ = campaign()
print(f"[golden  ] sign cost mean={statistics.mean(c0):11,.0f}   verifies {v0}/{N}")

# --- install the fault, then repeat -----------------------------------------
def force_r0_inbounds(mm, addr, size):
    last_real[0] = mm.reg("r0")          # record the true verdict...
    mm.set_reg("r0", 0)                  # ...then force "in bounds"

m.hook_code(force_r0_inbounds, begin=R0_CMP, end=R0_CMP, precise=False)

c1, v1, forbidden, forbidden_ok = campaign()
print(f"[r0-fault ] sign cost mean={statistics.mean(c1):11,.0f}   verifies {v1}/{N}")

# --- what the fault did -----------------------------------------------------
print(f"\nsigning got {100*(1-statistics.mean(c1)/statistics.mean(c0)):.0f}% cheaper: "
      "a whole rejection condition is gone, so far fewer retries.\n")

print(f"accepted signatures that were actually OUT of bounds (||r0|| >= gamma2-beta):"
      f"  {forbidden}/{N}")
print(f"   ...of those, how many still pass verify():  {forbidden_ok}/{forbidden}")
print("""   -> every forbidden signature still verifies.  A verify-after-sign
      countermeasure -- the primary defense proposed against the correction
      attack -- is BLIND to this fault: the poisoned signatures are valid.""")

# --- the fault's fingerprint, as a distribution -----------------------------
# The honest signer's cost is spread out (each rejection is another y..w..chknorm
# round); killing the r0 check pulls the whole distribution down toward the
# single-iteration floor.
BINS = 22
lo, hi = min(c0 + c1), max(c0 + c1) + 1
step = (hi - lo) / BINS


def hist(xs):
    h = [0] * BINS
    for x in xs:
        h[min(BINS - 1, int((x - lo) / step))] += 1
    return h


hg, hf = hist(c0), hist(c1)
scale = 46.0 / max(max(hg), max(hf))
print(f"\nper-signature cost distribution   ( # golden   * r0-faulted )")
print(f"  floor {lo:,.0f} insns  ..  {hi:,.0f}\n")
for k in range(BINS):
    a, b = int(hg[k] * scale), int(hf[k] * scale)
    row = "".join("#" if j < a else "*" for j in range(max(a, b)))
    print(f"  {lo + k*step:11,.0f} |{row}")

print("""
Reading it: the golden costs fan out to the right (many signatures need several
rejection rounds); with the r0 check dead the mass collapses onto the floor --
most signatures are now accepted on the first try that clears only ||z|| and
||ct0||.  That includes the ~20% whose r0 is out of bounds.

Those out-of-band samples are the leak.  The r0 rejection is exactly what keeps
LowBits(w - c*s2) uniform; the ones that slip through are correlated with c*s2,
so collecting them recovers s2 by statistical/differential fault analysis --
while the device keeps emitting perfectly verifiable signatures.  This is the
r0/s2 counterpart of the s1 unmasking that faulting the ||z|| check would give.""")
