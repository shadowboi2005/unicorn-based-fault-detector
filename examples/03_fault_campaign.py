"""Fault campaign against the rejection checks in Dilithium signing.

The signing loop only releases a signature once poly_chknorm() has confirmed
that z and r0 are small enough.  Those checks are the classic fault target:
if one is skipped, the signature that comes out is one the implementation
meant to throw away, and such signatures leak information about the secret.

This sweeps an instruction-skip fault across the norm check and classifies
what comes out.  Interpretation of the outcomes:

    silent      the skipped instruction did not matter here
    different   a complete but different signature -- the interesting case
    rejected    the operation itself failed (here: it no longer verifies)
    crash       the core faulted
    timeout     the signing loop stopped terminating

    python examples/03_fault_campaign.py [firmware.elf] [target-function]
"""

import sys

sys.path.insert(0, ".")

from ucpqc import FaultCampaign, Machine, Outcome, Scheme
from ucpqc.faults import SKIP, sweep_function_body

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
TARGET = sys.argv[2] if len(sys.argv) > 2 else "pqcrystals_dilithium_poly_chknorm"
MESSAGE = b"fault me"

m = Machine.from_elf(ELF)
scheme = Scheme.bind(m)
m.boot()
m.stub_randombytes(b"campaign")

pk, sk = scheme.keypair()


def sign_and_check(machine):
    """The operation under attack; its return value is what gets compared."""
    sig = scheme.sign(MESSAGE, sk, max_instructions=60_000_000)
    if not scheme.verify(sig, MESSAGE, pk):
        # A faulty signature that no longer verifies is still a result worth
        # recording, so it is reported rather than silently accepted.
        raise ValueError("faulty signature does not verify")
    return sig


campaign = FaultCampaign(m, sign_and_check)
golden = campaign.prepare()
print(f"{scheme.name}: golden signature is {len(golden)} bytes, "
      f"{campaign.golden_icount:,} instructions\n")

specs = list(sweep_function_body(m, TARGET, kind=SKIP, stride=1))
print(f"sweeping {len(specs)} instruction-skip faults across {TARGET}\n")
campaign.run(specs, progress=10)

print("\n" + campaign.format())

exploitable = [r for r in campaign.results if r.outcome == Outcome.DIFFERENT]
if exploitable:
    print("\nsignatures that changed but still verified -- inspect these first:")
    for result in exploitable[:10]:
        diff = sum(a != b for a, b in zip(result.output, golden))
        print(f"  {result.spec.describe(m.image):<52} {diff:>5} bytes differ")

campaign.write_csv("fault_campaign.csv")
print("\nfull results in fault_campaign.csv")


# --- the same target, attacked at the level of its result -------------------
#
# A single skipped instruction rarely flips the verdict of a check.  The
# stronger version of this fault is to bypass the check outright, which the
# emulator can express directly: replace the function with one that always
# answers "the norm is fine".  The signing loop then releases its first
# candidate instead of resampling, and that candidate is exactly the kind of
# out-of-bounds signature the rejection step exists to withhold.

print(f"\n\n=== bypassing {TARGET} entirely ===")
campaign.reset()
m.intercept(TARGET, lambda machine: 0)  # 0 == "norm is within bounds"

bypassed = scheme.sign(MESSAGE, sk, max_instructions=60_000_000)
still_valid = scheme.verify(bypassed, MESSAGE, pk)

print(f"golden signature:    {campaign.golden_icount:>12,} instructions")
print(f"with the check gone: {scheme.last_cost['signature']:>12,} instructions "
      f"({scheme.last_cost['signature'] / campaign.golden_icount:.0%} of golden)")
print(f"signature differs from golden: {bypassed != golden}")
print(f"signature still verifies:      {still_valid}")

print("\n  Either way the device has released a candidate its own rejection")
print("  step decided to throw away -- that is the leak, and the shortened")
print("  run above is how a timing side channel would spot it.")
if still_valid:
    print("  Here it still verifies, so a verifier cannot tell: the discarded")
    print("  candidate failed one of the other bounds, not the one verification")
    print("  re-checks.")
else:
    print("  Here it no longer verifies, so the released z is outside the bound")
    print("  the rejection step exists to enforce.")
