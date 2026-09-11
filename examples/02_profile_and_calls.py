"""Where does a Dilithium signature spend its cycles?

Combines the two cheap analyses -- a per-function instruction profile and a
call tree -- over one signing operation.  Both attach to the machine and cost
almost nothing, so they can run over a complete signature.

    python examples/02_profile_and_calls.py [firmware.elf]
"""

import sys

sys.path.insert(0, ".")

from ucpqc import CallTracer, Machine, Profiler, Scheme

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"

m = Machine.from_elf(ELF)
scheme = Scheme.bind(m)
m.boot()
m.stub_randombytes(b"profile")

pk, sk = scheme.keypair()

profiler = Profiler(m)
calls = CallTracer(m, max_depth=3)
sig = scheme.sign(b"profile me", sk)
calls.finish()
profiler.detach()
calls.detach()

print(f"one {scheme.name} signature = {scheme.last_cost['signature']:,} instructions\n")
print(profiler.format(15))

print("\n\ntop-level structure of the signing operation:\n")
print(calls.format(max_lines=25, min_cost=10_000))

print("\n\ninclusive cost per function (calls, instructions):\n")
for name, (count, cost) in list(calls.totals().items())[:10]:
    print(f"  {name:<52} {count:>6} x  {cost:>12,}")
