"""Intra-function instruction-skip faults via capture-and-replay.

Where example 09 skips whole calls, this skips *individual instructions inside* a
function, and does it cheaply: it captures the target function's I/O once per
golden signing, then replays only that function per fault trial (a few thousand
instructions) instead of re-running the whole ~1.5M-instruction signature.  Each
faulted output is scored with the two-key matched-filter detector.

On `polyvecl_add` (the z = z + y mask add) two sites reach 100%: the `bl poly_add`
(the add never runs, so z stays c*s1 -- catalog 4.2, the instruction-level twin of
ex 09) and `mov r7, r0` (corrupts the output pointer).  Note the latter is an
isolated-replay false positive: end-to-end its released z only weakly separates
(~69%), because the wild write corrupts downstream state -- a reminder that a
capture-replay flag on a pointer-setup instruction should be confirmed end to end.

This is now a thin driver over the framework; the capture/replay/sweep and the
target definition live in `ucpqc.replay`, `ucpqc.assess`, and the profile.
Equivalent CLI:

    python -m ucpqc funcskip firmware/ml-dsa-44_m4f_test.elf --target polyvecl_add --n 16
"""

import sys

sys.path.insert(0, ".")

from ucpqc import Machine, Scheme, assess, report
from ucpqc.profiles import profile_for

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 16

m = Machine.from_elf(ELF)
scheme = Scheme.bind(m)
m.boot()
profile = profile_for(scheme)

# default target is the profile's z = z + y mask add; try "y_sampler" (with
# --detector uniformity) or "polyvecl_reduce" (a clean control) too.
result = assess.sweep_function(scheme, profile, n=N)
print(report.format_table(result))
