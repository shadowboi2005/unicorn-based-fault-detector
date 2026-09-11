"""ALAFA-style whole-call fault sweep of the Dilithium signing loop.

ALAFA (Automatic Leakage Assessment for Fault Attacks) asks, mechanically and one
fault site at a time: *if I fault this operation, does the signature start leaking
the secret key?*  Here the fault is a whole-call skip (step the PC past a `bl`, so
the operation never runs) at every operation call in the reject-and-retry loop,
and the leak test is the two-key matched-filter classifier: sign under two keys
and see whether the released `z` distributions can be told apart.  50% = hidden,
100% = leak (flagged at >= 80%).

Result: exactly one site leaks -- `z = z + y` (the mask add) -- because skipping
it leaves `z = c*s1`, the secret in the clear (catalog 4.2, Ravi 2019).  The
rejection-check skips crash/hang instead (the whole-call skip leaves a stale
verdict -> always reject), so this sweep is a detector of high-SNR mask-removal
faults, honestly separated from the check-bypass class.

This is now a thin driver over the framework; the fault-site table, feature and
detector live in `ucpqc.profiles.mldsa` + `ucpqc.assess`.  Equivalent CLI:

    python -m ucpqc sweep firmware/ml-dsa-44_m4f_test.elf --n 16
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

result = assess.sweep_sites(scheme, profile_for(scheme), n=N)
print(report.format_table(result))
