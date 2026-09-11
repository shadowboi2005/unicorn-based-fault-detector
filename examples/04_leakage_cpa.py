"""A miniature CPA against the NTT, end to end inside the emulator.

The NTT is called directly with inputs we choose, one simulated power trace is
recorded per call, and the traces are correlated against the Hamming weight of
one input coefficient.  The correlation peak shows exactly where in the
routine that coefficient is manipulated -- the sample the same attack would
target on real hardware.

Traces are noise-free by construction, so this answers "does the leak exist
and where", not "how many real traces would it take".  Add --noise to see how
the peak survives.

    python examples/04_leakage_cpa.py [firmware.elf] [n_traces]
"""

import random
import struct
import sys

sys.path.insert(0, ".")

from ucpqc import LeakageTracer, Machine, Scheme, TraceSet, hamming_weight

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
N_TRACES = int(sys.argv[2]) if len(sys.argv) > 2 else 40
NOISE = 2.0 if "--noise" in sys.argv else 0.0

N = 256  # coefficients in a Dilithium polynomial
Q = 8380417
TARGET_COEFF = 0

m = Machine.from_elf(ELF)
scheme = Scheme.bind(m)
m.boot()

ntt = scheme.landmark("ntt") or "pqcrystals_dilithium_ntt"
poly = m.alloc(4 * N)
print(f"target: {ntt}() at {m.addr_of(ntt):#010x}, buffer at {poly:#010x}\n")

# One tracer, reused across calls: the leakage of each call is sliced out of
# the running sample list afterwards.
tracer = LeakageTracer(m, model="hd_reg", window=ntt, scope="body")

traces = TraceSet()
rng = random.Random(1234)
mark = 0
for i in range(N_TRACES):
    coeffs = [rng.randrange(Q) for _ in range(N)]
    m.write(poly, struct.pack(f"<{N}i", *coeffs))
    m.call(ntt, [poly])
    traces.add(tracer.samples[mark:], coeffs[TARGET_COEFF])
    mark = len(tracer.samples)

lengths = {len(t) for t in traces.traces}
print(f"{N_TRACES} traces of {lengths} samples each")

hypothesis = [hamming_weight(value) for value in traces.inputs]
correlation = traces.correlate(hypothesis)

import numpy as np

if NOISE:
    print(f"(noise sigma = {NOISE})")
peak = int(np.nanargmax(np.abs(correlation)))
print(f"\nbest correlation |rho| = {abs(correlation[peak]):.3f} at sample {peak}")
print(f"that sample is instruction {m.image.describe(tracer.pcs[peak])}")

print("\nstrongest 10 samples:")
order = np.argsort(-np.abs(np.nan_to_num(correlation)))[:10]
for idx in order:
    print(f"  sample {int(idx):>6}  rho={correlation[idx]:+.3f}  "
          f"{m.image.describe(tracer.pcs[int(idx)])}")

np.save("cpa_correlation.npy", correlation)
print("\ncorrelation curve saved to cpa_correlation.npy")
