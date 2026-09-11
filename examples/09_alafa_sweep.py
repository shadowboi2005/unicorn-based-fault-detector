"""ALAFA-style automatic leakage assessment: sweep fault sites, flag the leaky ones.

Example 07 ran ONE leakage test at ONE hand-picked fault point.  ALAFA
(Automatic Leakage Assessment for Fault Attack countermeasures) does it
automatically: try a fault at every candidate site, run a leakage test at each,
and report which faults make the code leak the secret.  That is this example.

For each `bl` (operation call) in the signing loop we install an instruction-
skip fault (drop the call), then run the two-key leakage test from example 07:
sign under two different secret keys and ask whether the emitted signatures are
DISTINGUISHABLE by key.  Distinguishable -> the output depends on the secret it
must hide -> that fault site is exploitable.  The detector uses only signatures
and the challenge c (via the firmware's poly_challenge); no public key, no
secret, no key recovery.

Sites that crash or fail to terminate under the fault are reported separately.
The sweep rediscovers, on its own, the documented mask-removal point -- the
z = y + c*s1 add (category 4.2, Ravi 2019).  Skipping the whole y sampler
crashes signing instead (the real category-4.1 loop-abort is a finer fault:
abort PART-way through sampling y, leaving some coefficients known -- not a
droppable whole call).  The rejection-check faults (category 4.3) either crash
or read as non-leaky here, because their leak needs a lattice/polytope solver
over many signatures, not a per-signature distinguisher.

    python examples/09_alafa_sweep.py [firmware.elf] [n_per_key]
"""

import struct
import sys

sys.path.insert(0, ".")

import numpy as np

from ucpqc import Machine, Scheme

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 16
CAP = 20_000_000                      # instruction cap: bounds a fault that hangs

L, NC, GAMMA1 = 4, 256, 1 << 17
CT, POLYZ = 32, NC * 18 // 8
SIGLEN = CT + POLYZ * L + 84          # 2420 for ML-DSA-44

m = Machine.from_elf(ELF)
scheme = Scheme.bind(m)
m.boot()
cbuf = m.alloc(4 * NC)


def challenge(ctilde):
    m.call("pqcrystals_dilithium_poly_challenge", [cbuf, m.alloc_bytes(ctilde)])
    return np.array(struct.unpack(f"<{NC}i", m.read(cbuf, 4 * NC)), float)


def unpack_z(sig):
    off, z = CT, []
    for _ in range(L):
        a = sig[off:off + POLYZ]; off += POLYZ
        for i in range(NC // 4):
            b = a[9 * i:9 * i + 9]
            z += [GAMMA1 - (b[0] | b[1] << 8 | (b[2] & 3) << 16),
                  GAMMA1 - ((b[2] >> 2) | b[3] << 6 | (b[4] & 15) << 14),
                  GAMMA1 - ((b[4] >> 4) | b[5] << 4 | (b[6] & 63) << 12),
                  GAMMA1 - ((b[6] >> 6) | b[7] << 2 | b[8] << 10)]
    return np.array(z, float).reshape(L, NC)


def matched(c, z):
    supp = np.nonzero(c)[0]; cs = c[supp]
    mf = np.zeros((L, NC))
    for l in range(L):
        zl = z[l]
        for lag in range(NC):
            idx = supp + lag
            mf[l, lag] = np.sum(cs * np.where(idx >= NC, -1.0, 1.0) * zl[idx % NC])
    return mf.ravel()


def make_key(seed):
    m.stub_randombytes(seed); return scheme.keypair()


k0 = make_key(b"secret-key-AAAA")[1]
k1 = make_key(b"secret-key-BBBB")[1]
messages = [f"msg-{i}".encode() for i in range(N)]


class Unstable(Exception):
    pass


def collect(sk, seed):
    """Feature matrix for one key; raise Unstable if signing misbehaves."""
    m.stub_randombytes(seed); hwm = m._alloc_ptr
    feats = []
    for msg in messages:
        m._alloc_ptr = hwm
        try:
            sig = scheme.sign(msg, sk, max_instructions=CAP)
        except Exception:
            raise Unstable("sign failed")
        if len(sig) != SIGLEN:
            raise Unstable("malformed signature")
        feats.append(matched(challenge(sig[:CT]), unpack_z(sig)))
    return np.array(feats)


def leakage_accuracy():
    """Two-key leave-one-out classifier accuracy; 0.5 == indistinguishable."""
    F0, F1 = collect(k0, b"nonce-0"), collect(k1, b"nonce-1")
    correct = total = 0
    for own, other in ((F0, F1), (F1, F0)):
        g_other = other.mean(0)
        for i in range(len(own)):
            g_own = (own.sum(0) - own[i]) / (len(own) - 1)
            correct += int(np.dot(own[i], g_own) > np.dot(own[i], g_other))
            total += 1
    return correct / total


# candidate fault sites: every operation call in the signing loop body
SITES = [
    (0x4c7c, "sample y (uniform_gamma1)"), (0x4c90, "memcpy"),
    (0x4c9a, "y -> NTT (polyvecl_ntt)"), (0x4cb0, "w = A*y (matrix_pointwise)"),
    (0x4cc4, "w -> invNTT"), (0x4ce0, "decompose w"), (0x4cec, "pack w1"),
    (0x4d18, "shake squeeze (c_tilde)"), (0x4d22, "poly_challenge (c)"),
    (0x4d4c, "c*s1 (basemul_invntt)"), (0x4d5e, "z = z + y (polyvecl_add)"),
    (0x4d68, "reduce z"), (0x4d74, "z-norm check (chknorm)"),
    (0x4d88, "pack z into sig"), (0x4dbc, "c*s2 (basemul_invntt)"),
    (0x4dca, "w0 - c*s2 (poly_sub)"), (0x4dd8, "r0 check (chknorm)"),
    (0x4dec, "c*t0 (pointwise)"), (0x4e0e, "ct0 check (chknorm)"),
    (0x4e32, "make_hint"),
]


def sweep():
    print(f"{scheme.name}   ALAFA-style sweep: {len(SITES)} skip-fault sites, "
          f"N={N} sigs/key\n")
    print(f"  {'no fault (control)':<30}", end="", flush=True)
    print(f" acc={leakage_accuracy():.0%}")
    rows = []
    for pc, label in SITES:
        h = m.hook_code(lambda mm, a, s, _pc=pc: mm.set_pc(_pc + 4),
                        begin=pc, end=pc, precise=False)
        try:
            acc = leakage_accuracy()
            status = "LEAK" if acc >= 0.80 else "ok"
            rows.append((pc, label, f"{acc:.0%}", status))
        except Unstable:
            rows.append((pc, label, "  -", "crash/hang"))
        finally:
            m.uc.hook_del(h)
            m.uc.ctl_flush_tb()
        pc_, lb_, ac_, st_ = rows[-1]
        print(f"  {label:<30} {ac_:>5}   {st_}")
    return rows


rows = sweep()
leaks = [r for r in rows if r[3] == "LEAK"]
print(f"\n=== leakage assessment ===")
print(f"{len(leaks)} of {len(SITES)} skip-fault sites make the output leak the key:")
for pc, label, acc, _ in leaks:
    print(f"   {pc:#08x}  {label:<30} two-key accuracy {acc}")
print("""
The flagged site drops the operation that mixes the nonce mask into the response
(z = z + y), leaving z = c*s1 -- the secret in the clear, category 4.2 of the
catalog (Ravi 2019).  Most other whole-call skips crash signing (the operation
is load-bearing) or leave z fully masked (~chance).  Notably the rejection-check
skips (z-norm, r0, ct0) are NOT flagged: they do leak, but only into a
lattice/polytope problem over many signatures (example 08), which a
per-signature two-key distinguisher cannot see.  So this sweep is a detector of
high-SNR mask-removal faults and honestly separates them from the check-bypass
class that needs heavier analysis.""")
