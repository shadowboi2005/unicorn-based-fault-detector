"""Fault-injection leakage assessment: does a fault make the output leak the key?

This is a *detector*, in the spirit of ALAFA (Automatic Leakage Assessment for
Fault Attack countermeasures) and "Learn From Your Faults": we do not recover a
key, we answer one question -- under a given instruction fault, has the signing
code started leaking secret-dependent information into its output?  The test is
the standard leakage-assessment one: fix the fault, sign under TWO different
secret keys, and ask whether the two output populations are DISTINGUISHABLE.
If they are, the output depends on the secret it should hide -> leakage.

The fault point is a documented one.  Grouping the Dilithium fault literature by
what is corrupted, this is category 4.2 -- the response computation z = y + c*s1:

    Ravi, Jhanwar et al. 2019 (Exploiting Determinism, ePrint 2019/769):
        skip the addition in z = y + c*s1, leaving one operand in the clear.
    ElGhamrawy 2023 (MLWE->RLWE), Du 2025 (Breaking the Shield): same target.

In this firmware the masking add is `polyvecl_add(&z, &z, &y)` at

    0x4d5e  bl  polyvecl_add        ; z = z + y   (z already holds c*s1)

Skipping that one call leaves z = c*s1 -- the nonce mask y is never applied, so
the response carries the secret directly.  A persistent hook steps the PC past
the call.  Then we run the leakage test.

Why this fault and not a rejection-check fault: removing the *mask* (4.1/4.2) is
high-SNR -- two keys separate from a handful of signatures.  Faulting a
rejection *check* (4.3, example 08) also leaks, but z stays masked by full-width
y, so the leak is real yet needs a lattice/polytope solver over many signatures,
not a simple distinguisher.

    python examples/07_z_distribution.py [firmware.elf] [n_per_key]
"""

import struct
import sys

sys.path.insert(0, ".")

import numpy as np

from ucpqc import Machine, Scheme

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 40

NONCE_ADD = 0x4d5e                    # bl polyvecl_add (z = z + y); skip -> z = c*s1
L, NC, GAMMA1, ETA = 4, 256, 1 << 17, 2
CT, POLYZ, S1_OFF = 32, NC * 18 // 8, 128

m = Machine.from_elf(ELF)
scheme = Scheme.bind(m)
m.boot()
cbuf = m.alloc(4 * NC)


def challenge(ctilde):
    """Expand c from c_tilde using the firmware's own SampleInBall."""
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


def unpack_s1(sk):                    # only for the internal validation line
    S = []
    for p in range(L):
        a = sk[S1_OFF + 96 * p: S1_OFF + 96 * (p + 1)]; poly = []
        for i in range(NC // 8):
            b = a[3 * i:3 * i + 3]
            poly += [ETA - x for x in
                     (b[0] & 7, (b[0] >> 3) & 7, (b[0] >> 6) | ((b[1] << 2) & 7),
                      (b[1] >> 1) & 7, (b[1] >> 4) & 7, (b[1] >> 7) | ((b[2] << 1) & 7),
                      (b[2] >> 2) & 7, (b[2] >> 5) & 7)]
        S.append(poly)
    return np.array(S, float)


def matched_filter(c, z):
    """Negacyclic correlation of the sparse challenge c against each z poly --
    a c-aware statistic (the marginal of z is secret-independent by design, so a
    plain histogram sees nothing; this is what exposes the joint (c, z) law)."""
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


k0, k1 = make_key(b"secret-key-AAAA"), make_key(b"secret-key-BBBB")
messages = [f"msg-{i}".encode() for i in range(N)]


def collect(sk, nonce_seed):
    m.stub_randombytes(nonce_seed); hwm = m._alloc_ptr
    feats = []
    for msg in messages:
        m._alloc_ptr = hwm
        sig = scheme.sign(msg, sk)
        feats.append(matched_filter(challenge(sig[:CT]), unpack_z(sig)))
    return np.array(feats)


def leakage_test(tag):
    """Two-key distinguishability: per key, build a template from that key's
    signatures and classify each held-out signature by which template it scores
    higher on (leave-one-out, so every signature is a test point).  Uses only
    signatures + c (no public key, no secret).  50% == no leakage."""
    F0, F1 = collect(k0[1], b"nonce-stream-0"), collect(k1[1], b"nonce-stream-1")
    correct = total = 0
    for own, other in ((F0, F1), (F1, F0)):
        g_other = other.mean(0)
        for i in range(len(own)):
            g_own = (own.sum(0) - own[i]) / (len(own) - 1)   # leave sig i out
            correct += int(np.dot(own[i], g_own) > np.dot(own[i], g_other))
            total += 1
    acc = correct / total
    g0, g1 = F0.mean(0), F1.mean(0)
    # internal validation only: does each template align with that key's real s1?
    v0 = np.corrcoef(g0, unpack_s1(k0[1]).ravel())[0, 1]
    v1 = np.corrcoef(g1, unpack_s1(k1[1]).ravel())[0, 1]
    verdict = "LEAKAGE DETECTED" if acc > 0.75 else "no leakage"
    print(f"[{tag:8}] two-key classifier accuracy = {acc:5.0%}   -> {verdict}")
    print(f"           (validation: corr(template, true s1) = {v0:+.2f}, {v1:+.2f}"
          "  -- 0 means the output holds nothing about s1)")


print(f"{scheme.name}   leakage assessment: are 2 keys distinguishable from the output?\n")
leakage_test("golden")

# install the documented category-4.2 fault: skip the z = z + y masking add
m.hook_code(lambda mm, a, s: mm.set_pc(NONCE_ADD + 4),
            begin=NONCE_ADD, end=NONCE_ADD, precise=False)
leakage_test("z=z+y skip")

print("""
Reading it: golden signing hides the key -- two secrets produce output the test
can barely separate (accuracy near chance, template correlation with s1 ~ 0),
which is rejection sampling doing its job.  Skip the masking add and z = c*s1:
the output
now carries the secret directly, the two keys separate cleanly (~100%), and the
per-key template lines up with the real s1.  The detector flagged the leak from
the emitted signatures alone -- no key recovery, no public key, just the
leakage-assessment question "does the output depend on the secret it must hide".
Fault point and effect match Ravi et al. 2019 / ElGhamrawy 2023 (category 4.2).""")
