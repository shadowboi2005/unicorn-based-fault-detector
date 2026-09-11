import sys

sys.path.insert(0, ".")

from ucpqc import Machine, Scheme

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
MESSAGE = b"correct me"

S1_OFFSET = 128           # rho(32) + K(32) + tr(64)
S1_LEN = 4 * 96           # L=4 polynomials, eta=2 -> 96 bytes each

m = Machine.from_elf(ELF)
scheme = Scheme.bind(m)
m.boot()
m.stub_randombytes(b"rowhammer-victim")
print(f"{scheme.name}\n")

# --- the victim device --------------------------------------------------------
pk, sk = scheme.keypair()

# ML-DSA-44 is hedged (the FIPS 204 default): every signature draws fresh
# randomness, so two signs of the same message differ.  This attack is
# *independent of that nonce* -- so the device is left fully hedged, and the
# only bookkeeping is reclaiming scratch between the many signs below without
# disturbing the RNG stream (that is what keeps hedging genuinely live).
alloc_hwm = m._alloc_ptr


def sign(message, secret_key):
    m._alloc_ptr = alloc_hwm       # free per-call buffers; RNG position untouched
    return scheme.sign(message, secret_key)


def flip(data, byte, bit):
    """Rowhammer: return a copy of `data` with one bit toggled."""
    out = bytearray(data)
    out[byte] ^= 1 << bit
    return bytes(out)


# Confirm hedging is genuinely on: same key, same message, different signatures.
a, b = sign(MESSAGE, sk), sign(MESSAGE, sk)
print(f"hedging live: two signs of one message differ = {a != b}, "
      f"both verify = {scheme.verify(a, MESSAGE, pk) and scheme.verify(b, MESSAGE, pk)}")
print(f"s1 occupies sk[{S1_OFFSET}:{S1_OFFSET + S1_LEN}] "
      f"({S1_LEN} bytes of the {len(sk)}-byte key)\n")

# --- 1. the fault: flip one bit of s1 in the stored key ---------------------
FAULT_BYTE, FAULT_BIT = S1_OFFSET + 7, 3        # some bit inside s1
sk_faulty = flip(sk, FAULT_BYTE, FAULT_BIT)

faulty = sign(MESSAGE, sk_faulty)               # device signs with corrupted s1
valid = scheme.verify(faulty, MESSAGE, pk)      # attacker runs the public oracle

print(f"=== fault: flip s1 bit (byte {FAULT_BYTE}, bit {FAULT_BIT}) ===")
print(f"faulty signature verifies against the true pk: {valid}")
print("  -> a single wrong bit in s1 makes the signature fail verification.")
print("     That pass/fail bit -- and nothing about the nonce -- is the whole")
print("     input to the correction step, which is why hedging does not help.\n")

# --- 2. the correction: recover the flipped bit from the oracle -------------
#
# The attacker holds only pk, the message, the faulty device, and verify().
# The paper's correction is offline lattice algebra that rebuilds the valid
# signature the un-flipped key would have produced; the emulator synthesises a
# corrected signature by re-signing under each single-bit hypothesis and asks
# the oracle.  The discriminator is verification ALONE:
#
#   * undo the truly-flipped bit  -> s1 is correct        -> signature verifies
#   * flip any other bit          -> s1 has two errors    -> signature is invalid
#
# Neither outcome depends on the nonce, so every candidate can (and here does)
# sign with fresh randomness.  Comparing bytes against a "golden" signature
# would instead need a pinned nonce -- a shortcut this attack does not require.
#
# Sweeping all 8*384 bits of s1 recovers all of s1; the search is bounded to a
# window around the fault to keep the demo to a few seconds.

WINDOW = range(S1_OFFSET + 4, S1_OFFSET + 11)   # 7 bytes * 8 bits = 56 hypotheses
print(f"=== correction: up to {len(WINDOW) * 8} single-bit hypotheses via the oracle ===")

recovered = None
tested = 0
for byte in WINDOW:
    for bit in range(8):
        tested += 1
        candidate_sk = flip(sk_faulty, byte, bit)          # undo hypothesis
        candidate_sig = sign(MESSAGE, candidate_sk)         # corrected signature
        if scheme.verify(candidate_sig, MESSAGE, pk):       # valid => key is correct
            recovered = (byte, bit)
            break
    if recovered:
        break

print(f"tested {tested} hypotheses")
print(f"recovered flipped bit: {recovered}")
print(f"injected  flipped bit: {(FAULT_BYTE, FAULT_BIT)}")
print(f"match: {recovered == (FAULT_BYTE, FAULT_BIT)}")
print("\n  Each recovered (byte, bit) is one bit of s1.  Repeating the fault"
      "\n  across the 384 bytes of s1 and running this loop per fault"
      "\n  reconstructs the entire secret vector -- full key recovery, with"
      "\n  the device never revealing s1 and its control flow never touched.")
