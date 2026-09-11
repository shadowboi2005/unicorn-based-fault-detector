"""Intra-function instruction-skip faults via capture-and-replay.

Where example 09 sweeps *whole-call* skips (bl sites) across the signing loop,
this sweeps skips *inside* a chosen function, and does it cheaply: it captures
the target's I/O once per golden signing, then replays only that function per
fault trial instead of re-running the whole signature.

It reproduces cataloged attacks (../dilithium_fault_attacks.md):
  * 4.2 response computation  -- skips inside polyvecl_add (z = z + y); the
    two-key matched-filter detector must flag the same leak example 09 found.
  * 4.3 rejection bypass      -- region replay over the r0 decision; a skip of
    the reject branch wrongly accepts out-of-spec r0 ("Finding a Polytope").
Plus an A-vs-B replay-backend benchmark (snapshot resume vs m.call).

    .venv/bin/python examples/10_intra_function_skip.py [firmware.elf] [N]
"""
import struct
import sys

sys.path.insert(0, ".")

import numpy as np

from ucpqc import Machine, Scheme
from ucpqc.tracing import CallTracer
from ucpqc.faults import SKIP, FaultSpec, Injector
from ucpqc.replay import Recorder, Target, benchmark_backends, replay, skip_sweep
from ucpqc.detectors import matched, two_key_accuracy, band_count

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 16

NC, L, K = 256, 4, 4
POLYVECL = L * NC * 4
Q = 8380417
GAMMA2 = (Q - 1) // 88
R0_BOUND = GAMMA2 - 78          # gamma2 - beta, the r0 rejection bound

m = Machine.from_elf(ELF)
scheme = Scheme.bind(m)
m.boot()
cbuf = m.alloc(4 * NC)


def challenge(ct):
    m.call("pqcrystals_dilithium_poly_challenge", [cbuf, m.alloc_bytes(ct)])
    return np.array(struct.unpack(f"<{NC}i", m.read(cbuf, 4 * NC)), float)


def unpack_vec(buf):
    return np.array(struct.unpack(f"<{L * NC}i", buf), float).reshape(L, NC)


def make_key(seed):
    m.stub_randombytes(seed)
    return scheme.keypair()


# ======================================================================
# 0. Call graph -- the target-selection front end
# ======================================================================
print(f"{scheme.name}  intra-function skip tool   N={N}/key\n")
print("=" * 70)
print("call graph of one signing (pick a function to target):")
print("=" * 70)
_pk, _sk = make_key(b"graph-key")
m.stub_randombytes(b"graph-nonce")
ct = CallTracer(m, max_depth=3)
scheme.sign(b"graph", _sk)
ct.finish(); ct.detach()
print(ct.format(max_lines=22, min_cost=20_000))


# ======================================================================
# 1. Primary demo -- 4.2 response computation, skips inside polyvecl_add
# ======================================================================
add_target = Target(func="pqcrystals_dilithium_polyvecl_add", nth=-1,
                    args=(("out", POLYVECL), ("in", POLYVECL), ("in", POLYVECL)),
                    out=0, label="polyvecl_add (z = z + y)")

kA = make_key(b"secret-key-AAAA")[1]
kB = make_key(b"secret-key-BBBB")[1]
messages = [f"msg-{i}".encode() for i in range(N)]


def collect(sk, nonce, key, snapshot=False):
    m.stub_randombytes(nonce)
    hwm = m._alloc_ptr
    rec = Recorder(m, add_target, snapshot=snapshot)
    caps = []
    for msg in messages:
        m._alloc_ptr = hwm
        rec.arm()
        sig = scheme.sign(msg, sk)
        cap = rec.take(key)
        if cap is not None:
            cap.c = challenge(sig[:32])         # the challenge for this signature
            caps.append(cap)
    rec.detach()
    return caps


capsA = collect(kA, b"nonce-A", "A")
capsB = collect(kB, b"nonce-B", "B")

# correctness self-test: no-fault replay must reproduce the golden output
bad = sum(replay(m, add_target, c, None, "call") != c.golden_output
          for c in capsA + capsB)
print("\n" + "=" * 70)
print(f"4.2  response computation -- skips inside {add_target.label}")
print("=" * 70)
print(f"captured A={len(capsA)} B={len(capsB)}   "
      f"no-fault replay==golden: {'OK' if bad == 0 else f'{bad} MISMATCH'}")


def featurize(cap, out):
    return matched(cap.c, unpack_vec(out))


def detect(feats):
    FA, FB = np.array(feats["A"]), np.array(feats["B"])
    if len(FA) < 3 or len(FB) < 3:
        return {"acc": None}
    return {"acc": two_key_accuracy(FA, FB)}


rows = skip_sweep(m, add_target, {"A": capsA, "B": capsB}, featurize, detect,
                  backend="call", persistent=True)
print(f"\n  {'pc':>7}  {'instruction':<26} {'ran':>3} {'crash':>5}  two-key")
for r in rows:
    acc = r.get("acc")
    flag = ""
    if isinstance(acc, float):
        accs = f"{acc:4.0%}"
        if acc >= 0.80:
            flag = "  <- LEAK"
    else:
        accs = " -- "
    print(f"  {r['pc']:#07x}  {r['text']:<26} {r['ran']:>3} {r['crashed']:>5}   {accs}{flag}")
leak_pcs = [r["pc"] for r in rows if isinstance(r.get("acc"), float) and r["acc"] >= 0.80]
print(f"\n  -> {len(leak_pcs)} skip site(s) leak; the bl-to-poly_add skip "
      f"reproduces example 09's z=z+y (two-key 100%).")


# ======================================================================
# 2. Replay-backend benchmark (snapshot resume vs m.call), on one capture
# ======================================================================
print("\n" + "=" * 70)
print("replay-backend benchmark (snapshot vs call), one polyvecl_add capture")
print("=" * 70)
fixture = collect(kA, b"nonce-bench", "A", snapshot=True)[0]
b = benchmark_backends(m, add_target, fixture, trials=100)
print(f"  {b['insns_per_trial']:,} instructions/trial (same code either way)")
print(f"  snapshot : {b['snapshot']['ms_per_trial']:6.3f} ms/trial   "
      f"stored {b['stored_bytes']['snapshot']:>10,} B/capture")
print(f"  call     : {b['call']['ms_per_trial']:6.3f} ms/trial   "
      f"stored {b['stored_bytes']['call']:>10,} B/capture")
print(f"  outputs equivalent: {b['equivalent']}   "
      f"(a full signing is ~1.5M insns -- replay is ~{1_500_000 // b['insns_per_trial']}x cheaper)")


# ======================================================================
# 3. 4.3 rejection bypass -- region replay over the r0 decision
# ======================================================================
# r0 check control flow (from disassembly):
#   4dd8 bl poly_chknorm ; 4ddc cmp r0,#0 ; 4dde bne 4e86 (reject) ; 4de0 accept
R0_BL, R0_ACCEPT, R0_REJECT = 0x4dd8, 0x4de0, 0x4e86
BRANCH = 0x4dde                 # the reject branch -- the load-bearing instruction
print("\n" + "=" * 70)
print("4.3  rejection bypass -- region replay over the r0 decision (0x4dd8)")
print("=" * 70)

# capture r0-check states (snapshot + whether the r0 is out-of-spec), a mix of
# in-spec (would accept) and out-of-spec (would reject) ones.
r0caps, LIMIT = [], 16
hwm = m._alloc_ptr


def on_r0(mm, addr, size):
    if len(r0caps) >= LIMIT:
        return
    coeffs = np.frombuffer(mm.read(mm.reg("r0"), 4 * NC), dtype="<i4")
    r0caps.append({"snap": mm.snapshot(),
                   "oob": int(np.abs(coeffs).max() >= R0_BOUND)})


h = m.hook_code(on_r0, begin=R0_BL, end=R0_BL, precise=False)
m.stub_randombytes(b"r0-nonce")
for msg in messages:
    if len(r0caps) >= LIMIT:
        break
    m._alloc_ptr = hwm
    scheme.sign(msg, kA)
m.uc.hook_del(h); m.uc.ctl_flush_tb()


def decide(snap, skip_pc=None):
    """Replay just the r0 decision from the captured state; return which branch
    target is reached first: 'accept' (fell through) or 'reject' (branched)."""
    m.restore(snap)
    where = [None]

    def hit_accept(mm, a, s):
        where[0] = "accept"; mm.uc.emu_stop()

    def hit_reject(mm, a, s):
        where[0] = "reject"; mm.uc.emu_stop()

    ha = m.hook_code(hit_accept, begin=R0_ACCEPT, end=R0_ACCEPT, precise=False)
    hr = m.hook_code(hit_reject, begin=R0_REJECT, end=R0_REJECT, precise=False)
    inj = Injector(m, FaultSpec(kind=SKIP, pc=skip_pc, hit=0)) if skip_pc else None
    try:
        m._emu_start(R0_BL | 1, 0, count=50_000)
    except Exception:
        pass
    finally:
        m.uc.hook_del(ha); m.uc.hook_del(hr); m.uc.ctl_flush_tb()
        if inj:
            inj.detach()
    return where[0]


n_oob = sum(c["oob"] for c in r0caps)
print(f"  captured {len(r0caps)} r0-check states "
      f"({n_oob} out-of-spec: |r0|>=gamma2-beta={R0_BOUND})")

# golden: chknorm's verdict should reject exactly the out-of-spec ones
g_reject = sum(decide(c["snap"]) == "reject" for c in r0caps)
# fault: skip the reject branch -> everything falls through to accept
f_accept_oob = sum(decide(c["snap"], BRANCH) == "accept"
                   for c in r0caps if c["oob"])
print(f"  golden           : rejects {g_reject}/{len(r0caps)} "
      f"(= the {n_oob} out-of-spec + margin)")
print(f"  skip bne @ {BRANCH:#x} : {f_accept_oob}/{n_oob} out-of-spec r0 now ACCEPTED"
      f" -> released though they should reject")

# which single instruction of the decision is load-bearing?
print(f"\n  {'skip pc':>8}  {'instruction':<22} {'oob->accept':>12}")
pc = R0_BL
while pc < R0_ACCEPT + 2:
    _, size, text = m.disasm_one(pc)
    a = sum(decide(c["snap"], pc) == "accept" for c in r0caps if c["oob"])
    print(f"  {pc:#08x}  {text:<22} {a:>8}/{n_oob}")
    pc += size or 2
print("  -> only skipping the reject branch bypasses the check; those wrongly-"
      "\n     released out-of-spec r0 are the polytope attack's input (example 08).")
