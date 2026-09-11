"""How many instructions does each key function have, and how many, when
skipped, flag as a leak?  Sweeps a few z-path functions and renders
examples/plots/10/function_flag_rates.png plus a printed table.

    .venv/bin/python examples/plots/plot_10_functions.py [firmware.elf] [n_per_key]
"""
import struct
import sys

sys.path.insert(0, ".")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from ucpqc import Machine, Scheme
from ucpqc.faults import SKIP, FaultSpec, Injector
from ucpqc.replay import Recorder, Target, replay, skip_sweep
from ucpqc.detectors import matched_filter, two_key_accuracy

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 24
OUT = "examples/plots/10"
NC, L = 256, 4
PV = L * NC * 4                      # polyvecl buffer bytes
PP = NC * 4                          # single poly buffer bytes

m = Machine.from_elf(ELF); scheme = Scheme.bind(m); m.boot()
cbuf = m.alloc(4 * NC)


def challenge(ct):
    m.call("pqcrystals_dilithium_poly_challenge", [cbuf, m.alloc_bytes(ct)])
    return np.array(struct.unpack(f"<{NC}i", m.read(cbuf, 4 * NC)), float)


def mk(seed):
    m.stub_randombytes(seed); return scheme.keypair()[1]


kA, kB = mk(b"secret-key-AAAA"), mk(b"secret-key-BBBB")
messages = [f"msg-{i}".encode() for i in range(N)]

# z-path functions whose (golden) output should be secret-INDEPENDENT (masked),
# so the two-key detector is meaningful.  (out arg index, per-arg spec, ncoeffs)
FUNCS = [
    ("polyvecl_add",
     Target(func="pqcrystals_dilithium_polyvecl_add", nth=-1,
            args=(("out", PV), ("in", PV), ("in", PV)), out=0), L, "4.2 z=z+y"),
    ("polyvecl_reduce",
     Target(func="pqcrystals_dilithium_polyvecl_reduce", nth=-1,
            args=(("in", PV),), out=0), L, "control"),
]


def collect(sk, nonce, key, target):
    m.stub_randombytes(nonce); hwm = m._alloc_ptr
    rec = Recorder(m, target, snapshot=False); caps = []
    for msg in messages:
        m._alloc_ptr = hwm; rec.arm(); sig = scheme.sign(msg, sk)
        c = rec.take(key)
        if c is not None:
            c.c = challenge(sig[:32]); caps.append(c)
    rec.detach(); return caps


def make_featurize(nc_rows):
    def fz(cap, out):
        z = np.array(struct.unpack(f"<{nc_rows * NC}i", out), float).reshape(nc_rows, NC)
        return matched_filter(cap.c, z)
    return fz


print(f"{scheme.name}  per-function flag rates  N={N}/key\n")
# summary rows: (label, detector, total_insns, leak, ok, crash, golden_acc_or_None)
summary = []
for short, target, rows, cat in FUNCS:
    caps = {"A": collect(kA, b"nA", "A", target), "B": collect(kB, b"nB", "B", target)}
    fz = make_featurize(rows)
    gA = np.array([fz(c, c.golden_output) for c in caps["A"]])
    gB = np.array([fz(c, c.golden_output) for c in caps["B"]])
    golden_acc = two_key_accuracy(gA, gB)          # must be ~chance for a valid target

    def detect(feats):
        FA, FB = np.array(feats["A"]), np.array(feats["B"])
        if len(FA) < 3 or len(FB) < 3:
            return {"acc": None}
        return {"acc": two_key_accuracy(FA, FB)}

    rowsout = skip_sweep(m, target, caps, fz, detect, backend="call", persistent=True)
    total = len(rowsout)
    leak = sum(isinstance(r.get("acc"), float) and r["acc"] >= 0.80 for r in rowsout)
    crash = sum(not isinstance(r.get("acc"), float) for r in rowsout)
    summary.append((f"{short}\n({cat})", "two-key", total, leak, total - leak - crash,
                    crash, golden_acc))
    print(f"  {short:<18} [{cat:<8}] insns={total:>3} golden2key={golden_acc:4.0%} "
          f"LEAK={leak:>2} crash={crash:>2} flagged={leak/total:5.1%}")

# --- r0 decision REGION (catalog 4.3): accept-flip detector on out-of-spec r0 ---
R0_BL, R0_ACCEPT, R0_REJECT, BRANCH = 0x4dd8, 0x4de0, 0x4e86, 0x4dde
r0caps, LIMIT = [], 16
hwm = m._alloc_ptr


def on_r0(mm, a, s):
    if len(r0caps) >= LIMIT:
        return
    coeffs = np.frombuffer(mm.read(mm.reg("r0"), 4 * NC), dtype="<i4")
    Q = 8380417
    r0caps.append({"snap": mm.snapshot(),
                   "oob": int(np.abs(coeffs).max() >= (Q - 1) // 88 - 78)})


h = m.hook_code(on_r0, begin=R0_BL, end=R0_BL, precise=False)
m.stub_randombytes(b"r0-nonce")
for msg in messages:
    if len(r0caps) >= LIMIT:
        break
    m._alloc_ptr = hwm
    scheme.sign(msg, kA)
m.uc.hook_del(h); m.uc.ctl_flush_tb()
n_oob = sum(c["oob"] for c in r0caps)


def decide(snap, skip_pc=None):
    m.restore(snap); where = [None]
    ha = m.hook_code(lambda mm, a, s: (where.__setitem__(0, "A"), mm.uc.emu_stop()),
                     begin=R0_ACCEPT, end=R0_ACCEPT, precise=False)
    hr = m.hook_code(lambda mm, a, s: (where.__setitem__(0, "R"), mm.uc.emu_stop()),
                     begin=R0_REJECT, end=R0_REJECT, precise=False)
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


reg_total = reg_leak = 0
pc = R0_BL
while pc < R0_ACCEPT + 2:
    _, size, _ = m.disasm_one(pc)
    reg_total += 1
    flips = sum(decide(c["snap"], pc) == "A" for c in r0caps if c["oob"])
    if n_oob and flips == n_oob:            # this skip accepts ALL out-of-spec r0
        reg_leak += 1
    pc += size or 2
summary.append((f"r0 decision region\n(4.3 bypass)", "accept-flip",
                reg_total, reg_leak, reg_total - reg_leak, 0, None))
print(f"  r0 region        [4.3     ] insns={reg_total:>3} (branch flips {n_oob} oob) "
      f"LEAK={reg_leak:>2} flagged={reg_leak/reg_total:5.1%}")

# ---- graph ----------------------------------------------------------------
# summary tuple: (label, detector, total, leak, ok, crash, golden_or_None)
fig, (axc, axr) = plt.subplots(1, 2, figsize=(13, 4.8))
names = [s[0] for s in summary]
y = np.arange(len(names))[::-1]
leak = np.array([s[3] for s in summary])
ok = np.array([s[4] for s in summary])
crash = np.array([s[5] for s in summary])
axc.barh(y, leak, color="#c44e52", label="LEAK (flagged)")
axc.barh(y, ok, left=leak, color="#55a868", label="ran, no leak")
axc.barh(y, crash, left=leak + ok, color="#bdbdbd", label="crash/hang")
for yi, s in zip(y, summary):
    tag = f"{s[2]} insns  ·  {s[1]}"
    if s[6] is not None:
        tag += f"  ·  golden {s[6]:.0%}"
    axc.text(s[2] + 0.2, yi, tag, va="center", fontsize=8)
axc.set_yticks(y); axc.set_yticklabels(names, fontsize=8)
axc.set_xlim(0, max(s[2] for s in summary) + 7)
axc.set_xlabel("instructions in function / region")
axc.set_title("Instruction-skip outcome per target")
axc.legend(fontsize=8, loc="lower right")

frac = [s[3] / s[2] * 100 for s in summary]
axr.barh(y, frac, color=["#c44e52" if f > 0 else "#bdbdbd" for f in frac])
for yi, f, s in zip(y, frac, summary):
    axr.text(f + 0.5, yi, f"{s[3]}/{s[2]} = {f:.0f}%", va="center", fontsize=8)
axr.set_yticks(y); axr.set_yticklabels(names, fontsize=8)
axr.set_xlim(0, max(frac) * 1.5 + 5)
axr.set_xlabel("% of instructions flagged as leak")
axr.set_title("Flagged fraction per target")
fig.suptitle(f"Intra-function skip flag rates (ml-dsa-44, N={N}/key)\n"
             "leak targets localize to a couple of instructions; the control "
             "flags none", fontsize=11)
fig.tight_layout(rect=(0, 0, 1, 0.9))
fig.savefig(f"{OUT}/function_flag_rates.png", dpi=130)
print(f"\nwrote {OUT}/function_flag_rates.png")

# emit a markdown table fragment for bookkeeping
print("\n--- markdown ---")
print("| target | catalog | detector | instructions | flagged | golden 2-key |")
print("|---|---|---|---|---|---|")
for s in summary:
    label = s[0].replace("\n", " ")
    gold = "n/a" if s[6] is None else f"{s[6]:.0%}"
    print(f"| `{label}` | — | {s[1]} | {s[2]} | {s[3]} | {gold} |")
