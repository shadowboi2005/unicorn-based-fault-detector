"""Render the intra-function skip results (example 10) as PNGs into plots/10/:

  intra_skip_accuracy.png  two-key accuracy per instruction-skip site inside
                           polyvecl_add (instruction-grained ALAFA, catalog 4.2)
  backend_cost.png         snapshot-resume vs m.call replay backends: time and
                           stored bytes per trial, against the full-signing cost
  rejection_flip.png       catalog 4.3: for each instruction of the r0 decision,
                           the fraction of out-of-spec r0 a skip wrongly accepts

    .venv/bin/python examples/plots/plot_10.py [firmware.elf] [n_per_key]
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
from ucpqc.replay import Recorder, Target, benchmark_backends, replay, skip_sweep
from ucpqc.detectors import matched_filter, two_key_accuracy

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 24
OUT = "examples/plots/10"
NC, L = 256, 4
POLYVECL = L * NC * 4
Q = 8380417
R0_BOUND = (Q - 1) // 88 - 78
R0_BL, R0_ACCEPT, R0_REJECT, BRANCH = 0x4dd8, 0x4de0, 0x4e86, 0x4dde

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


add_target = Target(func="pqcrystals_dilithium_polyvecl_add", nth=-1,
                    args=(("out", POLYVECL), ("in", POLYVECL), ("in", POLYVECL)),
                    out=0, label="polyvecl_add")
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
            cap.c = challenge(sig[:32])
            caps.append(cap)
    rec.detach()
    return caps


print(f"{scheme.name}  plotting intra-function skip results  N={N}/key -> {OUT}/")
capsA = collect(kA, b"nonce-A", "A")
capsB = collect(kB, b"nonce-B", "B")


def featurize(cap, out):
    return matched_filter(cap.c, unpack_vec(out))


def detect(feats):
    FA, FB = np.array(feats["A"]), np.array(feats["B"])
    if len(FA) < 3 or len(FB) < 3:
        return {"acc": None}
    return {"acc": two_key_accuracy(FA, FB)}


rows = skip_sweep(m, add_target, {"A": capsA, "B": capsB}, featurize, detect,
                  backend="call", persistent=True)

# ---- plot 1: instruction-grained accuracy bar chart -----------------------
labels, accs, colors = [], [], []
for r in rows:
    labels.append(f"{r['pc']:#06x}  {r['text']}")
    acc = r.get("acc")
    if not isinstance(acc, float):
        accs.append(0.0); colors.append("#bdbdbd")          # crash/hang
    else:
        accs.append(acc * 100)
        colors.append("#c44e52" if acc >= 0.80 else "#55a868")
fig, ax = plt.subplots(figsize=(9, 6))
y = np.arange(len(labels))[::-1]
ax.barh(y, accs, color=colors, edgecolor="white")
ax.axvline(80, color="#c44e52", ls="--", lw=1, label="leak threshold (80%)")
ax.axvline(50, color="#888888", ls=":", lw=1, label="chance (50%)")
for yi, r, a in zip(y, rows, accs):
    txt = "crash/hang" if not isinstance(r.get("acc"), float) else f"{a:.0f}%"
    ax.text(2, yi, txt, va="center", ha="left", fontsize=7.5,
            color="white" if a > 12 else "black")
ax.set_yticks(y); ax.set_yticklabels(labels, fontsize=7, family="monospace")
ax.set_xlim(0, 100); ax.set_xlabel("two-key classifier accuracy (%)")
ax.set_title(f"Instruction-skip sweep INSIDE polyvecl_add (z=z+y) — {scheme.name}\n"
             f"catalog 4.2; the bl-to-poly_add skip leaks like example 09 (N={N}/key)")
ax.legend(loc="lower right", fontsize=8)
fig.tight_layout()
fig.savefig(f"{OUT}/intra_skip_accuracy.png", dpi=130)
plt.close(fig)
print(f"  wrote {OUT}/intra_skip_accuracy.png")

# ---- plot 2: backend cost comparison --------------------------------------
fixture = collect(kA, b"nonce-bench", "A", snapshot=True)[0]
b = benchmark_backends(m, add_target, fixture, trials=100)
full_sign = 1_500_000
fig, (axt, axs) = plt.subplots(1, 2, figsize=(11, 4.2))
axt.bar(["snapshot\nresume", "m.call"],
        [b["snapshot"]["ms_per_trial"], b["call"]["ms_per_trial"]],
        color=["#4c72b0", "#55a868"])
axt.set_ylabel("ms / replay"); axt.set_title(
    f"replay cost per fault trial\n({b['insns_per_trial']:,} insns each, "
    f"vs ~{full_sign:,} for a full signing)")
for i, v in enumerate([b["snapshot"]["ms_per_trial"], b["call"]["ms_per_trial"]]):
    axt.text(i, v, f"{v:.2f} ms", ha="center", va="bottom", fontsize=9)
axs.bar(["snapshot\nresume", "m.call"],
        [b["stored_bytes"]["snapshot"], b["stored_bytes"]["call"]],
        color=["#4c72b0", "#55a868"])
axs.set_yscale("log"); axs.set_ylabel("bytes stored / capture (log)")
axs.set_title("capture storage per invocation")
for i, v in enumerate([b["stored_bytes"]["snapshot"], b["stored_bytes"]["call"]]):
    axs.text(i, v, f"{v:,} B", ha="center", va="bottom", fontsize=9)
fig.suptitle("Replay backends: m.call is faster and ~1000x smaller, but needs a "
             "function + arg spec;\nsnapshot works for any region (e.g. the 4.3 "
             "rejection decision). Outputs equivalent: "
             f"{b['equivalent']}", fontsize=10)
fig.tight_layout(rect=(0, 0, 1, 0.9))
fig.savefig(f"{OUT}/backend_cost.png", dpi=130)
plt.close(fig)
print(f"  wrote {OUT}/backend_cost.png")

# ---- plot 3: 4.3 rejection-decision flip map ------------------------------
r0caps, LIMIT = [], 20
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
n_oob = sum(c["oob"] for c in r0caps)


def decide(snap, skip_pc=None):
    m.restore(snap)
    where = [None]
    ha = m.hook_code(lambda mm, a, s: (where.__setitem__(0, "accept"), mm.uc.emu_stop()),
                     begin=R0_ACCEPT, end=R0_ACCEPT, precise=False)
    hr = m.hook_code(lambda mm, a, s: (where.__setitem__(0, "reject"), mm.uc.emu_stop()),
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


pcs, fracs, texts = [], [], []
pc = R0_BL
while pc < R0_ACCEPT + 2:
    _, size, text = m.disasm_one(pc)
    a = sum(decide(c["snap"], pc) == "accept" for c in r0caps if c["oob"])
    pcs.append(pc); texts.append(text)
    fracs.append(100.0 * a / max(n_oob, 1))
    pc += size or 2

fig, ax = plt.subplots(figsize=(8, 4.2))
x = np.arange(len(pcs))
cols = ["#c44e52" if p == BRANCH else "#4c72b0" for p in pcs]
ax.bar(x, fracs, color=cols, edgecolor="white")
ax.set_xticks(x)
ax.set_xticklabels([f"{p:#06x}\n{t}" for p, t in zip(pcs, texts)],
                   fontsize=7, family="monospace")
ax.set_ylabel("out-of-spec r0 wrongly ACCEPTED (%)")
ax.set_ylim(0, 105)
ax.set_title("catalog 4.3 — skipping each instruction of the r0 decision\n"
             f"only the reject branch (bne @ {BRANCH:#x}) bypasses the check "
             f"({n_oob} out-of-spec states)")
fig.tight_layout()
fig.savefig(f"{OUT}/rejection_flip.png", dpi=130)
plt.close(fig)
print(f"  wrote {OUT}/rejection_flip.png")
print("done.")
