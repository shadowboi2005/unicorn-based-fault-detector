#!/usr/bin/env python3
"""Infer a `ucpqc.replay.Target` for a function automatically.

STANDALONE / OPT-IN: this is *not* imported by the framework.  It exists so you
can decide later whether to fold auto-inference into `AnalysisProfile.targets()`.

Two sources, combined and cross-checked:

  * runtime footprint -- watch one real invocation's memory accesses relative to
    its argument registers (works because the functions are pure: the arg-pointed
    regions fully capture the I/O).  Gives pointer roles, sizes, and *in-place
    aliasing*.
  * the C prototype (optional, --src) -- gives the exact arg count, `const`->input
    roles, and struct sizes.  Resolves the one thing the footprint can't:
    scalar-arg vs unused-register.

The inferred Target is then **validated**: capture one invocation and replay it
with no fault; if the replayed output equals the golden output, the Target is
correct (for replay), regardless of how it was guessed.

    python tools/probe_target.py firmware/ml-dsa-44_m4f_test.elf \
        pqcrystals_dilithium_polyvecl_add --src ../pqm4/crypto_sign/ml-dsa-44
"""

import bisect
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ucpqc import Machine, Scheme
from ucpqc.replay import Recorder, Target, replay
from ucpqc.tracing import Trigger

# struct -> byte size for ML-DSA (extend per scheme as needed)
C_TYPE_SIZES = {"poly": 1024, "polyvecl": 4096, "polyveck": 4096}


# --------------------------------------------------------------------------
# 1. runtime footprint of the last invocation
# --------------------------------------------------------------------------
def probe_footprint(scheme, func, message=b"probe"):
    """Return (entry_regs r0-r3, accesses [(is_write, addr, size)]) for the last
    invocation of `func` during one signing."""
    m = scheme.machine
    state = {"regs": None, "acc": None, "on": False}
    last = {}

    def on_arm(mm):
        state["regs"] = {i: mm.reg(f"r{i}") for i in range(4)}
        state["acc"] = []
        state["on"] = True

    def on_disarm(mm):
        state["on"] = False
        last["regs"], last["acc"] = state["regs"], state["acc"]

    # one mem hook for the whole run, gated by the trigger window (the stable
    # MemoryTracer pattern -- adding/removing a hook inside a hook callback is
    # not safe in Unicorn)
    memh = m.hook_mem(
        lambda machine, w, a, s, v: state["acc"].append((bool(w), a, s)) if state["on"] else None,
        read=True, write=True)
    trig = Trigger(m, func, on_arm=on_arm, on_disarm=on_disarm)
    m.stub_randombytes(b"probe-key"); pk, sk = scheme.keypair()
    m.stub_randombytes(b"probe-nonce"); scheme.sign(message, sk)
    trig.detach(); m.unhook(memh)
    if not last:
        raise SystemExit(f"{func} was never called during signing")
    return last["regs"], last["acc"]


def infer_from_footprint(regs, acc):
    """Cluster accesses by arg pointer (nearest preceding base) and classify.
    Returns (args tuple over r0-r3, out) in ucpqc.replay.Target form."""
    lo = min(a for _, a, _ in acc)
    hi = max(a + s for _, a, s in acc)
    # a register is a pointer arg iff its value is the base of accessed memory
    cand = {i: regs[i] for i in range(4) if lo - 4 <= regs[i] <= hi}
    bases = sorted(set(cand.values()))
    region = {b: {"size": 0, "r": False, "w": False} for b in bases}
    for w, a, s in acc:
        idx = bisect.bisect_right(bases, a) - 1
        if idx < 0:
            continue
        b = bases[idx]
        nxt = bases[idx + 1] if idx + 1 < len(bases) else hi
        if a >= nxt:
            continue
        reg = region[b]
        reg["size"] = max(reg["size"], min(a + s, nxt) - b)
        reg["w"] |= w; reg["r"] |= (not w)

    # written region (lowest base) is the output; else the return value is
    written = [b for b in bases if region[b]["w"]]
    out_base = min(written) if written else None
    args, out = [], "ret"
    for i in range(4):
        if i not in cand:
            args.append("scalar"); continue
        b = cand[i]; reg = region[b]
        size = (reg["size"] + 3) & ~3
        # the output arg: written; if also read it is in-place -> capture as "in"
        if b == out_base and out == "ret":
            out = i
            args.append(("in", size) if reg["r"] else ("out", size))
        else:
            args.append(("in", size))          # read-only, or an in-place alias
    return tuple(args), out


# --------------------------------------------------------------------------
# 2. optional: the C prototype
# --------------------------------------------------------------------------
def prototype_from_c(func, src_dirs):
    """Best-effort: find `func`'s C prototype and return (raw, [(role, size|None)]).
    role is 'in'/'out' from const-ness; size from the struct type if known."""
    names = {func, func.replace("pqcrystals_dilithium_", "")}
    pat = re.compile(r"\b(?:void|int|unsigned|int32_t)\s+(\w+)\s*\(([^;{]*)\)")
    for d in src_dirs:
        for path in glob.glob(os.path.join(d, "**", "*.[ch]"), recursive=True):
            try:
                text = open(path, errors="ignore").read()
            except OSError:
                continue
            for mobj in pat.finditer(text):
                if mobj.group(1) not in names:          # exact match only
                    continue
                raw = f"{mobj.group(1)}({mobj.group(2).strip()})"
                specs = []
                for arg in mobj.group(2).split(","):
                    arg = arg.strip()
                    if not arg or arg == "void":
                        continue
                    is_ptr = "*" in arg or "[" in arg
                    if not is_ptr:
                        specs.append(("scalar", None)); continue
                    role = "in" if "const" in arg else "out"
                    ctype = next((t for t in C_TYPE_SIZES if t in arg), None)
                    specs.append((role, C_TYPE_SIZES.get(ctype)))
                return raw, specs
    return None, None


# --------------------------------------------------------------------------
# 3. validate the inferred Target by replay == golden
# --------------------------------------------------------------------------
def validate(scheme, target):
    m = scheme.machine
    m.stub_randombytes(b"val-key"); pk, sk = scheme.keypair()
    m.stub_randombytes(b"val-nonce")
    rec = Recorder(m, target, snapshot=False)
    mark = m.scratch_mark()
    cap = None
    for i in range(3):
        m.scratch_reset(mark); rec.arm()
        scheme.sign(f"v{i}".encode(), sk)
        c = rec.take("v")
        if c is not None:
            cap = c
    rec.detach()
    if cap is None:
        return None
    out = replay(m, target, cap, None, "call")
    return out == cap.golden_output


# --------------------------------------------------------------------------
def main(argv):
    if len(argv) < 2:
        print(__doc__); return 2
    elf, func = argv[0], argv[1]
    src = []
    if "--src" in argv:
        src = [argv[argv.index("--src") + 1]]

    m = Machine.from_elf(elf); scheme = Scheme.bind(m); m.boot()
    regs, acc = probe_footprint(scheme, func)
    foot_args, foot_out = infer_from_footprint(regs, acc)
    aliases = [i for i in range(4) if isinstance(foot_args[i], tuple)
               and regs[i] in {regs[j] for j in range(i)}]

    print(f"{scheme.name}  {func}")
    print(f"  entry regs:  " + "  ".join(f"r{i}={regs[i]:#010x}" for i in range(4)))
    print(f"  accesses:    {len(acc)}  ({sum(w for w, _, _ in acc)} writes)")
    print(f"  footprint:   args={foot_args}  out={foot_out}")
    if aliases:
        print(f"  in-place:    r{aliases} share a pointer with an earlier arg")

    args, out = foot_args, foot_out
    if src:
        raw, specs = prototype_from_c(func, src)
        if raw:
            print(f"  C prototype: {raw}")
            # combine: C fixes the arg COUNT and scalar/pointer classification;
            # footprint keeps sizes + in-place roles.
            args = []
            for i, (crole, csize) in enumerate(specs):
                if crole == "scalar":
                    args.append("scalar")
                else:
                    fa = foot_args[i] if i < len(foot_args) and isinstance(foot_args[i], tuple) else None
                    size = (fa[1] if fa and fa[1] else csize) or 0
                    args.append((fa[0] if fa else crole, size))
            args = tuple(args)
            out = foot_out if isinstance(foot_out, int) and foot_out < len(specs) else "ret"
            print(f"  combined:    args={args}  out={out}")
        else:
            print(f"  C prototype: not found under {src[0]} (asm or namespaced?)")

    target = Target(func=func, nth=-1, args=args, out=out, label=func)
    ok = validate(scheme, target)
    verdict = {True: "OK -- replay == golden", False: "MISMATCH", None: "n/a"}[ok]
    print(f"  validation: {verdict}")
    print(f"\n  Target(func={func!r}, nth=-1, args={args}, out={out!r})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
