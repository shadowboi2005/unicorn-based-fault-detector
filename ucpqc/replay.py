"""Capture a function/region's I/O during golden signings, then replay just that
target in isolation under instruction-skip faults -- without re-running the whole
program.

Motivation: a full ML-DSA signing is ~1.5M+ instructions (with retries), so
sweeping hundreds of instruction-skip sites x N messages x 2 keys by re-signing
each time is prohibitive.  Instead we capture the target's entry state once per
golden signing, then replay only the target (a few thousand instructions) per
fault trial.

Two replay backends (benchmark them; pick per situation):
  * snapshot  -- restore full machine state, resume from entry PC to the captured
                 return/end PC.  Works for ANY code region and any function; the
                 restored memory keeps every input in place.  (Backend A.)
  * call      -- rebuild the call from captured args on a fresh stack via
                 Machine.call.  Cheap storage, but needs the arg signature and
                 relocates input buffers (Machine.call's stack would otherwise
                 overlap the captured stack addresses).  Functions only.  (B.)

Built on: ucpqc.tracing.Trigger (entry/return boundaries), ucpqc.faults.Injector
(the SKIP fault, which disassembles for 2/4-byte width) and its
sweep_function_body, Machine.snapshot/restore/call/_emu_start.
"""

import time
from dataclasses import dataclass, field

from .faults import SKIP, FaultSpec, Injector, sweep_function_body
from .machine import EmulationError
from .tracing import Trigger

__all__ = [
    "Target", "Capture", "Recorder", "replay", "skip_sweep",
    "benchmark_backends",
]


# --------------------------------------------------------------------------
# target description
# --------------------------------------------------------------------------
@dataclass
class Target:
    """What to capture and replay.

    `func`  -- function symbol/address (the standard case), OR
    `region`-- (start_pc, end_pc) for an inline code region (snapshot backend
               only; e.g. the rejection decision, which is not a function).
    `nth`   -- which invocation within one signing to capture: k (1-based), or
               -1 for the last (e.g. the accepting iteration's).
    `args`  -- per-argument spec over r0, r1, ...: "scalar" | ("in", nbytes) |
               ("out", nbytes).  Needed for the `call` backend and to know the
               output buffer.  Empty => output is the return value.
    `out`   -- "ret" (return value) or an argument index whose buffer is the
               output.
    """
    func: object = None
    region: tuple = None
    nth: int = -1
    args: tuple = ()
    out: object = "ret"
    label: str = ""

    def out_size(self):
        return 0 if self.out == "ret" else int(self.args[self.out][1])

    @property
    def name(self):
        return self.label or (str(self.func) if self.func is not None
                              else f"region{self.region}")


@dataclass
class Capture:
    """One captured invocation's I/O, enough to replay it either way."""
    key: str
    entry: int
    ret: int                       # return PC (function) or end_pc (region)
    regs: dict = field(default_factory=dict)     # r0..r3, sp, lr at entry
    out_ptr: int = 0               # output buffer address (from the out arg reg)
    inputs: dict = field(default_factory=dict)   # {arg_index: bytes} for ("in")
    scalars: dict = field(default_factory=dict)  # {arg_index: value} for scalars
    snap: object = None            # Machine.Snapshot (backend A)
    golden_output: object = None   # bytes (buffer) or int (return value)


# --------------------------------------------------------------------------
# recorder -- capture the target's I/O across golden signings
# --------------------------------------------------------------------------
class Recorder:
    """Install capture hooks on a target; the caller drives the signings.

        rec = Recorder(m, target)
        mark = m.scratch_mark()
        for msg in messages:
            m.scratch_reset(mark)        # free the previous signing's buffers
            rec.arm()
            scheme.sign(msg, sk)
            cap = rec.take(key)          # the nth invocation's Capture, or None
            if cap: captures.append(cap)
        rec.detach()
    """

    def __init__(self, machine, target, snapshot=True, snapshot_regions=None):
        self.machine = machine
        self.target = target
        self._want_snap = snapshot
        self._regions = snapshot_regions
        self._count = 0
        self._pending = None
        self._result = None
        if target.func is not None:
            self.entry = machine.addr_of(target.func)
            self._trig = Trigger(machine, target.func, nth=0,
                                 on_arm=self._on_arm, on_disarm=self._on_disarm)
            self._region_hooks = None
        else:
            start, end = target.region
            self.entry, self._end = start, end
            self._trig = None
            self._region_hooks = (
                machine.hook_code(self._on_region_start, begin=start, end=start,
                                  precise=False),
                machine.hook_code(self._on_region_end, begin=end, end=end,
                                  precise=False),
            )

    # -- function target ----------------------------------------------------
    def _is_target(self, count):
        return self.target.nth == -1 or count == self.target.nth

    def _grab_entry(self, mm, ret):
        cap = Capture(key=None, entry=self.entry, ret=ret)
        cap.regs = {r: mm.reg(r) for r in ("r0", "r1", "r2", "r3", "sp", "lr")}
        for i, spec in enumerate(self.target.args):
            regval = cap.regs[f"r{i}"]
            if spec == "scalar":
                cap.scalars[i] = regval
            elif spec[0] == "in":
                cap.inputs[i] = mm.read(regval, spec[1])
            # ("out", n): nothing to read at entry
        if self.target.out != "ret":
            cap.out_ptr = cap.regs[f"r{self.target.out}"]
        if self._want_snap:
            cap.snap = (mm.snapshot(self._regions) if self._regions
                        else mm.snapshot())
        return cap

    def _finish_output(self, mm, cap):
        if self.target.out == "ret":
            cap.golden_output = mm.reg("r0")
        else:
            cap.golden_output = mm.read(cap.out_ptr, self.target.out_size())

    def _on_arm(self, mm):
        self._count += 1
        if self._is_target(self._count):
            self._pending = self._grab_entry(mm, self._trig._ret)

    def _on_disarm(self, mm):
        if self._pending is not None:
            self._finish_output(mm, self._pending)
            self._result = self._pending           # last target wins (nth=-1)
            self._pending = None

    # -- region target (backend A only) -------------------------------------
    def _on_region_start(self, mm, addr, size):
        self._count += 1
        if self._is_target(self._count):
            self._pending = self._grab_entry(mm, self._end)

    def _on_region_end(self, mm, addr, size):
        if self._pending is not None:
            self._finish_output(mm, self._pending)
            self._result = self._pending
            self._pending = None

    # -- caller interface ---------------------------------------------------
    def arm(self):
        self._count = 0
        self._pending = None
        self._result = None
        if self._trig is not None:
            self._trig.entries = 0
            self._trig.active = False

    def take(self, key):
        cap = self._result
        if cap is not None:
            cap.key = key
        self._result = None
        return cap

    def detach(self):
        if self._trig is not None:
            self._trig.detach()
        if self._region_hooks is not None:
            for h in self._region_hooks:
                self.machine.unhook(h)


# --------------------------------------------------------------------------
# replay one capture under an optional fault
# --------------------------------------------------------------------------
def replay(machine, target, capture, spec=None, backend="snapshot",
           budget=5_000_000):
    """Replay `capture` under optional FaultSpec `spec`.  Returns the faulted
    output (bytes or int) or None if the replay crashed/hung."""
    if backend == "snapshot":
        return _replay_snapshot(machine, target, capture, spec, budget)
    if backend == "call":
        return _replay_call(machine, target, capture, spec, budget)
    raise ValueError(f"unknown backend {backend!r}")


def _read_out(machine, target, out_ptr, ret_val):
    if target.out == "ret":
        return ret_val
    return machine.read(out_ptr, target.out_size())


def _replay_snapshot(machine, target, cap, spec, budget):
    if cap.snap is None:
        raise ValueError("snapshot backend needs Recorder(snapshot=True)")
    machine.restore(cap.snap)
    inj = Injector(machine, spec) if spec else None
    try:
        machine._emu_start(cap.entry | 1, cap.ret, count=budget)
    except EmulationError:
        return None
    finally:
        if inj:
            inj.detach()
    ret_val = machine.reg("r0")
    return _read_out(machine, target, cap.out_ptr, ret_val)


def _relocate_args(machine, target, cap):
    """Rebuild the captured call's arguments in fresh scratch and return
    ``(args, out_addr)`` (out_addr is None for a return-value target).

    Machine.call's stack would clobber the captured stack addresses, so every buffer
    is relocated -- but aliasing is PRESERVED: two args that shared a pointer in the
    capture (an in-place op like z = z + y, where the out buffer is also an input)
    share the relocated buffer too, or a skipped write would read the wrong (fresh)
    buffer."""
    args = []
    relocated = {}                          # captured pointer -> fresh buffer
    for i, arg_spec in enumerate(target.args[:4]):
        if arg_spec == "scalar":
            args.append(cap.scalars.get(i, cap.regs.get(f"r{i}", 0)))
            continue
        captured_ptr = cap.regs[f"r{i}"]
        buf = relocated.get(captured_ptr)
        if buf is None:
            buf = machine.alloc(arg_spec[1])
            relocated[captured_ptr] = buf
        if arg_spec[0] == "in":
            machine.write(buf, cap.inputs[i])
        args.append(buf)
    out_addr = relocated.get(cap.regs[f"r{target.out}"]) if target.out != "ret" else None
    return args, out_addr


def _replay_call(machine, target, cap, spec, budget):
    if target.func is None:
        raise ValueError("call backend needs a function target, not a region")
    mark = machine.scratch_mark()     # reclaim scratch after this trial
    try:
        args, out_addr = _relocate_args(machine, target, cap)
        inj = Injector(machine, spec) if spec else None
        try:
            ret_val = machine.call(target.func, args, max_instructions=budget)
        except EmulationError:
            return None
        finally:
            if inj:
                inj.detach()
        return _read_out(machine, target, out_addr, ret_val)   # copies bytes out
    finally:
        machine.scratch_reset(mark)


# --------------------------------------------------------------------------
# sweep instruction-skip sites across the target, per capture, and detect
# --------------------------------------------------------------------------
def _skip_sites(machine, target, stride=1, persistent=False):
    """FaultSpecs for a SKIP at every instruction of the target body."""
    hit = 0 if persistent else 1
    if target.func is not None:
        yield from sweep_function_body(machine, target.func, kind=SKIP,
                                       stride=stride, hit=hit)
    else:
        start, end = target.region
        addr, index = start, 0
        while addr < end:
            _, size, _ = machine.disasm_one(addr)
            if index % stride == 0:
                yield FaultSpec(kind=SKIP, pc=addr, hit=hit)
            addr += size or 2
            index += 1


def _replay_site(machine, target, spec, captures_by_key, featurize, detect,
                 backend, budget, on_output=None):
    """Replay every capture under one skip `spec`, featurize the survivors, and
    score the populations -> one row dict {'pc','text','crashed','ran',**detect}.

    The reusable per-site seam of `skip_sweep`; deterministic given the captures,
    so a parallel driver can call it against a shipped `captures_by_key`.
    `on_output(pc, text, key, cap_index, output)`, if given, is called for every
    surviving faulted output (before featurizing) -- the seam `--dump` records."""
    keys = list(captures_by_key)
    _, _, text = machine.disasm_one(spec.pc)
    feats = {k: [] for k in keys}
    crashed = ran = 0
    ineff_same = ineff_total = 0                      # ineffective fault: faulted == unfaulted
    for k in keys:
        for cap_i, cap in enumerate(captures_by_key[k]):
            out = replay(machine, target, cap, spec, backend, budget)
            if out is None:
                crashed += 1
            else:
                ran += 1
                if on_output is not None:
                    on_output(spec.pc, text, k, cap_i, out)
                feats[k].append(featurize(cap, out))
                if cap.golden_output is not None:
                    ineff_total += 1
                    ineff_same += (out == cap.golden_output)
    row = {"pc": spec.pc, "text": text, "crashed": crashed, "ran": ran,
           "ineffective": (ineff_same / ineff_total if ineff_total else None)}
    try:
        row.update(detect(feats))
    except Exception as exc:             # too few survivors, etc.
        row["error"] = str(exc)
    return row


def skip_sweep(machine, target, captures_by_key, featurize, detect,
               backend="snapshot", stride=1, persistent=False,
               budget=5_000_000, progress=None, on_output=None):
    """For each instruction-skip site in the target, replay every capture,
    turn each faulted output into a feature vector, and score the two
    populations.

    `captures_by_key` is {key: [Capture, ...]}.
    `featurize(capture, output) -> feature`   (e.g. matched_filter(cap.c, unpack(out)))
    `detect(features_by_key) -> dict`         (e.g. {'acc': two_key_accuracy(...)})
    Returns per-site dicts: {'pc', 'text', 'crashed', 'ran', **detect_result}.
    """
    results = []
    # sandbox: a wild persistent skip can make an isolated replay run away and
    # scribble over shared memory; snapshot here and restore at the end so the
    # caller's machine is left as we found it.
    guard = machine.snapshot()
    try:
        for spec in _skip_sites(machine, target, stride, persistent):
            row = _replay_site(machine, target, spec, captures_by_key,
                               featurize, detect, backend, budget, on_output)
            results.append(row)
            if progress:
                progress(row)
    finally:
        machine.restore(guard)
    return results


# --------------------------------------------------------------------------
# benchmark the two backends on one target
# --------------------------------------------------------------------------
def benchmark_backends(machine, target, capture, spec=None, trials=200,
                       budget=5_000_000):
    """Time both backends replaying one capture `trials` times; report
    instructions/trial, seconds, and stored bytes.  Asserts the two produce the
    same output (equivalence)."""
    out = {}
    guard = machine.snapshot()                   # leave the machine as we found it
    # instructions executed per trial (backend-independent: the target runs the
    # same code either way).  icount is measured across one call-backend replay,
    # whose icount delta is clean (the snapshot backend's restore() resets
    # icount, so its cross-trial delta is meaningless).
    if target.func is not None:
        i0 = machine.icount
        replay(machine, target, capture, spec, "call", budget)
        out["insns_per_trial"] = machine.icount - i0
    for backend in ("snapshot", "call"):
        if backend == "call" and target.func is None:
            out[backend] = {"skipped": "region target"}
            continue
        t0 = time.perf_counter()
        last = None
        for _ in range(trials):
            last = replay(machine, target, capture, spec, backend, budget)
        secs = time.perf_counter() - t0
        out[backend] = {"seconds": secs, "ms_per_trial": secs * 1e3 / max(trials, 1),
                        "output": last}
    # stored-bytes estimate
    snap_bytes = 0
    if capture.snap is not None:
        snap_bytes = sum(len(d) for _, d in capture.snap._mem.values())
    io_bytes = sum(len(b) for b in capture.inputs.values())
    out["stored_bytes"] = {"snapshot": snap_bytes, "call": io_bytes}
    if ("output" in out.get("snapshot", {}) and "output" in out.get("call", {})):
        out["equivalent"] = out["snapshot"]["output"] == out["call"]["output"]
    machine.restore(guard)
    return out
