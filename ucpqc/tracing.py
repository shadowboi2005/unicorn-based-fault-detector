"""Execution tracing: instruction traces, call trees, memory logs, profiles.

Everything here attaches to a :class:`~ucpqc.machine.Machine` and can be
scoped to a single function with :class:`Trigger`, which is normally what you
want: a full ML-DSA-44 signature is tens of millions of instructions, while
one call to poly_ntt or poly_challenge is a few thousand.
"""

import csv
from collections import Counter, defaultdict
from dataclasses import dataclass, field


def has_returned(sp, addr, entry_sp, ret_addr):
    """True when a call entered at `entry_sp` with return address `ret_addr`
    has finished, judged from the stack pointer at the start of a block.

    The stack pointer alone is not enough: a leaf function that pushes nothing
    keeps sp at its entry value for its whole body, so the return address is
    used to break the tie.
    """
    if sp > entry_sp:
        return True
    return sp == entry_sp and addr == ret_addr


def needs_precise_counting(begin, end):
    """Whether a hook over [begin, end] should force exact instruction counting.

    Exact counting means a Python callback on every instruction of the run,
    which costs about as much as the emulation itself.  A hook already scoped
    to a range is paying that price only inside the range, so the machine
    keeps its cheap per-block counter and the recorded indices are the
    block-level estimate (monotonic, and exact at block boundaries).
    """
    return begin <= 1 and end == 0


def scoped_range(machine, window, scope, begin, end):
    """Address range a windowed tracer should hook.

    scope="call" watches everything that runs while the window is open,
    including callees, at the cost of a Python callback on every instruction
    of the run.  scope="body" hooks only the window function's own address
    range, which is dramatically faster and is what you want when the routine
    itself is the target (an NTT, a rejection loop) rather than its callees.
    """
    if scope == "call":
        return begin, end
    if scope != "body":
        raise ValueError(f"scope must be 'call' or 'body', not {scope!r}")
    start, stop = machine.image.extent_of(window)
    return start, stop - 1


class Trigger:
    """Arms while a chosen function is on the call stack.

    The window opens when the function is entered and closes when the stack
    pointer rises back above the value it had on entry, i.e. when the call
    returns.  `nth` selects which invocation to arm on (0 = every one).
    """

    def __init__(self, machine, func, nth=0, on_arm=None, on_disarm=None):
        self.machine = machine
        self.addr = machine.addr_of(func)
        self.name = machine.image.describe(self.addr)
        self.nth = nth
        self.on_arm = on_arm
        self.on_disarm = on_disarm
        self.active = False
        self.entries = 0
        self._entry_sp = None
        self._ret = None
        self._handle = machine.hook_block(self._on_block)

    def _on_block(self, m, addr, size):
        sp = m.reg("sp")
        if self.active:
            if has_returned(sp, addr, self._entry_sp, self._ret):
                self.active = False
                if self.on_disarm:
                    self.on_disarm(m)
            return
        if addr == self.addr:
            self.entries += 1
            if self.nth and self.entries != self.nth:
                return
            self.active = True
            # At the first block of a function the caller's bl has already
            # pushed the return address into lr and left sp untouched, so both
            # are captured here and used to recognise the matching return.
            self._entry_sp = sp
            self._ret = m.reg("lr") & ~1
            if self.on_arm:
                self.on_arm(m)

    def detach(self):
        self.machine.unhook(self._handle)


@dataclass
class InsnRecord:
    index: int
    pc: int
    text: str
    regs: dict = field(default_factory=dict)


class InstructionTracer:
    """Records every instruction executed, optionally with register state.

    This is the expensive tracer (a Python callback per instruction); scope it
    with `window=` or `limit=` unless you really want the whole run.
    """

    def __init__(self, machine, window=None, limit=1_000_000, with_regs=False,
                 begin=1, end=0, scope="call", precise=None):
        self.machine = machine
        self.limit = limit
        self.with_regs = with_regs
        self.records = []
        self.truncated = False
        self._window = None
        if window is not None:
            begin, end = scoped_range(machine, window, scope, begin, end)
            if scope == "call":
                # In body scope the address range already is the window, so
                # the call-stack tracking hook would only cost time.
                self._window = Trigger(machine, window)
        precise = needs_precise_counting(begin, end) if precise is None else precise
        self.precise = precise
        machine.hook_code(self._on_insn, begin=begin, end=end, precise=precise)

    def _on_insn(self, m, addr, size):
        if self._window is not None and not self._window.active:
            return
        if len(self.records) >= self.limit:
            self.truncated = True
            return
        _, _, text = m.disasm_one(addr)
        regs = m.regs() if self.with_regs else {}
        self.records.append(InsnRecord(m.icount, addr, text, regs))

    def __len__(self):
        return len(self.records)

    def format(self, max_lines=None):
        img = self.machine.image
        lines = []
        for rec in self.records[: max_lines or len(self.records)]:
            line = f"{rec.index:>10}  {rec.pc:#010x}  {img.describe(rec.pc):<40} {rec.text}"
            if rec.regs:
                line += "   " + " ".join(f"{k}={v:#x}" for k, v in rec.regs.items())
            lines.append(line)
        if self.truncated:
            lines.append(f"... truncated at {self.limit} instructions")
        return "\n".join(lines)

    def write_csv(self, path):
        img = self.machine.image
        with open(path, "w", newline="") as fh:
            writer = csv.writer(fh)
            header = ["index", "pc", "location", "insn"]
            if self.with_regs:
                header += list(self.records[0].regs) if self.records else []
            writer.writerow(header)
            for rec in self.records:
                row = [rec.index, f"{rec.pc:#010x}", img.describe(rec.pc), rec.text]
                row += [rec.regs[k] for k in rec.regs]
                writer.writerow(row)
        return path


@dataclass
class CallRecord:
    name: str
    addr: int
    depth: int
    entry_icount: int
    exit_icount: int = None

    @property
    def cost(self):
        if self.exit_icount is None:
            return None
        return self.exit_icount - self.entry_icount


class CallTracer:
    """Reconstructs the call tree from basic-block entries.

    A call is recorded when execution enters the first block of a function
    symbol, and closed when the stack pointer rises back above its entry
    value.  Cheap enough to leave on for a whole signature.
    """

    def __init__(self, machine, max_depth=64, only=None):
        self.machine = machine
        self.max_depth = max_depth
        self.calls = []
        self._stack = []
        starts = {}
        for sym in machine.image.functions:
            starts.setdefault(sym.addr, sym.name)
        if only is not None:
            wanted = {machine.addr_of(f) for f in only}
            starts = {a: n for a, n in starts.items() if a in wanted}
        self._starts = starts
        self._handle = machine.hook_block(self._on_block)

    def _on_block(self, m, addr, size):
        sp = m.reg("sp")
        while self._stack and has_returned(sp, addr, self._stack[-1][1], self._stack[-1][2]):
            rec, _sp, _ret = self._stack.pop()
            rec.exit_icount = m.icount
        name = self._starts.get(addr)
        if name is None or len(self._stack) >= self.max_depth:
            return
        rec = CallRecord(name, addr, len(self._stack), m.icount)
        self.calls.append(rec)
        self._stack.append((rec, sp, m.reg("lr") & ~1))

    def finish(self):
        """Close any calls still open (e.g. when emulation was stopped)."""
        while self._stack:
            rec, _sp, _ret = self._stack.pop()
            rec.exit_icount = self.machine.icount
        return self.calls

    def detach(self):
        self.machine.unhook(self._handle)

    def format(self, max_lines=200, min_cost=0):
        lines = []
        for rec in self.calls:
            if rec.cost is not None and rec.cost < min_cost:
                continue
            cost = "?" if rec.cost is None else f"{rec.cost:,}"
            lines.append(f"{'  ' * rec.depth}{rec.name}  [{cost} insns]")
            if len(lines) >= max_lines:
                lines.append(f"... {len(self.calls) - max_lines} more calls")
                break
        return "\n".join(lines)

    def totals(self):
        """Inclusive instruction cost and call count per function."""
        agg = defaultdict(lambda: [0, 0])
        for rec in self.calls:
            entry = agg[rec.name]
            entry[0] += 1
            entry[1] += rec.cost or 0
        return {k: tuple(v) for k, v in sorted(agg.items(), key=lambda kv: -kv[1][1])}


class Profiler:
    """Instruction counts per function, attributed at basic-block granularity.

    Unlike :class:`InstructionTracer` this costs almost nothing, so it can run
    over a complete keygen/sign/verify cycle.
    """

    def __init__(self, machine):
        self.machine = machine
        self.counts = Counter()
        self.blocks = Counter()
        self._names = {}
        self._handle = machine.hook_block(self._on_block)

    def _on_block(self, m, addr, size):
        if size == 0:
            return
        name = self._names.get(addr)
        if name is None:
            name = self._names[addr] = m.image.describe(addr).split("+")[0]
        self.counts[name] += m.block_insn_count(addr, size)
        self.blocks[name] += 1

    def detach(self):
        self.machine.unhook(self._handle)

    def top(self, n=25):
        return self.counts.most_common(n)

    def format(self, n=25):
        total = sum(self.counts.values()) or 1
        lines = [f"{'instructions':>14}  {'share':>7}  {'blocks':>9}  function"]
        for name, count in self.top(n):
            lines.append(
                f"{count:>14,}  {100 * count / total:>6.2f}%  {self.blocks[name]:>9,}  {name}"
            )
        lines.append(f"{total:>14,}  {'100.00%':>7}  {'':>9}  TOTAL (self time, block-attributed)")
        return "\n".join(lines)


class MemoryTracer:
    """Logs memory accesses, optionally restricted to an address range."""

    def __init__(self, machine, begin=1, end=0, reads=True, writes=True,
                 limit=1_000_000, window=None):
        self.machine = machine
        self.limit = limit
        self.accesses = []  # (icount, is_write, addr, size, value, pc)
        self.truncated = False
        self._window = Trigger(machine, window) if window is not None else None
        machine.hook_mem(self._on_access, read=reads, write=writes, begin=begin, end=end)

    def _on_access(self, m, is_write, addr, size, value):
        if self._window is not None and not self._window.active:
            return
        if len(self.accesses) >= self.limit:
            self.truncated = True
            return
        self.accesses.append((m.icount, is_write, addr, size, value, m.reg("pc")))

    def __len__(self):
        return len(self.accesses)

    def write_csv(self, path):
        img = self.machine.image
        with open(path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["index", "op", "addr", "size", "value", "pc", "location"])
            for icount, is_write, addr, size, value, pc in self.accesses:
                writer.writerow(
                    [icount, "W" if is_write else "R", f"{addr:#010x}", size,
                     f"{value:#x}", f"{pc:#010x}", img.describe(pc)]
                )
        return path

    def format(self, max_lines=100):
        img = self.machine.image
        lines = []
        for icount, is_write, addr, size, value, pc in self.accesses[:max_lines]:
            lines.append(
                f"{icount:>10}  {'W' if is_write else 'R'}  {addr:#010x}/{size}"
                f"  {value:#010x}  {img.describe(pc)}"
            )
        if len(self.accesses) > max_lines:
            lines.append(f"... {len(self.accesses) - max_lines} more accesses")
        return "\n".join(lines)
