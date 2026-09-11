"""Fault injection: models, triggers, and campaign running.

A fault is a :class:`FaultSpec` (what to corrupt) plus a trigger (when).  The
campaign runner keeps one booted machine around and restores a snapshot
between trials, so the cost per trial is the target operation itself and
nothing else.

Nothing in here is scheme-specific: the campaign is handed a callable that
performs whatever operation should be faulted, and compares its output against
a golden run.
"""

import csv
import time
from collections import Counter
from dataclasses import dataclass

from .machine import EmulationError

# --- fault models -----------------------------------------------------------

SKIP = "skip"  # skip `count` instructions (instruction-skip / NOP fault)
BITFLIP_REG = "bitflip_reg"  # flip one bit of a register
SET_REG = "set_reg"  # force a register to a value (stuck-at)
BITFLIP_MEM = "bitflip_mem"  # flip one bit in memory
SET_MEM = "set_mem"  # force a word in memory to a value
FLIP_FLAGS = "flip_flags"  # invert a condition flag, i.e. take the other branch

MODELS = (SKIP, BITFLIP_REG, SET_REG, BITFLIP_MEM, SET_MEM, FLIP_FLAGS)

# CPSR flag positions, for FLIP_FLAGS.
FLAGS = {"n": 31, "z": 30, "c": 29, "v": 28}


class Outcome:
    GOLDEN = "golden"  # the unfaulted reference run
    SILENT = "silent"  # completed, output identical to golden
    DIFFERENT = "different"  # completed, output changed -- the interesting case
    REJECTED = "rejected"  # the operation itself reported failure
    CRASH = "crash"  # CPU fault, bad memory access, ...
    TIMEOUT = "timeout"  # ran past the instruction budget
    SKIPPED = "skipped"  # trigger never fired, so no fault was injected


@dataclass
class FaultSpec:
    """What to corrupt, and when.

    Trigger with exactly one of:
      * `at`  -- the global instruction index (as counted by Machine.icount);
      * `pc`  -- an address or symbol name, firing on its `hit`-th execution.

    The `pc` form is much faster: it hooks a single address instead of every
    instruction, so a sweep over a whole function costs about as much as the
    function itself.
    """

    kind: str = SKIP
    at: int = None
    pc: object = None  # int address or symbol name
    hit: int = 1  # fire on this execution of `pc`; <= 0 = every execution
    count: int = 1  # SKIP: number of instructions to skip
    reg: str = None  # BITFLIP_REG / SET_REG
    bit: int = None  # BITFLIP_REG / BITFLIP_MEM
    value: int = None  # SET_REG / SET_MEM
    addr: int = None  # BITFLIP_MEM / SET_MEM
    width: int = 4
    flag: str = "z"  # FLIP_FLAGS
    label: str = ""

    def __post_init__(self):
        if self.kind not in MODELS:
            raise ValueError(f"unknown fault model {self.kind!r}, expected one of {MODELS}")
        if (self.at is None) == (self.pc is None):
            raise ValueError("give exactly one trigger: at=<insn index> or pc=<addr|symbol>")

    def describe(self, image=None):
        where = (
            f"@insn {self.at}"
            if self.at is not None
            else f"@{image.describe(image.addr_of(self.pc)) if image else self.pc}#{self.hit}"
        )
        if self.kind == SKIP:
            what = f"skip {self.count}"
        elif self.kind == BITFLIP_REG:
            what = f"flip {self.reg}[{self.bit}]"
        elif self.kind == SET_REG:
            what = f"{self.reg}={self.value:#x}"
        elif self.kind == BITFLIP_MEM:
            what = f"flip [{self.addr:#x}][{self.bit}]"
        elif self.kind == SET_MEM:
            what = f"[{self.addr:#x}]={self.value:#x}"
        else:
            what = f"flip {self.flag.upper()}"
        return f"{what} {where}"


class Injector:
    """Installs one FaultSpec on a machine and reports whether it fired."""

    def __init__(self, machine, spec):
        self.machine = machine
        self.spec = spec
        self.fired = 0
        self._hits = 0

        if spec.pc is not None:
            # Scoped to one address, so the machine can keep counting
            # instructions per block instead of one at a time.
            addr = machine.addr_of(spec.pc)
            self._handle = machine.hook_code(
                self._on_pc, begin=addr, end=addr, precise=False
            )
        else:
            # Global instruction index: needs a hook on every instruction.
            self._handle = machine.hook_code(self._on_any)

    # -- triggers -----------------------------------------------------------

    def _on_pc(self, m, addr, size):
        self._hits += 1
        # hit <= 0 means "every execution" (persistent) -- needed for a fault on
        # a loop body or a rejection branch that runs once per iteration.
        if self.spec.hit <= 0 or self._hits == self.spec.hit:
            self._apply(m, addr, size)

    def _on_any(self, m, addr, size):
        # icount has already been incremented for this instruction by the
        # machine's counting hook, so `at` is 1-based over executed insns.
        if m.icount == self.spec.at:
            self._apply(m, addr, size)

    # -- effects ------------------------------------------------------------

    def _apply(self, m, addr, size):
        spec = self.spec
        self.fired += 1
        if spec.kind == SKIP:
            self._skip(m, addr, size)
        elif spec.kind == BITFLIP_REG:
            m.set_reg(spec.reg, m.reg(spec.reg) ^ (1 << spec.bit))
        elif spec.kind == SET_REG:
            m.set_reg(spec.reg, spec.value)
        elif spec.kind == BITFLIP_MEM:
            word = int.from_bytes(m.read(spec.addr, spec.width), "little")
            word ^= 1 << spec.bit
            m.write(spec.addr, word.to_bytes(spec.width, "little"))
        elif spec.kind == SET_MEM:
            m.write(spec.addr, spec.value.to_bytes(spec.width, "little"))
        elif spec.kind == FLIP_FLAGS:
            m.set_reg("cpsr", m.reg("cpsr") ^ (1 << FLAGS[spec.flag.lower()]))

    def _skip(self, m, addr, size):
        """Step the PC over `count` instructions without executing them.

        The instructions are skipped in address order, which is the usual
        model for a clock glitch or a laser pulse landing on the fetch stage:
        whatever the skipped bytes would have done, including a branch, does
        not happen.
        """
        pc = addr
        for _ in range(self.spec.count):
            _, insn_size, _ = m.disasm_one(pc)
            pc += insn_size or 2
        m.set_pc(pc)

    def detach(self):
        if self._handle is not None:
            self.machine.unhook(self._handle)
            self._handle = None


@dataclass
class TrialResult:
    spec: FaultSpec
    outcome: str
    icount: int = 0
    fired: int = 0
    output: object = None
    detail: str = ""

    def row(self, image=None):
        return {
            "fault": self.spec.describe(image),
            "kind": self.spec.kind,
            "at": self.spec.at,
            "pc": self.spec.pc,
            "hit": self.spec.hit,
            "outcome": self.outcome,
            "fired": self.fired,
            "icount": self.icount,
            "detail": self.detail,
        }


class FaultCampaign:
    """Runs a set of faults against one operation and classifies the results.

    `operation(machine)` must perform the thing under attack and return a
    comparable value (bytes, tuple, ...).  It is first run unfaulted to
    establish the golden output; each trial then restores the snapshot taken
    just before that run, injects one fault, and re-runs it.
    """

    def __init__(self, machine, operation, budget=200_000_000, on_result=None):
        self.machine = machine
        self.operation = operation
        self.budget = budget
        self.on_result = on_result
        self.results = []
        self._snapshot = None
        self.golden = None
        self.golden_icount = 0

    def prepare(self):
        """Boot, snapshot, and run the operation once without faults."""
        self.machine.boot()
        self._snapshot = self.machine.snapshot()
        start = self.machine.icount
        self.golden = self.operation(self.machine)
        self.golden_icount = self.machine.icount - start
        self.machine.restore(self._snapshot)
        return self.golden

    def reset(self):
        """Put the machine back in the state the golden run started from."""
        if self._snapshot is None:
            self.prepare()
        self.machine.restore(self._snapshot)

    def run_one(self, spec):
        if self._snapshot is None:
            self.prepare()
        self.machine.restore(self._snapshot)
        injector = Injector(self.machine, spec)
        start = self.machine.icount
        try:
            output = self.operation(self.machine)
            outcome = Outcome.SILENT if output == self.golden else Outcome.DIFFERENT
            detail = ""
        except EmulationError as exc:
            output, detail = None, str(exc)
            outcome = Outcome.TIMEOUT if "budget" in detail else Outcome.CRASH
        except Exception as exc:  # the operation itself rejected the result
            output, detail = None, f"{type(exc).__name__}: {exc}"
            outcome = Outcome.REJECTED
        finally:
            fired = injector.fired
            injector.detach()

        if fired == 0 and outcome == Outcome.SILENT:
            outcome = Outcome.SKIPPED

        result = TrialResult(
            spec=spec,
            outcome=outcome,
            icount=self.machine.icount - start,
            fired=fired,
            output=output,
            detail=detail,
        )
        self.results.append(result)
        if self.on_result:
            self.on_result(result)
        return result

    def run(self, specs, progress=None):
        specs = list(specs)
        started = time.time()
        for i, spec in enumerate(specs, 1):
            self.run_one(spec)
            if progress and (i % progress == 0 or i == len(specs)):
                elapsed = time.time() - started
                print(
                    f"  {i}/{len(specs)} trials  ({elapsed:.1f}s, "
                    f"{i / max(elapsed, 1e-6):.1f}/s)  {self.summary()}",
                    flush=True,
                )
        return self.results

    def summary(self):
        return dict(Counter(r.outcome for r in self.results))

    def interesting(self):
        """Trials that produced a different but complete output."""
        return [r for r in self.results if r.outcome == Outcome.DIFFERENT]

    def write_csv(self, path):
        image = self.machine.image
        with open(path, "w", newline="") as fh:
            rows = [r.row(image) for r in self.results]
            writer = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["outcome"])
            writer.writeheader()
            writer.writerows(rows)
        return path

    def format(self, max_lines=40):
        image = self.machine.image
        lines = [f"golden run: {self.golden_icount:,} instructions"]
        counts = self.summary()
        lines.append("outcomes:  " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        interesting = self.interesting()
        if interesting:
            lines.append(f"\n{len(interesting)} trial(s) changed the output:")
            for r in interesting[:max_lines]:
                lines.append(f"  {r.spec.describe(image):<52} {r.icount:>12,} insns")
            if len(interesting) > max_lines:
                lines.append(f"  ... {len(interesting) - max_lines} more")
        return "\n".join(lines)


# --- sweep helpers ----------------------------------------------------------


def sweep_instructions(start, end, step=1, kind=SKIP, **kwargs):
    """One fault per instruction index in [start, end)."""
    for index in range(start, end, step):
        yield FaultSpec(kind=kind, at=index, **kwargs)


def sweep_hits(machine, func, hits, kind=SKIP, **kwargs):
    """One fault per invocation of `func` (hit 1..hits)."""
    addr = machine.addr_of(func)
    for hit in range(1, hits + 1):
        yield FaultSpec(kind=kind, pc=addr, hit=hit, **kwargs)


def sweep_function_body(machine, func, kind=SKIP, stride=1, hit=1, **kwargs):
    """One fault per instruction address inside `func` (first execution).

    Walks the function linearly, which is exactly what an attacker sweeping a
    laser or clock-glitch offset across a routine approximates.
    """
    addr, end = machine.image.extent_of(func)
    index = 0
    while addr < end:
        _, size, _ = machine.disasm_one(addr)
        if index % stride == 0:
            yield FaultSpec(kind=kind, pc=addr, hit=hit, **kwargs)
        addr += size or 2
        index += 1


def sweep_register_bits(pc, regs=("r0", "r1", "r2", "r3"), bits=range(32), hit=1):
    """Single-bit flips across registers at one program point."""
    for reg in regs:
        for bit in bits:
            yield FaultSpec(kind=BITFLIP_REG, pc=pc, hit=hit, reg=reg, bit=bit)


def sweep_memory_bits(addr, width=4, bits=None, pc=None, hit=1, at=None):
    """Single-bit flips in one memory word, triggered at a program point."""
    bits = range(8 * width) if bits is None else bits
    for bit in bits:
        yield FaultSpec(
            kind=BITFLIP_MEM, addr=addr, width=width, bit=bit, pc=pc, hit=hit, at=at
        )
