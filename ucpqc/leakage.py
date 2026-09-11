"""Simulated side-channel leakage.

The models here are the ones normally used for simulated DPA/CPA work:
Hamming weight of values moved, and Hamming distance between consecutive
states.  A trace is one sample per emulated instruction (or per memory
access), which is a noise-free, perfectly aligned idealisation of a power
trace -- exactly what you want when checking whether an attack *can* work
before touching real hardware.

Traces are ordinary lists of floats; numpy is used when available for export
and for adding noise, but is not required.
"""

import csv

try:  # numpy is optional, everything degrades to plain lists without it
    import numpy as _np
except ImportError:  # pragma: no cover
    _np = None

from .tracing import Trigger, needs_precise_counting, scoped_range


def hamming_weight(value, width=32):
    """Number of set bits in `value` (masked to `width` bits)."""
    return (value & ((1 << width) - 1)).bit_count()


def hamming_distance(a, b, width=32):
    return hamming_weight(a ^ b, width)


# --- leakage models ---------------------------------------------------------

HW_MEM = "hw_mem"  # Hamming weight of every value read or written
HD_MEM = "hd_mem"  # Hamming distance old->new on every memory write
HW_REG = "hw_reg"  # Hamming weight of the whole register file, per instruction
HD_REG = "hd_reg"  # Hamming distance of the register file between instructions

MODELS = (HW_MEM, HD_MEM, HW_REG, HD_REG)

# Registers included in the register-file models: a bus-contention style model
# would weight these differently, but for CPA the sum is the usual choice.
LEAK_REGS = [f"r{i}" for i in range(13)]


class LeakageTracer:
    """Collects a simulated leakage trace from a machine.

    ::

        tracer = LeakageTracer(m, model="hd_reg", window="pqcrystals_dilithium_ntt")
        m.call("crypto_sign_signature_ctx", ...)
        tracer.save("ntt.npy")

    `window` restricts sampling to the time a given function is on the call
    stack, which is what keeps traces of a full signature manageable.
    """

    def __init__(self, machine, model=HD_REG, window=None, limit=5_000_000,
                 begin=1, end=0, mem_range=None, scope="call", precise=None):
        if model not in MODELS:
            raise ValueError(f"unknown leakage model {model!r}, expected one of {MODELS}")
        self.machine = machine
        self.model = model
        self.limit = limit
        self.samples = []
        self.index = []  # instruction index of each sample
        self.pcs = []  # program counter of each sample
        self.truncated = False
        self._prev_regs = None
        self._mem_state = {}
        self._window = None
        if window is not None:
            begin, end = scoped_range(machine, window, scope, begin, end)
            if scope == "call":
                # In body scope the address range already is the window, so
                # the call-stack tracking hook would only cost time.
                self._window = Trigger(machine, window)

        if model in (HW_REG, HD_REG):
            if precise is None:
                precise = needs_precise_counting(begin, end)
            self.precise = precise
            machine.hook_code(self._on_insn, begin=begin, end=end, precise=precise)
        else:
            lo, hi = mem_range if mem_range else (begin, end)
            machine.hook_mem(self._on_mem, begin=lo, end=hi)

    # -- sampling -----------------------------------------------------------

    def _armed(self):
        if self.truncated or len(self.samples) >= self.limit:
            self.truncated = True
            return False
        return self._window is None or self._window.active

    def _record(self, value, pc, index):
        self.samples.append(float(value))
        self.pcs.append(pc)
        self.index.append(index)

    def _on_insn(self, m, addr, size):
        if not self._armed():
            return
        values = m.reg_batch(LEAK_REGS)
        if self.model == HW_REG:
            leak = sum(v.bit_count() for v in values)
        else:
            # The very first sample has no predecessor; measuring it against a
            # zeroed state keeps every trace the same length, which is what
            # lets traces from separate calls be stacked and correlated.
            prev = self._prev_regs or [0] * len(values)
            leak = sum((a ^ b).bit_count() for a, b in zip(values, prev))
            self._prev_regs = values
        self._record(leak, addr, m.icount)

    def _on_mem(self, m, is_write, addr, size, value):
        if not self._armed():
            return
        width = 8 * size
        if self.model == HW_MEM:
            if is_write:
                leak = hamming_weight(value, width)
            else:
                leak = hamming_weight(int.from_bytes(m.read(addr, size), "little"), width)
        else:  # HD_MEM: transition on the bus / in the memory cell
            if not is_write:
                return
            old = self._mem_state.get(addr)
            if old is None:
                old = int.from_bytes(m.read(addr, size), "little")
            leak = hamming_distance(old, value, width)
            self._mem_state[addr] = value
        self._record(leak, m.reg("pc"), m.icount)

    # -- output -------------------------------------------------------------

    def __len__(self):
        return len(self.samples)

    def trace(self, noise=0.0, seed=None):
        """The trace, optionally with additive Gaussian noise (needs numpy)."""
        if noise and _np is None:
            raise RuntimeError("adding noise requires numpy")
        if _np is None:
            return list(self.samples)
        arr = _np.asarray(self.samples, dtype=_np.float64)
        if noise:
            rng = _np.random.default_rng(seed)
            arr = arr + rng.normal(0.0, noise, size=arr.shape)
        return arr

    def save(self, path, noise=0.0, seed=None):
        """Write the trace to .npy (numpy) or .csv (always available)."""
        if path.endswith(".npy"):
            if _np is None:
                raise RuntimeError("saving .npy requires numpy; use .csv instead")
            _np.save(path, self.trace(noise=noise, seed=seed))
            return path
        with open(path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["sample", "index", "pc", "leakage"])
            values = self.trace(noise=noise, seed=seed)
            for i, (idx, pc, value) in enumerate(zip(self.index, self.pcs, values)):
                writer.writerow([i, idx, f"{pc:#010x}", value])
        return path

    def summary(self):
        if not self.samples:
            return "no samples collected"
        lo, hi = min(self.samples), max(self.samples)
        mean = sum(self.samples) / len(self.samples)
        note = " (truncated)" if self.truncated else ""
        return (
            f"{len(self.samples):,} samples{note}, model={self.model}, "
            f"min={lo:.1f} max={hi:.1f} mean={mean:.2f}"
        )


class TraceSet:
    """A set of traces plus their inputs, ready for a CPA-style analysis."""

    def __init__(self):
        self.traces = []
        self.inputs = []

    def add(self, trace, plaintext):
        self.traces.append(list(trace))
        self.inputs.append(plaintext)

    def matrix(self):
        """Traces as a (n_traces x n_samples) array, truncated to the shortest."""
        if _np is None:
            raise RuntimeError("building a trace matrix requires numpy")
        width = min(len(t) for t in self.traces)
        return _np.asarray([t[:width] for t in self.traces], dtype=_np.float64)

    def correlate(self, hypothesis):
        """Pearson correlation of each sample against a per-trace hypothesis.

        `hypothesis` is one value per trace (e.g. HW of a guessed
        intermediate); the result is the classic CPA correlation curve.
        """
        if _np is None:
            raise RuntimeError("correlation requires numpy")
        traces = self.matrix()
        h = _np.asarray(hypothesis, dtype=_np.float64)
        h = h - h.mean()
        t = traces - traces.mean(axis=0)
        denom = _np.sqrt((h**2).sum() * (t**2).sum(axis=0))
        denom[denom == 0] = _np.nan
        return (h @ t) / denom

    def save(self, path_prefix):
        if _np is None:
            raise RuntimeError("saving a trace set requires numpy")
        _np.save(f"{path_prefix}_traces.npy", self.matrix())
        _np.save(f"{path_prefix}_inputs.npy", _np.asarray(self.inputs))
        return f"{path_prefix}_traces.npy"
