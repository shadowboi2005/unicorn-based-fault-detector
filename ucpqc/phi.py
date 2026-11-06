"""phi_IF -- the key-dependent-ineffective (SIFA-candidate) detector, constructive.

This replicates the QEMU-test `ineffective` oracle
(`QEMU-test/dist_tests/dilithium/early_stop_sweep_unicorn.py` + `common/ineffective.py`)
inside ucpqc, instead of the earlier *sampling* approach (which, correctly controlled,
found nothing because random keys never hit the chosen secret values a witness needs).

For one fault site (an interior `bl` callee of a target function F), the oracle asks the
LLVM/QEMU `ineffective` question:

    forall public background p : exists s1,s2 :
        skipping the call is a NO-OP for secret value s1 (correct == faulted) and
        OUTPUT-CHANGING for s2, at some output position

answered **constructively** -- by *injecting a chosen secret coefficient value* into F's
secret-input buffer and sweeping it over the coefficient's domain, with the public
background and RNG held fixed across the correct vs faulted run:

  * isolate F via capture-and-replay (`replay.Recorder`/`replay`, snapshot backend);
  * hold the public inputs + RNG fixed = the captured background `p_k` (the seed-restored
    `Machine.snapshot/restore` keeps correct and faulted on identical `(p, r)`);
  * sweep the secret value `sval` over `profile.domain_values(domain)` (0 first + spread),
    writing it into coefficient `secret_pos` of F's secret arg via `replay(overrides=...)`;
  * correct = replay with no fault; faulted = replay with a persistent SKIP at the `bl`;
  * per output word, record eq = (correct == faulted);
  * `IneffectiveTracker` declares a hit at an output position where, for EVERY background,
    both an ineffective `sval` and an effective `sval` were seen (ported from QEMU).

The fault is applied at **runtime** (`Injector` SKIP of the interior `bl`), so unlike
QEMU-test we need no prebuilt faulty ELF.

Caveats:
  * a per-position `ineffective` witness LOCATES a SIFA candidate; it is NOT a proven exploit.
  * v1 covers function-level targets whose secret arg is an unpacked int32 coefficient buffer
    (annotated `Target.secret`); `signature_internal`/packed-`sk` is out of scope.
  * run on a build whose target symbols exist un-inlined (the m4f/clean ref-style builds).
"""

import struct
from dataclasses import dataclass, field

import numpy as np

from . import assess
from .faults import SKIP, FaultSpec
from .profiles import _scan_calls
from .replay import replay

DEFAULT_K = 6               # public backgrounds (distinct messages)
DEFAULT_DOMAIN_CAP = 64     # max swept secret values per coefficient
DEFAULT_BUDGET = 5_000_000  # max instructions per isolated replay


# --------------------------------------------------------------------------
# ineffective verdict -- ported from QEMU-test dist_tests/common/ineffective.py
# --------------------------------------------------------------------------
class IneffectiveTracker:
    """Incremental ineffective oracle: feed one swept secret value at a time.

    `eq[k][j][pos]` = (correct == faulted) for public background k, ephemeral draw j
    (J = 1 here -- these targets consume no RNG), output position pos.  A hit is a
    position where, for EVERY background, some swept value was ineffective on all J draws
    and some other was effective on all J draws."""

    def __init__(self, n_pos, n_bg):
        shape = (n_bg, n_pos)
        self.has_inef = np.zeros(shape, dtype=bool)
        self.has_eff = np.zeros(shape, dtype=bool)
        self.val_inef = np.zeros(shape, dtype=np.int64)
        self.val_eff = np.zeros(shape, dtype=np.int64)

    def update(self, sv, eq):
        """eq: bool array (n_bg, n_eph, n_pos) for secret value `sv`."""
        eq = np.asarray(eq, dtype=bool)
        inef, eff = eq.all(axis=1), (~eq).all(axis=1)      # (n_bg, n_pos)
        new = inef & ~self.has_inef
        self.val_inef[new] = sv
        self.has_inef |= inef
        new = eff & ~self.has_eff
        self.val_eff[new] = sv
        self.has_eff |= eff

    def hit(self):
        """None, or (pos, [(s_ineffective, s_effective) per background])."""
        ok = (self.has_inef & self.has_eff).all(axis=0)
        pos = np.flatnonzero(ok)
        if pos.size == 0:
            return None
        p = int(pos[0])
        return p, [(int(self.val_inef[k, p]), int(self.val_eff[k, p]))
                   for k in range(self.val_inef.shape[0])]


# --------------------------------------------------------------------------
# result model
# --------------------------------------------------------------------------
@dataclass
class PhiSite:
    pc: int
    label: str
    detected: bool = False
    pos: int = -1                         # output position of the witness
    witness: tuple = None                 # (s1_ineffective, s2_effective), first background
    note: str = ""


@dataclass
class PhiResult:
    scheme: str
    target: str
    secret_pos: int
    k: int
    n_values: int
    sites: list = field(default_factory=list)

    def detections(self):
        return [s for s in self.sites if s.detected]


# --------------------------------------------------------------------------
# the constructive sweep
# --------------------------------------------------------------------------
def _splice_coeff(buf, pos, sval):
    """Return `buf` with the int32 coefficient at index `pos` replaced by `sval`."""
    ba = bytearray(buf)
    ba[pos * 4:pos * 4 + 4] = struct.pack("<i", int(sval))
    return bytes(ba)


def _eq_words(correct, faulted, n):
    """Per-output-word equality (bool[n]); a crash/None counts as effective (changed)."""
    if correct is None or faulted is None:
        return np.zeros(n, dtype=bool)
    a = np.frombuffer(correct, dtype="<i4")[:n]
    b = np.frombuffer(faulted, dtype="<i4")[:n]
    if a.size < n or b.size < n:
        return np.zeros(n, dtype=bool)
    return a == b


def _fault_sites(machine, func, wanted):
    """Interior `bl` callees of `func` as [(pc, label)], deduped; optionally filtered to
    labels containing one of the `wanted` substrings."""
    seen, out = set(), []
    for pc, _t, label in _scan_calls(machine, func):
        if pc in seen:
            continue
        seen.add(pc)
        if wanted and not any(w in label for w in wanted):
            continue
        out.append((pc, label))
    return out


def per_position_phi(scheme, profile, target_name, secret_pos=0, k=DEFAULT_K,
                     domain_cap=DEFAULT_DOMAIN_CAP, budget=DEFAULT_BUDGET,
                     sites=None, progress=None):
    """Constructive ineffective sweep over target `target_name`.  Returns a `PhiResult`.

    `secret_pos` -- which int32 coefficient of the secret arg to sweep (default 0).
    `k` -- public backgrounds (distinct messages).  `sites` -- substrings restricting the
    interior `bl` fault sites (default: all)."""
    if isinstance(sites, str):
        sites = [s.strip() for s in sites.split(",") if s.strip()]
    m = scheme.machine
    targets = profile.targets() if hasattr(profile, "targets") else {}
    if target_name not in targets:
        raise ValueError(f"unknown target {target_name!r}; known: {', '.join(sorted(targets))}")
    target = targets[target_name]
    if not target.secret:
        raise ValueError(f"target {target_name!r} has no `secret` annotation (which arg "
                         f"carries the secret + its domain); see dilithium_targets._t")
    secret_arg, domain_name = target.secret
    n_pos = target.out_size() // 4
    if n_pos == 0:
        raise ValueError(f"target {target_name!r} has a return-value output; the sweep needs "
                         f"a buffer output to compare per position")

    # Isolate F and capture K public backgrounds (one key, K distinct messages); the
    # snapshot backend keeps each background's full (public + RNG) state for replay.
    caps = assess._capture_funcskip(scheme, profile, target, "snapshot",
                                    assess.DEFAULT_KEYS, k)["A"]
    if len(caps) < 2:
        raise ValueError(f"target {target_name!r} captured < 2 backgrounds (reached "
                         f"{len(caps)}); not enough for the 'forall p' test")
    values = profile.domain_values(domain_name, domain_cap)

    # Zero the output buffer before each replay (QEMU-test convention), so a skipped
    # write leaves a clean 0 baseline and "ineffective" means the correct output is also 0
    # (e.g. decompose(0)=0) -- a well-defined per-secret condition. Skip when the output
    # buffer aliases the secret arg (in-place ops like z=z+y), where it cannot be zeroed
    # without destroying the injected secret.
    if target.out != "ret":
        out_z_bytes = b"\x00" * target.out_size()

    out_sites = []
    for pc, label in _fault_sites(m, target.func, sites):
        tracker = IneffectiveTracker(n_pos, len(caps))
        for sval in values:
            eq = np.zeros((len(caps), 1, n_pos), dtype=bool)
            for bi, cap in enumerate(caps):
                ov = {secret_arg: _splice_coeff(cap.inputs[secret_arg], secret_pos, sval)}
                if (target.out != "ret"
                        and cap.regs[f"r{target.out}"] != cap.regs[f"r{secret_arg}"]):
                    ov[target.out] = out_z_bytes          # clean output baseline
                correct = replay(m, target, cap, spec=None, backend="snapshot",
                                 budget=budget, overrides=ov)
                faulted = replay(m, target, cap, spec=FaultSpec(kind=SKIP, pc=pc, hit=0),
                                 backend="snapshot", budget=budget, overrides=ov)
                eq[bi, 0, :] = _eq_words(correct, faulted, n_pos)
            tracker.update(sval, eq)
        hit = tracker.hit()
        site = PhiSite(pc, label)
        if hit is not None:
            pos, wit = hit
            site.detected = True
            site.pos = pos
            site.witness = wit[0]
            site.note = (f"out-pos {pos}: s1={wit[0][0]} ineffective, s2={wit[0][1]} effective "
                         f"(secret coeff {secret_pos}, on all {len(caps)} backgrounds)")
        else:
            site.note = "no (ineffective, effective) pair on every background in range swept"
        out_sites.append(site)
        if progress:
            progress(site)
    return PhiResult(scheme.name, target_name, secret_pos, len(caps), len(values), out_sites)
