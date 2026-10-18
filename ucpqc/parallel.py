"""Free-threaded (no-GIL) backend for the whole-call fault sweep (`sweep -j`).

Uses real threads on a free-threaded CPython build (3.14t, `Py_GIL_DISABLED`).  A
`Machine` still cannot be *shared* between workers -- a Unicorn `Uc` is stateful --
so each worker THREAD builds its own machine (held in a `threading.local`).  Nothing
is pickled: threads share the read-only inputs (keys, messages, golden baseline) in
memory.

Independent `Uc` instances were verified to parallelise under free-threading
(a spike: 8 threads, each a full signing, ~4x wall-clock speedup, GIL staying
disabled).  On a non-free-threaded interpreter this degrades to serial (threads
serialise on the GIL) -- `sweep_sites_parallel` warns when that is the case.

The scheme-specific per-site work is `assess._run_site`; this module only
provisions per-thread machines and maps the work over a `ThreadPoolExecutor`, one
task per site + `as_completed` (dynamic load-balancing for the uneven hang-to-cap
sites).  The intra-function funcskip counterpart (`funcskip -j`) is
`parallel_funcskip`.
"""

import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from . import assess as _assess
from .assess import CAP, DEFAULT_KEYS, DEFAULT_N, DEFAULT_N_PERM, FDR_Q, AssessmentResult
from .scheme import SIGN

__all__ = ["sweep_sites_parallel", "resolve_jobs"]


def resolve_jobs(jobs, n_items):
    """Clamp a requested worker count to [1, n_items]; jobs<=0 => all CPUs."""
    want = jobs if jobs and jobs > 0 else (os.cpu_count() or 1)
    return max(1, min(want, max(1, n_items)))


def _warn_if_gil():
    if sys._is_gil_enabled() if hasattr(sys, "_is_gil_enabled") else True:
        print("warning: the GIL is enabled (not a free-threaded build) -- threads "
              "will not speed up the sweep; run under .venv314t (scripts/setup_env.sh --ft).",
              file=sys.stderr)


@dataclass
class _Cfg:
    elf_path: str
    platform_name: str
    keys: tuple
    n: int
    detector: object
    budget: int
    seed: bytes
    profile_override: object
    site_filter: object = None
    calibrate: bool = True                # calibrated p-value + FDR verdict (vs legacy cutoffs)
    n_perm: int = DEFAULT_N_PERM
    key_mode: str = "independent"
    golden: object = None                 # control-row baseline, shared read-only by the threads


# --------------------------------------------------------------------------
# shared provisioning (a fresh, fully-bound machine from the ELF path)
# --------------------------------------------------------------------------
def _build_bound_machine(elf_path, platform_name, seed, profile_override):
    """Replicate cli._machine: from_elf + bind + boot + RNG/cycle stubs + profile.
    Called once per worker thread; each thread gets its own live engine."""
    from .machine import Machine
    from .platform import PLATFORMS
    from .scheme import Scheme
    from .profiles import profile_for
    m = Machine.from_elf(elf_path, platform=PLATFORMS[platform_name])
    scheme = Scheme.bind(m)
    m.boot()
    m.stub_randombytes(seed)          # install the RNG hook (re-seeded per key later)
    m.stub_cycle_counter()
    profile = profile_for(scheme, override=profile_override)
    return m, scheme, profile


def _op_func(scheme):
    return scheme.binding.symbols["signature" if scheme.kind == SIGN else "dec"]


# --------------------------------------------------------------------------
# one task per site, per-thread machine
# --------------------------------------------------------------------------
_tls = threading.local()


def _worker_init(cfg):
    """Runs once per worker thread: build this thread's own machine and precompute
    the deterministic inputs (keys, messages, site labels)."""
    m, scheme, profile = _build_bound_machine(cfg.elf_path, cfg.platform_name,
                                              cfg.seed, cfg.profile_override)
    # same order as assess.sweep_sites (keys then setup) so the clean state each
    # site is isolated to is byte-identical to the serial engine's
    sk = _assess._make_keys(scheme, cfg.keys, cfg.key_mode, profile)
    profile.setup(m)
    sites = dict(profile.fault_sites(m, _op_func(scheme)))
    if cfg.site_filter is not None:
        sites = {a: sites[a] for a in cfg.site_filter if a in sites}
    _tls.state = dict(scheme=scheme, profile=profile, sk=sk,
                      messages=_assess.standard_messages(cfg.n),
                      sites=sites, detector=cfg.detector, budget=cfg.budget,
                      calibrate=cfg.calibrate, n_perm=cfg.n_perm, golden=cfg.golden)


def _worker_run_site(site_addr):
    """Per-task: run ONE faulted site via the shared seam on this thread's machine."""
    st = _tls.state
    row, _ = _assess._run_site(st["scheme"], st["profile"], st["sk"], st["messages"],
                               site_addr, st["sites"][site_addr], st["detector"],
                               st["budget"], calibrate=st["calibrate"],
                               n_perm=st["n_perm"], golden=st["golden"])
    return row


def _enumerate_sites(cfg):
    """Build a transient machine on the calling thread, enumerate
    [control]+fault_sites in serial order, and drop it.  Returns (name, ordered)."""
    m, scheme, profile = _build_bound_machine(cfg.elf_path, cfg.platform_name,
                                              cfg.seed, cfg.profile_override)
    profile.setup(m)
    discovered = list(profile.fault_sites(m, _op_func(scheme)))
    if cfg.site_filter is not None:
        keep = set(cfg.site_filter)
        discovered = [(a, lbl) for a, lbl in discovered if a in keep]
    ordered = [(None, "no fault (control)")] + discovered
    name = scheme.name
    del m, scheme, profile
    return name, ordered


def _run_control(cfg):
    """Run the control (unfaulted) row on the calling thread -> (control_row, golden);
    golden is shared with the worker threads (in memory) as the ineffective /
    differential / sifa baseline."""
    m, scheme, profile = _build_bound_machine(cfg.elf_path, cfg.platform_name,
                                              cfg.seed, cfg.profile_override)
    sk = _assess._make_keys(scheme, cfg.keys, cfg.key_mode, profile)
    profile.setup(m)
    return _assess._run_site(scheme, profile, sk, _assess.standard_messages(cfg.n), None,
                             "no fault (control)", cfg.detector, cfg.budget,
                             calibrate=cfg.calibrate, n_perm=cfg.n_perm, golden=None)


def sweep_sites_parallel(elf_path, platform_name="mps2-an386", keys=DEFAULT_KEYS,
                         n=DEFAULT_N, detector="per_coord", budget=CAP, jobs=0,
                         seed=b"ucpqc", profile_override=None, site_filter=None,
                         progress=None, calibrate=True, n_perm=DEFAULT_N_PERM,
                         fdr_q=FDR_Q, correction="bh", key_mode="independent"):
    """ThreadPool equivalent of `assess.sweep_sites`; bit-identical rows.

    `jobs<=0` uses all CPUs.  `site_filter` restricts the sweep to those sites (used by
    the parity test).  The control row runs first on the calling thread to produce the
    golden baseline (shared via `cfg` across the threads); the faulted sites then run in
    parallel, are gathered as they finish, re-imposed into serial control-first order,
    and finalized by the same sweep-wide FDR pass as serial."""
    _warn_if_gil()
    cfg = _Cfg(elf_path, platform_name, keys, n, detector, budget, seed,
               profile_override, site_filter=site_filter,
               calibrate=calibrate, n_perm=n_perm, key_mode=key_mode)
    scheme_name, ordered = _enumerate_sites(cfg)
    control_row, cfg.golden = _run_control(cfg)     # control first -> golden (shared via cfg)
    faulted = [sl for sl in ordered if sl[0] is not None]
    workers = resolve_jobs(jobs, len(faulted))
    by_addr = {}
    with ThreadPoolExecutor(max_workers=workers, initializer=_worker_init,
                            initargs=(cfg,)) as ex:
        futs = {ex.submit(_worker_run_site, addr): addr for addr, _ in faulted}
        for fut in as_completed(futs):
            row = fut.result()
            by_addr[row.addr] = row
            if progress:
                progress(row)               # arrives out of order; that's fine
    rows = [control_row] + [by_addr[addr] for addr, _ in faulted]
    if calibrate:                                   # same sweep-wide FDR pass as serial
        _assess._apply_correction(rows, fdr_q, correction)
    return AssessmentResult(scheme_name, "sweep", detector, n, rows,
                            calibrate=calibrate, fdr_q=fdr_q, correction=correction,
                            n_perm=n_perm, key_mode=key_mode)
