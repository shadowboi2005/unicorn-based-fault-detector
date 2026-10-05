"""Free-threaded (no-GIL) backend for the fault-analysis sweep.

Mirror of the multiprocessing backend, but using real threads on a free-threaded
CPython build (3.14t, `Py_GIL_DISABLED`).  A `Machine` still cannot be *shared*
between workers -- a Unicorn `Uc` is stateful -- so each worker THREAD builds its
own machine (held in a `threading.local`), exactly like the process backend's
per-worker initializer.  The win over processes is that nothing is pickled:
threads share the read-only inputs (keys, messages, captures) in memory.

Independent `Uc` instances were verified to parallelise under free-threading
(a spike: 8 threads, each a full signing, ~4x wall-clock speedup, GIL staying
disabled).  On a non-free-threaded interpreter this degrades to serial (threads
serialise on the GIL) -- `sweep_*_parallel` warns when that is the case.

The scheme-specific per-site work lives on `master` (`assess._run_site`,
`replay._replay_site`); this module only provisions per-thread machines and maps
the work over a `ThreadPoolExecutor`.  As in the process backend: sweep uses one
task per site + `as_completed` (dynamic load-balancing for the uneven hang-to-cap
sites); funcskip captures once on the main thread and splits the cheap replay
sites into contiguous chunks.  The snapshot backend falls back to serial (its
`Snapshot` context is tied to the capturing engine, so it is not portable to
another thread's machine).
"""

import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from . import assess as _assess
from .assess import (CAP, DEFAULT_KEYS, DEFAULT_N, DEFAULT_N_PERM, FDR_Q,
                     AssessmentResult, SiteResult)
from .scheme import SIGN

__all__ = ["sweep_sites_parallel", "sweep_function_parallel", "resolve_jobs"]


def resolve_jobs(jobs, n_items):
    """Clamp a requested worker count to [1, n_items]; jobs<=0 => all CPUs."""
    want = jobs if jobs and jobs > 0 else (os.cpu_count() or 1)
    return max(1, min(want, max(1, n_items)))


def _warn_if_gil():
    if sys._is_gil_enabled() if hasattr(sys, "_is_gil_enabled") else True:
        print("warning: the GIL is enabled (not a free-threaded build) -- threads "
              "will not speed up the sweep; use the parallel-multiprocessing branch.",
              file=sys.stderr)


def _chunk(seq, k):
    """Split `seq` into at most `k` contiguous, roughly-even chunks."""
    seq = list(seq)
    k = max(1, min(k, len(seq) or 1))
    q, r = divmod(len(seq), k)
    out, i = [], 0
    for c in range(k):
        size = q + (1 if c < r else 0)
        if size:
            out.append(seq[i:i + size])
            i += size
    return out


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
    target_name: object = None
    backend: str = "call"
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
# mode "sweep" -- one task per site, per-thread machine
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
                         n=DEFAULT_N, detector="two_key", budget=CAP, jobs=0,
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


# --------------------------------------------------------------------------
# mode "funcskip" -- capture once (shared in-memory), split the replay sites
# --------------------------------------------------------------------------
def _resolve_target(profile, target_name):
    if target_name:
        targets = profile.targets() if hasattr(profile, "targets") else {}
        return targets[target_name]
    return profile.default_target()


def _capture_and_enumerate(cfg):
    """Main-thread prelude: capture caps_by_key once and enumerate interior
    skip-site PCs.  Returns everything the workers share (in memory)."""
    from .replay import _skip_sites
    m, scheme, profile = _build_bound_machine(cfg.elf_path, cfg.platform_name,
                                              cfg.seed, cfg.profile_override)
    target = _resolve_target(profile, cfg.target_name)
    det = cfg.detector or profile.detector_for(target)
    caps_by_key = _assess._capture_funcskip(scheme, profile, target, cfg.backend,
                                            cfg.keys, cfg.n)
    pcs = [spec.pc for spec in _skip_sites(m, target, stride=1, persistent=True)]
    return scheme.name, caps_by_key, det, pcs


def _fs_worker_init(cfg, det, caps_by_key):
    m, scheme, profile = _build_bound_machine(cfg.elf_path, cfg.platform_name,
                                              cfg.seed, cfg.profile_override)
    profile.setup(m)
    target = _resolve_target(profile, cfg.target_name)
    _tls.fs = dict(machine=m, target=target, caps=caps_by_key,
                   featurize=_assess._make_featurize(profile, det),
                   detect=_assess._make_detect(profile, det, cfg.calibrate, cfg.n_perm),
                   backend=cfg.backend, budget=cfg.budget,
                   guard=m.snapshot())          # per-chunk sandbox baseline


def _fs_worker_run_chunk(pcs):
    from .faults import SKIP, FaultSpec
    from .replay import _replay_site
    fs = _tls.fs
    fs["machine"].restore(fs["guard"])          # undo any prior chunk's damage
    rows = []
    for pc in pcs:
        rows.append(_replay_site(fs["machine"], fs["target"],
                                 FaultSpec(kind=SKIP, pc=pc, hit=0),
                                 fs["caps"], fs["featurize"], fs["detect"],
                                 fs["backend"], fs["budget"]))
    return rows


def sweep_function_parallel(elf_path, platform_name="mps2-an386", target_name=None,
                            keys=DEFAULT_KEYS, n=DEFAULT_N, detector=None,
                            backend="call", budget=5_000_000, jobs=0,
                            seed=b"ucpqc", profile_override=None, progress=None,
                            calibrate=True, n_perm=DEFAULT_N_PERM,
                            fdr_q=FDR_Q, correction="bh"):
    """ThreadPool equivalent of `assess.sweep_function` (call backend only).

    Returns None for the snapshot backend (its Snapshot context is tied to the
    capturing engine and is not portable to another thread's machine) so the
    caller can fall back to serial `sweep_function`.  The calibrated verdict
    matches serial: workers return per-site p-values and the main thread runs the
    same sweep-wide FDR pass."""
    if backend == "snapshot":
        return None
    _warn_if_gil()
    cfg = _Cfg(elf_path, platform_name, keys, n, detector, budget, seed,
               profile_override, target_name=target_name, backend=backend,
               calibrate=calibrate, n_perm=n_perm)
    scheme_name, caps_by_key, det, pcs = _capture_and_enumerate(cfg)
    workers = resolve_jobs(jobs, len(pcs))
    chunks = _chunk(pcs, workers)
    rows = []
    with ThreadPoolExecutor(max_workers=workers, initializer=_fs_worker_init,
                            initargs=(cfg, det, caps_by_key)) as ex:
        for chunk_rows in ex.map(_fs_worker_run_chunk, chunks):   # order preserved
            for r in chunk_rows:
                metric, pvalue = r.get("metric"), r.get("pvalue")
                ran, crashed = r["ran"], r["crashed"]
                if ran < 3 or metric is None:
                    status = "crash"
                elif not calibrate:
                    status = "LEAK" if r.get("leak") else "ok"
                else:
                    status = "pending"           # finalized by the FDR pass below
                row = SiteResult(r["pc"], r["text"], metric, status, ran, crashed,
                                 pvalue=pvalue)
                rows.append(row)
                if progress:
                    progress(row)
    if calibrate:
        _assess._apply_correction(rows, fdr_q, correction)
    return AssessmentResult(scheme_name, "funcskip", det, n, rows,
                            calibrate=calibrate, fdr_q=fdr_q, correction=correction,
                            n_perm=n_perm)
