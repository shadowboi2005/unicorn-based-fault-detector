"""Multiprocessing backend for the fault-analysis sweep.

Both modes are embarrassingly parallel -- every fault site is independent -- but
a `Machine` wraps a live Unicorn/Capstone C handle and cannot cross a process
boundary.  The ELF path is a sufficient seed instead: each worker deterministically
rebuilds `(machine, scheme, profile)` and regenerates the seed-derived keys, so
the parallel result is *bit-identical* to the serial `assess.sweep_sites` /
`assess.sweep_function` -- only re-ordered.

The scheme-specific per-site work lives on `master` (`assess._run_site`,
`replay._replay_site`); this module only provisions per-worker machines and maps
the work over a `ProcessPoolExecutor`.  Start method is **spawn** so no live
Unicorn C state is inherited across the fork.

Sweep: one task per site + `as_completed`, so the pool's dynamic scheduler
load-balances the very uneven hang-to-cap sites.  Funcskip: capture once on the
coordinator (call-backend captures are pure data), ship them, split the cheap
replay sites into contiguous chunks (per-replay IPC would otherwise dominate).
The snapshot backend is not parallelizable here (its capture holds a non-picklable
Unicorn context) -- the caller falls back to serial `sweep_function`.
"""

import multiprocessing as mp
import os
from concurrent.futures import ProcessPoolExecutor, as_completed

from . import assess as _assess
from .assess import (CAP, DEFAULT_KEYS, DEFAULT_N, DEFAULT_N_PERM, FDR_Q,
                     AssessmentResult, SiteResult)
from .scheme import SIGN

__all__ = ["sweep_sites_parallel", "sweep_function_parallel", "resolve_jobs"]


def resolve_jobs(jobs, n_items):
    """Clamp a requested worker count to [1, n_items]; jobs<=0 => all CPUs."""
    want = jobs if jobs and jobs > 0 else (os.cpu_count() or 1)
    return max(1, min(want, max(1, n_items)))


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


# --------------------------------------------------------------------------
# shared provisioning (a fresh, fully-bound machine from the ELF path)
# --------------------------------------------------------------------------
def _build_bound_machine(elf_path, platform_name, seed, profile_override):
    """Replicate cli._machine: from_elf + bind + boot + RNG/cycle stubs + profile.
    Returns (machine, scheme, profile).  No live handle from this ever crosses a
    process boundary -- it is called inside each worker."""
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
# mode "sweep" -- one task per site
# --------------------------------------------------------------------------
_W = {}                               # per-worker state, populated by _worker_init


def _worker_init(elf_path, platform_name, keys, n, detector, budget, seed,
                 profile_override, site_filter, calibrate, n_perm, key_mode, golden):
    """Runs once per worker process: build our own machine and precompute the
    deterministic inputs (keys, messages, site labels).  `golden` is the coordinator's
    control-row baseline (plain picklable data), shared read-only so every faulted site
    can compute the ineffective / differential / sifa measurements."""
    m, scheme, profile = _build_bound_machine(elf_path, platform_name, seed,
                                              profile_override)
    # same order as assess.sweep_sites (keys then setup) so the clean state each
    # site is isolated to is byte-identical to the serial engine's
    sk = _assess._make_keys(scheme, keys, key_mode, profile)
    profile.setup(m)
    sites = dict(profile.fault_sites(m, _op_func(scheme)))
    if site_filter is not None:
        sites = {a: sites[a] for a in site_filter if a in sites}
    _W.clear()
    _W.update(scheme=scheme, profile=profile, sk=sk,
              messages=_assess.standard_messages(n),
              sites=sites, detector=detector, budget=budget,
              calibrate=calibrate, n_perm=n_perm, golden=golden)


def _worker_run_site(site_addr):
    """Per-task: run ONE faulted site via the shared seam and return its SiteResult."""
    row, _ = _assess._run_site(_W["scheme"], _W["profile"], _W["sk"], _W["messages"],
                               site_addr, _W["sites"][site_addr], _W["detector"],
                               _W["budget"], calibrate=_W["calibrate"],
                               n_perm=_W["n_perm"], golden=_W["golden"])
    return row


def _enumerate_sites(elf_path, platform_name, seed, profile_override, site_filter):
    """Build a TRANSIENT machine, enumerate [control]+fault_sites in serial order,
    then drop it so no live Unicorn handle survives into pool creation."""
    m, scheme, profile = _build_bound_machine(elf_path, platform_name, seed,
                                              profile_override)
    profile.setup(m)
    discovered = list(profile.fault_sites(m, _op_func(scheme)))
    if site_filter is not None:
        keep = set(site_filter)
        discovered = [(a, lbl) for a, lbl in discovered if a in keep]
    ordered = [(None, "no fault (control)")] + discovered
    name = scheme.name
    del m, scheme, profile
    return name, ordered


def _run_control(elf_path, platform_name, keys, n, detector, budget, seed,
                 profile_override, key_mode, calibrate, n_perm):
    """Run the control (unfaulted) row on the coordinator and return (control_row,
    golden); golden is shipped to the workers as the baseline for the ineffective /
    differential / sifa measurements."""
    m, scheme, profile = _build_bound_machine(elf_path, platform_name, seed,
                                              profile_override)
    sk = _assess._make_keys(scheme, keys, key_mode, profile)
    profile.setup(m)
    return _assess._run_site(scheme, profile, sk, _assess.standard_messages(n), None,
                             "no fault (control)", detector, budget,
                             calibrate=calibrate, n_perm=n_perm, golden=None)


def sweep_sites_parallel(elf_path, platform_name="mps2-an386", keys=DEFAULT_KEYS,
                         n=DEFAULT_N, detector="two_key", budget=CAP, jobs=0,
                         seed=b"ucpqc", profile_override=None, site_filter=None,
                         progress=None, calibrate=True, n_perm=DEFAULT_N_PERM,
                         fdr_q=FDR_Q, correction="bh", key_mode="independent"):
    """ProcessPool equivalent of `assess.sweep_sites`; bit-identical rows.

    `jobs<=0` uses all CPUs.  `site_filter` restricts the sweep to those sites (used by
    the parity test).  The control row runs first on the coordinator to produce the
    golden baseline, which is shipped (plain picklable data) to the workers; the faulted
    sites then run in parallel, are gathered as they finish, re-imposed into serial
    control-first order, and finalized by the same sweep-wide FDR pass as serial."""
    scheme_name, ordered = _enumerate_sites(elf_path, platform_name, seed,
                                            profile_override, site_filter)
    control_row, golden = _run_control(elf_path, platform_name, keys, n, detector,
                                       budget, seed, profile_override, key_mode,
                                       calibrate, n_perm)
    faulted = [sl for sl in ordered if sl[0] is not None]
    workers = resolve_jobs(jobs, len(faulted))
    ctx = mp.get_context("spawn")
    by_addr = {}
    with ProcessPoolExecutor(
            max_workers=workers, mp_context=ctx,
            initializer=_worker_init,
            initargs=(elf_path, platform_name, keys, n, detector, budget, seed,
                      profile_override, site_filter, calibrate, n_perm, key_mode,
                      golden)) as ex:
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
# mode "funcskip" -- capture once, ship, split the cheap replay sites
# --------------------------------------------------------------------------
def _resolve_target(profile, target_name):
    if target_name:
        targets = profile.targets() if hasattr(profile, "targets") else {}
        return targets[target_name]
    return profile.default_target()


def _capture_and_enumerate(elf_path, platform_name, target_name, keys, n,
                           detector, backend, seed, profile_override):
    """Coordinator-side prelude: capture caps_by_key once and enumerate the
    interior skip-site PCs.  Returns everything the workers need (pure data)."""
    from .replay import _skip_sites
    m, scheme, profile = _build_bound_machine(elf_path, platform_name, seed,
                                              profile_override)
    target = _resolve_target(profile, target_name)
    det = detector or profile.detector_for(target)
    caps_by_key = _assess._capture_funcskip(scheme, profile, target, backend, keys, n)
    pcs = [spec.pc for spec in _skip_sites(m, target, stride=1, persistent=True)]
    return scheme.name, caps_by_key, det, pcs


def _fs_worker_init(elf_path, platform_name, target_name, detector, backend,
                    budget, seed, profile_override, caps_by_key, calibrate, n_perm):
    from .faults import SKIP, FaultSpec        # noqa: F401 (used in run_chunk)
    m, scheme, profile = _build_bound_machine(elf_path, platform_name, seed,
                                              profile_override)
    profile.setup(m)
    target = _resolve_target(profile, target_name)
    _W.clear()
    _W.update(machine=m, target=target, caps=caps_by_key,
              featurize=_assess._make_featurize(profile, detector),
              detect=_assess._make_detect(profile, detector, calibrate, n_perm),
              backend=backend, budget=budget,
              guard=m.snapshot())              # per-chunk sandbox baseline


def _fs_worker_run_chunk(pcs):
    from .faults import SKIP, FaultSpec
    from .replay import _replay_site
    W = _W
    W["machine"].restore(W["guard"])           # undo any prior chunk's damage
    rows = []
    for pc in pcs:
        rows.append(_replay_site(W["machine"], W["target"],
                                 FaultSpec(kind=SKIP, pc=pc, hit=0),
                                 W["caps"], W["featurize"], W["detect"],
                                 W["backend"], W["budget"]))
    return rows


def sweep_function_parallel(elf_path, platform_name="mps2-an386", target_name=None,
                            keys=DEFAULT_KEYS, n=DEFAULT_N, detector=None,
                            backend="call", budget=5_000_000, jobs=0,
                            seed=b"ucpqc", profile_override=None, progress=None,
                            calibrate=True, n_perm=DEFAULT_N_PERM,
                            fdr_q=FDR_Q, correction="bh"):
    """ProcessPool equivalent of `assess.sweep_function` (call backend only).

    Returns None for the snapshot backend (its captures hold a non-picklable
    Unicorn context) so the caller can fall back to serial `sweep_function`.  The
    calibrated verdict matches serial: workers return per-site p-values and the
    coordinator runs the same sweep-wide FDR pass."""
    if backend == "snapshot":
        return None
    scheme_name, caps_by_key, det, pcs = _capture_and_enumerate(
        elf_path, platform_name, target_name, keys, n, detector, backend, seed,
        profile_override)
    workers = resolve_jobs(jobs, len(pcs))
    chunks = _chunk(pcs, workers)
    ctx = mp.get_context("spawn")
    rows = []
    with ProcessPoolExecutor(
            max_workers=workers, mp_context=ctx,
            initializer=_fs_worker_init,
            initargs=(elf_path, platform_name, target_name, det, backend, budget,
                      seed, profile_override, caps_by_key, calibrate, n_perm)) as ex:
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
