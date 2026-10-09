"""Multithreaded funcskip `--dump` for the free-threaded interpreter (3.14t).

The funcskip prelude is **2*N full signings** (the capture); the replay sweep is
``#sites * 2N`` short replays.  Which dominates depends on the function: a small
target (few sites) is capture-bound, a big one (hundreds of sites) is replay-bound.
So this driver parallelises **both phases** over ``jobs`` worker threads, each with
its own emulator (so there is no GIL contention on 3.14t):

  * capture  -- the 2N signings are split across threads (``N/jobs`` each), which is
    the win when sites are few;
  * replay   -- the skip sites are split across threads, the win when sites are many.

To make a signing an independent, order-free unit of work (so it can run on any
thread and the dump is identical for any ``jobs``), each signing restores a clean
post-setup snapshot and re-seeds the RNG stream to a per-(key, index) seed
``nonce-<key>-<i>``.  (This differs from the serial single-stream capture, so the
exact nonces -- not the leak verdicts -- differ; `jobs=1` here equals `jobs=K` here.)
Uses the "call" backend so captures are pure data shippable between threads.
"""

import threading
from concurrent.futures import ThreadPoolExecutor

import numpy as np

from . import assess, dump as dumpmod, profiles as profilemod
from .replay import Recorder, _replay_site, _skip_sites
from .machine import EmulationError, Machine
from .platform import PLATFORMS
from .scheme import Scheme

_tls = threading.local()


def _worker(elf_path, platform_name, keys, key_mode, profile_override):
    """The calling thread's reusable emulator context, built once per thread:
    a booted machine + scheme + profile + secret keys + the RNG stream to re-seed
    + a clean post-setup snapshot to restore before every signing."""
    ctx = getattr(_tls, "ctx", None)
    if ctx is None:
        m = Machine.from_elf(elf_path, platform=PLATFORMS[platform_name])
        scheme = Scheme.bind(m)
        m.boot()
        profile = profilemod.profile_for(scheme, override=profile_override)
        sk = assess._make_keys(scheme, keys, key_mode, profile)   # does its own keygen RNG
        profile.setup(m)
        m.stub_cycle_counter()
        stream = m.stub_randombytes(b"seed")                      # the signing RNG, reset per item
        clean = m.snapshot()
        ctx = _tls.ctx = dict(m=m, scheme=scheme, profile=profile, sk=sk,
                              stream=stream, clean=clean)
    return ctx


def _capture_item(ctx_args, target, key, i, msg, budget):
    """Capture one signing (key, i) as an independent unit: restore clean, seed the
    RNG to ``nonce-<key>-<i>``, sign, record the target's I/O (+ its challenge)."""
    w = _worker(*ctx_args)
    m, scheme, profile = w["m"], w["scheme"], w["profile"]
    m.restore(w["clean"])
    # shared per-message seed (same for A and B) so only the secret key differs between the
    # two populations -- isolates key-dependence for the leak and key-dependent-ineffective tests
    w["stream"].reset(f"nonce-{i}".encode())
    rec = Recorder(m, target, snapshot=False)           # "call" backend: pure-data caps
    rec.arm()
    try:
        art = scheme.sign(msg, w["sk"][key], max_instructions=budget)
    except EmulationError:
        rec.detach()
        return key, i, None
    cap = rec.take(key)
    rec.detach()
    if cap is None:
        return key, i, None
    cap.c = profile.challenge(m, art)
    return key, i, cap


def _replay_one(ctx_args, target, spec, caps_by_key, featurize, detect, budget):
    """Replay every capture under one skip `spec` on this thread's machine, recording
    the faulted outputs into a local sink.  Returns (row, site_dict_or_None)."""
    w = _worker(*ctx_args)
    m = w["m"]
    sink = assess._FuncskipDumpSink()
    guard = m.snapshot()                                          # leave the machine clean
    try:
        row = _replay_site(m, target, spec, caps_by_key, featurize, detect,
                                     "call", budget, sink.record)
    finally:
        m.restore(guard)
    sites = sink.sites()
    return row, (sites[0] if sites else None)


def sweep_function_dump_parallel(elf_path, target_name, platform_name="mps2-an386",
                                 keys=assess.DEFAULT_KEYS, n=assess.DEFAULT_N, jobs=0,
                                 key_mode="independent", profile_override=None,
                                 detector=None, budget=5_000_000, calibrate=True,
                                 n_perm=assess.DEFAULT_N_PERM, fdr_q=assess.FDR_Q,
                                 correction="bh", dump_dir=None, progress=None,
                                 caps_by_key=None):
    """Run a funcskip sweep over `target_name` with `jobs` threads and (optionally)
    write a dump to `dump_dir`.  Capture is parallelised over the 2N signings, replay
    over the skip sites, so a capture-bound (few-site) and a replay-bound (many-site)
    target both scale.  Returns an `AssessmentResult` (mode ``funcskip``).  Intended
    for the free-threaded interpreter; on a GIL build it is correct but serial.

    `caps_by_key` ({key: [Capture]}): if given, SKIP the capture phase and replay these
    pre-loaded captures (the `--captures` cache path) -- no re-signing."""
    import os
    jobs = jobs or (os.cpu_count() or 1)

    # coordinator: resolve target + sites + the featurize/detect closures (all pure)
    ctx_args = (elf_path, platform_name, keys, key_mode, profile_override)
    c = _worker(*ctx_args)
    scheme, profile, m = c["scheme"], c["profile"], c["m"]
    targets = profile.targets() if hasattr(profile, "targets") else {}
    target = targets.get(target_name) or profile.default_target()
    detector = detector or profile.detector_for(target)
    messages = assess.standard_messages(n)
    specs = list(_skip_sites(m, target, 1, True))
    featurize = assess._make_featurize(profile, detector)
    detect = assess._make_detect(profile, detector, calibrate, n_perm)

    # ---- phase 1: parallel capture (2N signings) -- skipped if captures were supplied
    if caps_by_key is None:
        raw = {"A": {}, "B": {}}
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            futs = [pool.submit(_capture_item, ctx_args, target, k, i, messages[i], budget)
                    for k in ("A", "B") for i in range(n)]
            for f in futs:
                key, i, cap = f.result()
                if cap is not None:
                    raw[key][i] = cap
        caps_by_key = {k: [raw[k][i] for i in sorted(raw[k])] for k in ("A", "B")}

    # ---- phase 2: parallel replay (skip sites) ----
    rows, site_recs = [], []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futs = [pool.submit(_replay_one, ctx_args, target, spec, caps_by_key,
                            featurize, detect, budget) for spec in specs]
        for f in futs:
            row_d, site = f.result()
            metric, pvalue = row_d.get("metric"), row_d.get("pvalue")
            ran, crashed = row_d["ran"], row_d["crashed"]
            if ran < 3 or metric is None:
                status = "crash"
            elif not calibrate:
                status = "LEAK" if row_d.get("leak") else "ok"
            else:
                status = "pending"
            r = assess.SiteResult(row_d["pc"], row_d["text"], metric, status, ran,
                                  crashed, pvalue=pvalue, ineffective=row_d.get("ineffective"))
            rows.append(r)
            if site is not None:
                site_recs.append(site)
            if progress:
                progress(r)
    rows.sort(key=lambda r: r.addr)
    site_recs.sort(key=lambda s: int(s["pc"], 16))
    if calibrate:
        assess._apply_correction(rows, fdr_q, correction)

    if dump_dir:
        meta = {"scheme": scheme.name, "mode": "funcskip",
                "target": getattr(target, "name", str(target)),
                "label": getattr(target, "label", ""),
                "detector": detector, "n": n, "key_mode": key_mode, "backend": "call",
                "out_kind": "ret" if target.out == "ret" else "buffer",
                "sites": [{"pc": s["pc"], "text": s["text"]} for s in site_recs]}
        caps = {k: [assess._cap_record(cp) for cp in caps_by_key[k]] for k in ("A", "B")}
        dumpmod.write_funcskip_dump(dump_dir, meta, caps, site_recs)

    return assess.AssessmentResult(scheme.name, "funcskip", detector, n, rows,
                                   calibrate=calibrate, fdr_q=fdr_q, correction=correction,
                                   n_perm=n_perm, key_mode=key_mode)
