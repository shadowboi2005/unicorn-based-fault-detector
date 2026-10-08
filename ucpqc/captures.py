"""Persistent capture cache for funcskip.

The funcskip prelude -- 2N full signings -- is the expensive, memory-bandwidth-bound
part, and it is re-done for every target and every rerun.  This module does it ONCE:
a single 2N-signing pass with a `Recorder` on EVERY target function at the same time,
saving each function's captured I/O to a `captures/` directory.  Afterwards any funcskip
run (`funcskip --captures DIR --target <fn>`) just loads the saved captures and does the
cheap replay -- no re-signing, across targets, reruns and sessions.

Each signing is an independent, order-free unit (clean snapshot/restore + per-(key,index)
RNG reseed, as in `parallel_funcskip`), so the pass is parallelised over the 2N signings
and the cache is identical for any `jobs`.  Uses the call backend, so captures are pure
data (`replay.cap_to_dict`).  A manifest records the keys/n/scheme the cache is valid for.
"""

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from . import assess, profiles as profilemod
from .replay import Recorder, cap_from_dict, cap_to_dict
from .machine import EmulationError, Machine
from .platform import PLATFORMS
from .scheme import Scheme

MANIFEST = "manifest.json"
_tls = threading.local()


def _worker(elf, platform, keys, key_mode, profile_override, target_items):
    """This thread's reusable emulator with a Recorder armed on every target."""
    ctx = getattr(_tls, "ctx", None)
    if ctx is None:
        m = Machine.from_elf(elf, platform=PLATFORMS[platform])
        scheme = Scheme.bind(m)
        m.boot()
        profile = profilemod.profile_for(scheme, override=profile_override)
        sk = assess._make_keys(scheme, keys, key_mode, profile)
        profile.setup(m)
        m.stub_cycle_counter()
        stream = m.stub_randombytes(b"seed")
        recs = {name: Recorder(m, tg, snapshot=False) for name, tg in target_items}
        clean = m.snapshot()
        ctx = _tls.ctx = dict(m=m, scheme=scheme, profile=profile, sk=sk,
                              stream=stream, recs=recs, clean=clean)
    return ctx


def _capture_item(args, target_items, key, i, msg, budget):
    """One signing (key, i): record every target's I/O during it (+ the challenge)."""
    w = _worker(*args, target_items)
    m, scheme, profile, recs = w["m"], w["scheme"], w["profile"], w["recs"]
    m.restore(w["clean"])
    w["stream"].reset(f"nonce-{key}-{i}".encode())
    for r in recs.values():
        r.arm()
    try:
        art = scheme.sign(msg, w["sk"][key], max_instructions=budget)
    except EmulationError:
        return key, i, {}
    c = profile.challenge(m, art)
    out = {}
    for name, r in recs.items():
        cap = r.take(key)
        if cap is not None:
            cap.c = c
            out[name] = cap
    return key, i, out


def capture_all(elf, out_dir, targets=None, platform="mps2-an386", n=assess.DEFAULT_N,
                jobs=0, keys=assess.DEFAULT_KEYS, key_mode="independent",
                profile_override=None, budget=assess.CAP, progress=None):
    """Capture every target's I/O across 2N signings in one pass and save to `out_dir`.
    `targets` is a list of target names (default: all of the profile's).  Returns
    `(out_dir, manifest)`."""
    jobs = jobs or (os.cpu_count() or 1)
    m = Machine.from_elf(elf, platform=PLATFORMS[platform])
    scheme = Scheme.bind(m)
    m.boot()
    profile = profilemod.profile_for(scheme, override=profile_override)
    allt = profile.targets()
    names = [nm for nm in (targets or allt) if nm in allt]
    target_items = tuple((nm, allt[nm]) for nm in names)
    messages = assess.standard_messages(n)
    args = (elf, platform, keys, key_mode, profile_override)

    raw = {nm: {"A": {}, "B": {}} for nm in names}
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futs = [pool.submit(_capture_item, args, target_items, k, i, messages[i], budget)
                for k in ("A", "B") for i in range(n)]
        for f in futs:
            key, i, caps = f.result()
            for nm, cap in caps.items():
                raw[nm][key][i] = cap
            if progress:
                progress()

    os.makedirs(out_dir, exist_ok=True)
    manifest = {"scheme": scheme.name, "platform": platform, "n": n, "key_mode": key_mode,
                "budget": budget, "targets": {}}
    for nm in names:
        caps = {k: [cap_to_dict(raw[nm][k][i]) for i in sorted(raw[nm][k])] for k in ("A", "B")}
        with open(os.path.join(out_dir, f"{nm}.captures.json"), "w") as fh:
            json.dump(caps, fh)
        manifest["targets"][nm] = {"A": len(caps["A"]), "B": len(caps["B"])}
    with open(os.path.join(out_dir, MANIFEST), "w") as fh:
        json.dump(manifest, fh, indent=2)
    return out_dir, manifest


def load_captures(cap_dir, name):
    """Load one target's saved captures -> (manifest, {key: [Capture, ...]})."""
    with open(os.path.join(cap_dir, MANIFEST)) as fh:
        meta = json.load(fh)
    with open(os.path.join(cap_dir, f"{name}.captures.json")) as fh:
        d = json.load(fh)
    caps_by_key = {k: [cap_from_dict(r) for r in d.get(k, [])] for k in ("A", "B")}
    return meta, caps_by_key
