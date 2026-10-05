"""On-disk capture of a sweep's correct (golden) and faulty runs, so the detectors
can be re-run offline (``ucpqc detect`` / :func:`assess.assess_from_dump`) without
re-emulating -- signing is ~1.5M instructions per trial, so a dumped sweep turns
minutes of emulation into seconds of pure-numpy scoring.

Pure JSON/fs I/O, no engine imports, so the format stays self-describing and
trivially testable.  Layout under ``<dump_dir>/``::

    meta.json          scheme, n, key_mode, nonce seeds, artifact_len, ordered sites
    golden.json        the control (unfaulted) run: {"A": [record, ...], "B": [...]}
    site_<addr>.json   one faulted site: {"addr", "label", "A": [record, ...], "B": [...]}

A *record* is ``{"msg", "artifact", "challenge"}``: ``msg`` is the input message,
``artifact`` the released signature (hex), and ``challenge`` the expanded challenge
``c`` (the one emulator-derived context the classifier/structural detectors need),
as a list of ints.  ``challenge`` is absent for schemes that expose no challenge --
only the artifact-based detectors then replay offline.  golden and ``site_*`` share
the record shape; the detectors pair golden vs faulty by the record index within a key.
"""

import json
import os

MANIFEST = "meta.json"
GOLDEN = "golden.json"


def write_dump(dump_dir, meta, golden, sites):
    """Write a dump: ``meta`` (dict), ``golden`` ({"A":[rec],"B":[rec]}), and one
    file per faulted site in ``sites`` (each a dict with ``addr``/``label``/``A``/``B``).
    Returns ``dump_dir``."""
    os.makedirs(dump_dir, exist_ok=True)
    _write(os.path.join(dump_dir, MANIFEST), meta)
    _write(os.path.join(dump_dir, GOLDEN), golden)
    for site in sites:
        _write(os.path.join(dump_dir, f"site_{site['addr']}.json"), site)
    return dump_dir


def load_dump(dump_dir):
    """Inverse of :func:`write_dump`: return ``(meta, golden, sites)`` where ``sites``
    is the list of per-site dicts in ``meta['sites']`` order (missing files skipped)."""
    meta = _read(os.path.join(dump_dir, MANIFEST))
    golden = _read(os.path.join(dump_dir, GOLDEN))
    sites = []
    for entry in meta.get("sites", []):
        path = os.path.join(dump_dir, f"site_{entry['addr']}.json")
        if os.path.exists(path):
            sites.append(_read(path))
    return meta, golden, sites


def _write(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh)


def _read(path):
    with open(path) as fh:
        return json.load(fh)
